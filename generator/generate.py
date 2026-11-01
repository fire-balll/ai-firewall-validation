#!/usr/bin/env python3
"""자연어 요구사항 -> IR 룰셋. (담당: 서진정)

--mock: 시나리오의 정답 룰셋을 그대로 내보낸다(파이프라인 연결용).
그 밖에는 로컬 Ollama 에 요구사항을 보내 구조화 출력(JSON)으로 룰셋을 받는다.
  - LLM 에 넘기는 것은 요구사항 문장과 prompts/<버전>.md 뿐이다. gold·probes 는 넘기지 않는다.
  - 출력이 JSON·스키마를 어기면 문제를 알려 주고 1회 재생성한다. 두 번째도 어기면 그대로 내보내 validator 가 반려한다.
    (seed 가 같으면 같은 입력에 같은 출력이 나오므로, 재생성은 문제를 덧붙인 대화로 한다)
  - 연결 실패·모델 없음·출력 잘림은 결과가 아니라 실행 실패다(종료 코드 1, 파일을 쓰지 않음).
  - 생성 조건(model, digest, ollama_version, temperature, seed, prompt_version)을 meta 로 남긴다.
    --save 는 generated/<시나리오>-<모델>-s<seed>.json 과 .meta.json 에 쓴다 (형식은 generated/README.md)
--feedback: eval/feedback.py 가 만든 <후보>.feedback.json 으로 다음 라운드 후보를 만든다.
  - 대화는 [시스템 프롬프트, 요구사항, 이전 후보, 실패 내용] 순서다. 실패 내용은 stage 에 따라
    검증 오류(validation)·고위험 이유(approval)·기대와 다른 프로브(deploy)만 넣는다. gold 와 통과한 프로브는 넣지 않는다.
  - 모델·프롬프트·temperature·seed 는 이전 후보의 meta 를 그대로 쓴다(라운드 사이 비교를 위해). 다르게 주면 멈춘다.
  - 피드백·이전 후보·meta 가 없거나 서로 맞지 않으면 생성하지 않고 종료 코드 1 (피드백을 꾸며 넣지 않는다).
  - 저장 이름은 <이전 후보 이름에서 -r<n> 을 뺀 것>-r<라운드>, meta 에 round·parent·feedback 을 남긴다.

사용: generate.py --scenario scenarios/req-001.json --mock > out/candidate.json
      generate.py --scenario scenarios/req-001.json --model qwen2.5:14b --seed 1 --save
      generate.py --scenario scenarios/req-006.json --feedback generated/req-006-qwen2.5-14b-s2.feedback.json --save
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.ir import ROOT, load_json, schema_errors  # noqa: E402
from generator import llm  # noqa: E402

PROMPTS = Path(__file__).resolve().parent / "prompts"
GENERATED = ROOT / "generated"


def _load_env_file(path=ROOT / ".env"):
    """.env 의 KEY=VALUE 를 환경변수로 읽는다. 이미 설정된 값은 덮지 않는다."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if value.strip():
            os.environ.setdefault(key.strip(), value.strip().strip("'\""))


_load_env_file()
DEFAULT_MODEL = os.environ.get("GEN_MODEL", "qwen2.5:14b")
DEFAULT_PROMPT = os.environ.get("GEN_PROMPT", "v2")
# temperature 0 이면 seed 를 바꿔도 출력이 같아 반복의 의미가 없다 (generated/README.md)
DEFAULT_TEMPERATURE = 0.7
# Ollama 기본 컨텍스트는 버전마다 다르고 넘치면 프롬프트 앞부분을 조용히 자른다. 고정하고 meta 에 남긴다
NUM_CTX = 8192
MAX_ATTEMPTS = 2  # 형식이 깨지면 재생성 1회 (계획서 리스크 대응)
# 피드백 문구(feedback_message)를 바꾸면 올린다. 시스템 프롬프트 버전(prompt_version)과 따로 meta 에 남긴다
FEEDBACK_VERSION = "f1"
STAGES = ("validation", "approval", "deploy")


def user_message(scenario):
    return "다음 요구사항을 구현하는 룰셋을 작성하라.\n\n" + "\n".join(f"- {r}" for r in scenario["requirements"])


def retry_message(problems):
    return "위 출력은 룰 형식을 어긴다. 아래 문제를 고친 룰셋 전체를 다시 작성하라.\n\n" + \
        "\n".join(f"- {p}" for p in problems)


def _endpoint(probe):
    port = f" {probe['port']}" if "port" in probe else ""
    return f"{probe['from_ip']} → {probe['to']} {probe['proto']}{port}"


def feedback_message(fb):
    """피드백 JSON -> 재생성 요청 문장. 근거(오류·이유·실패 프로브)가 없으면 ValueError."""
    stage = fb.get("stage")
    if stage == "validation":
        items = fb["validation"]["errors"]
        head = "위 룰셋은 룰 형식 검사에서 반려되어 방화벽에 적용하지 못했다. 오류:"
    elif stage == "approval":
        items = fb["validation"]["reasons"]
        head = "위 룰셋은 정적 검사에서 고위험으로 판정되어 방화벽에 적용하지 않았다. 이유:"
    elif stage == "deploy":
        items = [f"{_endpoint(p)}: " + ("차단되어야 하는데 통과했다" if p["expect"] == "block"
                                        else "허용되어야 하는데 차단됐다")
                 for p in fb["failed_probes"]]
        head = "위 룰셋을 방화벽에 적용하고 실제 통신을 시험했더니 아래 통신이 요구사항과 다르게 처리되어 되돌렸다."
    else:
        raise ValueError(f"알 수 없는 stage: {stage!r} ({', '.join(STAGES)} 중 하나여야 함)")
    if not items:
        raise ValueError(f"stage {stage} 인데 근거(오류·이유·실패 프로브)가 비어 있음")
    lines = [head, *(f"- {i}" for i in items)]
    if stage == "deploy":
        lines += ["", "'통과'는 방화벽이 그 통신을 허용했다는 뜻이다. 목적지가 그 포트를 열어 두지 않았더라도 "
                      "방화벽이 막지 않았으면 통과로 본다."]
    lines += ["", "위 문제를 고치고, 나머지 요구사항도 그대로 지키는 룰셋 전체를 다시 작성하라."]
    return "\n".join(lines)


def load_feedback(path, scenario_id):
    """피드백 파일 -> (피드백, 이전 후보 텍스트, 이전 meta). 맞지 않으면 ValueError."""
    path = Path(path)
    fb = load_json(path)
    if fb.get("scenario") != scenario_id:
        raise ValueError(f"피드백의 시나리오({fb.get('scenario')})가 --scenario({scenario_id})와 다름: {path}")
    prev, prev_meta = path.with_name(f"{fb['candidate']}.json"), path.with_name(f"{fb['candidate']}.meta.json")
    for f in (prev, prev_meta):
        if not f.exists():
            raise ValueError(f"피드백 대상 후보 파일 없음: {f}")
    meta = load_json(prev_meta)
    if meta.get("round", 1) != fb.get("round"):
        raise ValueError(f"피드백 round({fb.get('round')})와 이전 후보 meta round({meta.get('round', 1)})가 다름")
    text = prev.read_text(encoding="utf-8").strip()
    try:  # LLM 이 낸 형식({"rules": [...]})으로 되돌린다. scenario 는 생성기가 붙인 값이다
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            parsed.pop("scenario", None)
            text = json.dumps(parsed, ensure_ascii=False, indent=2)
    except ValueError:
        pass  # 파싱 실패로 반려된 후보는 원문 그대로 보여 준다
    feedback_message(fb)  # 근거가 비었으면 생성 전에 멈춘다
    return fb, text, meta


def to_candidate(text, scenario_id):
    """응답 텍스트 -> (후보 출력 텍스트, 문제 목록). 문제가 있어도 후보는 그대로 둬서 validator 가 반려하게 한다."""
    try:
        parsed = json.loads(text)
    except ValueError as ex:
        return text, [f"JSON 파싱 실패: {ex}"]
    if not isinstance(parsed, dict):
        return text, ["최상위가 객체가 아님"]
    ruleset = {"scenario": scenario_id, **parsed}
    try:
        problems = schema_errors(ruleset)
    except Exception as ex:  # rules 항목이 객체가 아니면 schema_errors 의 추가 검사가 예외를 낸다
        problems = [f"입력 구조 오류: {type(ex).__name__}: {ex}"]
    return json.dumps(ruleset, ensure_ascii=False, indent=2), problems


def generate(scenario, model, prompt, temperature, seed, client=None, feedback=None):
    """(후보 출력 텍스트, meta) 를 돌려준다. 생성 조건을 확인하지 못하면 GenerationError.

    feedback: load_feedback 의 결과에 파일 경로를 붙인 (피드백, 이전 후보 텍스트, 이전 meta, 경로). 주면 다음 라운드를 만든다.
    """
    client = client or llm.Client()
    digest, version = llm.environment(model, client)
    options = {"temperature": temperature, "seed": seed, "num_ctx": NUM_CTX}
    messages = [
        {"role": "system", "content": (PROMPTS / f"{prompt}.md").read_text(encoding="utf-8")},
        {"role": "user", "content": user_message(scenario)},
    ]
    if feedback:
        fb, prev_text, prev_meta, fb_path = feedback
        messages += [{"role": "assistant", "content": prev_text},
                     {"role": "user", "content": feedback_message(fb)}]
    attempts = []
    for _ in range(MAX_ATTEMPTS):
        text, info = llm.chat(messages, model, options, client)
        candidate, problems = to_candidate(text, scenario["id"])
        attempts.append({**info, "problems": problems})
        if not problems:
            break
        messages += [{"role": "assistant", "content": text}, {"role": "user", "content": retry_message(problems)}]
    meta = {
        "model": model,
        "digest": digest,
        "ollama_version": version,
        "temperature": temperature,
        "seed": seed,
        "prompt_version": prompt,
        "scenario": scenario["id"],
        "options": options,
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "attempts": attempts,
    }
    if feedback:
        meta.update(round=fb["round"] + 1, parent=fb["candidate"], feedback_version=FEEDBACK_VERSION,
                    feedback={"file": _rel(fb_path), "stage": fb["stage"], "source": fb.get("source")})
        if prev_meta.get("digest") != digest:
            print(f"경고: 이전 후보와 모델 digest 가 다름 ({prev_meta.get('digest')} → {digest})", file=sys.stderr)
    return candidate, meta


def _rel(path):
    path = Path(path).resolve()
    return str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)


def output_stem(scenario_id, model, seed, round=1):
    """generated/ 파일명: <시나리오>-<모델>-s<seed>[-r<라운드>]. 모델 태그의 ':' '/' 등은 '-' 로 바꾼다."""
    stem = f"{scenario_id}-{re.sub(r'[^A-Za-z0-9._-]+', '-', model)}-s{seed}"
    return stem if round == 1 else f"{stem}-r{round}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--mock", action="store_true", help="정답 룰셋을 그대로 출력")
    # --feedback 이면 기본값 대신 이전 후보의 meta 를 쓴다. 그래서 기본값은 None 으로 두고 아래에서 채운다
    ap.add_argument("--model", help=f"Ollama 모델 태그 (기본 GEN_MODEL 또는 {DEFAULT_MODEL})")
    ap.add_argument("--prompt", help=f"prompts/<버전>.md (기본 {DEFAULT_PROMPT})")
    ap.add_argument("--temperature", type=float, help=f"(기본 {DEFAULT_TEMPERATURE})")
    ap.add_argument("--seed", type=int, help="반복 회차 번호 (기본 1)")
    ap.add_argument("--save", action="store_true", help="generated/ 에 후보와 .meta.json 을 쓴다")
    ap.add_argument("--meta", help="meta 를 저장할 JSON 경로 (--save 없이 쓸 때)")
    ap.add_argument("--feedback", help="eval/feedback.py 가 만든 <후보>.feedback.json (다음 라운드 후보 생성)")
    args = ap.parse_args()

    scenario = load_json(args.scenario)
    if args.mock:
        ruleset = scenario["gold"]
        errors = schema_errors(ruleset)
        if errors:
            sys.exit("정답 룰셋이 스키마를 위반한다:\n" + "\n".join(errors))
        json.dump(ruleset, sys.stdout, ensure_ascii=False, indent=2)
        print()
        return

    feedback, rnd = None, 1
    given = {"model": args.model, "prompt": args.prompt, "temperature": args.temperature, "seed": args.seed}
    if args.feedback:
        try:
            fb, prev_text, prev_meta = load_feedback(args.feedback, scenario["id"])
        except (ValueError, KeyError, TypeError) as ex:
            sys.exit(f"피드백을 읽지 못함: {type(ex).__name__}: {ex}")
        inherited = {"model": prev_meta.get("model"), "prompt": prev_meta.get("prompt_version"),
                     "temperature": prev_meta.get("temperature"), "seed": prev_meta.get("seed")}
        conflict = [k for k, v in given.items() if v is not None and v != inherited[k]]
        if conflict:
            sys.exit(f"--feedback 은 이전 후보와 같은 조건으로만 만든다. 다른 값: {conflict} (이전 meta: {inherited})")
        if None in inherited.values():
            sys.exit(f"이전 후보 meta 에 생성 조건이 빠짐: {inherited}")
        given, rnd = inherited, fb["round"] + 1
        feedback = (fb, prev_text, prev_meta, Path(args.feedback))
    else:
        defaults = {"model": DEFAULT_MODEL, "prompt": DEFAULT_PROMPT, "temperature": DEFAULT_TEMPERATURE, "seed": 1}
        given = {k: defaults[k] if v is None else v for k, v in given.items()}
    model, prompt, temperature, seed = given["model"], given["prompt"], given["temperature"], given["seed"]

    if args.save:
        stem = GENERATED / output_stem(scenario["id"], model, seed, rnd)
        out, meta_path = stem.with_name(stem.name + ".json"), stem.with_name(stem.name + ".meta.json")
        if out.exists() or meta_path.exists():  # 생성 전에 확인한다 (14B 생성은 오래 걸린다)
            sys.exit(f"이미 있음: {out.relative_to(ROOT)} (같은 조건의 후보를 덮어쓰지 않는다)")
    try:
        candidate, meta = generate(scenario, model, prompt, temperature, seed, feedback=feedback)
    except llm.GenerationError as ex:
        sys.exit(f"생성 실패: {ex}")
    meta_text = json.dumps(meta, ensure_ascii=False, indent=2) + "\n"
    if args.save:
        GENERATED.mkdir(exist_ok=True)
        out.write_text(candidate + "\n", encoding="utf-8")
        meta_path.write_text(meta_text, encoding="utf-8")
        print(out.relative_to(ROOT))
        return
    if args.meta:
        Path(args.meta).write_text(meta_text, encoding="utf-8")
    print(candidate)


if __name__ == "__main__":
    main()
