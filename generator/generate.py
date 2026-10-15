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
TODO: --feedback 으로 받은 검증·프로브 실패 내용을 프롬프트에 넣어 재생성

사용: generate.py --scenario scenarios/req-001.json --mock > out/candidate.json
      generate.py --scenario scenarios/req-001.json --model qwen2.5:14b --seed 1 --save
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
DEFAULT_PROMPT = os.environ.get("GEN_PROMPT", "v1")
# temperature 0 이면 seed 를 바꿔도 출력이 같아 반복의 의미가 없다 (generated/README.md)
DEFAULT_TEMPERATURE = 0.7
# Ollama 기본 컨텍스트는 버전마다 다르고 넘치면 프롬프트 앞부분을 조용히 자른다. 고정하고 meta 에 남긴다
NUM_CTX = 8192
MAX_ATTEMPTS = 2  # 형식이 깨지면 재생성 1회 (계획서 리스크 대응)


def user_message(scenario):
    return "다음 요구사항을 구현하는 룰셋을 작성하라.\n\n" + "\n".join(f"- {r}" for r in scenario["requirements"])


def retry_message(problems):
    return "위 출력은 룰 형식을 어긴다. 아래 문제를 고친 룰셋 전체를 다시 작성하라.\n\n" + \
        "\n".join(f"- {p}" for p in problems)


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


def generate(scenario, model, prompt, temperature, seed, client=None):
    """(후보 출력 텍스트, meta) 를 돌려준다. 생성 조건을 확인하지 못하면 GenerationError."""
    client = client or llm.Client()
    digest, version = llm.environment(model, client)
    options = {"temperature": temperature, "seed": seed, "num_ctx": NUM_CTX}
    messages = [
        {"role": "system", "content": (PROMPTS / f"{prompt}.md").read_text(encoding="utf-8")},
        {"role": "user", "content": user_message(scenario)},
    ]
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
    return candidate, meta


def output_stem(scenario_id, model, seed):
    """generated/ 파일명: <시나리오>-<모델>-s<seed>. 모델 태그의 ':' '/' 등은 '-' 로 바꾼다."""
    return f"{scenario_id}-{re.sub(r'[^A-Za-z0-9._-]+', '-', model)}-s{seed}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--mock", action="store_true", help="정답 룰셋을 그대로 출력")
    ap.add_argument("--model", default=DEFAULT_MODEL, help="Ollama 모델 태그 (기본 GEN_MODEL 또는 %(default)s)")
    ap.add_argument("--prompt", default=DEFAULT_PROMPT, help="prompts/<버전>.md (기본 %(default)s)")
    ap.add_argument("--temperature", type=float, default=DEFAULT_TEMPERATURE)
    ap.add_argument("--seed", type=int, default=1, help="반복 회차 번호 (기본 %(default)s)")
    ap.add_argument("--save", action="store_true", help="generated/ 에 후보와 .meta.json 을 쓴다")
    ap.add_argument("--meta", help="meta 를 저장할 JSON 경로 (--save 없이 쓸 때)")
    ap.add_argument("--feedback", help="이전 검증/프로브 결과 JSON (재생성용, 아직 미구현)")
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

    if args.feedback:
        sys.exit("--feedback 재생성은 아직 구현되지 않았다.")
    if args.save:
        stem = GENERATED / output_stem(scenario["id"], args.model, args.seed)
        out, meta_path = stem.with_name(stem.name + ".json"), stem.with_name(stem.name + ".meta.json")
        if out.exists() or meta_path.exists():  # 생성 전에 확인한다 (14B 생성은 오래 걸린다)
            sys.exit(f"이미 있음: {out.relative_to(ROOT)} (같은 조건의 후보를 덮어쓰지 않는다)")
    try:
        candidate, meta = generate(scenario, args.model, args.prompt, args.temperature, args.seed)
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
