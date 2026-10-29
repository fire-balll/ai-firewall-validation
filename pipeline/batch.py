#!/usr/bin/env python3
"""시나리오 × 후보 룰셋 × 반복을 한 번에 실행하고, 실행 조건을 manifest 로 남긴다.

후보 룰셋:
  gold       시나리오의 정답 룰셋 (generator --mock)
  mutations  mutations/<시나리오>-*.json 오류 주입 룰셋
  generated  generated/<시나리오>-*.json LLM 생성 룰셋 (옆에 .meta.json 필수, 형식은 generated/README.md.
             .feedback.json 은 후보가 아니다)
  all        셋 다

generated 후보는 meta 의 모델·digest·temperature·seed·프롬프트 버전을 CSV generator 열에 남긴다.
meta 가 없거나 필드가 빠진 후보가 하나라도 있으면 아무것도 실행하지 않고 중단한다.

재현성을 위해 작업 트리가 깨끗해야 실행한다(커밋 해시를 기록하므로). --allow-dirty 로 무시할 수 있으나
그 결과는 실험 결과로 쓰지 않는다.

manifest: eval/results/batch-<시각>.json
  {"commit", "dirty", "args", "started", "finished", "runs": [{"scenario", "candidate", "rep", "status", "out", "meta"?}]}
  status: applied | rolled_back | rejected_validation | rejected_approval | aborted
  실행마다 out/batch-<시각>/<실행>/run.log 에 출력 전체를 남기고, aborted 는 manifest 에 마지막 에러 줄을 기록한다
사용: batch.py --candidates all --reps 3 --watch 10 --approve no
"""

import argparse
import datetime as dt
import glob
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATUS = {0: "applied", 3: "rejected_validation", 4: "rejected_approval"}
GENERATED = ROOT / "generated"
META_KEYS = ("model", "digest", "ollama_version", "temperature", "seed", "prompt_version")


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True).stdout.strip()


def now():
    return dt.datetime.now().isoformat(timespec="seconds")


def rolled_back(out):
    deploy = out / "deploy.json"
    return deploy.exists() and json.loads(deploy.read_text(encoding="utf-8")).get("rolled_back", False)


def candidates_for(scenario, kind):
    name = Path(scenario).stem
    out = []
    if kind in ("gold", "all"):
        out.append(None)  # None = 정답 룰셋 (mock)
    if kind in ("mutations", "all"):
        out += sorted(glob.glob(str(ROOT / "mutations" / f"{name}-*.json")))
    if kind in ("generated", "all"):
        # 후보 옆의 .meta.json(재현 조건)과 .feedback.json(eval/feedback.py 의 재생성 입력)은 후보가 아니다
        out += sorted(f for f in glob.glob(str(GENERATED / f"{name}-*.json"))
                      if not f.endswith((".meta.json", ".feedback.json")))
    return out


def is_generated(cand):
    return cand is not None and Path(cand).resolve().parent == GENERATED.resolve()


def _rel(path):
    """메시지용 경로. 저장소 밖이면 절대 경로 그대로."""
    try:
        return Path(path).resolve().relative_to(ROOT.resolve())
    except ValueError:
        return path


def _is_number(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


# 필드별 유효성. None·빈 문자열·잘못된 타입은 "재현 조건을 모름"과 같다
META_CHECKS = {
    "model": lambda v: isinstance(v, str) and v.strip() != "",
    "digest": lambda v: isinstance(v, str) and v.strip() != "",
    "ollama_version": lambda v: isinstance(v, str) and v.strip() != "",
    "temperature": _is_number,
    "seed": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "prompt_version": lambda v: isinstance(v, str) and v.strip() != "",
}


def load_meta(cand):
    """generated 후보의 meta. 없거나, 깨졌거나, 필드가 빠지거나 값이 비거나 타입이 틀리면 ValueError.

    round(피드백 루프 라운드)는 선택 필드로 없으면 1. 있으면 1 이상의 정수여야 한다.
    """
    path = Path(cand[: -len(".json")] + ".meta.json")
    if not path.exists():
        raise ValueError(f"meta 없음: {_rel(path)}")
    try:
        meta = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as e:
        raise ValueError(f"meta JSON 파싱 실패 ({e}): {_rel(path)}") from e
    if not isinstance(meta, dict):
        raise ValueError(f"meta 가 객체가 아님: {_rel(path)}")
    missing = [k for k in META_KEYS if k not in meta]
    if missing:
        raise ValueError(f"meta 필드 누락 {missing}: {_rel(path)}")
    invalid = [k for k in META_KEYS if not META_CHECKS[k](meta[k])]
    rnd = meta.get("round", 1)
    if not (isinstance(rnd, int) and not isinstance(rnd, bool) and rnd >= 1):
        invalid.append("round")
    if invalid:
        raise ValueError(f"meta 값이 비었거나 타입이 틀림 {invalid}: {_rel(path)}")
    if meta["temperature"] == 0:
        # 단독 기준 실행으로는 쓸 수 있어 막지는 않는다. 반복(seed 여러 개)이면 출력이 같아 의미가 없다
        print(f"경고: temperature 0 — seed 를 바꿔 반복해도 출력이 같을 수 있음: {_rel(path)}", file=sys.stderr)
    return dict(meta, round=rnd)


def generator_label(meta):
    """CSV generator 열에 들어갈 값. 쉼표 없이 한 칸에 재현 조건을 모두 담는다."""
    return (f"{meta['model']}@{str(meta['digest']).split(':')[-1][:12]}|t={meta['temperature']}"
            f"|seed={meta['seed']}|p={meta['prompt_version']}|r={meta.get('round', 1)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", default="scenarios/req-*.json")
    ap.add_argument("--candidates", choices=["gold", "mutations", "generated", "all"], default="all")
    ap.add_argument("--reps", type=int, default=1)
    ap.add_argument("--watch", type=int, default=10)
    ap.add_argument("--approve", choices=["yes", "no"], default="no",
                    help="고위험 룰을 승인한 것으로 볼지 (배치에서는 묻지 않는다)")
    ap.add_argument("--allow-dirty", action="store_true")
    args = ap.parse_args()

    # 커밋 안 된 새 파일(예: mutations/ 의 새 룰셋)도 실행 대상이 되므로 untracked 도 검사한다.
    # 결과 파일 자체는 실행할수록 바뀌므로 검사에서 뺀다
    dirty = bool(git("status", "--porcelain", "--", ".", ":(exclude)eval/results"))
    if dirty and not args.allow_dirty:
        sys.exit("커밋되지 않은 변경이 있다. 커밋 후 실행하거나 --allow-dirty (실험 결과로 쓰지 말 것)")

    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    manifest = {
        "commit": git("rev-parse", "HEAD"), "dirty": dirty, "args": vars(args),
        "started": now(), "finished": None, "runs": [],
    }
    path = ROOT / "eval" / "results" / f"batch-{stamp}.json"
    path.parent.mkdir(parents=True, exist_ok=True)

    scenarios = sorted(glob.glob(str(ROOT / args.scenarios)))
    if not scenarios:
        sys.exit(f"시나리오 없음: {args.scenarios}")

    # generated 후보의 meta 를 실행 전에 모두 확인한다. 재현 조건을 모르는 결과는 만들지 않는다
    metas = {}
    for scenario in scenarios:
        for cand in candidates_for(scenario, args.candidates):
            if is_generated(cand):
                try:
                    metas[cand] = load_meta(cand)
                except ValueError as e:
                    sys.exit(f"실행 중단: {e}")

    for scenario in scenarios:
        for cand in candidates_for(scenario, args.candidates):
            for rep in range(1, args.reps + 1):
                label = Path(cand).stem if cand else "gold"
                out = ROOT / "out" / f"batch-{stamp}" / f"{Path(scenario).stem}-{label}-r{rep}"
                # BATCH_ID·REP·COMMIT 은 결과 CSV 와 manifest 를 잇기 위한 값 (eval 쪽 반영은 별도 논의)
                env = dict(os.environ, WATCH=str(args.watch), APPROVE=args.approve, OUT_DIR=str(out),
                           BATCH_ID=stamp, REP=str(rep), COMMIT=manifest["commit"])
                if cand:
                    env["CANDIDATE"] = cand
                    if cand in metas:
                        env["GENERATOR"] = generator_label(metas[cand])
                    else:
                        env.pop("GENERATOR", None)
                else:
                    env.pop("CANDIDATE", None)
                    env["GENERATOR"] = "mock"
                res = subprocess.run([str(ROOT / "pipeline" / "run.sh"), scenario], cwd=ROOT,
                                     env=env, capture_output=True, text=True)
                out.mkdir(parents=True, exist_ok=True)
                (out / "run.log").write_text(res.stdout + res.stderr, encoding="utf-8")
                status = STATUS.get(res.returncode, "aborted")
                if status == "applied" and rolled_back(out):
                    status = "rolled_back"
                run = {
                    "scenario": Path(scenario).stem, "candidate": label, "rep": rep,
                    "status": status, "out": str(out.relative_to(ROOT)),
                }
                if cand in metas:
                    run["meta"] = metas[cand]
                if status == "aborted":
                    lines = (res.stderr or res.stdout).strip().splitlines()
                    run["error"] = lines[-1] if lines else f"exit {res.returncode}"
                manifest["runs"].append(run)
                print(f"{Path(scenario).stem:10} {label:28} r{rep} {status}", flush=True)
                path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    manifest["finished"] = now()
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    aborted = sum(r["status"] == "aborted" for r in manifest["runs"])
    print(f"manifest: {path.relative_to(ROOT)}  (실행 {len(manifest['runs'])}, 실행 실패 {aborted})")
    sys.exit(1 if aborted else 0)


if __name__ == "__main__":
    main()
