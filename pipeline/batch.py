#!/usr/bin/env python3
"""시나리오 × 후보 룰셋 × 반복을 한 번에 실행하고, 실행 조건을 manifest 로 남긴다.

후보 룰셋:
  gold       시나리오의 정답 룰셋 (generator --mock)
  mutations  mutations/<시나리오>-*.json 오류 주입 룰셋
  all        둘 다

재현성을 위해 작업 트리가 깨끗해야 실행한다(커밋 해시를 기록하므로). --allow-dirty 로 무시할 수 있으나
그 결과는 실험 결과로 쓰지 않는다.

manifest: eval/results/batch-<시각>.json
  {"commit", "dirty", "args", "started", "finished", "runs": [{"scenario", "candidate", "rep", "status", "out"}]}
  status: applied | rejected_validation | rejected_approval | aborted
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


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True).stdout.strip()


def now():
    return dt.datetime.now().isoformat(timespec="seconds")


def candidates_for(scenario, kind):
    name = Path(scenario).stem
    out = []
    if kind in ("gold", "all"):
        out.append(None)  # None = 정답 룰셋 (mock)
    if kind in ("mutations", "all"):
        out += sorted(glob.glob(str(ROOT / "mutations" / f"{name}-*.json")))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", default="scenarios/req-*.json")
    ap.add_argument("--candidates", choices=["gold", "mutations", "all"], default="all")
    ap.add_argument("--reps", type=int, default=1)
    ap.add_argument("--watch", type=int, default=10)
    ap.add_argument("--approve", choices=["yes", "no"], default="no",
                    help="고위험 룰을 승인한 것으로 볼지 (배치에서는 묻지 않는다)")
    ap.add_argument("--allow-dirty", action="store_true")
    args = ap.parse_args()

    # 결과 파일 자체는 실행할수록 바뀌므로 검사에서 뺀다
    dirty = bool(git("status", "--porcelain", "--untracked-files=no", "--", ".", ":(exclude)eval/results"))
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

    for scenario in scenarios:
        for cand in candidates_for(scenario, args.candidates):
            for rep in range(1, args.reps + 1):
                label = Path(cand).stem if cand else "gold"
                out = ROOT / "out" / f"batch-{stamp}" / f"{Path(scenario).stem}-{label}-r{rep}"
                env = dict(os.environ, WATCH=str(args.watch), APPROVE=args.approve, OUT_DIR=str(out))
                if cand:
                    env["CANDIDATE"] = cand
                else:
                    env.pop("CANDIDATE", None)
                    env["GENERATOR"] = "mock"
                res = subprocess.run([str(ROOT / "pipeline" / "run.sh"), scenario], cwd=ROOT,
                                     env=env, capture_output=True, text=True)
                status = STATUS.get(res.returncode, "aborted")
                manifest["runs"].append({
                    "scenario": Path(scenario).stem, "candidate": label, "rep": rep,
                    "status": status, "out": str(out.relative_to(ROOT)),
                })
                print(f"{Path(scenario).stem:10} {label:28} r{rep} {status}", flush=True)
                path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    manifest["finished"] = now()
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    aborted = sum(r["status"] == "aborted" for r in manifest["runs"])
    print(f"manifest: {path.relative_to(ROOT)}  (실행 {len(manifest['runs'])}, 실행 실패 {aborted})")
    sys.exit(1 if aborted else 0)


if __name__ == "__main__":
    main()
