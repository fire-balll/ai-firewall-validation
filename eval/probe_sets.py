#!/usr/bin/env python3
"""배치 결과의 프로브 통과율을 시나리오 프로브 v1 / v2 로 나눠 본다. (담당: 강윤서)

#74 에서 시나리오 프로브를 보강하며, 보강한 프로브에 "set": "v2" 를 붙이기로 했다 (없으면 v1).
prober 는 모든 프로브를 돌리고 결과에 set 을 남긴다 (#83). 여기서는 out/ 의 deploy.json 을 읽어
  by_kind            종류(gold·mutation·generated)·set 별 정상 통과율과 공격 차단율 (프로브 수 기준)
  candidates         실행마다 set 별 통과·전체 수와, v1 프로브가 모두 통과했는지(v1_pass)
  v2_only_failures   v1 은 모두 통과했는데 v2 에서 실패한 실행 = v1 만으로는 드러나지 않은 오류
를 낸다. 2라운드 후보(meta.round 2)는 피드백에 v1 실패만 들어갔으므로 v2 가 hold-out 채점이 된다.

deploy.json 의 프로브 결과는 마지막 회차다. 롤백된 실행은 실패가 처음 보인 회차이므로, v1_pass 는
"그 회차에 v1 이 모두 통과했다"는 뜻이다. 배포 단계까지 가지 않은 실행(검증 반려·승인 거부)은 프로브
결과가 없어 not_probed 에 상태별 수만 남긴다. aborted 는 세지 않고 시나리오·후보별 수를 함께 낸다.

아래 경우는 결과를 내지 않고 종료 코드 1 (AGENTS.md 핵심 원칙):
  manifest 가 끝나지 않음, 커밋 안 된 변경으로 돌린 배치(--allow-dirty 없이), deploy.json 이나
  프로브 결과가 없음, 프로브 결과에 set 이 없음(#83 이전 prober 로 돈 배치), manifest status 와
  deploy.json 의 rolled_back·프로브 통과가 맞지 않음
사용: probe_sets.py eval/results/batch-<id>.json
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.ir import ROOT, load_json  # noqa: E402

PROBED = ("applied", "rolled_back")


class ProbeSetsError(Exception):
    """나눠 볼 근거가 부족하다. 결과를 꾸미지 않고 멈춘다."""


def kind(run):
    if run["candidate"] == "gold":
        return "gold"
    return "generated" if "meta" in run else "mutation"


def probe_results(run):
    """실행 하나의 프로브 결과. manifest status 와 맞지 않으면 ProbeSetsError."""
    name = f"{run['candidate']} r{run['rep']}"
    path = ROOT / run["out"] / "deploy.json"
    if not path.exists():
        raise ProbeSetsError(f"{name}: deploy.json 없음: {path}")
    deploy = load_json(path)
    results = (deploy.get("probe") or {}).get("results")
    if not results:
        raise ProbeSetsError(f"{name}: deploy.json 에 프로브 결과 없음")
    if bool(deploy.get("rolled_back")) != (run["status"] == "rolled_back"):
        raise ProbeSetsError(f"{name}: status {run['status']} 와 deploy.json rolled_back 이 다름")
    if all(r["pass"] for r in results) != (run["status"] == "applied"):
        raise ProbeSetsError(f"{name}: status {run['status']} 인데 실패한 프로브 수가 맞지 않음")
    for r in results:
        if "set" not in r:
            raise ProbeSetsError(f"{name}: 프로브 {r['id']} 결과에 set 없음 (#83 이전 prober 로 돈 배치)")
    return results


def _rate(passed, total):
    return {"pass": passed, "total": total, "rate": round(passed / total, 4) if total else None}


def build(manifest, batch_id):
    counts = defaultdict(lambda: defaultdict(Counter))  # kind -> set -> {normal_pass, normal, attack_pass, attack}
    candidates, v2_only, aborted, not_probed = [], [], Counter(), Counter()
    for run in manifest["runs"]:
        if run["status"] == "aborted":
            aborted[(run["scenario"], run["candidate"])] += 1
            continue
        if run["status"] not in PROBED:
            not_probed[run["status"]] += 1
            continue
        k = kind(run)
        sets = defaultdict(Counter)
        failed = defaultdict(list)
        for r in probe_results(run):
            c = sets[r["set"]]
            c["total"] += 1
            c["pass"] += r["pass"]
            counts[k][r["set"]][r["kind"]] += 1
            counts[k][r["set"]][f"{r['kind']}_pass"] += r["pass"]
            if not r["pass"]:
                failed[r["set"]].append(r["id"])
        v1_pass = not failed["v1"]
        candidates.append({"scenario": run["scenario"], "candidate": run["candidate"], "rep": run["rep"],
                           "kind": k, "round": (run.get("meta") or {}).get("round"), "status": run["status"],
                           "v1_pass": v1_pass, "sets": {s: dict(c) for s, c in sorted(sets.items())}})
        if v1_pass and failed["v2"]:
            v2_only.append({"scenario": run["scenario"], "candidate": run["candidate"], "rep": run["rep"],
                            "failed": failed["v2"]})
    return {
        "batch_id": batch_id, "commit": manifest["commit"],
        "by_kind": {k: {s: {p: _rate(c[f"{p}_pass"], c[p]) for p in ("normal", "attack")}
                        for s, c in sorted(by_set.items())}
                    for k, by_set in sorted(counts.items())},
        "v2_only_failures": v2_only,
        "not_probed": dict(sorted(not_probed.items())),
        "aborted": [{"scenario": s, "candidate": c, "count": n} for (s, c), n in sorted(aborted.items())],
        "candidates": candidates,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("manifest", help="eval/results/batch-<id>.json")
    ap.add_argument("--allow-dirty", action="store_true", help="커밋 안 된 변경으로 돌린 배치도 쓴다 (실험용 아님)")
    args = ap.parse_args()

    path = Path(args.manifest)
    try:
        manifest = load_json(path)
        if not manifest.get("finished"):
            raise ProbeSetsError(f"끝나지 않은 배치 (finished 없음): {path}")
        if manifest.get("dirty") and not args.allow_dirty:
            raise ProbeSetsError(f"커밋 안 된 변경으로 돌린 배치: {path} (--allow-dirty 로만 허용)")
        result = build(manifest, path.stem.removeprefix("batch-"))
    except (ProbeSetsError, FileNotFoundError) as e:
        sys.exit(f"프로브 v1/v2 계산 중단: {e}")
    json.dump(result, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
