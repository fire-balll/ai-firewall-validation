#!/usr/bin/env python3
"""실행 1회의 결과를 CSV 한 줄로 기록한다. (담당: 강윤서)

현재 구현: 정상 통과율, 공격 차단율, 롤백 여부, MTTR, 상태 추적 여부,
  정답 룰셋 대비 의미 일치율(eval/semantic.py): semantic_match, policy_diff, over_allow, over_block
배치 실행이면 pipeline/batch.py 가 넘기는 환경변수 BATCH_ID·REP·COMMIT 을 같이 기록해
결과 CSV 한 줄을 manifest(eval/results/batch-<BATCH_ID>.json)의 실행과 잇는다. 단독 실행이면 빈 값.
TODO: 동적 추가 탐지율

사용: evaluate.py --scenario req-001 --scenario-file scenarios/req-001.json --generator mock \
        --candidate out/candidate.json --validation out/validation.json --deploy out/deploy.json
"""

import argparse
import csv
import datetime as dt
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.ir import load_json, schema_errors  # noqa: E402
from eval.semantic import compare  # noqa: E402

RESULTS = Path(__file__).resolve().parent / "results" / "results.csv"
FIELDS = ["timestamp", "batch_id", "rep", "commit", "scenario", "generator", "stateful",
          "valid", "risk", "approved",
          "normal_pass_rate", "attack_block_rate", "rolled_back", "detect_s", "mttr_s",
          "semantic_match", "policy_diff", "over_allow", "over_block"]
SEMANTIC = ("semantic_match", "policy_diff", "over_allow", "over_block")


def semantic(scenario_file, candidate_file):
    """의미 일치율 열. 후보가 IR 스키마를 어기면(검증 반려) 비교할 정책이 없으므로 빈 값.
    정답 룰셋을 읽지 못하면 결과를 꾸미지 않고 실패한다."""
    candidate = load_json(candidate_file)
    if not isinstance(candidate, dict) or schema_errors(candidate):
        return dict.fromkeys(SEMANTIC, "")
    try:
        r = compare(load_json(scenario_file)["gold"], candidate)
    except (KeyError, ValueError) as e:
        sys.exit(f"의미 일치율 계산 실패 ({scenario_file}): {e!r}")
    return {"semantic_match": r["match_rate"], "policy_diff": r["policy_diff"],
            "over_allow": r["over_allow"], "over_block": r["over_block"]}


def rate(results, kind):
    xs = [r for r in results if r["kind"] == kind]
    return round(sum(r["pass"] for r in xs) / len(xs), 3) if xs else ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True, help="CSV 에 남길 시나리오 이름")
    ap.add_argument("--scenario-file", required=True, help="정답 룰셋(gold)이 든 시나리오 파일")
    ap.add_argument("--candidate", required=True, help="이 실행의 후보 룰셋 (out/candidate.json)")
    ap.add_argument("--generator", required=True, help="mock, 모델명 등")
    ap.add_argument("--validation", required=True)
    ap.add_argument("--deploy", help="검증 실패로 적용하지 않았으면 생략")
    ap.add_argument("--approved", default="", help="고위험 룰 사람 승인 여부")
    args = ap.parse_args()

    v = load_json(args.validation)
    d = load_json(args.deploy) if args.deploy else {}
    results = (d.get("probe") or {}).get("results", [])
    row = {
        "timestamp": dt.datetime.now().isoformat(timespec="seconds"),
        "batch_id": os.environ.get("BATCH_ID", ""),
        "rep": os.environ.get("REP", ""),
        "commit": os.environ.get("COMMIT", ""),
        "scenario": args.scenario,
        "generator": args.generator,
        # GENERATOR 를 직접 정하면 파일명의 -state- 가 generator 열에 안 남으므로 따로 기록한다.
        # 검증 반려·승인 거부로 적용하지 않았으면 deploy.json 이 없어 빈 값이다
        "stateful": d.get("stateful", ""),
        "valid": v["ok"],
        "risk": v["risk"] or "",
        "approved": args.approved,
        "normal_pass_rate": rate(results, "normal"),
        "attack_block_rate": rate(results, "attack"),
        "rolled_back": d.get("rolled_back", ""),
        "detect_s": d.get("detect_s") or "",
        "mttr_s": d.get("mttr_s") or "",
        **semantic(args.scenario_file, args.candidate),
    }

    new = not RESULTS.exists() or RESULTS.stat().st_size == 0
    if not new:
        # 열이 다른 예전 CSV 에 이어 쓰면 값이 엉뚱한 열에 들어가 결과가 조용히 섞인다
        with RESULTS.open(newline="") as f:
            header = next(csv.reader(f), None)
        if header != FIELDS:
            # batch.py 는 마지막 줄을 manifest 의 error 로 남기므로 원인을 마지막에 쓴다
            print(f"  파일: {header}\n  기대: {FIELDS}", file=sys.stderr)
            sys.exit(f"{RESULTS.name} 의 열이 지금 형식과 다름. 옮기거나 지운 뒤 다시 실행할 것")
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    with RESULTS.open("a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if new:
            w.writeheader()
        w.writerow(row)
    print(f"기록: {RESULTS}")


if __name__ == "__main__":
    main()
