#!/usr/bin/env python3
"""실행 1회의 결과를 CSV 한 줄로 기록한다. (담당: 강윤서)

현재 구현: 정상 통과율, 공격 차단율, 롤백 여부, MTTR, 상태 추적 여부
TODO: 정답 룰셋 대비 의미 일치율(테스트 패킷 샘플링), 동적 추가 탐지율

사용: evaluate.py --scenario req-001 --generator mock \
        --validation out/validation.json --deploy out/deploy.json
"""

import argparse
import csv
import datetime as dt
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.ir import load_json  # noqa: E402

RESULTS = Path(__file__).resolve().parent / "results" / "results.csv"
FIELDS = ["timestamp", "scenario", "generator", "stateful", "valid", "risk", "approved",
          "normal_pass_rate", "attack_block_rate", "rolled_back", "detect_s", "mttr_s"]


def rate(results, kind):
    xs = [r for r in results if r["kind"] == kind]
    return round(sum(r["pass"] for r in xs) / len(xs), 3) if xs else ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True)
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
    }

    new = not RESULTS.exists()
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    with RESULTS.open("a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if new:
            w.writeheader()
        w.writerow(row)
    print(f"기록: {RESULTS}")


if __name__ == "__main__":
    main()
