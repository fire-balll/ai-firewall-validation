#!/usr/bin/env python3
"""최종 결과 CSV: 배치·후보 종류마다 한 줄로 전 지표를 모은다. (담당: 강윤서)

입력은 이미 검증을 거친 집계 결과다. 여기서 CSV·manifest·산출물을 다시 읽거나 값을 채우지 않는다.
  summary.py 출력 JSON     배치·종류(gold·mutation·generated)별 실행 수, 상태별 수, aborted 수,
                           정상 통과율·공격 차단율·의미 일치율·감지 시간·MTTR 의 평균과 값이 있는 실행 수(n)
  detection.py 출력 JSON   오류 주입(mutation) 줄에만 붙인다: 위험 룰 탐지율, 동적 추가 탐지율(state 포함·제외)
                           (여러 개 가능, 배치마다 하나)
평균은 그 종류의 실행 전체를 한꺼번에 낸 값이다 (summary.py 의 kinds). detection 을 주지 않은 오류 주입
배치는 탐지율 칸을 비운다. 사람 검토 룰 수는 정적 검증 쪽 집계라 여기에 넣지 않는다.

아래 경우는 결과를 내지 않고 종료 코드 1 (AGENTS.md 핵심 원칙):
  입력에 필요한 키가 없음, detection 의 배치가 summary 에 없거나 commit 이 다름, 같은 배치의 detection 이 둘,
  detection 을 준 배치에 오류 주입 실행이 없음
사용: summary.py eval/results/batch-*.json > out/summary.json
      detection.py eval/results/batch-<오류 주입 배치>.json > out/detection-<id>.json
      final.py out/summary.json [--detection out/detection-*.json] [--out out/final.csv]
"""

import argparse
import csv
import json
import sys
from pathlib import Path

STATUSES = ("applied", "rolled_back", "rejected_validation", "rejected_approval", "aborted")
METRICS = ("normal_pass_rate", "attack_block_rate", "semantic_match", "detect_s", "mttr_s")
RATES = (("risk_detection", "risk_detection_rate"), ("dynamic_detection", "rate"),
         ("dynamic_detection_without_state", "rate_without_state"))
COLUMNS = ["batch_id", "commit", "kind", "runs", *STATUSES, *[f"{m}_{k}" for m in METRICS for k in ("mean", "n")],
           "policy_diff", *[c for name, _ in RATES for c in (f"{name}_rate", f"{name}_n")]]


class FinalError(Exception):
    """합칠 근거가 부족하다. 결과를 꾸미지 않고 멈춘다."""


def _need(d, key, where):
    if key not in d:
        raise FinalError(f"{where} 에 {key} 없음")
    return d[key]


def build(summary, detections):
    batches = {_need(b, "batch_id", "batch"): b for b in _need(summary, "batches", "summary")}
    by_batch = {}
    for d in detections:
        bid = _need(d, "batch_id", "detection")
        if bid not in batches:
            raise FinalError(f"detection {bid}: summary 에 없는 배치")
        if _need(d, "commit", bid) != batches[bid]["commit"]:
            raise FinalError(f"detection {bid}: summary 와 commit 이 다름")
        if bid in by_batch:
            raise FinalError(f"detection {bid}: 같은 배치가 두 번 들어옴")
        if "mutation" not in batches[bid]["kinds"]:
            raise FinalError(f"detection {bid}: 그 배치에 오류 주입 실행이 없음")
        by_batch[bid] = d
    rows = []
    for bid, b in batches.items():
        for kind, s in _need(b, "kinds", bid).items():
            where = f"{bid} {kind}"
            row = {"batch_id": bid, "commit": b["commit"], "kind": kind, "runs": _need(s, "runs", where),
                   "policy_diff": _need(s, "policy_diff", where)}
            row.update({st: _need(s, "status", where).get(st, 0) for st in STATUSES})
            for m in METRICS:
                v = _need(s, m, where)
                row.update({f"{m}_mean": "" if v["mean"] is None else v["mean"], f"{m}_n": v["n"]})
            d = by_batch.get(bid) if kind == "mutation" else None
            for name, key in RATES:
                r = _need(d, key, f"detection {bid}") if d else None
                row[f"{name}_rate"] = "" if r is None or r["value"] is None else r["value"]
                row[f"{name}_n"] = "" if r is None else r["denominator"]
            rows.append(row)
    return rows


def write_csv(rows, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("summary", help="summary.py 출력 JSON")
    ap.add_argument("--detection", nargs="*", default=[], help="detection.py 출력 JSON (배치마다 하나)")
    ap.add_argument("--out", default="out/final.csv")
    args = ap.parse_args()
    try:
        summary = json.loads(Path(args.summary).read_text(encoding="utf-8"))
        detections = [json.loads(Path(p).read_text(encoding="utf-8")) for p in args.detection]
        rows = build(summary, detections)
    except (FinalError, FileNotFoundError, json.JSONDecodeError) as e:
        sys.exit(f"최종 결과 중단: {e}")
    write_csv(rows, Path(args.out))
    print(args.out)


if __name__ == "__main__":
    main()
