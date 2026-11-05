#!/usr/bin/env python3
"""배치 결과를 시나리오·후보별로 집계한다: 반복 실행의 평균·표준편차, 상태별 수, aborted 수. (담당: 강윤서)

입력은 배치 manifest(eval/results/batch-<id>.json)와 결과 CSV(eval/results/results.csv)다.
manifest 의 실행과 CSV 한 줄을 (batch_id, rep, scenario, generator) 로 잇는다. generator 는 run.sh·batch.py 가
쓰는 값과 같게 만든다: gold "mock", 오류 주입 "file:<이름>", 생성 후보 batch.generator_label(meta).

집계 단위는 (배치, 시나리오, 후보)다. 같은 후보라도 배치가 다르면 다른 실험이라 합치지 않는다.
  runs·aborted·status  manifest 기준. aborted 는 CSV 에 없으므로 여기서만 보인다 (AGENTS.md)
  지표              normal_pass_rate, attack_block_rate, detect_s, mttr_s, semantic_match
                    값이 있는 실행만으로 mean·std(표본 표준편차, 2회 이상일 때)·n 을 낸다.
                    검증 반려는 프로브 지표가 비어 있고, 롤백된 실행만 detect_s·mttr_s 가 있다
  policy_diff       정답과 다른 정책인 실행 수
배치마다 종류별(gold·mutation·generated) 합계도 낸다.

아래 경우는 결과를 내지 않고 종료 코드 1 (AGENTS.md 핵심 원칙):
  manifest 가 끝나지 않음, 커밋 안 된 변경으로 돌린 배치(--allow-dirty 없이),
  aborted 가 아닌 실행에 맞는 CSV 줄이 없거나 둘 이상, aborted 실행의 CSV 줄이 있음,
  manifest 에 없는 CSV 줄이 그 배치에 있음 (일부만 관측된 배치로 평균을 내지 않는다)

출력: {"batches": [{"batch_id", "commit", "runs", "aborted", "status", "kinds"}], "groups": [...]}
--csv-out 을 주면 groups 를 한 줄씩 CSV 로도 쓴다 (그래프·표용).
사용: summary.py eval/results/batch-*.json [--results eval/results/results.csv] [--csv-out out/summary.csv]
"""

import argparse
import csv
import json
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.ir import load_json  # noqa: E402
from pipeline.batch import generator_label  # noqa: E402

RESULTS = Path(__file__).resolve().parent / "results" / "results.csv"
METRICS = ("normal_pass_rate", "attack_block_rate", "detect_s", "mttr_s", "semantic_match")
STATUSES = ("applied", "rolled_back", "rejected_validation", "rejected_approval", "aborted")


class SummaryError(Exception):
    """집계할 근거가 부족하다. 결과를 꾸미지 않고 멈춘다."""


def kind(run):
    if run["candidate"] == "gold":
        return "gold"
    return "generated" if "meta" in run else "mutation"


def label(run):
    """manifest 실행 -> CSV generator 열 값"""
    k = kind(run)
    if k == "gold":
        return "mock"
    return generator_label(run["meta"]) if k == "generated" else f"file:{run['candidate']}"


def stats(values):
    vals = [float(v) for v in values if v != ""]
    if not vals:
        return {"mean": None, "std": None, "n": 0}
    std = round(statistics.stdev(vals), 4) if len(vals) > 1 else None
    return {"mean": round(statistics.fmean(vals), 4), "std": std, "n": len(vals)}


def summarize(runs_rows):
    """[(manifest 실행, CSV 줄 또는 None)] -> 지표 요약"""
    rows = [row for _, row in runs_rows if row is not None]
    status = Counter(run["status"] for run, _ in runs_rows)
    out = {"runs": len(runs_rows), "aborted": status["aborted"],
           "status": {s: status[s] for s in STATUSES if status[s]}}
    out.update({m: stats([r[m] for r in rows]) for m in METRICS})
    out["policy_diff"] = sum(r["policy_diff"] == "True" for r in rows)
    return out


def match(manifest, batch_id, rows):
    """manifest 실행마다 CSV 줄을 하나씩 짝짓는다. 맞지 않으면 SummaryError."""
    index = defaultdict(list)
    for r in rows:
        index[(r["rep"], r["scenario"], r["generator"])].append(r)
    pairs, used = [], 0
    for run in manifest["runs"]:
        key = (str(run["rep"]), run["scenario"], label(run))
        found = index.get(key, [])
        name = f"{batch_id} {run['scenario']} {run['candidate']} r{run['rep']}"
        if run["status"] == "aborted":
            if found:
                raise SummaryError(f"{name}: aborted 인데 CSV 줄이 있음")
            pairs.append((run, None))
            continue
        if len(found) != 1:
            raise SummaryError(f"{name}: 맞는 CSV 줄이 {len(found)}개 (1개여야 함)")
        pairs.append((run, found[0]))
        used += 1
    if used != len(rows):
        raise SummaryError(f"{batch_id}: manifest 에 없는 CSV 줄이 {len(rows) - used}개 있음")
    return pairs


def build(manifests, rows):
    """manifests: [(batch_id, manifest)]. rows: 결과 CSV 전체."""
    by_batch = defaultdict(list)
    for r in rows:
        by_batch[r["batch_id"]].append(r)
    batches, groups = [], []
    for batch_id, manifest in manifests:
        pairs = match(manifest, batch_id, by_batch.get(batch_id, []))
        by_group, by_kind = defaultdict(list), defaultdict(list)
        for run, row in pairs:
            by_group[(run["scenario"], run["candidate"])].append((run, row))
            by_kind[kind(run)].append((run, row))
        total = summarize(pairs)
        batches.append({"batch_id": batch_id, "commit": manifest["commit"], "runs": total["runs"],
                        "aborted": total["aborted"], "status": total["status"],
                        "kinds": {k: summarize(v) for k, v in sorted(by_kind.items())}})
        for (scenario, candidate), rr in by_group.items():
            groups.append({"batch_id": batch_id, "scenario": scenario, "candidate": candidate,
                           "kind": kind(rr[0][0]), "generator": label(rr[0][0]), **summarize(rr)})
    return {"batches": batches, "groups": groups}


def write_csv(groups, path):
    cols = ["batch_id", "scenario", "candidate", "kind", "generator", "runs", "aborted", *STATUSES[:-1]]
    for m in METRICS:
        cols += [f"{m}_mean", f"{m}_std", f"{m}_n"]
    cols.append("policy_diff")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for g in groups:
            row = {k: g[k] for k in ("batch_id", "scenario", "candidate", "kind", "generator", "runs", "aborted",
                                     "policy_diff")}
            row.update({s: g["status"].get(s, 0) for s in STATUSES[:-1]})
            for m in METRICS:
                row.update({f"{m}_{k}": "" if g[m][k] is None else g[m][k] for k in ("mean", "std", "n")})
            w.writerow(row)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("manifests", nargs="+", help="eval/results/batch-<id>.json")
    ap.add_argument("--results", default=str(RESULTS), help="결과 CSV (기본 eval/results/results.csv)")
    ap.add_argument("--csv-out", help="groups 를 CSV 로도 쓸 경로")
    ap.add_argument("--allow-dirty", action="store_true", help="커밋 안 된 변경으로 돌린 배치도 쓴다 (실험용 아님)")
    args = ap.parse_args()

    try:
        manifests = []
        for p in map(Path, args.manifests):
            m = load_json(p)
            if not m.get("finished"):
                raise SummaryError(f"끝나지 않은 배치 (finished 없음): {p}")
            if m.get("dirty") and not args.allow_dirty:
                raise SummaryError(f"커밋 안 된 변경으로 돌린 배치: {p} (--allow-dirty 로만 허용)")
            manifests.append((p.stem.removeprefix("batch-"), m))
        if len({b for b, _ in manifests}) != len(manifests):
            raise SummaryError("같은 배치가 두 번 들어옴")
        with open(args.results, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        result = build(manifests, rows)
    except (SummaryError, FileNotFoundError) as e:
        sys.exit(f"집계 중단: {e}")
    if args.csv_out:
        write_csv(result["groups"], Path(args.csv_out))
    json.dump(result, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
