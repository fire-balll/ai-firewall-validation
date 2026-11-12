#!/usr/bin/env python3
"""배치 결과로 동적 추가 탐지율을 계산한다. (담당: 강윤서)

동적 추가 탐지율 = 정적 검증을 통과한 오류 중 동적 검증(프로브 실패 → 롤백)만 잡은 비율.
대상은 오류 주입 룰셋(mutations/)이다. 정답과 다르다는 것이 확실한 룰셋은 이것뿐이다.

실행(rep) 하나를 아래 중 하나로 센다.
  static   정적 검증이 잡음: validation.json 의 ok=false 또는 risk=high (mutations/README.md 의 "잡힘")
  dynamic  정적 검증을 통과했고, 적용 뒤 프로브가 실패해 롤백됨
  missed   정적 검증을 통과했고, 적용 뒤 모든 프로브가 통과함 (오류가 그대로 남음)
비율 = dynamic / (dynamic + missed). static 은 분모에 넣지 않는다.

랩에서 관측할 수 없는 오류는 분모에서 뺀다 (AGENTS.md, scenarios/coverage.py #13).
오류 주입 파일마다 실행 전에 정한다:
  equivalent    어떤 패킷에도 정답과 같은 정책 (validator/compare.py 의 전체 비교로 차이 0)
  unobservable  정답과 다르지만, 랩 호스트 사이의 tcp·icmp 프로브와 UDP 에코 서비스로 가는 udp 프로브로는
                차이가 안 난다 (coverage.py 의 lab_probes, 판정은 common/sim.py). 에코 서비스가 아닌 udp 포트는
                차단이면 prober 가 실행 실패로 끝나 관측할 수 없다 (#62)
  observable    랩 프로브로 차이가 난다. 시나리오에 그 프로브가 없어 놓친 것(uncovered)도 여기 들어간다
state 유형(파일명으로 상태 추적 룰을 뺌)은 IR 이 정답과 같아 시뮬레이터로는 같게 나오지만, 정상 프로브가
실패하는 것이 랩에서 확인됐다(#23). 그래서 observable 로 두고, state 를 뺀 비율도 따로 낸다.

aborted 실행은 세지 않고 시나리오·후보별 수를 함께 낸다. 같은 후보의 rep 끼리 결과가 다르면 inconsistent 에 적는다.
unobservable·equivalent 로 분류한 후보가 롤백되면 분류나 랩이 틀린 것이므로 anomalies 에 적는다.

아래 경우는 결과를 내지 않고 종료 코드 1 (AGENTS.md 핵심 원칙):
  manifest 가 끝나지 않음, 커밋 안 된 변경으로 돌린 배치(--allow-dirty 없이), 오류 주입 파일·시나리오·
  실행 산출물이 없음, manifest status 와 산출물이 맞지 않음, 정답과의 전체 비교를 할 수 없음

출력: {"batch_id", "commit", "rate", "rate_without_state", "by_type", "excluded", "aborted", "inconsistent",
       "anomalies", "candidates": [...]}
사용: detection.py eval/results/batch-20261030-090000.json
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.ir import ROOT, load_json, stateful_for  # noqa: E402
from common.topology import hosts, udp_echo  # noqa: E402
from scenarios.coverage import lab_probes, probe_ports, verdicts  # noqa: E402
from validator.compare import ComparisonUnavailable, compare_offline  # noqa: E402

MUTATIONS = ROOT / "mutations"
SCENARIOS = ROOT / "scenarios"


class DetectionError(Exception):
    """탐지율을 낼 근거가 부족하다. 결과를 꾸미지 않고 멈춘다."""


def _read(path, what):
    if not path.exists():
        raise DetectionError(f"{what} 없음: {path}")
    return load_json(path)


def mutation_type(scenario, candidate):
    """req-002-port-any-01 -> port-any"""
    return candidate.removeprefix(f"{scenario}-").rsplit("-", 1)[0]


def observability(gold, mutant, path, host_ips):
    """오류 주입 파일 하나를 equivalent·unobservable·observable 로 나눈다."""
    if not stateful_for(path):
        return "observable"  # state 유형: IR 은 정답과 같지만 랩에서 정상 프로브가 실패한다 (#23)
    universe = lab_probes(host_ips, probe_ports(gold["rules"] + mutant["rules"]), udp_echo())
    if verdicts(gold["rules"], universe, host_ips) != verdicts(mutant["rules"], universe, host_ips):
        return "observable"
    try:
        r = compare_offline(gold, mutant, before_stateful=True, after_stateful=True)
    except ComparisonUnavailable as e:
        raise DetectionError(f"{path.name}: 정답과 전체 비교를 할 수 없음 ({e})")
    changed = r["counts"]["allow_to_block"] + r["counts"]["block_to_allow"]
    return "unobservable" if changed else "equivalent"


def outcome(run):
    """실행 하나 -> static | dynamic | missed. manifest status 와 산출물이 맞지 않으면 DetectionError."""
    out = ROOT / run["out"]
    v = _read(out / "validation.json", "validation.json")
    caught = not v["ok"] or v.get("risk") == "high"
    status = run["status"]
    if status.startswith("rejected_"):
        if not caught:
            raise DetectionError(f"{run['candidate']} r{run['rep']}: {status} 인데 정적 검증이 잡지 않음 ({out})")
        return "static"
    deploy = _read(out / "deploy.json", "deploy.json")
    if bool(deploy.get("rolled_back")) != (status == "rolled_back"):
        raise DetectionError(f"{run['candidate']} r{run['rep']}: status {status} 와 deploy.json rolled_back 이 다름")
    if caught:
        return "static"  # --approve yes 로 고위험도 적용한 배치. 정적 검증이 이미 잡았다
    return "dynamic" if status == "rolled_back" else "missed"


def _rate(counts):
    d = counts["dynamic"] + counts["missed"]
    return {"dynamic": counts["dynamic"], "missed": counts["missed"], "denominator": d,
            "value": round(counts["dynamic"] / d, 4) if d else None}


def build(manifest, batch_id, host_ips):
    runs = [r for r in manifest["runs"] if (MUTATIONS / f"{r['candidate']}.json").exists() and "meta" not in r]
    golds = {}
    classes = {}
    by_cand = defaultdict(list)
    aborted = Counter()
    for run in runs:
        name = run["candidate"]
        if name not in classes:
            sc = run["scenario"]
            if sc not in golds:
                golds[sc] = _read(SCENARIOS / f"{sc}.json", "시나리오")["gold"]
            path = MUTATIONS / f"{name}.json"
            classes[name] = observability(golds[sc], load_json(path), path, host_ips)
        if run["status"] == "aborted":
            aborted[(run["scenario"], name)] += 1
            continue
        by_cand[name].append((run, outcome(run)))

    total, without_state = Counter(), Counter()
    by_type = defaultdict(Counter)
    excluded = defaultdict(list)
    candidates, inconsistent, anomalies = [], [], []
    for name in sorted(classes):
        results = by_cand.get(name, [])
        if not results:
            continue  # 모든 rep 이 aborted. aborted 에 남는다
        sc = results[0][0]["scenario"]
        mtype = mutation_type(sc, name)
        counts = Counter(o for _, o in results)
        cls = classes[name]
        candidates.append({"scenario": sc, "candidate": name, "type": mtype, "class": cls,
                           "reps": len(results), **{k: counts[k] for k in ("static", "dynamic", "missed")}})
        if len(counts) > 1:
            inconsistent.append({"candidate": name, "outcomes": {f"r{r['rep']}": o for r, o in results}})
        if cls != "observable":
            excluded[cls].append(name)
            if counts["dynamic"]:
                anomalies.append({"candidate": name, "class": cls, "dynamic": counts["dynamic"],
                                  "note": "랩 프로브로 차이가 없어야 하는데 롤백됨"})
            continue
        total.update(counts)
        by_type[mtype].update(counts)
        if mtype != "state":
            without_state.update(counts)

    return {
        "batch_id": batch_id, "commit": manifest["commit"],
        "rate": _rate(total), "rate_without_state": _rate(without_state),
        "static_caught": total["static"],
        "by_type": {t: dict(_rate(c), static=c["static"]) for t, c in sorted(by_type.items())},
        "excluded": {k: sorted(v) for k, v in sorted(excluded.items())},
        "aborted": [{"scenario": s, "candidate": c, "count": n} for (s, c), n in sorted(aborted.items())],
        "inconsistent": inconsistent, "anomalies": anomalies, "candidates": candidates,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("manifest", help="eval/results/batch-<id>.json")
    ap.add_argument("--allow-dirty", action="store_true", help="커밋 안 된 변경으로 돌린 배치도 쓴다 (실험용 아님)")
    args = ap.parse_args()

    path = Path(args.manifest)
    manifest = load_json(path)
    try:
        if not manifest.get("finished"):
            raise DetectionError(f"끝나지 않은 배치 (finished 없음): {path}")
        if manifest.get("dirty") and not args.allow_dirty:
            raise DetectionError(f"커밋 안 된 변경으로 돌린 배치: {path} (--allow-dirty 로만 허용)")
        result = build(manifest, path.stem.removeprefix("batch-"), hosts())
    except DetectionError as e:
        sys.exit(f"탐지율 계산 중단: {e}")
    json.dump(result, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
