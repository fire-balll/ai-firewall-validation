#!/usr/bin/env python3
"""시뮬레이터(common/sim.py)와 실제 랩(prober)의 판정을 비교한다.

룰셋을 fw 에 적용하고 프로브를 돌린 뒤, 같은 룰셋을 시뮬레이터로 계산해 프로브별로 비교한다.
끝나면 적용 전 상태로 원복한다. 판정이 다르면 변환기·커널·상태 추적 쪽 차이이므로 원인을 확인해야 한다.

출력: {"agree": bool, "mismatches": [...], "sim": {...}, "lab": {...}}
사용: crosscheck.py --scenario scenarios/req-001.json [--ruleset 파일]  (ruleset 생략 시 정답 룰셋)
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from common.ir import load_json, to_nft  # noqa: E402
from common.lab import FW, exec_in  # noqa: E402
from common.sim import simulate  # noqa: E402


def nft_apply(text):
    res = exec_in(FW, "nft", "-f", "-", stdin=text)
    if res.returncode != 0:
        raise RuntimeError(f"nft -f 실패: {res.stderr.strip()}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--ruleset", help="생략하면 시나리오의 정답 룰셋")
    args = ap.parse_args()

    scenario = load_json(args.scenario)
    ruleset = load_json(args.ruleset) if args.ruleset else scenario["gold"]

    snap = exec_in(FW, "nft", "list", "ruleset")
    if snap.returncode != 0:
        sys.exit(f"nft list 실패: {snap.stderr.strip()}")
    saved = "flush ruleset\n" + snap.stdout

    nft_apply(to_nft(ruleset))
    try:
        res = subprocess.run([sys.executable, str(ROOT / "prober" / "probe.py"), args.scenario],
                             capture_output=True, text=True)
        if res.returncode != 0:
            sys.exit(f"prober 실패: {res.stderr.strip().splitlines()[-1:]}")
        lab = json.loads(res.stdout)
    finally:
        nft_apply(saved)

    sim = simulate(ruleset, scenario["probes"])
    lab_by_id = {r["id"]: r["observed"] for r in lab["results"]}
    mismatches = [
        {"id": r["id"], "sim": r["observed"], "lab": lab_by_id.get(r["id"])}
        for r in sim["results"] if r["observed"] != lab_by_id.get(r["id"])
    ]
    json.dump({"agree": not mismatches, "mismatches": mismatches, "sim": sim, "lab": lab},
              sys.stdout, ensure_ascii=False, indent=2)
    print()
    sys.exit(0 if not mismatches else 2)


if __name__ == "__main__":
    main()
