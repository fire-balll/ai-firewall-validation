#!/usr/bin/env python3
"""정적 검증 + 위험도 판정. (담당: 양경찬)

현재 구현: 스키마 검사, nft 문법 검사(--nft-check, fw 컨테이너 필요), 문서 2-2의 고위험 기준 중 범위 기준.
TODO: 4가지 이상 탐지(shadowing, redundancy, correlation, generalization)
TODO: 기존 룰셋과의 충돌 검사

출력: {"ok": bool, "errors": [...], "risk": "low"|"high", "reasons": [...]}
사용: validate.py out/candidate.json [--nft-check] > out/validation.json
"""

import argparse
import ipaddress
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.ir import load_json, schema_errors, to_nft  # noqa: E402
from common.lab import FW, exec_in  # noqa: E402

WIDE_PREFIX = 16  # 이보다 넓은 accept 는 고위험


def is_wide(addr):
    return addr == "any" or ipaddress.ip_network(addr).prefixlen < WIDE_PREFIX


def risk_reasons(ruleset):
    reasons = []
    for r in ruleset["rules"]:
        if r["action"] != "accept":
            continue
        if is_wide(r["src"]) or is_wide(r["dst"]):
            reasons.append(f"{r['id']}: accept 범위가 /{WIDE_PREFIX} 보다 넓음")
        if r["proto"] in ("tcp", "udp") and r["dport"] == "any":
            reasons.append(f"{r['id']}: 모든 포트 accept")
        if r["proto"] == "any":
            reasons.append(f"{r['id']}: 모든 프로토콜 accept")
    return reasons


def nft_check(ruleset):
    res = exec_in(FW, "nft", "-c", "-f", "-", stdin=to_nft(ruleset))
    return [] if res.returncode == 0 else [f"nft -c: {res.stderr.strip()}"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ruleset")
    ap.add_argument("--nft-check", action="store_true", help="fw 컨테이너에서 nft -c 로 문법 검사")
    args = ap.parse_args()

    ruleset = load_json(args.ruleset)
    errors = schema_errors(ruleset)
    if not errors and args.nft_check:
        errors += nft_check(ruleset)

    out = {"ok": not errors, "errors": errors, "risk": None, "reasons": []}
    if not errors:
        out["reasons"] = risk_reasons(ruleset)
        out["risk"] = "high" if out["reasons"] else "low"
    json.dump(out, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
