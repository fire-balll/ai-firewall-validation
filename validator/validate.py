#!/usr/bin/env python3
"""정적 검증 + 위험도 판정. (담당: 양경찬)

현재 구현: 스키마 검사, 포트 값 검사, nft 문법 검사(--nft-check, fw 컨테이너 필요),
문서 2-2의 고위험 기준 중 범위 기준, 룰 간 이상 탐지 4종(anomalies.py, 기준은 README.md).
TODO: 기존 룰셋과의 충돌 검사

출력: {"ok": bool, "errors": [...], "risk": "low"|"high", "reasons": [...], "anomalies": [...]}
  reasons 는 risk=high 를 만든 이유만 담는다. anomalies 는 risk 가 low 인 참고 항목까지 모두 담는다.
  분석 중 예외가 나면 fail-closed 로 ok=false 를 낸다.
사용: validate.py out/candidate.json [--nft-check] > out/validation.json
"""

import argparse
import ipaddress
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.ir import load_json, schema_errors, to_nft  # noqa: E402
from common.lab import FW, exec_in  # noqa: E402
from validator.anomalies import find_anomalies, port_errors  # noqa: E402

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
    try:
        res = exec_in(FW, "nft", "-c", "-f", "-", stdin=to_nft(ruleset))
    except (OSError, subprocess.SubprocessError) as ex:  # fail-closed: 검사 못 하면 통과로 보지 않는다
        return [f"nft -c 실행 실패: {type(ex).__name__}: {ex}"]
    return [] if res.returncode == 0 else [f"nft -c: {res.stderr.strip()}"]


def validate(ruleset, nft=False):
    errors = schema_errors(ruleset)
    if not errors:
        errors = port_errors(ruleset)
    if not errors and nft:
        errors += nft_check(ruleset)

    out = {"ok": False, "errors": errors, "risk": None, "reasons": [], "anomalies": []}
    if errors:
        return out
    try:
        anomalies = find_anomalies(ruleset)
        reasons = risk_reasons(ruleset)
    except Exception as ex:  # fail-closed: 분석하지 못한 룰셋은 통과시키지 않는다
        out["errors"] = [f"정적 분석 실패: {type(ex).__name__}: {ex}"]
        return out
    reasons += [f"{a['rules'][1]}: {a['type']} - {a['detail']}" for a in anomalies if a["risk"] == "high"]
    out.update(ok=True, risk="high" if reasons else "low", reasons=reasons, anomalies=anomalies)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ruleset")
    ap.add_argument("--nft-check", action="store_true", help="fw 컨테이너에서 nft -c 로 문법 검사")
    args = ap.parse_args()

    out = validate(load_json(args.ruleset), nft=args.nft_check)
    json.dump(out, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
