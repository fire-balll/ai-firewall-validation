#!/usr/bin/env python3
"""정적 검증 + 위험도 판정. (담당: 양경찬)

현재 구현: 스키마 검사, 포트 값 검사, nft 문법 검사(--nft-check, fw 컨테이너 필요),
문서 2-2의 고위험 기준 중 범위 기준, 룰 간 이상 탐지 4종(anomalies.py, 기준은 README.md).
TODO: 기존 룰셋과의 충돌 검사

출력: {"ok": bool, "errors": [...], "risk": "low"|"high", "reasons": [...], "anomalies": [...]}
  reasons 는 risk=high 를 만든 이유만 담는다. anomalies 는 risk 가 low 인 참고 항목까지 모두 담는다.
  분석 중 예외가 나거나 입력이 JSON·룰셋 구조가 아니면 fail-closed 로 ok=false 를 낸다.
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
from common.lab import FW, PODMAN  # noqa: E402
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
        if r["proto"] in ("tcp", "udp") and r["dport"] in ("any", "0-65535"):  # 같은 범위의 다른 표기
            reasons.append(f"{r['id']}: 모든 포트 accept")
        if r["proto"] == "any":
            reasons.append(f"{r['id']}: 모든 프로토콜 accept")
    return reasons


def nft_check(ruleset):
    # common.lab.exec_in 은 text=True 라 Windows 에서 stdin 의 \n 이 \r\n 으로 바뀌고 nft 가 \r 을
    # 문법 오류로 본다. 같은 PODMAN·FW 설정으로 UTF-8 bytes 를 직접 넘긴다.
    try:
        res = subprocess.run(
            [*PODMAN, "exec", "-i", FW, "nft", "-c", "-f", "-"],
            input=to_nft(ruleset).encode("utf-8"), capture_output=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as ex:  # fail-closed: 검사 못 하면 통과로 보지 않는다
        return [f"nft -c 실행 실패: {type(ex).__name__}: {ex}"]
    if res.returncode == 0:
        return []
    return [f"nft -c: {res.stderr.decode('utf-8', errors='replace').strip()}"]


def rejected(errors):
    return {"ok": False, "errors": errors, "risk": None, "reasons": [], "anomalies": []}


def input_errors(ruleset):
    """스키마 검사. 최상위가 배열이거나 rules 항목이 객체가 아니면 schema_errors 의 추가 검사가
    예외를 내므로, 이때도 통과시키지 않고 오류로 돌려준다(fail-closed)."""
    try:
        return schema_errors(ruleset)
    except Exception as ex:
        return [f"입력 구조 오류(룰셋 객체와 rules 배열이 아님): {type(ex).__name__}: {ex}"]


def validate(ruleset, nft=False):
    errors = input_errors(ruleset)
    if not errors:
        errors = port_errors(ruleset)
    if not errors and nft:
        errors += nft_check(ruleset)

    out = rejected(errors)
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

    # JSON 문법·인코딩 오류는 후보가 틀린 것이므로 ok=false 로 낸다. 파일 없음(OSError)은 실행 실패로 둔다
    try:
        ruleset = load_json(args.ruleset)
    except ValueError as ex:
        out = rejected([f"입력 JSON 파싱 실패: {type(ex).__name__}: {ex}"])
    else:
        out = validate(ruleset, nft=args.nft_check)
    json.dump(out, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
