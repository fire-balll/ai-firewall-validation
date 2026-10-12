#!/usr/bin/env python3
"""정적 검증 + 위험도 판정. (담당: 양경찬)

현재 구현: 스키마 검사, 포트 값 검사, nft 문법 검사(--nft-check, fw 컨테이너 필요),
문서 2-2의 고위험 기준 중 범위 기준, 룰 간 이상 탐지 4종(anomalies.py, 기준은 README.md).
TODO: 기존 룰셋과의 충돌 검사

출력: {"ok": bool, "errors": [...], "risk": "low"|"high", "reasons": [...], "anomalies": [...]}
  reasons 는 risk=high 를 만든 이유만 담는다. anomalies 는 risk 가 low 인 참고 항목까지 모두 담는다.
  ok=false 는 후보 룰셋이 틀렸을 때만 낸다(JSON·룰셋 구조·스키마·포트·nft 문법 오류).
  검사 도구가 고장 나면(sudo·podman 실행 실패·시간 초과, nft 실행 완료 마커 없음) 결과 JSON 을 내지 않고
  종료코드 2 로 끝낸다. 분석기 내부 예외도 결과로 바꾸지 않고 그대로 올린다(비0 종료).
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
NFT_SYNTAX_ERROR = 1  # nft 가 룰셋을 거부할 때의 종료코드. 이것만 후보 오류로 본다
TOOL_FAILURE_EXIT = 2  # 검사 도구 고장 시 validate.py 종료코드
NFT_RC_MARKER = "__validator_nft_rc="  # nft 가 실행을 마쳤다는 표시. 뒤에 nft 종료코드가 붙는다
NFT_CHECK_SCRIPT = f'nft -c -f -; echo "{NFT_RC_MARKER}$?"'


class ToolError(RuntimeError):
    """검사 도구(podman·fw 컨테이너) 고장. 후보 룰셋의 문제가 아니므로 ok=false 로 바꾸지 않는다."""


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


def parse_nft_rc(res):
    """컨테이너 안 sh 가 끝에 찍은 NFT_RC_MARKER 에서 nft 종료코드를 읽는다. 없으면 None.

    sudo·podman 의 실패도 종료코드 1 을 낼 수 있어 podman 종료코드만으로는 nft 가 룰셋을 거부했는지
    알 수 없다. 마커가 있으면 nft 가 실제로 실행을 마쳤다는 뜻이다.
    """
    if res.returncode != 0:
        return None
    lines = res.stdout.decode("utf-8", errors="replace").strip().splitlines()
    if not lines or not lines[-1].startswith(NFT_RC_MARKER):
        return None
    value = lines[-1][len(NFT_RC_MARKER):]
    return int(value) if value.isascii() and value.isdigit() else None


def nft_check(ruleset):
    # 룰셋은 UTF-8 bytes 로 넘긴다(text 모드면 Windows 에서 \n 이 \r\n 으로 바뀌어 nft 가 문법 오류로 본다).
    # 실행 실패를 후보 오류와 구분해야 해서 common.lab.exec_in 대신 같은 PODMAN·FW 설정으로 직접 부른다.
    try:
        res = subprocess.run(
            [*PODMAN, "exec", "-i", FW, "sh", "-c", NFT_CHECK_SCRIPT],
            input=to_nft(ruleset).encode("utf-8"), capture_output=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as ex:  # 검사를 못 한 것이지 후보가 틀린 것이 아니다
        raise ToolError(f"nft -c 실행 실패: {type(ex).__name__}: {ex}") from ex
    stderr = res.stderr.decode("utf-8", errors="replace").strip()
    rc = parse_nft_rc(res)
    if rc == 0:
        return []
    if rc == NFT_SYNTAX_ERROR:
        return [f"nft -c: {stderr}"]
    # 마커 없음: sudo·podman 실패(1 포함), 컨테이너 없음(125), sh 없음(126/127), 시그널.
    # 마커가 1 이외: nft 없음(127)·강제 종료 등. 어느 쪽도 nft 가 룰셋을 거부했다는 근거가 아니다
    where = f"podman 종료코드 {res.returncode}" if rc is None else f"nft 종료코드 {rc}"
    raise ToolError(f"nft -c 실행 실패: {where}: {stderr}")


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
    # 입력 검사를 통과한 룰셋에서 분석기가 예외를 내면 분석기 버그다. ok=false 로 바꾸지 않고 그대로 올린다
    anomalies = find_anomalies(ruleset)
    reasons = risk_reasons(ruleset)
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
        try:
            out = validate(ruleset, nft=args.nft_check)
        except ToolError as ex:  # 결과 JSON 을 쓰지 않아야 pipeline 이 판정으로 기록하지 않는다
            print(f"validate.py: 검사 도구 실패: {ex}", file=sys.stderr)
            sys.exit(TOOL_FAILURE_EXIT)
    json.dump(out, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
