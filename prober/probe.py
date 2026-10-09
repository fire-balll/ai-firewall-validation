#!/usr/bin/env python3
"""능동 프로빙. 실제로 연결을 맺어 허용/차단을 관측한다. (담당: 강윤서)

tcpreplay 는 쓰지 않는다: 상태 기반 방화벽에서 handshake 없는 재생은 차단으로 오측정된다.
방화벽 판정을 잰다: 서버의 포트가 닫혀 있어도 방화벽이 통과시켰으면(Connection refused) allow 다.

현재 구현: tcp(nc -vz), icmp(ping)
방화벽 drop 으로 확실한 경우(nc timed out, ping 응답 없음)만 block 으로 판정한다.
그 외 실패(컨테이너 꺼짐, 명령 없음, 주소 오류, 경로 없음 등)는 실행 실패로 보고
결과를 내지 않고 종료 코드 1 로 끝낸다. 실험 결과에 섞이지 않게 하기 위함.
종료 코드·메시지는 lab/Containerfile 이미지(debian bookworm netcat-openbsd, iputils-ping)에서 확인했다.

TODO: nmap 스캔, hping3 SYN 프로브(속도 제한 필수), 실패 사유 상세화

출력: {"results": [{"id", "kind", "expect", "observed", "pass"}...]}
사용: probe.py scenarios/req-001.json > out/probe.json
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.ir import load_json  # noqa: E402
from common.lab import exec_in  # noqa: E402

TIMEOUT_S = 2

# nc -v 는 사용 오류(주소·포트 오류)와 경로 없음에도 종료 코드 1 을 내므로 메시지로 구분한다.
#   timed out: 방화벽 drop (IR 의 action 은 accept/drop 뿐이라 reject 는 없다)
#   Connection refused: SYN 이 방화벽을 지나 서버가 RST 로 응답함 = 방화벽은 허용
NC_BLOCKED = "timed out"
NC_PASSED = "Connection refused"


class ProbeError(Exception):
    """프로브를 실행하지 못함. 허용/차단을 관측한 것이 아니다."""


def observe(proto, res):
    if res.returncode == 0:
        return "allow"
    if proto == "tcp" and res.returncode == 1:
        if NC_PASSED in res.stderr:
            return "allow"
        if NC_BLOCKED in res.stderr:
            return "block"
    if proto == "icmp" and res.returncode == 1:  # ping: 1 응답 없음, 2 오류
        return "block"
    return None


def run_probe(p):
    if p["proto"] == "tcp":
        cmd = ["nc", "-vz", "-w", str(TIMEOUT_S), p["to"], str(p["port"])]
    elif p["proto"] == "icmp":
        cmd = ["ping", "-c", "1", "-W", str(TIMEOUT_S), p["to"]]
    else:
        raise ValueError(f"{p['id']}: 지원하지 않는 proto {p['proto']}")
    res = exec_in(p["from"], *cmd, timeout=TIMEOUT_S + 10)
    observed = observe(p["proto"], res)
    if observed is None:
        lines = res.stderr.strip().splitlines()
        raise ProbeError(f"{p['id']}: 프로브 실행 실패 (exit {res.returncode}) "
                         f"{lines[-1] if lines else ''}".rstrip())
    return {
        "id": p["id"], "kind": p["kind"], "expect": p["expect"],
        "observed": observed, "pass": observed == p["expect"],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario")
    args = ap.parse_args()

    scenario = load_json(args.scenario)
    try:
        results = [run_probe(p) for p in scenario["probes"]]
    except ProbeError as e:
        sys.exit(str(e))
    json.dump({"results": results}, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
