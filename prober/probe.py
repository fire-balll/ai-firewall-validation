#!/usr/bin/env python3
"""능동 프로빙. 실제로 연결을 맺어 허용/차단을 관측한다. (담당: 강윤서)

tcpreplay 는 쓰지 않는다: 상태 기반 방화벽에서 handshake 없는 재생은 차단으로 오측정된다.
주의: expect=allow 프로브는 실제로 열려 있는 포트를 겨냥해야 한다. 닫힌 포트도 '차단'으로 관측된다.

현재 구현: tcp(nc -z), icmp(ping)
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


def run_probe(p):
    if p["proto"] == "tcp":
        cmd = ["nc", "-z", "-w", str(TIMEOUT_S), p["to"], str(p["port"])]
    elif p["proto"] == "icmp":
        cmd = ["ping", "-c", "1", "-W", str(TIMEOUT_S), p["to"]]
    else:
        raise ValueError(f"{p['id']}: 지원하지 않는 proto {p['proto']}")
    res = exec_in(p["from"], *cmd, timeout=TIMEOUT_S + 10)
    observed = "allow" if res.returncode == 0 else "block"
    return {
        "id": p["id"], "kind": p["kind"], "expect": p["expect"],
        "observed": observed, "pass": observed == p["expect"],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario")
    args = ap.parse_args()

    scenario = load_json(args.scenario)
    results = [run_probe(p) for p in scenario["probes"]]
    json.dump({"results": results}, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
