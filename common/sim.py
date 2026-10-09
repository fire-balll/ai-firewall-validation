#!/usr/bin/env python3
"""IR 룰셋 시뮬레이터. 실제 랩 없이 프로브 결과를 계산한다.

to_nft 가 만드는 룰셋과 같은 의미로 판정한다:
  - priority 오름차순 first-match, 매칭 없으면 drop (default deny)
  - 연결을 "시작하는" 패킷만 판정한다. 응답 트래픽은 맨 앞의
    ct state established,related accept 로 항상 허용된다고 본다.

쓰임:
  - "정적 + 명세" 비교군: prober 대신 이 결과를 쓰면 랩 없이 같은 형식의 판정이 나온다
  - 의미 일치율: 정답 룰셋과 후보 룰셋의 판정을 패킷 단위로 비교
  - 랩 결과와 다르면 변환기·커널·상태 추적 쪽 차이다 (pipeline/crosscheck.py)

출력은 prober 와 같은 형식: {"results": [{"id", "kind", "expect", "observed", "pass"}...]}
사용: python3 common/sim.py out/candidate.json --scenario scenarios/req-001.json
"""

import argparse
import ipaddress
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.ir import load_json, sorted_rules  # noqa: E402
from common.topology import hosts  # noqa: E402


def _addr_match(ip, spec):
    return spec == "any" or ipaddress.ip_address(ip) in ipaddress.ip_network(spec)


def _port_match(port, spec):
    if spec == "any":
        return True
    lo, _, hi = spec.partition("-")
    return int(lo) <= port <= int(hi or lo)


def matching_rule(ruleset, src, dst, proto, port=None):
    """연결 시작 패킷에 처음 매칭되는 룰. 없으면 None (default deny)."""
    for r in sorted_rules(ruleset):
        if not (_addr_match(src, r["src"]) and _addr_match(dst, r["dst"])):
            continue
        if r["proto"] != "any" and r["proto"] != proto:
            continue
        if r["proto"] in ("tcp", "udp") and not _port_match(port, r["dport"]):
            continue
        return r
    return None


def decide(ruleset, src, dst, proto, port=None):
    r = matching_rule(ruleset, src, dst, proto, port)
    return "allow" if r and r["action"] == "accept" else "block"


def simulate(ruleset, probes, host_ips=None):
    host_ips = host_ips or hosts()
    results = []
    for p in probes:
        observed = decide(ruleset, host_ips[p["from"]], p["to"], p["proto"], p.get("port"))
        results.append({
            "id": p["id"], "kind": p["kind"], "expect": p["expect"],
            "observed": observed, "pass": observed == p["expect"],
        })
    return {"results": results}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ruleset")
    ap.add_argument("--scenario", required=True)
    args = ap.parse_args()

    out = simulate(load_json(args.ruleset), load_json(args.scenario)["probes"])
    json.dump(out, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
