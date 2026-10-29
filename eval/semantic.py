#!/usr/bin/env python3
"""정답 룰셋 대비 의미 일치율. 같은 테스트 패킷을 정답·후보에 넣어 판정을 비교한다. (담당: 강윤서)

판정은 common/sim.py 를 쓴다(priority first-match, 매칭 없으면 drop, 연결을 시작하는 패킷만).

테스트 패킷 집합 (src 주소 × dst 주소 × (tcp·udp 포트 + icmp)):
  주소  랩 호스트 주소 + 두 룰셋의 주소 경계 대표값(각 네트워크의 첫 주소, 끝 다음 주소) + 0.0.0.0
  포트  80·8080 등 고정 포트 + 두 룰셋의 포트 경계 대표값(범위의 시작, 끝 다음 포트) + 0
경계 대표값이 있으면 "모든 룰이 똑같이 매칭되는 구간"마다 패킷이 하나 이상 들어간다.
그래서 정답과 판정이 다른 패킷이 어딘가에 있으면 이 집합에서도 반드시 하나 이상 나온다(policy_diff 는 정확).
반면 일치율은 이 집합 안에서의 비율이다. 실제 트래픽 비율이 아니며, 같은 정답이라도 후보의 경계가 다르면
집합이 달라진다. 후보끼리 비교할 때는 policy_diff·over_allow·over_block 을 같이 본다.

상태 추적(stateful)은 IR 에 없으므로 보지 않는다. state 오류 주입은 IR 이 정답과 같아 여기서는
같은 정책으로 나온다. 상태 추적 여부는 CSV 의 stateful 열로 구분한다 (#30, #39).

출력: {"packets", "same", "match_rate", "policy_diff", "over_allow", "over_block", "examples": [...]}
  over_allow  정답은 block 인데 후보가 allow (과허용)
  over_block  정답은 allow 인데 후보가 block (과차단)
사용: semantic.py out/candidate.json --scenario scenarios/req-001.json
"""

import argparse
import ipaddress
import json
import sys
from itertools import product
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.ir import load_json, schema_errors  # noqa: E402
from common.sim import decide  # noqa: E402
from common.topology import hosts  # noqa: E402

# 시나리오가 자주 쓰는 포트. 경계값만으로도 정확하지만 비율이 랩에서 쓰는 포트를 반영하게 넣는다
COMMON_PORTS = (22, 53, 80, 443, 8080, 9999)
MAX_EXAMPLES = 10


def _addresses(rules, host_ips):
    points = {0} | {int(ipaddress.ip_address(ip)) for ip in host_ips}
    for r in rules:
        for key in ("src", "dst"):
            if r[key] != "any":
                net = ipaddress.ip_network(r[key])
                points.add(int(net.network_address))
                if int(net.broadcast_address) + 1 < 1 << 32:
                    points.add(int(net.broadcast_address) + 1)
    return [str(ipaddress.IPv4Address(p)) for p in sorted(points)]


def _ports(rules):
    points = {0, *COMMON_PORTS}
    for r in rules:
        if r["proto"] in ("tcp", "udp", "any") and r["dport"] != "any":
            lo, _, hi = r["dport"].partition("-")
            points.add(int(lo))
            if int(hi or lo) + 1 <= 65535:
                points.add(int(hi or lo) + 1)
    return sorted(points)


def packets(gold, candidate, host_ips):
    rules = gold["rules"] + candidate["rules"]
    addrs = _addresses(rules, host_ips)
    ports = _ports(rules)
    for src, dst in product(addrs, addrs):
        for proto, port in [*((p, n) for p in ("tcp", "udp") for n in ports), ("icmp", None)]:
            yield src, dst, proto, port


def compare(gold, candidate, host_ips=None):
    """정답·후보의 판정을 비교한다. 룰셋이 IR 스키마를 어기면 ValueError."""
    for label, rs in (("정답", gold), ("후보", candidate)):
        errors = schema_errors(rs)
        if errors:
            raise ValueError(f"{label} 룰셋이 IR 스키마 위반: {errors[0]}")
    host_ips = list((host_ips or hosts()).values())
    total = same = over_allow = over_block = 0
    examples = []
    for src, dst, proto, port in packets(gold, candidate, host_ips):
        g = decide(gold, src, dst, proto, port)
        c = decide(candidate, src, dst, proto, port)
        total += 1
        if g == c:
            same += 1
            continue
        if c == "allow":
            over_allow += 1
        else:
            over_block += 1
        if len(examples) < MAX_EXAMPLES:
            examples.append({"src": src, "dst": dst, "proto": proto, "port": port, "gold": g, "candidate": c})
    return {
        "packets": total, "same": same, "match_rate": round(same / total, 4),
        "policy_diff": same != total, "over_allow": over_allow, "over_block": over_block,
        "examples": examples,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("candidate")
    ap.add_argument("--scenario", required=True)
    args = ap.parse_args()

    try:
        out = compare(load_json(args.scenario)["gold"], load_json(args.candidate))
    except ValueError as e:
        sys.exit(str(e))
    json.dump(out, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
