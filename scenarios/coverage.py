#!/usr/bin/env python3
"""시나리오 프로브가 오류 주입을 얼마나 드러내는지 시뮬레이터로 계산한다. (담당: 서진정)

정답 룰셋의 룰마다 mutations/README.md 의 유형으로 변형을 만들고, 시나리오 프로브 중
하나라도 판정이 바뀌면 "드러남"으로 본다. 판정은 common/sim.py 를 쓴다.

프로브는 포트가 닫혀 있어도 방화벽 판정을 관측한다(#7: drop 은 timed out = block,
통과는 Connection refused = allow). 그래서 랩 호스트의 어떤 포트로든 프로브를 보낼 수 있다.
후보 포트는 정답 룰의 포트와 범위 경계(lo-1, lo, hi, hi+1), 80, 8080, 그리고 어느 룰에도
없는 포트 하나(OTHER_PORT)다.

드러나지 않은 변형은 셋으로 나눈다.
  equivalent  오류가 아니다. 순서를 바꾼 두 룰이 겹치지 않거나 action 이 같아 어떤 패킷에도 정답과 같다
  missed      랩에서 보낼 수 있는 어떤 프로브로도 드러나지 않는다 (랩 호스트·네트워크가 부족)
  uncovered   랩 프로브로 드러낼 수 있는데 시나리오에 그 프로브가 없다 -> suggest 에 추가 후보

출력: {"scenarios": [{"id", "mutants", "caught", "equivalent": [...], "uncovered": [...], "missed": [...],
                     "suggest": [...]}]}
사용: coverage.py [scenarios/req-*.json ...]
"""

import argparse
import copy
import glob
import ipaddress
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.ir import ROOT, load_json  # noqa: E402
from common.sim import decide  # noqa: E402
from common.topology import hosts  # noqa: E402

BASE_PORTS = (80, 8080)
OTHER_PORT = 9999  # 어느 정답 룰에도 없는 포트. 포트를 any 로 넓힌 오류를 드러낸다


def probe_ports(rules):
    ports = set(BASE_PORTS) | {OTHER_PORT}
    for r in rules:
        if r["dport"] == "any":
            continue
        lo, _, hi = r["dport"].partition("-")
        lo, hi = int(lo), int(hi or lo)
        ports |= {lo, hi} | ({lo - 1, hi + 1} if lo != hi else set())
    return sorted(p for p in ports if 0 < p < 65536)


def lab_probes(host_ips, ports):
    """랩에서 보낼 수 있는 모든 프로브. 같은 서브넷 안은 fw 를 거치지 않으므로 뺀다."""
    def net(ip):
        return ipaddress.ip_network(f"{ip}/24", strict=False)

    out = []
    for src_name, src in host_ips.items():
        for dst in host_ips.values():
            if net(src) == net(dst):
                continue
            out.append({"from": src_name, "to": dst, "proto": "icmp"})
            out += [{"from": src_name, "to": dst, "proto": "tcp", "port": p} for p in ports]
    return out


def _ports(r):
    if r["proto"] not in ("tcp", "udp") or r["dport"] == "any":
        return 0, 65535
    lo, _, hi = r["dport"].partition("-")
    return int(lo), int(hi or lo)


def overlaps(a, b):
    """두 룰에 함께 매칭되는 패킷이 있을 수 있는가."""
    for f in ("src", "dst"):
        if "any" not in (a[f], b[f]) and not ipaddress.ip_network(a[f]).overlaps(ipaddress.ip_network(b[f])):
            return False
    if "any" not in (a["proto"], b["proto"]) and a["proto"] != b["proto"]:
        return False
    (alo, ahi), (blo, bhi) = _ports(a), _ports(b)
    return alo <= bhi and blo <= ahi


def mutants(rules):
    """(이름, 변형 룰 목록). 한 변형에는 오류 하나만 넣는다."""
    def edit(i, **kw):
        m = copy.deepcopy(rules)
        m[i].update(kw)
        return m

    for i, r in enumerate(rules):
        rid = r["id"]
        for f in ("src", "dst"):
            if r[f] != "any":
                yield f"widen:{rid}.{f}->any", edit(i, **{f: "any"})
        if r["proto"] in ("tcp", "udp") and r["dport"] != "any":
            yield f"port-any:{rid}", edit(i, dport="any")
            lo, _, hi = r["dport"].partition("-")
            if hi:
                yield f"range:{rid}.lo+1", edit(i, dport=f"{int(lo) + 1}-{hi}")
                yield f"range:{rid}.hi-1", edit(i, dport=f"{lo}-{int(hi) - 1}")
            for p in (80, 8080):
                if r["dport"] != str(p):
                    yield f"port:{rid}->{p}", edit(i, dport=str(p))
        if r["proto"] != "any":
            yield f"proto:{rid}->any", edit(i, proto="any", dport="any")
        if r["proto"] == "tcp":
            yield f"proto:{rid}->udp", edit(i, proto="udp")
        if r["src"] != r["dst"]:
            yield f"swap:{rid}", edit(i, src=r["dst"], dst=r["src"])
        yield f"action:{rid}", edit(i, action="drop" if r["action"] == "accept" else "accept")
        yield f"missing:{rid}", [x for j, x in enumerate(rules) if j != i]
    ordered = sorted(rules, key=lambda r: (r["priority"], r["id"]))
    for a, b in zip(ordered, ordered[1:]):
        m = copy.deepcopy(rules)
        for x in m:
            if x["id"] == a["id"]:
                x["priority"] = b["priority"]
            elif x["id"] == b["id"]:
                x["priority"] = a["priority"]
        equivalent = a["action"] == b["action"] or not overlaps(a, b)
        yield f"order:{a['id']}<->{b['id']}" + ("=" if equivalent else ""), m


def verdicts(rules, probes, host_ips):
    rs = {"rules": rules}
    return [decide(rs, host_ips[p["from"]], p["to"], p["proto"], p.get("port")) for p in probes]


def analyze(scenario, host_ips):
    gold = scenario["gold"]["rules"]
    probes = scenario["probes"]
    universe = lab_probes(host_ips, probe_ports(gold))
    gold_s, gold_u = verdicts(gold, probes, host_ips), verdicts(gold, universe, host_ips)

    caught, equivalent, uncovered, missed = 0, [], {}, []
    for name, m in mutants(gold):
        if name.endswith("="):
            equivalent.append(name[:-1])
            continue
        if verdicts(m, probes, host_ips) != gold_s:
            caught += 1
            continue
        diff = {k for k, v in enumerate(verdicts(m, universe, host_ips)) if v != gold_u[k]}
        if diff:
            uncovered[name] = diff
        else:
            missed.append(name)

    # 드러낼 수 있는 변형을 가장 많이 덮는 프로브부터 고른다 (greedy set cover)
    suggest, left = [], dict(uncovered)
    while left:
        best = max(range(len(universe)), key=lambda k: (sum(k in d for d in left.values()), -k))
        p = dict(universe[best], expect=gold_u[best])
        p["covers"] = sorted(n for n, d in left.items() if best in d)
        suggest.append(p)
        left = {n: d for n, d in left.items() if best not in d}

    return {"id": scenario["id"], "mutants": caught + len(equivalent) + len(uncovered) + len(missed),
            "caught": caught, "equivalent": equivalent, "uncovered": sorted(uncovered), "missed": missed,
            "suggest": suggest}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scenarios", nargs="*")
    args = ap.parse_args()

    paths = args.scenarios or sorted(glob.glob(str(ROOT / "scenarios" / "req-*.json")))
    host_ips = hosts()
    out = {"scenarios": [analyze(load_json(p), host_ips) for p in paths]}
    json.dump(out, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
