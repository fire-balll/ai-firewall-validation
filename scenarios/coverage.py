#!/usr/bin/env python3
"""시나리오 프로브가 오류 주입을 얼마나 드러내는지 시뮬레이터로 계산한다. (담당: 서진정)

정답 룰셋의 룰마다 mutations/README.md 의 유형으로 변형을 만들고, 시나리오 프로브 중
하나라도 판정이 바뀌면 "드러남"으로 본다. 판정은 common/sim.py 를 쓴다.

드러나지 않은 변형은 둘로 나눈다.
  missed      랩에서 보낼 수 있는 어떤 프로브로도 드러나지 않는다 (랩 안에서는 정답과 같은 정책)
  uncovered   랩 프로브로 드러낼 수 있는데 시나리오에 그 프로브가 없다 -> suggest 에 추가 후보

출력: {"scenarios": [{"id", "mutants", "caught", "uncovered": [...], "missed": [...], "suggest": [...]}]}
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

# 랩에서 실제로 열려 있는 서비스 (lab/topology.env). expect=allow 프로브는 여기만 겨냥한다.
SERVICES = {"iot-dev": [80], "server": [80, 8080]}


def lab_probes(host_ips):
    """랩에서 보낼 수 있는 모든 프로브. 같은 서브넷 안은 fw 를 거치지 않으므로 뺀다."""
    def net(ip):
        return ipaddress.ip_network(f"{ip}/24", strict=False)

    out = []
    for frm, src in host_ips.items():
        for to, dst in host_ips.items():
            if net(src) == net(dst):
                continue
            out.append({"from": frm, "to": dst, "proto": "icmp"})
            out += [{"from": frm, "to": dst, "proto": "tcp", "port": p} for p in SERVICES.get(to, [])]
    return out


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
        yield f"order:{a['id']}<->{b['id']}", m


def verdicts(rules, probes, host_ips):
    rs = {"rules": rules}
    return [decide(rs, host_ips[p["from"]], p["to"], p["proto"], p.get("port")) for p in probes]


def analyze(scenario, host_ips):
    gold = scenario["gold"]["rules"]
    probes = scenario["probes"]
    universe = lab_probes(host_ips)
    gold_s, gold_u = verdicts(gold, probes, host_ips), verdicts(gold, universe, host_ips)

    caught, uncovered, missed = 0, {}, []
    for name, m in mutants(gold):
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

    return {"id": scenario["id"], "mutants": caught + len(uncovered) + len(missed), "caught": caught,
            "uncovered": sorted(uncovered), "missed": missed, "suggest": suggest}


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
