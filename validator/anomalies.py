"""룰 간 이상 탐지 4종: shadowing, redundancy, correlation, generalization. (담당: 양경찬)

정의는 Al-Shaer & Hamed(2004)의 룰 쌍 관계를 따르고, 판정 순서는 common/ir.py 의
to_nft 와 같다(priority 오름차순, 같으면 id 순, first-match, 기본 정책 drop).
상세 기준과 예시는 validator/README.md.

룰 하나의 매칭 범위는 프로토콜마다 (src 구간) x (dst 구간) x (포트 구간) 상자다.
  - tcp/udp: 해당 프로토콜 하나, dport 범위 (any 는 0-65535)
  - icmp: icmp 하나 (포트 없음)
  - any: tcp·udp(전체 포트), icmp, 그 밖의 프로토콜 전부. to_nft 가 proto any 에
    프로토콜 조건을 붙이지 않기 때문이다.

한계: 룰 두 개씩만 비교한다. 여러 앞 룰의 합집합이 한 룰을 덮는 경우는 잡지 않는다.
"""

import ipaddress

from common.ir import sorted_rules

FULL_PORTS = (0, 65535)
NO_PORT = (0, 0)
ANY_PROTO = {"tcp": FULL_PORTS, "udp": FULL_PORTS, "icmp": NO_PORT, "other": NO_PORT}


def _addr_range(spec):
    net = ipaddress.ip_network("0.0.0.0/0" if spec == "any" else spec)
    return int(net.network_address), int(net.broadcast_address)


def _port_range(spec):
    if spec == "any":
        return FULL_PORTS
    lo, _, hi = spec.partition("-")
    return int(lo), int(hi or lo)


def port_errors(ruleset):
    """스키마 정규식으로는 못 막는 포트 값 오류. 0-65535 밖이거나 범위가 뒤집힌 경우,
    앞자리가 0 인 경우("080"). 마지막은 IR 은 10진수로 보지만 nft 가 같은 값으로 읽는지
    확인되지 않아 분석과 적용이 어긋날 수 있으므로 막는다."""
    errors = []
    for r in ruleset["rules"]:
        if r["dport"] == "any":
            continue
        lo, hi = _port_range(r["dport"])
        if any(len(p) > 1 and p.startswith("0") for p in r["dport"].split("-")):
            errors.append(f"{r['id']}.dport: {r['dport']} 에 앞자리 0 이 있음 (10진수로만 적을 것)")
        elif hi > 65535:
            errors.append(f"{r['id']}.dport: {r['dport']} 는 0-65535 밖")
        elif lo > hi:
            errors.append(f"{r['id']}.dport: {r['dport']} 범위의 시작이 끝보다 큼")
    return errors


def match_space(rule):
    """{프로토콜: (src 구간, dst 구간, 포트 구간)}"""
    src, dst = _addr_range(rule["src"]), _addr_range(rule["dst"])
    if rule["proto"] == "any":
        protos = ANY_PROTO
    elif rule["proto"] == "icmp":
        protos = {"icmp": NO_PORT}
    else:
        protos = {rule["proto"]: _port_range(rule["dport"])}
    return {p: (src, dst, ports) for p, ports in protos.items()}


def _within(a, b):
    return b[0] <= a[0] and a[1] <= b[1]


def _overlaps(a, b):
    return a[0] <= b[1] and b[0] <= a[1]


def is_subset(a, b):
    """매칭 범위 a 가 b 안에 모두 들어가나"""
    return all(p in b and all(_within(x, y) for x, y in zip(box, b[p])) for p, box in a.items())


def intersects(a, b):
    return any(p in b and all(_overlaps(x, y) for x, y in zip(box, b[p])) for p, box in a.items())


def _anomaly(type_, earlier, later, risk, detail):
    return {"type": type_, "rules": [earlier["id"], later["id"]], "risk": risk, "detail": detail}


def _redundant_earlier(rules, i, j, spaces):
    """앞 룰 i 가 뒤 룰 j 에 포함되고 동작이 같을 때, 사이에 i 와 겹치면서 동작이 다른 룰이 없으면
    i 를 지워도 i 의 패킷은 j(또는 같은 동작의 사이 룰)에 걸려 판정이 같다."""
    return not any(
        rules[k]["action"] != rules[i]["action"] and intersects(spaces[i], spaces[k])
        for k in range(i + 1, j)
    )


def classify(earlier, later, earlier_space, later_space):
    """앞 룰(우선)과 뒤 룰의 관계. 이상이 없으면 None. redundancy(앞 룰 쪽)는 find_anomalies 에서 본다."""
    same = earlier["action"] == later["action"]
    a, b = earlier["id"], later["id"]
    if is_subset(later_space, earlier_space):
        if same:
            return _anomaly("redundancy", earlier, later, "low",
                            f"{b} 의 범위가 앞 룰 {a} 에 모두 포함되고 동작({later['action']})이 같다. "
                            f"{b} 는 매칭되지 않으므로 지워도 판정이 같다")
        overallow = later["action"] == "drop"
        return _anomaly("shadowing", earlier, later, "high",
                        f"{b}({later['action']}) 의 범위가 앞 룰 {a}({earlier['action']}) 에 모두 가려 "
                        f"{b} 는 적용되지 않는다 ({'과허용' if overallow else '과차단'} 위험)")
    if not intersects(earlier_space, later_space):
        return None
    if same:
        return None
    if is_subset(earlier_space, later_space):
        return _anomaly("generalization", earlier, later, "low",
                        f"뒤의 넓은 룰 {b}({later['action']}) 가 앞의 좁은 예외 {a}({earlier['action']}) 를 "
                        f"감싼다. 예외 패턴일 수 있어 참고로만 표시한다")
    if earlier["action"] == "accept":
        return _anomaly("correlation", earlier, later, "high",
                        f"{a}(accept) 와 {b}(drop) 의 범위가 일부 겹치고 겹친 부분은 앞의 accept 가 "
                        f"이긴다 (과허용 위험, 순서 확인 필요)")
    return _anomaly("correlation", earlier, later, "low",
                    f"{a}(drop) 와 {b}(accept) 의 범위가 일부 겹치고 겹친 부분은 앞의 drop 이 "
                    f"이긴다 (차단 쪽, 과차단 여부는 동적 검증으로 확인)")


def find_anomalies(ruleset):
    """적용 순서상 모든 룰 쌍 (앞, 뒤) 의 이상 목록."""
    rules = sorted_rules(ruleset)
    spaces = [match_space(r) for r in rules]
    found = []
    for i in range(len(rules)):
        for j in range(i + 1, len(rules)):
            x, y = rules[i], rules[j]
            a = classify(x, y, spaces[i], spaces[j])
            if (a is None and x["action"] == y["action"]
                    and is_subset(spaces[i], spaces[j]) and _redundant_earlier(rules, i, j, spaces)):
                a = _anomaly("redundancy", x, y, "low",
                             f"{x['id']} 의 범위가 뒤 룰 {y['id']} 에 포함되고 동작({x['action']})이 같으며 "
                             f"사이에 동작이 다른 겹치는 룰이 없다. {x['id']} 를 지워도 판정이 같다")
            if a:
                found.append(a)
    return found
