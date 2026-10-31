"""Offline-only replacement policy comparison for the validator owner.

This is NOT an applied-ruleset check: a trusted live nft snapshot, deployment
provenance, conntrack and requirement approval must be supplied by integration.
Never feed its result into validate.py's ok/risk or a deploy decision.
"""
from __future__ import annotations

import ipaddress
from itertools import product

from common.sim import matching_rule
from validator.validate import validate

IP_END = 1 << 32
PORT_END = 1 << 16
PROTOS = ("tcp", "udp", "icmp")


class ComparisonUnavailable(ValueError):
    """The requested offline comparison cannot be established."""


def _intervals(points):
    values = sorted(points)
    return [(start, end) for start, end in zip(values, values[1:]) if start < end]


def _bounds(rules):
    src_points = {0, IP_END}
    dst_points = {0, IP_END}
    port_points = {0, PORT_END}
    for rule in rules:
        for key, points in (("src", src_points), ("dst", dst_points)):
            if rule[key] != "any":
                net = ipaddress.ip_network(rule[key], strict=True)
                if net.version != 4:
                    raise ComparisonUnavailable("IPv4 only")
                points.update((int(net.network_address), int(net.broadcast_address) + 1))
        if rule["proto"] in ("tcp", "udp") and rule["dport"] != "any":
            lo, _, hi = rule["dport"].partition("-")
            port_points.update((int(lo), int(hi or lo) + 1))
    return _intervals(src_points), _intervals(dst_points), _intervals(port_points)


def compare_offline(before, after, *, before_stateful, after_stateful,
                    max_regions=200000, max_examples=20,
                    max_rules=128, max_work=100000):
    """Partition IPv4 TCP/UDP/ICMP initial-packet decision space; no lab/VM I/O.

    Results count decision regions, NOT packets or traffic. A bounded example
    list is not a complete change list; counts are exhaustive only if no cap
    was exceeded. Unsupported inputs fail, never return a success-shaped value.
    Region, per-ruleset rule and region-times-total-rule limits are positive
    integers; example limits are nonnegative integers. These are deterministic
    input budgets, not a wall-clock or memory guarantee.
    Booleans and nonfinite/fractional numbers are not valid resource limits.
    Both stateful flags are required: IR has no state field and filename-based
    mutation mode must be passed by the caller via common.ir.stateful_for(path).
    """
    if type(max_regions) is not int or max_regions < 1:
        raise ComparisonUnavailable("max_regions must be a positive integer")
    if type(max_examples) is not int or max_examples < 0:
        raise ComparisonUnavailable("max_examples must be a nonnegative integer")
    if type(max_rules) is not int or max_rules < 1:
        raise ComparisonUnavailable("max_rules must be a positive integer")
    if type(max_work) is not int or max_work < 1:
        raise ComparisonUnavailable("max_work must be a positive integer")
    if not isinstance(before_stateful, bool) or not isinstance(after_stateful, bool):
        raise ComparisonUnavailable("stateful mode must be explicit booleans")
    # Reject oversized lists before schema validation and its quadratic anomaly
    # pass. Malformed inputs still go through validate() for a fail-closed error.
    for label, ruleset in (("before", before), ("after", after)):
        if isinstance(ruleset, dict) and isinstance(ruleset.get("rules"), list):
            if len(ruleset["rules"]) > max_rules:
                raise ComparisonUnavailable(f"{label} rule cap exceeded: {len(ruleset['rules'])} > {max_rules}")
    for label, ruleset in (("before", before), ("after", after)):
        result = validate(ruleset)
        if not result["ok"]:
            raise ComparisonUnavailable(f"{label} invalid: {result['errors']}")
        ids = [r["id"] for r in ruleset["rules"]]
        if len(ids) != len(set(ids)):
            raise ComparisonUnavailable(f"{label} has duplicate rule IDs")
    if before_stateful != after_stateful:
        return {"status": "indeterminate", "reason": "stateful mode differs; initial packets cannot establish policy equivalence"}
    before_rules, after_rules = before["rules"], after["rules"]
    src, dst, ports = _bounds(before_rules + after_rules)
    total = len(src) * len(dst) * (2 * len(ports) + 1)
    if total > max_regions:
        raise ComparisonUnavailable(f"region cap exceeded: {total} > {max_regions}")
    work = total * (len(before_rules) + len(after_rules))
    if work > max_work:
        raise ComparisonUnavailable(f"work cap exceeded: {work} > {max_work}")
    counts = {"allow_to_block": 0, "block_to_allow": 0, "same": 0}
    examples = []
    for (src_start, _), (dst_start, _), proto in product(src, dst, PROTOS):
        choices = ports if proto != "icmp" else [(0, 1)]
        for port_start, _ in choices:
            packet = {"src": str(ipaddress.IPv4Address(src_start)),
                      "dst": str(ipaddress.IPv4Address(dst_start)), "proto": proto,
                      "port": port_start if proto != "icmp" else None}
            hits = [matching_rule(rs, packet["src"], packet["dst"], proto, packet["port"])
                    for rs in (before, after)]
            decisions = ["allow" if r and r["action"] == "accept" else "block" for r in hits]
            category = "same" if decisions[0] == decisions[1] else f"{decisions[0]}_to_{decisions[1]}"
            counts[category] += 1
            if category != "same" and len(examples) < max_examples:
                examples.append({"packet": packet, "change": category,
                                 "before_rule": hits[0]["id"] if hits[0] else None,
                                 "after_rule": hits[1]["id"] if hits[1] else None})
    return {"status": "offline_only", "scope": "IPv4 TCP/UDP/ICMP initial packets; first-match/default-drop; no snapshot, conntrack or approval",
            "stateful": before_stateful, "regions": total, "counts": counts,
            "examples": examples, "examples_truncated": counts["allow_to_block"] + counts["block_to_allow"] > len(examples)}
