"""scenarios/ 데이터 검사. 실행: python3 -m unittest discover -s tests -t ."""

import glob
import ipaddress
import unittest

from common.ir import ROOT, load_json, schema_errors
from common.sim import simulate
from common.topology import hosts
from scenarios.coverage import analyze, overlaps

SCENARIOS = sorted(glob.glob(str(ROOT / "scenarios" / "req-*.json")))


class ScenarioTest(unittest.TestCase):
    def setUp(self):
        self.host_ips = hosts()
        self.by_ip = {ip: name for name, ip in self.host_ips.items()}

    def each(self):
        return [load_json(path) for path in SCENARIOS]

    def test_gold_passes_schema(self):
        for s in self.each():
            with self.subTest(scenario=s["id"]):
                self.assertEqual(schema_errors(s["gold"]), [])

    def test_gold_passes_all_probes(self):
        for s in self.each():
            with self.subTest(scenario=s["id"]):
                failed = [r["id"] for r in simulate(s["gold"], s["probes"], self.host_ips)["results"] if not r["pass"]]
                self.assertEqual(failed, [])

    def test_probe_ids_unique(self):
        for s in self.each():
            with self.subTest(scenario=s["id"]):
                ids = [p["id"] for p in s["probes"]]
                self.assertEqual(len(ids), len(set(ids)))

    def test_probes_cross_firewall(self):
        # 같은 서브넷 안의 트래픽은 fw 를 거치지 않아 아무것도 검증하지 못한다
        for s in self.each():
            with self.subTest(scenario=s["id"]):
                for p in s["probes"]:
                    src = ipaddress.ip_network(f"{self.host_ips[p['from']]}/24", strict=False)
                    self.assertNotIn(ipaddress.ip_address(p["to"]), src, p["id"])

    def test_probes_target_lab_host(self):
        # 랩에 없는 주소는 경로가 없어 prober 가 실행 실패로 끝난다. 포트는 닫혀 있어도 된다 (#7)
        for s in self.each():
            with self.subTest(scenario=s["id"]):
                for p in s["probes"]:
                    self.assertIn(p["to"], self.by_ip, p["id"])

    def test_no_uncovered_mutants(self):
        # 랩 프로브로 드러낼 수 있는 오류 주입은 시나리오 프로브로도 드러나야 한다
        for s in self.each():
            with self.subTest(scenario=s["id"]):
                self.assertEqual(analyze(s, self.host_ips)["uncovered"], [])


def rule(src, dst, proto, dport, action="accept"):
    return {"id": "r", "intent": "t", "src": src, "dst": dst, "proto": proto, "dport": dport,
            "action": action, "priority": 1}


class OverlapTest(unittest.TestCase):
    def test_host_inside_subnet_overlaps(self):
        # req-004: 침해 기기 drop 과 IoT 망 accept 는 겹친다 -> 순서가 바뀌면 오류
        self.assertTrue(overlaps(rule("10.10.10.66/32", "any", "any", "any", "drop"),
                                 rule("10.10.10.0/24", "10.10.30.10/32", "tcp", "8080")))

    def test_disjoint_sources(self):
        self.assertFalse(overlaps(rule("10.10.10.66/32", "any", "any", "any", "drop"),
                                  rule("10.10.20.0/24", "10.10.30.10/32", "tcp", "80")))

    def test_disjoint_protocols_and_ports(self):
        self.assertFalse(overlaps(rule("any", "any", "icmp", "any"), rule("any", "any", "tcp", "80")))
        self.assertFalse(overlaps(rule("any", "any", "tcp", "80"), rule("any", "any", "tcp", "8000-8100")))
        self.assertTrue(overlaps(rule("any", "any", "tcp", "8080"), rule("any", "any", "tcp", "8000-8100")))
        self.assertTrue(overlaps(rule("any", "any", "any", "any"), rule("any", "any", "tcp", "80")))


if __name__ == "__main__":
    unittest.main()
