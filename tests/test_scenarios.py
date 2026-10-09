"""scenarios/ 데이터 검사. 실행: python3 -m unittest discover -s tests -t ."""

import glob
import ipaddress
import unittest

from common.ir import ROOT, load_json, schema_errors
from common.sim import simulate
from common.topology import hosts
from scenarios.coverage import SERVICES, analyze

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

    def test_allow_probes_target_open_service(self):
        # 닫힌 포트는 fw 와 상관없이 '차단'으로 관측된다 (prober/probe.py)
        for s in self.each():
            with self.subTest(scenario=s["id"]):
                for p in s["probes"]:
                    if p["expect"] == "allow" and p["proto"] == "tcp":
                        self.assertIn(p["port"], SERVICES.get(self.by_ip[p["to"]], []), p["id"])

    def test_no_uncovered_mutants(self):
        # 랩 프로브로 드러낼 수 있는 오류 주입은 시나리오 프로브로도 드러나야 한다
        for s in self.each():
            with self.subTest(scenario=s["id"]):
                self.assertEqual(analyze(s, self.host_ips)["uncovered"], [])


if __name__ == "__main__":
    unittest.main()
