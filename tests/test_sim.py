"""common/sim.py 테스트. 실행: python3 -m unittest discover -s tests"""

import glob
import unittest

from common.ir import ROOT, load_json
from common.sim import decide, simulate
from common.topology import hosts


def rule(id_, src, dst, proto, dport, action, priority):
    return {"id": id_, "intent": "t", "src": src, "dst": dst, "proto": proto,
            "dport": dport, "action": action, "priority": priority}


class DecideTest(unittest.TestCase):
    def test_default_deny(self):
        self.assertEqual(decide({"rules": []}, "10.10.20.10", "10.10.30.10", "tcp", 80), "block")

    def test_first_match_by_priority_not_list_order(self):
        rs = {"rules": [
            rule("wide", "10.10.10.0/24", "any", "tcp", "8080", "accept", 110),
            rule("narrow", "10.10.10.66/32", "any", "any", "any", "drop", 100),
        ]}
        self.assertEqual(decide(rs, "10.10.10.66", "10.10.30.10", "tcp", 8080), "block")
        self.assertEqual(decide(rs, "10.10.10.10", "10.10.30.10", "tcp", 8080), "allow")

    def test_port_range_boundaries(self):
        rs = {"rules": [rule("r", "any", "any", "tcp", "8000-8100", "accept", 1)]}
        self.assertEqual(decide(rs, "1.1.1.1", "2.2.2.2", "tcp", 8000), "allow")
        self.assertEqual(decide(rs, "1.1.1.1", "2.2.2.2", "tcp", 8100), "allow")
        self.assertEqual(decide(rs, "1.1.1.1", "2.2.2.2", "tcp", 8101), "block")

    def test_proto_must_match(self):
        rs = {"rules": [rule("r", "any", "any", "tcp", "80", "accept", 1)]}
        self.assertEqual(decide(rs, "1.1.1.1", "2.2.2.2", "udp", 80), "block")
        self.assertEqual(decide(rs, "1.1.1.1", "2.2.2.2", "icmp"), "block")

    def test_proto_any_matches_icmp(self):
        rs = {"rules": [rule("r", "10.10.20.0/24", "any", "any", "any", "accept", 1)]}
        self.assertEqual(decide(rs, "10.10.20.10", "10.10.10.10", "icmp"), "allow")


class TopologyTest(unittest.TestCase):
    def test_hosts_from_topology_env(self):
        self.assertEqual(hosts(), {
            "iot-dev": "10.10.10.10", "attacker": "10.10.10.66",
            "pc": "10.10.20.10", "server": "10.10.30.10",
        })


class ScenarioGoldTest(unittest.TestCase):
    """모든 시나리오의 정답 룰셋은 자기 프로브 기대값을 전부 만족해야 한다."""

    def test_gold_satisfies_probes(self):
        files = sorted(glob.glob(str(ROOT / "scenarios" / "req-*.json")))
        self.assertTrue(files)
        for f in files:
            s = load_json(f)
            failed = [r["id"] for r in simulate(s["gold"], s["probes"])["results"] if not r["pass"]]
            with self.subTest(scenario=s["id"]):
                self.assertEqual(failed, [])


if __name__ == "__main__":
    unittest.main()
