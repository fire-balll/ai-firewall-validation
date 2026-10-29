"""eval/semantic.py 의미 일치율 테스트. 랩 없이 돈다."""

import copy
import unittest

from eval import semantic

HOSTS = {"pc": "10.10.20.10", "server": "10.10.30.10", "iot-dev": "10.10.10.10"}


def rule(rid, src, dst, proto="tcp", dport="80", action="accept", priority=100):
    return {"id": rid, "intent": "t", "src": src, "dst": dst, "proto": proto, "dport": dport,
            "action": action, "priority": priority}


GOLD = {"rules": [rule("g-001", "10.10.20.0/24", "10.10.30.10/32")]}


class SemanticTest(unittest.TestCase):
    def compare(self, cand, gold=GOLD):
        return semantic.compare(gold, cand, HOSTS)

    def test_same_ruleset_is_full_match(self):
        r = self.compare(copy.deepcopy(GOLD))
        self.assertEqual((r["match_rate"], r["policy_diff"], r["over_allow"], r["over_block"]), (1.0, False, 0, 0))

    def test_rewritten_but_equivalent_ruleset_is_full_match(self):
        # 같은 정책을 다른 id·priority 와 겹치지 않는 drop 룰로 써도 같은 정책이다
        cand = {"rules": [rule("r-1", "10.10.10.0/24", "any", "any", "any", "drop", 5),
                          rule("r-2", "10.10.20.0/24", "10.10.30.10/32", priority=50)]}
        r = self.compare(cand)
        self.assertFalse(r["policy_diff"])

    def test_widen_is_over_allow(self):
        r = self.compare({"rules": [rule("g-001", "any", "10.10.30.10/32")]})
        self.assertTrue(r["policy_diff"])
        self.assertGreater(r["over_allow"], 0)
        self.assertEqual(r["over_block"], 0)
        self.assertTrue(all(e["gold"] == "block" and e["candidate"] == "allow" for e in r["examples"]))

    def test_missing_rule_is_over_block(self):
        r = self.compare({"rules": []})
        self.assertGreater(r["over_block"], 0)
        self.assertEqual(r["over_allow"], 0)

    def test_difference_outside_lab_hosts_is_found(self):
        # 랩 호스트(10.10.20.10)는 그대로 허용되고, 같은 /24 의 랩에 없는 주소만 달라지는 후보
        cand = {"rules": [rule("g-001", "10.10.20.10/32", "10.10.30.10/32")]}
        r = self.compare(cand)
        self.assertTrue(r["policy_diff"])
        self.assertGreater(r["over_block"], 0)

    def test_difference_on_single_port_is_found(self):
        # 범위 안의 한 포트만 다른 경우 (req-014 유형): 경계 대표값 덕에 반드시 들어간다
        gold = {"rules": [rule("g-001", "10.10.20.0/24", "10.10.30.10/32", dport="8080", action="drop"),
                          rule("g-002", "10.10.20.0/24", "10.10.30.10/32", dport="8000-8100", priority=110)]}
        cand = {"rules": [rule("g-001", "10.10.20.0/24", "10.10.30.10/32", dport="8081", action="drop"),
                          rule("g-002", "10.10.20.0/24", "10.10.30.10/32", dport="8000-8100", priority=110)]}
        r = semantic.compare(gold, cand, HOSTS)
        self.assertTrue(r["policy_diff"])
        self.assertEqual({e["port"] for e in r["examples"] if e["proto"] == "tcp"}, {8080, 8081})

    def test_schema_invalid_ruleset_is_an_error(self):
        with self.assertRaisesRegex(ValueError, "후보 룰셋이 IR 스키마 위반"):
            self.compare({"rules": [rule("g-001", "10.10.20.0/24,10.10.10.0/24", "10.10.30.10/32")]})


if __name__ == "__main__":
    unittest.main()
