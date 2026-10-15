"""common/ir.py 변환기 테스트."""

import unittest

from common.ir import stateful_for, to_nft

RULESET = {"rules": [{"id": "r1", "intent": "t", "src": "10.10.20.0/24", "dst": "10.10.30.10/32",
                      "proto": "tcp", "dport": "80", "action": "accept", "priority": 100}]}
CT = "ct state established,related accept"


class ToNftTest(unittest.TestCase):
    def test_stateful_by_default_puts_ct_rule_first(self):
        lines = [x.strip() for x in to_nft(RULESET).splitlines()]
        self.assertIn(CT, lines)
        self.assertLess(lines.index(CT), next(i for i, x in enumerate(lines) if 'comment "r1"' in x))

    def test_stateless_omits_ct_rule_only(self):
        stateful, stateless = to_nft(RULESET), to_nft(RULESET, stateful=False)
        self.assertNotIn(CT, stateless)
        self.assertEqual(stateful.replace(f"    {CT}\n", ""), stateless)

    def test_stateful_for_only_matches_state_mutation_names(self):
        self.assertFalse(stateful_for("mutations/req-001-state-01.json"))
        self.assertFalse(stateful_for("/abs/path/req-010-state-12.json"))
        self.assertTrue(stateful_for("mutations/req-001-port-01.json"))
        self.assertTrue(stateful_for("out/req-001/candidate.json"))
        # 모델 태그에 -state- 가 든 LLM 후보는 상태 추적을 유지해야 한다
        self.assertTrue(stateful_for("generated/req-001-foo-state-7b-s1.json"))
        self.assertTrue(stateful_for("generated/req-001-state-7b-s1.json"))


if __name__ == "__main__":
    unittest.main()
