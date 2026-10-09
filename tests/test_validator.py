"""validator 테스트. 실행: python3 -m unittest discover -s tests -t .

nft 문법 검사는 fw 컨테이너 없이 exec_in 을 mock 으로 바꿔 결과 처리만 본다.
실제 nft -c 통과 여부는 랩에서 따로 확인해야 한다.
"""

import glob
import subprocess
import unittest
from types import SimpleNamespace
from unittest import mock

from common.ir import ROOT, load_json
from validator.anomalies import find_anomalies
from validator.validate import nft_check, validate

IOT = "10.10.10.0/24"
ATTACKER = "10.10.10.66/32"
SERVER = "10.10.30.10/32"


def rule(id_, src, dst, proto, dport, action, priority):
    return {"id": id_, "intent": "t", "src": src, "dst": dst, "proto": proto,
            "dport": dport, "action": action, "priority": priority}


def types(rules):
    return [(a["type"], a["rules"], a["risk"]) for a in find_anomalies({"rules": rules})]


class ShadowingTest(unittest.TestCase):
    def test_wide_accept_hides_narrow_drop(self):
        rs = [rule("wide", IOT, SERVER, "tcp", "8080", "accept", 100),
              rule("narrow", ATTACKER, SERVER, "tcp", "8080", "drop", 110)]
        self.assertEqual(types(rs), [("shadowing", ["wide", "narrow"], "high")])
        self.assertIn("과허용", find_anomalies({"rules": rs})[0]["detail"])

    def test_drop_hides_accept_is_overblock(self):
        rs = [rule("d", IOT, SERVER, "tcp", "any", "drop", 100),
              rule("a", ATTACKER, SERVER, "tcp", "80", "accept", 110)]
        self.assertEqual(types(rs), [("shadowing", ["d", "a"], "high")])
        self.assertIn("과차단", find_anomalies({"rules": rs})[0]["detail"])

    def test_proto_any_covers_icmp(self):
        rs = [rule("a", "10.10.20.0/24", "10.10.30.0/24", "any", "any", "accept", 100),
              rule("d", "10.10.20.10/32", SERVER, "icmp", "any", "drop", 110)]
        self.assertEqual(types(rs), [("shadowing", ["a", "d"], "high")])

    def test_priority_not_list_order(self):
        rs = [rule("narrow", ATTACKER, SERVER, "tcp", "8080", "drop", 110),
              rule("wide", IOT, SERVER, "tcp", "8080", "accept", 100)]
        self.assertEqual(types(rs)[0][:2], ("shadowing", ["wide", "narrow"]))

    def test_not_shadowing_when_narrow_comes_first(self):
        rs = [rule("narrow", ATTACKER, SERVER, "tcp", "8080", "drop", 100),
              rule("wide", IOT, SERVER, "tcp", "8080", "accept", 110)]
        self.assertNotIn("shadowing", [t for t, _, _ in types(rs)])

    def test_not_shadowing_when_port_partly_outside(self):
        rs = [rule("a", IOT, SERVER, "tcp", "8000-8079", "accept", 100),
              rule("d", ATTACKER, SERVER, "tcp", "8000-8100", "drop", 110)]
        self.assertNotIn("shadowing", [t for t, _, _ in types(rs)])


class RedundancyTest(unittest.TestCase):
    def test_later_inside_earlier_same_action(self):
        rs = [rule("wide", IOT, SERVER, "tcp", "8080", "accept", 100),
              rule("narrow", "10.10.10.10/32", SERVER, "tcp", "8080", "accept", 110)]
        self.assertEqual(types(rs), [("redundancy", ["wide", "narrow"], "low")])

    def test_earlier_inside_later_same_action(self):
        rs = [rule("narrow", "10.10.10.10/32", SERVER, "tcp", "8080", "accept", 100),
              rule("wide", IOT, SERVER, "tcp", "8000-8100", "accept", 110)]
        self.assertEqual(types(rs), [("redundancy", ["narrow", "wide"], "low")])

    def test_not_redundant_when_middle_rule_differs(self):
        # narrow 를 지우면 iot-dev:8080 이 mid 의 drop 에 걸리므로 판정이 바뀐다
        rs = [rule("narrow", "10.10.10.10/32", SERVER, "tcp", "8080", "accept", 100),
              rule("mid", IOT, SERVER, "tcp", "8080", "drop", 105),
              rule("wide", IOT, SERVER, "tcp", "8000-8100", "accept", 110)]
        self.assertNotIn("redundancy", [t for t, _, _ in types(rs)])

    def test_not_redundant_when_disjoint(self):
        rs = [rule("a", "10.10.20.0/24", SERVER, "tcp", "80", "accept", 100),
              rule("b", IOT, SERVER, "tcp", "80", "accept", 110)]
        self.assertEqual(types(rs), [])


class CorrelationTest(unittest.TestCase):
    def test_accept_first_overlap_is_high(self):
        # mutations 의 order 유형: req-004 정답의 순서를 뒤집음
        rs = [rule("acc", IOT, SERVER, "tcp", "8080", "accept", 100),
              rule("blk", ATTACKER, "any", "any", "any", "drop", 110)]
        self.assertEqual(types(rs), [("correlation", ["acc", "blk"], "high")])

    def test_drop_first_overlap_is_low(self):
        # req-004 정답과 같은 모양: 침해 기기 drop 을 먼저 둔 예외 패턴
        rs = [rule("blk", ATTACKER, "any", "any", "any", "drop", 100),
              rule("acc", IOT, SERVER, "tcp", "8080", "accept", 110)]
        self.assertEqual(types(rs), [("correlation", ["blk", "acc"], "low")])

    def test_no_correlation_across_protocols(self):
        rs = [rule("t", IOT, SERVER, "tcp", "80", "accept", 100),
              rule("u", ATTACKER, "any", "udp", "any", "drop", 110)]
        self.assertEqual(types(rs), [])

    def test_no_correlation_with_same_action(self):
        rs = [rule("a", IOT, SERVER, "tcp", "8080", "accept", 100),
              rule("b", ATTACKER, "any", "tcp", "8000-9000", "accept", 110)]
        self.assertEqual(types(rs), [])


class GeneralizationTest(unittest.TestCase):
    def test_narrow_drop_then_wide_accept(self):
        rs = [rule("narrow", ATTACKER, SERVER, "tcp", "8080", "drop", 100),
              rule("wide", IOT, SERVER, "tcp", "8080", "accept", 110)]
        self.assertEqual(types(rs), [("generalization", ["narrow", "wide"], "low")])

    def test_narrow_accept_then_wide_drop(self):
        rs = [rule("narrow", "10.10.20.10/32", SERVER, "tcp", "80", "accept", 100),
              rule("wide", "10.10.20.0/24", SERVER, "any", "any", "drop", 110)]
        self.assertEqual(types(rs), [("generalization", ["narrow", "wide"], "low")])

    def test_same_action_is_not_generalization(self):
        rs = [rule("narrow", ATTACKER, SERVER, "tcp", "8080", "drop", 100),
              rule("wide", IOT, SERVER, "tcp", "8080", "drop", 110)]
        self.assertEqual([t for t, _, _ in types(rs)], ["redundancy"])


class ValidateTest(unittest.TestCase):
    def test_high_anomaly_raises_risk(self):
        out = validate({"rules": [rule("acc", IOT, SERVER, "tcp", "8080", "accept", 100),
                                  rule("blk", ATTACKER, "any", "any", "any", "drop", 110)]})
        self.assertTrue(out["ok"])
        self.assertEqual(out["risk"], "high")
        self.assertTrue(any("correlation" in r for r in out["reasons"]))

    def test_low_anomaly_kept_but_risk_low(self):
        out = validate({"rules": [rule("blk", ATTACKER, "any", "any", "any", "drop", 100),
                                  rule("acc", IOT, SERVER, "tcp", "8080", "accept", 110)]})
        self.assertEqual((out["ok"], out["risk"], out["reasons"]), (True, "low", []))
        self.assertEqual([a["type"] for a in out["anomalies"]], ["correlation"])

    def test_port_out_of_range_rejected(self):
        out = validate({"rules": [rule("r", IOT, SERVER, "tcp", "70000", "accept", 1)]})
        self.assertFalse(out["ok"])
        self.assertIsNone(out["risk"])

    def test_reversed_port_range_rejected(self):
        out = validate({"rules": [rule("r", IOT, SERVER, "tcp", "9000-8000", "accept", 1)]})
        self.assertFalse(out["ok"])

    def test_analysis_error_fails_closed(self):
        with mock.patch("validator.validate.find_anomalies", side_effect=RuntimeError("boom")):
            out = validate({"rules": [rule("r", IOT, SERVER, "tcp", "80", "accept", 1)]})
        self.assertFalse(out["ok"])
        self.assertIsNone(out["risk"])
        self.assertIn("정적 분석 실패", out["errors"][0])

    def test_gold_rulesets_are_low_risk(self):
        files = sorted(glob.glob(str(ROOT / "scenarios" / "req-*.json")))
        self.assertTrue(files)
        for f in files:
            s = load_json(f)
            out = validate(s["gold"])
            with self.subTest(scenario=s["id"]):
                self.assertEqual((out["ok"], out["risk"]), (True, "low"), out["reasons"])

    def test_port_mutation_not_caught_statically(self):
        # mutations/README.md 가설: port 오류는 정답 비교 없이는 안 잡힘
        out = validate(load_json(ROOT / "mutations" / "req-001-port-01.json"))
        self.assertEqual((out["ok"], out["risk"]), (True, "low"))


class NftCheckTest(unittest.TestCase):
    rs = {"rules": [rule("r", IOT, SERVER, "tcp", "80", "accept", 1)]}

    def test_pass(self):
        with mock.patch("validator.validate.exec_in",
                        return_value=SimpleNamespace(returncode=0, stderr="")) as m:
            self.assertEqual(nft_check(self.rs), [])
        self.assertEqual(m.call_args.args[1:5], ("nft", "-c", "-f", "-"))

    def test_syntax_error_reported(self):
        with mock.patch("validator.validate.exec_in",
                        return_value=SimpleNamespace(returncode=1, stderr="Error: syntax error\n")):
            self.assertEqual(nft_check(self.rs), ["nft -c: Error: syntax error"])

    def test_cannot_run_fails_closed(self):
        for ex in (FileNotFoundError("podman"), subprocess.TimeoutExpired("podman", 30)):
            with self.subTest(ex=type(ex).__name__), \
                    mock.patch("validator.validate.exec_in", side_effect=ex):
                errors = nft_check(self.rs)
                self.assertEqual(len(errors), 1)
                self.assertIn("nft -c 실행 실패", errors[0])


if __name__ == "__main__":
    unittest.main()
