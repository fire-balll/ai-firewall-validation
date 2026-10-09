"""validator 테스트. 실행: python3 -m unittest discover -s tests -t .

nft 문법 검사는 fw 컨테이너 없이 subprocess.run 을 mock 으로 바꿔 호출 인자와 결과 처리만 본다.
실제 nft -c 통과 여부는 랩에서 따로 확인해야 한다.
"""

import glob
import io
import json
import os
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from common.ir import ROOT, load_json
from common.lab import FW
from validator.anomalies import find_anomalies
from validator.validate import main, nft_check, validate

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


class EqualRangeTest(unittest.TestCase):
    """두 룰의 범위가 완전히 같을 때(포함 관계의 경계)"""

    def test_same_range_different_action_is_shadowing(self):
        rs = [rule("a", IOT, SERVER, "tcp", "8080", "accept", 100),
              rule("d", IOT, SERVER, "tcp", "8080", "drop", 110)]
        self.assertEqual(types(rs), [("shadowing", ["a", "d"], "high")])

    def test_same_range_same_action_reported_once(self):
        rs = [rule("a1", IOT, SERVER, "tcp", "8080", "accept", 100),
              rule("a2", IOT, SERVER, "tcp", "8080", "accept", 110)]
        self.assertEqual(types(rs), [("redundancy", ["a1", "a2"], "low")])


class BoundaryTest(unittest.TestCase):
    def check(self, rules):
        return validate({"rules": rules})

    def test_prefix_16_is_not_wide_but_15_is(self):
        out = self.check([rule("r", "10.10.0.0/16", SERVER, "tcp", "80", "accept", 1)])
        self.assertEqual((out["ok"], out["risk"]), (True, "low"))
        out = self.check([rule("r", "10.10.0.0/15", SERVER, "tcp", "80", "accept", 1)])
        self.assertEqual((out["ok"], out["risk"]), (True, "high"))
        self.assertIn("/16 보다 넓음", out["reasons"][0])

    def test_wide_drop_is_not_risk(self):
        out = self.check([rule("r", "any", "any", "any", "any", "drop", 1)])
        self.assertEqual((out["ok"], out["risk"]), (True, "low"))

    def test_full_port_range_counts_as_all_ports(self):
        out = self.check([rule("r", IOT, SERVER, "tcp", "0-65535", "accept", 1)])
        self.assertEqual(out["risk"], "high")
        self.assertIn("모든 포트 accept", out["reasons"][0])

    def test_port_upper_bound(self):
        self.assertTrue(self.check([rule("r", IOT, SERVER, "udp", "65535", "accept", 1)])["ok"])
        self.assertFalse(self.check([rule("r", IOT, SERVER, "udp", "65536", "accept", 1)])["ok"])
        self.assertFalse(self.check([rule("r", IOT, SERVER, "tcp", "8000-65536", "accept", 1)])["ok"])

    def test_leading_zero_port_rejected(self):
        for dport in ("080", "8000-08080", "00"):
            with self.subTest(dport=dport):
                out = self.check([rule("r", IOT, SERVER, "tcp", dport, "accept", 1)])
                self.assertFalse(out["ok"])
                self.assertIn("앞자리 0", out["errors"][0])
        self.assertTrue(self.check([rule("r", IOT, SERVER, "tcp", "0", "accept", 1)])["ok"])

    def test_cidr_host_bits_rejected(self):
        out = self.check([rule("r", "10.10.10.1/24", SERVER, "tcp", "80", "accept", 1)])
        self.assertFalse(out["ok"])


class MalformedInputTest(unittest.TestCase):
    """구조가 어긋난 입력도 예외로 죽지 않고 ok=false JSON 을 낸다(fail-closed)."""

    def test_not_a_ruleset_object(self):
        for bad in ([], {"rules": ["r1"]}, {"rules": "r1"}, None):
            with self.subTest(bad=bad):
                out = validate(bad)
                self.assertEqual((out["ok"], out["risk"]), (False, None))
                self.assertTrue(out["errors"])

    def run_main(self, *argv):
        buf = io.StringIO()
        with mock.patch("sys.argv", ["validate.py", *argv]), mock.patch("sys.stdout", buf):
            main()
        return json.loads(buf.getvalue())

    def test_invalid_json_file_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "candidate.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write('{"rules": [')
            out = self.run_main(path)
        self.assertEqual((out["ok"], out["risk"]), (False, None))
        self.assertIn("입력 JSON 파싱 실패", out["errors"][0])

    def test_missing_file_is_run_failure(self):
        # 파일이 없는 것은 후보의 문제가 아니라 실행 실패다. ok=false 로 기록하지 않고 예외로 멈춘다
        with self.assertRaises(FileNotFoundError):
            self.run_main(os.path.join(tempfile.gettempdir(), "no-such-candidate-c010.json"))


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
        with mock.patch("validator.validate.subprocess.run",
                        return_value=SimpleNamespace(returncode=0, stderr=b"")) as m:
            self.assertEqual(nft_check(self.rs), [])
        self.assertEqual(m.call_args.args[0][-6:], ["-i", FW, "nft", "-c", "-f", "-"])
        self.assertEqual(m.call_args.kwargs["timeout"], 30)

    def test_stdin_is_lf_bytes(self):
        # Windows 회귀: text=True 로 넘기면 \n 이 \r\n 으로 바뀌어 nft 가 매 줄 \r 을 syntax error 로 본다
        with mock.patch("validator.validate.subprocess.run",
                        return_value=SimpleNamespace(returncode=0, stderr=b"")) as m:
            nft_check(self.rs)
        kw = m.call_args.kwargs
        self.assertIsInstance(kw["input"], bytes)
        self.assertNotIn(b"\r", kw["input"])
        self.assertIn(b"\n", kw["input"])
        self.assertFalse(kw.get("text") or kw.get("universal_newlines"))

    def test_syntax_error_reported(self):
        stderr = "Error: syntax error\n".encode("utf-8")
        with mock.patch("validator.validate.subprocess.run",
                        return_value=SimpleNamespace(returncode=1, stderr=stderr)):
            self.assertEqual(nft_check(self.rs), ["nft -c: Error: syntax error"])

    def test_cannot_run_fails_closed(self):
        for ex in (FileNotFoundError("podman"), subprocess.TimeoutExpired("podman", 30)):
            with self.subTest(ex=type(ex).__name__), \
                    mock.patch("validator.validate.subprocess.run", side_effect=ex):
                errors = nft_check(self.rs)
                self.assertEqual(len(errors), 1)
                self.assertIn("nft -c 실행 실패", errors[0])


if __name__ == "__main__":
    unittest.main()
