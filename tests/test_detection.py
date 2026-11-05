"""eval/detection.py 동적 추가 탐지율 테스트. 랩 없이 돈다."""

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from common.topology import hosts
from eval import detection

ROOT = Path(__file__).resolve().parents[1]
GOLD = json.loads((ROOT / "scenarios" / "req-001.json").read_text(encoding="utf-8"))["gold"]
LOW = {"ok": True, "errors": [], "risk": "low", "reasons": []}
HIGH = {"ok": True, "errors": [], "risk": "high", "reasons": ["r-001: accept 범위가 /16 보다 넓음"]}
BAD = {"ok": False, "errors": ["rules/0/dst: does not match"], "risk": None, "reasons": []}


def mutant(**changes):
    m = copy.deepcopy(GOLD)
    for rid, kw in changes.items():
        next(r for r in m["rules"] if r["id"] == rid).update(kw)
    return m


PORT = mutant(**{"g-001": {"dport": "8080"}})  # 정상 프로브 n-001 이 실패한다
WIDE = mutant(**{"g-001": {"src": "any"}})
# 두 룰은 목적지가 겹치지 않으므로 순서를 바꿔도 같은 정책이다
SWAPPED = mutant(**{"g-001": {"priority": 110}, "g-002": {"priority": 100}})
# udp 만 바뀐 오류. 지금 prober 는 udp 를 보내지 않아 랩에서는 정답과 같게 보인다
UDP_ONLY = copy.deepcopy(GOLD)
UDP_ONLY["rules"].append({"id": "x-001", "intent": "추가", "src": "10.10.20.0/24", "dst": "10.10.30.10/32",
                          "proto": "udp", "dport": "53", "action": "accept", "priority": 200})


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        (self.root / "mutations").mkdir()
        for name, value in (("ROOT", self.root), ("MUTATIONS", self.root / "mutations")):
            patcher = mock.patch.object(detection, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.runs = []

    def add_mutation(self, name, ruleset):
        (self.root / "mutations" / f"{name}.json").write_text(json.dumps(ruleset), encoding="utf-8")

    def add_run(self, candidate, status, rep=1, validation=LOW, rolled_back=None):
        out = f"out/batch-x/{candidate}-r{rep}"
        (self.root / out).mkdir(parents=True)
        if status != "aborted":
            (self.root / out / "validation.json").write_text(json.dumps(validation), encoding="utf-8")
        if status in ("applied", "rolled_back"):
            rb = status == "rolled_back" if rolled_back is None else rolled_back
            (self.root / out / "deploy.json").write_text(json.dumps({"rolled_back": rb}), encoding="utf-8")
        self.runs.append({"scenario": "req-001", "candidate": candidate, "rep": rep, "status": status, "out": out})

    def build(self):
        manifest = {"commit": "abc123", "dirty": False, "finished": "t", "runs": self.runs}
        return detection.build(manifest, "20261030-090000", hosts())


class ObservabilityTest(unittest.TestCase):
    def classify(self, ruleset, name="req-001-port-01.json"):
        return detection.observability(GOLD, ruleset, Path(name), hosts())

    def test_lab_visible_error_is_observable(self):
        self.assertEqual(self.classify(PORT), "observable")

    def test_same_policy_is_equivalent(self):
        self.assertEqual(self.classify(SWAPPED, "req-001-order-01.json"), "equivalent")

    def test_udp_only_difference_is_unobservable(self):
        self.assertEqual(self.classify(UDP_ONLY, "req-001-extra-01.json"), "unobservable")

    def test_state_type_is_observable_although_ir_is_gold(self):
        self.assertEqual(self.classify(copy.deepcopy(GOLD), "req-001-state-01.json"), "observable")

    def test_mutation_type_from_name(self):
        self.assertEqual(detection.mutation_type("req-002", "req-002-port-any-01"), "port-any")
        self.assertEqual(detection.mutation_type("req-001", "req-001-state-01"), "state")


class DetectionTest(Base):
    def test_rate_counts_only_statically_passed_runs(self):
        self.add_mutation("req-001-port-01", PORT)
        self.add_mutation("req-001-widen-01", WIDE)
        self.add_mutation("req-001-missing-01", mutant(**{"g-002": {"dport": "81"}}))
        for rep in (1, 2, 3):
            self.add_run("req-001-port-01", "rolled_back", rep=rep)
            self.add_run("req-001-widen-01", "rejected_approval", rep=rep, validation=HIGH)
        self.add_run("req-001-missing-01", "applied")
        r = self.build()
        self.assertEqual(r["rate"], {"dynamic": 3, "missed": 1, "denominator": 4, "value": 0.75})
        self.assertEqual(r["static_caught"], 3)
        self.assertEqual(r["by_type"]["widen"]["denominator"], 0)
        self.assertIsNone(r["by_type"]["widen"]["value"])
        self.assertEqual(r["by_type"]["port"]["value"], 1.0)

    def test_validation_rejection_is_static(self):
        self.add_mutation("req-001-port-01", PORT)
        self.add_run("req-001-port-01", "rejected_validation", validation=BAD)
        self.assertEqual(self.build()["static_caught"], 1)

    def test_high_risk_applied_with_approve_yes_is_static(self):
        self.add_mutation("req-001-widen-01", WIDE)
        self.add_run("req-001-widen-01", "rolled_back", validation=HIGH)
        r = self.build()
        self.assertEqual((r["static_caught"], r["rate"]["denominator"]), (1, 0))

    def test_state_is_reported_with_and_without(self):
        self.add_mutation("req-001-state-01", copy.deepcopy(GOLD))
        self.add_mutation("req-001-port-01", PORT)
        self.add_run("req-001-state-01", "rolled_back")
        self.add_run("req-001-port-01", "applied")
        r = self.build()
        self.assertEqual(r["rate"]["value"], 0.5)
        self.assertEqual(r["rate_without_state"]["value"], 0.0)

    def test_equivalent_and_unobservable_leave_denominator(self):
        self.add_mutation("req-001-order-01", SWAPPED)
        self.add_mutation("req-001-extra-01", UDP_ONLY)
        self.add_mutation("req-001-port-01", PORT)
        self.add_run("req-001-order-01", "applied")
        self.add_run("req-001-extra-01", "applied")
        self.add_run("req-001-port-01", "rolled_back")
        r = self.build()
        self.assertEqual(r["rate"]["denominator"], 1)
        self.assertEqual(r["excluded"], {"equivalent": ["req-001-order-01"], "unobservable": ["req-001-extra-01"]})
        self.assertEqual(r["anomalies"], [])

    def test_rollback_of_unobservable_is_an_anomaly(self):
        self.add_mutation("req-001-extra-01", UDP_ONLY)
        self.add_run("req-001-extra-01", "rolled_back")
        r = self.build()
        self.assertEqual([a["candidate"] for a in r["anomalies"]], ["req-001-extra-01"])
        self.assertEqual(r["rate"]["denominator"], 0)

    def test_aborted_runs_are_reported_not_counted(self):
        self.add_mutation("req-001-port-01", PORT)
        self.add_run("req-001-port-01", "aborted", rep=1)
        self.add_run("req-001-port-01", "rolled_back", rep=2)
        r = self.build()
        self.assertEqual(r["aborted"], [{"scenario": "req-001", "candidate": "req-001-port-01", "count": 1}])
        self.assertEqual(r["rate"]["denominator"], 1)

    def test_reps_that_disagree_are_listed(self):
        self.add_mutation("req-001-port-01", PORT)
        self.add_run("req-001-port-01", "rolled_back", rep=1)
        self.add_run("req-001-port-01", "applied", rep=2)
        r = self.build()
        self.assertEqual(r["inconsistent"], [{"candidate": "req-001-port-01",
                                              "outcomes": {"r1": "dynamic", "r2": "missed"}}])
        self.assertEqual(r["rate"]["value"], 0.5)

    def test_gold_and_generated_runs_are_ignored(self):
        self.add_mutation("req-001-port-01", PORT)
        self.add_run("gold", "applied")
        self.add_run("req-001-port-01", "rolled_back")
        self.runs.append(dict(self.runs[-1], candidate="req-001-qwen2.5-14b-s1", meta={"round": 1}))
        r = self.build()
        self.assertEqual([c["candidate"] for c in r["candidates"]], ["req-001-port-01"])

    def test_status_and_outputs_must_agree(self):
        self.add_mutation("req-001-port-01", PORT)
        self.add_run("req-001-port-01", "applied", rolled_back=True)
        with self.assertRaisesRegex(detection.DetectionError, "rolled_back 이 다름"):
            self.build()

    def test_rejection_without_static_finding_is_an_error(self):
        self.add_mutation("req-001-port-01", PORT)
        self.add_run("req-001-port-01", "rejected_approval", validation=LOW)
        with self.assertRaisesRegex(detection.DetectionError, "정적 검증이 잡지 않음"):
            self.build()

    def test_missing_output_is_an_error(self):
        self.add_mutation("req-001-port-01", PORT)
        self.add_run("req-001-port-01", "rolled_back")
        (self.root / self.runs[-1]["out"] / "deploy.json").unlink()
        with self.assertRaisesRegex(detection.DetectionError, "deploy.json 없음"):
            self.build()


class MainTest(Base):
    def run_main(self, *extra, **overrides):
        manifest = dict({"commit": "abc123", "dirty": False, "finished": "t", "runs": self.runs}, **overrides)
        path = self.root / "batch-20261030-090000.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        with mock.patch("sys.argv", ["detection.py", str(path), *extra]), mock.patch("sys.stdout"):
            detection.main()

    def test_unfinished_batch_is_an_error(self):
        with self.assertRaisesRegex(SystemExit, "끝나지 않은 배치"):
            self.run_main(finished=None)

    def test_dirty_batch_needs_flag(self):
        self.add_mutation("req-001-port-01", PORT)
        self.add_run("req-001-port-01", "rolled_back")
        with self.assertRaisesRegex(SystemExit, "커밋 안 된 변경"):
            self.run_main(dirty=True)
        self.run_main("--allow-dirty", dirty=True)


if __name__ == "__main__":
    unittest.main()
