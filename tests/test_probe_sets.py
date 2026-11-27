"""eval/probe_sets.py 프로브 v1 / v2 나눠 보기 테스트. 랩 없이 돈다."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from eval import probe_sets


def res(pid, kind, ok, set_="v1"):
    r = {"id": pid, "kind": kind, "expect": "allow" if kind == "normal" else "block", "pass": ok}
    if set_ is not None:
        r["set"] = set_
    return r


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        patcher = mock.patch.object(probe_sets, "ROOT", self.root)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.runs = []

    def add_run(self, candidate, status, results=None, rep=1, meta=None, rolled_back=None):
        out = f"out/batch-x/{candidate}-r{rep}"
        (self.root / out).mkdir(parents=True)
        if results is not None:
            rb = status == "rolled_back" if rolled_back is None else rolled_back
            (self.root / out / "deploy.json").write_text(
                json.dumps({"rolled_back": rb, "probe": {"results": results}}), encoding="utf-8")
        run = {"scenario": "req-013", "candidate": candidate, "rep": rep, "status": status, "out": out}
        if meta:
            run["meta"] = meta
        self.runs.append(run)

    def build(self):
        return probe_sets.build({"commit": "abc123", "runs": self.runs}, "20261120-090000")


class ProbeSetsTest(Base):
    def test_rates_are_split_by_set(self):
        self.add_run("gold", "applied", [res("n-001", "normal", True), res("a-001", "attack", True),
                                         res("n-101", "normal", True, "v2")])
        self.add_run("req-013-qwen2.5-14b-s1", "rolled_back",
                     [res("n-001", "normal", True), res("a-001", "attack", True),
                      res("n-101", "normal", False, "v2")], meta={"round": 1})
        r = self.build()
        gen = r["by_kind"]["generated"]
        self.assertEqual(gen["v1"]["normal"], {"pass": 1, "total": 1, "rate": 1.0})
        self.assertEqual(gen["v2"]["normal"], {"pass": 0, "total": 1, "rate": 0.0})
        self.assertIsNone(gen["v2"]["attack"]["rate"])
        self.assertEqual(r["by_kind"]["gold"]["v2"]["normal"]["rate"], 1.0)

    def test_v2_only_failure_is_listed(self):
        self.add_run("req-013-qwen2.5-14b-s1", "rolled_back",
                     [res("n-001", "normal", True), res("n-101", "normal", False, "v2")], meta={"round": 1})
        self.add_run("req-013-qwen2.5-14b-s2", "rolled_back",
                     [res("n-001", "normal", False), res("n-101", "normal", False, "v2")], meta={"round": 1})
        r = self.build()
        self.assertEqual([c["candidate"] for c in r["v2_only_failures"]], ["req-013-qwen2.5-14b-s1"])
        self.assertEqual(r["v2_only_failures"][0]["failed"], ["n-101"])
        by = {c["candidate"]: c for c in r["candidates"]}
        self.assertTrue(by["req-013-qwen2.5-14b-s1"]["v1_pass"])
        self.assertFalse(by["req-013-qwen2.5-14b-s2"]["v1_pass"])

    def test_round_and_kind_are_recorded(self):
        self.add_run("req-013-port-01", "applied", [res("n-001", "normal", True)])
        self.add_run("req-013-qwen2.5-14b-s1-r2", "applied", [res("n-001", "normal", True)], meta={"round": 2})
        by = {c["candidate"]: c for c in self.build()["candidates"]}
        self.assertEqual((by["req-013-port-01"]["kind"], by["req-013-port-01"]["round"]), ("mutation", None))
        self.assertEqual(by["req-013-qwen2.5-14b-s1-r2"]["round"], 2)

    def test_unprobed_and_aborted_runs_are_counted_not_used(self):
        self.add_run("req-013-qwen2.5-14b-s1", "rejected_approval", meta={"round": 1})
        self.add_run("req-013-qwen2.5-14b-s2", "aborted", meta={"round": 1})
        r = self.build()
        self.assertEqual(r["candidates"], [])
        self.assertEqual(r["not_probed"], {"rejected_approval": 1})
        self.assertEqual(r["aborted"], [{"scenario": "req-013", "candidate": "req-013-qwen2.5-14b-s2", "count": 1}])

    def test_result_without_set_is_an_error(self):
        self.add_run("gold", "applied", [res("n-001", "normal", True, None)])
        with self.assertRaisesRegex(probe_sets.ProbeSetsError, "set 없음"):
            self.build()

    def test_status_and_results_must_agree(self):
        self.add_run("gold", "applied", [res("n-001", "normal", False)])
        with self.assertRaisesRegex(probe_sets.ProbeSetsError, "실패한 프로브"):
            self.build()
        self.runs.clear()
        self.add_run("gold", "rolled_back", [res("n-001", "normal", True)], rep=2)
        with self.assertRaisesRegex(probe_sets.ProbeSetsError, "실패한 프로브"):
            self.build()
        self.runs.clear()
        self.add_run("gold", "applied", [res("n-001", "normal", True)], rep=3, rolled_back=True)
        with self.assertRaisesRegex(probe_sets.ProbeSetsError, "rolled_back 이 다름"):
            self.build()

    def test_missing_output_is_an_error(self):
        self.add_run("gold", "applied")
        with self.assertRaisesRegex(probe_sets.ProbeSetsError, "deploy.json 없음"):
            self.build()


class MainTest(Base):
    def test_unfinished_batch_is_an_error(self):
        path = self.root / "batch-20261120-090000.json"
        path.write_text(json.dumps({"commit": "abc123", "dirty": False, "finished": None, "runs": []}),
                        encoding="utf-8")
        with mock.patch("sys.argv", ["probe_sets.py", str(path)]), \
                self.assertRaisesRegex(SystemExit, "끝나지 않은 배치"):
            probe_sets.main()


if __name__ == "__main__":
    unittest.main()
