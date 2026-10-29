"""eval/feedback.py 피드백 JSON 생성 테스트. 랩 없이 돈다."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from eval import feedback

HOSTS = {"pc": "10.10.20.10", "attacker": "10.10.10.66", "server": "10.10.30.10"}
META = {"model": "qwen2.5:14b", "digest": "sha256:7cdf", "ollama_version": "0.40.3",
        "temperature": 0.7, "seed": 1, "prompt_version": "v2", "round": 1}
SCENARIO = {"id": "req-001", "probes": [
    {"id": "n-001", "kind": "normal", "from": "pc", "to": "10.10.30.10", "proto": "tcp", "port": 80,
     "expect": "allow"},
    {"id": "a-001", "kind": "attack", "from": "attacker", "to": "10.10.30.10", "proto": "tcp", "port": 8080,
     "tool": "nmap", "expect": "block"},
    {"id": "a-002", "kind": "attack", "from": "attacker", "to": "10.10.20.10", "proto": "icmp",
     "expect": "block"},
]}
LOW = {"ok": True, "errors": [], "risk": "low", "reasons": [], "anomalies": [{"type": "correlation"}]}
HIGH = {"ok": True, "errors": [], "risk": "high", "reasons": ["r-001: accept 범위가 /16 보다 넓음"],
        "anomalies": [{"type": "correlation"}]}
BAD = {"ok": False, "errors": ["rules/0/dst: does not match"], "risk": None, "reasons": [], "anomalies": []}


def probe_result(pid, kind, expect, observed):
    return {"id": pid, "kind": kind, "expect": expect, "observed": observed, "pass": expect == observed}


ROLLED_BACK = {"stateful": True, "rolled_back": True, "probe": {"results": [
    probe_result("n-001", "normal", "allow", "allow"),
    probe_result("a-001", "attack", "block", "allow"),
    probe_result("a-002", "attack", "block", "allow"),
]}}


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        (self.root / "scenarios").mkdir()
        (self.root / "scenarios" / "req-001.json").write_text(json.dumps(SCENARIO), encoding="utf-8")
        for name, value in (("ROOT", self.root), ("SCENARIOS", self.root / "scenarios")):
            patcher = mock.patch.object(feedback, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.runs = []

    def add_run(self, candidate, status, rep=1, validation=LOW, deploy=None, meta=META):
        out = f"out/batch-x/req-001-{candidate}-r{rep}"
        (self.root / out).mkdir(parents=True)
        if validation is not None:
            (self.root / out / "validation.json").write_text(json.dumps(validation), encoding="utf-8")
        if deploy is not None:
            (self.root / out / "deploy.json").write_text(json.dumps(deploy), encoding="utf-8")
        run = {"scenario": "req-001", "candidate": candidate, "rep": rep, "status": status, "out": out}
        if meta is not None:
            run["meta"] = meta
        self.runs.append(run)

    def build(self):
        manifest = {"commit": "abc123", "dirty": False, "finished": "t", "runs": self.runs}
        return feedback.build(manifest, "20261030-090000", HOSTS)


class FeedbackTest(Base):
    def test_rolled_back_lists_only_failed_probes_with_definitions(self):
        self.add_run("c-s1", "rolled_back", deploy=ROLLED_BACK)
        [(name, fb)], skipped = self.build()
        self.assertEqual((name, fb["stage"], fb["round"]), ("c-s1", "deploy", 1))
        self.assertEqual(fb["source"], {"batch_id": "20261030-090000", "rep": 1, "commit": "abc123"})
        self.assertEqual([p["id"] for p in fb["failed_probes"]], ["a-001", "a-002"])
        self.assertEqual(fb["failed_probes"][0], {
            "id": "a-001", "kind": "attack", "from": "attacker", "from_ip": "10.10.10.66",
            "to": "10.10.30.10", "proto": "tcp", "port": 8080, "expect": "block", "observed": "allow"})
        self.assertNotIn("port", fb["failed_probes"][1])  # icmp
        self.assertNotIn("tool", fb["failed_probes"][0])
        self.assertNotIn("anomalies", fb["validation"])

    def test_approval_rejection_gives_reasons_only(self):
        self.add_run("c-s1", "rejected_approval", validation=HIGH)
        [(_, fb)], _ = self.build()
        self.assertEqual(fb["stage"], "approval")
        self.assertEqual(fb["validation"]["reasons"], HIGH["reasons"])
        self.assertEqual(fb["failed_probes"], [])

    def test_validation_rejection_gives_errors(self):
        self.add_run("c-s1", "rejected_validation", validation=BAD)
        [(_, fb)], _ = self.build()
        self.assertEqual((fb["stage"], fb["validation"]["errors"]), ("validation", BAD["errors"]))

    def test_applied_aborted_gold_and_mutations_make_no_feedback(self):
        self.add_run("c-s1", "applied")
        self.add_run("c-s2", "aborted", validation=None)
        self.add_run("gold", "rolled_back", deploy=ROLLED_BACK, meta=None)
        self.add_run("req-001-port-01", "rolled_back", deploy=ROLLED_BACK, meta=None)
        feedback_list, skipped = self.build()
        self.assertEqual(feedback_list, [])
        self.assertEqual({(s["candidate"], s["status"]) for s in skipped},
                         {("c-s1", "applied"), ("c-s2", "aborted")})

    def test_first_non_aborted_rep_is_used(self):
        self.add_run("c-s1", "aborted", rep=1, validation=None)
        self.add_run("c-s1", "rolled_back", rep=2, deploy=ROLLED_BACK)
        self.add_run("c-s1", "applied", rep=3)
        [(_, fb)], skipped = self.build()
        self.assertEqual(fb["source"]["rep"], 2)
        self.assertEqual(sorted(s["rep"] for s in skipped), [1, 3])

    def test_round_comes_from_meta(self):
        self.add_run("c-s1-r2", "rejected_approval", validation=HIGH, meta=dict(META, round=2))
        [(_, fb)], _ = self.build()
        self.assertEqual(fb["round"], 2)

    def test_rolled_back_without_failed_probe_is_an_error(self):
        deploy = {"rolled_back": True, "probe": {"results": [probe_result("n-001", "normal", "allow", "allow")]}}
        self.add_run("c-s1", "rolled_back", deploy=deploy)
        with self.assertRaisesRegex(feedback.FeedbackError, "실패한 프로브가 없음"):
            self.build()

    def test_unknown_probe_id_is_an_error(self):
        deploy = {"rolled_back": True, "probe": {"results": [probe_result("a-099", "attack", "block", "allow")]}}
        self.add_run("c-s1", "rolled_back", deploy=deploy)
        with self.assertRaisesRegex(feedback.FeedbackError, "a-099"):
            self.build()

    def test_missing_output_is_an_error(self):
        self.add_run("c-s1", "rolled_back", deploy=None)
        with self.assertRaisesRegex(feedback.FeedbackError, "deploy.json 없음"):
            self.build()


class MainTest(Base):
    def run_main(self, *extra, **manifest_overrides):
        manifest = dict({"commit": "abc123", "dirty": False, "finished": "t", "runs": self.runs},
                        **manifest_overrides)
        path = self.root / "batch-20261030-090000.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        self.out_dir = self.root / "generated"
        argv = ["feedback.py", str(path), "--out-dir", str(self.out_dir), *extra]
        with mock.patch("sys.argv", argv), mock.patch("sys.stdout"), \
                mock.patch.object(feedback, "hosts", return_value=HOSTS):
            feedback.main()

    def test_writes_feedback_file(self):
        self.add_run("c-s1", "rolled_back", deploy=ROLLED_BACK)
        self.run_main()
        fb = json.loads((self.out_dir / "c-s1.feedback.json").read_text(encoding="utf-8"))
        self.assertEqual(fb["candidate"], "c-s1")

    def test_dry_run_writes_nothing(self):
        self.add_run("c-s1", "rolled_back", deploy=ROLLED_BACK)
        self.run_main("--dry-run")
        self.assertFalse(self.out_dir.exists())

    def test_unfinished_batch_is_an_error(self):
        self.add_run("c-s1", "rolled_back", deploy=ROLLED_BACK)
        with self.assertRaisesRegex(SystemExit, "끝나지 않은 배치"):
            self.run_main(finished=None)

    def test_dirty_batch_needs_flag(self):
        self.add_run("c-s1", "rolled_back", deploy=ROLLED_BACK)
        with self.assertRaisesRegex(SystemExit, "커밋 안 된 변경"):
            self.run_main(dirty=True)
        self.run_main("--allow-dirty", dirty=True)
        self.assertTrue((self.out_dir / "c-s1.feedback.json").exists())

    def test_existing_file_is_not_overwritten_and_nothing_is_written(self):
        self.add_run("c-s1", "rolled_back", deploy=ROLLED_BACK)
        self.add_run("c-s2", "rejected_approval", validation=HIGH)
        self.out_dir = self.root / "generated"
        self.out_dir.mkdir()
        (self.out_dir / "c-s1.feedback.json").write_text("old", encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "이미 있는 피드백 파일"):
            self.run_main()
        self.assertEqual((self.out_dir / "c-s1.feedback.json").read_text(encoding="utf-8"), "old")
        self.assertFalse((self.out_dir / "c-s2.feedback.json").exists())
        self.run_main("--overwrite")
        self.assertNotEqual((self.out_dir / "c-s1.feedback.json").read_text(encoding="utf-8"), "old")

    def test_error_in_one_run_writes_nothing(self):
        self.add_run("c-s1", "rejected_approval", validation=HIGH)
        self.add_run("c-s2", "rolled_back", deploy=None)
        with self.assertRaisesRegex(SystemExit, "deploy.json 없음"):
            self.run_main()
        self.assertFalse(self.out_dir.exists())


if __name__ == "__main__":
    unittest.main()
