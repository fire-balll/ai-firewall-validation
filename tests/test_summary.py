"""eval/summary.py 배치 집계 테스트. 랩 없이 돈다."""

import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from eval import summary
from eval.evaluate import FIELDS

META = {"model": "qwen2.5:14b", "digest": "sha256:7cdf5a0187d5c58c", "ollama_version": "0.40.3",
        "temperature": 0.7, "seed": 1, "prompt_version": "v2", "round": 1}
GEN = "qwen2.5:14b@7cdf5a0187d5|t=0.7|seed=1|p=v2|r=1"


def run(candidate, rep, status, scenario="req-001", meta=None):
    r = {"scenario": scenario, "candidate": candidate, "rep": rep, "status": status, "out": "out/x"}
    if meta:
        r["meta"] = meta
    return r


def row(generator, rep, batch="b1", scenario="req-001", **kw):
    r = dict.fromkeys(FIELDS, "")
    r.update(batch_id=batch, rep=str(rep), scenario=scenario, generator=generator,
             normal_pass_rate="1.0", attack_block_rate="1.0", semantic_match="1.0", policy_diff="False")
    r.update({k: str(v) for k, v in kw.items()})
    return r


def manifest(*runs):
    return {"commit": "abc123", "dirty": False, "finished": "t", "runs": list(runs)}


class StatsTest(unittest.TestCase):
    def test_mean_std_ignores_empty(self):
        self.assertEqual(summary.stats(["1.0", "", "0.5", "0.0"]), {"mean": 0.5, "std": 0.5, "n": 3})

    def test_single_value_has_no_std(self):
        self.assertEqual(summary.stats(["0.3"]), {"mean": 0.3, "std": None, "n": 1})

    def test_no_values(self):
        self.assertEqual(summary.stats(["", ""]), {"mean": None, "std": None, "n": 0})

    def test_label_matches_run_sh_and_batch(self):
        self.assertEqual(summary.label(run("gold", 1, "applied")), "mock")
        self.assertEqual(summary.label(run("req-001-port-01", 1, "applied")), "file:req-001-port-01")
        self.assertEqual(summary.label(run("req-001-qwen2.5-14b-s1", 1, "applied", meta=META)), GEN)


class BuildTest(unittest.TestCase):
    def test_groups_by_scenario_and_candidate(self):
        m = manifest(run("gold", 1, "applied"), run("gold", 2, "applied"),
                     run("req-001-port-01", 1, "rolled_back"), run("req-001-port-01", 2, "rolled_back"))
        rows = [row("mock", 1), row("mock", 2),
                row("file:req-001-port-01", 1, normal_pass_rate=0.5, rolled_back=True, detect_s=10, mttr_s=0.2,
                    semantic_match=0.99, policy_diff=True),
                row("file:req-001-port-01", 2, normal_pass_rate=0.5, rolled_back=True, detect_s=12, mttr_s=0.4,
                    semantic_match=0.99, policy_diff=True)]
        r = summary.build([("b1", m)], rows)
        port = next(g for g in r["groups"] if g["candidate"] == "req-001-port-01")
        self.assertEqual((port["kind"], port["runs"], port["status"]), ("mutation", 2, {"rolled_back": 2}))
        self.assertEqual(port["detect_s"], {"mean": 11.0, "std": 1.4142, "n": 2})
        self.assertEqual(port["policy_diff"], 2)
        gold = next(g for g in r["groups"] if g["candidate"] == "gold")
        self.assertEqual(gold["detect_s"]["n"], 0)
        self.assertEqual(set(r["batches"][0]["kinds"]), {"gold", "mutation"})

    def test_aborted_is_counted_but_not_averaged(self):
        m = manifest(run("gold", 1, "aborted"), run("gold", 2, "applied"))
        r = summary.build([("b1", m)], [row("mock", 2, normal_pass_rate=0.8)])
        g = r["groups"][0]
        self.assertEqual((g["runs"], g["aborted"]), (2, 1))
        self.assertEqual(g["normal_pass_rate"], {"mean": 0.8, "std": None, "n": 1})
        self.assertEqual(r["batches"][0]["aborted"], 1)

    def test_rejected_runs_have_no_probe_metrics(self):
        m = manifest(run("req-002-port-any-01", 1, "rejected_approval", scenario="req-002"))
        rows = [row("file:req-002-port-any-01", 1, scenario="req-002", normal_pass_rate="", attack_block_rate="",
                    semantic_match=0.98, policy_diff=True)]
        g = summary.build([("b1", m)], rows)["groups"][0]
        self.assertEqual((g["normal_pass_rate"]["n"], g["semantic_match"]["n"]), (0, 1))

    def test_generated_rows_match_by_meta_label(self):
        m = manifest(run("req-001-qwen2.5-14b-s1", 1, "applied", meta=META))
        g = summary.build([("b1", m)], [row(GEN, 1)])["groups"][0]
        self.assertEqual((g["kind"], g["generator"]), ("generated", GEN))

    def test_other_batches_rows_are_ignored(self):
        m = manifest(run("gold", 1, "applied"))
        r = summary.build([("b1", m)], [row("mock", 1), row("mock", 1, batch="b2")])
        self.assertEqual(r["batches"][0]["runs"], 1)

    def test_missing_row_is_an_error(self):
        m = manifest(run("gold", 1, "applied"), run("gold", 2, "applied"))
        with self.assertRaisesRegex(summary.SummaryError, "r2: 맞는 CSV 줄이 0개"):
            summary.build([("b1", m)], [row("mock", 1)])

    def test_duplicate_row_is_an_error(self):
        m = manifest(run("gold", 1, "applied"))
        with self.assertRaisesRegex(summary.SummaryError, "2개"):
            summary.build([("b1", m)], [row("mock", 1), row("mock", 1)])

    def test_row_for_aborted_run_is_an_error(self):
        m = manifest(run("gold", 1, "aborted"))
        with self.assertRaisesRegex(summary.SummaryError, "aborted 인데 CSV 줄이 있음"):
            summary.build([("b1", m)], [row("mock", 1)])

    def test_row_not_in_manifest_is_an_error(self):
        m = manifest(run("gold", 1, "applied"))
        with self.assertRaisesRegex(summary.SummaryError, "manifest 에 없는 CSV 줄이 1개"):
            summary.build([("b1", m)], [row("mock", 1), row("mock", 1, scenario="req-009")])


class MainTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.results = self.root / "results.csv"
        with self.results.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=FIELDS)
            w.writeheader()
            w.writerow(row("mock", 1, batch="20261105-140710"))

    def run_main(self, *extra, **overrides):
        path = self.root / "batch-20261105-140710.json"
        path.write_text(json.dumps(dict(manifest(run("gold", 1, "applied")), **overrides)), encoding="utf-8")
        argv = ["summary.py", str(path), "--results", str(self.results), *extra]
        with mock.patch("sys.argv", argv), mock.patch("sys.stdout"):
            summary.main()
        return path

    def test_writes_group_csv(self):
        out = self.root / "summary.csv"
        self.run_main("--csv-out", str(out))
        with out.open(encoding="utf-8") as f:
            [g] = list(csv.DictReader(f))
        self.assertEqual((g["candidate"], g["applied"], g["normal_pass_rate_mean"], g["detect_s_mean"]),
                         ("gold", "1", "1.0", ""))

    def test_unfinished_batch_is_an_error(self):
        with self.assertRaisesRegex(SystemExit, "끝나지 않은 배치"):
            self.run_main(finished=None)

    def test_dirty_batch_needs_flag(self):
        with self.assertRaisesRegex(SystemExit, "커밋 안 된 변경"):
            self.run_main(dirty=True)
        self.run_main("--allow-dirty", dirty=True)

    def test_same_batch_twice_is_an_error(self):
        path = self.run_main()
        argv = ["summary.py", str(path), str(path), "--results", str(self.results)]
        with mock.patch("sys.argv", argv), self.assertRaisesRegex(SystemExit, "같은 배치가 두 번"):
            summary.main()

    def test_missing_results_csv_is_an_error(self):
        self.results.unlink()
        with self.assertRaisesRegex(SystemExit, "집계 중단"):
            self.run_main()


if __name__ == "__main__":
    unittest.main()
