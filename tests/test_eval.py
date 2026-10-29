"""eval/evaluate.py 의 CSV 기록 테스트. 랩 없이 돈다."""

import csv
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from common.ir import ROOT

spec = importlib.util.spec_from_file_location("evaluate", ROOT / "eval" / "evaluate.py")
evaluate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evaluate)

VALIDATION = {"ok": True, "risk": "low", "reasons": []}
DEPLOY = {"stateful": False, "applied": True, "rolled_back": False, "aborted": False, "error": None,
          "probe": {"results": [
              {"id": "n-001", "kind": "normal", "expect": "allow", "observed": "allow", "pass": True},
              {"id": "a-001", "kind": "attack", "expect": "block", "observed": "allow", "pass": False},
          ]}}
SCENARIO = str(ROOT / "scenarios" / "req-001.json")
GOLD = json.loads(Path(SCENARIO).read_text(encoding="utf-8"))["gold"]
BATCH_ENV = {"BATCH_ID": "20261030-090000", "REP": "2", "COMMIT": "45b2ee6" + "0" * 33}


class EvaluateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.results = self.dir / "results" / "results.csv"
        patcher = mock.patch.object(evaluate, "RESULTS", self.results)
        patcher.start()
        self.addCleanup(patcher.stop)
        # 테스트를 돌리는 셸에 배치 변수가 있어도 영향받지 않게 한다
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        for k in BATCH_ENV:
            os.environ.pop(k, None)

    def write(self, name, obj):
        path = self.dir / name
        path.write_text(json.dumps(obj), encoding="utf-8")
        return str(path)

    def run_eval(self, deploy=DEPLOY, env=None, candidate=GOLD, scenario=SCENARIO):
        argv = ["evaluate.py", "--scenario", "req-001", "--scenario-file", scenario,
                "--generator", "file:req-001-state-01",
                "--candidate", self.write("candidate.json", candidate),
                "--validation", self.write("validation.json", VALIDATION)]
        if deploy is not None:
            argv += ["--deploy", self.write("deploy.json", deploy)]
        with mock.patch("sys.argv", argv), mock.patch.dict(os.environ, env or {}), \
                mock.patch("sys.stdout"):
            evaluate.main()

    def rows(self):
        with self.results.open(newline="") as f:
            return list(csv.DictReader(f))

    def test_batch_env_is_recorded(self):
        self.run_eval(env=BATCH_ENV)
        row = self.rows()[0]
        self.assertEqual((row["batch_id"], row["rep"], row["commit"]),
                         (BATCH_ENV["BATCH_ID"], BATCH_ENV["REP"], BATCH_ENV["COMMIT"]))

    def test_single_run_leaves_batch_columns_empty(self):
        self.run_eval()
        row = self.rows()[0]
        self.assertEqual((row["batch_id"], row["rep"], row["commit"]), ("", "", ""))

    def test_rates_empty_without_deploy(self):
        # 검증 반려·승인 거부로 적용하지 않은 경우
        self.run_eval(deploy=None)
        row = self.rows()[0]
        self.assertEqual((row["normal_pass_rate"], row["attack_block_rate"]), ("", ""))

    def test_rates_unchanged(self):
        self.run_eval()
        row = self.rows()[0]
        self.assertEqual((row["normal_pass_rate"], row["attack_block_rate"]), ("1.0", "0.0"))

    def test_stateful_comes_from_deploy(self):
        self.run_eval()
        self.run_eval(deploy=dict(DEPLOY, stateful=True))
        self.assertEqual([r["stateful"] for r in self.rows()], ["False", "True"])

    def test_stateful_is_empty_without_deploy(self):
        # 검증 반려·승인 거부로 적용하지 않은 경우
        self.run_eval(deploy=None)
        self.assertEqual(self.rows()[0]["stateful"], "")

    def test_column_order(self):
        # 열 순서를 바꾸면 기존 CSV 와 맞지 않으므로 순서를 고정해 둔다
        self.run_eval()
        header = self.results.read_text(encoding="utf-8").splitlines()[0]
        self.assertEqual(header, "timestamp,batch_id,rep,commit,scenario,generator,stateful,valid,risk,"
                                 "approved,normal_pass_rate,attack_block_rate,rolled_back,detect_s,mttr_s,"
                                 "semantic_match,policy_diff,over_allow,over_block")

    def test_gold_candidate_matches(self):
        self.run_eval()
        row = self.rows()[0]
        self.assertEqual((row["semantic_match"], row["policy_diff"], row["over_allow"], row["over_block"]),
                         ("1.0", "False", "0", "0"))

    def test_widened_candidate_is_over_allow(self):
        cand = json.loads(json.dumps(GOLD))
        cand["rules"][0]["src"] = "any"
        self.run_eval(candidate=cand)
        row = self.rows()[0]
        self.assertEqual(row["policy_diff"], "True")
        self.assertGreater(int(row["over_allow"]), 0)
        self.assertEqual(row["over_block"], "0")
        self.assertLess(float(row["semantic_match"]), 1.0)

    def test_schema_invalid_candidate_leaves_semantic_empty(self):
        # 검증 반려(스키마 위반) 후보는 비교할 정책이 없다
        bad = {"rules": [dict(GOLD["rules"][0], dst="10.10.20.0/24,10.10.30.0/24")]}
        self.run_eval(deploy=None, candidate=bad)
        row = self.rows()[0]
        self.assertEqual([row[k] for k in evaluate.SEMANTIC], ["", "", "", ""])

    def test_scenario_without_gold_is_an_error(self):
        scenario = self.write("scenario.json", {"id": "req-x", "probes": []})
        with self.assertRaises(SystemExit) as cm:
            self.run_eval(scenario=scenario)
        self.assertIn("의미 일치율 계산 실패", str(cm.exception.code))
        self.assertFalse(self.results.exists())

    def test_header_written_once(self):
        self.run_eval()
        self.run_eval()
        lines = self.results.read_text(encoding="utf-8").splitlines()
        self.assertEqual(lines[0].split(","), evaluate.FIELDS)
        self.assertEqual(len(lines), 3)

    def test_empty_file_gets_header(self):
        self.results.parent.mkdir(parents=True)
        self.results.touch()
        self.run_eval()
        self.assertEqual(len(self.rows()), 1)

    def test_old_header_is_an_error_and_file_untouched(self):
        self.results.parent.mkdir(parents=True)
        old = "timestamp,scenario,generator,valid,risk,approved,normal_pass_rate,attack_block_rate," \
              "rolled_back,detect_s,mttr_s\n2026-10-12T10:00:00,req-001,mock,True,low,,1.0,1.0,False,,\n"
        self.results.write_text(old, encoding="utf-8")
        with self.assertRaises(SystemExit) as cm:
            self.run_eval()
        self.assertIn("열이 지금 형식과 다름", str(cm.exception.code))
        self.assertEqual(self.results.read_text(encoding="utf-8"), old)

    def test_header_without_stateful_is_an_error(self):
        # #38 이후·stateful 열 추가 전에 만든 CSV
        self.results.parent.mkdir(parents=True)
        old = "timestamp,batch_id,rep,commit,scenario,generator,valid,risk,approved,normal_pass_rate," \
              "attack_block_rate,rolled_back,detect_s,mttr_s\n"
        self.results.write_text(old, encoding="utf-8")
        with self.assertRaises(SystemExit):
            self.run_eval()
        self.assertEqual(self.results.read_text(encoding="utf-8"), old)


if __name__ == "__main__":
    unittest.main()
