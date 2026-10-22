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

    def run_eval(self, deploy=DEPLOY, env=None):
        argv = ["evaluate.py", "--scenario", "req-001", "--generator", "file:req-001-state-01",
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


if __name__ == "__main__":
    unittest.main()
