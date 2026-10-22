"""eval/evaluate.py 의 stateful 열 테스트. 랩 없이 돈다."""

import csv
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from common.ir import ROOT

spec = importlib.util.spec_from_file_location("evaluate", ROOT / "eval" / "evaluate.py")
evaluate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evaluate)

VALIDATION = {"ok": True, "risk": "low", "reasons": []}
DEPLOY = {"stateful": True, "applied": True, "rolled_back": False, "aborted": False, "error": None,
          "probe": {"results": []}}


class StatefulColumnTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.results = self.dir / "results.csv"
        patcher = mock.patch.object(evaluate, "RESULTS", self.results)
        patcher.start()
        self.addCleanup(patcher.stop)

    def write(self, name, obj):
        path = self.dir / name
        path.write_text(json.dumps(obj), encoding="utf-8")
        return str(path)

    def run_eval(self, deploy):
        argv = ["evaluate.py", "--scenario", "req-001", "--generator", "file:req-001-state-01",
                "--validation", self.write("validation.json", VALIDATION)]
        if deploy is not None:
            argv += ["--deploy", self.write("deploy.json", deploy)]
        with mock.patch("sys.argv", argv), mock.patch("sys.stdout"):
            evaluate.main()

    def stateful_column(self):
        with self.results.open(newline="") as f:
            return [r["stateful"] for r in csv.DictReader(f)]

    def test_stateful_comes_from_deploy(self):
        self.run_eval(DEPLOY)
        self.run_eval(dict(DEPLOY, stateful=False))
        self.assertEqual(self.stateful_column(), ["True", "False"])

    def test_stateful_is_empty_without_deploy(self):
        # 검증 반려·승인 거부로 적용하지 않은 경우
        self.run_eval(None)
        self.assertEqual(self.stateful_column(), [""])


if __name__ == "__main__":
    unittest.main()
