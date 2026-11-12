"""deployer/deploy.py 흐름 테스트. 랩·nft·타이머는 mock 으로 바꾸고 순서와 결과 JSON 만 확인한다."""

import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from unittest import mock

from deployer import deploy

PASS = {"results": [{"id": "n-001", "pass": True}]}
FAIL = {"results": [{"id": "n-001", "pass": False}]}


class DeployFlowTest(unittest.TestCase):
    def run_deploy(self, probes, disarm="disarmed", apply_error=None, recovered=()):
        calls = []
        applied = []

        def nft_apply(text):
            calls.append("apply")
            if apply_error and not applied:
                raise RuntimeError(apply_error)
            applied.append(text)

        patches = {
            "require_lab": mock.DEFAULT, "snapshot": mock.Mock(return_value="SAVED"),
            "nft_apply": mock.Mock(side_effect=nft_apply),
            "probe": mock.Mock(side_effect=list(probes)), "load_json": mock.Mock(return_value={"rules": []}),
            "to_nft": mock.Mock(return_value="CANDIDATE"),
        }
        dm = mock.Mock()
        dm.recover.return_value = list(recovered)
        dm.arm.side_effect = lambda saved, ttl: calls.append(f"arm:{saved}:{ttl}") or "t" * 32
        dm.disarm.side_effect = lambda token: calls.append("disarm") or disarm
        buf = io.StringIO()
        argv = ["deploy.py", "c.json", "--scenario", "s.json", "--watch", "0", "--interval", "1"]
        with mock.patch.multiple(deploy, **patches), mock.patch.object(deploy, "deadman", dm), \
                mock.patch.object(sys, "argv", argv), redirect_stdout(buf):
            try:
                deploy.main()
                code = 0
            except SystemExit as e:
                code = e.code
        return code, json.loads(buf.getvalue()), calls, applied

    def test_pass_arms_before_apply_and_disarms(self):
        code, out, calls, applied = self.run_deploy([PASS])
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["arm:SAVED:300", "apply", "disarm"])
        self.assertEqual(applied, ["CANDIDATE"])
        self.assertEqual(out["deadman"], "disarmed")
        self.assertFalse(out["rolled_back"])

    def test_rollback_restores_then_disarms(self):
        code, out, calls, applied = self.run_deploy([FAIL])
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["arm:SAVED:300", "apply", "apply", "disarm"])
        self.assertEqual(applied, ["CANDIDATE", "SAVED"])
        self.assertTrue(out["rolled_back"])

    def test_timer_fired_during_watch_is_aborted_not_result(self):
        # 타이머가 감시 중에 만료됐으면 프로브가 원래 룰셋을 봤을 수 있으므로 결과로 내지 않는다
        code, out, _, applied = self.run_deploy([PASS], disarm="fired")
        self.assertEqual(code, 1)
        self.assertTrue(out["aborted"])
        self.assertIn("데드맨", out["error"])
        self.assertEqual(applied, ["CANDIDATE", "SAVED"])

    def test_aborted_after_rollback_clears_timings(self):
        # 롤백한 뒤 타이머가 이미 만료돼 있었으면 실행 실패다. 복구 시간이 결과처럼 남지 않아야 한다 (#54 리뷰)
        code, out, _, _ = self.run_deploy([FAIL], disarm="fired")
        self.assertEqual(code, 1)
        self.assertTrue(out["aborted"])
        self.assertTrue(out["rolled_back"])
        self.assertIsNone(out["detect_s"])
        self.assertIsNone(out["mttr_s"])

    def test_apply_failure_disarms_and_aborts(self):
        code, out, calls, _ = self.run_deploy([], apply_error="nft -f 실패")
        self.assertEqual(code, 1)
        self.assertTrue(out["aborted"])
        self.assertFalse(out["applied"])
        self.assertEqual(calls, ["arm:SAVED:300", "apply", "disarm"])

    def test_probe_error_restores_and_disarms(self):
        code, out, calls, applied = self.run_deploy([RuntimeError("prober 실패")])
        self.assertEqual(code, 1)
        self.assertTrue(out["aborted"])
        self.assertEqual(applied, ["CANDIDATE", "SAVED"])
        self.assertEqual(calls[-1], "disarm")
        self.assertEqual(out["deadman"], "disarmed")

    def test_recovered_leftover_is_reported(self):
        _, out, _, _ = self.run_deploy([PASS], recovered=["a" * 32])
        self.assertEqual(out["recovered"], ["a" * 32])


if __name__ == "__main__":
    unittest.main()
