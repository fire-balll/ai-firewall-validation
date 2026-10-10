"""common/lab.py 테스트. 컨테이너 없이 subprocess 호출 인자만 확인한다."""

import subprocess
import unittest
from unittest import mock

from common import lab


class ExecInTest(unittest.TestCase):
    def run_with(self, stdin):
        fake = subprocess.CompletedProcess([], 0, "출력\n".encode("utf-8"), b"")
        with mock.patch.object(lab.subprocess, "run", return_value=fake) as run:
            res = lab.exec_in("fw", "nft", "-f", "-", stdin=stdin)
        return run.call_args.kwargs, res

    def test_stdin_is_passed_as_utf8_bytes_without_newline_translation(self):
        kwargs, _ = self.run_with("flush ruleset\ntable inet fwlab {\n}\n")
        self.assertIsInstance(kwargs["input"], bytes)
        self.assertNotIn(b"\r", kwargs["input"])
        self.assertFalse(kwargs.get("text", False))

    def test_output_is_decoded_to_str(self):
        _, res = self.run_with(None)
        self.assertEqual(res.stdout, "출력\n")
        self.assertEqual(res.stderr, "")

    def test_no_stdin(self):
        kwargs, _ = self.run_with(None)
        self.assertIsNone(kwargs["input"])


if __name__ == "__main__":
    unittest.main()
