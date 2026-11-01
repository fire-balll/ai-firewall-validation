"""The legacy self-attested reader must never act as a live provider."""
import os
import subprocess
import sys
import unittest
from unittest import mock

from common.ir import ROOT
from validator.live_current import LiveCurrentProvider, live_snapshot


class CurrentReaderTest(unittest.TestCase):
    def test_legacy_json_record_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'legacy current record unsupported'):
            LiveCurrentProvider('any/current.json')

    @mock.patch('validator.live_current.require_lab')
    @mock.patch('validator.live_current.exec_in')
    def test_partial_or_failed_nft_collection_rejected(self, run, lab):
        for code, stdout in ((125, ''), (0, '')):
            with self.subTest(code=code):
                run.return_value = mock.Mock(returncode=code, stdout=stdout, stderr='unavailable')
                with self.assertRaisesRegex(RuntimeError, 'nft snapshot unavailable'):
                    live_snapshot()
        lab.side_effect = RuntimeError('lab unavailable')
        with self.assertRaisesRegex(RuntimeError, 'lab unavailable'):
            live_snapshot()

    def test_cli_missing_record_has_no_verdict(self):
        env = os.environ.copy()
        env.pop('FW_MANAGED_STORE', None)
        result = subprocess.run([sys.executable, 'validator/validate.py',
                                 'scenarios/req-001.json', '--stateful', 'yes', '--compare-current'],
                                cwd=ROOT, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertIn('current', result.stderr)


if __name__ == '__main__':
    unittest.main()