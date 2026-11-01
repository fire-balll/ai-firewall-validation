"""Consumer failure boundary; mocked lock/nft are not a live lab test."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from common.ir import ROOT, load_json
from deployer import deploy
from deployer.managed import digest


class CurrentConsumerBoundaryTest(unittest.TestCase):
    def test_lock_acquisition_failure_never_starts_apply(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            candidate = Path(tmp) / 'candidate.json'
            candidate.write_text(json.dumps(load_json(ROOT / 'scenarios/req-001.json')['gold']),
                                 encoding='utf-8')
            args = SimpleNamespace(managed_store=tmp, ruleset=str(candidate),
                                   expected_sha256=digest(candidate.read_bytes()),
                                   expected_current='b' * 64, approved_high=True,
                                   approved_replacement=True, scenario='scenarios/req-001.json',
                                   watch=0, interval=5)
            store = mock.Mock()
            store.locked.side_effect = RuntimeError('synthetic lock busy')
            with mock.patch('deployer.managed.ManagedStore', return_value=store), \
                 mock.patch('validator.validate.nft_check', return_value=[]), \
                 mock.patch('deployer.deploy.nft_apply') as apply, \
                 mock.patch('deployer.deploy.snapshot') as snapshot, \
                 mock.patch('deployer.deploy.probe') as probe, \
                 mock.patch('deployer.deploy.subprocess.run',
                            return_value=SimpleNamespace(stdout='a' * 40)):
                with self.assertRaisesRegex(RuntimeError, 'lock busy'):
                    deploy.managed_apply(args, True)
            store.current.assert_not_called()
            store.intent.assert_not_called()
            apply.assert_not_called()
            snapshot.assert_not_called()
            probe.assert_not_called()


if __name__ == '__main__':
    unittest.main()
