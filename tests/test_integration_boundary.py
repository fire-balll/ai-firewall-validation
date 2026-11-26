"""Offline regression for PR48 integration; no real nft or VM execution."""
import ast
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

from common.ir import ROOT
from deployer import deploy


class IntegrationBoundaryTest(unittest.TestCase):
    def test_legacy_partial_probe_aborts_and_restores_instead_of_accepting_empty_results(self):
        scenario = {'probes': [{'id': 'n-001', 'kind': 'normal', 'expect': 'allow'}]}
        argv = ['deploy.py', 'candidate.json', '--scenario', 'scenario.json', '--watch', '0']
        for rows in ([], [{'id': 'n-001', 'kind': 'normal', 'expect': 'allow',
                           'observed': 'block', 'pass': True, 'evidence': 'synthetic'}],
                     [{'id': 'n-001', 'kind': 'attack', 'expect': 'allow',
                       'observed': 'allow', 'pass': True, 'evidence': 'synthetic'}],
                     [{'id': 'wrong', 'kind': 'normal', 'expect': 'allow',
                       'observed': 'allow', 'pass': True, 'evidence': 'synthetic'}]):
            with self.subTest(rows=rows), mock.patch('sys.argv', argv), \
                    mock.patch.object(deploy, 'load_json', side_effect=[scenario, {'rules': []}]), \
                    mock.patch.object(deploy, 'require_lab'), \
                    mock.patch.object(deploy, 'snapshot', return_value='baseline'), \
                    mock.patch.object(deploy.deadman, 'recover', return_value=[]), \
                    mock.patch.object(deploy.deadman, 'arm', return_value='token'), \
                    mock.patch.object(deploy.deadman, 'disarm', return_value='disarmed') as disarm, \
                    mock.patch.object(deploy, 'to_nft', return_value='candidate'), \
                    mock.patch.object(deploy, 'nft_apply') as apply, \
                    mock.patch.object(deploy, 'probe', return_value={'results': rows}), \
                    mock.patch('sys.stdout', new_callable=io.StringIO) as output:
                with self.assertRaises(SystemExit) as exit_:
                    deploy.main()
                self.assertEqual(exit_.exception.code, 1)
                result = json.loads(output.getvalue())
                self.assertTrue(result['aborted'])
                self.assertFalse(result['rolled_back'])
                self.assertIsNone(result['mttr_s'])
                self.assertEqual(apply.call_args_list[-1].args, ('baseline',))
                disarm.assert_called_once_with('token')

    def test_default_snapshot_retains_main_command(self):
        with mock.patch.object(deploy, 'exec_in', return_value=SimpleNamespace(
                returncode=0, stdout='baseline\n', stderr='')) as call:
            self.assertEqual(deploy.snapshot(), 'flush ruleset\nbaseline\n')
        call.assert_called_once_with(deploy.FW, 'nft', 'list', 'ruleset')

    def test_deployer_does_not_import_validator_implementation(self):
        tree = ast.parse((ROOT / 'deployer/deploy.py').read_text(encoding='utf-8'))
        imports = [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
        self.assertFalse([name for name in imports if name and name.startswith('validator')])

    def test_compare_args_uses_unset_safe_array_expansion(self):
        text = (ROOT / 'pipeline/run.sh').read_text(encoding='utf-8')
        self.assertIn('${compare_args[@]+"${compare_args[@]}"}', text)

    def test_cli_receives_exact_store_mode_and_utf8(self):
        args = SimpleNamespace(ruleset='candidate.json', managed_store='store')
        response = {'ok': True, 'risk': 'low', 'reasons': [],
                    'candidate_sha256': 'a'*64,
                    'comparison': {'status': 'offline_only',
                                   'baseline_snapshot_token': 'b'*64,
                                   'counts': {'allow_to_block': 0, 'block_to_allow': 0}}}
        with mock.patch.object(deploy.subprocess, 'run', return_value=SimpleNamespace(
                returncode=0, stdout=json.dumps(response), stderr='')) as call:
            self.assertEqual(deploy.validator_check(args, False), response)
        command = call.call_args.args[0]
        self.assertEqual(command[2:], ['candidate.json', '--nft-check', '--stateful', 'no', '--compare-current'])
        self.assertEqual(call.call_args.kwargs['env']['FW_MANAGED_STORE'], 'store')
        self.assertEqual(call.call_args.kwargs['env']['PYTHONIOENCODING'], 'utf-8')

    def test_cli_nonzero_never_accepts_stdout_verdict(self):
        with mock.patch.object(deploy.subprocess, 'run', return_value=SimpleNamespace(
                returncode=3, stdout='{"ok":true}', stderr='tool unavailable')):
            with self.assertRaisesRegex(RuntimeError, 'CLI failed'):
                deploy.validator_check(SimpleNamespace(ruleset='x', managed_store='x'), True)

    def test_cli_invalid_json_or_incomplete_comparison_aborts(self):
        responses = ['', '[]', '{"ok":true}',
                     json.dumps({'ok': True, 'risk': 'low', 'reasons': [],
                                 'comparison': {'status': 'offline_only',
                                                'counts': {'allow_to_block': True, 'block_to_allow': 0}}})]
        for response in responses:
            with self.subTest(response=response), mock.patch.object(
                    deploy.subprocess, 'run', return_value=SimpleNamespace(
                        returncode=0, stdout=response, stderr='')):
                with self.assertRaisesRegex(RuntimeError, 'CLI JSON'):
                    deploy.validator_check(SimpleNamespace(ruleset='x', managed_store='x'), True)

    def test_real_validator_cli_rejects_missing_store_without_lab(self):
        args = SimpleNamespace(ruleset=str(ROOT / 'mutations/req-001-state-01.json'),
                               managed_store=str(ROOT / 'course010-absent-store'))
        with self.assertRaisesRegex(RuntimeError, 'validator CLI failed'):
            deploy.validator_check(args, False)


if __name__ == '__main__':
    unittest.main()
