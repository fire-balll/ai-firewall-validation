"""#48 minimal legacy safety regressions; never launches Podman/nft."""
import io
import json
import subprocess
import unittest
from unittest import mock
from deployer import deploy

class ProbeBoundaryTest(unittest.TestCase):
    def test_probe_child_has_finite_timeout(self):
        with mock.patch.object(deploy, 'require_lab'), mock.patch.object(
                deploy.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '{"results": []}', '')) as run:
            deploy.probe('scenario.json')
        self.assertGreater(run.call_args.kwargs.get('timeout', 0), 0)
        self.assertLessEqual(run.call_args.kwargs['timeout'], 300)

    def test_empty_observation_aborts_restores_and_disarms(self):
        saved = 'flush ruleset\n# saved'
        scenario = {'probes': [{'id': 'n-001', 'kind': 'normal', 'expect': 'allow'}]}
        def load(path):
            return scenario if path == 'scenario.json' else {'rules': []}
        output = io.StringIO()
        with mock.patch.object(deploy, 'load_json', side_effect=load), \
                mock.patch.object(deploy, 'require_lab'), \
                mock.patch.object(deploy, 'snapshot', return_value=saved), \
                mock.patch.object(deploy.deadman, 'recover', return_value=[]), \
                mock.patch.object(deploy.deadman, 'arm', return_value='a'*32), \
                mock.patch.object(deploy.deadman, 'disarm', return_value='disarmed') as disarm, \
                mock.patch.object(deploy, 'nft_apply') as apply, \
                mock.patch.object(deploy, 'to_nft', return_value='candidate'), \
                mock.patch.object(deploy, 'probe', return_value={'results': []}), \
                mock.patch('sys.argv', ['deploy.py', 'candidate.json', '--scenario', 'scenario.json', '--watch', '0']), \
                mock.patch('sys.stdout', output):
            with self.assertRaises(SystemExit) as exit_:
                deploy.main()
        self.assertEqual(exit_.exception.code, 1)
        out = json.loads(output.getvalue())
        self.assertTrue(out['aborted'])
        self.assertIsNone(out['detect_s'])
        self.assertIsNone(out['mttr_s'])
        self.assertEqual(apply.call_args_list, [mock.call('candidate'), mock.call(saved)])
        disarm.assert_called_once_with('a'*32)


class DeadmanBudgetTest(unittest.TestCase):
    def test_small_grace_aborts_restores_without_starting_child(self):
        from contextlib import ExitStack, redirect_stdout
        from tests.test_deploy import PASS
        output = io.StringIO()
        with ExitStack() as stack:
            for name, value in {'require_lab': None, 'snapshot': 'SAVED', 'nft_apply': None,
                                'to_nft': 'CANDIDATE'}.items():
                boundary = stack.enter_context(mock.patch.object(deploy, name, return_value=value))
                if name == 'nft_apply':
                    apply = boundary
            stack.enter_context(mock.patch.object(deploy, 'load_json', return_value={
                'probes': [{'id': 'n-001', 'kind': 'normal', 'expect': 'allow'}]}))
            stack.enter_context(mock.patch.object(deploy.deadman, 'recover', return_value=[]))
            stack.enter_context(mock.patch.object(deploy.deadman, 'arm', return_value='a'*32))
            stack.enter_context(mock.patch.object(deploy.deadman, 'disarm', return_value='disarmed'))
            stack.enter_context(mock.patch.object(deploy.time, 'monotonic', return_value=100))
            child = stack.enter_context(mock.patch.object(deploy.subprocess, 'run'))
            stack.enter_context(mock.patch('sys.argv', ['deploy.py', 'c.json', '--scenario', 's.json', '--watch', '0', '--deadman-grace', '10']))
            stack.enter_context(redirect_stdout(output))
            with self.assertRaises(SystemExit) as stopped:
                deploy.main()
        self.assertEqual(stopped.exception.code, 1)
        out = json.loads(output.getvalue())
        self.assertTrue(out['aborted'])
        self.assertIsNone(out['mttr_s'])
        self.assertEqual(out['deadman'], 'disarmed')
        child.assert_not_called()

        self.assertEqual(apply.call_args_list, [mock.call('CANDIDATE'), mock.call('SAVED')])


    def test_main_supplies_arm_start_deadline(self):
        from contextlib import ExitStack, redirect_stdout
        from tests.test_deploy import PASS
        output = io.StringIO()
        with ExitStack() as stack:
            for name, value in {'require_lab': None, 'snapshot': 'SAVED', 'nft_apply': None,
                                'to_nft': 'CANDIDATE'}.items():
                stack.enter_context(mock.patch.object(deploy, name, return_value=value))
            stack.enter_context(mock.patch.object(deploy, 'load_json', return_value={
                'probes': [{'id': 'n-001', 'kind': 'normal', 'expect': 'allow'}]}))
            stack.enter_context(mock.patch.object(deploy.deadman, 'recover', return_value=[]))
            stack.enter_context(mock.patch.object(deploy.deadman, 'arm', return_value='a'*32))
            stack.enter_context(mock.patch.object(deploy.deadman, 'disarm', return_value='disarmed'))
            stack.enter_context(mock.patch.object(deploy.time, 'monotonic', return_value=100))
            boundary = stack.enter_context(mock.patch.object(deploy, 'probe', return_value=PASS))
            stack.enter_context(mock.patch('sys.argv', ['deploy.py', 'c.json', '--scenario', 's.json', '--watch', '0']))
            stack.enter_context(redirect_stdout(output))
            deploy.main()
        self.assertEqual(boundary.call_args.kwargs.get('deadman_deadline'), 400)


    def test_child_budget_accounts_for_elapsed_lab_check_and_restore_reserve(self):
        with mock.patch.object(deploy, 'require_lab'), mock.patch.object(
                deploy.time, 'monotonic', side_effect=[100, 125]), mock.patch.object(
                deploy.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '{"results": []}', '')) as run:
            deploy.probe('scenario.json', deadman_deadline=300)
        self.assertEqual(run.call_args.kwargs['timeout'], 84)

    def test_exhausted_budget_does_not_launch_child(self):
        with mock.patch.object(deploy, 'require_lab'), mock.patch.object(
                deploy.time, 'monotonic', return_value=210), mock.patch.object(deploy.subprocess, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'budget'):
                deploy.probe('scenario.json', deadman_deadline=300)
        run.assert_not_called()


class ObservationContractTest(unittest.TestCase):
    def test_real_prober_output_rows_match_deployer_contract(self):
        from common.ir import ROOT, load_json
        from prober import probe as actual
        for path in (ROOT / 'scenarios').glob('req-*.json'):
            scenario = load_json(path)
            rows = []
            for p in scenario['probes']:
                with mock.patch.object(actual, 'exec_in', return_value=subprocess.CompletedProcess([], 0, '', '')), \
                        mock.patch.object(actual, 'judge', return_value=(p['expect'], 'isolated lab observation')), \
                        mock.patch.object(actual, 'target_alive', return_value=(True, 'isolated alive')), \
                        mock.patch.object(actual, 'echo_alive', return_value=True):
                    rows.append(actual.run_probe(p))
            with mock.patch.object(actual, 'load_json', return_value=scenario), \
                    mock.patch.object(actual, 'run_probe', side_effect=rows), \
                    mock.patch('sys.argv', ['probe.py', str(path)]), mock.patch('sys.stdout', new_callable=io.StringIO) as output:
                actual.main()
            emitted = json.loads(output.getvalue())
            with self.subTest(scenario=path.name):
                self.assertEqual(deploy.complete_probe(emitted, {p['id']: p for p in scenario['probes']}), rows)
                self.assertTrue(all(set(r) == {'id', 'kind', 'set', 'expect', 'observed', 'pass', 'evidence'} for r in rows))


    def test_all_current_scenario_rows_including_v2_are_accepted(self):
        from common.ir import ROOT, load_json
        for path in (ROOT/'scenarios').glob('req-*.json'):
            probes = load_json(path)['probes']
            expected = {p['id']: p for p in probes}
            rows = [dict(id=p['id'], kind=p['kind'], expect=p['expect'], set=p.get('set', 'v1'), observed=p['expect'], **{'pass': True}, evidence='synthetic') for p in probes]
            with self.subTest(scenario=path.name):
                self.assertEqual(deploy.complete_probe({'results': rows}, expected), rows)

    def test_incomplete_duplicate_inconsistent_and_foreign_rows_are_rejected(self):
        expected = {'n-001': {'kind': 'normal', 'expect': 'allow'}}
        row = {'id': 'n-001', 'kind': 'normal', 'expect': 'allow', 'observed': 'allow', 'pass': True}
        bad = [None, {}, {'results': []}, {'results': [row, row]}]
        for changes in ({'id': 'foreign'}, {'kind': 'attack'}, {'expect': 'block'}, {'pass': 1}, {'pass': False}, {'observed': 'unknown'}, {'set': 'v2'}, {'set': None}, {'evidence': []}, {'unknown': True}):
            bad.append({'results': [row | changes]})
        for key in row:
            bad.append({'results': [{k:v for k,v in row.items() if k != key}]})
        for result in bad:
            with self.subTest(result=result), self.assertRaises(RuntimeError):
                deploy.complete_probe(result, expected)

    def test_timeout_uses_existing_abort_restore_disarm_path(self):
        from tests.test_deploy import DeployFlowTest
        code, out, calls, applied = DeployFlowTest().run_deploy([subprocess.TimeoutExpired('synthetic child', 300)])
        self.assertEqual(code, 1)
        self.assertTrue(out['aborted'])
        self.assertIsNone(out['detect_s'])
        self.assertIsNone(out['mttr_s'])
        self.assertEqual(applied, ['CANDIDATE', 'SAVED'])
        self.assertEqual(calls[-1], 'disarm')
