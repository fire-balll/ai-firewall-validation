"""Managed path state-machine tests use synthetic nft; not a live lab."""
from contextlib import nullcontext
import hashlib
import base64
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from common.ir import ROOT, load_json, to_nft
from deployer import deploy
from deployer.managed import ManagedStore, digest, structure
from validator.replacement import CurrentRules


class FakeStore:
    def __init__(self, path, lab, ir):
        self.lab = lab
        self.raw = json.dumps(ir).encode()
        self.commit = 'a' * 40
        self.intent_seen = False
        self.events = []

    def locked(self):
        self.events.append('lock')
        return nullcontext()

    def current(self):
        self.events.append('read')
        if self.intent_seen:
            raise RuntimeError('unresolved managed intent')
        ir = json.loads(self.raw)
        structure(self.lab['text'], ir, True)
        return CurrentRules(self.raw, digest(self.raw), True,
                            self.commit, digest(self.lab['text'].encode()))

    read_verified_current = current

    def assert_still_current(self, current):
        if self.current() != current:
            raise RuntimeError('managed current changed')

    def intent(self, before, candidate, stateful, rollback_nft):
        self.intent_seen = True
        self.events.append('intent')

    def publish(self, raw, stateful, commit, observation):
        structure(observation, json.loads(raw), stateful)
        self.raw = raw
        self.commit = commit
        self.events.append('publish')

    def finish(self):
        self.intent_seen = False
        self.events.append('finish')


class ManagedTransactionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.ir = load_json(ROOT / 'scenarios/req-001.json')['gold']
        self.candidate = {'rules': []}
        self.path = Path(self.tmp.name) / 'candidate.json'
        self.path.write_text(json.dumps(self.candidate))
        self.lab = {'text': '\n'.join(to_nft(self.ir).splitlines()[1:]) + '\n'}
        self.store = FakeStore(self.tmp.name, self.lab, self.ir)
        self.probe_results = [dict(id=p['id'], kind=p['kind'], expect=p['expect'],
                                   observed=p['expect'], **{'pass': True})
                              for p in load_json(ROOT / 'scenarios/req-001.json')['probes']]
        self.args = SimpleNamespace(managed_store=self.tmp.name,
                                    ruleset=str(self.path), approved_high=True,
                                    approved_replacement=True,
                                    expected_sha256=digest(self.path.read_bytes()),
                                    expected_current=digest(self.lab['text'].encode()),
                                    scenario='scenarios/req-001.json', watch=0, interval=5)
        self.apply_calls = []
        self.real_probe = deploy.probe
        def apply(text):
            self.apply_calls.append(text)
            self.lab['text'] = '\n'.join(text.splitlines()[1:]) + '\n'
        patches = [
            mock.patch('deployer.managed.ManagedStore', return_value=self.store),
            mock.patch('validator.validate.nft_check', return_value=[]),
            mock.patch('deployer.deploy.snapshot', side_effect=lambda: 'flush ruleset\n' + self.lab['text']),
            mock.patch('deployer.deploy.nft_apply', side_effect=apply),
            mock.patch('deployer.deploy.probe', return_value={'results': self.probe_results}),
            mock.patch('validator.live_current.live_snapshot', side_effect=lambda: self.lab['text']),
            mock.patch('deployer.deploy.subprocess.run', return_value=SimpleNamespace(stdout='b' * 40)),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def test_apply_readback_then_commit(self):
        result = deploy.managed_apply(self.args, True)
        self.assertTrue(result['applied'])
        self.assertFalse(result['rolled_back'])
        self.assertEqual(self.store.events.count('publish'), 1)
        self.assertEqual(self.store.events[-2:], ['publish', 'finish'])
        self.assertEqual(json.loads(self.store.raw), self.candidate)
        self.assertEqual(len(self.apply_calls), 1)

    def test_candidate_swap_or_baseline_swap_cannot_reuse_approval(self):
        self.path.write_text(json.dumps(self.ir))
        with self.assertRaisesRegex(RuntimeError, 'candidate changed'):
            deploy.managed_apply(self.args, True)
        self.assertEqual(self.apply_calls, [])
        self.path.write_text(json.dumps(self.candidate))
        self.args.expected_current = '0' * 64
        with self.assertRaisesRegex(RuntimeError, 'current changed'):
            deploy.managed_apply(self.args, True)
        self.assertEqual(self.apply_calls, [])

    def test_policy_delta_needs_explicit_approval(self):
        self.args.approved_replacement = False
        with self.assertRaisesRegex(RuntimeError, 'requires explicit approval'):
            deploy.managed_apply(self.args, True)
        self.assertEqual(self.apply_calls, [])

    def test_probe_failure_restores_before_record(self):
        failed = [dict(r) for r in self.probe_results]
        failed[0]['observed'], failed[0]['pass'] = 'block', False
        with mock.patch('deployer.deploy.probe', return_value={'results': failed}):
            result = deploy.managed_apply(self.args, True)
        self.assertTrue(result['rolled_back'])
        self.assertEqual(json.loads(self.store.raw), self.ir)
        self.assertEqual(len(self.apply_calls), 2)
        self.assertEqual(self.store.events[-2:], ['publish', 'finish'])

    def test_empty_probe_aborts_and_restores(self):
        with mock.patch('deployer.deploy.probe', return_value={'results': []}):
            with self.assertRaisesRegex(RuntimeError, 'incomplete probe'):
                deploy.managed_apply(self.args, True)
        self.assertEqual(json.loads(self.store.raw), self.ir)
        self.assertEqual(len(self.apply_calls), 2)

    def test_incomplete_or_forged_probe_never_publishes_candidate(self):
        cases = [self.probe_results[:1],
                 self.probe_results[:-1] + [dict(self.probe_results[0])],
                 self.probe_results[:-1] + [dict(self.probe_results[-1], id='other')],
                 [dict(self.probe_results[0], kind='attack')] + self.probe_results[1:],
                 [dict(self.probe_results[0], expect='block')] + self.probe_results[1:],
                 [dict(self.probe_results[0], observed='block')] + self.probe_results[1:],
                 [dict(self.probe_results[0], **{'pass': False})] + self.probe_results[1:]]
        for result in cases:
            with self.subTest(result=result):
                self.lab['text'] = '\n'.join(to_nft(self.ir).splitlines()[1:]) + '\n'
                self.apply_calls.clear()
                self.store.events.clear()
                with mock.patch('deployer.deploy.probe', return_value={'results': result}):
                    with self.assertRaisesRegex(RuntimeError, 'incomplete probe'):
                        deploy.managed_apply(self.args, True)
                self.assertEqual(json.loads(self.store.raw), self.ir)
                self.assertEqual(len(self.apply_calls), 2)
                self.assertEqual(self.store.events[-2:], ['publish', 'finish'])

    def test_invalid_watch_interval_fails_before_apply(self):
        for watch, interval in ((-1, 5), (0, 0), (1, -1)):
            with self.subTest(watch=watch, interval=interval):
                self.lab['text'] = '\n'.join(to_nft(self.ir).splitlines()[1:]) + '\n'
                self.args.watch, self.args.interval = watch, interval
                with self.assertRaisesRegex(ValueError, 'watch|interval'):
                    deploy.managed_apply(self.args, True)
                self.assertEqual(self.apply_calls, [])

    def test_termination_signal_restores_and_retains_no_candidate_record(self):
        def stop(*_args, **_kwargs):
            signal.raise_signal(signal.SIGTERM)
        with mock.patch('deployer.deploy.probe', side_effect=stop):
            with self.assertRaisesRegex(RuntimeError, 'interrupted by signal'):
                deploy.managed_apply(self.args, True)
        self.assertEqual(json.loads(self.store.raw), self.ir)
        self.assertEqual(len(self.apply_calls), 2)
        self.assertFalse(self.store.intent_seen)

    def test_managed_probe_timeout_kills_child_and_restores(self):
        def delayed(*_args, **_kwargs):
            raise RuntimeError('probe deadline expired')
        with mock.patch('deployer.deploy.probe', side_effect=delayed):
            with self.assertRaisesRegex(RuntimeError, 'deadline expired'):
                deploy.managed_apply(self.args, True)
        self.assertEqual(json.loads(self.store.raw), self.ir)
        self.assertEqual(len(self.apply_calls), 2)

    def test_probe_child_timeout_reaps_direct_child(self):
        child = mock.Mock(pid=123, args=['probe'])
        child.communicate.side_effect = [subprocess.TimeoutExpired('probe', 1), ('', '')]
        kill_context = (mock.patch('deployer.deploy.os.killpg') if os.name == 'posix'
                        else mock.patch.object(child, 'kill'))
        with mock.patch('deployer.deploy.require_lab'), \
             mock.patch('deployer.deploy.subprocess.Popen', return_value=child), \
             kill_context as killed:
            with self.assertRaisesRegex(RuntimeError, 'deadline expired'):
                self.real_probe('scenarios/req-001.json', timeout=1)
            killed.assert_called_once()
        self.assertEqual(child.communicate.call_count, 2)

    def test_probe_child_signal_exception_reaps_before_reraising(self):
        child = mock.Mock(pid=123, args=['probe'])
        child.communicate.side_effect = [RuntimeError('interrupted'), ('', '')]
        kill_context = (mock.patch('deployer.deploy.os.killpg') if os.name == 'posix'
                        else mock.patch.object(child, 'kill'))
        with mock.patch('deployer.deploy.require_lab'), \
             mock.patch('deployer.deploy.subprocess.Popen', return_value=child), \
             kill_context as killed:
            with self.assertRaisesRegex(RuntimeError, 'interrupted'):
                self.real_probe('scenarios/req-001.json', timeout=1)
            killed.assert_called_once()
        self.assertEqual(child.communicate.call_count, 2)

    def test_external_change_before_apply_never_writes(self):
        initial = self.lab['text']
        def changed(before, candidate, stateful, rollback_nft):
            self.store.intent_seen = True
            self.lab['text'] += 'table ip unmanaged {}\n'
        with mock.patch.object(self.store, 'intent', side_effect=changed):
            with self.assertRaisesRegex(RuntimeError, 'immediately before apply'):
                deploy.managed_apply(self.args, True)
        self.assertEqual(self.apply_calls, [])
        self.assertEqual(initial + 'table ip unmanaged {}\n', self.lab['text'])

    def test_unknown_readback_preserves_external_rules_and_intent(self):
        baseline = self.lab['text']
        def corrupt(text):
            self.apply_calls.append(text)
            self.lab['text'] = ('table ip unmanaged {}\n' if len(self.apply_calls) == 1
                                else baseline)
        with mock.patch('deployer.deploy.nft_apply', side_effect=corrupt):
            with self.assertRaisesRegex(RuntimeError, 'unmanaged'):
                deploy.managed_apply(self.args, True)
        self.assertEqual(self.lab['text'], 'table ip unmanaged {}\n')
        self.assertTrue(self.store.intent_seen)
        self.assertEqual(len(self.apply_calls), 1)
        self.assertNotIn('finish', self.store.events)

    def test_external_writer_during_probe_is_not_clobbered(self):
        def changed(*_args, **_kwargs):
            self.lab['text'] = 'table ip unmanaged {}\n'
            return {'results': self.probe_results}
        with mock.patch('deployer.deploy.probe', side_effect=changed):
            with self.assertRaisesRegex(RuntimeError, 'unmanaged'):
                deploy.managed_apply(self.args, True)
        self.assertEqual(self.lab['text'], 'table ip unmanaged {}\n')
        self.assertTrue(self.store.intent_seen)
        self.assertEqual(len(self.apply_calls), 1)

    def test_failed_restore_preserves_intent(self):
        def broken(text):
            self.apply_calls.append(text)
            if len(self.apply_calls) == 1:
                self.lab['text'] = '\n'.join(text.splitlines()[1:]) + '\n'
                return
            raise RuntimeError('nft apply failed')
        with mock.patch('deployer.deploy.nft_apply', side_effect=broken):
            failed = [dict(r) for r in self.probe_results]
            failed[0]['observed'], failed[0]['pass'] = 'block', False
            with mock.patch('deployer.deploy.probe', return_value={'results': failed}):
                with self.assertRaisesRegex(RuntimeError, 'nft apply failed'):
                    deploy.managed_apply(self.args, True)
        self.assertTrue(self.store.intent_seen)
        self.assertNotIn('finish', self.store.events)


class StructureAndSecurityTest(unittest.TestCase):
    def setUp(self):
        self.ir = load_json(ROOT / 'scenarios/req-001.json')['gold']
        self.snapshot = '\n'.join(to_nft(self.ir).splitlines()[1:]) + '\n'

    def test_rollback_snapshot_uses_same_stateless_nft_rendering_as_provider(self):
        with mock.patch('deployer.deploy.exec_in', return_value=SimpleNamespace(
                returncode=0, stdout=self.snapshot, stderr='')) as run:
            self.assertEqual(deploy.snapshot(), 'flush ruleset\n' + self.snapshot)
        run.assert_called_once_with(deploy.FW, 'nft', '-n', '-y', '-s', 'list', 'ruleset')

    def test_exact_subset_and_unmanaged_fail_closed(self):
        structure(self.snapshot, self.ir, True)
        for changed in (self.snapshot + 'table ip other {}\n',
                        self.snapshot.replace('policy drop', 'policy accept'),
                        self.snapshot.replace('counter accept', 'counter drop'),
                        self.snapshot.replace('ct state established,related accept', '')):
            with self.subTest(changed=changed), self.assertRaisesRegex(RuntimeError, 'structure'):
                structure(changed, self.ir, True)

    def test_windows_store_rejected_before_bootstrap(self):
        if os.name == 'nt':
            with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
                with self.assertRaisesRegex(RuntimeError, 'Windows ACL unsupported'):
                    ManagedStore(tmp)

    def test_lock_collision_aborts_without_entering_critical_section(self):
        store = ManagedStore.__new__(ManagedStore)
        store.root = Path('synthetic-store')
        lock = SimpleNamespace(LOCK_EX=2, LOCK_NB=4, LOCK_UN=8)
        def busy(fd, operation):
            if operation == 6:
                raise BlockingIOError('busy')
        lock.flock = mock.Mock(side_effect=busy)
        with mock.patch.object(store, '_assert_secure'), \
             mock.patch('deployer.managed.fcntl', lock), \
             mock.patch('deployer.managed.os.open', return_value=123), \
             mock.patch('deployer.managed.os.close') as close:
            with self.assertRaisesRegex(RuntimeError, 'lock busy'):
                with store.locked():
                    self.fail('critical section entered after lock collision')
        lock.flock.assert_any_call(123, 6)
        close.assert_called_once_with(123)

    def test_real_cli_untrusted_store_never_emits_verdict(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            result = subprocess.run([sys.executable, 'deployer/deploy.py',
                                     'scenarios/req-001.json', '--scenario',
                                     'scenarios/req-001.json', '--managed-store', tmp],
                                    cwd=ROOT, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, '')

    def test_recovery_intent_replays_saved_policy_before_record(self):
        raw = json.dumps(self.ir).encode()
        rollback = 'flush ruleset\n' + self.snapshot
        intent = {'before': digest(raw), 'candidate': 'b' * 64,
                  'snapshot': digest(self.snapshot.encode()),
                  'before_ir': base64.b64encode(raw).decode(),
                  'before_stateful': True, 'before_commit': 'a' * 40,
                  'candidate_ir': base64.b64encode(raw).decode(),
                  'candidate_stateful': True,
                  'rollback_nft': rollback, 'rollback_sha256': digest(rollback.encode())}
        intent['candidate'] = digest(raw)
        store = ManagedStore.__new__(ManagedStore)
        actions = []
        with mock.patch.object(store, '_read', return_value=intent), \
             mock.patch.object(store, 'publish', side_effect=lambda *args: actions.append('publish')), \
             mock.patch.object(store, 'finish', side_effect=lambda: actions.append('finish')), \
             mock.patch('deployer.managed.live_snapshot', return_value=self.snapshot):
            store.recover(lambda text: actions.append(('apply', text)))
        self.assertEqual(actions, [('apply', rollback), 'publish', 'finish'])

    def test_empty_live_ruleset_recovery_replays_and_records(self):
        raw = json.dumps(self.ir).encode()
        rollback = 'flush ruleset\n' + self.snapshot
        intent = {'before': digest(raw), 'candidate': digest(raw),
                  'snapshot': digest(self.snapshot.encode()),
                  'before_ir': base64.b64encode(raw).decode(), 'before_stateful': True,
                  'before_commit': 'a' * 40,
                  'candidate_ir': base64.b64encode(raw).decode(), 'candidate_stateful': True,
                  'rollback_nft': rollback, 'rollback_sha256': digest(rollback.encode())}
        store = ManagedStore.__new__(ManagedStore)
        live = {'text': ''}
        actions = []
        def apply(text):
            actions.append('apply')
            live['text'] = self.snapshot
        with mock.patch.object(store, '_read', return_value=intent), \
             mock.patch.object(store, 'publish', side_effect=lambda *args: actions.append('publish')), \
             mock.patch.object(store, 'finish', side_effect=lambda: actions.append('finish')), \
             mock.patch('deployer.managed.live_snapshot', side_effect=lambda: live['text']):
            store.recover(apply)
        self.assertEqual(actions, ['apply', 'publish', 'finish'])

    def test_recovery_unknown_nonempty_policy_preserves_intent(self):
        raw = json.dumps(self.ir).encode()
        rollback = 'flush ruleset\n' + self.snapshot
        intent = {'before': digest(raw), 'candidate': digest(raw),
                  'snapshot': digest(self.snapshot.encode()),
                  'before_ir': base64.b64encode(raw).decode(), 'before_stateful': True,
                  'before_commit': 'a' * 40,
                  'candidate_ir': base64.b64encode(raw).decode(), 'candidate_stateful': True,
                  'rollback_nft': rollback, 'rollback_sha256': digest(rollback.encode())}
        store = ManagedStore.__new__(ManagedStore)
        with mock.patch.object(store, '_read', return_value=intent), \
             mock.patch('deployer.managed.live_snapshot', return_value='table ip foreign {}\n'):
            with self.assertRaisesRegex(RuntimeError, 'structure'):
                store.recover(lambda _: self.fail('foreign policy overwritten'))

    def test_corrupt_recovery_intent_never_applies(self):
        store = ManagedStore.__new__(ManagedStore)
        with mock.patch.object(store, '_read', return_value={'before': 'x'}):
            with self.assertRaisesRegex(RuntimeError, 'invalid recovery intent'):
                store.recover(lambda text: self.fail('corrupt intent applied'))

    def test_recovery_refuses_self_consistent_but_unrelated_rollback(self):
        raw = json.dumps(self.ir).encode()
        foreign = 'flush ruleset\ntable ip unrelated {}\n'
        intent = {'before': digest(raw), 'candidate': digest(raw),
                  'snapshot': digest(self.snapshot.encode()),
                  'before_ir': base64.b64encode(raw).decode(), 'before_stateful': True,
                  'before_commit': 'a' * 40,
                  'candidate_ir': base64.b64encode(raw).decode(), 'candidate_stateful': True,
                  'rollback_nft': foreign, 'rollback_sha256': digest(foreign.encode())}
        store = ManagedStore.__new__(ManagedStore)
        with mock.patch.object(store, '_read', return_value=intent), \
             mock.patch('deployer.managed.live_snapshot', return_value=self.snapshot):
            with self.assertRaisesRegex(RuntimeError, 'structure'):
                store.recover(lambda text: self.fail('foreign policy applied'))

    def test_record_or_nft_change_during_current_collection_aborts(self):
        raw = json.dumps(self.ir).encode()
        record = {'version': 1, 'ir': base64.b64encode(raw).decode(),
                  'sha256': digest(raw), 'stateful': True, 'commit': 'a' * 40,
                  'nft_sha256': digest(self.snapshot.encode())}
        store = ManagedStore.__new__(ManagedStore)
        store.root = Path('unused')
        with mock.patch.object(store, '_read', return_value=record), \
             mock.patch('deployer.managed.live_snapshot', return_value=self.snapshot):
            current = store.current()
            self.assertEqual(current.ir_bytes, raw)
            self.assertEqual(current.commit, 'a' * 40)
        with mock.patch.object(store, '_read', side_effect=[record, dict(record, commit='b' * 40)]), \
             mock.patch('deployer.managed.live_snapshot', return_value=self.snapshot):
            with self.assertRaisesRegex(RuntimeError, 'changed during collection'):
                store.current()
        with mock.patch.object(store, '_read', return_value=record), \
             mock.patch('deployer.managed.live_snapshot', side_effect=[self.snapshot, self.snapshot + 'table ip unexpected {}\n']):
            with self.assertRaisesRegex(RuntimeError, 'changed during collection'):
                store.current()


if __name__ == '__main__':
    unittest.main()
