"""Real run.sh/validator/deployer CLIs with synthetic lab boundaries, not a VM test."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from common.ir import ROOT


# python3 shim keeps the real JSON/CLI/nft conversion paths, replacing only lab
# I/O and CSV persistence. It is installed only in each isolated test directory.
DISPATCH = r'''
import hashlib, json, os, runpy, subprocess, sys
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, os.getcwd())
args = sys.argv[1:]
trace = Path('trace.jsonl')
def log(kind, **values):
    with trace.open('a', encoding='utf-8') as f:
        f.write(json.dumps(dict(kind=kind, **values)) + '\n')
if args[0] == '-c':
    sys.argv = ['-c', *args[2:]]
    exec(args[1])
elif args[0] == 'validator/validate.py':
    from validator import validate as v
    from validator.replacement import CurrentRules
    from deployer import managed
    def nft_run(cmd, **kwargs):
        log('nft', text=kwargs['input'].decode('utf-8'))
        return subprocess.CompletedProcess(cmd, 0, b'__validator_nft_rc=0\n', b'')
    sys.argv = args
    class Current:
        def __init__(self, root):
            log('provider_init', root=root)
        def read_verified_current(self):
            log('provider_read')
            if os.environ.get('TEST_CURRENT_ERROR') == '1':
                raise RuntimeError('synthetic nft snapshot unavailable')
            from common.ir import load_json
            raw = json.dumps(load_json('scenarios/req-001.json')['gold']).encode()
            return CurrentRules(raw, hashlib.sha256(raw).hexdigest(), True,
                                'a'*40, 'b'*64)
        def assert_still_current(self, current):
            log('provider_recheck')
            if os.environ.get('TEST_CURRENT_STALE') == '1':
                raise RuntimeError('synthetic nft changed during comparison')
    actual = os.environ.get('TEST_ACTUAL_PROVIDER') == '1'
    provider_patch = nullcontext() if actual else patch.object(managed, 'ManagedCurrentProvider', Current)
    security_patch = patch.object(managed.ManagedStore, '_assert_secure') if actual else nullcontext()
    # Windows cannot exercise POSIX fstat/owner ACL. Read the fixture record,
    # but keep the real ManagedCurrentProvider.current/recheck/structure logic.
    record_patch = patch.object(managed.ManagedStore, '_read',
                                lambda self, name: json.loads((self.root / name).read_text())) if actual else nullcontext()
    nft_patch = patch.object(managed, 'live_snapshot', return_value=os.environ['TEST_NFT_TEXT']) if actual else nullcontext()
    with provider_patch, security_patch, record_patch, nft_patch:
        if os.environ.get('TEST_NFT_ABSENT') == '1':
            with patch.object(v, 'PODMAN', ['course010-guaranteed-absent-command']):
                v.main()
        else:
            with patch.object(v.subprocess, 'run', side_effect=nft_run):
                v.main()
elif args[0] == 'deployer/deploy.py':
    from deployer import deploy as d
    sys.argv = args
    log('deploy_args', args=args)
    if '--managed-store' in args:
        def managed_apply(options, mode):
            log('managed_apply', mode=mode, expected_sha=options.expected_sha256,
                expected_current=options.expected_current,
                approved_replacement=options.approved_replacement)
            if os.environ.get('TEST_APPLY_STALE') == '1':
                raise RuntimeError('synthetic current changed inside apply lock')
            return {'applied': True, 'rolled_back': False, 'aborted': False}
        with patch.object(d, 'managed_apply', side_effect=managed_apply):
            d.main()
        sys.exit(0)
    with patch.object(d, 'require_lab'), patch.object(d, 'snapshot', return_value='saved'), \
         patch.object(d, 'probe', return_value={'results': [{'pass': True}]}), \
         patch.object(d, 'nft_apply', side_effect=lambda text: log('apply', text=text)):
        d.main()
elif args[0] == 'eval/evaluate.py':
    log('record', args=args)
else:
    sys.argv = args
    runpy.run_path(args[0], run_name='__main__')
'''


@unittest.skipUnless(shutil.which('bash'), 'bash required for actual pipeline CLI')
class PipelineValidatorModeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='pipeline-mode-', dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for directory in ('common', 'validator', 'deployer', 'generator', 'schema', 'scenarios', 'mutations'):
            shutil.copytree(ROOT / directory, self.root / directory,
                            ignore=shutil.ignore_patterns('__pycache__'))
        (self.root / 'pipeline').mkdir()
        # Git may check out CRLF on Windows; the bash fixture uses repository LF.
        (self.root / 'pipeline/run.sh').write_text(
            (ROOT / 'pipeline/run.sh').read_text(encoding='utf-8'), encoding='utf-8', newline='\n')
        (self.root / 'dispatch.py').write_text(DISPATCH, encoding='utf-8')
        bin_dir = self.root / 'bin'
        bin_dir.mkdir()
        shim = bin_dir / 'python3'
        shim.write_text('#!/usr/bin/env bash\nexec "' + Path(sys.executable).as_posix()
                        + '" dispatch.py "$@"\n', encoding='utf-8', newline='\n')
        shim.chmod(0o755)
        self.env = os.environ.copy()
        self.env.update(PATH=str(bin_dir) + os.pathsep + self.env['PATH'], WATCH='0',
                        APPROVE='yes', GENERATOR='mock', OUT_DIR='out/test')
        self.env.pop('CANDIDATE', None)
        self.env.pop('TEST_NFT_ABSENT', None)
        self.env.pop('CURRENT_COMPARE', None)
        self.env.pop('FW_MANAGED_STORE', None)

    def run_pipeline(self, candidate=None, absent=False):
        if candidate:
            self.env['CANDIDATE'] = candidate
        if absent:
            self.env['TEST_NFT_ABSENT'] = '1'
        result = subprocess.run(['bash', 'pipeline/run.sh', 'scenarios/req-001.json'],
                                cwd=self.root, env=self.env, capture_output=True, text=True,
                                encoding='utf-8', errors='replace', timeout=45)
        trace = self.root / 'trace.jsonl'
        events = [json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []
        return result, events

    def assert_mode(self, candidate, stateful):
        result, events = self.run_pipeline(candidate)
        self.assertEqual(result.returncode, 0, result.stderr)
        check = next(e['text'] for e in events if e['kind'] == 'nft')
        applied = next(e['text'] for e in events if e['kind'] == 'apply')
        self.assertEqual(check, applied)
        self.assertEqual('ct state established,related accept' in check, stateful)
        deploy = json.loads((self.root / 'out/test/deploy.json').read_text())
        self.assertIs(deploy['stateful'], stateful)
        self.assertTrue(deploy['applied'])
        self.assertEqual(sum(e['kind'] == 'record' for e in events), 1)

    def test_generated_mock_is_stateful(self):
        self.assert_mode(None, True)

    def test_original_stateful_candidate(self):
        self.assert_mode('mutations/req-001-port-01.json', True)

    def test_original_state_mutation_is_stateless(self):
        self.assert_mode('mutations/req-001-state-01.json', False)

    def test_missing_nft_aborts_without_verdict_or_record(self):
        result, events = self.run_pipeline(absent=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('nft -c', result.stderr)
        self.assertEqual((self.root / 'out/test/validation.json').read_bytes(), b'')
        self.assertFalse(any(e['kind'] in ('record', 'apply', 'deploy_args') for e in events))
        self.assertFalse((self.root / 'out/test/deploy.json').exists())

    def test_missing_nft_stateless_also_aborts(self):
        result, events = self.run_pipeline('mutations/req-001-state-01.json', absent=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('nft -c', result.stderr)
        self.assertEqual((self.root / 'out/test/validation.json').read_bytes(), b'')
        self.assertFalse(any(e['kind'] in ('record', 'apply', 'deploy_args') for e in events))
        self.assertFalse((self.root / 'out/test/deploy.json').exists())

    def test_current_opt_in_without_trusted_record_aborts_before_apply_and_csv(self):
        self.env['CURRENT_COMPARE'] = 'yes'
        self.env.pop('FW_MANAGED_STORE', None)
        result, events = self.run_pipeline()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('FW_MANAGED_STORE', result.stderr)
        self.assertFalse((self.root / 'out/test/validation.json').exists())
        self.assertFalse(any(e['kind'] in ('apply', 'record', 'deploy_args') for e in events))
        self.assertFalse((self.root / 'out/test/deploy.json').exists())

    def test_legacy_path_rejected_when_managed_store_configured(self):
        self.env['FW_MANAGED_STORE'] = str(self.root / 'managed')
        result, events = self.run_pipeline()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('레거시 적용 금지', result.stderr)
        self.assertFalse(any(e['kind'] in ('apply', 'record', 'deploy_args') for e in events))

    def test_current_provider_error_does_not_emit_verdict(self):
        self.env['CURRENT_COMPARE'] = 'yes'
        self.env['FW_MANAGED_STORE'] = str(self.root / 'managed')
        self.env['TEST_CURRENT_ERROR'] = '1'
        result, events = self.run_pipeline()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual((self.root / 'out/test/validation.json').read_bytes(), b'')
        self.assertFalse(any(e['kind'] in ('apply', 'record', 'deploy_args') for e in events))

    def test_current_compare_hands_cli_evidence_to_managed_deployer(self):
        self.env['CURRENT_COMPARE'] = 'yes'
        self.env['FW_MANAGED_STORE'] = str(self.root / 'managed')
        result, events = self.run_pipeline()
        self.assertEqual(result.returncode, 0, result.stderr)
        validation = json.loads((self.root / 'out/test/validation.json').read_text())
        self.assertEqual(validation['comparison']['status'], 'offline_only')
        self.assertEqual(validation['comparison']['baseline_snapshot_token'], 'b'*64)
        self.assertEqual(sum(e['kind'] == 'provider_read' for e in events), 1)
        self.assertEqual(sum(e['kind'] == 'provider_recheck' for e in events), 1)
        handoff = next(e for e in events if e['kind'] == 'managed_apply')
        self.assertEqual(handoff['expected_sha'], validation['candidate_sha256'])
        self.assertEqual(handoff['expected_current'], 'b'*64)
        self.assertEqual(sum(e['kind'] == 'record' for e in events), 1)

    def test_pipeline_uses_actual_managed_provider_record_and_nft_comparison(self):
        from common.ir import load_json, to_nft
        import base64
        import hashlib
        self.env['CURRENT_COMPARE'] = 'yes'
        store = self.root / 'managed'
        store.mkdir()
        self.env['FW_MANAGED_STORE'] = str(store)
        self.env['TEST_ACTUAL_PROVIDER'] = '1'
        ir = load_json(ROOT / 'scenarios/req-001.json')['gold']
        raw = json.dumps(ir).encode()
        nft = '\n'.join(to_nft(ir).splitlines()[1:]) + '\n'
        self.env['TEST_NFT_TEXT'] = nft
        record = {'version': 1, 'ir': base64.b64encode(raw).decode(),
                  'sha256': hashlib.sha256(raw).hexdigest(), 'stateful': True,
                  'commit': 'a' * 40, 'nft_sha256': hashlib.sha256(nft.encode()).hexdigest()}
        (store / 'current.json').write_text(json.dumps(record), encoding='utf-8')
        result, events = self.run_pipeline()
        self.assertEqual(result.returncode, 0, result.stderr)
        validation = json.loads((self.root / 'out/test/validation.json').read_text())
        self.assertEqual(validation['comparison']['baseline_sha256'], record['sha256'])
        self.assertEqual(validation['comparison']['baseline_snapshot_token'], record['nft_sha256'])
        handoff = next(e for e in events if e['kind'] == 'managed_apply')
        self.assertEqual(handoff['expected_sha'], validation['candidate_sha256'])
        self.assertEqual(handoff['expected_current'], record['nft_sha256'])
        self.assertEqual(sum(e['kind'] == 'record' for e in events), 1)

    def test_actual_provider_rejects_sha_state_commit_nft_and_partial_record(self):
        from common.ir import load_json, to_nft
        import base64
        import hashlib
        self.env['CURRENT_COMPARE'] = 'yes'
        store = self.root / 'managed'
        store.mkdir()
        self.env['FW_MANAGED_STORE'] = str(store)
        self.env['TEST_ACTUAL_PROVIDER'] = '1'
        ir = load_json(ROOT / 'scenarios/req-001.json')['gold']
        raw = json.dumps(ir).encode()
        nft = '\n'.join(to_nft(ir).splitlines()[1:]) + '\n'
        self.env['TEST_NFT_TEXT'] = nft
        record = {'version': 1, 'ir': base64.b64encode(raw).decode(),
                  'sha256': hashlib.sha256(raw).hexdigest(), 'stateful': True,
                  'commit': 'a'*40, 'nft_sha256': hashlib.sha256(nft.encode()).hexdigest()}
        cases = {
            'sha': (dict(record, sha256='0'*64), nft),
            'state': (dict(record, stateful=False), nft),
            'commit': (dict(record, commit='bad'), nft),
            'nft': (record, nft + 'table ip unmanaged {}\n'),
            'partial': ({'version': 1}, nft),
        }
        for label, (broken, observation) in cases.items():
            with self.subTest(case=label):
                self.env['TEST_NFT_TEXT'] = observation
                (store / 'current.json').write_text(json.dumps(broken), encoding='utf-8')
                (self.root / 'trace.jsonl').unlink(missing_ok=True)
                result, events = self.run_pipeline()
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual((self.root / 'out/test/validation.json').read_bytes(), b'')
                self.assertFalse(any(e['kind'] in ('managed_apply', 'record') for e in events))

    def test_current_provider_failure_or_comparison_race_aborts(self):
        for failure in ('TEST_CURRENT_ERROR', 'TEST_CURRENT_STALE'):
            with self.subTest(failure=failure):
                self.env['CURRENT_COMPARE'] = 'yes'
                self.env['FW_MANAGED_STORE'] = str(self.root / 'managed')
                self.env[failure] = '1'
                result, events = self.run_pipeline()
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual((self.root / 'out/test/validation.json').read_bytes(), b'')
                self.assertFalse(any(e['kind'] in ('managed_apply', 'record') for e in events))
                self.env.pop(failure)
                (self.root / 'trace.jsonl').unlink(missing_ok=True)

    def test_apply_lock_race_aborts_without_csv(self):
        self.env['CURRENT_COMPARE'] = 'yes'
        self.env['FW_MANAGED_STORE'] = str(self.root / 'managed')
        self.env['TEST_APPLY_STALE'] = '1'
        result, events = self.run_pipeline()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual((self.root / 'out/test/deploy.json').read_bytes(), b'')
        self.assertEqual(sum(e['kind'] == 'managed_apply' for e in events), 1)
        self.assertFalse(any(e['kind'] == 'record' for e in events))


if __name__ == '__main__':
    unittest.main()
