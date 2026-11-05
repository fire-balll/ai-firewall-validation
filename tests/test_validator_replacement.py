"""Validator-side provider contract tests, NOT a live nft/deployer test."""
import hashlib
import io
import json
import unittest
from copy import deepcopy
from dataclasses import replace
from unittest import mock

from common.ir import ROOT, load_json
from validator.validate import ToolError, validate, validate_with_current
from validator.replacement import CurrentRules


class FakeProvider:
    """Synthetic provider; deployment integration must implement real reads."""
    def __init__(self, rules):
        raw = json.dumps(rules).encode('utf-8')
        self.current = CurrentRules(raw, hashlib.sha256(raw).hexdigest(), True,
                                    'a' * 40, 'snapshot-generation-1')
        self.events = []

    def read_verified_current(self):
        self.events.append('read')
        return self.current

    def assert_still_current(self, current):
        self.events.append('recheck')
        if current != self.current:
            raise RuntimeError('stale_baseline')


class ReplacementContractTest(unittest.TestCase):
    def setUp(self):
        self.rules = load_json(ROOT / 'scenarios' / 'req-001.json')['gold']
        self.provider = FakeProvider(self.rules)

    def run_check(self, rules=None, stateful=True):
        return validate_with_current(self.rules if rules is None else rules,
                                     candidate_stateful=stateful, provider=self.provider)

    def test_legacy_output_unchanged(self):
        self.assertNotIn('comparison', validate(self.rules))

    def test_comparison_is_separate_from_risk(self):
        result = self.run_check({'rules': []})
        self.assertEqual({k:v for k,v in result.items() if k != 'comparison'},
                         validate({'rules': []}))
        self.assertGreater(result['comparison']['counts']['allow_to_block'], 0)
        self.assertEqual(result['comparison']['status'], 'offline_only')
        self.assertEqual(self.provider.events, ['read', 'recheck'])
        self.assertNotIn('approved', result['comparison'])

    def test_equal_initial_packet_policy_not_deployment_approval(self):
        result = self.run_check()
        self.assertEqual(result['comparison']['counts']['allow_to_block'], 0)
        self.assertEqual(result['comparison']['baseline_commit'], 'a' * 40)
        self.assertEqual(result['comparison']['baseline_sha256'], self.provider.current.sha256)

    def test_missing_provider_fails(self):
        with self.assertRaisesRegex(ToolError, 'provider'):
            validate_with_current(self.rules, candidate_stateful=True, provider=None)

    def test_read_failure_does_not_return_a_verdict(self):
        for ex in (FileNotFoundError('current'), PermissionError('snapshot'),
                   TimeoutError('nft'), RuntimeError('unmanaged rules')):
            with self.subTest(ex=ex), mock.patch.object(self.provider, 'read_verified_current', side_effect=ex):
                with self.assertRaises(ToolError):
                    self.run_check()

    def test_stale_or_unmanaged_recheck_fails(self):
        for message in ('stale_baseline', 'unmanaged rules'):
            with self.subTest(message=message), mock.patch.object(
                    self.provider, 'assert_still_current', side_effect=RuntimeError(message)):
                with self.assertRaisesRegex(ToolError, message):
                    self.run_check()

    def test_boolean_recheck_not_silently_accepted(self):
        for value in (False, True, 'verified', {}):
            with self.subTest(value=value), mock.patch.object(
                    self.provider, 'assert_still_current', return_value=value):
                with self.assertRaises(ToolError):
                    self.run_check()

    def test_digest_tampering_fails(self):
        self.provider.current = replace(self.provider.current, sha256='0' * 64)
        with self.assertRaisesRegex(ToolError, 'SHA-256'):
            self.run_check()

    def test_malformed_current_and_metadata_fail(self):
        original = self.provider.current
        for change in ({'ir_bytes': b'not json'}, {'ir_bytes': b'\xff'},
                       {'ir_bytes': b'{}'}, {'stateful': 'true'},
                       {'commit': 'main'}, {'snapshot_token': ''},
                       {'sha256': 'z' * 64}, {'ir_bytes': '{}'}):
            with self.subTest(change=change):
                self.provider.current = replace(original, **change)
                with self.assertRaises(ToolError):
                    self.run_check()

    def test_no_json_dict_as_trusted_provider_record(self):
        self.provider.current = {'verified': True, 'rules': self.rules}
        with self.assertRaises(ToolError):
            self.run_check()

    def test_mode_mismatch_is_execution_failure(self):
        with self.assertRaisesRegex(ToolError, 'stateful'):
            self.run_check(stateful=False)

    def test_candidate_mode_must_be_explicit_boolean(self):
        for flag in (None, 0, 1, 'true'):
            with self.subTest(flag=flag), self.assertRaises(ToolError):
                self.run_check(stateful=flag)

    def test_invalid_candidate_uses_existing_rejection_without_provider(self):
        result = self.run_check({'rules': 'bad'})
        self.assertFalse(result['ok'])
        self.assertNotIn('comparison', result)
        self.assertEqual(self.provider.events, [])

    def test_unsupported_or_cap_failure_not_partial_success(self):
        bad = deepcopy(self.rules)
        bad['rules'][0]['src'] = '::/0'
        self.provider = FakeProvider(bad)
        with self.assertRaises(ToolError):
            self.run_check()
        self.provider = FakeProvider(self.rules)
        with self.assertRaises(ToolError):
            validate_with_current(self.rules, candidate_stateful=True,
                                  provider=self.provider, max_regions=1)

    def test_inputs_unchanged_and_no_external_command(self):
        before = deepcopy(self.rules)
        raw = self.provider.current.ir_bytes
        with mock.patch('subprocess.run', side_effect=AssertionError('external call')):
            self.run_check()
        self.assertEqual(self.rules, before)
        self.assertEqual(self.provider.current.ir_bytes, raw)

    def test_nft_tool_failure_prevents_current_comparison(self):
        with mock.patch('validator.validate.nft_check', side_effect=ToolError('fw down')):
            with self.assertRaises(ToolError):
                validate_with_current(self.rules, candidate_stateful=True,
                                      provider=self.provider, nft=True)
        self.assertEqual(self.provider.events, [])

    def test_failure_emits_no_stdout_json(self):
        buf = io.StringIO()
        with mock.patch('sys.stdout', buf), mock.patch.object(
                self.provider, 'read_verified_current', side_effect=FileNotFoundError('current')):
            with self.assertRaises(ToolError):
                self.run_check()
        self.assertEqual(buf.getvalue(), '')

    def test_provider_side_mutation_of_candidate_is_not_hidden(self):
        # The function compares a defensive copy captured before provider calls.
        original = deepcopy(self.rules)
        def mutate_then_read():
            self.rules['rules'].clear()
            return self.provider.current
        with mock.patch.object(self.provider, 'read_verified_current', side_effect=mutate_then_read):
            result = self.run_check()
        self.assertEqual(result['comparison']['counts']['allow_to_block'], 0)
        self.assertTrue(original['rules'])


if __name__ == '__main__':
    unittest.main()
