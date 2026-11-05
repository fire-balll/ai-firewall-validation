"""Static experiment harness tests; fixtures never stand in for real runs."""
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from common.ir import ROOT
from validator.offline_experiment import main, measure


class OfflineExperimentTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for directory in ('scenarios', 'mutations', 'generated'):
            (self.root / directory).mkdir()
        raw = (ROOT / 'scenarios/req-001.json').read_bytes()
        (self.root / 'scenarios/req-001.json').write_bytes(raw)
        rules = json.loads(raw)['gold']
        (self.root / 'mutations/req-001-port-01.json').write_text(json.dumps(rules), encoding='utf-8')
        self.generated = self.root / 'generated/req-001-test-s1.json'
        self.generated.write_text(json.dumps(rules), encoding='utf-8')
        self.meta = self.generated.with_suffix('.meta.json')
        self.meta.write_text(json.dumps({'model':'fixture', 'digest':'fixture-digest',
             'ollama_version':'fixture', 'temperature':0.5, 'seed':1,
             'prompt_version':'fixture-v1', 'round':1}), encoding='utf-8')

    def test_counts_sha_and_gold_reference_scope(self):
        out = measure(self.root)
        self.assertEqual(out['scenario_count'], 1)
        self.assertEqual(out['summary']['generated']['files'], 1)
        self.assertEqual(out['review_file_count']['B'], 1)
        self.assertEqual(out['review_file_count']['C'], 0)
        self.assertEqual(out['records'][0]['gold_comparison']['status'], 'offline_only')
        self.assertEqual(len(out['records'][1]['meta_sha256']), 64)

    def test_feedback_sidecar_not_treated_as_candidate(self):
        self.generated.with_suffix('.feedback.json').write_text('{"stage":"deploy"}', encoding='utf-8')
        out = measure(self.root)
        self.assertEqual(out['summary']['generated']['files'], 1)

    def test_missing_metadata_is_failure(self):
        self.meta.unlink()
        with self.assertRaises(ValueError):
            measure(self.root)

    def test_missing_candidate_set_is_failure(self):
        self.generated.unlink()
        with self.assertRaisesRegex(ValueError, 'empty'):
            measure(self.root)

    def test_wrong_metadata_type_is_failure(self):
        meta = json.loads(self.meta.read_text(encoding='utf-8'))
        meta['seed'] = True
        self.meta.write_text(json.dumps(meta), encoding='utf-8')
        with self.assertRaises(ValueError):
            measure(self.root)

    def test_later_round_not_in_first_round_denominator(self):
        meta = json.loads(self.meta.read_text(encoding='utf-8'))
        meta['round'] = 2
        self.meta.write_text(json.dumps(meta), encoding='utf-8')
        out = measure(self.root)
        self.assertEqual(out['review_file_count']['B'], 0)
        self.assertIsNone(out['review_file_count']['reduction_fraction'])

    def test_state_mode_difference_not_policy_equality(self):
        original = self.root / 'mutations/req-001-port-01.json'
        original.rename(self.root / 'mutations/req-001-state-01.json')
        out = measure(self.root)
        self.assertEqual(out['records'][0]['gold_comparison']['status'], 'indeterminate')
        self.assertEqual(out['summary']['mutation']['initial_packet_policy_changed'], 0)

    def test_partial_observations_do_not_emit_json(self):
        buf = io.StringIO()
        with mock.patch('sys.argv', ['offline_experiment.py']), mock.patch('sys.stdout', buf), \
                mock.patch('sys.stderr', io.StringIO()), \
                mock.patch('validator.offline_experiment.measure', side_effect=OSError('gone')):
            self.assertEqual(main(), 2)
        self.assertEqual(buf.getvalue(), '')


if __name__ == '__main__':
    unittest.main()
