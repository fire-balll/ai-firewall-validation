"""Review workload is a static accounting proxy, never observed human time."""
import io
import json
import tempfile
from pathlib import Path
from unittest import mock
import unittest
from validator import offline_experiment as module
from validator.validate import input_errors

class ReviewWorkloadTest(unittest.TestCase):
    def test_rounds_and_invalid_candidates_are_separate(self):
        def record(round_, ok, risk, rules):
            return {'kind': 'generated', 'meta': {'round': round_},
                    'validation': {'ok': ok, 'risk': risk}, 'rule_count': rules}
        records = [record(1, True, 'low', 4), record(1, True, 'high', 2),
                   record(2, True, 'high', 7), record(2, False, None, 3),
                   {'kind': 'mutation'}]
        self.assertEqual(module.review_workload(records), {
            '1': {'candidate_files': 2, 'rejected_files': 0, 'B_files': 2, 'C_files': 1,
                  'B_rules': 6, 'C_rules': 2, 'rule_reduction_fraction': 4/6},
            '2': {'candidate_files': 2, 'rejected_files': 1, 'B_files': 2, 'C_files': 1,
                  'B_rules': 10, 'C_rules': 7, 'rule_reduction_fraction': 3/10}})

    def test_measure_includes_reproducible_rule_counts(self):
        result = module.measure()
        first = result['review_rule_count']['1']
        self.assertEqual((first['B_files'], first['C_files'], first['B_rules'], first['C_rules']),
                         (63, 9, 216, 40))
        self.assertAlmostEqual(first['rule_reduction_fraction'], 176/216)

    def test_real_round2_counts_include_both_rejected_inputs(self):
        result = module.measure()
        second = result['review_rule_count']['2']
        self.assertEqual((second['B_files'], second['C_files'], second['B_rules'],
                          second['C_rules'], second['rejected_files']), (12, 3, 67, 16, 2))
        self.assertAlmostEqual(second['rule_reduction_fraction'], 51/67)
        rejected = [r for r in result['records'] if r['kind'] == 'generated'
                    and not r['validation']['ok']]
        self.assertEqual(sorted(r['rule_count'] for r in rejected), [6, 7])
        self.assertTrue(all(r['gold_comparison'] is None for r in rejected))

    def test_invalid_rule_counts_fail_even_when_rejected(self):
        for ok in (True, False):
            for count in (None, True, -1, 1.5, '3'):
                with self.subTest(ok=ok, count=count), self.assertRaisesRegex(ValueError, 'rule_count'):
                    module.review_workload([{'kind':'generated', 'meta':{'round':1},
                        'validation':{'ok':ok, 'risk':None}, 'rule_count':count}])

    def test_rejected_high_does_not_enter_c(self):
        group = module.review_workload([{'kind':'generated', 'meta':{'round':1},
            'validation':{'ok':False, 'risk':'high'}, 'rule_count':5}])['1']
        self.assertEqual((group['B_rules'], group['C_rules'], group['C_files']), (5, 0, 0))

    def test_empty_and_mutation_only_have_no_generated_round(self):
        self.assertEqual(module.review_workload([]), {})
        self.assertEqual(module.review_workload([{'kind':'mutation'}]), {})

    def test_zero_rule_denominator_is_null(self):
        group = module.review_workload([{'kind':'generated', 'meta':{'round':3},
            'validation':{'ok':True, 'risk':'low'}, 'rule_count':0}])['3']
        self.assertEqual(group['B_files'], 1)
        self.assertIsNone(group['rule_reduction_fraction'])

    def fixture_root(self, value):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        for directory in ('scenarios', 'mutations', 'generated'):
            (root / directory).mkdir()
        raw = (module.ROOT / 'scenarios/req-001.json').read_bytes()
        (root / 'scenarios/req-001.json').write_bytes(raw)
        (root / 'mutations/req-001-port-01.json').write_text(
            json.dumps(json.loads(raw)['gold']), encoding='utf-8')
        candidate = root / 'generated/req-001-fixture-s1.json'
        candidate.write_text(json.dumps(value), encoding='utf-8')
        candidate.with_suffix('.meta.json').write_text(json.dumps({
            'model':'fixture', 'digest':'fixture-digest', 'ollama_version':'fixture',
            'temperature':0.5, 'seed':1, 'prompt_version':'fixture', 'round':1}), encoding='utf-8')
        return root

    def test_port_rejection_still_contributes_rules(self):
        value = json.loads((module.ROOT / 'scenarios/req-001.json').read_bytes())['gold']
        value['rules'][0]['dport'] = '99999'
        self.assertEqual(input_errors(value), [])
        validation = module.validate(value)
        self.assertFalse(validation['ok'])
        self.assertTrue(any('99999' in error for error in validation['errors']))
        result = module.measure(self.fixture_root(value))
        group = result['review_rule_count']['1']
        self.assertEqual(group['rejected_files'], 1)
        self.assertEqual(group['B_rules'], len(value['rules']))
        self.assertEqual(group['C_rules'], 0)

    def test_unaccountable_rules_abort_without_json(self):
        root = self.fixture_root({'rules': 'not-an-array'})
        with self.assertRaisesRegex(ValueError, 'rule_count'):
            module.measure(root)
        real_measure = module.measure
        buf = io.StringIO()
        with mock.patch.object(module, 'measure', side_effect=lambda: real_measure(root)), \
                mock.patch('sys.argv', ['offline_experiment.py']), \
                mock.patch('sys.stdout', buf), mock.patch('sys.stderr', io.StringIO()):
            self.assertEqual(module.main(), 2)
        self.assertEqual(buf.getvalue(), '')

if __name__ == '__main__':
    unittest.main()
