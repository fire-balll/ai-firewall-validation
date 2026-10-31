"""Offline replacement comparator regression tests; no live firewall access."""
import unittest
from copy import deepcopy
from typing import Any, cast

from common.ir import ROOT, load_json, stateful_for
from validator.compare import ComparisonUnavailable, compare_offline as compare_policy

def compare_offline(before, after, **kwargs):
    """Test fixtures explicitly model two stateful policies unless overridden."""
    return compare_policy(before, after, before_stateful=kwargs.pop('before_stateful', True),
                          after_stateful=kwargs.pop('after_stateful', True), **kwargs)


def rule(rule_id, src='10.10.20.0/24', dport='80', action='accept', priority=100):
    return {'id': rule_id, 'intent': 'test', 'src': src, 'dst': '10.10.30.10/32',
            'proto': 'tcp', 'dport': dport, 'action': action, 'priority': priority}


class OfflineComparisonTest(unittest.TestCase):
    def test_implicit_state_modes_are_not_accepted(self):
        same = {'rules': [rule('a')]}
        with self.assertRaisesRegex(TypeError, 'before_stateful'):
            compare_policy(same, same)

    def test_real_state_mutation_requires_explicit_mode(self):
        before_path = ROOT / 'scenarios' / 'req-001.json'
        after_path = ROOT / 'mutations' / 'req-001-state-01.json'
        before, after = load_json(before_path)['gold'], load_json(after_path)
        self.assertTrue(stateful_for(before_path))
        self.assertFalse(stateful_for(after_path))
        result = compare_policy(before, after, before_stateful=stateful_for(before_path),
                                after_stateful=stateful_for(after_path))
        self.assertEqual(result['status'], 'indeterminate')

    def test_repository_mutations_preserve_mode_boundary(self):
        paths = sorted((ROOT / 'mutations').glob('req-*-*.json'))
        self.assertEqual(len(paths), 26)
        for path in paths:
            scenario = path.name.split('-')[0] + '-' + path.name.split('-')[1]
            before_path = ROOT / 'scenarios' / (scenario + '.json')
            with self.subTest(candidate=path.name):
                result = compare_policy(load_json(before_path)['gold'], load_json(path),
                                        before_stateful=stateful_for(before_path),
                                        after_stateful=stateful_for(path))
                self.assertEqual(result['status'],
                                 'indeterminate' if '-state-' in path.name else 'offline_only')

    def test_design_seeds(self):
        a = rule('a')
        b = rule('b', src='10.10.20.0/24', dport='8080', priority=110)
        cases = [('same', {'rules': [a, b]}, {'rules': [a, b]}, 'equal'),
                 ('remove', {'rules': [a, b]}, {'rules': [b]}, 'different'),
                 ('port', {'rules': [a]}, {'rules': [rule('a', dport='8080')]}, 'different'),
                 ('list-order', {'rules': [a, b]}, {'rules': [b, a]}, 'equal'),
                 ('approved-still-changed', {'rules': [a]},
                  {'rules': [rule('a', dport='8080')]}, 'different')]
        for name, before, after, expected in cases:
            with self.subTest(seed=name):
                result = compare_offline(before, after)
                self.assertEqual(result['status'], 'offline_only')
                changed = result['counts']['allow_to_block'] + result['counts']['block_to_allow']
                self.assertEqual(changed == 0, expected == 'equal')
                self.assertEqual(sum(result['counts'].values()), result['regions'])

    def test_priority_swap_deltas(self):
        narrow = rule('narrow', src='10.10.20.10/32', action='accept', priority=100)
        wide = rule('wide', action='drop', priority=110)
        before = {'rules': [narrow, wide]}
        after = {'rules': [dict(narrow, priority=110), dict(wide, priority=100)]}
        result = compare_offline(before, after)
        self.assertGreater(result['counts']['allow_to_block'], 0)

    def test_port_and_prefix_boundaries(self):
        before = {'rules': [rule('a', dport='80-82')]}
        after = {'rules': [rule('a', src='10.10.20.0/25', dport='81-82')]}
        result = compare_offline(before, after)
        self.assertGreater(result['counts']['allow_to_block'], 0)
        self.assertEqual(result['counts']['block_to_allow'], 0)
        self.assertTrue(any(e['packet']['port'] == 80 for e in result['examples']))

    def test_mode_mismatch_not_equivalent(self):
        same = {'rules': [rule('a')]}
        self.assertEqual(compare_offline(same, same, after_stateful=False)['status'], 'indeterminate')
        with self.assertRaises(ComparisonUnavailable):
            compare_offline(same, same, before_stateful='yes')

    def test_invalid_or_ambiguous_fails(self):
        good = {'rules': [rule('a')]}
        for bad in ({'rules': [rule('a', dport='99999')]},
                    {'rules': [rule('a'), rule('a', priority=101)]},
                    {'rules': [rule('a', src='10.10.20.1/24')]},
                    {'rules': [rule('a', src='::/0')]}, None):
            with self.subTest(bad=bad), self.assertRaises(ComparisonUnavailable):
                compare_offline(good, bad)

    def test_region_cap_fails_instead_of_partial_result(self):
        good = {'rules': [rule('a')]}
        with self.assertRaises(ComparisonUnavailable):
            compare_offline(good, good, max_regions=1)

    def test_example_limit_is_explicit(self):
        out = compare_offline({'rules': [rule('a')]}, {'rules': []}, max_examples=0)
        self.assertEqual(out['examples'], [])
        self.assertTrue(out['examples_truncated'])

    def test_region_limit_rejects_invalid_numbers(self):
        same = {'rules': [rule('a')]}
        for cap in (True, False, 0, -1, 2.5, float('nan'), float('inf'), '100'):
            with self.subTest(cap=cap), self.assertRaises(ComparisonUnavailable):
                compare_offline(same, same, max_regions=cast(Any, cap))

    def test_example_limit_rejects_invalid_numbers(self):
        same = {'rules': [rule('a')]}
        for cap in (True, False, -1, 1.5, float('nan'), float('inf'), '20'):
            with self.subTest(cap=cap), self.assertRaises(ComparisonUnavailable):
                compare_offline(same, same, max_examples=cast(Any, cap))

    def test_limit_validation_precedes_mode_mismatch(self):
        same = {'rules': [rule('a')]}
        with self.assertRaises(ComparisonUnavailable):
            compare_offline(same, same, after_stateful=False, max_regions=cast(Any, float('nan')))

    def test_valid_integer_limits_preserve_output(self):
        same = {'rules': [rule('a')]}
        out = compare_offline(same, same, max_regions=200000, max_examples=0)
        self.assertEqual(out['status'], 'offline_only')
        self.assertEqual(out['examples'], [])

    def test_rule_cap_precedes_validation_and_returns_no_partial_result(self):
        many = {'rules': [rule(f'r{i}', priority=i) for i in range(129)]}
        with self.assertRaisesRegex(ComparisonUnavailable, 'rule cap exceeded'):
            compare_offline(many, {'rules': []})

    def test_distinct_boundary_rules_exceed_work_cap_without_partial_result(self):
        rules = {'rules': [rule(f'r{i}', src=f'10.10.20.{i}/32',
                                  dport=str(1000 + i), action='drop', priority=i)
                           for i in range(40)]}
        with self.assertRaisesRegex(ComparisonUnavailable, 'work cap exceeded'):
            compare_offline(rules, rules)

    def test_work_cap_rejects_before_evaluation(self):
        before = {'rules': [rule('a')]}
        after = {'rules': []}
        with self.assertRaisesRegex(ComparisonUnavailable, 'work cap exceeded'):
            compare_offline(before, after, max_work=1)

    def test_new_caps_reject_bool_float_and_negative(self):
        same = {'rules': []}
        for value in (True, 1.5, float('nan'), 0, -1):
            with self.subTest(value=value), self.assertRaises(ComparisonUnavailable):
                compare_offline(same, same, max_rules=cast(Any, value))
            with self.subTest(work=value), self.assertRaises(ComparisonUnavailable):
                compare_offline(same, same, max_work=cast(Any, value))

    def test_exact_counts_and_input_immutability(self):
        before = {'rules': [rule('a', src='10.10.20.10/32')]}
        after = {'rules': []}
        original = deepcopy(before)
        result = compare_offline(before, after, max_examples=0)
        self.assertEqual(result['regions'], 63)
        self.assertEqual(result['counts'], {'allow_to_block': 1, 'block_to_allow': 0, 'same': 62})
        self.assertTrue(result['examples_truncated'])
        self.assertEqual(before, original)

    def test_equal_priority_id_order_changes_decision(self):
        accept = rule('a', src='10.10.20.10/32', priority=100)
        drop = rule('z', src='10.10.20.10/32', action='drop', priority=100)
        before = {'rules': [accept, drop]}
        after = {'rules': [dict(accept, id='zz'), drop]}
        result = compare_offline(before, after)
        self.assertEqual(result['counts'], {'allow_to_block': 1, 'block_to_allow': 0, 'same': 62})


if __name__ == '__main__':
    unittest.main()
