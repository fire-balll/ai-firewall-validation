"""Probe observation contract regression; AST-load only the pure guard.

No lab, subprocess, network, or rule application is invoked by this suite.
"""
import ast
from pathlib import Path
import unittest


source = Path(__file__).resolve().parents[1] / 'deployer' / 'deploy.py'
function = next(node for node in ast.parse(source.read_text(encoding='utf-8')).body
                if isinstance(node, ast.FunctionDef) and node.name == 'complete_probe')
namespace = {}
exec(compile(ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[])),
             str(source), 'exec'), namespace)
complete_probe = namespace['complete_probe']


class ProbeSetCompatibilityTests(unittest.TestCase):
    def test_current_prober_rows_are_accepted(self):
        for probe_set in ('v1', 'v2'):
            for evidence in (False, True):
                with self.subTest(probe_set=probe_set, evidence=evidence):
                    reference = {'id': 'n-001', 'kind': 'normal',
                                 'expect': 'allow', 'set': probe_set}
                    row = dict(reference, observed='allow', **{'pass': True})
                    if evidence:
                        row['evidence'] = 'synthetic observation for guard test'
                    self.assertEqual(complete_probe({'results': [row]},
                                     {'n-001': reference}), [row])


    def test_current_scenarios_match_real_expected_builders(self):
        # Evaluate the two exact comprehensions used by managed and legacy paths.
        tree = ast.parse(source.read_text(encoding='utf-8'))
        builders = [node.value for node in ast.walk(tree)
                    if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == 'expected'
                            for target in node.targets)
                    and isinstance(node.value, ast.DictComp)]
        self.assertEqual(len(builders), 2)
        import json
        for scenario in sorted(source.parent.parent.joinpath('scenarios').glob('req-*.json')):
            probes = json.loads(scenario.read_text(encoding='utf-8'))['probes']
            rows = [dict(id=p['id'], kind=p['kind'], expect=p['expect'],
                         set=p.get('set', 'v1'), observed=p['expect'], **{'pass': True})
                    for p in probes]
            for builder in builders:
                with self.subTest(scenario=scenario.name, builder_line=builder.lineno):
                    expression = ast.Expression(body=builder)
                    ast.fix_missing_locations(expression)
                    expected = eval(compile(expression, str(source), 'eval'), {'probes': probes})
                    self.assertEqual(len(expected), len(probes))
                    self.assertEqual(complete_probe({'results': rows}, expected), rows)

    def check(self, row, reference=None):
        if reference is None:
            reference = {'id': 'n-001', 'kind': 'normal', 'expect': 'allow'}
        return complete_probe({'results': [row]}, {'n-001': reference})

    def valid_row(self):
        return {'id': 'n-001', 'kind': 'normal', 'expect': 'allow',
                'observed': 'allow', 'pass': True}

    def test_legacy_rows_remain_accepted(self):
        row = self.valid_row()
        self.assertEqual(self.check(row), [row])
        row['evidence'] = 'synthetic regression evidence'
        self.assertEqual(self.check(row), [row])

    def test_wrong_set_is_rejected(self):
        row = self.valid_row()
        row['set'] = 'v2'
        with self.assertRaisesRegex(RuntimeError, 'incomplete probe observation'):
            self.check(row)

    def test_v2_requires_explicit_set(self):
        reference = {'id': 'n-001', 'kind': 'normal', 'expect': 'allow', 'set': 'v2'}
        with self.assertRaisesRegex(RuntimeError, 'incomplete probe observation'):
            self.check(self.valid_row(), reference)

    def test_invalid_set_values_are_rejected(self):
        for value in ('v3', '', None, False, ['v1'], {'v1': True}):
            with self.subTest(value=value):
                row = self.valid_row()
                row['set'] = value
                with self.assertRaisesRegex(RuntimeError, 'incomplete probe observation'):
                    self.check(row)

    def test_unknown_fields_remain_rejected(self):
        row = self.valid_row()
        row['arbitrary'] = True
        with self.assertRaisesRegex(RuntimeError, 'incomplete probe observation'):
            self.check(row)

    def test_incomplete_fields_remain_rejected(self):
        for field in self.valid_row():
            with self.subTest(field=field):
                row = self.valid_row()
                del row[field]
                with self.assertRaisesRegex(RuntimeError, 'incomplete probe observation'):
                    self.check(row)

    def test_non_string_evidence_remains_rejected(self):
        row = self.valid_row()
        row['evidence'] = ['synthetic']
        with self.assertRaisesRegex(RuntimeError, 'incomplete probe observation'):
            self.check(row)

    def test_verdict_consistency_and_bool_type_remain_enforced(self):
        for changes in ({'pass': 1}, {'pass': False}, {'observed': 'unknown'},
                        {'kind': 'attack'}, {'expect': 'block'}, {'id': 'unknown'}):
            with self.subTest(changes=changes):
                row = self.valid_row() | changes
                with self.assertRaisesRegex(RuntimeError, 'incomplete probe observation'):
                    self.check(row)

    def test_duplicate_rows_remain_rejected(self):
        expected = {'n-001': {'kind': 'normal', 'expect': 'allow'},
                    'n-002': {'kind': 'normal', 'expect': 'allow'}}
        with self.assertRaisesRegex(RuntimeError, 'incomplete probe observation'):
            complete_probe({'results': [self.valid_row(), self.valid_row()]}, expected)


if __name__ == '__main__':
    unittest.main()
