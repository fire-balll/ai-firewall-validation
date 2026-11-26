"""Synthetic prober error-envelope regression; no lab commands."""
import unittest
from deployer.deploy import complete_probe

class ProbeEnvelopeTest(unittest.TestCase):
    def test_error_envelope_cannot_certify_complete_rows(self):
        row = dict(id='n-001', kind='normal', expect='allow', observed='allow', **{'pass': True})
        expected = {'n-001': row}
        self.assertEqual(complete_probe({'results': [row]}, expected), [row])
        for extra in ({'error': 'probe failed'}, {'partial': True}, {'aborted': True}):
            with self.subTest(extra=extra), self.assertRaisesRegex(RuntimeError, 'incomplete probe'):
                complete_probe({'results': [row], **extra}, expected)
