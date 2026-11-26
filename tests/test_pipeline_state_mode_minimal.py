"""Real JSON CLIs with synthetic lab/CSV only; no Podman or nft is run."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from common.ir import ROOT

DISPATCH = r'''import json, runpy, subprocess, sys
from unittest.mock import patch
from pathlib import Path
sys.path.insert(0, str(Path.cwd()))
a = sys.argv[1:]
sys.argv = a
if a[0] == '-c':
    sys.argv = ['-c', *a[2:]]
    exec(a[1])
elif a[0] == 'validator/validate.py':
    from validator import validate as v
    def nft(cmd, **kw):
        Path('checked.nft').write_bytes(kw['input'])
        return subprocess.CompletedProcess(cmd, 0, b'__validator_nft_rc=0\n', b'')
    with patch.object(v.subprocess, 'run', side_effect=nft):
        v.main()
elif a[0] == 'deployer/deploy.py':
    from deployer import deploy as d
    from common.ir import load_json
    s = load_json('scenarios/req-001.json')
    rows = [dict(id=p['id'], kind=p['kind'], expect=p['expect'], set=p.get('set','v1'), observed=p['expect'], **{'pass': True}) for p in s['probes']]
    with patch.object(d, 'require_lab'), patch.object(d, 'snapshot', return_value='saved'), patch.object(d.deadman, 'recover', return_value=[]), patch.object(d.deadman, 'arm', return_value='a'*32), patch.object(d.deadman, 'disarm', return_value='disarmed'), patch.object(d, 'probe', return_value={'results': rows}), patch.object(d, 'nft_apply', side_effect=lambda text: Path('applied.nft').write_text(text, encoding='utf-8')):
        d.main()
elif a[0] == 'eval/evaluate.py':
    Path('recorded').touch()
else:
    runpy.run_path(a[0], run_name='__main__')
'''

class PipelineStateModeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='minimal-state-', dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for folder in ('common', 'validator', 'deployer', 'generator', 'schema', 'scenarios', 'mutations'):
            shutil.copytree(ROOT/folder, self.root/folder, ignore=shutil.ignore_patterns('__pycache__'))
        (self.root/'pipeline').mkdir()
        (self.root/'pipeline/run.sh').write_text((ROOT/'pipeline/run.sh').read_text(encoding='utf-8'), encoding='utf-8', newline='\n')
        (self.root/'dispatch.py').write_text(DISPATCH, encoding='utf-8')
        (self.root/'bin').mkdir()
        shim = self.root/'bin/python3'
        shim.write_text('#!/usr/bin/env bash\nexec "'+Path(sys.executable).as_posix()+'" dispatch.py "$@"\n', encoding='utf-8', newline='\n')
        shim.chmod(0o755)
        self.env = os.environ.copy()
        self.env.update(PATH=str(self.root/'bin')+os.pathsep+self.env['PATH'], WATCH='0', APPROVE='yes', GENERATOR='mock', OUT_DIR='out/test')
        self.env.pop('CANDIDATE', None)

    def check_mode(self, candidate, stateful):
        if candidate:
            self.env['CANDIDATE'] = candidate
        r = subprocess.run(['bash', 'pipeline/run.sh', 'scenarios/req-001.json'], cwd=self.root, env=self.env, capture_output=True, encoding='utf-8', timeout=45)
        self.assertEqual(r.returncode, 0, r.stderr)
        checked = (self.root/'checked.nft').read_text(encoding='utf-8')
        applied = (self.root/'applied.nft').read_text(encoding='utf-8')
        self.assertEqual(checked, applied)
        self.assertEqual('ct state established,related accept' in checked, stateful)
        self.assertTrue((self.root/'recorded').exists())

    def test_state_mutation_checked_and_applied_stateless(self):
        self.check_mode('mutations/req-001-state-01.json', False)

    def test_regular_candidate_checked_and_applied_stateful(self):
        self.check_mode('mutations/req-001-port-01.json', True)

    def test_mock_checked_and_applied_stateful(self):
        self.check_mode(None, True)
