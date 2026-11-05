#!/usr/bin/env python3
"""Read-only static experiment. No nft/VM, deployment or dynamic metrics.

JSON is emitted only after every requested file and metadata item is read and
all supported comparisons finish. Gold is a reference policy, NOT live current.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from common.ir import load_json, stateful_for  # noqa: E402
from pipeline.batch import load_meta  # noqa: E402
from validator.compare import compare_offline  # noqa: E402
from validator.validate import validate  # noqa: E402


def read_input(path):
    raw = path.read_bytes()
    return json.loads(raw.decode('utf-8')), hashlib.sha256(raw).hexdigest()


def measure(root=ROOT):
    root = Path(root)
    scenarios = sorted((root / 'scenarios').glob('req-*.json'))
    mutations = sorted((root / 'mutations').glob('req-*-*.json'))
    generated = sorted(p for p in (root / 'generated').glob('req-*.json')
                       if not p.name.endswith(('.meta.json', '.feedback.json')))
    if not scenarios or not mutations or not generated:
        raise ValueError('requested scenarios/mutations/generated set is empty')
    gold = {}
    scenario_inputs = []
    for path in scenarios:
        value, digest = read_input(path)
        if value['id'] != path.stem or not validate(value['gold'])['ok']:
            raise ValueError(f'invalid scenario/gold: {path.name}')
        gold[path.stem] = value['gold']
        scenario_inputs.append({'path': str(path.relative_to(root)), 'sha256': digest})
    records = []
    for kind, paths in [('mutation', mutations), ('generated', generated)]:
        for path in paths:
            value, digest = read_input(path)
            scenario = '-'.join(path.stem.split('-')[:2])
            if scenario not in gold:
                raise ValueError(f'candidate without scenario: {path.name}')
            meta = load_meta(str(path)) if kind == 'generated' else None
            meta_digest = hashlib.sha256(path.with_suffix('.meta.json').read_bytes()).hexdigest() if meta else None
            result = validate(value)
            comparison = None
            if result['ok']:
                comparison = compare_offline(gold[scenario], value,
                                             before_stateful=True,
                                             after_stateful=stateful_for(path))
            records.append({'kind': kind, 'scenario': scenario,
                            'path': str(path.relative_to(root)), 'sha256': digest,
                            'stateful': stateful_for(path), 'meta': meta,
                            'meta_sha256': meta_digest, 'validation': result,
                            'gold_comparison': comparison})
    first = [r for r in records if r['kind'] == 'generated' and r['meta']['round'] == 1]
    b = len(first)
    c = sum(r['validation']['ok'] and r['validation']['risk'] == 'high' for r in first)
    summary = {}
    for kind in ('mutation', 'generated'):
        items = [r for r in records if r['kind'] == kind]
        counts = Counter('invalid' if not r['validation']['ok'] else r['validation']['risk'] for r in items)
        comparison_counts = Counter('not_compared_invalid' if r['gold_comparison'] is None else
                                   r['gold_comparison']['status'] for r in items)
        changed = sum(r['gold_comparison'] is not None and
                      r['gold_comparison']['status'] == 'offline_only' and
                      (r['gold_comparison']['counts']['allow_to_block'] +
                       r['gold_comparison']['counts']['block_to_allow']) > 0 for r in items)
        summary[kind] = {'files': len(items), 'unique_sha256': len({r['sha256'] for r in items}),
                         'static': dict(counts), 'comparison': dict(comparison_counts),
                         'initial_packet_policy_changed': changed}
    return {'scope': 'offline static measurements; gold reference, not live current; no dynamic result',
            'scenario_count': len(scenarios), 'scenario_inputs': scenario_inputs,
            'summary': summary, 'review_file_count': {'B': b, 'C': c,
                'reduction_fraction': (b-c)/b if b else None,
                'scope': 'round1 generated candidate files; not rule count or human time'},
            'records': records}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.parse_args()
    try:
        result = measure()
        head = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, check=True,
                              capture_output=True, text=True).stdout.strip()
        dirty = subprocess.run(['git', 'status', '--porcelain'], cwd=ROOT, check=True,
                               capture_output=True, text=True).stdout.strip()
        result.update(source_commit=head, source_dirty=bool(dirty))
    except Exception as ex:
        print(f'offline experiment aborted: {type(ex).__name__}: {ex}', file=sys.stderr)
        return 2
    json.dump(result, sys.stdout, ensure_ascii=False, indent=2)
    print()
    return 0


if __name__ == '__main__':
    sys.exit(main())
