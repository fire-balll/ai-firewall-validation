#!/usr/bin/env python3
"""Explicit one-time managed IR registration; never infer IR from nft."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from deployer.managed import ManagedStore  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--store', required=True, help='existing protected POSIX directory, 0700 owner only')
    ap.add_argument('--ir', required=True, help='known, reviewed deployed IR (not a candidate)')
    ap.add_argument('--commit', required=True, help='full deployed source commit')
    ap.add_argument('--stateful', choices=('yes', 'no'), required=True)
    args = ap.parse_args()
    try:
        ManagedStore(args.store).bootstrap(Path(args.ir).read_bytes(),
                                           args.stateful == 'yes', args.commit)
    except Exception as ex:
        print(f'bootstrap aborted: {type(ex).__name__}: {ex}', file=sys.stderr)
        return 1
    print('managed current registered; external nft writers must honor deployer lock')
    return 0


if __name__ == '__main__':
    sys.exit(main())
