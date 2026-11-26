#!/usr/bin/env python3
"""Manual interrupted managed transaction recovery; never run on production implicitly."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from deployer.managed import ManagedStore  # noqa: E402
from deployer.deploy import nft_apply  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--store', required=True)
    args = ap.parse_args()
    try:
        store = ManagedStore(args.store)
        with store.locked():
            store.recover(nft_apply)
    except Exception as ex:
        print(f'recovery aborted; intent retained: {type(ex).__name__}: {ex}', file=sys.stderr)
        return 1
    print('managed rollback readback and previous record restored')
    return 0


if __name__ == '__main__':
    sys.exit(main())
