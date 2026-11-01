"""Fail-closed current reader for a deployment-owned, pinned baseline.

The record must be created by a trusted deployer after a successful managed apply,
not by the validator or an untrusted JSON input. A missing record cannot be bootstrapped
from the live firewall. This reader only supports an exact recorded nft snapshot;
no policy verdict can be made from an unrecorded/partially recorded installation.
"""
from common.lab import FW, exec_in, require_lab


def live_snapshot():
    require_lab()
    # Counters change under normal traffic. -s excludes their live values;
    # -n/-y keep numeric addresses and chain priority for strict comparison.
    # Do not use -t (would hide set data).
    result = exec_in(FW, 'nft', '-n', '-y', '-s', 'list', 'ruleset')
    if result.returncode != 0 or not result.stdout.strip():
        raise RuntimeError(f'nft snapshot unavailable (exit {result.returncode}): {result.stderr}')
    return result.stdout


class LiveCurrentProvider:
    def __init__(self, record_path):
        # The former two-file JSON reader could certify unrelated IR by pairing
        # it with a self-reported nft hash. Keep a loud migration failure rather
        # than a second, less strict provider alongside ManagedCurrentProvider.
        raise RuntimeError('legacy current record unsupported; use ManagedCurrentProvider with protected store')

    def read_verified_current(self):
        raise RuntimeError('legacy current record unsupported')

    def assert_still_current(self, current):
        raise RuntimeError('legacy current record unsupported')
