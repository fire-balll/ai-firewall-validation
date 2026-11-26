"""Validator-side boundary for deployer's managed current policy.

ManagedCurrentProvider lives in deployer.managed. A CurrentRules object alone is
NOT an attestation: only a protected-store provider may supply it after actual
nft structure and management-boundary checks. A JSON verified=true flag cannot.
This adapter never applies a rule or grants approval.
"""
from dataclasses import dataclass
import hashlib
import json
import re
from typing import Protocol

from validator.compare import ComparisonUnavailable, compare_offline


@dataclass(frozen=True)
class CurrentRules:
    ir_bytes: bytes  # original persisted IR bytes; digest is over these exact bytes
    sha256: str
    stateful: bool
    commit: str
    snapshot_token: str  # provider-owned opaque generation, not wall-clock freshness


class CurrentProvider(Protocol):
    def read_verified_current(self) -> CurrentRules:
        """Read current and actual nft; reject mismatch/unmanaged/partial evidence."""
        ...

    def assert_still_current(self, current: CurrentRules) -> None:
        """Re-read current AND nft; raise on stale/mismatch/unmanaged/error.

        Return None only on success. Deployer must repeat inside its own
        compare-and-apply lock immediately before application; this is no lock.
        """
        ...


def compare_current(candidate, *, candidate_stateful, provider, **limits):
    """Return initial-packet deltas only after both provider checks succeed.

    Provider transport/persistence/nft normalization belong to the managed
    provider, not this comparison adapter. Real nft integration is separate.
    Exceptions are execution failures, not ok=false or risk=high verdicts.
    """
    if provider is None:
        raise ComparisonUnavailable('verified current provider is not implemented')
    if type(candidate_stateful) is not bool:
        raise ComparisonUnavailable('candidate stateful must be an explicit boolean')
    current = provider.read_verified_current()
    if not isinstance(current, CurrentRules):
        raise ComparisonUnavailable('provider must return CurrentRules, not a JSON attestation')
    if type(current.ir_bytes) is not bytes:
        raise ComparisonUnavailable('current IR must be exact bytes')
    if not isinstance(current.sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', current.sha256):
        raise ComparisonUnavailable('current SHA-256 format invalid')
    if hashlib.sha256(current.ir_bytes).hexdigest() != current.sha256:
        raise ComparisonUnavailable('current SHA-256 mismatch')
    if type(current.stateful) is not bool:
        raise ComparisonUnavailable('current stateful must be an explicit boolean')
    if not isinstance(current.commit, str) or not re.fullmatch(r'[0-9a-f]{40}', current.commit):
        raise ComparisonUnavailable('current commit must be a full SHA-1')
    if not isinstance(current.snapshot_token, str) or not current.snapshot_token.strip():
        raise ComparisonUnavailable('current snapshot token missing')
    before = json.loads(current.ir_bytes.decode('utf-8'))
    result = compare_offline(before, candidate, before_stateful=current.stateful,
                             after_stateful=candidate_stateful, **limits)
    if result['status'] != 'offline_only':
        raise ComparisonUnavailable(result.get('reason', 'comparison indeterminate'))
    if provider.assert_still_current(current) is not None:
        raise ComparisonUnavailable('provider recheck must return None or raise')
    return {**result, 'baseline_sha256': current.sha256, 'baseline_commit': current.commit,
            'baseline_snapshot_token': current.snapshot_token}
