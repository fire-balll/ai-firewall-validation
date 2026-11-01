"""Opt-in managed current transaction. Never adopt an existing firewall implicitly.

The POSIX directory and all writers must be owned by the same deployment principal.
An exclusive flock coordinates *this* deployer, not arbitrary external nft writers.
Unknown nft rendering, ACLs or platform => abort, never infer a current policy.
"""
import base64
from contextlib import contextmanager
try:
    import fcntl
except ImportError:  # Windows cannot provide the POSIX lock/ownership contract.
    fcntl = None
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from common.ir import schema_errors, to_nft
from validator.live_current import live_snapshot
from validator.replacement import CurrentRules

HEX = re.compile(r'[0-9a-f]{40}\Z')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def structure(snapshot, ir, stateful):
    """Accept only the supported textual nft rendering; any unknown construct fails.

    This strict subset does not claim to support all nft versions. Full ruleset
    equality alone cannot establish that an operator's JSON describes its rules.
    """
    if not isinstance(snapshot, str) or not snapshot.strip():
        raise RuntimeError('empty nft observation')
    expected = to_nft(ir, stateful=stateful).splitlines()[1:]
    observed = snapshot.splitlines()
    # Whitespace-only differences in nft pretty printing are inconsequential.
    # No comments, handles, sets, counters with live values or extra tables are ignored.
    def canonical(lines):
        return [re.sub(r'\s+', ' ', line.strip()) for line in lines if line.strip()]
    if canonical(observed) != canonical(expected):
        raise RuntimeError('unsupported or unmanaged nft structure (IR mismatch)')


class ManagedStore:
    def __init__(self, root):
        self.root = Path(root)
        self._assert_secure()

    def _assert_secure(self):
        if os.name != 'posix' or fcntl is None:
            raise RuntimeError('managed store requires POSIX owner/mode and flock; Windows ACL unsupported')
        path = self.root
        if path.is_symlink():
            raise RuntimeError('managed store symlink forbidden')
        s = path.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.geteuid() or stat.S_IMODE(s.st_mode) != 0o700:
            raise RuntimeError('managed store ownership/mode invalid')
        if path.resolve() != path.absolute():
            raise RuntimeError('managed store ancestor symlink forbidden')
        for name in ('current.json', 'intent.json', 'lock'):
            p = path / name
            if p.exists() or p.is_symlink():
                s = p.lstat()
                if not stat.S_ISREG(s.st_mode) or s.st_uid != os.geteuid() or stat.S_IMODE(s.st_mode) != 0o600 or s.st_nlink != 1:
                    raise RuntimeError(f'managed {name} ownership/mode invalid')

    @contextmanager
    def locked(self):
        self._assert_secure()
        flags = os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(self.root / 'lock', flags, 0o600)
        try:
            # A conflicting deployment is an abort, not an unbounded wait that
            # might apply after the validator's baseline has gone stale.
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as ex:
                raise RuntimeError('managed store lock busy') from ex
            self._assert_secure()
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _write(self, name, value):
        self._assert_secure()
        fd, tmp = tempfile.mkstemp(prefix='.managed-', dir=self.root)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, 'wb') as file:
                file.write(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())
                file.flush()
                os.fsync(file.fileno())
            os.replace(tmp, self.root / name)
            directory = os.open(self.root, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def _read(self, name):
        self._assert_secure()
        p = self.root / name
        fd = os.open(p, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(fd, 'rb') as file:
            opened = os.fstat(file.fileno())
            linked = p.lstat()
            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or
                    opened.st_uid != os.geteuid() or stat.S_IMODE(opened.st_mode) != 0o600 or
                    (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)):
                raise RuntimeError('managed record replaced during read')
            if opened.st_size > 4_000_000:
                raise RuntimeError('managed record too large')
            raw = file.read(4_000_001)
            if len(raw) > 4_000_000 or os.fstat(file.fileno()).st_size != opened.st_size:
                raise RuntimeError('managed record changed during read')
            value = json.loads(raw)
        if not isinstance(value, dict):
            raise RuntimeError('invalid managed record')
        return value

    def current(self):
        if (self.root / 'intent.json').exists():
            raise RuntimeError('unresolved managed intent; manual recovery required')
        record = self._read('current.json')
        if set(record) != {'version', 'ir', 'sha256', 'stateful', 'commit', 'nft_sha256'} or record['version'] != 1:
            raise RuntimeError('invalid managed record fields')
        if type(record['stateful']) is not bool or not isinstance(record['commit'], str) or not HEX.fullmatch(record['commit']):
            raise RuntimeError('invalid managed mode/commit')
        raw = base64.b64decode(record['ir'], validate=True)
        if len(raw) > 1_000_000 or digest(raw) != record['sha256']:
            raise RuntimeError('managed IR digest mismatch')
        ir = json.loads(raw)
        if not isinstance(ir, dict) or schema_errors(ir):
            raise RuntimeError('invalid managed IR')
        snapshot = live_snapshot()
        structure(snapshot, ir, record['stateful'])
        if digest(snapshot.encode()) != record['nft_sha256']:
            raise RuntimeError('live nft drift or unmanaged changes')
        # This is not a kernel-wide nft lock: detect cooperative record updates
        # and observed policy changes during collection; the consumer rechecks.
        if (self._read('current.json') != record or
                (self.root / 'intent.json').exists() or live_snapshot() != snapshot):
            raise RuntimeError('managed current changed during collection')
        return CurrentRules(raw, record['sha256'], record['stateful'], record['commit'], record['nft_sha256'])

    def read_verified_current(self):
        return self.current()

    def assert_still_current(self, current):
        if self.current() != current:
            raise RuntimeError('managed current changed')

    def publish(self, raw, stateful, commit, snapshot):
        if type(stateful) is not bool or not HEX.fullmatch(commit):
            raise RuntimeError('invalid managed commit/mode')
        ir = json.loads(raw)
        if not isinstance(ir, dict) or schema_errors(ir):
            raise RuntimeError('invalid managed IR')
        structure(snapshot, ir, stateful)
        self._write('current.json', {'version': 1, 'ir': base64.b64encode(raw).decode(),
                                     'sha256': digest(raw), 'stateful': stateful,
                                     'commit': commit, 'nft_sha256': digest(snapshot.encode())})

    def bootstrap(self, raw, stateful, commit):
        """Explicit first registration only; never derive IR from a live snapshot."""
        with self.locked():
            if (self.root / 'current.json').exists() or (self.root / 'intent.json').exists():
                raise RuntimeError('bootstrap requires empty managed store')
            self.publish(raw, stateful, commit, live_snapshot())

    def intent(self, before, candidate_raw, candidate_stateful, rollback_nft):
        if (self.root / 'intent.json').exists():
            raise RuntimeError('unresolved intent')
        if (len(rollback_nft.encode()) > 1_000_000 or len(before.ir_bytes) > 1_000_000 or
                len(candidate_raw) > 1_000_000 or type(candidate_stateful) is not bool):
            raise RuntimeError('recovery data too large')
        if not rollback_nft.startswith('flush ruleset\n'):
            raise RuntimeError('non-restorable snapshot')
        structure(rollback_nft.split('\n', 1)[1], json.loads(before.ir_bytes), before.stateful)
        self._write('intent.json', {'before': before.sha256, 'candidate': digest(candidate_raw),
                                    'snapshot': before.snapshot_token,
                                    'before_ir': base64.b64encode(before.ir_bytes).decode(),
                                    'before_stateful': before.stateful,
                                    'before_commit': before.commit,
                                    'candidate_ir': base64.b64encode(candidate_raw).decode(),
                                    'candidate_stateful': candidate_stateful,
                                    'rollback_nft': rollback_nft,
                                    'rollback_sha256': digest(rollback_nft.encode())})

    def recover(self, apply):
        """Manual recovery of an interrupted transaction; caller holds lock."""
        intent = self._read('intent.json')
        required = {'before', 'candidate', 'snapshot', 'before_ir',
                    'before_stateful', 'before_commit', 'candidate_ir',
                    'candidate_stateful', 'rollback_nft', 'rollback_sha256'}
        if (set(intent) != required or type(intent['before_stateful']) is not bool or
                type(intent['candidate_stateful']) is not bool):
            raise RuntimeError('invalid recovery intent')
        raw = base64.b64decode(intent['before_ir'], validate=True)
        candidate = base64.b64decode(intent['candidate_ir'], validate=True)
        saved = intent['rollback_nft']
        if (digest(raw) != intent['before'] or
                digest(candidate) != intent['candidate'] or
                digest(saved.encode()) != intent['rollback_sha256'] or
                not saved.startswith('flush ruleset\n')):
            raise RuntimeError('corrupt recovery intent')
        if not isinstance(intent['before_commit'], str) or not HEX.fullmatch(intent['before_commit']):
            raise RuntimeError('invalid recovery commit')
        before_ir = json.loads(raw)
        candidate_ir = json.loads(candidate)
        if (not isinstance(before_ir, dict) or schema_errors(before_ir) or
                not isinstance(candidate_ir, dict) or schema_errors(candidate_ir)):
            raise RuntimeError('invalid recovery IR')
        structure(saved.split('\n', 1)[1], before_ir, intent['before_stateful'])
        observed = live_snapshot()
        try:
            structure(observed, before_ir, intent['before_stateful'])
        except RuntimeError:
            # An unknown third-party policy must not be silently overwritten.
            structure(observed, candidate_ir, intent['candidate_stateful'])
        if observed != live_snapshot():
            raise RuntimeError('nft changed during recovery collection')
        # Unknown record state after a crash: revert even if apply had completed.
        apply(saved)
        observed = live_snapshot()
        self.publish(raw, intent['before_stateful'], intent['before_commit'], observed)
        self.finish()

    def finish(self):
        # Only after committed record has been fsynced and live readback succeeded.
        (self.root / 'intent.json').unlink()
        directory = os.open(self.root, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


class ManagedCurrentProvider:
    def __init__(self, root):
        self.store = ManagedStore(root)

    def read_verified_current(self):
        return self.store.current()

    def assert_still_current(self, current):
        if self.store.current() != current:
            raise RuntimeError('managed current changed')
