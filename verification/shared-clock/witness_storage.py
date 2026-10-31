# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Private one-host witness storage; OS calls are not a durability qualification.

Only an explicitly provisioned directory may be opened. A missing witness is never
initialized by read/CAS. The live OS owner is mandatory for every access. A trusted
same-UID operator and the external directory's rollback custody remain assumptions.
"""
import base64
import copy
import fcntl
import json
import os
from pathlib import Path
import secrets
import stat
import threading


MAX_BYTES = 16384
MAX_SECOND = 253402300799
MAX_SEQUENCE = (1 << 64) - 1
PROFILE = {
    'maximumUtcErrorNanos': 250000000,
    'maximumAuthorityAdvance': 2,
    'maximumWorkerOffsetNanos': 5000000000,
    'maximumElapsedRatePpm': 500,
    'healthHorizonNanos': 30000000000,
    'renewalIntervalNanos': 10000000000,
}
FIELDS = frozenset(('format', 'controlSequence', 'mode', 'ownerIncarnation',
                    'authorityId', 'recoveryGeneration', 'clockGeneration',
                    'profile', 'reservationUpper', 'brokerBootIdentity',
                    'admissionScopes', 'activeDatabaseAdmission',
                    'pendingTransition', 'utcCaptureEvidence', 'migrationIntent'))
CLOSED = frozenset(('RECOVERY_CLOSED', 'UTC_CLOSED', 'MIGRATING'))


class WitnessStorageError(RuntimeError):
    """No proposed entitlement follows from a rejected storage operation."""


class DurabilityUncertain(WitnessStorageError):
    """A replacement may be visible, but its durability was not acknowledged."""


def canonical_id(value):
    """Validate a canonical unpadded Base64URL encoding of exactly 32 bytes."""
    if not isinstance(value, str) or len(value) != 43 or not value.isascii():
        raise WitnessStorageError('Expected canonical 32-byte identity')
    try:
        raw = base64.b64decode(value + '=', altchars=b'-_', validate=True)
    except (ValueError, TypeError) as exc:
        raise WitnessStorageError('Expected canonical 32-byte identity') from exc
    if len(raw) != 32 or base64.urlsafe_b64encode(raw).decode().rstrip('=') != value:
        raise WitnessStorageError('Expected canonical 32-byte identity')
    return value


def _fields(value, expected):
    if type(value) is not dict or set(value) != set(expected):
        raise WitnessStorageError('Unexpected manifest object fields')


def _integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise WitnessStorageError('Manifest integer outside selected bound')


def _scope(value, extra=()):
    _fields(value, ('family', 'namespace', *extra))
    if value['family'] not in ('ISSUER', 'TOTP', 'WEBAUTHN'):
        raise WitnessStorageError('Unknown admission family')
    canonical_id(value['namespace'])
    for key in extra:
        canonical_id(value[key])
    return value['family'], value['namespace']


def validate_manifest(value):
    """Return an independent validated manifest; no runtime anchor is accepted."""
    _fields(value, FIELDS)
    _integer(value['format'], 1, 1)
    _integer(value['controlSequence'], 0, MAX_SEQUENCE)
    if value['mode'] not in (*CLOSED, 'ACTIVE'):
        raise WitnessStorageError('Unknown witness mode')
    for key in ('ownerIncarnation', 'authorityId', 'recoveryGeneration',
                'clockGeneration', 'utcCaptureEvidence'):
        canonical_id(value[key])
    _fields(value['profile'], PROFILE)
    for key, expected in PROFILE.items():
        _integer(value['profile'][key], expected, expected)
    upper = value['reservationUpper']
    _fields(upper, ('epochSecond', 'nano'))
    _integer(upper['epochSecond'], 0, MAX_SECOND)
    _integer(upper['nano'], 0, 999999999)
    boot = value['brokerBootIdentity']
    if not isinstance(boot, str) or not 1 <= len(boot) <= 128 or not boot.isascii() or any(ord(c) < 33 or ord(c) > 126 for c in boot):
        raise WitnessStorageError('Invalid elapsed-clock boot identity')
    scopes = value['admissionScopes']
    if type(scopes) is not list or not 1 <= len(scopes) <= 3:
        raise WitnessStorageError('Expected one to three admission scopes')
    keys = [_scope(scope) for scope in scopes]
    if keys != sorted(keys) or len({key[0] for key in keys}) != len(keys):
        raise WitnessStorageError('Scopes must be sorted and unique per family')
    mirrors = value['activeDatabaseAdmission']
    if type(mirrors) is not list or len(mirrors) != len(keys):
        raise WitnessStorageError('Admission mirrors do not cover exact scopes')
    extra = ('metadataCommitment', 'schemaCommitment', 'writerRoleIdentity')
    if [_scope(mirror, extra) for mirror in mirrors] != keys:
        raise WitnessStorageError('Admission mirror scopes disagree')
    pending = value['pendingTransition']
    if pending is not None:
        _fields(pending, ('transitionId', 'expectedOldCommitment', 'targetCommitment'))
        for field in pending:
            canonical_id(pending[field])
        if value['mode'] == 'ACTIVE':
            raise WitnessStorageError('Pending transition cannot be ACTIVE')
    migration = value['migrationIntent']
    if migration is not None:
        canonical_id(migration)
    if value['mode'] == 'MIGRATING' and migration is None:
        raise WitnessStorageError('MIGRATING requires closed intent commitment')
    if value['mode'] == 'ACTIVE' and migration is not None:
        raise WitnessStorageError('ACTIVE cannot retain closed migration intent')
    result = copy.deepcopy(value)
    if len(_encode(result)) > MAX_BYTES:
        raise WitnessStorageError('Manifest exceeds bounded encoding')
    return result


def _encode(value):
    try:
        return (json.dumps(value, ensure_ascii=True, sort_keys=True,
                           separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')
    except (ValueError, TypeError, RecursionError) as exc:
        raise WitnessStorageError('Invalid manifest encoding') from exc


def canonical_bytes(value):
    return _encode(validate_manifest(value))


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise WitnessStorageError('Duplicate manifest field')
        result[key] = value
    return result


def _open_directory(path):
    # Walk from / using pinned dirfds. O_NOFOLLOW on the final component alone
    # would still follow symbolic ancestor directories.
    path = Path(os.path.abspath(os.fspath(path)))
    if '..' in Path(os.fspath(path)).parts:
        raise WitnessStorageError('Parent traversal is not supported')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _protected_file(info):
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        raise WitnessStorageError('Witness file identity or protection invalid')


class DirectoryOwner:
    """Nonblocking OS owner lock, retained until explicit close/process exit."""
    def __init__(self, path):
        self.path = Path(os.path.abspath(os.fspath(path)))
        self._pid = os.getpid()
        self._directory = None
        self._lock = None
        self._manifest_state_lock = threading.Lock()
        self._manifest_writer_lock = threading.Lock()
        self._known_manifest = None
        try:
            self._directory = _open_directory(self.path)
            info = os.fstat(self._directory)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise WitnessStorageError('Witness directory must be owned and private')
            self._directory_identity = info.st_dev, info.st_ino
            self._lock = os.open('owner.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self._directory)
            info = os.fstat(self._lock)
            _protected_file(info)
            self._lock_identity = info.st_dev, info.st_ino
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.fsync(self._directory)
            self.check()
        except (OSError, WitnessStorageError) as exc:
            self.close()
            raise WitnessStorageError('Exclusive protected witness ownership unavailable') from exc

    @property
    def directory_fd(self):
        self.check()
        return self._directory

    def check(self):
        if self._directory is None or self._lock is None or self._pid != os.getpid():
            raise WitnessStorageError('Witness ownership is not live')
        try:
            fd = _open_directory(self.path)
            try:
                info = os.fstat(fd)
                if (info.st_dev, info.st_ino) != self._directory_identity or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                    raise WitnessStorageError('Witness directory was substituted')
            finally:
                os.close(fd)
            info = os.stat('owner.lock', dir_fd=self._directory, follow_symlinks=False)
            _protected_file(info)
            if (info.st_dev, info.st_ino) != self._lock_identity:
                raise WitnessStorageError('Witness owner lock was substituted')
            _protected_file(os.fstat(self._lock))
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise WitnessStorageError('Witness ownership check failed') from exc

    def close(self):
        for name in ('_lock', '_directory'):
            fd = getattr(self, name, None)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)

    def __enter__(self):
        self.check()
        return self

    def __exit__(self, *_):
        self.close()


class ManifestStore:
    """Exact CAS persistence under the live exclusive directory owner.

    The optional fault hook is a private component-test phase barrier. It is not
    accepted from a broker request and cannot manufacture a durable acknowledgement.
    """
    def __init__(self, owner, fault_hook=None):
        self.owner = owner
        self._fault_hook = fault_hook
        # Every wrapper for this live owner shares the same serialization and
        # rollback high-water state; constructing a second store resets neither.
        self._state_lock = owner._manifest_state_lock
        self._writer_lock = owner._manifest_writer_lock

    @property
    def _known(self):
        return self.owner._known_manifest

    @_known.setter
    def _known(self, value):
        self.owner._known_manifest = value

    def _phase(self, name):
        if self._fault_hook is not None:
            self._fault_hook(name)

    def read(self):
        self.owner.check()
        with self._state_lock:
            known_before_read = copy.deepcopy(self._known)
        fd = None
        try:
            fd = os.open('manifest.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.owner.directory_fd)
            _protected_file(os.fstat(fd))
            parts = []
            remaining = MAX_BYTES + 1
            while remaining:
                part = os.read(fd, remaining)
                if not part:
                    break
                parts.append(part)
                remaining -= len(part)
            raw = b''.join(parts)
            if len(raw) > MAX_BYTES:
                raise WitnessStorageError('Manifest exceeds bounded encoding')
            value = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                               parse_constant=lambda _: (_ for _ in ()).throw(WitnessStorageError('Nonfinite manifest scalar')))
            value = validate_manifest(value)
            if raw != canonical_bytes(value):
                raise WitnessStorageError('Manifest is not canonical')
            if known_before_read is not None:
                if value['controlSequence'] < known_before_read['controlSequence'] or _upper(value) < _upper(known_before_read):
                    raise WitnessStorageError('Witness manifest rollback detected')
                if value['controlSequence'] == known_before_read['controlSequence'] and value != known_before_read:
                    raise WitnessStorageError('Witness manifest sequence reused')
            self.owner.check()
            # A read begun before concurrent replacement may still observe the
            # exact old file. It must not lower the live high-water mark. No state
            # lock spans file I/O or a control writer's fsync.
            with self._state_lock:
                if self._known is None or value['controlSequence'] > self._known['controlSequence']:
                    self._known = copy.deepcopy(value)
            return value
        except (OSError, ValueError, UnicodeError, RecursionError) as exc:
            raise WitnessStorageError('Witness manifest unavailable or malformed') from exc
        finally:
            if fd is not None:
                os.close(fd)

    def provision_genesis(self, manifest, *, confirmed_never_used=False):
        if not self._writer_lock.acquire(blocking=False):
            raise WitnessStorageError('Concurrent witness control writer refused')
        try:
            self._provision_genesis(manifest, confirmed_never_used=confirmed_never_used)
        finally:
            self._writer_lock.release()

    def _provision_genesis(self, manifest, *, confirmed_never_used):
        value = validate_manifest(manifest)
        if confirmed_never_used is not True or value['controlSequence'] != 0 or value['mode'] not in CLOSED:
            raise WitnessStorageError('Explicit never-used closed provisioning is required')
        with self._state_lock:
            if self._known is not None:
                raise WitnessStorageError('Known prior witness cannot be provisioned again')
        self.owner.check()
        try:
            os.stat('manifest.json', dir_fd=self.owner.directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            self._write(value, initial=True)
            return
        except OSError as exc:
            raise WitnessStorageError('Cannot establish absent genesis witness') from exc
        raise WitnessStorageError('Witness already exists; genesis cannot overwrite it')

    def compare_and_set(self, expected, proposed):
        if not self._writer_lock.acquire(blocking=False):
            raise WitnessStorageError('Concurrent witness control writer refused')
        try:
            self._compare_and_set(expected, proposed)
        finally:
            self._writer_lock.release()

    def _compare_and_set(self, expected, proposed):
        expected = validate_manifest(expected)
        proposed = validate_manifest(proposed)
        if self.read() != expected:
            raise WitnessStorageError('Witness CAS expected manifest mismatch')
        if expected['controlSequence'] == MAX_SEQUENCE or proposed['controlSequence'] != expected['controlSequence'] + 1:
            raise WitnessStorageError('Witness CAS sequence exhausted or not next')
        if _upper(proposed) < _upper(expected):
            raise WitnessStorageError('Reservation ceiling cannot decrease')
        if proposed['profile'] != expected['profile'] or proposed['admissionScopes'] != expected['admissionScopes']:
            raise WitnessStorageError('Selected profile/scopes cannot be rebound')
        identity_keys = ('authorityId', 'recoveryGeneration', 'clockGeneration',
                         'ownerIncarnation', 'brokerBootIdentity', 'activeDatabaseAdmission')
        if any(proposed[key] != expected[key] for key in identity_keys):
            if expected['mode'] not in CLOSED or proposed['mode'] not in CLOSED or proposed['pendingTransition'] is None:
                raise WitnessStorageError('Identity changes require closed pending transition')
        self._write(proposed)

    def _write(self, value, initial=False):
        raw = canonical_bytes(value)
        self.owner.check()
        temporary = 'manifest.' + secrets.token_hex(16) + '.tmp'
        fd = None
        renamed = False
        try:
            self._phase('before_temp')
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.owner.directory_fd)
            _protected_file(os.fstat(fd))
            self._phase('after_temp')
            offset = 0
            while offset < len(raw):
                count = os.write(fd, raw[offset:])
                if count <= 0:
                    raise OSError('No forward progress writing manifest')
                offset += count
            self._phase('after_write')
            os.fsync(fd)
            self._phase('after_file_fsync')
            self.owner.check()
            if initial:
                # Under the protected owner lock. Same-UID hostile operators are
                # outside the boundary, but refuse an already present target.
                try:
                    os.stat('manifest.json', dir_fd=self.owner.directory_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise WitnessStorageError('Genesis target appeared')
            os.rename(temporary, 'manifest.json', src_dir_fd=self.owner.directory_fd, dst_dir_fd=self.owner.directory_fd)
            renamed = True
            self._phase('after_rename')
            os.fsync(self.owner.directory_fd)
            self._phase('after_directory_fsync')
            self.owner.check()
            with self._state_lock:
                self._known = copy.deepcopy(value)
        except (OSError, WitnessStorageError) as exc:
            if renamed:
                raise DurabilityUncertain('Manifest replacement lacks acknowledged durability') from exc
            raise WitnessStorageError('Manifest reservation not acknowledged') from exc
        finally:
            if fd is not None:
                os.close(fd)
            if not renamed:
                try:
                    os.unlink(temporary, dir_fd=self.owner.directory_fd)
                except (FileNotFoundError, WitnessStorageError):
                    pass


def _upper(value):
    upper = value['reservationUpper']
    return upper['epochSecond'], upper['nano']
