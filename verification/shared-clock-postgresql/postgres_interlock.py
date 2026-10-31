# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Inactive private external/SQL admission checkpoint, never an activation lease.

The native adapter targets an explicitly owned disposable fixture. Protected
operator inputs and checked Witness.start still own source/profile qualification.
No constructor opens SQL, changes roles, starts a service or repairs a manifest.
"""
import base64
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time

SIBLING = Path(__file__).resolve().parent.parent / 'shared-clock'
if str(SIBLING) not in sys.path:
    sys.path.insert(0, str(SIBLING))
from witness_storage import canonical_id, validate_manifest

ROW_FIELDS = ('family', 'namespace', 'authorityId', 'recoveryGeneration',
              'clockGeneration', 'profileCommitment', 'schemaCommitment',
              'metadataCommitment', 'writerRoleIdentity', 'allocationGeneration',
              'formatVersion', 'mode')
ROLE = re.compile(r'scp05_old_[a-z0-9_]{1,50}\Z')


class InterlockClosed(RuntimeError):
    """No new admission is authorized; factual SQL completion is retained.

    Preflight/initial-close failure can leave the prior admission unchanged.
    Once the pending intent is durable, every failure leaves that transition closed.
    """
    def __init__(self, message, sql_completion=None):
        super().__init__(message)
        self.sql_completion = sql_completion


def commitment(value):
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False) + '\n').encode('ascii')
    return base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip('=')


def role_identity(role):
    if type(role) is not str or not ROLE.fullmatch(role):
        raise InterlockClosed('Only explicit retired fixture roles are accepted')
    return base64.urlsafe_b64encode(hashlib.sha256(role.encode('ascii')).digest()).decode().rstrip('=')


def _roles(values):
    if type(values) not in (list, tuple) or not 1 <= len(values) <= 3 or len(set(values)) != len(values):
        raise InterlockClosed('Retired role set is not bounded and unique')
    for role in values:
        role_identity(role)
    return sorted(values)


def _rows(values):
    if type(values) not in (list, tuple) or not 1 <= len(values) <= 3:
        raise InterlockClosed('Expected one to three SQL scope rows')
    result = []
    for raw in values:
        if type(raw) is not dict or set(raw) != set(ROW_FIELDS):
            raise InterlockClosed('SQL admission row fields differ')
        row = copy.deepcopy(raw)
        if row['family'] not in ('ISSUER', 'TOTP', 'WEBAUTHN'):
            raise InterlockClosed('Unsupported SQL family')
        for name in ROW_FIELDS[1:10]:
            canonical_id(row[name])
        expected_format = 3 if row['family'] == 'TOTP' else 2
        if type(row['formatVersion']) is not int or row['formatVersion'] != expected_format:
            raise InterlockClosed('SQL target format differs from selected family')
        if row['mode'] not in ('ACTIVE', 'CLOSED'):
            raise InterlockClosed('Invalid SQL mode')
        result.append(row)
    keys = [(x['family'], x['namespace']) for x in result]
    if keys != sorted(keys) or len({x[0] for x in keys}) != len(keys):
        raise InterlockClosed('SQL scope rows must be sorted and unique by family')
    return result


def _binding(manifest, rows):
    scopes = [(x['family'], x['namespace']) for x in manifest['admissionScopes']]
    if scopes != [(x['family'], x['namespace']) for x in rows]:
        raise InterlockClosed('SQL scope allowlist differs from external allowlist')
    for row, mirror in zip(rows, manifest['activeDatabaseAdmission']):
        for field in ('authorityId', 'recoveryGeneration', 'clockGeneration'):
            if row[field] != manifest[field]:
                raise InterlockClosed('SQL authority/generation differs from external intent')
        if row['profileCommitment'] != commitment(manifest['profile']):
            raise InterlockClosed('SQL profile differs from external intent')
        for field in ('metadataCommitment', 'schemaCommitment', 'writerRoleIdentity'):
            if row[field] != mirror[field]:
                raise InterlockClosed('SQL mirror commitment differs from external intent')


class NativeAdapter:
    """Bounded CLI bridge. Credentials stay in the explicit child environment.

    A process failure after dispatch is UNKNOWN, never a fabricated rollback.
    verify is read-only and withholds its fact on any process/deadline failure.
    """
    def __init__(self, java, classpath, environment, *, elapsed=time.monotonic_ns):
        self.java = str(java)
        self.classpath = str(classpath)
        self.environment = dict(environment)
        self.elapsed = elapsed

    def _call(self, command, roles, expected, target, deadline_ns):
        left = deadline_ns - self.elapsed()
        if left <= 0:
            return 'NO_EFFECT' if command != 'verify' else 'UNVERIFIED'
        roles = _roles(roles)
        expected = _rows(expected) if expected else []
        target = _rows(target) if target else []
        if command != 'fence' and (len(expected) != len(target) or not target):
            raise InterlockClosed('Native exact scope request is incomplete')
        data = ['SCP05/1', str(len(roles)), *roles, str(len(target))]
        for old, new in zip(expected, target):
            data.append('\t'.join(str(old[name]) for name in ROW_FIELDS))
            data.append('\t'.join(str(new[name]) for name in ROW_FIELDS))
        encoded = '\n'.join(data) + '\n'
        if len(encoded.encode('ascii')) > 16384:
            raise InterlockClosed('Native control request exceeds bound')
        millis = min(60_000, max(1, (left + 999_999) // 1_000_000))
        try:
            result = subprocess.run([self.java, '-cp', self.classpath,
                                     'verification.sharedclock.PgControl', command, str(millis)],
                                    input=encoded, capture_output=True, text=True,
                                    env=self.environment, timeout=left / 1_000_000_000,
                                    check=False)
        except (OSError, subprocess.TimeoutExpired):
            return 'UNVERIFIED' if command == 'verify' else 'UNKNOWN'
        allowed = ('VERIFIED', 'UNVERIFIED') if command == 'verify' else ('COMMITTED', 'NO_EFFECT', 'UNKNOWN')
        answer = result.stdout.strip()
        if result.returncode != 0 or result.stderr or answer not in allowed:
            return 'UNVERIFIED' if command == 'verify' else 'UNKNOWN'
        return answer

    def fence(self, retired_roles, deadline_ns):
        return self._call('fence', retired_roles, [], [], deadline_ns)

    def transition(self, expected_rows, target_rows, retired_roles, deadline_ns):
        return self._call('transition', retired_roles, expected_rows, target_rows, deadline_ns)

    def verify(self, target_rows, retired_roles, deadline_ns):
        return self._call('verify', retired_roles, target_rows, target_rows, deadline_ns) == 'VERIFIED'


class Controller:
    """Prepare a closed next-generation checkpoint; never starts ordinary traffic.

    stop_routes must stop/drain the fixture's actual process/route boundary. SQL
    writer exclusion is separately established by the native adapter, not inferred
    from that callback. An interrupted/UNKNOWN transition needs explicit operator
    reconciliation; prepare never retries or resumes a pending intent.
    """
    def __init__(self, owner, store, adapter, stop_routes, *, elapsed=time.monotonic_ns):
        self.owner = owner
        self.store = store
        self.adapter = adapter
        self.stop_routes = stop_routes
        self.elapsed = elapsed

    def _time(self, deadline_ns, sql_completion=None):
        if type(deadline_ns) is not int or self.elapsed() >= deadline_ns:
            raise InterlockClosed('Original control budget exhausted', sql_completion)
        self.owner.check()

    def prepare(self, expected_manifest, target_manifest, expected_rows, target_rows,
                retired_roles, transition_id, deadline_ns):
        sql_completion = None
        try:
            self._time(deadline_ns)
            expected = validate_manifest(expected_manifest)
            target = validate_manifest(target_manifest)
            old_rows, new_rows = _rows(expected_rows), _rows(target_rows)
            roles = _roles(retired_roles)
            canonical_id(transition_id)
            _binding(expected, old_rows)
            _binding(target, new_rows)
            if expected['pendingTransition'] is not None or target['pendingTransition'] is not None:
                raise InterlockClosed('Pending transitions require explicit reconciliation')
            if target['mode'] not in ('UTC_CLOSED', 'MIGRATING', 'RECOVERY_CLOSED'):
                raise InterlockClosed('Target must remain externally closed')
            if target['admissionScopes'] != expected['admissionScopes'] or target['profile'] != expected['profile']:
                raise InterlockClosed('Selected scope/profile cannot be rebound')
            if target['clockGeneration'] == expected['clockGeneration']:
                raise InterlockClosed('Effective transition requires a new clock generation')
            if (target['reservationUpper']['epochSecond'], target['reservationUpper']['nano']) < (expected['reservationUpper']['epochSecond'], expected['reservationUpper']['nano']):
                raise InterlockClosed('Target reservation cannot decrease')
            if {role_identity(x) for x in roles} != {x['writerRoleIdentity'] for x in old_rows}:
                raise InterlockClosed('Retired role identities do not cover exact old writers')
            if {x['writerRoleIdentity'] for x in new_rows} & {x['writerRoleIdentity'] for x in old_rows}:
                raise InterlockClosed('New writer role identity must never reuse old credentials')
            for old, new in zip(old_rows, new_rows):
                if old['allocationGeneration'] != new['allocationGeneration']:
                    raise InterlockClosed('Quota reallocation is a separate closed operation')
                if new['mode'] != 'ACTIVE':
                    raise InterlockClosed('Prepared target SQL admission is not structurally active')
            intent = {'transitionId':transition_id,
                      'expectedOldCommitment':commitment({'manifest':expected, 'rows':old_rows}),
                      'targetCommitment':commitment({'manifest':target, 'rows':new_rows})}
            closed = copy.deepcopy(expected)
            closed.update(controlSequence=expected['controlSequence']+1,
                          mode='RECOVERY_CLOSED' if target['mode']=='RECOVERY_CLOSED' else 'UTC_CLOSED',
                          pendingTransition=intent)
            self.store.compare_and_set(expected, closed)
            self._time(deadline_ns)
            if self.stop_routes(deadline_ns) is not True:
                raise InterlockClosed('Actual fixture route/process drain was not established')
            self._time(deadline_ns)
            fence = self.adapter.fence(roles, deadline_ns)
            if fence != 'COMMITTED':
                raise InterlockClosed('Old writer quarantine is not known complete', fence)
            self._time(deadline_ns)
            if self.store.read() != closed:
                raise InterlockClosed('External intent changed before SQL serialization')
            sql_completion = self.adapter.transition(old_rows, new_rows, roles, deadline_ns)
            if sql_completion != 'COMMITTED':
                raise InterlockClosed('SQL admission transition is not known committed', sql_completion)
            self._time(deadline_ns, sql_completion)
            if self.store.read() != closed or self.adapter.verify(new_rows, roles, deadline_ns) is not True:
                raise InterlockClosed('SQL/external target or retired writer facts disagree', sql_completion)
            self._time(deadline_ns, sql_completion)
            prepared_pending = copy.deepcopy(target)
            prepared_pending.update(controlSequence=closed['controlSequence']+1, pendingTransition=intent)
            self.store.compare_and_set(closed, prepared_pending)
            self._time(deadline_ns, sql_completion)
            prepared = copy.deepcopy(prepared_pending)
            prepared.update(controlSequence=prepared_pending['controlSequence']+1, pendingTransition=None)
            self.store.compare_and_set(prepared_pending, prepared)
            self._time(deadline_ns, sql_completion)
            return copy.deepcopy(prepared)
        except InterlockClosed:
            raise
        except Exception as exc:
            raise InterlockClosed('External/SQL transition did not reach a prepared checkpoint', sql_completion) from exc
