# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Scripted schema, OS owner and syscall-failure checks; no power-loss claim."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from witness_storage import (DirectoryOwner, DurabilityUncertain, ManifestStore,
                             MAX_BYTES, MAX_SEQUENCE, PROFILE, WitnessStorageError,
                             canonical_bytes, canonical_id, validate_manifest)


def identity(label):
    return base64.urlsafe_b64encode(hashlib.sha256(label.encode()).digest()).decode().rstrip('=')


def make_manifest():
    scope = {'family': 'ISSUER', 'namespace': identity('namespace')}
    return {
        'format': 1, 'controlSequence': 0, 'mode': 'UTC_CLOSED',
        'ownerIncarnation': identity('owner'), 'authorityId': identity('authority'),
        'recoveryGeneration': identity('recovery'), 'clockGeneration': identity('clock'),
        'profile': dict(PROFILE), 'reservationUpper': {'epochSecond': 100, 'nano': 1},
        'brokerBootIdentity': 'scripted-boot', 'admissionScopes': [scope],
        'activeDatabaseAdmission': [{**scope, 'metadataCommitment': identity('metadata'),
                                     'schemaCommitment': identity('schema'),
                                     'writerRoleIdentity': identity('writer')}],
        'pendingTransition': None, 'utcCaptureEvidence': identity('evidence'),
        'migrationIntent': None,
    }


def next_manifest(value, **changes):
    result = copy.deepcopy(value)
    result['controlSequence'] += 1
    result.update(changes)
    return result


class ManifestSchemaTests(unittest.TestCase):
    def test_canonical_identity_exact_bytes_and_padding_bits(self):
        value = identity('canonical')
        self.assertEqual(value, canonical_id(value))
        bad_last = value[:-1] + ('B' if value[-1] != 'B' else 'C')
        for bad in (None, '', value + '=', value[:-1], '+' + value[1:], bad_last):
            with self.subTest(value=bad), self.assertRaises(WitnessStorageError):
                canonical_id(bad)

    def test_roundtrip_is_canonical_and_defensively_copied(self):
        original = make_manifest()
        checked = validate_manifest(original)
        checked['admissionScopes'][0]['namespace'] = identity('different')
        self.assertNotEqual(checked, original)
        raw = canonical_bytes(original)
        self.assertTrue(raw.endswith(b'\n'))
        self.assertLessEqual(len(raw), MAX_BYTES)
        self.assertEqual(json.loads(raw), original)

    def test_exact_root_and_nested_fields(self):
        changes = []
        for field in make_manifest():
            value = make_manifest()
            del value[field]
            changes.append(value)
        value = make_manifest(); value['runtimeAnchor'] = 42; changes.append(value)
        for field in ('profile', 'reservationUpper', 'admissionScopes', 'activeDatabaseAdmission'):
            value = make_manifest()
            target = value[field][0] if isinstance(value[field], list) else value[field]
            target['unknown'] = 1
            changes.append(value)
        for value in changes:
            with self.subTest(value=value), self.assertRaises(WitnessStorageError):
                validate_manifest(value)

    def test_bool_float_negative_overflow_and_profile_substitution_refused(self):
        mutations = [
            ('format', True), ('format', 1.0), ('controlSequence', True),
            ('controlSequence', -1), ('controlSequence', MAX_SEQUENCE + 1),
            ('mode', 'UNAVAILABLE'), ('brokerBootIdentity', ''),
            ('brokerBootIdentity', 'x' * 129), ('brokerBootIdentity', 'bad\nboot'),
        ]
        for key, bad in mutations:
            value = make_manifest(); value[key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(WitnessStorageError):
                validate_manifest(value)
        for key, bad in [('epochSecond', -1), ('epochSecond', 253402300800), ('nano', 1000000000), ('nano', True)]:
            value = make_manifest(); value['reservationUpper'][key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(WitnessStorageError):
                validate_manifest(value)
        for key in PROFILE:
            value = make_manifest(); value['profile'][key] = True
            with self.subTest(key=key), self.assertRaises(WitnessStorageError):
                validate_manifest(value)

    def test_exact_one_to_three_scope_allowlist_and_mirrors(self):
        value = make_manifest()
        for family in ('TOTP', 'WEBAUTHN'):
            value['admissionScopes'].append({'family': family, 'namespace': identity(family)})
            value['activeDatabaseAdmission'].append({**value['admissionScopes'][-1],
                'metadataCommitment': identity('metadata'), 'schemaCommitment': identity('schema'),
                'writerRoleIdentity': identity('writer')})
        self.assertEqual(3, len(validate_manifest(value)['admissionScopes']))
        mutations = []
        for scopes in ([], value['admissionScopes'] + [value['admissionScopes'][0]],
                       list(reversed(value['admissionScopes'])), [value['admissionScopes'][0]] * 2):
            bad = copy.deepcopy(value); bad['admissionScopes'] = scopes; mutations.append(bad)
        bad = copy.deepcopy(value); bad['activeDatabaseAdmission'].pop(); mutations.append(bad)
        bad = copy.deepcopy(value); bad['activeDatabaseAdmission'][0]['namespace'] = identity('different'); mutations.append(bad)
        for bad in mutations:
            with self.subTest(value=bad), self.assertRaises(WitnessStorageError):
                validate_manifest(bad)

    def test_pending_and_migration_mode_binding(self):
        pending = {key: identity(key) for key in ('transitionId', 'expectedOldCommitment', 'targetCommitment')}
        value = make_manifest(); value['pendingTransition'] = pending
        validate_manifest(value)
        value['mode'] = 'ACTIVE'
        with self.assertRaises(WitnessStorageError): validate_manifest(value)
        value = make_manifest(); value['mode'] = 'MIGRATING'
        with self.assertRaises(WitnessStorageError): validate_manifest(value)
        value['migrationIntent'] = identity('migration')
        validate_manifest(value)
        value['mode'] = 'ACTIVE'
        with self.assertRaises(WitnessStorageError): validate_manifest(value)


class ManifestStorageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name).resolve()
        self.path.chmod(0o700)
        self.owner = DirectoryOwner(self.path)
        self.addCleanup(self.owner.close)
        self.store = ManifestStore(self.owner)
        self.original = make_manifest()

    def provision(self):
        self.store.provision_genesis(self.original, confirmed_never_used=True)

    def raw(self, raw):
        path = self.path / 'manifest.json'
        path.write_bytes(raw)
        path.chmod(0o600)

    def test_missing_manifest_never_initializes_on_read_or_cas(self):
        with self.assertRaises(WitnessStorageError): self.store.read()
        with self.assertRaises(WitnessStorageError): self.store.compare_and_set(self.original, next_manifest(self.original))
        self.assertFalse((self.path / 'manifest.json').exists())

    def test_genesis_requires_explicit_closed_never_used_assertion(self):
        with self.assertRaises(WitnessStorageError): self.store.provision_genesis(self.original)
        active = next_manifest(self.original, mode='ACTIVE'); active['controlSequence'] = 0
        with self.assertRaises(WitnessStorageError): self.store.provision_genesis(active, confirmed_never_used=True)
        self.provision()
        self.assertEqual(self.original, self.store.read())
        with self.assertRaises(WitnessStorageError): self.store.provision_genesis(self.original, confirmed_never_used=True)

    def test_deleted_known_manifest_cannot_be_reprovisioned(self):
        self.provision()
        (self.path / 'manifest.json').unlink()
        with self.assertRaises(WitnessStorageError):
            ManifestStore(self.owner).provision_genesis(self.original, confirmed_never_used=True)
        self.assertFalse((self.path / 'manifest.json').exists())

    def test_cas_exact_expected_next_sequence_and_monotonic_upper(self):
        self.provision()
        proposed = next_manifest(self.original, mode='ACTIVE', reservationUpper={'epochSecond': 130, 'nano': 1})
        self.store.compare_and_set(self.original, proposed)
        self.assertEqual(proposed, self.store.read())
        with self.assertRaises(WitnessStorageError): self.store.compare_and_set(self.original, proposed)
        for bad in (next_manifest(proposed, reservationUpper={'epochSecond': 100, 'nano': 1}),
                    next_manifest(proposed, controlSequence=proposed['controlSequence']),
                    next_manifest(proposed, controlSequence=proposed['controlSequence'] + 2)):
            with self.assertRaises(WitnessStorageError): self.store.compare_and_set(proposed, bad)
        self.assertEqual(proposed, self.store.read())

    def test_sequence_exhaustion_stays_closed(self):
        value = make_manifest(); value['controlSequence'] = MAX_SEQUENCE
        self.raw(canonical_bytes(value))
        with self.assertRaises(WitnessStorageError): self.store.compare_and_set(value, value)
        self.assertEqual(value, self.store.read())

    def test_identity_requires_closed_pending_transition_and_scope_never_rebinds(self):
        self.provision()
        for field in ('ownerIncarnation', 'authorityId', 'recoveryGeneration', 'clockGeneration'):
            bad = next_manifest(self.original, **{field: identity('new-' + field)})
            with self.subTest(field=field), self.assertRaises(WitnessStorageError):
                self.store.compare_and_set(self.original, bad)
        pending = {key: identity(key) for key in ('transitionId', 'expectedOldCommitment', 'targetCommitment')}
        closed = next_manifest(self.original, ownerIncarnation=identity('next-owner'),
                               clockGeneration=identity('next-clock'), pendingTransition=pending)
        self.store.compare_and_set(self.original, closed)
        self.assertEqual(closed, self.store.read())
        bad = next_manifest(closed)
        bad['admissionScopes'][0]['namespace'] = identity('rebound')
        bad['activeDatabaseAdmission'][0]['namespace'] = identity('rebound')
        with self.assertRaises(WitnessStorageError): self.store.compare_and_set(closed, bad)

    def test_duplicate_unknown_noncanonical_nonutf8_and_oversized_files_refused(self):
        raw = canonical_bytes(self.original)
        invalid = [raw.replace(b'{', b'{"format":1,', 1), raw.replace(b'"format":1', b'"format":1,"unknown":null'),
                   raw.replace(b'"format":1', b'"format":NaN'), b'\xff', b'{' + b' ' * MAX_BYTES,
                   json.dumps(self.original, indent=2).encode(), raw.rstrip(b'\n'), b'[' * 2000]
        for data in invalid:
            self.raw(data)
            with self.subTest(data=data[:80]), self.assertRaises(WitnessStorageError): self.store.read()

    def test_detects_same_owner_sequence_upper_and_content_rollback(self):
        self.provision()
        higher = next_manifest(self.original, reservationUpper={'epochSecond': 150, 'nano': 0})
        self.store.compare_and_set(self.original, higher)
        for bad in (self.original, next_manifest(higher, reservationUpper={'epochSecond': 149, 'nano': 999999999}),
                    {**higher, 'utcCaptureEvidence': identity('changed')}):
            self.raw(canonical_bytes(bad))
            with self.subTest(value=bad), self.assertRaises(WitnessStorageError): self.store.read()
        # A fresh process has no independent rollback oracle. Custody must prove
        # the durable witness was not restored; this test makes no such claim.

    def test_manifest_symlink_and_hardlink_refused(self):
        target = self.path / 'other'; target.write_bytes(canonical_bytes(self.original)); target.chmod(0o600)
        path = self.path / 'manifest.json'
        path.symlink_to(target)
        with self.assertRaises(WitnessStorageError): self.store.read()
        path.unlink(); os.link(target, path)
        with self.assertRaises(WitnessStorageError): self.store.read()

    def test_owner_is_nonblocking_for_same_process_and_subprocess(self):
        with self.assertRaises(WitnessStorageError): DirectoryOwner(self.path)
        command = [sys.executable, '-c', 'from witness_storage import DirectoryOwner; import sys; DirectoryOwner(sys.argv[1])', str(self.path)]
        result = subprocess.run(command, cwd=Path(__file__).parent, capture_output=True, timeout=5)
        self.assertNotEqual(0, result.returncode)
        self.assertIn(b'ownership unavailable', result.stderr)
        self.owner.close()
        with DirectoryOwner(self.path) as successor:
            successor.check()

    def test_forked_owner_refused_and_child_close_preserves_parent_lock(self):
        pid = os.fork()
        if pid == 0:
            try:
                try:
                    self.owner.check()
                except WitnessStorageError:
                    self.owner.close()
                    os._exit(74)
                os._exit(75)
            except BaseException:
                os._exit(76)
        _, status = os.waitpid(pid, 0)
        self.assertTrue(os.WIFEXITED(status))
        self.assertEqual(74, os.WEXITSTATUS(status))
        self.owner.check()
        with self.assertRaises(WitnessStorageError): DirectoryOwner(self.path)
        self.owner.close()
        with DirectoryOwner(self.path) as successor:
            successor.check()

    def test_closed_owner_and_substituted_lock_refused(self):
        lock = self.path / 'owner.lock'
        lock.rename(self.path / 'old-lock')
        lock.write_bytes(b''); lock.chmod(0o600)
        with self.assertRaises(WitnessStorageError): self.owner.check()
        self.owner.close()
        with self.assertRaises(WitnessStorageError): self.store.read()

    def test_symlink_directory_ancestor_and_insecure_directory_refused(self):
        parent = self.path / 'parent'; parent.mkdir(mode=0o700)
        child = parent / 'child'; child.mkdir(mode=0o700)
        alias = self.path / 'alias'; alias.symlink_to(parent, target_is_directory=True)
        with self.assertRaises(WitnessStorageError): DirectoryOwner(alias / 'child')
        child.chmod(0o755)
        with self.assertRaises(WitnessStorageError): DirectoryOwner(child)

    def test_substituted_directory_and_manifest_mode_refused(self):
        self.provision()
        (self.path / 'manifest.json').chmod(0o644)
        with self.assertRaises(WitnessStorageError): self.store.read()
        original_path = self.path
        replacement = self.path / 'replacement'; replacement.mkdir(mode=0o700)
        self.owner.path = replacement
        with self.assertRaises(WitnessStorageError): self.owner.check()
        self.owner.path = original_path

    def test_actual_directory_replacement_refuses_old_owner(self):
        path = self.path / 'nested'; path.mkdir(mode=0o700)
        with DirectoryOwner(path) as owner:
            path.rename(self.path / 'moved')
            path.mkdir(mode=0o700)
            with self.assertRaises(WitnessStorageError): owner.check()

    def test_write_failure_before_rename_keeps_old_entitlement(self):
        self.provision()
        proposed = next_manifest(self.original, reservationUpper={'epochSecond': 140, 'nano': 0})
        for phase in ('before_temp', 'after_temp', 'after_write', 'after_file_fsync'):
            def fail(name):
                if name == phase: raise OSError('scripted write failure')
            store = ManifestStore(self.owner, fault_hook=fail)
            with self.subTest(phase=phase), self.assertRaises(WitnessStorageError) as caught:
                store.compare_and_set(self.original, proposed)
            self.assertNotIsInstance(caught.exception, DurabilityUncertain)
            self.assertEqual(self.original, self.store.read())
            self.assertFalse(list(self.path.glob('manifest.*.tmp')))

    def test_actual_file_fsync_and_rename_errors_do_not_replace_manifest(self):
        self.provision()
        proposed = next_manifest(self.original, reservationUpper={'epochSecond': 140, 'nano': 0})
        directory_fd = self.owner.directory_fd
        real_fsync = os.fsync
        def file_fsync_fails(fd):
            if fd != directory_fd:
                raise OSError('scripted file fsync failure')
            return real_fsync(fd)
        with patch('witness_storage.os.fsync', side_effect=file_fsync_fails):
            with self.assertRaises(WitnessStorageError) as caught:
                self.store.compare_and_set(self.original, proposed)
        self.assertNotIsInstance(caught.exception, DurabilityUncertain)
        self.assertEqual(self.original, self.store.read())
        with patch('witness_storage.os.rename', side_effect=OSError('scripted rename failure')):
            with self.assertRaises(WitnessStorageError) as caught:
                self.store.compare_and_set(self.original, proposed)
        self.assertNotIsInstance(caught.exception, DurabilityUncertain)
        self.assertEqual(self.original, self.store.read())

    def test_actual_directory_fsync_failure_is_uncertain(self):
        self.provision()
        proposed = next_manifest(self.original, reservationUpper={'epochSecond': 140, 'nano': 0})
        directory_fd = self.owner.directory_fd
        real_fsync = os.fsync
        def directory_fsync_fails(fd):
            if fd == directory_fd:
                raise OSError('scripted directory fsync failure')
            return real_fsync(fd)
        with patch('witness_storage.os.fsync', side_effect=directory_fsync_fails):
            with self.assertRaises(DurabilityUncertain):
                self.store.compare_and_set(self.original, proposed)
        self.assertEqual(proposed, self.store.read())

    def test_reservation_writer_does_not_block_read_of_old_manifest(self):
        self.provision()
        writing = threading.Event()
        proceed = threading.Event()
        failures = []
        def pause(phase):
            if phase == 'after_file_fsync':
                writing.set()
                if not proceed.wait(3):
                    raise OSError('scripted writer rendezvous expired')
        self.store._fault_hook = pause
        proposed = next_manifest(self.original, reservationUpper={'epochSecond': 140, 'nano': 0})
        def write():
            try:
                self.store.compare_and_set(self.original, proposed)
            except BaseException as exc:
                failures.append(exc)
        thread = threading.Thread(target=write)
        thread.start()
        self.addCleanup(proceed.set)
        try:
            self.assertTrue(writing.wait(3))
            self.assertEqual(self.original, self.store.read())
            with self.assertRaises(WitnessStorageError):
                self.store.compare_and_set(self.original, proposed)
            second_store = ManifestStore(self.owner)
            self.assertEqual(self.original, second_store.read())
            divergent = next_manifest(self.original, reservationUpper={'epochSecond': 160, 'nano': 0})
            with self.assertRaises(WitnessStorageError):
                second_store.compare_and_set(self.original, divergent)
        finally:
            proceed.set()
            thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual([], failures)
        self.assertEqual(proposed, self.store.read())

    def test_new_store_wrapper_does_not_reset_owner_rollback_highwater(self):
        self.provision()
        proposed = next_manifest(self.original, reservationUpper={'epochSecond': 140, 'nano': 0})
        self.store.compare_and_set(self.original, proposed)
        self.raw(canonical_bytes(self.original))
        with self.assertRaises(WitnessStorageError):
            ManifestStore(self.owner).read()

    def test_rename_or_directory_acknowledgement_failure_is_uncertain(self):
        self.provision()
        for phase in ('after_rename', 'after_directory_fsync'):
            current = self.store.read()
            proposed = next_manifest(current, reservationUpper={'epochSecond': current['reservationUpper']['epochSecond'] + 30, 'nano': 0})
            def fail(name):
                if name == phase: raise OSError('scripted ambiguous acknowledgement')
            store = ManifestStore(self.owner, fault_hook=fail)
            with self.subTest(phase=phase), self.assertRaises(DurabilityUncertain):
                store.compare_and_set(current, proposed)
            self.assertEqual(proposed, self.store.read())

    def test_syscall_write_order_is_temp_file_flush_rename_directory_flush(self):
        phases = []
        store = ManifestStore(self.owner, fault_hook=phases.append)
        store.provision_genesis(self.original, confirmed_never_used=True)
        self.assertEqual(['before_temp', 'after_temp', 'after_write', 'after_file_fsync', 'after_rename', 'after_directory_fsync'], phases)

    def test_crash_between_reservation_steps_never_reconstructs_live_anchor(self):
        self.provision()
        current = self.original
        self.owner.close()
        command = '''import json,os,sys
from witness_storage import DirectoryOwner,ManifestStore
with DirectoryOwner(sys.argv[1]) as owner:
    def crash(phase):
        if phase == sys.argv[2]: os._exit(73)
    store=ManifestStore(owner, fault_hook=crash)
    old=store.read(); new=json.loads(json.dumps(old)); new['controlSequence']+=1
    new['reservationUpper']['epochSecond']+=30
    store.compare_and_set(old,new)
'''
        for phase in ('before_temp', 'after_temp', 'after_write', 'after_file_fsync', 'after_rename', 'after_directory_fsync'):
            result = subprocess.run([sys.executable, '-c', command, str(self.path), phase], cwd=Path(__file__).parent,
                                    capture_output=True, timeout=5)
            self.assertEqual(73, result.returncode, result.stderr.decode())
            with DirectoryOwner(self.path) as owner:
                observed = ManifestStore(owner).read()
            expected_sequence = current['controlSequence'] + (phase in ('after_rename', 'after_directory_fsync'))
            self.assertEqual(expected_sequence, observed['controlSequence'])
            self.assertNotIn('runtimeAnchor', observed)
            self.assertNotIn('healthEnd', observed)
            current = observed


if __name__ == '__main__':
    unittest.main()
