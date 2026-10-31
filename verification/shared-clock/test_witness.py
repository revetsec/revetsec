# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Scripted projection evidence; no actual source/rate/SQL/durability claim."""
import base64
import copy
import hashlib
from pathlib import Path
import tempfile
import threading
import unittest

from witness import Witness, WitnessUnavailable, Observation, AdministrativeObservation, HORIZON_NS, RENEWAL_NS
from witness_capture import CheckedCapture, CaptureUnavailable, MAX_UTC_NS
from witness_storage import DirectoryOwner, ManifestStore, PROFILE, WitnessStorageError

SECOND = 1_000_000_000
BASE = 1_800_000_000 * SECOND


def identity(label):
    return base64.urlsafe_b64encode(hashlib.sha256(label.encode()).digest()).decode().rstrip('=')


def manifest(mode='UTC_CLOSED'):
    scopes = [{'family': family, 'namespace': identity(family)} for family in ['ISSUER', 'TOTP', 'WEBAUTHN']]
    return {
        'format': 1, 'controlSequence': 0, 'mode': mode,
        'ownerIncarnation': identity('owner'), 'authorityId': identity('authority'),
        'recoveryGeneration': identity('recovery'), 'clockGeneration': identity('clock'),
        'profile': dict(PROFILE), 'reservationUpper': {'epochSecond': 0, 'nano': 0},
        'brokerBootIdentity': 'boot-A', 'admissionScopes': scopes,
        'activeDatabaseAdmission': [dict(scope, metadataCommitment=identity(scope['family'] + '-metadata'),
                                         schemaCommitment=identity('schema'), writerRoleIdentity=identity('role'))
                                    for scope in scopes],
        'pendingTransition': None, 'utcCaptureEvidence': identity('capture'),
        'migrationIntent': identity('migration') if mode == 'MIGRATING' else None,
    }


class ScriptedClock:
    def __init__(self):
        self.ns = 0
        self.boot = 'boot-A'
        self.failure = None
        self.continuous = True
        self.offset = 0
        self.uncertainty = 50_000_000
        self.base = BASE
        self.captures = 0
        self.read_hook = None
        self.capture_hook = None

    def elapsed(self):
        if self.failure is not None:
            raise self.failure
        if self.read_hook is not None:
            self.read_hook()
        return self.boot, self.ns

    def capture(self, deadline):
        self.captures += 1
        if self.capture_hook is not None:
            return self.capture_hook(deadline)
        return CheckedCapture(self.base + self.ns + self.offset, self.ns, self.uncertainty,
                              self.boot, identity('capture'))


class WitnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='revetsec-scp04-projection-',
                                                dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.owner = DirectoryOwner(self.directory)
        self.addCleanup(self.owner.close)
        self.store = ManifestStore(self.owner)
        self.initial = manifest()
        self.current_admission = copy.deepcopy(self.initial)
        self.store.provision_genesis(self.initial, confirmed_never_used=True)
        self.clock = ScriptedClock()
        self.witness = self.make_witness()

    def make_witness(self, *, previous=None, owner_id=None):
        return Witness(self.owner, self.store, self.clock.elapsed, self.clock.capture,
                       owner_incarnation=owner_id or self.initial['ownerIncarnation'],
                       previous_clock_generation=previous, continuity=lambda: self.clock.continuous)

    def deadline(self):
        return self.clock.ns + 100_000_000

    def start(self, *, administrative=False):
        value = self.store.read()
        self.witness.start(value['activeDatabaseAdmission'], self.deadline(), administrative=administrative)
        self.current_admission = self.store.read()
        return self.current_admission

    def expected(self, family='ISSUER'):
        value = self.current_admission
        return {**{key: copy.deepcopy(value[key]) for key in ['authorityId', 'recoveryGeneration', 'clockGeneration', 'profile']},
                'scope': next(copy.deepcopy(s) for s in value['activeDatabaseAdmission'] if s['family'] == family)}

    def sample(self, family='ISSUER'):
        return self.witness.sample(self.expected(family), self.deadline())

    def renew(self, *, resume=False):
        self.witness.renew(self.current_admission['activeDatabaseAdmission'], self.deadline(), resume=resume)
        self.current_admission = self.store.read()

    def replace(self, **changes):
        old = self.store.read()
        new = copy.deepcopy(old)
        new['controlSequence'] += 1
        new.update(changes)
        self.store.compare_and_set(old, new)
        return new

    def prepare_restart(self):
        # Scripted external controller checkpoint, not actual SQL fencing.
        old = self.store.read()
        prior = old['clockGeneration']
        self.replace(mode='UTC_CLOSED', pendingTransition={'transitionId': identity('transition'),
                     'expectedOldCommitment': identity('old'), 'targetCommitment': identity('target')})
        owner_id = identity('new-owner-' + str(old['controlSequence']))
        self.replace(ownerIncarnation=owner_id, clockGeneration=identity('new-clock-' + str(old['controlSequence'])))
        self.replace(pendingTransition=None)
        self.owner.close()
        self.owner = DirectoryOwner(self.directory)
        self.addCleanup(self.owner.close)
        self.store = ManifestStore(self.owner)
        self.witness = self.make_witness(previous=prior, owner_id=owner_id)
        self.current_admission = self.store.read()
        return self.current_admission

    def test_constructor_has_no_capture_projection_or_implicit_activation(self):
        self.assertEqual(self.clock.captures, 0)
        self.assertEqual(self.store.read(), self.initial)
        with self.assertRaises(WitnessUnavailable):
            self.sample()
        self.assertEqual(self.clock.captures, 0)

    def test_initial_reservation_precedes_fresh_query_observations_without_writes(self):
        active = self.start()
        reserved = (active['reservationUpper']['epochSecond'] * SECOND + active['reservationUpper']['nano'])
        self.assertEqual(reserved, BASE + HORIZON_NS)
        before = (self.directory / 'manifest.json').read_bytes()
        for family, elapsed in [('ISSUER', 1), ('TOTP', 2), ('WEBAUTHN', 3)]:
            self.clock.ns = elapsed
            observation = self.sample(family)
            self.assertIs(type(observation), Observation)
            self.assertEqual(observation.authority_ns, BASE + elapsed)
            self.assertLess(observation.authority_ns, reserved)
            self.assertEqual(observation.maximum_utc_error_ns, 250_000_000)
        self.assertEqual((self.directory / 'manifest.json').read_bytes(), before)
        self.assertEqual(self.clock.captures, 1)

    def test_exclusive_health_end_refuses_equality_and_does_not_write(self):
        self.start()
        before = (self.directory / 'manifest.json').read_bytes()
        self.clock.ns = HORIZON_NS - 1
        self.assertEqual(self.sample().authority_ns, BASE + HORIZON_NS - 1)
        self.clock.ns = HORIZON_NS
        with self.assertRaises(WitnessUnavailable):
            self.sample()
        self.assertEqual((self.directory / 'manifest.json').read_bytes(), before)
        self.clock.ns += 1
        with self.assertRaises(WitnessUnavailable):
            self.sample()

    def test_renewal_is_due_at_ten_seconds_and_keeps_projection_and_generation(self):
        first = self.start()
        self.clock.ns = RENEWAL_NS - 1
        self.assertFalse(self.witness.renewal_due(self.deadline()))
        self.clock.ns += 1
        self.assertTrue(self.witness.renewal_due(self.deadline()))
        self.clock.offset = 100_000_000  # Boundary accepted; it cannot reanchor T.
        self.renew()
        renewed = self.store.read()
        self.assertEqual(renewed['clockGeneration'], first['clockGeneration'])
        self.assertEqual(renewed['authorityId'], first['authorityId'])
        self.assertEqual(renewed['recoveryGeneration'], first['recoveryGeneration'])
        self.assertEqual(self.sample().authority_ns, BASE + RENEWAL_NS)
        self.assertEqual(renewed['reservationUpper']['epochSecond'], BASE // SECOND + 40)
        self.assertFalse(self.witness.renewal_due(self.deadline()))

    def test_capture_offset_beyond_bound_loses_same_generation_continuity(self):
        self.start()
        self.clock.ns = RENEWAL_NS
        self.clock.offset = 100_000_001
        with self.assertRaises(WitnessUnavailable):
            self.renew()
        self.assertEqual(self.store.read()['mode'], 'UTC_CLOSED')
        self.clock.offset = 0
        with self.assertRaises(WitnessUnavailable):
            self.renew(resume=True)
        with self.assertRaises(WitnessUnavailable):
            self.sample()

    def test_failed_capture_closes_then_explicit_same_owner_resume_keeps_anchor(self):
        first = self.start()
        self.clock.ns = RENEWAL_NS
        def fail(_):
            raise CaptureUnavailable('Scripted failed source capture')
        self.clock.capture_hook = fail
        with self.assertRaises(WitnessUnavailable):
            self.renew()
        self.assertEqual(self.store.read()['mode'], 'UTC_CLOSED')
        with self.assertRaises(WitnessUnavailable):
            self.sample()
        self.clock.capture_hook = None
        self.clock.offset = -100_000_000
        self.clock.ns += 1
        self.renew(resume=True)
        self.assertEqual(self.sample().authority_ns, BASE + self.clock.ns)
        self.assertEqual(self.store.read()['clockGeneration'], first['clockGeneration'])

    def test_health_expiry_requires_explicit_resume_but_not_reanchor(self):
        self.start()
        self.clock.ns = HORIZON_NS
        with self.assertRaises(WitnessUnavailable):
            self.sample()
        with self.assertRaises(WitnessUnavailable):
            self.renew()
        self.renew(resume=True)
        self.assertEqual(self.sample().authority_ns, BASE + HORIZON_NS)

    def test_failed_or_invalid_elapsed_read_cannot_recover_same_generation(self):
        for failure in [OSError('Scripted elapsed read failure'), ValueError('Invalid elapsed fixture')]:
            with self.subTest(failure=type(failure).__name__):
                if self.witness._anchor_utc is None:
                    self.start()
                self.clock.failure = failure
                with self.assertRaises(WitnessUnavailable):
                    self.sample()
                self.clock.failure = None
                with self.assertRaises(WitnessUnavailable):
                    self.sample()
                with self.assertRaises(WitnessUnavailable):
                    self.renew(resume=True)

    def test_boot_rate_and_elapsed_regression_each_permanently_close_projection(self):
        self.start()
        self.clock.ns = 10
        self.sample()
        self.clock.ns = 9
        with self.assertRaises(WitnessUnavailable):
            self.sample()
        self.clock.ns = 11
        with self.assertRaises(WitnessUnavailable):
            self.renew(resume=True)
        # New independent runtimes exercise the other loss conditions.
        for change in ['boot', 'rate']:
            self.prepare_restart()
            self.clock.ns += 40 * SECOND
            self.clock.boot = 'boot-A'
            self.clock.continuous = True
            self.start()
            if change == 'boot':
                self.clock.boot = 'boot-B'
            else:
                self.clock.continuous = False
            with self.assertRaises(WitnessUnavailable):
                self.sample()
            self.clock.boot = 'boot-A'
            self.clock.continuous = True
            with self.assertRaises(WitnessUnavailable):
                self.renew(resume=True)

    def test_invalid_elapsed_tuple_and_recovered_provider_cannot_resume(self):
        self.start()
        self.witness.elapsed = lambda: ('boot-A', True)
        with self.assertRaises(WitnessUnavailable):
            self.sample()
        self.witness.elapsed = self.clock.elapsed
        with self.assertRaises(WitnessUnavailable):
            self.sample()
        with self.assertRaises(WitnessUnavailable):
            self.renew(resume=True)

    def test_unobserved_old_health_expiry_still_requires_explicit_resume(self):
        self.start()
        self.clock.ns = HORIZON_NS
        with self.assertRaisesRegex(WitnessUnavailable, 'Explicit continuity resumption'):
            self.renew()
        self.renew(resume=True)
        self.assertEqual(self.sample().authority_ns, BASE + HORIZON_NS)

    def test_concurrent_control_request_refuses_without_waiting_for_first(self):
        self.start()
        self.clock.ns = RENEWAL_NS
        entered, release = threading.Event(), threading.Event()
        errors = []
        def capture(_):
            entered.set()
            if not release.wait(2):
                raise RuntimeError('Control barrier expired')
            return CheckedCapture(BASE + self.clock.ns, self.clock.ns, self.clock.uncertainty, 'boot-A', identity('capture'))
        self.clock.capture_hook = capture
        def renew():
            try:
                self.renew()
            except Exception as exc:
                errors.append(exc)
        thread = threading.Thread(target=renew)
        thread.start()
        self.assertTrue(entered.wait(2))
        try:
            with self.assertRaisesRegex(WitnessUnavailable, 'control operation is in progress'):
                self.renew()
        finally:
            release.set()
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])

    def test_query_only_expiry_survives_restart_catchup_lower_endpoint(self):
        self.start()
        self.clock.ns = 29 * SECOND
        expiry = BASE + 28 * SECOND
        self.assertGreater(self.sample().authority_ns, expiry)
        prepared = self.prepare_restart()
        self.clock.ns = 30 * SECOND
        # Center reaches old U, but the complete lower endpoint is still behind.
        with self.assertRaisesRegex(WitnessUnavailable, 'durable prior ceiling'):
            self.start()
        self.clock.ns += self.clock.uncertainty
        self.start()
        point = self.sample().authority_ns
        self.assertGreater(point, expiry)
        self.assertEqual(self.store.read()['authorityId'], prepared['authorityId'])
        self.assertEqual(self.store.read()['recoveryGeneration'], prepared['recoveryGeneration'])
        self.assertEqual(point, BASE + self.clock.ns)

    def test_new_runtime_never_reuses_clock_generation_or_disk_anchor(self):
        self.start()
        current = self.store.read()
        self.replace(mode='UTC_CLOSED')
        other = self.make_witness(previous=current['clockGeneration'])
        with self.assertRaisesRegex(WitnessUnavailable, 'new clock generation'):
            other.start(current['activeDatabaseAdmission'], self.deadline())
        self.assertIsNone(other._anchor_utc)
        other = self.make_witness()
        with self.assertRaisesRegex(WitnessUnavailable, 'Genesis assertion'):
            other.start(current['activeDatabaseAdmission'], self.deadline())
        self.assertIsNone(other._anchor_utc)

    def test_missing_manifest_stays_closed_even_after_same_file_reappears(self):
        self.start()
        path = self.directory / 'manifest.json'
        raw = path.read_bytes()
        path.unlink()
        with self.assertRaises(WitnessUnavailable):
            self.sample()
        path.write_bytes(raw)
        path.chmod(0o600)
        with self.assertRaises(WitnessUnavailable):
            self.renew(resume=True)
        with self.assertRaises(WitnessUnavailable):
            self.sample()

    def test_manifest_rollback_or_changed_control_is_not_repaired(self):
        before = (self.directory / 'manifest.json').read_bytes()
        self.start()
        (self.directory / 'manifest.json').write_bytes(before)
        with self.assertRaises(WitnessUnavailable):
            self.sample()
        self.assertEqual((self.directory / 'manifest.json').read_bytes(), before)

    def test_pending_recovery_or_owner_mismatch_refuses_fresh_start(self):
        for change in [dict(mode='RECOVERY_CLOSED'),
                       dict(pendingTransition={'transitionId': identity('t'), 'expectedOldCommitment': identity('o'), 'targetCommitment': identity('n')}),
                       dict(ownerIncarnation=identity('someone-else'), pendingTransition={'transitionId': identity('t'), 'expectedOldCommitment': identity('o'), 'targetCommitment': identity('n')})]:
            # Use private mutable schema inputs with a standalone store, not a
            # normal active admission or arbitrary SQL capability.
            with self.subTest(change=change):
                original = self.store.read()
                candidate = copy.deepcopy(original)
                candidate.update(change)
                candidate['controlSequence'] += 1
                self.store.compare_and_set(original, candidate)
                other = self.make_witness(previous=identity('previous'))
                with self.assertRaises(WitnessUnavailable):
                    other.start(candidate['activeDatabaseAdmission'], self.deadline())
                restored = copy.deepcopy(original)
                restored['controlSequence'] = candidate['controlSequence'] + 1
                if restored['ownerIncarnation'] != candidate['ownerIncarnation']:
                    restored['pendingTransition'] = candidate['pendingTransition']
                self.store.compare_and_set(candidate, restored)

    def test_namespace_only_mirror_and_tuple_are_required_for_ordinary_sample(self):
        self.start()
        valid = self.expected('TOTP')
        self.assertEqual(self.witness.sample(valid, self.deadline()).family, 'TOTP')
        for key in ['authorityId', 'recoveryGeneration', 'clockGeneration', 'profile', 'scope']:
            bad = copy.deepcopy(valid)
            bad[key] = {} if key in ['profile', 'scope'] else identity('wrong')
            with self.subTest(key=key), self.assertRaises(WitnessUnavailable):
                self.witness.sample(bad, self.deadline())
        self.assertEqual(self.sample('WEBAUTHN').family, 'WEBAUTHN')

    def test_closed_migration_uses_separate_admin_type_and_full_reserved_time(self):
        self.replace(mode='MIGRATING', migrationIntent=identity('migration'))
        self.witness = self.make_witness(previous=identity('previous'))
        value = self.start(administrative=True)
        self.clock.ns = 7
        admin = self.witness.administrative_sample(value['activeDatabaseAdmission'], value['migrationIntent'], self.deadline())
        self.assertIs(type(admin), AdministrativeObservation)
        self.assertNotIsInstance(admin, Observation)
        self.assertEqual(admin.authority_ns, BASE + 7)
        with self.assertRaises(WitnessUnavailable):
            self.sample()
        with self.assertRaises(WitnessUnavailable):
            self.witness.administrative_sample(value['activeDatabaseAdmission'], identity('wrong'), self.deadline())
        self.clock.ns = RENEWAL_NS
        self.renew()
        self.assertEqual(self.store.read()['mode'], 'MIGRATING')
        self.clock.ns = 40 * SECOND
        with self.assertRaises(WitnessUnavailable):
            self.witness.administrative_sample(value['activeDatabaseAdmission'], value['migrationIntent'], self.deadline())

    def test_original_deadline_and_reference_hundred_millisecond_cap(self):
        self.start()
        expected = self.expected()
        for deadline in [self.clock.ns, self.clock.ns - 1]:
            with self.assertRaises(WitnessUnavailable):
                self.witness.sample(expected, deadline)
        def advancing_read():
            self.clock.ns += 100_000_000
        self.clock.read_hook = advancing_read
        with self.assertRaises(WitnessUnavailable):
            self.witness.sample(expected, self.clock.ns + SECOND)

    def test_stale_capture_and_late_capture_close_without_window_extension(self):
        self.start()
        self.clock.ns = RENEWAL_NS
        def stale(_):
            return CheckedCapture(BASE, 0, self.clock.uncertainty, 'boot-A', identity('capture'))
        self.clock.capture_hook = stale
        with self.assertRaises(WitnessUnavailable):
            self.renew()
        self.assertEqual(self.store.read()['reservationUpper']['epochSecond'], BASE // SECOND + 30)
        self.clock.capture_hook = None
        self.renew(resume=True)
        def late(_):
            self.clock.ns += 100_000_000
            return CheckedCapture(BASE + self.clock.ns, self.clock.ns, self.clock.uncertainty, 'boot-A', identity('capture'))
        self.clock.capture_hook = late
        with self.assertRaises(WitnessUnavailable):
            self.renew()
        self.clock.capture_hook = None
        with self.assertRaises(WitnessUnavailable):
            self.sample()

    def test_ceiling_or_capture_uncertainty_outside_common_range_refuses(self):
        self.clock.base = MAX_UTC_NS - HORIZON_NS + 1
        with self.assertRaises(WitnessUnavailable):
            self.start()
        self.assertEqual(self.store.read()['mode'], 'UTC_CLOSED')
        self.assertEqual(self.store.read()['reservationUpper'], {'epochSecond': 0, 'nano': 0})

    def test_reservation_failure_before_and_after_rename_never_grants_new_window(self):
        self.start()
        self.clock.ns = RENEWAL_NS
        old = self.store.read()
        for phase in ['before_temp', 'after_rename']:
            with self.subTest(phase=phase):
                def fail(current):
                    if current == phase:
                        raise OSError('Scripted reservation failure')
                self.store._fault_hook = fail
                with self.assertRaises(WitnessUnavailable):
                    self.renew(resume=True)
                self.store._fault_hook = None
                with self.assertRaises(WitnessUnavailable):
                    self.sample()
                if phase == 'before_temp':
                    self.assertEqual(self.store.read()['reservationUpper'], old['reservationUpper'])

    def test_capture_and_reservation_waits_do_not_hold_publication_lock(self):
        self.start()
        self.clock.ns = RENEWAL_NS
        entered = threading.Event()
        release = threading.Event()
        errors = []
        def capture(_):
            entered.set()
            if not release.wait(2):
                raise RuntimeError('Capture barrier expired')
            return CheckedCapture(BASE + self.clock.ns, self.clock.ns, self.clock.uncertainty, 'boot-A', identity('capture'))
        self.clock.capture_hook = capture
        def renew():
            try:
                self.renew()
            except Exception as exc:
                errors.append(exc)
        thread = threading.Thread(target=renew)
        thread.start()
        self.assertTrue(entered.wait(2))
        try:
            self.assertEqual(self.sample().authority_ns, BASE + RENEWAL_NS)
        finally:
            release.set()
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.clock.capture_hook = None
        entered.clear()
        release.clear()
        def reservation(phase):
            if phase == 'after_rename':
                entered.set()
                if not release.wait(2):
                    raise OSError('Reservation barrier expired')
        self.store._fault_hook = reservation
        self.clock.ns += RENEWAL_NS
        thread = threading.Thread(target=renew)
        thread.start()
        self.assertTrue(entered.wait(2))
        try:
            self.assertEqual(self.sample().authority_ns, BASE + 20 * SECOND)
        finally:
            release.set()
            thread.join(2)
            self.store._fault_hook = None
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])

    def test_visible_unacknowledged_reservation_does_not_extend_old_health_end(self):
        self.start()
        self.clock.ns = RENEWAL_NS
        entered, release = threading.Event(), threading.Event()
        errors = []
        def hold(phase):
            if phase == 'after_rename':
                entered.set()
                if not release.wait(2):
                    raise OSError('Reservation barrier expired')
        self.store._fault_hook = hold
        def renew():
            try:
                self.renew()
            except WitnessUnavailable as exc:
                errors.append(exc)
        thread = threading.Thread(target=renew)
        thread.start()
        self.assertTrue(entered.wait(2))
        try:
            self.clock.ns = HORIZON_NS
            with self.assertRaises(WitnessUnavailable):
                self.sample()
        finally:
            release.set()
            thread.join(2)
            self.store._fault_hook = None
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1)
        with self.assertRaises(WitnessUnavailable):
            self.sample()

    def test_owner_loss_and_manifest_owner_change_refuse_without_repair(self):
        self.start()
        before = (self.directory / 'manifest.json').read_bytes()
        self.owner.close()
        with self.assertRaises(WitnessUnavailable):
            self.sample()
        self.assertEqual((self.directory / 'manifest.json').read_bytes(), before)

    def test_parallel_publications_are_ordered_and_query_only_never_persists(self):
        self.start()
        expected = self.expected()
        before = (self.directory / 'manifest.json').read_bytes()
        points, errors, sampled = [], [], []
        counter = threading.Lock()
        project = self.witness._project
        def trace(elapsed):
            point = project(elapsed)
            sampled.append(point)  # Actual sampling, under publication lock.
            return point
        self.witness._project = trace
        def elapsed():
            with counter:
                self.clock.ns += 1
                return self.clock.boot, self.clock.ns
        self.witness.elapsed = elapsed
        def query():
            try:
                point = self.witness.sample(expected, SECOND).authority_ns
                with counter:
                    points.append(point)
            except Exception as exc:
                errors.append(exc)
        threads = [threading.Thread(target=query) for _ in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(2)
            self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(set(points)), 16)
        self.assertEqual(sampled, sorted(sampled))
        self.assertEqual(sorted(points), sampled)
        self.assertEqual((self.directory / 'manifest.json').read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
