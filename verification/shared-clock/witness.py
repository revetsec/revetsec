# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Inactive private witness projection; explicit fixture control owns its lifecycle.

The capture/continuity providers and prepared SQL admission inputs are trusted
component boundaries. They are scripted in this slice, not proof of actual UTC,
worker elapsed continuity, PostgreSQL fencing, or external control custody.
No constructor starts a daemon, captures UTC, repairs a manifest, or opens traffic.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import copy
import threading

from witness_capture import CheckedCapture, MAX_UTC_NS, MAX_REQUEST_NS
from witness_storage import WitnessStorageError, canonical_id, validate_manifest

SECOND = 1_000_000_000
HORIZON_NS = 30 * SECOND
RENEWAL_NS = 10 * SECOND
MAX_OFFSET_NS = 100_000_000


class WitnessUnavailable(RuntimeError):
    """The component cannot publish admitted authority time."""


@dataclass(frozen=True, slots=True, repr=False)
class Observation:
    authority_id: str
    recovery_generation: str
    clock_generation: str
    family: str
    namespace: str
    authority_ns: int
    maximum_utc_error_ns: int = 250_000_000
    maximum_authority_advance: int = 2
    maximum_worker_offset_ns: int = 5 * SECOND

    def __repr__(self):
        return 'Observation[private admitted-time component]'


@dataclass(frozen=True, slots=True, repr=False)
class AdministrativeObservation:
    """Intentionally a separate type, never a normal-store observation."""
    authority_id: str
    recovery_generation: str
    clock_generation: str
    migration_intent: str
    authority_ns: int
    maximum_utc_error_ns: int = 250_000_000

    def __repr__(self):
        return 'AdministrativeObservation[closed migration component]'


def _ns(upper):
    return upper['epochSecond'] * SECOND + upper['nano']


def _upper(value):
    seconds, nano = divmod(value, SECOND)
    return {'epochSecond': seconds, 'nano': nano}


class Witness:
    """One live owner's unstepped projection with explicit bounded control calls.

    elapsed() returns (boot_identity, integer BOOTTIME nanoseconds).
    capture(deadline_ns) returns a fresh CheckedCapture made inside that call.
    continuity() must establish the live elapsed/rate/step assumptions. A constant
    callback establishes only the scripted component condition.

    start() consumes an already prepared closed external manifest: the controller
    must have completed the actual SQL/role transition before supplying its exact
    all-scope admission commitments. previous_clock_generation is its known old
    identity (None only for explicitly provisioned never-used genesis). These are
    private control inputs, not capabilities or a substitute SQL coordinator.
    """
    def __init__(self, owner, store, elapsed, capture, *, owner_incarnation,
                 previous_clock_generation, continuity):
        self.owner = owner
        self.store = store
        self.elapsed = elapsed
        self.capture = capture
        self.continuity = continuity
        self.owner_incarnation = canonical_id(owner_incarnation)
        if previous_clock_generation is not None:
            canonical_id(previous_clock_generation)
        self.previous_clock_generation = previous_clock_generation
        self._publication = threading.RLock()
        self._control = threading.Lock()
        self._manifest = None
        self._pending_reservation = None
        self._anchor_utc = None
        self._anchor_elapsed = None
        self._boot = None
        self._last_elapsed = None
        self._health_end = None
        self._renewal_due = None
        self._healthy = False
        self._continuity_lost = False
        self._administrative = False

    def _raw_elapsed(self):
        try:
            boot, value = self.elapsed()
            if type(boot) is not str or not boot or type(value) is not int or value < 0:
                raise ValueError('Invalid elapsed sample')
            return boot, value
        except Exception as exc:
            with self._publication:
                self._fail(continuity_lost=True)
            raise WitnessUnavailable('Elapsed source unavailable') from exc

    def _fresh(self):
        boot, value = self._raw_elapsed()
        if self._boot is not None and boot != self._boot:
            self._fail(continuity_lost=True)
            raise WitnessUnavailable('Boot continuity lost')
        if self._last_elapsed is not None and value < self._last_elapsed:
            self._fail(continuity_lost=True)
            raise WitnessUnavailable('Elapsed continuity lost')
        self._last_elapsed = value
        return boot, value

    def _fail(self, *, continuity_lost=False):
        self._healthy = False
        self._continuity_lost |= continuity_lost

    @contextmanager
    def _control_request(self):
        if not self._control.acquire(blocking=False):
            raise WitnessUnavailable('Another bounded control operation is in progress')
        try:
            yield
        finally:
            self._control.release()

    @contextmanager
    def _request(self, deadline_ns):
        # The first elapsed read measures request budget, not authority time.
        # Fresh authority sampling occurs only under the publication lock.
        _, start = self._raw_elapsed()
        if type(deadline_ns) is not int or deadline_ns <= start:
            raise WitnessUnavailable('Original request budget exhausted')
        end = min(deadline_ns, start + MAX_REQUEST_NS)
        if not self._publication.acquire(timeout=(end - start) / SECOND):
            raise WitnessUnavailable('Publication lock exhausted original budget')
        try:
            _, now = self._fresh()
            self._within(now, end)
            yield end
        finally:
            self._publication.release()

    @staticmethod
    def _within(now, end):
        if now >= end:
            raise WitnessUnavailable('Original request budget exhausted')

    def _control_snapshot(self):
        try:
            self.owner.check()
            value = self.store.read()
        except Exception as exc:
            self._fail(continuity_lost=True)
            raise WitnessUnavailable('External witness missing or uncertain') from exc
        if self._manifest is not None and value != self._manifest:
            pending = self._pending_reservation
            if pending is None or value not in pending:
                self._fail(continuity_lost=True)
                raise WitnessUnavailable('External control changed or disappeared')
        if value['ownerIncarnation'] != self.owner_incarnation:
            self._fail(continuity_lost=True)
            raise WitnessUnavailable('Manifest owner differs from live owner')
        if value['pendingTransition'] is not None:
            self._fail()
            raise WitnessUnavailable('External transition remains pending')
        try:
            continuous = self.continuity()
        except Exception:
            continuous = False
        if continuous is not True:
            self._fail(continuity_lost=True)
            raise WitnessUnavailable('Elapsed/rate continuity unavailable')
        return value

    @staticmethod
    def _all_admission(value, expected):
        if expected != value['activeDatabaseAdmission']:
            raise WitnessUnavailable('Prepared all-scope SQL admission differs')

    @staticmethod
    def _scope_admission(value, expected):
        fields = {'authorityId', 'recoveryGeneration', 'clockGeneration', 'profile', 'scope'}
        if type(expected) is not dict or set(expected) != fields:
            raise WitnessUnavailable('Incomplete namespace SQL admission')
        for name in ('authorityId', 'recoveryGeneration', 'clockGeneration', 'profile'):
            if expected[name] != value[name]:
                raise WitnessUnavailable('Namespace SQL admission differs')
        scope = expected['scope']
        if scope not in value['activeDatabaseAdmission']:
            raise WitnessUnavailable('Namespace SQL admission is outside allowlist')
        return scope

    def _capture(self, end, *, initial):
        with self._request(end):
            _, before = self._fresh()
        # Potentially slow adapter work stays outside the publication lock.
        try:
            capture = self.capture(end)
        except Exception as exc:
            with self._publication:
                self._fail()
            raise WitnessUnavailable('Checked capture unavailable') from exc
        with self._request(end):
            _, after = self._fresh()
            self._within(after, end)
            if self._continuity_lost:
                raise WitnessUnavailable('Live continuity was lost during capture')
            if type(capture) is not CheckedCapture or capture.boot_identity != self._boot:
                self._fail(continuity_lost=True)
                raise WitnessUnavailable('Capture boot/source differs')
            if not before <= capture.elapsed_ns <= after:
                self._fail()
                raise WitnessUnavailable('Capture is stale or outside this request')
            if capture.center_ns - capture.uncertainty_ns < 0 or capture.center_ns + capture.uncertainty_ns > MAX_UTC_NS:
                self._fail()
                raise WitnessUnavailable('Capture uncertainty leaves common range')
            if not initial and abs(self._project(capture.elapsed_ns) - capture.center_ns) > MAX_OFFSET_NS:
                self._fail(continuity_lost=True)
                raise WitnessUnavailable('Fixed projection no longer fits capture')
            return capture

    def _project(self, elapsed):
        if self._anchor_utc is None or self._anchor_elapsed is None or elapsed < self._anchor_elapsed:
            self._fail(continuity_lost=True)
            raise WitnessUnavailable('No continuous live projection')
        value = self._anchor_utc + elapsed - self._anchor_elapsed
        if not 0 <= value <= MAX_UTC_NS:
            self._fail(continuity_lost=True)
            raise WitnessUnavailable('Projection outside common range')
        return value

    def _next(self, expected, **changes):
        result = copy.deepcopy(expected)
        result['controlSequence'] += 1
        result.update(changes)
        return validate_manifest(result)

    def _persist(self, expected, proposed):
        # No capture or fsync is performed while holding the publication lock.
        # In-flight queries retain only the old independently valid window, even
        # if the proposed ceiling is already visible before directory fsync.
        with self._publication:
            if self._manifest != expected:
                self._fail()
                raise WitnessUnavailable('Control snapshot changed before reservation')
            self._pending_reservation = (expected, proposed)
        try:
            self.store.compare_and_set(expected, proposed)
        except Exception as exc:
            with self._publication:
                self._pending_reservation = None
                self._fail()
            raise WitnessUnavailable('Reservation durability not acknowledged') from exc
        with self._publication:
            self._pending_reservation = None
            self._manifest = proposed

    def _close_control(self):
        # Control-plane only: ordinary reads never write a health/maximum row.
        with self._publication:
            self._fail()
            expected = self._manifest
            if expected is None or expected['mode'] != 'ACTIVE' or self._pending_reservation is not None:
                return
            try:
                proposed = self._next(expected, mode='UTC_CLOSED')
            except WitnessStorageError:
                return  # Sequence exhaustion also leaves local admission closed.
        try:
            self._persist(expected, proposed)
        except (WitnessUnavailable, WitnessStorageError):
            pass  # No failed/ambiguous close can restore local publication.

    def start(self, expected_database_admission, deadline_ns, *, administrative=False):
        """Activate this fresh runtime only after an external prepared checkpoint."""
        with self._control_request():
            try:
                with self._request(deadline_ns) as end:
                    if self._anchor_utc is not None:
                        raise WitnessUnavailable('Runtime already has a projection')
                    value = self._control_snapshot()
                    desired = 'MIGRATING' if administrative else 'UTC_CLOSED'
                    if value['mode'] != desired:
                        raise WitnessUnavailable('Prepared closed mode required')
                    if value['clockGeneration'] == self.previous_clock_generation:
                        raise WitnessUnavailable('A new runtime requires a new clock generation')
                    if self.previous_clock_generation is None and value['controlSequence'] != 0:
                        raise WitnessUnavailable('Genesis assertion cannot reconstruct prior witness')
                    self._all_admission(value, expected_database_admission)
                    boot, _ = self._fresh()
                    if value['brokerBootIdentity'] != boot:
                        raise WitnessUnavailable('Prepared boot differs from elapsed source')
                    self._boot = boot
                capture = self._capture(end, initial=True)
                with self._request(end):
                    if self._control_snapshot() != value:
                        raise WitnessUnavailable('Prepared checkpoint changed during capture')
                    if capture.lower_ns < _ns(value['reservationUpper']):
                        raise WitnessUnavailable('Checked UTC has not reached durable prior ceiling')
                    self._anchor_utc = capture.center_ns
                    self._anchor_elapsed = capture.elapsed_ns
                    self._administrative = administrative
                    self._manifest = value
                    health_end = capture.elapsed_ns + HORIZON_NS
                    ceiling = self._project(health_end)
                    proposed = self._next(value, mode='MIGRATING' if administrative else 'ACTIVE',
                                          reservationUpper=_upper(ceiling), utcCaptureEvidence=capture.evidence_id)
                self._persist(value, proposed)
                with self._request(end):
                    self._control_snapshot()
                    _, now = self._fresh()
                    self._within(now, end)
                    if now >= health_end:
                        raise WitnessUnavailable('Reservation completed after health horizon')
                    self._health_end = health_end
                    self._renewal_due = capture.elapsed_ns + RENEWAL_NS
                    self._healthy = True
            except Exception as exc:
                self._close_control()
                if isinstance(exc, WitnessUnavailable):
                    raise
                raise WitnessUnavailable('Witness start refused') from exc

    def renew(self, expected_database_admission, deadline_ns, *, resume=False):
        """Explicit same-projection control renewal/resumption; no automatic retry."""
        with self._control_request():
            try:
                with self._request(deadline_ns) as end:
                    if self._anchor_utc is None or self._continuity_lost:
                        raise WitnessUnavailable('No live continuous projection for renewal')
                    value = self._control_snapshot()
                    allowed = ('MIGRATING',) if self._administrative else (('UTC_CLOSED', 'ACTIVE') if resume else ('ACTIVE',))
                    if value['mode'] not in allowed:
                        raise WitnessUnavailable('Current data admission cannot renew')
                    _, now = self._fresh()
                    if not resume and self._health_end is not None and now >= self._health_end:
                        self._fail()
                    if not resume and not self._healthy:
                        raise WitnessUnavailable('Explicit continuity resumption required')
                    self._all_admission(value, expected_database_admission)
                capture = self._capture(end, initial=False)
                with self._request(end):
                    if self._control_snapshot() != value:
                        raise WitnessUnavailable('Admission changed during capture')
                    health_end = capture.elapsed_ns + HORIZON_NS
                    ceiling = self._project(health_end)
                    if ceiling < _ns(value['reservationUpper']):
                        raise WitnessUnavailable('Renewal would decrease reservation ceiling')
                    proposed = self._next(value, mode='MIGRATING' if self._administrative else 'ACTIVE',
                                          reservationUpper=_upper(ceiling), utcCaptureEvidence=capture.evidence_id)
                self._persist(value, proposed)
                with self._request(end):
                    self._control_snapshot()
                    _, now = self._fresh()
                    self._within(now, end)
                    if now >= health_end or self._continuity_lost:
                        raise WitnessUnavailable('Renewal cannot activate this health window')
                    self._health_end = health_end
                    self._renewal_due = capture.elapsed_ns + RENEWAL_NS
                    self._healthy = True
            except Exception as exc:
                self._close_control()
                if isinstance(exc, WitnessUnavailable):
                    raise
                raise WitnessUnavailable('Witness renewal refused') from exc

    def renewal_due(self, deadline_ns):
        """Explicit scheduler query; caller attempts control renewal each 10s."""
        with self._request(deadline_ns):
            self._control_snapshot()
            _, now = self._fresh()
            if self._renewal_due is None:
                raise WitnessUnavailable('No running projection')
            return now >= self._renewal_due

    def _sample_point(self, expected, end, *, administrative=False, migration_intent=None):
        value = self._control_snapshot()
        if not self._healthy or self._health_end is None or self._continuity_lost:
            raise WitnessUnavailable('Projection health unavailable')
        if administrative:
            if value['mode'] != 'MIGRATING' or not self._administrative or migration_intent != value['migrationIntent']:
                raise WitnessUnavailable('Closed administrative intent differs')
            self._all_admission(value, expected)
        else:
            if value['mode'] != 'ACTIVE' or self._administrative:
                raise WitnessUnavailable('Normal data admission closed')
            scope = self._scope_admission(value, expected)
        _, now = self._fresh()
        self._within(now, end)
        point = self._project(now)
        # Always use the known acknowledged ceiling and health end. A visible
        # pending higher ceiling grants no extension before the fsync outcome.
        if now >= self._health_end or point >= _ns(self._manifest['reservationUpper']):
            self._fail()
            raise WitnessUnavailable('Exclusive health/reservation end reached')
        return value, point, None if administrative else scope

    def sample(self, expected_admission, deadline_ns):
        """Fresh ordinary/query observation under its own namespace admission."""
        try:
            with self._request(deadline_ns) as end:
                value, point, scope = self._sample_point(expected_admission, end)
                return Observation(value['authorityId'], value['recoveryGeneration'], value['clockGeneration'],
                                   scope['family'], scope['namespace'], point)
        except (WitnessStorageError, OSError) as exc:
            self._fail()
            raise WitnessUnavailable('Witness unavailable for ordinary observation') from exc

    def administrative_sample(self, expected_database_admission, migration_intent, deadline_ns):
        """Privileged closed-migration time; never returns Observation."""
        try:
            with self._request(deadline_ns) as end:
                value, point, _ = self._sample_point(expected_database_admission, end, administrative=True,
                                                     migration_intent=migration_intent)
                return AdministrativeObservation(value['authorityId'], value['recoveryGeneration'],
                                                 value['clockGeneration'], value['migrationIntent'], point)
        except (WitnessStorageError, OSError) as exc:
            self._fail()
            raise WitnessUnavailable('Witness unavailable for administrative observation') from exc
