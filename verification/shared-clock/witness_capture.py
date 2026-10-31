# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Private checked-capture boundary; supplied trusted reports require qualification.

This module does not turn a chrony status string, configured identity, or scripted
report into evidence of UTC accuracy. The deployment-owned reader must establish
those facts. No wall-clock/DB fallback, daemon, synchronization, or I/O on import.
"""
from dataclasses import dataclass
import base64
import hashlib
import json
import os
import sys
import time
import uuid

NANOSECOND = 1_000_000_000
MAX_UTC_NS = 253402300799 * NANOSECOND + 999_999_999
MAX_CAPTURE_NS = 25_000_000
MAX_UNCERTAINTY_NS = 125_000_000
MAX_REQUEST_NS = 100_000_000


class CaptureUnavailable(RuntimeError):
    """The complete capture/continuity contract could not be established."""


def _integer(value, low=0, high=None):
    if type(value) is not int or value < low or (high is not None and value > high):
        raise CaptureUnavailable('Invalid bounded capture integer')
    return value


def _identifier(value):
    if type(value) is not str or len(value) != 43:
        raise CaptureUnavailable('Invalid evidence commitment')
    try:
        decoded = base64.b64decode(value + '=', altchars=b'-_', validate=True)
    except (ValueError, TypeError) as exc:
        raise CaptureUnavailable('Invalid evidence commitment') from exc
    if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).decode().rstrip('=') != value:
        raise CaptureUnavailable('Noncanonical evidence commitment')
    return value


def _identity(value):
    if type(value) is not str or not value or len(value) > 128 or not value.isascii() or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise CaptureUnavailable('Invalid source identity')
    return value


@dataclass(frozen=True, slots=True)
class SourceState:
    """Protected adapter identity/step snapshot, read before and after capture.

    step_identity must change after a manual step, leap policy, source, daemon,
    configuration or rate-continuity change. A constant test marker proves none
    of those events absent; its actual mechanism is a live qualification input.
    """
    source_id: str
    configuration_id: str
    daemon_id: str
    evidence_id: str
    clock_configuration_id: str
    step_identity: str

    def validate(self):
        _identity(self.source_id)
        for value in (self.configuration_id, self.daemon_id, self.evidence_id,
                      self.clock_configuration_id, self.step_identity):
            _identifier(value)
        return self


@dataclass(frozen=True, slots=True)
class SourcePolicy:
    """Pinned approved deployment facts, not facts measured by this constructor."""
    state: SourceState
    elapsed_rate_error_ppm: int
    reference_holdover_rate_ppm: int

    def __post_init__(self):
        if type(self.state) is not SourceState:
            raise CaptureUnavailable('Missing source policy')
        self.state.validate()
        _integer(self.elapsed_rate_error_ppm, high=500)
        _integer(self.reference_holdover_rate_ppm, high=500)


@dataclass(frozen=True, slots=True)
class CaptureReport:
    """Trusted reader's contemporaneous UTC reading and complete error terms.

    system_utc_ns is read at sample_elapsed_ns within the measured bracket.
    source_error_ns is the separately justified upstream bound; remaining system
    correction, root distance, reference aging, full bracket and quantization are
    added conservatively, including deliberate overcount if the reader's terms
    overlap. The reader must authenticate its upstream and reject local fallback.
    Age and error terms are conservative bounds at sample_elapsed_ns, rather
    than nominal counters copied from an earlier report.
    """
    state: SourceState
    system_utc_ns: int
    sample_elapsed_ns: int
    externally_authenticated: bool
    local_reference: bool
    leap_status: str
    reference_age_ns: int
    source_update_interval_ns: int
    remaining_correction_ns: int
    root_delay_ns: int
    root_dispersion_ns: int
    source_error_ns: int
    quantization_ns: int


@dataclass(frozen=True, slots=True)
class CheckedCapture:
    center_ns: int
    elapsed_ns: int
    uncertainty_ns: int
    boot_identity: str
    evidence_id: str

    def __post_init__(self):
        _integer(self.center_ns, high=MAX_UTC_NS)
        _integer(self.elapsed_ns)
        _integer(self.uncertainty_ns, high=MAX_UNCERTAINTY_NS)
        _identity(self.boot_identity)
        _identifier(self.evidence_id)
        if self.lower_ns < 0 or self.center_ns + self.uncertainty_ns > MAX_UTC_NS:
            raise CaptureUnavailable('UTC capture uncertainty exceeds supported range')

    @property
    def lower_ns(self):
        return self.center_ns - self.uncertainty_ns


class CheckedCaptureAdapter:
    """Bound a trusted local capture call by original deadline and 100ms maximum.

    The supplied reader(deadline_ns) must itself obey the deadline; a late return
    is rejected here, but synchronous Python cannot interrupt arbitrary blocked
    caller code. Source-reader process/timeouts belong to that trusted adapter.
    identity() and elapsed() must also be bounded, read-only local operations.
    elapsed() returns (boot_identity, integer CLOCK_BOOTTIME nanoseconds).
    """
    def __init__(self, policy, elapsed, identity, reader):
        if type(policy) is not SourcePolicy:
            raise CaptureUnavailable('Missing pinned source policy')
        self.policy = policy
        self.elapsed = elapsed
        self.identity = identity
        self.reader = reader

    def __call__(self, deadline_ns):
        try:
            _integer(deadline_ns)
            boot, before = self.elapsed()
            _identity(boot)
            _integer(before)
            end = min(deadline_ns, before + MAX_REQUEST_NS)
            if before >= end:
                raise CaptureUnavailable('Capture original budget exhausted')
            state = self.identity()
            if type(state) is not SourceState or state.validate() != self.policy.state:
                raise CaptureUnavailable('Source identity/configuration mismatch')
            report = self.reader(end)
            after_state = self.identity()
            after_boot, after = self.elapsed()
            _integer(after)
            if (after_boot != boot or after < before or after >= end
                    or after - before > MAX_CAPTURE_NS):
                raise CaptureUnavailable('Capture bracket/boot/deadline invalid')
            if after_state != state or type(report) is not CaptureReport or report.state != state:
                raise CaptureUnavailable('Source/step changed during capture')
            if (report.externally_authenticated is not True or report.local_reference is not False
                    or report.leap_status != 'Normal'):
                raise CaptureUnavailable('External reference not admitted')
            _integer(report.system_utc_ns, high=MAX_UTC_NS)
            _integer(report.sample_elapsed_ns, before, after)
            _integer(report.reference_age_ns, high=16 * NANOSECOND)
            _integer(report.source_update_interval_ns, 1, 8 * NANOSECOND)
            _integer(report.remaining_correction_ns, -MAX_UTC_NS, MAX_UTC_NS)
            for value in (report.root_delay_ns, report.root_dispersion_ns,
                          report.source_error_ns, report.quantization_ns):
                _integer(value, high=MAX_UTC_NS)
            age_error = (report.reference_age_ns * self.policy.reference_holdover_rate_ppm + 999_999) // 1_000_000
            uncertainty = (abs(report.remaining_correction_ns) + report.root_dispersion_ns
                           + (report.root_delay_ns + 1) // 2 + report.source_error_ns
                           + age_error + (after - before) + report.quantization_ns)
            _integer(uncertainty, high=MAX_UNCERTAINTY_NS)
            # Bind the resulting metadata to every admitted report term without
            # retaining source report text or any credential/authentication key.
            evidence = dict(state={name: getattr(state, name) for name in state.__slots__},
                            bracket=[before, after], boot=boot,
                            report={name: getattr(report, name) for name in report.__slots__ if name != 'state'},
                            elapsed_rate_error_ppm=self.policy.elapsed_rate_error_ppm,
                            reference_holdover_rate_ppm=self.policy.reference_holdover_rate_ppm)
            digest = hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(',', ':')).encode()).digest()
            commitment = base64.urlsafe_b64encode(digest).decode().rstrip('=')
            return CheckedCapture(report.system_utc_ns, report.sample_elapsed_ns,
                                  uncertainty, boot, commitment)
        except CaptureUnavailable:
            raise
        except Exception as exc:
            raise CaptureUnavailable('Trusted capture unavailable') from exc


class BoottimeClock:
    """Linux-only read-only clock adapter; no claim of calibrated rate/suspend.

    Opening /proc is explicit and performed on each sample. It is never replaced
    by wall clock or time.monotonic() on an unsupported platform.
    """
    def __init__(self):
        if not sys.platform.startswith('linux') or not hasattr(time, 'CLOCK_BOOTTIME'):
            raise CaptureUnavailable('Linux CLOCK_BOOTTIME required')

    def sample(self):
        try:
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
            fd = os.open('/proc/sys/kernel/random/boot_id', flags)
            try:
                raw = os.read(fd, 128)
            finally:
                os.close(fd)
            boot = raw.decode('ascii').strip()
            if str(uuid.UUID(boot)) != boot or len(raw) != 37:
                raise CaptureUnavailable('Invalid Linux boot identity')
            return boot, _integer(time.clock_gettime_ns(time.CLOCK_BOOTTIME))
        except CaptureUnavailable:
            raise
        except Exception as exc:
            raise CaptureUnavailable('Linux clock unavailable') from exc
