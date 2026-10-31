# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Scripted checked-capture assertions, not UTC/source qualification."""
from dataclasses import replace
import base64
import sys
import unittest
from witness_capture import (SourceState, SourcePolicy, CaptureReport, CheckedCapture,
                             CheckedCaptureAdapter, CaptureUnavailable, BoottimeClock,
                             MAX_UTC_NS)


def cid(number):
    return base64.urlsafe_b64encode(bytes([number]) * 32).decode().rstrip('=')


STATE = SourceState('approved.example', cid(1), cid(2), cid(3), cid(4), cid(5))
BASE = 1_800_000_000_000_000_000


class CaptureTests(unittest.TestCase):
    def adapter(self, *, before=1_000_000_000, after=1_010_000_000, states=None, boots=None, **changes):
        report = CaptureReport(STATE, BASE, before + 1, True, False, 'Normal',
                               1_000_000_000, 8_000_000_000, -1_000_000,
                               3, 2_000_000, 3_000_000, 1)
        report = replace(report, **changes)
        samples = iter(boots or [('boot', before), ('boot', after)])
        identities = iter(states or [STATE, STATE])
        self.deadlines = []
        def reader(deadline):
            self.deadlines.append(deadline)
            return report
        return CheckedCaptureAdapter(SourcePolicy(STATE, 500, 500),
                                     lambda: next(samples), lambda: next(identities), reader)

    def test_error_budget_accounts_for_every_term_with_ceiling(self):
        capture = self.adapter()(2_000_000_000)
        self.assertEqual(capture.uncertainty_ns, 16_500_003)
        self.assertEqual(capture.lower_ns, BASE - 16_500_003)
        self.assertEqual(self.deadlines, [1_100_000_000])
        self.assertNotEqual(capture.evidence_id, STATE.evidence_id)
        self.assertEqual(len(capture.evidence_id), 43)

    def test_request_obeys_smaller_original_budget(self):
        self.adapter()(1_020_000_000)
        self.assertEqual(self.deadlines, [1_020_000_000])

    def test_expired_original_budget_never_calls_reader(self):
        with self.assertRaises(CaptureUnavailable):
            self.adapter()(1_000_000_000)
        self.assertEqual(self.deadlines, [])

    def test_return_at_deadline_is_unavailable(self):
        with self.assertRaises(CaptureUnavailable):
            self.adapter()(1_010_000_000)

    def test_bracket_limit_equality_and_next_nanosecond(self):
        self.adapter(after=1_025_000_000)(2_000_000_000)
        with self.assertRaises(CaptureUnavailable):
            self.adapter(after=1_025_000_001)(2_000_000_000)

    def test_uncertainty_limit_equality_and_next_nanosecond(self):
        self.assertEqual(self.adapter(root_dispersion_ns=110_499_997)(2_000_000_000).uncertainty_ns, 125_000_000)
        with self.assertRaises(CaptureUnavailable):
            self.adapter(root_dispersion_ns=110_499_998)(2_000_000_000)

    def test_reference_freshness_and_update_exact_limits(self):
        self.adapter(reference_age_ns=16_000_000_000)(2_000_000_000)
        for changes in [{'reference_age_ns': 16_000_000_001},
                        {'source_update_interval_ns': 8_000_000_001},
                        {'source_update_interval_ns': 0}]:
            with self.subTest(changes=changes), self.assertRaises(CaptureUnavailable):
                self.adapter(**changes)(2_000_000_000)

    def test_authentication_leap_and_local_fallback_refuse(self):
        for changes in [{'externally_authenticated':False}, {'externally_authenticated':1},
                        {'local_reference':True}, {'local_reference':0},
                        {'leap_status':'Not synchronised'}, {'leap_status':'Insert second'}]:
            with self.subTest(changes=changes), self.assertRaises(CaptureUnavailable):
                self.adapter(**changes)(2_000_000_000)

    def test_source_daemon_config_and_step_race_refuse(self):
        for field in STATE.__slots__:
            replacement = 'another.example' if field == 'source_id' else cid(7)
            changed = replace(STATE, **{field:replacement})
            for states in [[changed, changed], [STATE, changed]]:
                with self.subTest(field=field, states=states), self.assertRaises(CaptureUnavailable):
                    self.adapter(states=states)(2_000_000_000)

    def test_report_identity_must_match_both_snapshots(self):
        with self.assertRaises(CaptureUnavailable):
            self.adapter(state=replace(STATE, evidence_id=cid(7)))(2_000_000_000)

    def test_boot_change_and_backward_elapsed_refuse(self):
        for samples in [[('boot',1_000_000_000),('next',1_010_000_000)],
                        [('boot',1_000_000_000),('boot',999_999_999)]]:
            with self.subTest(samples=samples), self.assertRaises(CaptureUnavailable):
                self.adapter(boots=samples)(2_000_000_000)

    def test_utc_sample_must_lie_inside_elapsed_bracket(self):
        for value in [999_999_999,1_010_000_001]:
            with self.subTest(value=value), self.assertRaises(CaptureUnavailable):
                self.adapter(sample_elapsed_ns=value)(2_000_000_000)

    def test_integer_types_ranges_and_nonnegative_error_terms(self):
        for changes in [{'root_delay_ns':True}, {'root_dispersion_ns':-1},
                        {'source_error_ns':-1}, {'quantization_ns':0.5},
                        {'system_utc_ns':True}, {'reference_age_ns':-1},
                        {'sample_elapsed_ns':1.0}]:
            with self.subTest(changes=changes), self.assertRaises(CaptureUnavailable):
                self.adapter(**changes)(2_000_000_000)

    def test_utc_uncertainty_endpoints_stay_in_common_range(self):
        for value in [0,MAX_UTC_NS]:
            with self.subTest(value=value), self.assertRaises(CaptureUnavailable):
                self.adapter(system_utc_ns=value)(2_000_000_000)
        CheckedCapture(0,0,0,'boot',cid(1))
        CheckedCapture(MAX_UTC_NS,0,0,'boot',cid(1))

    def test_policy_bounds_and_noncanonical_commitment_refuse(self):
        for rate in [501,-1,True,0.5]:
            with self.subTest(rate=rate), self.assertRaises(CaptureUnavailable):
                SourcePolicy(STATE,rate,500)
        with self.assertRaises(CaptureUnavailable):
            SourcePolicy(replace(STATE, evidence_id='!' * 43),500,500)
        with self.assertRaises(CaptureUnavailable):
            SourcePolicy(replace(STATE, step_identity='A' * 42 + 'B'),500,500)

    def test_reader_failures_are_unavailable_with_no_synthetic_time(self):
        def fail(deadline):
            raise OSError('private adapter failed')
        elapsed=iter([('boot',0)])
        adapter=CheckedCaptureAdapter(SourcePolicy(STATE,500,500),lambda:next(elapsed),lambda:STATE,fail)
        with self.assertRaises(CaptureUnavailable):
            adapter(100_000_000)

    def test_evidence_changes_for_each_admitted_report_term(self):
        original=self.adapter()(2_000_000_000).evidence_id
        for changes in [{'system_utc_ns':BASE+1}, {'quantization_ns':2}, {'remaining_correction_ns':1_000_000}]:
            with self.subTest(changes=changes):
                self.assertNotEqual(original,self.adapter(**changes)(2_000_000_000).evidence_id)

    def test_linux_clock_has_no_portable_fallback(self):
        if sys.platform.startswith('linux'):
            boot,elapsed=BoottimeClock().sample()
            self.assertGreater(elapsed,0)
            self.assertEqual(len(boot),36)
        else:
            with self.assertRaises(CaptureUnavailable):
                BoottimeClock()


if __name__ == '__main__':
    unittest.main()
