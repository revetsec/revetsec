# Copyright 2026 Revetware LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Acceptance controls for scheduled evidence accounting (no external tools)."""
import datetime
import importlib.util
from pathlib import Path
import unittest

module = importlib.util.spec_from_file_location("soak", Path(__file__).with_name("soak.py"))
soak = importlib.util.module_from_spec(module)
module.loader.exec_module(soak)
runner_spec = importlib.util.spec_from_file_location("scim_run", Path(__file__).with_name("run.py"))
runner = importlib.util.module_from_spec(runner_spec)
runner_spec.loader.exec_module(runner)


class TesterDispositionTests(unittest.TestCase):
    def fixture(self):
        report = {"checks": [{"title": name, "resourceType": "User", "status": "ERROR",
                               "reason": "Failed attribute '" + runner.ENTERPRISE_URI + "': Invalid attribute path."}
                              for name in ("check_add_attribute", "check_replace_attribute")]}
        wire = [{"requestBodyShape": {"Operations": [{"op": operation, "path": runner.ENTERPRISE_URI,
                                                       "value": {"schemas": [runner.ENTERPRISE_URI]}}]}}
                for operation in ("add", "replace")]
        return report, wire

    def test_exact_fixture_defect_is_identified_from_checks_and_wire(self):
        report, wire = self.fixture()
        self.assertTrue(runner.identified_default_fixture_errors(report, wire))

    def test_extra_server_error_cannot_be_dispositioned_as_upstream(self):
        report, wire = self.fixture()
        report["checks"].append({"title": "object_replacement", "resourceType": "Group", "status": "ERROR"})
        self.assertFalse(runner.identified_default_fixture_errors(report, wire))

    def test_different_or_missing_wire_defect_cannot_be_dispositioned(self):
        report, wire = self.fixture()
        self.assertFalse(runner.identified_default_fixture_errors(report, wire[:1]))
        wire[0]["requestBodyShape"]["Operations"][0]["value"]["schemas"] = ["urn:other"]
        self.assertFalse(runner.identified_default_fixture_errors(report, wire))


class NightlyEvidenceTests(unittest.TestCase):
    def fixture(self, count=1):
        now = datetime.datetime(2026, 10, 13, 7, tzinfo=datetime.timezone.utc)
        runs = []
        records = {}
        for index in range(count):
            day = now - datetime.timedelta(days=count-index-1)
            run = {"id": index + 1, "event": "schedule", "status": "completed", "conclusion": "success",
                   "created_at": day.isoformat(), "head_sha": "revision", "run_attempt": 1}
            runs.append(run)
            records[str(run["id"])] = {"formatVersion": 1, "outcome": "passed", "githubEvent": "schedule",
                "githubRunId": str(run["id"]), "githubRunAttempt": "1", "githubSha": "revision",
                "testerOutcome": "passed", "authentikOutcome": "passed", "requiredOutcomes": sorted(soak.REQUIRED),
                "authentikCompatibilityMode": "aws",
                "testerProfile": "discovered-extension-schemas-field-excluded",
                "testerDefaultOutcome": "failed-with-identified-fixture-defect",
                "applicationArtifactSha256": "a" * 64, "pinsSha256": "b" * 64,
                "toolingSha256": "d" * 64,
                "tlsControls": ["scoped-ca-positive", "default-trust-negative", "foreign-hostname-negative"]}
        return now, runs, records

    def test_one_scheduled_success_has_no_duration_gate(self):
        now, runs, records = self.fixture()
        result = soak.evaluate(runs, records, now)
        self.assertEqual(result["outcome"], "passed")
        self.assertFalse(result["releaseDurationGate"])
        self.assertEqual(result["scheduledRunCount"], 1)

    def test_manual_repeats_do_not_count(self):
        now, runs, records = self.fixture()
        for run in runs:
            run["event"] = "workflow_dispatch"
        self.assertEqual(soak.evaluate(runs, records, now)["outcome"], "unavailable")

    def test_failure_skip_and_missing_evidence_remain_failures(self):
        for cause in ("failure", "skipped", "missing", "outcome", "source"):
            now, runs, records = self.fixture(2)
            if cause in {"failure", "skipped"}:
                runs[-1]["conclusion"] = cause
            elif cause == "missing":
                del records[str(runs[-1]["id"])]
            elif cause == "outcome":
                records[str(runs[-1]["id"])]["requiredOutcomes"] = []
            else:
                records[str(runs[-1]["id"])]["githubSha"] = "wrong"
            self.assertEqual(soak.evaluate(runs, records, now)["outcome"], "failed", cause)

    def test_age_and_changed_pins_do_not_impose_a_release_wait(self):
        now, runs, records = self.fixture(2)
        records[str(runs[-1]["id"])]["pinsSha256"] = "c" * 64
        result = soak.evaluate(runs, records, now + datetime.timedelta(days=2))
        self.assertEqual(result["outcome"], "passed")
        self.assertEqual(result["runs"][-1]["ageSeconds"], 172800)
        self.assertFalse(result["releaseDurationGate"])

    def test_artifact_sha_run_event_and_attempt_must_match(self):
        for field in ("githubSha", "githubRunId", "githubRunAttempt", "githubEvent", "testerOutcome", "authentikCompatibilityMode", "testerProfile", "testerDefaultOutcome"):
            now, runs, records = self.fixture()
            records[str(runs[-1]["id"])][field] = "wrong"
            self.assertEqual(soak.evaluate(runs, records, now)["outcome"], "failed", field)

    def test_successful_rerun_preserves_prior_failure_and_matches_attempt(self):
        now, runs, records = self.fixture(2)
        runs[0]["conclusion"] = "failure"
        runs[-1]["run_attempt"] = 2
        records[str(runs[-1]["id"])]["githubRunAttempt"] = "2"
        result = soak.evaluate(runs, records, now)
        self.assertEqual(result["outcome"], "passed")
        self.assertEqual([row["outcome"] for row in result["runs"]], ["failed", "passed"])

    def test_malformed_artifact_hash_is_a_failure_not_an_exception(self):
        now, runs, records = self.fixture()
        records[str(runs[-1]["id"])]["pinsSha256"] = None
        self.assertEqual(soak.evaluate(runs, records, now)["outcome"], "failed")


if __name__ == "__main__":
    unittest.main()
