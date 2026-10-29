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

"""Readiness and safe startup-failure diagnostics without external processes."""
import importlib.util
import json
from pathlib import Path
import ssl
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, call, patch
import urllib.error


runner_spec = importlib.util.spec_from_file_location("scim_startup_runner", Path(__file__).with_name("run.py"))
runner = importlib.util.module_from_spec(runner_spec)
runner_spec.loader.exec_module(runner)


def response(status=200):
    result = MagicMock()
    result.__enter__.return_value = SimpleNamespace(status=status)
    return result


def untrusted_certificate():
    return urllib.error.URLError(ssl.SSLCertVerificationError(1, "synthetic private CA is untrusted"))


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.states = self.enterContext(patch.object(runner, "container_states", return_value=[
            ("application", {"Status": "running"}), ("edge", {"Status": "running"})]))
        self.urlopen = self.enterContext(patch.object(runner.urllib.request, "urlopen"))
        self.sleep = self.enterContext(patch.object(runner.time, "sleep"))
        self.monotonic = self.enterContext(patch.object(runner.time, "monotonic", return_value=0))
        self.scoped_context = object()
        self.default_context = object()
        self.contexts = self.enterContext(patch.object(runner.ssl, "create_default_context",
                                                     side_effect=[self.scoped_context, self.default_context]))

    def wait(self):
        runner.wait_ready("https://localhost:1234/scim/v2", Path("disposable-ca.crt"), "synthetic-token",
                          docker="docker", containers=["application", "edge"])

    def test_exited_application_fails_without_an_http_request_or_sleep(self):
        self.states.return_value = [("application", {"Status": "exited", "ExitCode": 1}),
                                    ("edge", {"Status": "running"})]
        with self.assertRaisesRegex(RuntimeError, "exited before readiness"):
            self.wait()
        self.urlopen.assert_not_called()
        self.sleep.assert_not_called()

    def test_scoped_trust_requires_an_actual_default_trust_rejection(self):
        self.urlopen.side_effect = [response(), untrusted_certificate()]
        self.wait()
        self.contexts.assert_has_calls([call(cafile="disposable-ca.crt"), call()])
        scoped, default = self.urlopen.call_args_list
        self.assertEqual(scoped.args[0].full_url, "https://localhost:1234/scim/v2/ServiceProviderConfig")
        self.assertEqual(scoped.args[0].get_header("Authorization"), "Bearer synthetic-token")
        self.assertIs(scoped.kwargs["context"], self.scoped_context)
        self.assertIs(default.kwargs["context"], self.default_context)
        self.assertIs(scoped.args[0], default.args[0])
        self.sleep.assert_not_called()

    def test_private_ca_accepted_by_default_trust_fails_qualification(self):
        self.urlopen.side_effect = [response(), response()]
        with self.assertRaisesRegex(RuntimeError, "private CA unexpectedly trusted"):
            self.wait()
        self.sleep.assert_not_called()

    def test_default_trust_connection_failure_cannot_count_as_certificate_rejection(self):
        self.urlopen.side_effect = [response(), urllib.error.URLError(ConnectionRefusedError())]
        with self.assertRaisesRegex(RuntimeError, "reason other than certificate validation"):
            self.wait()
        self.sleep.assert_not_called()

    def test_transient_http_503_retries_then_checks_both_trust_controls(self):
        self.urlopen.side_effect = [urllib.error.HTTPError("https://localhost", 503, "starting", {}, None),
                                   response(), untrusted_certificate()]
        self.wait()
        self.assertEqual(self.states.call_count, 2)
        self.assertEqual(self.urlopen.call_count, 3)
        self.sleep.assert_called_once_with(0.1)

    def test_unready_running_application_stops_at_the_deadline(self):
        self.monotonic.side_effect = [0, 60]
        self.urlopen.side_effect = urllib.error.URLError(ConnectionRefusedError())
        with self.assertRaisesRegex(RuntimeError, "within 60 seconds"):
            self.wait()
        self.sleep.assert_not_called()


class StartupDiagnosticsTests(unittest.TestCase):
    def test_state_inspection_reads_only_state_and_preserves_container_identity(self):
        states = [{"Status": "exited", "ExitCode": 1}, {"Status": "running", "ExitCode": 0}]
        with patch.object(runner, "checked", return_value=SimpleNamespace(
                stdout="\n".join(json.dumps(state) for state in states))) as checked:
            self.assertEqual(runner.container_states("docker", ["application", "edge"]),
                             list(zip(["application", "edge"], states)))
        checked.assert_called_once_with("docker", "inspect", "--format", "{{json .State}}",
                                        "application", "edge", timeout=10)

    def test_incomplete_state_inspection_is_an_explicit_failure(self):
        with patch.object(runner, "checked", return_value=SimpleNamespace(stdout='{"Status":"running"}')):
            with self.assertRaisesRegex(RuntimeError, "lifecycle state is incomplete"):
                runner.container_states("docker", ["application", "edge"])

    def test_diagnostics_cap_and_redact_logs_and_exclude_other_state_fields(self):
        token = "synthetic-secret-bearer-token"
        state = {"Status": "exited", "ExitCode": 1, "OOMKilled": False,
                 "Error": "private-state-error", "Pid": 1234, "StartedAt": "private-state-timestamp"}
        with patch.object(runner, "checked", side_effect=[
                SimpleNamespace(stdout=json.dumps(state)),
                SimpleNamespace(stdout="old logs " * 2000 + "\nUnsupportedClassVersionError " + token,
                                stderr="\n" + token)]) as checked:
            diagnostics = runner.startup_diagnostics("docker", ["application"], [token, None, ""])
        self.assertEqual(len(diagnostics), 1)
        diagnostic = diagnostics[0]
        self.assertEqual(set(diagnostic), {"container", "status", "exitCode", "oomKilled", "logExcerpt"})
        self.assertEqual({key: value for key, value in diagnostic.items() if key != "logExcerpt"},
                         {"container": "application", "status": "exited", "exitCode": 1, "oomKilled": False})
        self.assertLessEqual(len(diagnostic["logExcerpt"]), 12000)
        self.assertIn("UnsupportedClassVersionError", diagnostic["logExcerpt"])
        self.assertEqual(diagnostic["logExcerpt"].count("[redacted]"), 2)
        serialized = json.dumps(diagnostics)
        for private in (token, "private-state-error", "private-state-timestamp"):
            self.assertNotIn(private, serialized)
        checked.assert_has_calls([
            call("docker", "inspect", "--format", "{{json .State}}", "application", timeout=10),
            call("docker", "logs", "--tail", "40", "application", timeout=10)])


if __name__ == "__main__":
    unittest.main()
