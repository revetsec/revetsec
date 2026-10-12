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

"""Exercise capture lifecycle without an IdP or Docker daemon."""

from contextlib import ExitStack, redirect_stdout
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "simplesamlphp_capture", ROOT / "interop/simplesamlphp/capture.py")
CAPTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAPTURE)


class SimpleSamlPhpCaptureTests(unittest.TestCase):
    def test_both_signing_modes_capture_while_stopped_name_is_still_reserved(self):
        reserved = set()
        started = []
        stopped = []
        captured = []

        def docker(args, **kwargs):
            self.assertEqual(args[0], "docker")
            if args[1] == "run":
                name = args[args.index("--name") + 1]
                if name in reserved:
                    raise subprocess.CalledProcessError(
                        125, args, stderr="docker: container name is already in use")
                reserved.add(name)
                started.append(name)
                return subprocess.CompletedProcess(args, 0, stdout="container-id\n")
            if args[1] == "port":
                return subprocess.CompletedProcess(args, 0, stdout="127.0.0.1:44443\n")
            if args[1] == "stop":
                stopped.append(args[2])
                # Model --rm removal still pending after docker stop returns.
                self.assertIn(args[2], reserved)
                return subprocess.CompletedProcess(args, 0, stdout=args[2] + "\n")
            self.fail(f"Unexpected Docker command: {args}")

        def capture(directory, port, label, response_signed):
            mode = ("'saml20.sign.response' => true" if response_signed
                    else "'saml20.sign.response' => false")
            self.assertIn(mode, (directory.parent / "saml20-sp-remote.php").read_text())
            captured.append((label, response_signed))
            return b"<Response/>"

        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            output = Path(temporary) / "output"
            stack.enter_context(patch.object(CAPTURE.subprocess, "run", side_effect=docker))
            for name in ("verify_image", "compile_generator", "wait_for_idp",
                         "assert_signed_request_validation", "save"):
                stack.enter_context(patch.object(CAPTURE, name))
            stack.enter_context(patch.object(
                CAPTURE, "generate_request", side_effect=lambda classes, directory: directory.mkdir()))
            stack.enter_context(patch.object(CAPTURE, "capture", side_effect=capture))
            stack.enter_context(patch("sys.argv", ["capture.py", "--output", str(output)]))
            with redirect_stdout(io.StringIO()):
                CAPTURE.main()
            self.assertTrue((output / "capture-manifest.json").is_file())

        self.assertEqual(captured, [("cbc-response-signed", True), ("cbc-assertion-signed", False)])
        self.assertEqual(len(started), 2)
        self.assertNotEqual(started[0], started[1])
        self.assertEqual(stopped, started)

    def test_startup_failure_reports_docker_stderr(self):
        error = subprocess.CalledProcessError(
            125, ["docker", "run"], stderr="docker: port allocation failed\n")
        with patch.object(CAPTURE.subprocess, "run", side_effect=error):
            with self.assertRaisesRegex(RuntimeError, "exit 125.*") as raised:
                CAPTURE.start_idp(Path("/tmp/capture-test"))
        self.assertIn("docker: port allocation failed", str(raised.exception))
        self.assertIs(raised.exception.__cause__, error)

    def test_non_loopback_port_is_rejected_and_container_stopped(self):
        results = [subprocess.CompletedProcess([], 0, stdout="container-id\n"),
                   subprocess.CompletedProcess([], 0, stdout="0.0.0.0:44443\n"),
                   subprocess.CompletedProcess([], 0, stdout="stopped\n")]
        with patch.object(CAPTURE.subprocess, "run", side_effect=results) as run:
            with self.assertRaisesRegex(RuntimeError, "not published on loopback"):
                CAPTURE.start_idp(Path("/tmp/capture-test"))
        command = run.call_args_list[0].args[0]
        name = command[command.index("--name") + 1]
        self.assertEqual(run.call_args_list[-1].args[0], ("docker", "stop", name))


if __name__ == "__main__":
    unittest.main()
