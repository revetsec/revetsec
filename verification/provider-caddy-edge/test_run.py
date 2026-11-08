# Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0.
"""Focused controls for provider-Caddy evidence stream framing."""
from pathlib import Path
from types import SimpleNamespace
import hashlib
import importlib.util
import unittest


SPEC = importlib.util.spec_from_file_location("provider_caddy_run", Path(__file__).with_name("run.py"))
RUN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUN)


class ProcessOutputReceiptTests(unittest.TestCase):
    def output(self, stdout, stderr):
        return SimpleNamespace(stdout=stdout, stderr=stderr)

    def test_stream_boundary_is_part_of_digest(self):
        left = RUN.process_output_receipt(self.output("ab", "c"))
        right = RUN.process_output_receipt(self.output("a", "bc"))
        self.assertNotEqual(left["sha256"], right["sha256"])

    def test_stderr_only_output_is_counted_and_hashed(self):
        receipt = RUN.process_output_receipt(self.output("", "caddy-started\n"))
        self.assertEqual(0, receipt["stdoutBytes"])
        self.assertEqual(14, receipt["stderrBytes"])
        self.assertNotEqual(hashlib.sha256(b"").hexdigest(), receipt["sha256"])

    def test_empty_streams_still_have_canonical_framing(self):
        receipt = RUN.process_output_receipt(self.output("", ""))
        self.assertEqual("revetsec-process-streams-v1-length-prefixed-utf8", receipt["framing"])
        self.assertNotEqual(hashlib.sha256(b"").hexdigest(), receipt["sha256"])


if __name__ == "__main__":
    unittest.main()
