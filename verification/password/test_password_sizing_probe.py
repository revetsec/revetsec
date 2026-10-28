"""Exercise the Java 17 password sizing probe against compiled core classes."""

import csv
import io
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
PROBE = Path(__file__).with_name("PasswordSizingProbe.java")
SUMMARY = re.compile(
    r"^completed=(?P<completed>\d+) work_capacity=(?P<capacity>\d+) "
    r"measured_wall_ms=(?P<wall>[0-9.]+) completed_per_s=(?P<completed_rate>[0-9.]+) "
    r"attempted_per_s=(?P<attempted_rate>[0-9.]+) p50_ms=(?P<p50>[0-9.]+) "
    r"p95_ms=(?P<p95>[0-9.]+) p99_ms=(?P<p99>[0-9.]+)$",
    re.M,
)


class PasswordSizingProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.core_classes = ROOT / "target/classes"
        if not (cls.core_classes / "com/revetsec/password/PasswordHasher.class").is_file():
            raise AssertionError("Compile core before running password sizing probe tests")
        java_home = os.environ.get("JAVA_HOME")
        cls.java = str(Path(java_home) / "bin/java") if java_home else shutil.which("java")
        javac = str(Path(java_home) / "bin/javac") if java_home else shutil.which("javac")
        if not cls.java or not javac:
            raise AssertionError("A Java 17-or-newer JDK is required")
        repository = Path.home() / ".m2/repository"
        annotations = [
            repository / "org/jspecify/jspecify/1.0.1/jspecify-1.0.1.jar",
            repository / "com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar",
        ]
        if any(not path.is_file() for path in annotations):
            raise AssertionError("Build core first so the annotation jars are present in the local Maven repository")
        temporary = tempfile.TemporaryDirectory(prefix="revetsec-password-sizing-test-")
        cls.addClassCleanup(temporary.cleanup)
        cls.classes = Path(temporary.name)
        result = subprocess.run(
            [javac, "--release", "17", "-Xlint:all", "-Werror", "-cp",
             os.pathsep.join(str(path) for path in [cls.core_classes, *annotations]),
             "-d", str(cls.classes), str(PROBE)],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            raise AssertionError("Warning-fatal Java 17 probe compilation failed:\n" + result.stderr)

    @classmethod
    def run_probe(cls, *arguments):
        return subprocess.run(
            [cls.java, "-Xms128m", "-Xmx256m", "-cp",
             os.pathsep.join((str(cls.core_classes), str(cls.classes))),
             "PasswordSizingProbe", *arguments],
            capture_output=True, text=True, timeout=60,
        )

    def assert_measurement(self, result, workers, rounds):
        self.assertEqual(0, result.returncode, result.stderr)
        reader = csv.DictReader(io.StringIO(result.stdout))
        self.assertEqual(["round", "worker", "elapsed_ms", "outcome"], reader.fieldnames)
        rows = list(reader)
        attempts = workers * rounds
        self.assertEqual(attempts, len(rows))
        self.assertEqual(
            {(round_number, worker) for round_number in range(1, rounds + 1)
             for worker in range(workers)},
            {(int(row["round"]), int(row["worker"])) for row in rows},
        )
        self.assertTrue(all(float(row["elapsed_ms"]) >= 0 for row in rows))
        outcomes = [row["outcome"] for row in rows]
        self.assertTrue(set(outcomes) <= {"DONE", "WORK_CAPACITY"})

        match = SUMMARY.search(result.stderr)
        self.assertIsNotNone(match, result.stderr)
        summary = {key: float(value) for key, value in match.groupdict().items()}
        completed = outcomes.count("DONE")
        capacity = outcomes.count("WORK_CAPACITY")
        self.assertEqual(completed, int(summary["completed"]))
        self.assertEqual(capacity, int(summary["capacity"]))
        self.assertEqual(attempts, completed + capacity)
        self.assertGreater(summary["wall"], 0)
        self.assertTrue(all(math.isfinite(value) for value in summary.values()))
        for name, count in (("completed_rate", completed), ("attempted_rate", attempts)):
            expected = count / (summary["wall"] / 1_000)
            self.assertAlmostEqual(expected, summary[name], delta=max(0.05, expected * 0.005))
        completed_latencies = sorted(float(row["elapsed_ms"]) for row in rows if row["outcome"] == "DONE")
        for name, fraction in (("p50", 0.50), ("p95", 0.95), ("p99", 0.99)):
            expected = completed_latencies[math.ceil(fraction * len(completed_latencies)) - 1]
            self.assertAlmostEqual(expected, summary[name], delta=0.002)
        return completed, capacity

    def test_steady_state_summary_and_csv_agree(self):
        result = self.run_probe("argon2-hash", "19456", "2", "1", "1", "1", "2")
        self.assertEqual((2, 0), self.assert_measurement(result, workers=1, rounds=2))

    def test_overload_counts_and_throughput_include_refusals(self):
        result = self.run_probe("argon2-hash", "19456", "2", "1", "1", "8", "3")
        completed, capacity = self.assert_measurement(result, workers=8, rounds=3)
        self.assertGreater(completed, 0)
        self.assertGreater(capacity, 0)

    def test_invalid_profile_fails_before_csv_output(self):
        result = self.run_probe("argon2-hash", "1", "2", "1", "1", "1", "1")
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn("round,worker,elapsed_ms,outcome", result.stdout)


if __name__ == "__main__":
    unittest.main()
