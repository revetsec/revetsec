# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Actual actor-origin checks; caller supplies exact current artifact and JDK."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SPEC = importlib.util.spec_from_file_location('pg_qualification_runner', HERE / 'run_postgres.py')
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class CoreSelectionTests(unittest.TestCase):
    def setUp(self):
        self.runtime = Path(tempfile.mkdtemp(prefix='revetsec-pg-selection-'))
        self.addCleanup(shutil.rmtree, self.runtime)
        self.jar = self.runtime / 'selected.jar'
        self.jar.write_bytes(b'Only the byte-identity selector is under test here.')
        self.expected = hashlib.sha256(self.jar.read_bytes()).hexdigest()

    def test_explicit_pair_binds_exact_file_bytes(self):
        self.assertEqual((self.jar.resolve(), self.expected), RUNNER.select_core(self.jar, self.expected))

    def test_default_retains_exact_legacy_origin(self):
        selected, expected = RUNNER.select_core(None, None)
        self.assertEqual(RUNNER.CORE.resolve(), selected)
        self.assertEqual(RUNNER.LEGACY_CORE_SHA256, expected)

    def test_path_without_hash_is_not_an_implicit_acceptance(self):
        with self.assertRaisesRegex(ValueError, 'supplied together'):
            RUNNER.select_core(self.jar, None)

    def test_hash_without_path_is_not_an_implicit_selection(self):
        with self.assertRaisesRegex(ValueError, 'supplied together'):
            RUNNER.select_core(None, self.expected)

    def test_mismatched_digest_refuses(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            RUNNER.select_core(self.jar, '0' * 64)

    def test_noncanonical_digest_refuses(self):
        for value in ['a' * 63, 'g' * 64, self.expected.upper(), ' ' + self.expected]:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'lowercase SHA-256'):
                RUNNER.select_core(self.jar, value)

    def test_missing_file_refuses(self):
        with self.assertRaises(OSError):
            RUNNER.select_core(self.runtime / 'absent.jar', self.expected)

    def test_cli_mismatch_refuses_before_output_or_native_resources(self):
        output = self.runtime / 'must-not-exist'
        result = subprocess.run([os.sys.executable, str(HERE / 'run_postgres.py'), '--output', str(output), '--java-home', str(self.runtime / 'no-jdk'), '--core-jar', str(self.jar), '--core-sha256', '0' * 64], text=True, capture_output=True, timeout=10)
        self.assertEqual(2, result.returncode)
        self.assertIn('Selected core SHA-256 mismatch', result.stderr)
        self.assertEqual('', result.stdout)
        self.assertFalse(output.exists())


class ActorOriginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.jar = Path(os.environ['PG_QUALIFICATION_CORE_JAR']).resolve()
        cls.expected = os.environ['PG_QUALIFICATION_CORE_SHA256']
        cls.java_home = Path(os.environ['PG_QUALIFICATION_JAVA_HOME']).resolve()
        if hashlib.sha256(cls.jar.read_bytes()).hexdigest() != cls.expected:
            raise AssertionError('Explicit test core SHA mismatch')
        cls.runtime = Path(tempfile.mkdtemp(prefix='revetsec-pg-origin-'))
        cls.addClassCleanup(shutil.rmtree, cls.runtime)
        manifest = json.loads((ROOT / 'planning/records/security/shared-clock-scp01-2026-10-29/ARTIFACT-PRESERVATION.json').read_text())
        cls.dependencies = []
        for coordinate in ['com.pyranid:pyranid:4.7.0', 'org.postgresql:postgresql:42.7.14', 'org.jspecify:jspecify:1.0.1', 'com.google.code.findbugs:jsr305:3.0.2', 'com.google.errorprone:error_prone_annotations:2.50.0']:
            row = next(r for r in manifest['artifacts'] if r.get('coordinate') == coordinate)
            path = ROOT / row['frozen_path']
            if hashlib.sha256(path.read_bytes()).hexdigest() != row['sha256']:
                raise AssertionError('Frozen dependency changed')
            cls.dependencies.append(path)
        source = ROOT / 'revetsec/examples/postgresql-pending-store/src/main/java/example/pending'
        sources = [*sorted(source.glob('*Pg*.java')), *[source / name for name in ['PostgresqlTotpStore.java', 'PostgresqlWebAuthnStore.java', 'PostgresqlIssuerStore.java', 'PostgresqlPyranidDataSource.java']], *sorted((HERE / 'native').rglob('*.java'))]
        classes = cls.runtime / 'classes'
        classes.mkdir()
        cp = os.pathsep.join(map(str, [cls.jar, *cls.dependencies]))
        compiled = subprocess.run([str(cls.java_home / 'bin/javac'), '--release', '17', '-proc:none', '-Xlint:all', '-Werror', '-cp', cp, '-d', str(classes), *map(str, sources)], text=True, capture_output=True, timeout=45)
        if compiled.returncode != 0 or compiled.stderr:
            raise AssertionError('Actual actor strict compilation failed: ' + compiled.stderr)
        cls.classes = classes

    def actor(self, jar, expected):
        env = dict(os.environ)
        env.pop('REVETSEC_QUALIFICATION_CORE_SHA256', None)
        if expected is not None:
            env['REVETSEC_QUALIFICATION_CORE_SHA256'] = expected
        cp = os.pathsep.join(map(str, [self.classes, jar, *self.dependencies]))
        return subprocess.run([str(self.java_home / 'bin/java'), '-cp', cp, 'example.pending.NativeContentionActor', 'keys', 'TOTP', 'origin-regression'], env=env, text=True, capture_output=True, timeout=15)

    def test_selected_current_core_reaches_structural_key_preparation(self):
        result = self.actor(self.jar, self.expected)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual('', result.stderr)
        rows = result.stdout.splitlines()
        self.assertEqual(1, sum(row.startswith('ROOT\t') for row in rows))
        self.assertEqual(16, sum(row.startswith('DISTINCT\t') for row in rows))
        self.assertEqual(16, sum(row.startswith('COLLISION\t') for row in rows))

    def test_wrong_selected_core_never_prepares_keys(self):
        result = self.actor(self.jar, '0' * 64)
        self.assertEqual(1, result.returncode)
        self.assertEqual('', result.stdout)
        self.assertIn('STRUCTURAL_ACTOR_FAILED START IllegalStateException', result.stderr)

    def test_missing_hash_retains_legacy_artifact_binding(self):
        result = self.actor(self.jar, None)
        self.assertEqual(1, result.returncode)
        self.assertEqual('', result.stdout)

    def test_legacy_origin_still_accepts_original_default(self):
        jar = ROOT / 'planning/records/security/shared-clock-scp09-2026-10-30/candidate/core/revetsec-1.0.0.jar'
        result = self.actor(jar, None)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(result.stdout.startswith('ROOT\t'))


if __name__ == '__main__':
    unittest.main()
