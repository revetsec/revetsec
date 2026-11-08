# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Actual recipe lock helpers; source/recorded-SQL subset of PG-03, not native C."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


class ActualLockHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.jar = Path(os.environ['PG_QUALIFICATION_CORE_JAR']).resolve()
        cls.expected = os.environ['PG_QUALIFICATION_CORE_SHA256']
        cls.java_home = Path(os.environ['PG_QUALIFICATION_JAVA_HOME']).resolve()
        if hashlib.sha256(cls.jar.read_bytes()).hexdigest() != cls.expected:
            raise AssertionError('Explicit test core SHA mismatch')
        cls.runtime = Path(tempfile.mkdtemp(prefix='revetsec-actual-locks-'))
        cls.addClassCleanup(shutil.rmtree, cls.runtime)
        manifest = json.loads((ROOT / 'planning/records/security/shared-clock-scp01-2026-10-29/ARTIFACT-PRESERVATION.json').read_text())
        dependencies = []
        for coordinate in ['com.pyranid:pyranid:4.7.0', 'org.postgresql:postgresql:42.7.14', 'org.jspecify:jspecify:1.0.1', 'com.google.code.findbugs:jsr305:3.0.2', 'com.google.errorprone:error_prone_annotations:2.50.0']:
            row = next(r for r in manifest['artifacts'] if r.get('coordinate') == coordinate)
            path = ROOT / row['frozen_path']
            if hashlib.sha256(path.read_bytes()).hexdigest() != row['sha256']:
                raise AssertionError('Frozen dependency changed')
            dependencies.append(path)
        source = Path(os.environ.get('PG_LOCK_HELPER_SOURCE', str(ROOT / 'revetsec/examples/postgresql-pending-store/src/main/java/example/pending'))).resolve()
        sources = [*sorted(source.glob('*Pg*.java')), *[source / name for name in ['PostgresqlTotpStore.java', 'PostgresqlWebAuthnStore.java', 'PostgresqlIssuerStore.java', 'PostgresqlPyranidDataSource.java']], HERE / 'native/example/pending/ActualLockHelperChecks.java']
        auditor = ROOT / 'revetsec/verification/examples/NullabilityAudit.java'
        classes = cls.runtime / 'classes'
        classes.mkdir()
        cp = os.pathsep.join(map(str, [cls.jar, *dependencies]))
        compiled = subprocess.run([str(cls.java_home / 'bin/javac'), '--release', '17', '-proc:none', '-Xlint:all', '-Werror', '-cp', cp, '-d', str(classes), *map(str, sources), str(auditor)], text=True, capture_output=True, timeout=45)
        if compiled.returncode != 0 or compiled.stderr:
            raise AssertionError('Actual helper strict compilation failed: ' + compiled.stderr)
        cp = os.pathsep.join([str(classes), cp])
        source_list = cls.runtime / 'sources.txt'
        source_list.write_text('\n'.join(map(str, sources)) + '\n')
        cp_file = cls.runtime / 'classpath.txt'
        cp_file.write_text(cp)
        audit_file = cls.runtime / 'NULLABILITY.json'
        audit = subprocess.run([str(cls.java_home / 'bin/java'), '-cp', cp, 'NullabilityAudit', str(source_list), str(cp_file), str(audit_file)], text=True, capture_output=True, timeout=30)
        audited = json.loads(audit_file.read_text()) if audit_file.exists() else {}
        if audit.returncode != 0 or audited.get('missing', [True]) or audited.get('attribution_errors', [True]):
            raise AssertionError('Actual helper source nullability failed: ' + json.dumps(audited))
        output = Path(os.environ['PG_LOCK_HELPER_OUTPUT']).resolve()
        output.mkdir(parents=True, exist_ok=False)
        (output / 'compile.log').write_text(compiled.stdout + compiled.stderr)
        (output / 'NULLABILITY.json').write_text(json.dumps(audited, indent=2) + '\n')
        shutil.copytree(classes, output / 'classes')
        cls.runs = {}
        for family in ['TOTP', 'WEBAUTHN', 'ISSUER']:
            result = subprocess.run([str(cls.java_home / 'bin/java'), '-cp', cp, 'example.pending.ActualLockHelperChecks', family], text=True, capture_output=True, timeout=30)
            cls.runs[family] = result
            (output / (family + '.stdout')).write_text(result.stdout)
            (output / (family + '.stderr')).write_text(result.stderr)
        receipt = {'coreJarSha256': cls.expected, 'javaHome': str(cls.java_home), 'sourceInputsSha256': {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in [*sources, auditor, Path(__file__)]}, 'artifactInputsSha256': {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in [cls.jar, *dependencies]}, 'compiledClassfiles': {str(p.relative_to(classes)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(classes.rglob('*.class'))}, 'nullability': audited, 'runs': {family: {'exitCode': value.returncode, 'assertions': [line[5:] for line in value.stdout.splitlines() if line.startswith('PASS ')], 'stderr': value.stderr} for family, value in cls.runs.items()}, 'scope': 'Actual helper source and requested SQL recording. No actual database locks, multi-JVM deadlock or full-key/version collision proof.'}
        (output / 'RESULT.json').write_text(json.dumps(receipt, indent=2) + '\n')

    def assert_matrix(self, family):
        result = self.runs[family]
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual('', result.stderr)
        labels = [line[5:] for line in result.stdout.splitlines() if line.startswith('PASS ')]
        self.assertEqual(1501, len(labels))
        self.assertEqual(len(labels), len(set(labels)))
        self.assertIn('SUMMARY ' + family + ' 1501', result.stdout.splitlines())

    def test_totp_actual_lock_helper_matrix(self):
        self.assert_matrix('TOTP')

    def test_webauthn_actual_lock_helper_matrix(self):
        self.assert_matrix('WEBAUTHN')

    def test_issuer_actual_lock_helper_matrix(self):
        self.assert_matrix('ISSUER')

    def test_independent_exact_scope_domain_and_ASCII_hash_grammar(self):
        cells = 0
        variants = {}
        for family, result in self.runs.items():
            for line in result.stdout.splitlines():
                if not line.startswith('HASH\t'):
                    continue
                _, implementation, domain_family, namespace64, key64, first, second, entity = line.split('\t')
                self.assertEqual(family, implementation)
                namespace = base64.b64decode(namespace64)
                key = base64.b64decode(key64)
                domain = domain_family.encode('ascii')
                fields = struct.pack('>I', len(domain)) + domain + struct.pack('>I', len(namespace)) + namespace
                admission = hashlib.sha256(b'revetsec/pg-admission/v1\x00' + fields).digest()
                record = hashlib.sha256(b'revetsec/pg-entity/v1\x00' + fields + struct.pack('>I', len(key)) + key).digest()
                expected = (*struct.unpack('>ii', admission[:8]), struct.unpack('>q', record[:8])[0])
                self.assertEqual(expected, (int(first), int(second), int(entity)))
                identity = (domain_family, namespace64, key64)
                self.assertEqual(variants.setdefault(identity, expected), expected)
                cells += 1
        self.assertEqual(378, cells)
        self.assertEqual(126, len(variants))


if __name__ == '__main__':
    unittest.main()
