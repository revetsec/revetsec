# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""CAP-11 pure source contracts: no database, driver lookup or network service.

Compile the actual private quota components with their frozen Pyranid/annotation
dependencies. The Java sentinel records and rejects every connection-provider
lookup; a connection can never be returned. SQL locking, fencing, restore and
reinventory belong to the separate native component/profile certificate.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
ARTIFACTS = ROOT / 'planning/records/security/shared-clock-scp01-2026-10-29/artifacts/third-party'
DEPENDENCIES = [
    ('com.pyranid__pyranid__4.7.0/pyranid-4.7.0.jar',
     'a9f142bb5e5a9de76668fb1ae1fede6a6dafae392196b551a2f965fbf19a226b'),
    ('org.jspecify__jspecify__1.0.1/jspecify-1.0.1.jar',
     '070d75f261fe4c5b8202508366715f7f2d4660f88c8ef7e6d3575e48c9683b66'),
    ('com.google.code.findbugs__jsr305__3.0.2/jsr305-3.0.2.jar',
     '766ad2a0783f2687962c8ad74ceecc38a28b9f72a2d085ee438b7813e928d0c7'),
    ('com.google.errorprone__error_prone_annotations__2.50.0/error_prone_annotations-2.50.0.jar',
     '4667724877f1d37a689202da191e23efa7657c62eef93ccdac406eccfe5cdd0a'),
]
SOURCES = ['PgScope', 'PgLocks', 'PgTransactions', 'PgCapacity',
           'PgPrimitives', 'PgQuotaControl', 'PgCapacityChecks', 'ClosedQuotaConstructorChecks']


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ClosedQuotaContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.java_home = Path(os.environ.get('CAP11_JAVA_HOME',
            '/Users/agents/Java/amazon-corretto-21.jdk/Contents/Home')).resolve()
        cls.source_root = Path(os.environ.get('CAP11_SOURCE_ROOT', HERE / 'src/verification/sharedclock')).resolve()
        output = os.environ.get('CAP11_OUTPUT')
        cls.output = Path(output).resolve() if output else Path(tempfile.mkdtemp(prefix='revetsec-cap11-pure-')).resolve()
        if output:
            cls.output.mkdir(parents=True, exist_ok=False)
        else:
            cls.addClassCleanup(shutil.rmtree, cls.output, ignore_errors=True)
        cls.classes = cls.output / 'classes'
        cls.classes.mkdir()
        cls.receipt = {
            'scope': 'CAP-11 local constructors/preflight only; no SQL or trusted-time/profile claim',
            'qualification': False,
            'coreJarUsed': False,
            'sourceRoot': str(cls.source_root),
            'javaHome': str(cls.java_home),
            'dependencies': [],
            'sources': {},
            'processes': [],
        }
        cls.addClassCleanup(cls.write_receipt)
        dependencies = []
        for relative, expected in DEPENDENCIES:
            path = ARTIFACTS / relative
            actual = digest(path)
            if actual != expected:
                raise AssertionError('CAP11-frozen-dependency-sha256')
            dependencies.append(path)
            cls.receipt['dependencies'].append({'path': str(path), 'sha256': actual})
        sources = [cls.source_root / (name + '.java') for name in SOURCES]
        cls.receipt['sources'] = {str(path): digest(path) for path in sources}
        cls.classpath = os.pathsep.join(map(str, [cls.classes, *dependencies]))
        version = subprocess.run([str(cls.java_home / 'bin/java'), '-version'], capture_output=True, text=True, timeout=30)
        cls.receipt['javaVersion'] = version.stdout + version.stderr
        command = [str(cls.java_home / 'bin/javac'), '--release', '17', '-proc:none',
            '-Xlint:all,-serial', '-Werror', '-cp', os.pathsep.join(map(str, dependencies)),
            '-d', str(cls.classes), *map(str, sources)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        (cls.output / 'compile.stdout').write_text(result.stdout)
        (cls.output / 'compile.stderr').write_text(result.stderr)
        cls.receipt['compile'] = {'command': command, 'exit': result.returncode,
            'lint': 'all,-serial; existing private SQLException subtype has no serialVersionUID'}
        if result.returncode or result.stdout or result.stderr:
            raise AssertionError('CAP11-warning-fatal-current-source-compile: ' + result.stderr)

    @classmethod
    def write_receipt(cls):
        cls.receipt['classfiles'] = {str(path.relative_to(cls.output)): digest(path)
            for path in sorted(cls.classes.rglob('*.class'))}
        cls.receipt['sourcesUnchangedDuringRun'] = all(
            digest(Path(path)) == expected for path, expected in cls.receipt['sources'].items())
        (cls.output / 'RESULT.json').write_text(json.dumps(cls.receipt, indent=2) + '\n')

    def run_main(self, name, *arguments):
        command = [str(self.java_home / 'bin/java'), '-ea', '-cp', self.classpath,
            'verification.sharedclock.' + name, *arguments]
        # Remove inherited deployment coordinates even though the subject provider
        # cannot return a connection. PgCapacityChecks MUST receive "pure".
        environment = {key: value for key, value in os.environ.items()
            if key not in {'DB_URL', 'DB_USER', 'DB_PASSWORD', 'PGHOST', 'PGPORT', 'PGDATABASE'}}
        result = subprocess.run(command, capture_output=True, text=True, timeout=40, env=environment)
        (self.output / (name + '.stdout')).write_text(result.stdout)
        (self.output / (name + '.stderr')).write_text(result.stderr)
        assertions = [line[5:] for line in result.stdout.splitlines() if line.startswith('PASS ')]
        self.receipt['processes'].append({'class': name, 'arguments': list(arguments),
            'command': command, 'exit': result.returncode, 'assertions': assertions})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        self.assertTrue(assertions)
        self.assertEqual(len(assertions), len(set(assertions)))
        return result.stdout, assertions

    def test_closed_quota_constructors_and_no_io_preflight(self):
        stdout, assertions = self.run_main('ClosedQuotaConstructorChecks')
        total = [line for line in stdout.splitlines() if line.startswith('TOTAL ')]
        self.assertEqual(total, ['TOTAL ' + str(len(assertions))])
        for family in ['TOTP', 'ISSUER', 'WEBAUTHN']:
            for operation in ['bootstrap', 'reallocate']:
                prefix = 'CAP11/service/' + operation + '/' + family
                self.assertIn(prefix + '/canonical-positive-denied-provider', assertions)
                self.assertIn(prefix + '/same-generation/equal-content/no-provider-lookup', assertions)
                self.assertIn(prefix + '/wrong-family-byte-shape/no-provider-lookup', assertions)

    def test_existing_capacity_arithmetic_and_copy_contracts_pure_only(self):
        _, assertions = self.run_main('PgCapacityChecks', 'pure')
        self.assertEqual(len(assertions), 11)
        self.assertIn('capacity-quota-remainder-exact', assertions)
        self.assertIn('capacity-allocation-defensive-copy', assertions)
        self.assertIn('capacity-hard-limit-overflow-refusals', assertions)


if __name__ == '__main__':
    unittest.main()
