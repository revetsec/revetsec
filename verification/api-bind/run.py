#!/usr/bin/env python3
# Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0.
"""Exact-JAR API-BIND positive, before/after and cross-role compile verification."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

HERE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--current-jar', type=Path, required=True)
    parser.add_argument('--baseline-jar', type=Path, required=True)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if not args.output.is_absolute() or output.exists() or output == HERE or HERE in output.parents:
        parser.error('--output must be a new absolute directory outside fixture sources')
    version = subprocess.run([str(args.java_home/'bin/javac'), '-version'],
            capture_output=True, text=True, timeout=10)
    match = re.search(r'javac (17|21|27)(?:[. ]|$)', version.stdout + version.stderr)
    if version.returncode or not match:
        parser.error('Expected JDK 17, 21 or 27')

    current = args.current_jar.resolve()
    baseline = args.baseline_jar.resolve()
    output.mkdir(parents=True, mode=0o700)
    result = {
        'schema': 'api-bind-verification-v1',
        'status': 'RUNNING',
        'jdk': int(match.group(1)),
        'artifacts': {
            'current': {'path': str(current), 'sha256': digest(current)},
            'baseline': {'path': str(baseline), 'sha256': digest(baseline)}},
        'sourceSha256': {str(path.relative_to(HERE)): digest(path)
            for path in sorted(HERE.rglob('*')) if path.is_file()},
        'checks': []}

    def run(label, command, expected):
        completed = subprocess.run(list(map(str, command)), capture_output=True, text=True,
                timeout=45)
        log = output/(label + '.log')
        log.write_text(completed.stdout + completed.stderr)
        passed = (completed.returncode == expected)
        result['checks'].append({'id': label, 'returncode': completed.returncode,
            'expectedReturncode': expected, 'passed': passed, 'log': str(log)})
        if not passed:
            raise AssertionError(label)

    try:
        classes = output/'classes'
        classes.mkdir()
        javac = args.java_home/'bin/javac'
        java = args.java_home/'bin/java'
        common = [javac, '--release', '17', '-proc:none', '-Xlint:all', '-Werror']
        positive = HERE/'src/consumer/PositiveBindings.java'
        run('current-positive-compile', [*common, '-cp', current, '-d', classes, positive], 0)
        run('current-positive-runtime', [java, '-cp', os.pathsep.join([str(classes), str(current)]),
                'consumer.PositiveBindings', current, baseline], 0)

        legacy = HERE/'negative/LegacyStringBindings.java'
        baseline_classes = output/'baseline-classes'
        baseline_classes.mkdir()
        run('baseline-legacy-string-compile', [*common, '-cp', baseline,
                '-d', baseline_classes, legacy], 0)
        for source in sorted((HERE/'negative').glob('*.java')):
            negative_classes = output/('negative-' + source.stem)
            negative_classes.mkdir()
            run('current-negative-' + source.stem, [*common, '-XDrawDiagnostics',
                    '-cp', current, '-d', negative_classes, source], 1)

        result['status'] = 'PASS'
        result['failingBeforeRegression'] = (
            'LegacyStringBindings compiles against the exact pre-API-BIND baseline and fails '
            'against the exact current typed JAR.')
        result['compatibilityCaveat'] = (
            'Well-formed OAuth/OIDC pending bindings over 65,536 Java UTF-16 code units that '
            'were accepted by sufficiently provisioned in-memory or custom stores are no '
            'longer accepted. Expire, clear or rotate only affected live pending/session '
            'correlation; no account, credential or reference-PostgreSQL schema/key/codec '
            'migration follows.')
    except Exception as failure:
        result['status'] = 'FAIL'
        result['failure'] = {'type': type(failure).__name__, 'message': str(failure)}
    (output/'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'checks': len(result['checks'])}))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
