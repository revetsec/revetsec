#!/usr/bin/env python3
# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Exact-JAR public service outcomes and Java17 branches/Java21 exhaustive switches."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--core-jar', type=Path, required=True)
    parser.add_argument('--core-sha256', required=True)
    parser.add_argument('--consumer-release', type=int, choices=[17, 21], default=21)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    core = args.core_jar.resolve()
    result = {'status': 'RUNNING', 'coreJar': str(core), 'coreJarSha256': sha(core),
              'sourceRelease': args.consumer_release, 'coreSourceRelease': 17, 'checks': [], 'plants': [],
              'wholeScPub01Closed': False,
              'boundary': '120 genuine public service executions cover16 families/84 unique variants, including11 checked reauthentication modes; known time outage and permit-close withholding, UNKNOWN applied/absent, prewrite unavailable and eligible payloads. Java21+ has exhaustive switches plus11 preserved ordinary routes; Java17 uses explicit instanceof branches. Volatile fixture authority is synthetic; no trustedUTC/native/C or wholecase closure. No private result/proof construction.'}

    def save():
        (out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')

    def check(label, condition):
        assert not any(c['id'] == label for c in result['checks']), label
        result['checks'].append({'id': label, 'passed': bool(condition)})
        save()
        if not condition:
            raise AssertionError(label)

    def run(command):
        return subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=45)

    try:
        check('explicit-exact-core-artifact', sha(core) == args.core_sha256)
        manifest = json.loads((ROOT / 'planning/records/security/shared-clock-scp01-2026-10-29/ARTIFACT-PRESERVATION.json').read_text())
        dependencies = []
        for coordinate in ['org.jspecify:jspecify:1.0.1', 'com.google.code.findbugs:jsr305:3.0.2', 'com.google.errorprone:error_prone_annotations:2.50.0']:
            row = next(a for a in manifest['artifacts'] if a.get('coordinate') == coordinate)
            path = ROOT / row['frozen_path']
            check('pinned/' + coordinate, sha(path) == row['sha256'])
            dependencies.append(path)
        result['classpathArtifacts'] = {str(p): sha(p) for p in [core, *dependencies]}
        source = HERE / 'src/consumer/PublicResultSwitches.java'
        producer = ROOT / 'revetsec/verification/webauthn-reauthentication/src/consumer'
        java_sources = sorted((HERE / 'src').rglob('*.java')) + [producer / 'PublicProofCases.java', producer / 'SyntheticAuthenticator.java']
        source_inputs = [*java_sources, Path(__file__), HERE / 'README.md']
        source_text = source.read_text()
        result['sourceInputsSha256'] = {str(p.relative_to(ROOT)): sha(p) for p in source_inputs}
        (out / 'SOURCE').mkdir()
        for path in source_inputs:
            shutil.copy2(path, out / 'SOURCE' / path.name)
        families = re.findall(r'static @NonNull String route\(@NonNull (\w+) result\)', source_text)
        branches = re.findall(r'case (\w+)\.(\w+) ignored ->', source_text)
        check('sixteen-unique-explicit-switch-families', len(families) == len(set(families)) == source_text.count('return switch (result)') == 16)
        check('eighty-four-explicit-variant-arms', len(branches) == len(set(branches)) == 84)
        check('no-default-or-base-class-catchall', 'default' not in source_text and all(family in families for family, _ in branches))
        check('no-internal-api-or-access-bypass', not any(token in path.read_text() for path in java_sources for token in ['com.revetsec.internal', 'setAccessible', 'trySetAccessible', 'getDeclaredMethod(', 'newInstance(', 'Unsafe']))
        branches_source = HERE / 'src/consumer/PublicResultBranches.java'
        branch_arms = re.findall(r'if\(value instanceof (\w+)\.(\w+) ignored\)return', branches_source.read_text())
        check('java17-explicit-branches-name-the-same84-leaves', set(branch_arms) == set(branches) and len(branch_arms) == 84)
        classes = out / 'classes'
        classes.mkdir()
        cp = os.pathsep.join(map(str, [core, *dependencies]))
        selected_sources = java_sources if args.consumer_release == 21 else [path for path in java_sources if path.name not in {'PublicResultSwitches.java', 'PublicSwitchRouter.java'}]
        compile_command = [args.java_home / 'bin/javac', '--release', str(args.consumer_release), '-proc:none', '-Xlint:all', '-Werror', '-XDrawDiagnostics', '-cp', cp]
        compiled = run([*compile_command, '-d', classes, *selected_sources])
        (out / 'compile.log').write_text(compiled.stdout + compiled.stderr)
        check('strict-selected-release-public-consumer-compile', compiled.returncode == 0)
        classfiles = {str(p.relative_to(classes)): sha(p) for p in sorted(classes.rglob('*.class'))}
        check('no-core-classpath-shadowing', bool(classfiles) and all(name.startswith('consumer/') for name in classfiles))
        result['compiledClassfiles'] = classfiles
        result['javaVersion'] = run([args.java_home / 'bin/java', '-version']).stderr.strip()
        main_class = 'consumer.PublicResultSwitches' if args.consumer_release == 21 else 'consumer.PublicResultBranches'
        runtime = run([args.java_home / 'bin/java', '-Dconsumer.evidence.directory=' + str(out), '-cp', os.pathsep.join([str(classes), cp]), main_class, core, args.core_sha256])
        (out / 'runtime.stdout').write_text(runtime.stdout)
        (out / 'runtime.stderr').write_text(runtime.stderr)
        check('public-runtime-routes-and-all-permitted-shapes', runtime.returncode == 0)
        markers = dict(line.split(' ', 1) for line in runtime.stdout.splitlines())
        expected = {'PUBLIC_SERVICE_RUNTIME_CASES': '120', 'PUBLIC_SERVICE_UNIQUE_VARIANTS': '84', 'PUBLIC_SERVICE_RECONCILIATION_FAMILIES': '16', 'PUBLIC_SERVICE_UNKNOWN_FAMILIES': '16', 'PUBLIC_SERVICE_PREWRITE_UNAVAILABLE_FAMILIES': '16', 'PUBLIC_SERVICE_ELIGIBLE_FAMILIES': '16', 'PERMITTED_VARIANTS': '84', 'RUNTIME_RECONCILIATION_ROUTES': '33', 'CORE_ORIGIN_SHA256': args.core_sha256}
        expected.update({'SWITCH_FAMILIES': '16', 'PUBLIC_RUNTIME_ROUTES': '11'} if args.consumer_release == 21 else {'BRANCH_FAMILIES': '16'})
        check('exact-runtime-marker-set', len(markers) == len(runtime.stdout.splitlines()) == len(expected) + 1 and markers.keys() == expected.keys() | {'WA_FIXTURE_MAX_DRIFT_MILLIS'} and all(markers[key] == value for key, value in expected.items()))
        check('explicit-default-worker-fixture-drift-bound', 0 <= int(markers['WA_FIXTURE_MAX_DRIFT_MILLIS']) <= 3000)
        result['runtimeMarkers'] = markers
        case_rows = (out / 'public-service-cases.tsv').read_text().splitlines()[1:]
        count_rows = (out / 'public-service-counts.tsv').read_text().splitlines()[1:]
        check('exact-runtime-case-and-callback-evidence', len(case_rows) == 120 and len({tuple(row.split('\t')[:2]) for row in case_rows}) == 84 and len(count_rows) == 101 and len({tuple(row.split('\t')[:2]) for row in count_rows}) == 101)
        result['runtimeCaseEvidenceSha256'] = {name: sha(out / name) for name in ['public-service-cases.tsv', 'public-service-counts.tsv']}
        dependencies_report = run([args.java_home / 'bin/jdeps', '--multi-release', str(args.consumer_release), '--class-path', cp, '-verbose:class', classes])
        (out / 'jdeps.log').write_text(dependencies_report.stdout + dependencies_report.stderr)
        check('public-linkage-only-no-internal-imports', dependencies_report.returncode == 0 and 'com.revetsec.internal' not in dependencies_report.stdout)
        for family in families:
            directory = out / 'plants' / family
            (directory / 'src/consumer').mkdir(parents=True)
            selected_text = source_text if args.consumer_release == 21 else branches_source.read_text()
            marker = '            case ' + family + '.ReconciliationRequired ignored -> "' + family + '.ReconciliationRequired";\n' if args.consumer_release == 21 else '  if(value instanceof ' + family + '.ReconciliationRequired ignored)return "' + family + '.ReconciliationRequired";\n'
            check('unique-removable-reconciliation-arm/' + family, selected_text.count(marker) == 1)
            plant = directory / 'src/consumer' / ('PublicResultSwitches.java' if args.consumer_release == 21 else 'PublicResultBranches.java')
            plant.write_text(selected_text.replace(marker, ''))
            dest = directory / 'classes'
            dest.mkdir()
            plant_compile = [*compile_command[:-1], os.pathsep.join([str(classes), cp])]
            failed = run([*plant_compile, '-d', dest, plant])
            diagnostic = failed.stdout + failed.stderr
            (directory / 'compile.log').write_text(diagnostic)
            if args.consumer_release == 21:
                detected = failed.returncode != 0 and diagnostic.count('compiler.err.not.exhaustive') == 1 and re.search(r'(?m)^1 error\s*$', diagnostic) is not None and not re.search(r'compiler\.(err|warn)\.(?!not.exhaustive)', diagnostic)
                result['plants'].append({'family': family, 'removedVariant': 'ReconciliationRequired', 'sourceSha256': sha(plant), 'exit': failed.returncode, 'detectedForExhaustivenessOnly': bool(detected)})
            else:
                check('java17-branch-plant-is-valid-source/' + family, failed.returncode == 0)
                exercised = run([args.java_home / 'bin/java', '-cp', os.pathsep.join([str(dest), str(classes), cp]), main_class, core, args.core_sha256])
                (directory / 'runtime.log').write_text(exercised.stdout + exercised.stderr)
                detected = exercised.returncode != 0 and 'java.lang.AssertionError: Unreviewed public result leaf' in exercised.stderr
                result['plants'].append({'family': family, 'removedVariant': 'ReconciliationRequired', 'sourceSha256': sha(plant), 'compileExit': failed.returncode, 'runtimeExit': exercised.returncode, 'detectedForMissingRuntimeBranchOnly': bool(detected)})
            check('missing-variant-detected/' + family, detected)
        check('final-source-stable', all(sha(ROOT / path) == digest for path, digest in result['sourceInputsSha256'].items()))
        result['status'] = 'PASS'
    except Exception as failure:
        result['status'] = 'FAIL'
        result['failure'] = {'type': type(failure).__name__, 'message': str(failure)}
    save()
    print(json.dumps({'status': result['status'], 'checks': len(result['checks']), 'missingVariantPlants': len(result['plants']), 'wholeScPub01Closed': False}))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
