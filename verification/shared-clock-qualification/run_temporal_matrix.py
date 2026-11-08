#!/usr/bin/env python3
# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Owned actual-adapter temporal matrix, with scripted UTC and opaque structural values."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import queue
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import traceback

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
EXAMPLE = ROOT / 'revetsec/examples/postgresql-pending-store'
OLD = ROOT / 'planning/records/security/shared-clock-scp01-2026-10-29'
IMAGE = 'sha256:3a82e1f56c8f0f5616a11103ac3d47e632c3938698946a7ad26da0df1334744a'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def execute(command, **kwargs):
    return subprocess.run(list(map(str, command)), text=True, capture_output=True, timeout=45, **kwargs)


def raw(form):
    return base64.urlsafe_b64decode(form + '=' * (-len(form) % 4))


def inventory_usage(entries, family):
    counts = [[0, 0] for _ in range(256)]
    for row in entries:
        bucket = hashlib.sha256(row['storage_key'].encode('ascii')).digest()[0]
        counts[bucket][0] += 1
        if family == 'TOTP':
            core = raw(row['sealed_form'])
            wire = raw(core.decode('ascii'))
            assert wire[0] == 1 and 1 <= wire[1] <= 64
            reservation = (8 * (118 + len(wire) - 54 - wire[1]) + 5) // 6
            assert row['reserved_size'] == reservation and row['sealed_size'] == len(core)
            counts[bucket][1] += reservation
    return counts


class Peer:
    """Read complete child lines without select/TextIO buffering ambiguities."""
    def __init__(self, command, environment, output, name):
        self.process = subprocess.Popen(list(map(str, command)), env=environment, text=True, bufsize=1, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.events, self.lines = queue.Queue(), []
        self.output, self.name, self.saved = output, name, False
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self):
        for line in self.process.stdout:
            self.lines.append(line)
            self.events.put(line.rstrip('\n'))
        self.events.put(None)

    def read(self, timeout=12):
        line = self.events.get(timeout=timeout)
        if line is None:
            raise RuntimeError('Owned temporal child ended before its protocol completed')
        return line

    def send(self, command):
        self.process.stdin.write(command + '\n')
        self.process.stdin.flush()

    def finish(self):
        self.process.stdin.close()
        self.process.wait(timeout=15)
        self.thread.join(timeout=2)
        stderr = self.process.stderr.read()
        (self.output / (self.name + '.stdout')).write_text(''.join(self.lines))
        (self.output / (self.name + '.stderr')).write_text(stderr)
        self.saved = True
        return self.process.returncode == 0 and not stderr and not self.thread.is_alive()

    def stop(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=5)
        self.thread.join(timeout=2)
        if not self.saved:
            (self.output / (self.name + '.stdout')).write_text(''.join(self.lines))
            (self.output / (self.name + '.stderr')).write_text(self.process.stderr.read())
            self.saved = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--core-jar', type=Path, required=True)
    parser.add_argument('--core-sha256', required=True)
    parser.add_argument('--adapter-sources', type=Path, default=EXAMPLE / 'src/main/java/example/pending')
    parser.add_argument('--family', choices=['TOTP', 'WEBAUTHN', 'ISSUER'])
    parser.add_argument('--case', choices=['expired', 'below', 'unavailable', 'catchup', 'N-1', 'N', 'E-1', 'E', 'E+1'])
    parser.add_argument('--compile-only', action='store_true')
    args = parser.parse_args()
    if sha(args.core_jar) != args.core_sha256:
        parser.error('Selected core SHA-256 mismatch')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    runtime = Path(tempfile.mkdtemp(prefix='revetsec-temporal-'))
    runtime.chmod(0o700)
    result = {'status': 'RUNNING', 'checks': [], 'cases': [], 'coreJarSha256': args.core_sha256, 'qualified': False,
              'scope': 'Actual SPI with structural opaque values/scripted UTC; no authenticated engine/service or full C profile claim.',
              'compileOnly': args.compile_only, 'image': IMAGE, 'cleanup': {}}
    created, children = [], []
    resource = 'revetsec-temporal-' + secrets.token_hex(6)
    volume, network = resource + '-data', resource + '-network'
    password = secrets.token_urlsafe(32)

    def save():
        (output / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')

    def check(label, condition):
        assert not any(row['id'] == label for row in result['checks']), label
        result['checks'].append({'id': label, 'passed': bool(condition)})
        save()
        if not condition:
            raise AssertionError(label)

    def docker(*parts, data=None):
        p = execute(['docker', *parts], input=data)
        if p.returncode:
            raise RuntimeError('Owned Docker operation failed: ' + parts[0])
        return p.stdout.strip()

    def sql(statement):
        return docker('exec', '-i', resource, 'psql', '-XqAt', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres', data=statement)

    def snapshot(schema, family):
        suffixes = ['entry', 'escrow', 'namespace', 'epoch' if family == 'TOTP' else 'root']
        pieces = []
        for suffix in suffixes:
            order = 'bucket' if suffix == 'escrow' else 'storage_key' if suffix in ['entry', 'root'] else 'namespace'
            pieces.append("'" + suffix + "',coalesce((SELECT jsonb_agg(to_jsonb(t) ORDER BY " + order + ') FROM ' + schema + '.' + family.lower() + '_store_' + suffix + " t),'[]'::jsonb)")
        return json.loads(sql('SELECT jsonb_build_object(' + ','.join(pieces) + ');'))

    def reconcile(label, state, family):
        counts = inventory_usage(state['entry'], family)
        quotas = state['escrow']
        check(label + '/all-256-exact-assigned-counters', len(quotas) == 256 and all(row['bucket'] == i and [row['used_entries'], row['used_bytes']] == counts[i] and row['used_entries'] <= row['entry_limit'] and row['used_bytes'] <= row['byte_limit'] for i, row in enumerate(quotas)) and sum(row['entry_limit'] for row in quotas) == 4096 and sum(row['byte_limit'] for row in quotas) == (4_000_000 if family == 'TOTP' else 0))

    try:
        dependencies = []
        manifest = json.loads((OLD / 'ARTIFACT-PRESERVATION.json').read_text())
        for coordinate in ['com.pyranid:pyranid:4.7.0', 'org.postgresql:postgresql:42.7.14', 'org.jspecify:jspecify:1.0.1', 'com.google.code.findbugs:jsr305:3.0.2', 'com.google.errorprone:error_prone_annotations:2.50.0']:
            row = next(r for r in manifest['artifacts'] if r.get('coordinate') == coordinate)
            dependency = ROOT / row['frozen_path']
            check('pinned/' + coordinate, sha(dependency) == row['sha256'])
            dependencies.append(dependency)
        sources = [*sorted(args.adapter_sources.glob('*Pg*.java')), *[args.adapter_sources / name for name in ['PostgresqlTotpStore.java', 'PostgresqlWebAuthnStore.java', 'PostgresqlIssuerStore.java', 'PostgresqlPyranidDataSource.java']], HERE / 'native/example/pending/TemporalMatrixChecks.java', HERE / 'native/com/revetsec/oauth/server/TemporalIssuerCarrier.java']
        auditor = ROOT / 'revetsec/verification/examples/NullabilityAudit.java'
        inputs = [*sources, auditor, Path(__file__), *[EXAMPLE / (family + '-schema.sql') for family in ['totp', 'webauthn', 'issuer']]]
        result['sourceInputsSha256'] = {str(p): sha(p) for p in inputs}
        result['artifactInputsSha256'] = {str(p): sha(p) for p in [args.core_jar, *dependencies]}
        for index, source in enumerate(inputs):
            dest = output / 'SOURCE' / (str(index) + '-' + source.name)
            dest.parent.mkdir(exist_ok=True)
            shutil.copy2(source, dest)
        classes = runtime / 'classes'
        classes.mkdir()
        cp = os.pathsep.join(map(str, [args.core_jar, *dependencies]))
        compiled = execute([args.java_home / 'bin/javac', '--release', '17', '-proc:none', '-Xlint:all', '-Werror', '-cp', cp, '-d', classes, *sources, auditor])
        (output / 'compile.log').write_text(compiled.stdout + compiled.stderr)
        check('strict-release17-current-adapter-compile', compiled.returncode == 0 and not compiled.stderr)
        result['compiledClassfiles'] = {str(p.relative_to(classes)): sha(p) for p in sorted(classes.rglob('*.class'))}
        shutil.copytree(classes, output / 'classes')
        cp = os.pathsep.join([str(classes), cp])
        source_list = runtime / 'sources.txt'
        source_list.write_text('\n'.join(map(str, sources)) + '\n')
        cp_file = runtime / 'classpath.txt'
        cp_file.write_text(cp)
        audit = execute([args.java_home / 'bin/java', '-cp', cp, 'NullabilityAudit', source_list, cp_file, output / 'NULLABILITY.json'])
        audited = json.loads((output / 'NULLABILITY.json').read_text()) if (output / 'NULLABILITY.json').exists() else {}
        check('all-compiled-source-nullability', audit.returncode == 0 and not audited.get('missing', [True]) and not audited.get('attribution_errors', [True]))
        result['nullability'] = audited
        result['javaVersion'] = execute([args.java_home / 'bin/java', '-version']).stderr.strip()
        common_env = dict(os.environ, PG_QUALIFICATION_CORE_SHA256=args.core_sha256)
        java = [args.java_home / 'bin/java', '-cp', cp, 'example.pending.TemporalMatrixChecks']
        origin = execute([*java, 'TOTP', 'origin'], env=common_env)
        (output / 'origin.log').write_text(origin.stdout + origin.stderr)
        check('actual-current-core-origin', origin.returncode == 0 and origin.stdout.strip() == 'ORIGIN ' + args.core_sha256 and not origin.stderr)
        if not args.compile_only:
            check('exact-cached-image-no-pull', docker('image', 'inspect', IMAGE, '--format', '{{.Id}}') == IMAGE)
            docker('network', 'create', '--label', 'com.revetsec.temporal=true', network)
            created.append(('network', network))
            docker('volume', 'create', '--label', 'com.revetsec.temporal=true', volume)
            created.append(('volume', volume))
            envfile = runtime / 'postgres.env'
            envfile.write_text('POSTGRES_PASSWORD=' + password + '\n')
            envfile.chmod(0o600)
            with socket.socket() as bound:
                bound.bind(('127.0.0.1', 0))
                port = bound.getsockname()[1]
            created.append(('container', resource))
            docker('run', '-d', '--pull=never', '--name', resource, '--network', network, '--label', 'com.revetsec.temporal=true', '--env-file', envfile, '-p', f'127.0.0.1:{port}:5432', '-v', volume + ':/var/lib/postgresql', IMAGE)
            result['ownedResources'] = {'container': resource, 'network': network, 'volume': volume, 'loopbackPort': port}
            for _ in range(100):
                ready = execute(['docker', 'exec', resource, 'psql', '-XqAt', '-U', 'postgres', '-c', 'SELECT 1'])
                primary = execute(['docker', 'exec', resource, 'cat', '/proc/1/comm'])
                if ready.returncode == 0 and ready.stdout.strip() == '1' and primary.stdout.strip() == 'postgres':
                    break
                time.sleep(.1)
            else:
                raise RuntimeError('Owned primary startup failed')
            check('owned-primary-durable-settings-and-raw-wall-time-not-authority', sql("SELECT NOT pg_is_in_recovery() AND current_setting('fsync')='on' AND current_setting('full_page_writes')='on' AND extract(epoch FROM clock_timestamp())>1700000021") == 't')
            sql("CREATE ROLE temporal_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '" + password + "'")
            for family in ([args.family] if args.family else ['TOTP', 'WEBAUTHN', 'ISSUER']):
                scenarios = [(kind, point) for kind in ['entity', 'quota'] for point in ['expired', 'below', 'unavailable', 'catchup']] + [('none', point) for point in ['N-1', 'N', 'E-1', 'E', 'E+1']]
                if args.case:
                    scenarios = [case for case in scenarios if case[1] == args.case]
                for index, (kind, point) in enumerate(scenarios):
                    label = family + '/' + kind + '/' + point
                    schema = 'temporal_' + family.lower() + '_' + str(index)
                    sql('CREATE SCHEMA ' + schema + ';SET search_path TO ' + schema + ';' + (EXAMPLE / (family.lower() + '-schema.sql')).read_text() + ';GRANT USAGE ON SCHEMA ' + schema + ' TO temporal_runtime;GRANT SELECT,INSERT,UPDATE ON ALL TABLES IN SCHEMA ' + schema + ' TO temporal_runtime;GRANT USAGE ON ALL SEQUENCES IN SCHEMA ' + schema + ' TO temporal_runtime;')
                    environment = dict(common_env, DB_URL=f'jdbc:postgresql://127.0.0.1:{port}/postgres', DB_USER='temporal_runtime', DB_PASSWORD=password, DB_SCHEMA=schema)
                    setup = execute([*java, family, 'setup'], env=environment)
                    (output / (schema + '-setup.stdout')).write_text(setup.stdout)
                    (output / (schema + '-setup.stderr')).write_text(setup.stderr)
                    check(label + '/setup', setup.returncode == 0 and setup.stdout.strip() == 'SETUP ready' and not setup.stderr)
                    before = snapshot(schema, family)
                    reconcile(label + '/before', before, family)
                    worker = Peer([*java, family, 'worker', *(['catchup'] if point == 'catchup' else [])], environment, output, schema + '-worker')
                    children.append(worker)
                    plan = worker.read().split('\t')
                    ready = worker.read().split()
                    check(label + '/prepared-original-condition-before-lock-holder', len(plan) == 4 and plan[0] == 'PLAN' and len(ready) == 3 and ready[0] == 'READY' and int(ready[2]) == 1)
                    expected_bucket, samples_before = int(ready[1]), int(ready[2])
                    check(label + '/independent-target-bucket', hashlib.sha256(plan[1].encode('ascii')).digest()[0] == expected_bucket)
                    if kind != 'none':
                        holder = Peer([*java, family, 'hold', kind], environment, output, schema + '-holder')
                        children.append(holder)
                        held = holder.read().split()
                        check(label + '/actual-holder-ready', len(held) == 2 and held[0] == 'HELD')
                        holder_pid = int(held[1])
                    else:
                        worker.send('SET ' + point)
                        check(label + '/scripted-exact-edge', worker.read() == 'POINT SET')
                    worker.send('GO')
                    check(label + '/single-target-started', worker.read() == 'STARTED')
                    if kind != 'none':
                        deadline, observed, wait = time.monotonic() + 4, False, None
                        while time.monotonic() < deadline:
                            worker.send('STATUS')
                            state = worker.read().split()
                            if len(state) != 5 or state[0] != 'STATE':
                                raise RuntimeError('Owned temporal state protocol')
                            worker_pid = int(state[4])
                            if worker_pid:
                                wait = json.loads(sql("SELECT coalesce((SELECT jsonb_build_object('pid',pid,'wait',wait_event_type,'holder'," + str(holder_pid) + "=ANY(pg_blocking_pids(pid)),'query',query) FROM pg_stat_activity WHERE pid=" + str(worker_pid) + "),'null'::jsonb)"))
                                if wait and wait['wait'] == 'Lock' and wait['holder']:
                                    observed = True
                                    break
                            time.sleep(.005)
                        check(label + '/actual-pg-blocking-pids-wait', observed and ('pg_advisory_xact_lock' in wait['query'] if kind == 'entity' else family.lower() + '_store_escrow' in wait['query'] and 'FOR UPDATE' in wait['query']))
                        # The poll's STATE may precede the SQL observer's lock observation.
                        # Refresh it while the holder still owns the actual blocking lock.
                        worker.send('STATUS')
                        state = worker.read().split()
                        check(label + '/no-authority-sample-before-wait-release', int(state[1]) == int(state[2]) == samples_before and state[3] == 'false')
                        worker.send('SET ' + point)
                        check(label + '/changed-authority-while-waiting', worker.read() == 'POINT SET')
                        worker.send('STATUS')
                        still = worker.read().split()
                        check(label + '/still-no-sample-or-completion-under-holder', int(still[1]) == int(still[2]) == samples_before and still[3] == 'false')
                        holder.send('RELEASE')
                        check(label + '/actual-holder-released', holder.read() == 'RELEASED' and holder.finish())
                    worker.send('FINISH')
                    answer = worker.read().split()
                    check(label + '/owned-worker-finished', worker.finish())
                    expected = 'TIME_EXPIRED' if point in ['expired', 'E', 'E+1'] else 'TIME_BEFORE_FLOOR' if point in ['below', 'N-1'] else 'TIME_UNAVAILABLE' if point == 'unavailable' else 'COMMITTED'
                    check(label + '/truthful-exact-temporal-result', len(answer) == 7 and answer[0] == 'RESULT' and answer[1] == expected and answer[2] == str(expected == 'COMMITTED').lower())
                    check(label + '/fresh-single-sample-after-all-waits', int(answer[3]) == samples_before and int(answer[4]) == samples_before + 1)
                    check(label + '/factual-receipt-validation-equals-fresh-observation', answer[6] == (answer[5] if expected == 'COMMITTED' else '-'))
                    after = snapshot(schema, family)
                    reconcile(label + '/after', after, family)
                    if expected != 'COMMITTED':
                        check(label + '/exact-zero-data-version-quota-metadata-effects', after == before)
                    else:
                        key, version, form = plan[1:]
                        data = {row['storage_key']: row for row in after['entry']}
                        row = {'namespace': 'temporal', 'storage_key': key, 'version': version, 'sealed_form': form}
                        if family == 'TOTP':
                            row.update(kind='ACCOUNT_STATE', recovery_epoch='one', sealed_size=len(raw(form)), reserved_size=158)
                        elif family == 'WEBAUTHN':
                            check(label + '/renewed-positive-version', isinstance(data[key]['version'], int) and data[key]['version'] > 0)
                            row.update(kind='CEREMONY', version=data[key]['version'], sealed_size=len(raw(form)), expires_seconds=1700000020, expires_nanos=123456789)
                        else:
                            row.update(kind='INTERACTION', retain_seconds=1700000021, retain_nanos=0)
                        rows = {row['storage_key']: row for row in before['entry']}
                        check(label + '/target-was-confirmed-absent', key not in rows)
                        rows[key] = row
                        check(label + '/exact-new-data-version-expiry-retention', data == rows)
                        expected_state = json.loads(json.dumps(before))
                        expected_state['entry'] = after['entry']
                        expected_state['escrow'][expected_bucket]['used_entries'] += 1
                        expected_state['escrow'][expected_bucket]['used_bytes'] += 158 if family == 'TOTP' else 0
                        check(label + '/only-target-assigned-quota-delta-no-metadata-effects', after == expected_state)
                    result['cases'].append({'id': label, 'family': family, 'lock': kind, 'scriptedPoint': point, 'expected': expected, 'samplesBefore': samples_before, 'samplesAfter': int(answer[4]), 'observedAt': answer[5], 'validatedAt': answer[6], 'blocker': wait if kind != 'none' else None, 'beforeSha256': hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest(), 'afterSha256': hashlib.sha256(json.dumps(after, sort_keys=True).encode()).hexdigest()})
                    (output / (schema + '-states.json')).write_text(json.dumps({'before': before, 'after': after}, indent=2) + '\n')
        check('all-executed-sources-and-artifacts-stable', all(sha(Path(path)) == value for path, value in {**result['sourceInputsSha256'], **result['artifactInputsSha256']}.items()))
        result['status'] = 'PASS'
    except Exception as failure:
        result['status'] = 'FAIL'
        result['failure'] = {'type': type(failure).__name__, 'message': str(failure)}
        (output / 'failure.log').write_text(traceback.format_exc())
    finally:
        for child in children:
            child.stop()
        result['cleanup']['children'] = all(child.process.poll() is not None for child in children)
        for kind, name in reversed(created):
            command = ['docker', 'rm', '-f', name] if kind == 'container' else ['docker', kind, 'rm', name]
            result['cleanup'][kind] = execute(command).returncode == 0
        shutil.rmtree(runtime)
        result['cleanup']['protectedRuntime'] = not runtime.exists()
        if not all(result['cleanup'].values()):
            result['status'] = 'FAIL'
        save()
    print(json.dumps({'status': result['status'], 'checks': len(result['checks']), 'cases': len(result['cases']), 'cleanup': result['cleanup']}))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
