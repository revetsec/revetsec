#!/usr/bin/env python3
# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""CAP-10 actual reference-adapter SPI atomicity on an owned disposable primary.

Structural opaque fixtures and scripted time only; no authenticated engine, UTC,
serving activation, deployment witness or device durability qualification claim.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import traceback

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
EXAMPLE = ROOT / 'revetsec/examples/postgresql-pending-store'
OLD = ROOT / 'planning/records/security/shared-clock-scp01-2026-10-29'
IMAGE = 'sha256:3a82e1f56c8f0f5616a11103ac3d47e632c3938698946a7ad26da0df1334744a'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def execute(args, **kwargs):
    return subprocess.run(list(map(str, args)), text=True, capture_output=True, timeout=45, **kwargs)


def raw(form):
    return base64.urlsafe_b64decode(form + '=' * (-len(form) % 4))


def usage(entries, family):
    """Independent SQL-inventory oracle; no Java capacity helper is called."""
    counts = [[0, 0] for _ in range(256)]
    for entry in entries:
        bucket = hashlib.sha256(entry['storage_key'].encode('ascii')).digest()[0]
        counts[bucket][0] += 1
        if family == 'TOTP':
            core_ascii = raw(entry['sealed_form'])
            wire = raw(core_ascii.decode('ascii'))
            assert wire[0] == 1 and 1 <= wire[1] <= 64
            reserved = (8 * (118 + len(wire) - 54 - wire[1]) + 5) // 6
            assert entry['reserved_size'] == reserved and entry['sealed_size'] == len(core_ascii)
            counts[bucket][1] += reserved
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--core-jar', type=Path, required=True)
    parser.add_argument('--core-sha256', required=True)
    # Private calibration uses copied sources; normal invocation always uses current sources.
    parser.add_argument('--adapter-sources', type=Path, default=EXAMPLE / 'src/main/java/example/pending')
    parser.add_argument('--family', choices=['TOTP', 'WEBAUTHN', 'ISSUER'])
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    result = {'status': 'RUNNING', 'checks': [], 'cases': [], 'image': IMAGE,
              'qualified': False, 'scope': 'Structural native SPI + scripted time; disposable component only.',
              'coreJarSha256': sha(args.core_jar), 'cleanup': {}}

    def save():
        (out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')

    def check(label, condition):
        assert not any(c['id'] == label for c in result['checks']), label
        result['checks'].append({'id': label, 'passed': bool(condition)})
        save()
        if not condition:
            raise AssertionError(label)

    resource = 'revetsec-cap10-' + secrets.token_hex(6)
    volume, network = resource + '-data', resource + '-bridge'
    created = []
    runtime = Path(tempfile.mkdtemp(prefix='revetsec-cap10-'))
    runtime.chmod(0o700)
    password = secrets.token_urlsafe(32)

    def docker(*parts, data=None):
        p = execute(['docker', *parts], input=data)
        if p.returncode:
            raise RuntimeError('Owned Docker operation failed: ' + parts[0])
        return p.stdout.strip()

    def sql(statement):
        return docker('exec', '-i', resource, 'psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres', data=statement)

    def ready():
        for _ in range(100):
            p = execute(['docker', 'exec', resource, 'psql', '-XqAt', '-U', 'postgres', '-c', 'SELECT 1'])
            primary = execute(['docker', 'exec', resource, 'cat', '/proc/1/comm'])
            if p.returncode == 0 and p.stdout.strip() == '1' and primary.stdout.strip() == 'postgres':
                return
            time.sleep(.1)
        raise RuntimeError('Owned primary not ready')

    def snapshot(schema, family):
        tables = ['entry', 'escrow', 'namespace'] + (['epoch'] if family == 'TOTP' else ['root'])
        pieces = []
        for suffix in tables:
            order = 'bucket' if suffix == 'escrow' else 'storage_key' if suffix in ['entry', 'root'] else 'namespace'
            table = family.lower() + '_store_' + suffix
            pieces.append("'" + suffix + "',coalesce((SELECT jsonb_agg(to_jsonb(t) ORDER BY " + order + ') FROM ' + schema + '.' + table + " t),'[]'::jsonb)")
        return json.loads(sql('SELECT jsonb_build_object(' + ','.join(pieces) + ');'))

    def reconcile(label, state, family):
        counts = usage(state['entry'], family)
        rows = state['escrow']
        check(label + '/all-256-exact-counters', len(rows) == 256 and all(r['bucket'] == i and [r['used_entries'], r['used_bytes']] == counts[i] and r['used_entries'] <= r['entry_limit'] and r['used_bytes'] <= r['byte_limit'] for i, r in enumerate(rows)))

    try:
        check('exact-current-core', result['coreJarSha256'] == args.core_sha256)
        check('cached-image-no-pull', docker('image', 'inspect', IMAGE, '--format', '{{.Id}}') == IMAGE)
        dependencies = []
        manifest = json.loads((OLD / 'ARTIFACT-PRESERVATION.json').read_text())
        for coordinate in ['com.pyranid:pyranid:4.7.0', 'org.postgresql:postgresql:42.7.14', 'org.jspecify:jspecify:1.0.1', 'com.google.code.findbugs:jsr305:3.0.2', 'com.google.errorprone:error_prone_annotations:2.50.0']:
            row = next(r for r in manifest['artifacts'] if r.get('coordinate') == coordinate)
            dependency = ROOT / row['frozen_path']
            check('pinned/' + coordinate, sha(dependency) == row['sha256'])
            dependencies.append(dependency)
        sources = sorted(args.adapter_sources.glob('*Pg*.java')) + [args.adapter_sources / ('Postgresql' + f + 'Store.java') for f in ['Totp', 'WebAuthn', 'Issuer']] + [HERE / 'native/example/pending/Cap10AtomicityChecks.java']
        schemas = [EXAMPLE / (f + '-schema.sql') for f in ['totp', 'webauthn', 'issuer']]
        source_inputs = {str(p): sha(p) for p in sources + schemas + [Path(__file__)]}
        result['sourceInputsSha256'] = source_inputs
        for i, source in enumerate(sources + schemas + [Path(__file__)]):
            dest = out / 'SOURCE' / (str(i) + '-' + source.name)
            dest.parent.mkdir(exist_ok=True)
            shutil.copy2(source, dest)
        classes = out / 'classes'
        classes.mkdir()
        cp = os.pathsep.join(map(str, [args.core_jar, *dependencies]))
        p = execute([args.java_home / 'bin/javac', '--release', '17', '-proc:none', '-Xlint:all', '-Werror', '-cp', cp, '-d', classes, *sources])
        (out / 'compile.log').write_text(p.stdout + p.stderr)
        check('strict-current-adapter-compile', p.returncode == 0)
        result['compiledClassfiles'] = {str(p.relative_to(classes)): sha(p) for p in sorted(classes.rglob('*.class'))}
        result['javaVersion'] = execute([args.java_home / 'bin/java', '-version']).stderr.strip()
        cp = os.pathsep.join([str(classes), cp])
        docker('network', 'create', network)
        created.append(('network', network))
        docker('volume', 'create', volume)
        created.append(('volume', volume))
        envfile = runtime / 'postgres.env'
        envfile.write_text('POSTGRES_PASSWORD=' + password + '\n')
        envfile.chmod(0o600)
        with socket.socket() as bound:
            bound.bind(('127.0.0.1', 0))
            port = bound.getsockname()[1]
        created.append(('container', resource))
        docker('run', '-d', '--pull=never', '--name', resource, '--network', network, '--env-file', str(envfile), '-p', f'127.0.0.1:{port}:5432', '-v', volume + ':/var/lib/postgresql', IMAGE)
        ready()
        result['ownedResources'] = {'container': resource, 'volume': volume, 'network': network, 'loopbackPort': port}
        check('primary-fsync-fullpage', sql("SELECT NOT pg_is_in_recovery() AND current_setting('fsync')='on' AND current_setting('full_page_writes')='on'") == 't')
        # The test role has ordinary table privileges, not schema/role/cluster administration.
        sql("CREATE ROLE cap10_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '" + password + "';")
        retained = []
        for family in ([args.family] if args.family else ['TOTP', 'WEBAUTHN', 'ISSUER']):
            scenarios = [('positive', 'normal', None), ('zero', 'normal', 'fill_cancel'), ('negative', 'normal', None), ('positive', 'normal', 'fill_entry'), ('positive', 'fail_data', None), ('positive', 'fail_quota', None), ('positive', 'lost', None), ('positive', 'halt_data', None), ('positive', 'halt_quota', None), ('positive', 'halt_after', None)]
            if family == 'TOTP':
                scenarios.append(('positive', 'normal', 'fill_bytes'))
            for index, (shape, mode, fill) in enumerate(scenarios):
                label = family + '/' + str(index) + '-' + shape + '-' + (fill or mode)
                schema = 'cap10_' + family.lower() + '_' + str(index)
                privileges = 'SELECT,INSERT,UPDATE' + (',DELETE' if family != 'TOTP' else '')
                sql('CREATE SCHEMA ' + schema + ';SET search_path TO ' + schema + ';' + (EXAMPLE / (family.lower() + '-schema.sql')).read_text() + ';GRANT USAGE ON SCHEMA ' + schema + ' TO cap10_runtime;GRANT ' + privileges + ' ON ALL TABLES IN SCHEMA ' + schema + ' TO cap10_runtime;GRANT USAGE ON ALL SEQUENCES IN SCHEMA ' + schema + ' TO cap10_runtime;')
                env = dict(os.environ, DB_URL=f'jdbc:postgresql://127.0.0.1:{port}/postgres?sslmode=disable&gssEncMode=disable', DB_USER='cap10_runtime', DB_PASSWORD=password, DB_SCHEMA=schema)

                def java(operation):
                    p = execute([args.java_home / 'bin/java', '-cp', cp, 'example.pending.Cap10AtomicityChecks', family, operation, shape], env=env)
                    (out / (schema + '-' + operation + '.stdout')).write_text(p.stdout)
                    (out / (schema + '-' + operation + '.stderr')).write_text(p.stderr)
                    return p

                check(label + '/setup', java('setup').returncode == 0)
                if fill:
                    check(label + '/fill-actual-adapter', java(fill).returncode == 0)
                before = snapshot(schema, family)
                reconcile(label + '/before', before, family)
                p = java(mode)
                plans = [line.split('\t')[1:] for line in p.stdout.splitlines() if line.startswith('PLAN\t')]
                check(label + '/multi-key-plan', 3 <= len(plans) <= 8 and len({row[0] for row in plans}) == len(plans))
                # Process death must close its physical transaction before observation.
                after = snapshot(schema, family)
                reconcile(label + '/after', after, family)
                refused = fill in ['fill_entry', 'fill_bytes']
                old = refused or mode in ['fail_data', 'fail_quota', 'halt_data', 'halt_quota']
                if mode.startswith('halt_'):
                    marker = 'BOUNDARY committed-before-receipt' if mode == 'halt_after' else 'BOUNDARY after-first-' + mode[5:] + '-dml'
                    check(label + '/actual-worker-crash-boundary', p.returncode == (79 if mode == 'halt_after' else 78) and marker in p.stdout)
                else:
                    status = 'CAPACITY_REFUSED' if refused and family == 'TOTP' else 'CAPACITY' if refused else 'UNAVAILABLE' if mode.startswith('fail_') else 'UNKNOWN' if mode == 'lost' else 'COMMITTED'
                    check(label + '/truthful-status', p.returncode == 0 and 'STATUS ' + status in p.stdout)
                    check(label + '/receipt-timing', ('TIMING false' if status != 'COMMITTED' else 'TIMING true') in p.stdout)
                    trace = next(line.split()[1:] for line in p.stdout.splitlines() if line.startswith('TRACE '))
                    dml, quotas, commits, opens = map(int, trace)
                    check(label + '/single-target-no-refund-retry', (dml == quotas == commits == 0 if refused else commits == 1 if mode in ['normal', 'lost'] else commits == 0) and opens == (len(plans) + 1 if family == 'ISSUER' else 2))
                    if mode == 'fail_data':
                        check(label + '/actual-first-data-fault', dml == 1 and quotas == 0)
                    if mode == 'fail_quota':
                        check(label + '/actual-first-quota-fault', dml == len(plans) and quotas == 1)
                if old:
                    check(label + '/all-old-data-and-every-quota', after == before)
                else:
                    expected = {r['storage_key']: dict(r) for r in before['entry']}
                    versions = set()
                    actual = {r['storage_key']: r for r in after['entry']}
                    for key, action, version, form in plans:
                        previous = expected.get(key)
                        if action == 'REMOVE':
                            del expected[key]
                            continue
                        row = dict(previous) if previous else {'namespace': 'cap10', 'storage_key': key}
                        row.update(sealed_form=form, version=version)
                        if family == 'TOTP':
                            core_ascii = raw(form)
                            wire = raw(core_ascii.decode('ascii'))
                            row.update(recovery_epoch='one', kind='ACCOUNT_STATE', sealed_size=len(core_ascii), reserved_size=(8 * (118 + len(wire) - 54 - wire[1]) + 5) // 6)
                        elif family == 'WEBAUTHN':
                            fresh = actual[key]['version']
                            assert isinstance(fresh, int) and fresh > 0 and fresh not in versions and (not previous or fresh != previous['version'])
                            versions.add(fresh)
                            row.update(kind='CEREMONY', version=fresh, sealed_size=len(raw(form)), expires_seconds=1700000070, expires_nanos=0)
                        else:
                            row.update(kind='INTERACTION', retain_seconds=1700000070, retain_nanos=0)
                        expected[key] = row
                    check(label + '/all-new-exact-data-and-versions', actual == expected)
                    counts = usage(list(expected.values()), family)
                    expected_state = json.loads(json.dumps(before))
                    expected_state['entry'] = after['entry']
                    for i, quota in enumerate(expected_state['escrow']):
                        quota['used_entries'], quota['used_bytes'] = counts[i]
                    check(label + '/all-new-exact-quota-no-metadata-effects', after == expected_state)
                    before_usage = usage(before['entry'], family)
                    net = sum(c[1 if family == 'TOTP' else 0] - b[1 if family == 'TOTP' else 0] for c, b in zip(counts, before_usage))
                    check(label + '/independent-net-sign', (net > 0 if shape == 'positive' else net == 0 if shape == 'zero' else net < 0))
                    if fill == 'fill_cancel':
                        # The shared a/b/e bucket was full in the relevant dimension.
                        shared = hashlib.sha256(plans[0][0].encode('ascii')).digest()[0]
                        q = before['escrow'][shared]
                        check(label + '/full-bucket-merged-zero-no-transient-refusal', (q['byte_limit'] - q['used_bytes'] < 4 if family == 'TOTP' else q['used_entries'] == q['entry_limit']) and counts[shared] == before_usage[shared])
                result['cases'].append({'id': label, 'family': family, 'shape': shape, 'mode': mode, 'fill': fill, 'expectedState': 'ALL_OLD' if old else 'ALL_NEW', 'beforeSha256': hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest(), 'afterSha256': hashlib.sha256(json.dumps(after, sort_keys=True).encode()).hexdigest()})
                (out / (schema + '-states.json')).write_text(json.dumps({'before': before, 'after': after}, indent=2) + '\n')
                retained.append((label, schema, family, after))
        # Abruptly stop only this disposable primary, then check complete persisted atoms.
        docker('kill', '--signal=KILL', resource)
        docker('start', resource)
        ready()
        for label, schema, family, state in retained:
            observed = snapshot(schema, family)
            check(label + '/primary-crash-restart-exact-state', observed == state)
            reconcile(label + '/restarted', observed, family)
        check('source-stable', all(sha(Path(path)) == digest for path, digest in source_inputs.items()))
        result['status'] = 'PASS'
    except Exception as failure:
        result['status'] = 'FAIL'
        result['failure'] = {'type': type(failure).__name__, 'message': str(failure)}
        (out / 'failure.log').write_text(traceback.format_exc())
    finally:
        for kind, name in reversed(created):
            p = execute(['docker', kind, 'rm', '-f', name] if kind == 'container' else ['docker', kind, 'rm', name])
            result['cleanup'][kind + 'Removed'] = p.returncode == 0
        shutil.rmtree(runtime)
        result['cleanup']['protectedRuntimeRemoved'] = not runtime.exists()
        if not all(result['cleanup'].values()):
            result['status'] = 'FAIL'
        save()
    print(json.dumps({'status': result['status'], 'checks': len(result['checks']), 'cases': len(result['cases']), 'cleanup': result['cleanup']}))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
