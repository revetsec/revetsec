# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Owned logical-restore qualification. No snapshot/key/credential bytes enter evidence."""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import time


def atomic_control(path, value):
    """Trusted local coordinator only. This is not a distributed lease or a drain."""
    temporary = path.with_name(path.name + '.' + secrets.token_hex(8))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(value.encode('ascii'))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        temporary.unlink(missing_ok=True)


def exercise(state, container, port, record, sql, docker, digest, call, launch, outcome, proxy_type, proxies):
    control = state / 'recovery-control'
    control.mkdir(mode=0o700)
    gate = control / 'admission'

    def generation():
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')

    def phase(value, gen):
        atomic_control(gate, value + ' ' + gen + '\n')

    def route(command, directory, name, gen, **options):
        return call(command, directory, name, gate=str(gate), generation=gen, **options)

    def fresh(name, **options):
        directory = state / name
        record(name + '-initialize', call('init', directory, name, **options) == 'COMMITTED')
        record(name + '-prepare', call('prepare', directory, name, **options) == 'PREPARED')
        record(name + '-issue', call('redeem', directory, name, **options).startswith('SUCCEEDED '))
        return directory

    def namespace(name):
        return base64.urlsafe_b64encode(hashlib.sha256(('https://issuer.example/' + name).encode()).digest()).decode().rstrip('=')

    def issuer_version(name):
        prefix = 'revetsec:as:1:' + namespace(name) + ':'
        value = sql("SELECT version FROM issuer_entries WHERE kind='ISSUER_STATE' AND storage_key LIKE '" + prefix + "%';")
        if len(value) != 43:
            raise RuntimeError('Expected one authoritative recovery fence')
        return value

    def backup():
        # Single owned database, consistent custom logical archive; no credentials in argv.
        archive = '/tmp/revetsec-owned-' + secrets.token_hex(8) + '.dump'
        before = digest()
        docker('exec', container, 'pg_dump', '-Fc', '-U', 'postgres', '-d', 'issuer_fixture', '-f', archive)
        record('restore-consistent-backup-' + str(backups[0]), digest() == before)
        backups[0] += 1
        return archive, before

    def restore(snapshot):
        archive, expected = snapshot
        # All fixture request JVMs are finished or paused before route/store admission.
        # The trusted operator has closed/drained routes and isolated old writers.
        docker('exec', container, 'pg_restore', '--clean', '--if-exists', '--single-transaction',
               '--exit-on-error', '-U', 'postgres', '-d', 'issuer_fixture', archive)
        record('restore-exact-authentic-transport-' + str(restores[0]), digest() == expected)
        restores[0] += 1

    def wait_ready(directory, process):
        until = time.monotonic() + 12
        while not (directory / 'ready').exists():
            if process.poll() is not None or time.monotonic() > until:
                raise RuntimeError('Recovery JVM rendezvous expired')
            time.sleep(.01)

    backups, restores = [0], [0]
    name = 'restore-main'
    directory = fresh(name)
    unused = state / 'restore-unused-code'
    pending = state / 'restore-pending-consent'
    record('restore-unused-code-created', call('prepare', unused, name) == 'PREPARED')
    record('restore-consent-created', call('begin', pending, name) == 'PREPARED')
    gen_a, gen_b = generation(), generation()
    phase('LIVE', gen_a)
    record('restore-original-generation-live', route('active', directory, name, gen_a) == 'ACTIVE')
    old_node = state / 'restore-old-node'
    old_node.mkdir(mode=0o700)
    shutil.copy2(directory / 'access', old_node)
    waiting = launch('active', old_node, name, mode='wait', gate=str(gate), generation=gen_a)
    wait_ready(old_node, waiting)
    snapshot = backup()
    later = state / 'restore-post-backup'
    record('restore-post-backup-authorization', call('prepare', later, name) == 'PREPARED')
    record('restore-post-backup-issue', call('redeem', later, name).startswith('SUCCEEDED '))
    record('restore-subject-revoked', call('subject-fence', directory, name) == 'FENCED' and call('active', directory, name) == 'INACTIVE')
    record('restore-issuer-revoked', call('fence', directory, name) == 'FENCED')
    phase('CLOSED', gen_b)
    old_digest = digest()
    record('restore-closed-routes-do-not-write', route('refresh', directory, name, gen_b) == 'GATED' and digest() == old_digest)
    restore(snapshot)
    record('restore-authentic-rollback-passes-warmup', call('warm', directory, name) == 'READY')
    record('restore-bypass-demonstrates-revoked-token-revival', call('active', directory, name) == 'ACTIVE', deliberateDiagnosticBypass=True)
    record('restore-closed-gate-prevents-revival', route('active', directory, name, gen_b) == 'GATED')
    record('restore-public-recovery-fence', call('fence', directory, name) == 'FENCED')
    record('restore-pre-backup-token-invalidated', call('active', directory, name) == 'INACTIVE')
    record('restore-post-backup-token-absent', call('active', later, name) == 'INACTIVE')
    record('restore-refresh-invalidated', call('refresh', directory, name).startswith('REJECTED '))
    record('restore-unused-code-invalidated', call('redeem', unused, name).startswith('REJECTED '))
    record('restore-consent-invalidated', call('complete', pending, name) == 'REJECTED')
    phase('LIVE', gen_b)
    (old_node / 'go').touch()
    record('restore-already-built-old-generation-isolated', outcome(waiting) == 'GATED')
    record('restore-wrong-generation-rejected', route('active', directory, name, gen_a) == 'GATED')
    new = state / 'restore-new-grant'
    record('restore-new-generation-authorization', route('prepare', new, name, gen_b) == 'PREPARED')
    record('restore-new-generation-issue', route('redeem', new, name, gen_b).startswith('SUCCEEDED '))
    record('restore-new-generation-active', route('active', new, name, gen_b) == 'ACTIVE')
    old_digest = digest()
    gate.unlink()
    record('restore-missing-gate-fails-closed', route('active', new, name, gen_b) == 'GATED' and digest() == old_digest)
    atomic_control(gate, 'LIVE ' + gen_b + '\nextra')
    record('restore-malformed-gate-fails-closed', route('active', new, name, gen_b) == 'GATED' and digest() == old_digest)
    gen_c = generation()
    phase('CLOSED', gen_c)
    restore(snapshot)
    record('restore-repeat-keeps-external-control-closed', route('active', directory, name, gen_c) == 'GATED')
    record('restore-repeat-fence', call('fence', directory, name) == 'FENCED')
    phase('LIVE', gen_c)
    record('restore-repeat-invalidates-original-and-later', route('active', directory, name, gen_c) == 'INACTIVE' and route('active', new, name, gen_c) == 'INACTIVE')

    # UNKNOWN is never admission permission. External intent survives DB rollback.
    # Isolated sole management writer permits definitive version reconciliation here.
    for when in ['before', 'after']:
        name = 'restore-unknown-' + when
        directory = fresh(name)
        snapshot = backup()
        gen = generation()
        phase('CLOSED', gen)
        restore(snapshot)
        before = issuer_version(name)
        intent = control / (name + '.intent')
        atomic_control(intent, json.dumps(dict(generation=gen, previousVersion=before, phase='FENCE_PENDING')) + '\n')
        proxy = proxy_type(port, when)
        proxies.append(proxy)
        result = call('fence', directory, name, proxy_port=proxy.local_port)
        proxy.close()
        record(name + '-unknown-one-attempt', result == 'COMMIT_OUTCOME_UNKNOWN 1' and proxy.drops == 1 and not proxy.errors, committedReady=proxy.committed_ready)
        record(name + '-unknown-admission-closed', route('active', directory, name, gen) == 'GATED')
        current = issuer_version(name)
        retained = json.loads(intent.read_text())
        record(name + '-intent-authoritative-reconciliation', retained['previousVersion'] == before and ((current == before) == (when == 'before')))
        if when == 'before':
            # Explicit operator action AFTER authoritative rollback determination,
            # never an automatic UNKNOWN retry inside the provider/engine.
            record(name + '-confirmed-rollback-still-active-only-bypass', call('active', directory, name) == 'ACTIVE')
            record(name + '-operator-fence-after-confirmed-rollback', call('fence', directory, name) == 'FENCED')
        else:
            record(name + '-confirmed-commit-no-second-fence', call('active', directory, name) == 'INACTIVE' and issuer_version(name) == current)
        atomic_control(intent, json.dumps(dict(generation=gen, phase='FENCE_CONFIRMED')) + '\n')
        phase('LIVE', gen)
        record(name + '-opens-only-after-fence-confirmation', route('active', directory, name, gen) == 'INACTIVE')

    name = 'restore-coordinator-crash'
    directory = fresh(name)
    gen = generation()
    phase('CLOSED', gen)
    before = issuer_version(name)
    atomic_control(control / 'crash.intent', json.dumps(dict(generation=gen, previousVersion=before, phase='FENCE_PENDING')) + '\n')
    process = launch('fence', directory, name, mode='pause-after-commit')
    wait_ready(directory, process)
    process.kill()
    stdout, _ = process.communicate(timeout=5)
    after = issuer_version(name)
    record('restore-coordinator-sigkill-after-durable-fence', process.returncode < 0 and not stdout.strip() and after != before)
    record('restore-restarted-coordinator-defaults-closed', route('active', directory, name, gen) == 'GATED')
    record('restore-crash-reconciles-without-refencing', call('active', directory, name) == 'INACTIVE' and issuer_version(name) == after)
    phase('LIVE', gen)
    record('restore-crash-recovery-admits-no-old-token', route('active', directory, name, gen) == 'INACTIVE')

    name = 'restore-clock'
    now = '2026-10-06T12:00:00.000000500Z'
    directory = fresh(name, now=now)
    old = digest()
    record('restore-nanosecond-highwater-rejects-behind-node', call('warm', directory, name, now='2026-10-06T12:00:00.000000499Z') == 'STORE_UNAVAILABLE' and digest() == old)
    record('restore-forward-node-advances-fence', call('fence', directory, name, now='2026-10-06T12:00:00.000000501Z') == 'FENCED')
    old = digest()
    record('restore-highwater-persists-across-fresh-jvm', call('warm', directory, name, now=now) == 'STORE_UNAVAILABLE' and digest() == old)
    record('restore-current-clock-ready', call('warm', directory, name, now='2026-10-06T12:00:00.000000501Z') == 'READY')
    record('restore-extreme-clock-rejects-without-commit', call('fence', directory, name, now='+1000000000-12-31T23:59:59.999999999Z') == 'STORE_UNAVAILABLE 0' and digest() == old)

    name = 'restore-sealing'
    directory = fresh(name)
    old = digest()
    record('restore-lost-sealing-key-fails-corrupt', call('warm', directory, name, sealing='lost') == 'STORE_CORRUPT' and digest() == old)
    record('restore-premature-old-key-retirement-fails-corrupt', call('warm', directory, name, sealing='next-only') == 'STORE_CORRUPT' and digest() == old)
    record('restore-overlap-key-ring-reads-old-state', call('warm', directory, name, sealing='next-with-old') == 'READY')
    prefix = 'revetsec:as:1:' + namespace(name) + ':'
    def metadata():
        return sql("SELECT storage_key||'|'||kind||'|'||retain_seconds||'|'||retain_nanos FROM issuer_entries WHERE storage_key LIKE '" + prefix + "%' ORDER BY storage_key;")
    rows = metadata()
    keys = [row.split('|')[0] for row in rows.splitlines()]
    kinds = [row.split('|')[1] for row in rows.splitlines()]
    record('restore-reseal-includes-both-permanent-fences', 'ISSUER_STATE' in kinds and 'SUBJECT_STATE' in kinds)
    for index, key in enumerate(keys):
        record('restore-authenticated-cas-reseal-' + str(index), call('reseal', directory, name, sealing='next-with-old', key=key) == 'COMMITTED')
    record('restore-reseal-preserves-keys-kinds-retention', metadata() == rows and digest() != old)
    record('restore-overlap-old-writer-reads-new-seals', call('warm', directory, name, sealing='old-with-next') == 'READY')
    record('restore-retired-key-ring-reads-permanent-state', call('warm', directory, name, sealing='next-only') == 'READY')
    record('restore-retired-key-ring-keeps-existing-token', call('active', directory, name, sealing='next-only') == 'ACTIVE')
    record('restore-retired-key-ring-refreshes', call('refresh', directory, name, sealing='next-only').startswith('SUCCEEDED '))
    record('restore-stale-old-only-node-fails-corrupt', call('warm', directory, name) == 'STORE_CORRUPT')
