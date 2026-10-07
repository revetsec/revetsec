#!/usr/bin/env python3
# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Owned offline PostgreSQL/JVM process qualification. Never download images or contact an external service.

Only structural outcomes/hashes enter evidence. Keys, tokens, SQL and credentials are ephemeral.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import select
from pathlib import Path
import secrets
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import xml.etree.ElementTree as ET

IMAGE = 'sha256:3a82e1f56c8f0f5616a11103ac3d47e632c3938698946a7ad26da0df1334744a'
PYRANID_SHA = 'a9f142bb5e5a9de76668fb1ae1fede6a6dafae392196b551a2f965fbf19a226b'
DRIVER_SHA = '6e0e4cc2d8cae902084f8a2b18728b073a6fd9d1f87c9d8bff8f298c18185b93'


def exact(stream, count):
    data = bytearray()
    while len(data) < count:
        piece = stream.recv(count - len(data))
        if not piece:
            raise EOFError('Fixture connection closed')
        data.extend(piece)
    return bytes(data)


def packet(stream):
    kind = exact(stream, 1)
    length = struct.unpack('!I', exact(stream, 4))[0]
    if not 4 <= length <= 131072:
        raise ValueError('Fixture packet bound')
    body = exact(stream, length - 4)
    return kind, body, kind + struct.pack('!I', length) + body


class CommitLossProxy:
    """Plaintext *owned test* PostgreSQL v3 proxy, simple-query mode only.

    Drops exactly one writing COMMIT before forwarding, or withholds its whole response
    until authoritative ReadyForQuery confirms server commit, then closes the client.
    Read COMMITs are forwarded. Raw protocol bytes/queries are never retained or logged.
    """
    def __init__(self, port, when):
        self.port, self.when = port, when
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen()
        self.listener.settimeout(.2)
        self.local_port = self.listener.getsockname()[1]
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.drops = 0
        self.committed_ready = 0
        self.errors = []
        self.sockets = []
        self.threads = []
        self.acceptor = threading.Thread(target=self.accept, daemon=True)
        self.acceptor.start()

    def accept(self):
        while not self.stop.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                server = socket.create_connection(('127.0.0.1', self.port), timeout=5)
            except OSError:
                client.close()
                if not self.stop.is_set():
                    self.errors.append('owned-primary-connect')
                continue
            if self.stop.is_set():
                client.close()
                server.close()
                return
            self.sockets += [client, server]
            client.settimeout(2)
            server.settimeout(2)
            thread = threading.Thread(target=self.forward, args=(client, server), daemon=True)
            self.threads.append(thread)
            thread.start()

    def forward(self, client, server):
        # One owner per connection avoids concurrent close/recv on the same socket.
        dirty = False
        withholding = False
        try:
            size = struct.unpack('!I', exact(client, 4))[0]
            if not 8 <= size <= 4096:
                raise ValueError('Startup bound')
            startup = exact(client, size - 4)
            if startup[:4] != b'\x00\x03\x00\x00':
                raise ValueError('Expected plaintext v3 owned fixture')
            server.sendall(struct.pack('!I', size) + startup)
            while not self.stop.is_set():
                readable, _, _ = select.select([client, server], [], [], .2)
                for stream in readable:
                    kind, body, raw = packet(stream)
                    if stream is client:
                        if kind == b'Q':
                            upper = body.upper()
                            dirty |= b'INSERT INTO ISSUER_ENTRIES' in upper or b'DELETE FROM ISSUER_ENTRIES' in upper
                            if upper.strip(b'\x00; \r\n\t') == b'COMMIT' and dirty:
                                with self.lock:
                                    selected = self.drops == 0
                                    if selected:
                                        self.drops += 1
                                if selected and self.when == 'before':
                                    return
                                withholding = selected
                        server.sendall(raw)
                    elif withholding:
                        if kind == b'Z':
                            if body != b'I':
                                self.errors.append('commit-not-idle')
                            else:
                                self.committed_ready += 1
                            return
                    else:
                        client.sendall(raw)
                        if kind == b'Z' and body == b'I':
                            dirty = False
        except (EOFError, OSError):
            pass
        except ValueError:
            self.errors.append('protocol-bound')
        finally:
            for stream in [client, server]:
                try:
                    stream.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                stream.close()

    def close(self):
        self.stop.set()
        try:
            self.listener.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.listener.close()
        # Wake accept explicitly and finish registration before closing worker sockets.
        self.acceptor.join(6)
        for stream in self.sockets:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        for thread in self.threads:
            thread.join(3)
        for stream in self.sockets:
            stream.close()
        if self.acceptor.is_alive() or any(t.is_alive() for t in self.threads):
            raise RuntimeError('Proxy fixture threads did not stop')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['java-home', 'core-jar', 'fixture-jar', 'driver-jar', 'pyranid-jar', 'output']:
        p.add_argument('--' + name, required=True, type=Path)
    p.add_argument("--recovery", action="store_true", help="Exercise authentic logical restore and application recovery generation")
    args = p.parse_args()
    java = args.java_home / 'bin/java'
    jars = [args.core_jar, args.fixture_jar, args.driver_jar, args.pyranid_jar]
    if not java.is_file() or any(not jar.is_file() for jar in jars):
        p.error('Expected existing JDK and four JARs')
    if hashlib.sha256(args.driver_jar.read_bytes()).hexdigest() != DRIVER_SHA:
        p.error('Driver does not match qualification pin')
    if hashlib.sha256(args.pyranid_jar.read_bytes()).hexdigest() != PYRANID_SHA:
        p.error('Pyranid does not match qualification pin')
    if args.output.exists():
        p.error('Evidence output must be new')
    args.output.mkdir(parents=True)
    results = []
    processes = []
    proxies = []
    stamp = 'revetsec-store-' + secrets.token_hex(6)
    network, volume, container = stamp + '-net', stamp + '-data', stamp
    created = []

    def docker(*command, data=None):
        result = subprocess.run(['docker', *command], input=data, capture_output=True, timeout=40)
        if result.returncode:
            # PostgreSQL/Docker diagnostics can contain SQL or environment: exclude raw failure output.
            raise RuntimeError('Owned Docker fixture action failed: ' + command[0])
        return result.stdout.decode().strip()

    def record(name, valid, **facts):
        results.append(dict(name=name, status='PASS' if valid else 'FAIL', **facts))
        (args.output / 'checks.json').write_text(json.dumps(results, indent=2) + '\n')
        suite = ET.Element('testsuite', name='issuer-store-process-contract', tests=str(len(results)), failures=str(sum(item['status'] != 'PASS' for item in results)))
        for item in results:
            case = ET.SubElement(suite, 'testcase', classname='verification.store.ProcessContract', name=item['name'])
            if item['status'] != 'PASS':
                ET.SubElement(case, 'failure', message='Structural fixture assertion failed')
        ET.ElementTree(suite).write(args.output / 'TEST-issuer-store.xml', encoding='utf-8', xml_declaration=True)
        print(('PASS ' if valid else 'FAIL ') + name, flush=True)
        if not valid:
            raise AssertionError(name)

    try:
        with tempfile.TemporaryDirectory(prefix=stamp + '-') as temporary:
            state = Path(temporary)
            state.chmod(0o700)
            password = secrets.token_urlsafe(32)
            env_file = state / 'database.env'
            env_file.write_text('POSTGRES_PASSWORD=' + password + '\nPOSTGRES_DB=issuer_fixture\n')
            env_file.chmod(0o600)
            docker('network', 'create', '--label', 'com.revetsec.owned-fixture=true', network)
            created.append('network')
            docker('volume', 'create', '--label', 'com.revetsec.owned-fixture=true', volume)
            created.append('volume')
            with socket.socket() as reserve:
                reserve.bind(('127.0.0.1', 0))
                host_port = reserve.getsockname()[1]
            docker('run', '-d', '--pull=never', '--name', container, '--network', network,
                   '-p', '127.0.0.1:' + str(host_port) + ':5432', '--env-file', str(env_file),
                   '--mount', 'type=volume,source=' + volume + ',target=/var/lib/postgresql', IMAGE,
                   '-c', 'fsync=on', '-c', 'full_page_writes=on', '-c', 'synchronous_commit=on',
                   '-c', 'log_statement=none', '-c', 'log_min_error_statement=panic')
            created.append('container')

            def ready():
                until = time.monotonic() + 25
                while time.monotonic() < until:
                    r = subprocess.run(['docker', 'exec', container, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres', '-d', 'issuer_fixture'],
                                       capture_output=True, timeout=5)
                    if r.returncode == 0:
                        return
                    time.sleep(.2)
                raise RuntimeError('Owned PostgreSQL readiness expired')

            ready()
            port = int(docker('port', container, '5432/tcp').rsplit(':', 1)[1])
            if port != host_port:
                raise RuntimeError("Fixture port changed")
            (args.output / 'postgres.json').write_text(json.dumps(dict(image=IMAGE,
                version=docker('exec', container, 'postgres', '--version'), primary=True,
                fsync='on', full_page_writes='on', synchronous_commit='on', volume='owned-isolated',
                boundary='one primary, multiple independent JVMs, one host; no HA/power-loss proof'), indent=2)+'\n')

            def sql(query):
                return docker('exec', '-i', container, 'psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1',
                              '-U', 'postgres', '-d', 'issuer_fixture', data=query.encode())

            sql((Path(__file__).parent / 'schema.sql').read_text())
            cp = os.pathsep.join(str(jar.resolve()) for jar in jars)
            secrets_dir = state / 'keys'
            secrets_dir.mkdir(mode=0o700)

            def config(directory, name, mode='normal', proxy_port=None, **properties):
                directory.mkdir(mode=0o700, exist_ok=True)
                values = dict(url='jdbc:postgresql://127.0.0.1:' + str(proxy_port or port) + '/issuer_fixture',
                              user='postgres', password=password, gssEncMode='disable',
                              issuer='https://issuer.example/' + name, secrets=str(secrets_dir), mode=mode, **properties)
                path = directory / 'connection.properties'
                path.write_text(''.join(key + '=' + value + '\n' for key, value in values.items()))
                path.chmod(0o600)
                return path

            def launch(command, directory, name, **options):
                path = config(directory, name, **options)
                process = subprocess.Popen([str(java), '-cp', cp, 'verification.store.Worker', command, str(path), str(directory)],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                processes.append(process)
                return process

            def outcome(process):
                out, err = process.communicate(timeout=35)
                if process.returncode:
                    # Do not put keys, credentials, raw JDBC errors or SQL into logs.
                    frames = re.findall(r'(?m)^\s*at ([A-Za-z0-9_.$/]+\([^\n]*\))$', err)
                    types = re.findall(r'(?:Exception in thread \"main\" |Caused by: )([A-Za-z0-9_.$]+)', err)
                    structural = dict(exit=process.returncode, types=types, frames=frames,
                                      checks=[line for line in out.splitlines() if line.startswith('PASS ')])
                    (args.output / 'worker-failure.json').write_text(json.dumps(structural, indent=2)+'\n')
                    raise RuntimeError('JVM fixture failed; see redacted worker-failure.json')
                return out.strip()

            def call(command, directory, name, **options):
                return outcome(launch(command, directory, name, **options))

            def fresh(name):
                directory = state / name
                record(name + '-initialize', call('init', directory, name) == 'COMMITTED')
                record(name + '-prepare', call('prepare', directory, name) == 'PREPARED')
                return directory

            def digest():
                # Never store rows, versions or sealed values. SQL MD5 is only an equality fingerprint here.
                return hashlib.sha256(sql("SELECT storage_key||':'||version||':'||retain_seconds||':'||retain_nanos||':'||sealed FROM issuer_entries ORDER BY storage_key;").encode()).hexdigest()

            record('ephemeral-test-keys', call('keys', secrets_dir, 'keys') == 'KEYS')
            contract = call('contract', state / 'contract', 'contract')
            for line in contract.splitlines():
                record('contract-' + line.removeprefix('PASS '), line.startswith('PASS '))

            # A bounded fixture refuses new records without evicting active/permanent rows.
            cap = fresh('capacity')
            old = digest()
            count = sql('SELECT count(*) FROM issuer_entries;')
            record('capacity-rejects-no-eviction', call('redeem', cap, 'capacity', capacity=count).startswith('STORE_UNAVAILABLE ') and digest() == old)

            for command in ['redeem', 'refresh']:
                name = 'race-' + command
                origin = fresh(name)
                if command == 'refresh':
                    record(name + '-initial-issue', call('redeem', origin, name).startswith('SUCCEEDED '))
                workers = []
                for index in range(2):
                    directory = state / (name + '-' + str(index))
                    directory.mkdir(mode=0o700)
                    shutil.copy2(origin / ('code' if command == 'redeem' else 'refresh'), directory)
                    workers.append((directory, launch(command, directory, name, mode='race')))
                until = time.monotonic() + 10
                while not all((d / 'ready').exists() for d, _ in workers):
                    if time.monotonic() > until:
                        raise RuntimeError('Independent JVM race rendezvous expired')
                    time.sleep(.01)
                for directory, _ in workers:
                    (directory / 'go').touch()
                outcomes = [outcome(process) for _, process in workers]
                record(name + '-one-winner-one-replay', sorted(o.split()[0] for o in outcomes) == ['REJECTED', 'SUCCEEDED'], independentJvms=2)
                winner = next(directory for (directory, _), result in zip(workers, outcomes) if result.startswith('SUCCEEDED'))
                record(name + '-loser-invalidates-winner', call('active', winner, name) == 'INACTIVE')
                record(name + '-winner-refresh-invalidated', call('refresh', winner, name).startswith('REJECTED '))
                if command == 'refresh':
                    record(name + '-previous-access-invalidated', call('active', origin, name) == 'INACTIVE')

            # Actual uncertain commit: owned proxy drops before acceptance or after complete server ACK.
            for command in ['redeem', 'refresh']:
                for when in ['before', 'after']:
                    name = 'unknown-' + command + '-' + when
                    directory = fresh(name)
                    if command == 'refresh':
                        record(name + '-initial-issue', call('redeem', directory, name).startswith('SUCCEEDED '))
                    for credential in ['access']:
                        (directory / credential).unlink(missing_ok=True)
                    old = digest()
                    proxy = CommitLossProxy(port, when)
                    proxies.append(proxy)
                    result = call(command, directory, name, proxy_port=proxy.local_port)
                    proxy.close()
                    record(name + '-uncertain-no-retry-no-response', result == 'COMMIT_OUTCOME_UNKNOWN 1' and not (directory / 'access').exists()
                           and proxy.drops == 1 and not proxy.errors, actualConnectionLoss=True)
                    record(name + '-authoritative-reconciliation', (digest() == old) == (when == 'before'), committedReady=proxy.committed_ready)
                    if when == 'before':
                        record(name + '-later-valid-presentation', call(command, directory, name).startswith('SUCCEEDED '))
                    else:
                        record(name + '-later-replay-rejected', call(command, directory, name).startswith('REJECTED '))

            # Kill caller at partially written transaction / after durable ACK, then restart PostgreSQL.
            for command in ['redeem', 'refresh']:
                for stage in ['mutation', 'after-commit']:
                    name = 'crash-' + command + '-' + stage
                    directory = fresh(name)
                    if command == 'refresh':
                        record(name + '-initial-issue', call('redeem', directory, name).startswith('SUCCEEDED '))
                        (directory / 'access').unlink()
                    old = digest()
                    process = launch(command, directory, name, mode='pause-' + stage)
                    until = time.monotonic() + 10
                    while not (directory / 'ready').exists():
                        if time.monotonic() > until:
                            raise RuntimeError('Crash rendezvous expired')
                        time.sleep(.01)
                    process.kill()
                    process.communicate(timeout=5)
                    docker('kill', '--signal', 'KILL', container)
                    docker('start', container)
                    ready()
                    record(name + '-restart-atomic-state', (digest() == old) == (stage == 'mutation'), callerSigkill=True, databaseSigkill=True)
                    record(name + '-no-lost-response-credentials', not (directory / 'access').exists())
                    replay = call(command, directory, name)
                    record(name + '-post-restart-presentation', replay.startswith('SUCCEEDED ' if stage == 'mutation' else 'REJECTED '), observedOutcome=replay.split()[0])

            # Established restart reuses keys/namespace/fences, checks durable high-water and missing fences.
            recovery = fresh('restart')
            record('restart-issue', call('redeem', recovery, 'restart').startswith('SUCCEEDED '))
            docker('kill', '--signal', 'KILL', container)
            docker('start', container)
            ready()
            record('restart-fresh-jvm-status', call('active', recovery, 'restart') == 'ACTIVE')
            record('restart-existing-namespace-not-recreated', call('warm', recovery, 'restart') == 'READY')
            # Hold the SQL mutex on an independent administrative connection; a backend read must time out.
            locker = subprocess.Popen(['docker', 'exec', '-i', container, 'psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1',
                                       '-U', 'postgres', '-d', 'issuer_fixture'], stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            processes.append(locker)
            locker.stdin.write("BEGIN; DO $$ BEGIN PERFORM id FROM issuer_mutex WHERE id=1 FOR UPDATE; END $$; SELECT 'LOCKED';\n")
            locker.stdin.flush()
            until = time.monotonic() + 5
            locked = False
            while time.monotonic() < until:
                if select.select([locker.stdout], [], [], .1)[0]:
                    if locker.stdout.readline().strip() == 'LOCKED':
                        locked = True
                        break
            if not locked:
                raise RuntimeError('Fixture mutex rendezvous expired')
            key = sql("SELECT storage_key FROM issuer_entries WHERE kind='ISSUER_STATE' ORDER BY storage_key LIMIT 1;")
            try:
                record('database-lock-wait-honors-budget', call('budget', recovery, 'restart', key=key) == 'BOUNDED')
            finally:
                locker.stdin.write('ROLLBACK;\n\\q\n')
                locker.stdin.flush()
                locker.communicate(timeout=5)
            record('durable-clock-highwater-rejects-backward', call('warm', recovery, 'restart', now='2026-10-06T11:59:59Z') == 'STORE_UNAVAILABLE')
            waiting = launch('active', recovery, 'restart', mode='wait')
            until = time.monotonic() + 10
            while not (recovery / 'ready').exists():
                if time.monotonic() > until:
                    raise RuntimeError('Old engine rendezvous expired')
                time.sleep(.01)
            record('explicit-issuer-fence', call('fence', recovery, 'restart') == 'FENCED')
            (recovery / 'go').touch()
            record('already-built-engine-reloads-issuer-fence', outcome(waiting) == 'INACTIVE')
            if args.recovery:
                import recovery as recovery_checks
                recovery_checks.exercise(state, container, port, record, sql, docker, digest, call, launch, outcome, CommitLossProxy, proxies)
            sql("DELETE FROM issuer_entries WHERE kind='ISSUER_STATE';")
            record('missing-permanent-fence-fails-closed', call('warm', recovery, 'restart') == 'STORE_CORRUPT')

            module_files = sorted(path for path in Path(__file__).parent.rglob('*') if path.is_file() and 'target' not in path.relative_to(Path(__file__).parent).parts and '__pycache__' not in path.parts)
            source = hashlib.sha256()
            for path in module_files:
                source.update(str(path.relative_to(Path(__file__).parent)).encode()+b'\0')
                source.update(hashlib.sha256(path.read_bytes()).digest())
            facts = dict(logicalRestoreExercised=args.recovery, moduleSourceSha256=source.hexdigest(), moduleFiles=len(module_files), status='PASS' , checks=len(results), jvm=str(java), runtimeJars=4,
                         sourceJars=[dict(name=jar.name, sha256=hashlib.sha256(jar.read_bytes()).hexdigest()) for jar in jars],
                         cases=results, scope='single authoritative PostgreSQL primary, two independent JVM callers',
                         exclusions=['HA/failover', 'power loss', 'cross-host', 'physical/PITR restore', 'distributed traffic drain/lease', 'HSM/key-loss reconstruction', *(['authentic backup restore'] if not args.recovery else []), 'browser/independent client', 'full AS closure'])
            (args.output / 'RESULT.json').write_text(json.dumps(facts, indent=2) + '\n')
    finally:
        cleanup_errors = []
        def cleanup(action):
            try:
                action()
            except Exception:
                cleanup_errors.append('owned-resource-cleanup')
        for process in processes:
            if process.poll() is None:
                def stop_process(p=process):
                    p.kill()
                    p.communicate(timeout=5)
                cleanup(stop_process)
        for proxy in proxies:
            cleanup(proxy.close)
        if 'container' in created:
            cleanup(lambda: docker('rm', '-f', container))
        if 'volume' in created:
            cleanup(lambda: docker('volume', 'rm', volume))
        if 'network' in created:
            cleanup(lambda: docker('network', 'rm', network))
        if cleanup_errors:
            raise RuntimeError('Owned fixture cleanup incomplete')



if __name__ == '__main__':
    main()
