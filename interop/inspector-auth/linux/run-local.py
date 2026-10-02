#!/usr/bin/env python3
# Copyright 2026 Revetware LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Run the packaged local Playground with a released Inspector in an isolated container."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['context', 'runtime', 'app', 'app-manifest', 'provider', 'tls', 'output']:
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--image', default='revetsec-interop/inspector-linux:local')
    parser.add_argument('--token-format', choices=['jwt', 'opaque'], required=True)
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[3]
    paths = {name: Path(getattr(args, name.replace('-', '_'))).resolve()
             for name in ['context', 'runtime', 'app', 'app-manifest', 'provider', 'tls', 'output']}
    if any(',' in str(path) or ':' in str(path) for path in paths.values()):
        parser.error('Input paths must not contain mount separators')
    if paths['output'].exists():
        parser.error('Use a new private output directory')
    expected_names = {'playground-1.0.0-SNAPSHOT.jar', 'revetsec-1.0.0-SNAPSHOT.jar',
                      'revetsec-soklet-1.0.0-SNAPSHOT.jar', 'soklet-4.0.0.jar'}
    rows = json.loads(paths['app-manifest'].read_text())
    if {row['name'] for row in rows} != expected_names or len(rows) != 4:
        raise RuntimeError('APP_MANIFEST_INVALID')
    for row in rows:
        data = (paths['app'] / row['name']).read_bytes()
        if hashlib.sha256(data).hexdigest() != row['sha256']:
            raise RuntimeError('PACKAGED_APP_DRIFT')
    prepared = json.loads((paths['context'] / 'PREPARED.json').read_text())
    profile = paths['context'] / 'seccomp-browser-sandbox.json'
    if prepared['status'] != 'PASS' or hashlib.sha256(profile.read_bytes()).hexdigest() != prepared['derivedSeccompSha256']:
        raise RuntimeError('SCOPED_PROFILE_DRIFT')
    for path in [paths['runtime'] / 'java/bin/java', paths['runtime'] / 'caddy', paths['provider'] / 'server.js']:
        if not path.is_file():
            raise RuntimeError('RUNTIME_INPUT_MISSING')
    paths['output'].mkdir(mode=0o700, parents=True)
    evidence = paths['output'] / 'evidence'
    evidence.mkdir(mode=0o777)
    evidence.chmod(0o777)  # Only sanitized receipts are written by container uid1001.
    payload = {'tokenFormat': args.token_format, 'issuer': 'https://127.0.0.1:9443'}
    for name, filename in [('ca', 'ca.crt'), ('cert', 'localhost.crt'), ('key', 'localhost.key')]:
        data = (paths['tls'] / filename).read_bytes()
        if len(data) > 32768:
            raise RuntimeError('TLS_INPUT_EXCEEDS_BOUND')
        payload[name] = data.decode('ascii')
    container = 'revetsec-local-client-' + uuid.uuid4().hex[:12]
    command = ['docker', 'run', '--pull', 'never', '--rm', '--init', '-i', '--name', container,
               '--network', 'none', '--shm-size', '512m', '--user', 'pwuser', '--cap-drop', 'ALL',
               '--security-opt', 'no-new-privileges', '--security-opt', 'seccomp=' + str(profile)]
    for host, target in [(source, '/source'), (paths['runtime'], '/runtime'),
                         (paths['app'], '/app'), (paths['provider'], '/provider')]:
        command += ['--mount', 'type=bind,src=' + str(host) + ',dst=' + target + ',readonly']
    command += ['--mount', 'type=bind,src=' + str(evidence) + ',dst=/evidence', args.image,
                'node', '/source/interop/inspector-auth/linux/playground-client.mjs']
    result = {'command': command, 'privateTlsInput': 'bounded stdin only; never logged',
              'packagedApps': rows, 'issuer': payload['issuer'],
              'globalTrustMutation': False, 'network': 'none'}
    try:
        completed = subprocess.run(command, input=json.dumps(payload), text=True,
                                   capture_output=True, timeout=190)
        result['exit'] = completed.returncode
        (paths['output'] / 'stdout.log').write_text(completed.stdout)
        (paths['output'] / 'stderr.log').write_text(completed.stderr)
    except subprocess.TimeoutExpired:
        stop = subprocess.run(['docker', 'stop', '--timeout', '5', container],
                              capture_output=True, text=True, timeout=15)
        result.update(exit=124, failure='BOUNDED_RUN_TIMEOUT', cleanupExit=stop.returncode)
    (paths['output'] / 'COMMAND.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'exit': result['exit'], 'receiptDirectory': str(evidence)}))
    raise SystemExit(result['exit'])


if __name__ == '__main__':
    main()
