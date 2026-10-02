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

"""Create SAN-correct disposable TLS materials without changing any trust store."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', required=True)
    parser.add_argument('--openssl', required=True)
    args = parser.parse_args()
    work, openssl = Path(args.work_dir), Path(args.openssl)
    if not work.is_absolute() or work.exists() or not openssl.is_absolute() or not openssl.is_file():
        parser.error('Use a new absolute private directory and an absolute OpenSSL executable')
    if any(parent.is_symlink() for parent in work.parents):
        parser.error('The private directory must have no symlink ancestors')
    work.mkdir(mode=0o700, parents=True)
    os.umask(0o077)
    rows = []

    def run(arguments, expected=0):
        command = [str(openssl), *arguments]
        result = subprocess.run(command, cwd=work, capture_output=True, timeout=30)
        # TLS tool diagnostics contain only paths/certificate facts, not keys.
        rows.append({'command': command, 'exit': result.returncode,
                     'expectedExit': expected, 'stdout': result.stdout.decode(errors='replace')[:8192],
                     'stderr': result.stderr.decode(errors='replace')[:8192]})
        (work / 'COMMANDS.json').write_text(json.dumps(rows, indent=2) + '\n')
        if result.returncode != expected:
            raise RuntimeError('TLS_COMMAND_FAILED')

    run(['version'])
    run(['req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-days', '2',
         '-keyout', 'ca.key', '-out', 'ca.crt', '-subj', '/CN=Revetsec disposable local test CA',
         '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
         '-addext', 'keyUsage=critical,keyCertSign,cRLSign'])
    run(['req', '-new', '-newkey', 'rsa:3072', '-nodes', '-sha256',
         '-keyout', 'localhost.key', '-out', 'localhost.csr', '-subj', '/CN=localhost'])
    (work / 'localhost.ext').write_text('basicConstraints=critical,CA:FALSE\n'
                                      'keyUsage=critical,digitalSignature,keyEncipherment\n'
                                      'extendedKeyUsage=serverAuth\n'
                                      'subjectAltName=DNS:localhost,IP:127.0.0.1\n')
    run(['x509', '-req', '-in', 'localhost.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key',
         '-CAcreateserial', '-out', 'localhost.crt', '-days', '2', '-sha256',
         '-extfile', 'localhost.ext'])
    run(['verify', '-CAfile', 'ca.crt', '-verify_hostname', 'localhost', 'localhost.crt'])
    run(['verify', '-CAfile', 'ca.crt', '-verify_ip', '127.0.0.1', 'localhost.crt'])
    run(['verify', '-CAfile', 'ca.crt', '-verify_hostname', 'foreign.invalid', 'localhost.crt'], expected=2)
    run(['x509', '-in', 'localhost.crt', '-noout', '-dates', '-ext', 'subjectAltName'])
    receipt = {'status': 'PASS', 'globalTrustMutation': False, 'privateDirectory': str(work),
               'certificateDays': 2, 'san': {'dns': ['localhost'], 'ip': ['127.0.0.1']},
               'certificateSha256': {name: hashlib.sha256((work / name).read_bytes()).hexdigest()
                                     for name in ['ca.crt', 'localhost.crt']},
               'privateKeysExcludedFromEvidence': True, 'commands': len(rows)}
    (work / 'RESULT.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'status': 'PASS', 'globalTrustMutation': False, 'commands': len(rows)}))


if __name__ == '__main__':
    main()
