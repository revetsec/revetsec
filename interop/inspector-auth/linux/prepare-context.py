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
"""Prepare a narrow private Linux browser build context from pinned public inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', required=True)
    args = parser.parse_args()
    work = Path(args.work_dir)
    if not work.is_absolute() or work.exists() or any(parent.is_symlink() for parent in work.parents):
        parser.error('Use a new absolute private directory without symlink ancestors')
    source = Path(__file__).resolve().parent
    pins = json.loads((source / 'pins.json').read_text())
    client = source.parent / 'client'
    client_pins = json.loads((client / 'pins.json').read_text())
    work.mkdir(mode=0o700, parents=True)
    (work / 'artifacts').mkdir()
    (work / 'client').mkdir()
    rows = []

    def fetch(url, expected, destination, limit):
        request = urllib.request.Request(url, headers={'User-Agent': 'Revetsec-local-verification'})
        with urllib.request.urlopen(request, timeout=30) as response:
            data = response.read(limit + 1)
        digest = hashlib.sha256(data).hexdigest()
        if len(data) > limit or digest != expected:
            raise RuntimeError('PINNED_ARTIFACT_DRIFT')
        destination.write_bytes(data)
        rows.append({'url': url, 'exit': 0, 'sha256': digest,
                     'bytes': len(data), 'file': str(destination.relative_to(work))})
        return data

    for name, expected in [('package.json', client_pins['packageSha256']),
                           ('package-lock.json', client_pins['lockSha256'])]:
        data = (client / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError('CLIENT_LOCK_DRIFT')
        (work / 'client' / name).write_bytes(data)
    lock = json.loads((work / 'client/package-lock.json').read_text())
    inspector = lock['packages']['node_modules/@modelcontextprotocol/inspector']
    if inspector['version'] != '2.9.0' or inspector['integrity'] != client_pins['integrity']:
        raise RuntimeError('RELEASED_CLIENT_DRIFT')
    fetch(pins['nssTool']['url'], pins['nssTool']['sha256'],
          work / 'artifacts/nss-tools.deb', 1_000_000)
    upstream = fetch(pins['sandboxProfile']['upstreamUrl'],
                     pins['sandboxProfile']['upstreamSha256'],
                     work / 'upstream-seccomp.json', 100_000)
    profile = json.loads(upstream)
    if profile.get('defaultAction') != 'SCMP_ACT_ERRNO':
        raise RuntimeError('SANDBOX_PROFILE_DRIFT')
    # Deny clone3 with ENOSYS so Chromium falls back to its allowed clone path.
    # chroot is used inside its sandbox namespace; no capability is added.
    profile['syscalls'].extend([
        {'names': ['clone3'], 'action': 'SCMP_ACT_ERRNO', 'errnoRet': 38},
        {'names': ['chroot'], 'action': 'SCMP_ACT_ALLOW'},
    ])
    (work / 'seccomp-browser-sandbox.json').write_text(json.dumps(profile, indent=2) + '\n')
    license_info = pins['sandboxProfile']['upstreamLicense']
    license_data = (source / license_info['file']).read_bytes()
    if hashlib.sha256(license_data).hexdigest() != license_info['sha256']:
        raise RuntimeError('UPSTREAM_LICENSE_DRIFT')
    (work / 'PLAYWRIGHT-LICENSE').write_bytes(license_data)
    shutil.copyfile(source / 'Dockerfile', work / 'Dockerfile')
    result = {'status': 'PASS', 'image': pins['image'], 'artifacts': rows,
              'clientLockSha256': client_pins['lockSha256'],
              'derivedSeccompSha256': hashlib.sha256((work / 'seccomp-browser-sandbox.json').read_bytes()).hexdigest(),
              'browserSandboxDisabled': False, 'globalHostPolicyMutation': False,
              'nativeTrustStoreOrPrivateKeyIncluded': False}
    (work / 'PREPARED.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': 'PASS', 'artifacts': len(rows),
                      'globalHostPolicyMutation': False}))


if __name__ == '__main__':
    main()
