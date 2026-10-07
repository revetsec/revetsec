#!/usr/bin/env python3
# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Run the self-issued example with a released client and a sandboxed real browser.

Inputs are public packaged artifacts and a previously prepared, pinned Linux runtime.
Disposable TLS, application keys and browser/client state never leave the container
or private temporary directory. Only structural JSON/XML receipts are persisted.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path
import subprocess
import tempfile
import uuid
import xml.etree.ElementTree as ET

NAMESPACE_IMAGE = 'sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b'
BROWSER_IMAGE = 'sha256:6ab3458a9171e175d9066297fb5e46db7d3d35b199966655c7670ef06f3cdb7f'
SECCOMP_SHA = '4196af2ea4c1921e0c1ab2891da6cb829308cfc2e9fe5f5fdf6fc4bead8665b7'
CADDY_SHA = 'e1f904038fc11ca897ac5a12fdacfb2a7add02a8720c426d562a37f6fdad2afe'
JAVA_TREE_SHA = 'd09a334ac692ed5f0736801f9dd43baced395fcd011fe05e32adab7fa2bb9493'
NAMES = {'self-issued-1.0.0-SNAPSHOT.jar', 'revetsec-1.0.0-SNAPSHOT.jar',
         'revetsec-soklet-1.0.0-SNAPSHOT.jar', 'soklet-4.0.0.jar'}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def java_identity(directory):
    rows = []
    for path in sorted(directory.rglob('*')):
        name = str(path.relative_to(directory))
        if path.is_symlink():
            rows.append([name, 'link', str(path.readlink())])
        elif path.is_file():
            rows.append([name, 'file', sha(path)])
    return hashlib.sha256(json.dumps(rows, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()


def support_identity(source):
    names = ['support/'+name+'.mjs' for name in ['process','config','cdp','web','identity']]
    names += ['client/'+name for name in ['pins.json','package.json','package-lock.json']]
    return {name: sha(source/'interop/inspector-auth'/name) for name in names}


def invoke(command, **kwargs):
    result = subprocess.run(command, capture_output=True, timeout=30, **kwargs)
    if result.returncode:
        raise RuntimeError('LOCAL_PREPARATION_FAILED')
    return result


def certificates(directory, cimd):
    # Trust this CA in this invocation's private NSS/Node store only.
    config = directory / 'openssl.cnf'
    config.write_text('''[req]
distinguished_name=dn
prompt=no
[dn]
CN=localhost
[ca]
basicConstraints=critical,CA:true,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
[leaf]
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
'''.replace('DNS:localhost,IP:127.0.0.1', 'DNS:localhost,IP:127.0.0.1,DNS:cimd.example.com' if cimd else 'DNS:localhost,IP:127.0.0.1'))
    invoke(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-config', str(config), '-extensions', 'ca', '-keyout', str(directory/'ca.key'),
            '-out', str(directory/'ca.pem')])
    invoke(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-config', str(config),
            '-keyout', str(directory/'key.pem'), '-out', str(directory/'leaf.csr')])
    invoke(['openssl', 'x509', '-req', '-in', str(directory/'leaf.csr'),
            '-CA', str(directory/'ca.pem'), '-CAkey', str(directory/'ca.key'),
            '-set_serial', str(uuid.uuid4().int), '-days', '1', '-extfile', str(config),
            '-extensions', 'leaf', '-out', str(directory/'cert.pem')])
    for path in directory.iterdir():
        path.chmod(0o600)
    result = {}
    for name in ['ca', 'cert', 'key']:
        data = (directory/(name+'.pem')).read_bytes()
        if len(data) > 32768:
            raise RuntimeError('TLS_INPUT_EXCEEDS_BOUND')
        result[name] = data.decode('ascii')
    return result


def junit(path, checks):
    failures = sum(row['status'] != 'PASS' for row in checks)
    suite = ET.Element('testsuite', name='SelfIssuedBrowser', tests=str(len(checks)),
                       failures=str(failures), errors='0', skipped='0')
    for row in checks:
        case = ET.SubElement(suite, 'testcase', classname='SelfIssuedBrowser', name=row['name'])
        if row['status'] != 'PASS':
            ET.SubElement(case, 'failure', message='Structural assertion failed')
    ET.ElementTree(suite).write(path, encoding='utf-8', xml_declaration=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['source', 'runtime', 'app', 'app-manifest', 'output']:
        parser.add_argument('--'+name, required=True)
    parser.add_argument('--image', default=BROWSER_IMAGE, help='Pinned linux/arm64 derived browser image ID, already present locally')
    parser.add_argument('--client-type', choices=['public', 'confidential', 'cimd'], required=True)
    parser.add_argument('--second-resource', action='store_true', help='Authorize two resources independently and perform separately labeled cross-resource probes')
    parser.add_argument('--recovery', choices=['none', 'expiry', 'step-up'], default='none',
                        help='Normal flow, real two-minute expiry/automatic refresh, or actual scope step-up')
    parser.add_argument('--return-mode', choices=['exact-native', 'native-port', 'https', 'native-ephemeral-ipv4', 'native-ephemeral-ipv6'], default='exact-native',
                        help='Exact IP loopback, different native callback port, or exact HTTPS browser return')
    parser.add_argument('--native-followup-era', choices=['legacy', 'modern'], help='Native stored-auth-only call/denial era; defaults to the initial era')
    parser.add_argument('--era', choices=['legacy', 'modern'], required=True)
    parser.add_argument('--port', type=int, required=True,
                        help='A never-used issuer namespace port, between 10000 and 60000')
    args = parser.parse_args()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.image):
        parser.error("Use an immutable browser image ID")
    if args.second_resource and args.recovery != 'none':
        parser.error('Second-resource qualification uses two normal grants')
    if args.client_type == 'cimd' and (args.return_mode != 'https' or args.second_resource or args.recovery == 'step-up'):
        parser.error('CIMD uses exact HTTPS return with normal or expiry recovery')
    native = args.return_mode.startswith('native-ephemeral-')
    if native and (args.client_type == 'cimd' or args.recovery != 'none' or args.second_resource):
        parser.error('Native executable mode uses normal preregistered grants')
    if args.native_followup_era and not native:
        parser.error('Followup era is for native executable mode only')
    paths = {name: Path(getattr(args, name.replace('-', '_'))).resolve()
             for name in ['source', 'runtime', 'app', 'app-manifest', 'output']}
    module = Path(__file__).resolve().parent
    if any(',' in str(p) or ':' in str(p) for p in [*paths.values(), module]):
        parser.error('Input paths must not contain mount separators')
    if not 10000 <= args.port <= 60000 or paths['output'].exists():
        parser.error('Use a new private output directory and an unused issuer port')
    rows = json.loads(paths['app-manifest'].read_text())
    if len(rows) != 4 or {r['name'] for r in rows} != NAMES:
        raise RuntimeError('APP_MANIFEST_INVALID')
    if any(sha(paths['app']/r['name']) != r['sha256'] for r in rows):
        raise RuntimeError('PACKAGED_APP_DRIFT')
    profile = paths['runtime']/'seccomp.json'
    if sha(profile) != SECCOMP_SHA or sha(paths['runtime']/'caddy') != CADDY_SHA:
        raise RuntimeError('RUNTIME_PIN_DRIFT')
    if java_identity(paths['runtime']/'java') != JAVA_TREE_SHA:
        raise RuntimeError('JAVA_RUNTIME_DRIFT')
    support = support_identity(paths['source'])
    if not (paths['runtime']/'java/bin/java').is_file():
        raise RuntimeError('JAVA_RUNTIME_MISSING')
    inspected = invoke(['docker', 'image', 'inspect', args.image, '--format',
                        '{{.Id}} {{.Architecture}} {{.Os}}'], text=True).stdout.strip()
    if inspected != args.image+' arm64 linux':
        raise RuntimeError('BROWSER_IMAGE_DRIFT')
    if args.client_type == 'cimd':
        namespace_pin = invoke(['docker', 'image', 'inspect', NAMESPACE_IMAGE, '--format', '{{.Id}} {{.Architecture}} {{.Os}}'], text=True).stdout.strip()
        if namespace_pin != NAMESPACE_IMAGE+' arm64 linux':
            raise RuntimeError('NAMESPACE_IMAGE_DRIFT')
    paths['output'].mkdir(parents=True, mode=0o700)
    evidence = paths['output']/'evidence'
    evidence.mkdir(mode=0o777)
    evidence.chmod(0o777)  # Only sanitized receipts are written by container uid1001.
    container = 'revetsec-self-issued-'+uuid.uuid4().hex[:12]
    namespace = container+'-namespace'
    command = ['docker', 'run', '--pull', 'never', '--rm', '--init', '-i', '--name', container,
               '--network', 'container:'+namespace if args.client_type=='cimd' else 'none', '--shm-size', '512m', '--user', 'pwuser', '--cap-drop', 'ALL',
               '--security-opt', 'no-new-privileges', '--security-opt', 'seccomp='+str(profile)]
    for host, target in [(paths['source'], '/source'), (paths['runtime'], '/runtime'),
                         (paths['app'], '/app'), (module, '/suite')]:
        command += ['--mount', 'type=bind,src='+str(host)+',dst='+target+',readonly']
    command += ['--mount', 'type=bind,src='+str(evidence)+',dst=/evidence', args.image,
                'node', '/suite/browser-client.mjs']
    receipt = {'status': 'FAILED', 'clientType': args.client_type, 'era': args.era, 'returnMode': args.return_mode, 'nativeFollowupEra': args.native_followup_era or args.era, 'recovery': args.recovery, 'secondResource': args.second_resource,
               'issuer': 'https://localhost:'+str(args.port), 'appArtifacts': rows,
               'image': args.image, 'seccompSha256': SECCOMP_SHA, 'caddySha256': CADDY_SHA,
               'harness': {p.name: sha(p) for p in sorted(module.iterdir()) if p.is_file()},
               'tlsInput': 'private disposable CA and leaf; bounded stdin only',
               'namespaceImage': NAMESPACE_IMAGE if args.client_type=='cimd' else None,
               'network': 'owned network-none namespace with loopback public-form peer' if args.client_type=='cimd' else 'none', 'globalTrustMutation': False, 'rawLogsArchived': False,
               'javaRuntimeSha256': JAVA_TREE_SHA, 'supportHashes': support}
    try:
        if args.client_type == 'cimd':
            invoke(['docker', 'run', '-d', '--rm', '--pull', 'never', '--network', 'none',
                    '--name', namespace, '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN',
                    '--security-opt', 'no-new-privileges', NAMESPACE_IMAGE, '/bin/sh', '-c',
                    'ip addr add 8.8.8.8/32 dev lo && ip -6 addr add fd00::1/128 dev lo && exec sleep 330'])
            peer = invoke(['docker', 'exec', namespace, 'ip', 'addr', 'show', 'dev', 'lo'], text=True).stdout
            if '8.8.8.8/32' not in peer:
                raise RuntimeError('NAMESPACE_PEER_MISSING')
        with tempfile.TemporaryDirectory(prefix='revetsec-self-issued-tls-') as temp:
            directory = Path(temp)
            directory.chmod(0o700)
            payload = certificates(directory, args.client_type == 'cimd')
            payload.update(clientType=args.client_type, era=args.era, port=args.port, returnMode=args.return_mode, nativeFollowupEra=args.native_followup_era or args.era, recovery=args.recovery, secondResource=args.second_resource)
            completed = subprocess.run(command, input=json.dumps(payload), text=True,
                                       capture_output=True, timeout=300 if args.recovery!='none' else 200)
            receipt['exit'] = completed.returncode
            # Do not archive Docker/child stdout or stderr: a crash can include secrets.
        receipt['hostPrivateTlsRemoved'] = not directory.exists()
        report = json.loads((evidence/'RESULT.json').read_text())
        checks = [*report['checks'],
                  {'name': 'browser-and-client-run-completed', 'status': report['status']},
                  {'name': 'private-state-removed', 'status': 'PASS' if report.get('privateStateRemoved') and receipt['hostPrivateTlsRemoved'] else 'FAIL'},
                  {'name': 'all-owned-child-processes-closed', 'status': 'PASS' if set(report['shutdown']) == ({'browser','native-list','native-call','native-denial','application','wire','edge'} if native else {'browser','inspector','application','wire','edge'}) and set(report['shutdown'].values()) == {'CLOSED'} else 'FAIL'}]
        receipt['artifactHashesUnchanged'] = all(sha(paths['app']/r['name']) == r['sha256'] for r in rows)
        checks.append({'name': 'packaged-artifacts-unchanged', 'status': 'PASS' if receipt['artifactHashesUnchanged'] else 'FAIL'})
        receipt['supportAndRuntimeUnchanged'] = support_identity(paths['source']) == support and java_identity(paths['runtime']/'java') == JAVA_TREE_SHA
        checks.append({'name': 'support-and-java-runtime-unchanged', 'status': 'PASS' if receipt['supportAndRuntimeUnchanged'] else 'FAIL'})
        receipt['status'] = 'PASS' if completed.returncode == 0 and all(r['status']=='PASS' for r in checks) else 'FAILED'
        receipt['failure'] = report.get('failure')
    except (subprocess.TimeoutExpired, OSError, ValueError, KeyError, RuntimeError):
        receipt['failure'] = 'BOUNDED_RUN_OR_RECEIPT_FAILURE'
        checks = [{'name': 'browser-and-client-run-completed', 'status': 'FAIL'}]
    finally:
        # Operate on this random owned fixture name only, including timeout paths.
        for owned in [container, namespace]:
            subprocess.run(['docker', 'rm', '-f', owned], capture_output=True, timeout=20)
        state = subprocess.run(['docker', 'ps', '-aq', '--filter', 'name=^/'+container+'(-namespace)?$'],
                               capture_output=True, text=True, timeout=20)
        receipt['ownedContainerRemoved'] = state.returncode == 0 and state.stdout.strip() == ''
        if not receipt['ownedContainerRemoved']:
            receipt['status'] = 'FAILED'
        checks.append({'name': 'owned-container-removed', 'status': 'PASS' if receipt['ownedContainerRemoved'] else 'FAIL'})
        junit(paths['output']/'junit.xml', checks)
        receipt['checks'] = checks
        (paths['output']/'RUN.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(json.dumps({'status': receipt['status'], 'checks': len(checks), 'failure': receipt.get('failure')}))
    raise SystemExit(0 if receipt['status']=='PASS' else 1)


if __name__ == '__main__':
    main()
