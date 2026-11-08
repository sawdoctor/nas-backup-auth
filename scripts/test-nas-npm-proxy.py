#!/usr/bin/env python3
"""Test a verified NPM candidate on loopback, then remove the bounded trial."""
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import types
import urllib.request
import uuid
import yaml

HELPER_PIN = 'd913c6318bde2dbdd94fbe64c1d6b3cf9640f1fa'
HELPER_SHA = '009889cbb655f24e44dc4097e3c8ced6a5344ca1c1bf99ec5712bd220aa12749'
CERT_SHA = '1f1e511e98c872b46d36309b5a2b26934e27c0ce0143107fc760f892a4c40c0c'
NAME = 'npm-private-proxy-trial'
LABEL = 'net.sawdoctor.npm-private-trial'
PORTS = {'80/tcp': '18080', '81/tcp': '18081', '443/tcp': '18443'}
CA_FILE = '/etc/ssl/certs/ca-certificates.crt'
FORMAT = 'sawdoctor-npm-private-proxy-test-v1'
ERROR_LOG = None
TIMER = '''\tinitTimer: () => {
\t\tlogger.info("Let's Encrypt Renewal Timer initialized");
\t\tinternalCertificate.interval = setInterval(
\t\t\tinternalCertificate.processExpiringHosts,
\t\t\tinternalCertificate.intervalTimeout,
\t\t);
\t\t// And do this now as well
\t\tinternalCertificate.processExpiringHosts();
\t},'''


def say(message):
    print(message, flush=True)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def command(*args, stdin=None, timeout=30, allowed=(0,)):
    result = subprocess.run(args, input=stdin, capture_output=True, timeout=timeout)
    if result.returncode not in allowed:
        if ERROR_LOG is not None:
            ERROR_LOG.write_bytes((result.stdout + b'\n' + result.stderr)[-1024**2:])
            ERROR_LOG.chmod(0o600)
        raise RuntimeError('A private proxy-test command failed; diagnostic output was retained privately.')
    return result.stdout


def inspect(name):
    result = subprocess.run(['docker', 'inspect', name], capture_output=True, timeout=20)
    if result.returncode:
        error = result.stderr.decode(errors='replace').lower()
        if 'no such object:' in error or 'no such container:' in error:
            return None
        raise RuntimeError('Docker inspection failed; trial files were retained.')
    records = json.loads(result.stdout)
    return records[0] if len(records) == 1 else None


def hold_certificate_worker(data):
    if sha(data) != CERT_SHA:
        raise RuntimeError('The NPM certificate worker differs from the reviewed 2.16.0 file.')
    source = data.decode()
    if source.count(TIMER) != 1:
        raise RuntimeError('The reviewed certificate timer block differs.')
    source = source.replace(TIMER, '\tinitTimer: () => {\n\t\tlogger.info("NAS PRIVATE TRIAL: CERTIFICATE RENEWAL HELD");\n\t},', 1)
    for method in ('create', 'renew'):
        signature = '\t' + method + ': async (access, data) => {\n'
        if source.count(signature) != 1:
            raise RuntimeError('A reviewed certificate operation differs.')
        source = source.replace(signature, signature + '\t\tthrow Object.assign(new Error("Certificate operations held during NAS trial"), {code: "NAS_NPM_TRIAL_CERT_HOLD"});\n', 1)
    return source.encode()


def trial_model(model, current, folder, guard):
    result = copy.deepcopy(model)
    if set(result.get('services', {})) != {'npm'} or set(result.get('networks', {})) != {'default'}:
        raise RuntimeError('The candidate service/network structure differs.')
    service = result['services']['npm']
    if service.get('container_name') != 'npm-nas':
        raise RuntimeError('The candidate proxy name differs.')
    service.update(container_name=NAME, image=current['Image'], restart='no', pull_policy='never')
    service['ports'] = [{'target': int(key.split('/')[0]), 'published': value, 'host_ip': '127.0.0.1', 'protocol': 'tcp', 'mode': 'ingress'}
                        for key, value in PORTS.items()]
    if {m.get('target') for m in service['volumes']} != {'/data', '/etc/letsencrypt'}:
        raise RuntimeError('The candidate storage targets differ.')
    for mount in service['volumes']:
        if mount.get('type') != 'bind' or mount.get('read_only'):
            raise RuntimeError('The candidate storage type differs.')
        mount['source'] = str(folder / ('data' if mount['target'] == '/data' else 'letsencrypt'))
        mount.setdefault('bind', {})['create_host_path'] = False
    service['volumes'].append({'type': 'bind', 'source': str(guard), 'target': '/app/internal/certificate.js',
                               'read_only': True, 'bind': {'create_host_path': False}})
    network = current['NetworkSettings']['Networks']
    if set(network) != {'npm-nas_default'}:
        raise RuntimeError('The current NAS proxy network differs.')
    if set(service.get('networks', {})) != {'default'}:
        raise RuntimeError('The candidate service network differs.')
    result['networks'] = {'default': {'external': True, 'name': 'npm-nas_default'}}
    result['name'] = 'nas-npm-private-test'
    return result


def routes_in(database):
    with contextlib.closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)) as db:
        db.execute('PRAGMA query_only=ON')
        rows = db.execute('SELECT id,domain_names,forward_host,forward_port,access_list_id '
                          'FROM proxy_host WHERE is_deleted=0 AND enabled=1 ORDER BY id').fetchall()
    result = []
    for identity, names, host, port, acl in rows:
        names = json.loads(names)
        if (len(names) != 1 or not re.fullmatch(r'[A-Za-z0-9-]+\.sawdoctor\.uk', names[0])
                or names[0].lower() == 'soundspan.sawdoctor.uk' or host not in ('192.168.0.29', '192.168.0.220')):
            raise RuntimeError('An unexpected private-test route needs review.')
        result.append({'id': identity, 'domain': names[0], 'upstream': host, 'port': port, 'accessList': acl})
    if len(result) != 29 or len({r['domain'].lower() for r in result}) != 29:
        raise RuntimeError('The candidate no longer contains the 29 reviewed routes.')
    return result


def request_route(row, folder):
    headers = folder / ('headers-' + str(row['id']))
    hostname = row['domain'].lower()
    result = subprocess.run([
        'curl', '--disable', '--silent', '--show-error', '--noproxy', '*', '--cacert', CA_FILE,
        '--connect-timeout', '3', '--max-time', '8', '--connect-to',
        hostname + ':443:127.0.0.1:' + PORTS['443/tcp'],
        '--dump-header', str(headers), '--output', '/dev/null', '--write-out', '%{http_code}',
        'https://' + hostname + '/'], capture_output=True, timeout=12)
    data = headers.read_bytes() if headers.exists() else b''
    headers.unlink(missing_ok=True)
    status = result.stdout.decode().strip()
    code = int(status) if re.fullmatch(r'\d{3}', status) else 0
    return {**row, 'curlExit': result.returncode, 'httpStatus': code,
            'curlError': result.stderr.decode(errors='replace')[:800],
            'httpAuthChallenge': b'www-authenticate:' in data.lower(),
            'responseReceivedWithTrustedTls': result.returncode == 0 and code > 0,
            'needsAttention': result.returncode != 0 or code == 0 or code >= 500 or code == 404}


RENDER = r'''
import fs from 'node:fs';
import proxy from './internal/proxy-host.js';
import nginx from './internal/nginx.js';
import db from './db.js';
try {
  const access = {can: async () => ({permission_visibility: 'all'})};
  const rows = (await proxy.getAll(access, ['owner', 'certificate', 'access_list.[clients,items]'])).filter(h => h.enabled);
  if (rows.length !== 29 || rows.some(h => h.domain_names.some(n => n.toLowerCase() === 'soundspan.sawdoctor.uk'))) throw Error('Route count/retirement differs');
  await nginx.bulkGenerateConfigs('proxy_host', rows);
  for (const row of rows) {
    const text = fs.readFileSync('/data/nginx/proxy_host/' + row.id + '.conf', 'utf8');
    const host = text.match(/^\s*set\s+\$server\s+["']([^"']+)["'];/m);
    const port = text.match(/^\s*set\s+\$port\s+(\d+);/m);
    if (!host || host[1] !== row.forward_host || !port || Number(port[1]) !== row.forward_port) throw Error('Rendered upstream differs');
  }
  await nginx.test();
  await nginx.reload();
  console.log('NPM_PRIVATE_ROUTES_RENDERED=' + rows.length);
} catch (error) {
  console.error(error);
  process.exitCode = 1;
} finally {
  await db().destroy();
}
'''


def cleanup_trial(token, folder, work):
    trial = inspect(NAME)
    if trial is not None:
        if trial.get('Config', {}).get('Labels', {}).get(LABEL) != token:
            raise RuntimeError('An unrelated trial-named container was retained; working files were retained.')
        if ERROR_LOG is not None:
            try:
                logs = subprocess.run(['docker', 'logs', '--tail', '120', trial['Id']], capture_output=True, timeout=15)
                previous = ERROR_LOG.read_bytes() if ERROR_LOG.exists() else b''
                ERROR_LOG.write_bytes((previous + b'\nCONTAINER LOG:\n' + logs.stdout + b'\n' + logs.stderr)[-1024**2:])
                ERROR_LOG.chmod(0o600)
            except (OSError, subprocess.TimeoutExpired):
                pass  # An optional log capture must never prevent cleanup.
        command('docker', 'rm', '-f', trial['Id'], timeout=25, allowed=(0, 1))
    if inspect(NAME) is not None:
        raise RuntimeError('The temporary proxy could not be removed; working files were retained.')
    shutil.rmtree(folder)
    (work / 'trial.yaml').unlink(missing_ok=True)


def run_trial(complete, routes, restore):
    global ERROR_LOG
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in routes.run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the NAS.')
    routes.mounted(routes.APP, routes.APP_UUID)
    routes.mounted(routes.BACKUP, routes.BACKUP_UUID)
    candidate = routes.APP / 'compose/npm-restore/cutover'
    work = routes.APP / 'compose/npm-restore/proxy-test'
    routes.no_links(work)
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(work.glob('.payload-*')):
        raise RuntimeError('An earlier private-test working copy remains; it was retained for review.')
    if any(p.name not in ('result.json', 'private-error.log') for p in work.iterdir()):
        raise RuntimeError('The private-test folder contains unexpected files; they were retained.')
    if (work / 'result.json').exists() and json.loads(routes.read(work / 'result.json')).get('format') != FORMAT:
        raise RuntimeError('An unrelated private-test result was retained.')
    ERROR_LOG = work / 'private-error.log'
    routes.no_links(ERROR_LOG)
    routes.no_links(work / 'result.json')
    with routes.locked(routes.LOCK):
        current = routes.target_bindings()
        record = json.loads(routes.read(candidate / 'prepared.json'))
        if (record.get('format') != complete.FORMAT or record.get('status') != 'complete-offline-not-activated'
                or record.get('nasImage') != current['Image'] or record.get('retiredService') != complete.RETIRED):
            raise RuntimeError('The accepted complete offline candidate identity differs.')
        inventory_path = candidate / 'payload-inventory.json'
        expected = json.loads(routes.read(inventory_path, 16 * 1024**2))
        if (sha(routes.read(inventory_path, 16 * 1024**2)) != record['payloadInventorySha256']
                or complete.file_digest(candidate / 'ready.yaml') != record['readySha256']
                or complete.inventory(candidate / 'payload') != expected):
            raise RuntimeError('The immutable offline candidate changed; it was retained.')
        rows = routes_in(candidate / 'payload/data/database.sqlite')
        if shutil.disk_usage(routes.APP).free < 1024**3 or inspect(NAME) is not None:
            raise RuntimeError('Private-test space/name preflight failed; existing state was retained.')
        for port in PORTS.values():
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', int(port)))
        source = command('docker', 'exec', 'npm-nas', 'cat', '/app/internal/certificate.js')
        held = hold_certificate_worker(source)
        command('docker', 'exec', '-i', 'npm-nas', 'node', '--input-type=module', '--check', stdin=held)
        model = json.loads(command('docker', 'compose', '-p', 'npm-nas', '-f', str(candidate / 'ready.yaml'), 'config', '--format', 'json'))
        token = uuid.uuid4().hex
        folder = Path(tempfile.mkdtemp(prefix='.payload-', dir=work))
        before = (current['Id'], current['Image'], current['State']['Status'], current['State']['StartedAt'])
        reports = []
        removed = False
        try:
            say('Copying only the bounded NPM trial payload; no image pull or build...')
            command('rsync', '-aHAX', '--numeric-ids', '--one-file-system', '--no-devices', '--no-specials',
                    '--', str(candidate / 'payload') + '/', str(folder) + '/', timeout=180)
            if complete.inventory(folder) != expected:
                raise RuntimeError('The temporary trial copy differs from the accepted candidate.')
            guard = folder / 'certificate-held.js'
            guard.write_bytes(held)
            guard.chmod(0o644)
            definition = work / 'trial.yaml'
            routes.no_links(definition)
            definition.write_text(yaml.safe_dump(complete.escaped(trial_model(model, current, folder, guard)), sort_keys=False))
            definition.chmod(0o600)
            rendered = json.loads(command('docker', 'compose', '-p', 'nas-npm-private-test', '-f', str(definition), 'config', '--format', 'json'))
            wanted = trial_model(model, current, folder, guard)
            if rendered.get('services') != wanted.get('services') or rendered.get('networks') != wanted.get('networks'):
                raise RuntimeError('The private-test Compose round trip differs.')
            say('Starting the temporary proxy on 127.0.0.1 only; certificate creation/renewal held...')
            command('docker', 'compose', '-p', 'nas-npm-private-test', '-f', str(definition), 'run', '--rm', '--no-deps',
                    '--service-ports', '--pull', 'never', '--name', NAME, '--label', LABEL + '=' + token, '-d', 'npm', timeout=120)
            trial = inspect(NAME)
            wanted_ports = {k: [{'HostIp': '127.0.0.1', 'HostPort': v}] for k, v in PORTS.items()}
            if (not trial or trial['Image'] != current['Image'] or trial['Config'].get('Labels', {}).get(LABEL) != token
                    or trial['HostConfig'].get('PortBindings') != wanted_ports or not trial['HostConfig'].get('AutoRemove')
                    or trial['HostConfig']['RestartPolicy']['Name'] not in ('', 'no')):
                raise RuntimeError('The temporary container does not match its private test definition.')
            actual_binds = {m['Destination']: (m.get('Source'), m.get('RW')) for m in trial.get('Mounts', [])}
            if actual_binds != {'/data': (str(folder / 'data'), True), '/etc/letsencrypt': (str(folder / 'letsencrypt'), True),
                                '/app/internal/certificate.js': (str(guard), False)}:
                raise RuntimeError('The temporary data/renewal-guard mounts differ; trial was stopped.')
            deadline = time.monotonic() + 100
            while time.monotonic() < deadline:
                ping = subprocess.run(['curl', '--disable', '--silent', '--noproxy', '*', '--max-time', '2', '--output', '/dev/null',
                                       '--write-out', '%{http_code}', 'http://127.0.0.1:' + PORTS['81/tcp'] + '/api/'],
                                      capture_output=True, timeout=4)
                if ping.returncode == 0 and ping.stdout.strip() == b'200':
                    break
                if inspect(NAME) is None:
                    raise RuntimeError('The temporary proxy exited before becoming ready.')
                time.sleep(2)
            else:
                raise RuntimeError('The temporary proxy backend did not become ready within its time bound.')
            logged = subprocess.run(['docker', 'logs', NAME], capture_output=True, timeout=20)
            log = logged.stdout + logged.stderr
            if b'NAS PRIVATE TRIAL: CERTIFICATE RENEWAL HELD' not in log:
                raise RuntimeError('The running backend renewal hold was not confirmed.')
            say('Regenerating the 29 trial proxy files from the reviewed database, including its access-list relations...')
            output = command('docker', 'exec', '-i', '--workdir', '/app', NAME, 'node', '--input-type=module', stdin=RENDER.encode(), timeout=90)
            if b'NPM_PRIVATE_ROUTES_RENDERED=29' not in output:
                raise RuntimeError('The regenerated trial route count was not confirmed.')
            for row in rows:
                result = request_route(row, folder)
                reports.append(result)
                say(row['domain'] + ': HTTPS=' + ('trusted' if result['responseReceivedWithTrustedTls'] else 'FAILED')
                    + '; HTTP=' + str(result['httpStatus']) + '; ACL=' + str(row['accessList'])
                    + '; curlExit=' + str(result['curlExit'])
                    + ('; needs review' if result['needsAttention'] else ''))
        finally:
            cleanup_trial(token, folder, work)
            removed = True
        now = inspect('npm-nas')
        if not now or (now['Id'], now['Image'], now['State']['Status'], now['State']['StartedAt']) != before:
            raise RuntimeError('The existing NAS proxy changed during the test; investigate before handover.')
        if complete.inventory(candidate / 'payload') != expected:
            raise RuntimeError('The immutable candidate changed during the test; investigate before handover.')
        attention = sum(r['needsAttention'] for r in reports)
        result = {'format': FORMAT, 'status': 'needs-attention' if attention else 'route-responses-checked',
                  'testedUtc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                  'sourceSnapshot': record['sourceSnapshot'], 'automaticRenewalHeld': True,
                  'certificateCreateAndRenewHeld': True, 'temporaryContainerRemoved': removed,
                  'temporaryPayloadRemoved': not folder.exists(), 'existingNasProxyUnchanged': True,
                  'candidateUnchanged': True, 'routes': reports,
                  'limits': 'No browser login, WebSocket/media playback, valid-password or external-client Fail2ban test. ACL bypasses need policy review.'}
        (work / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        (work / 'result.json').chmod(0o600)
        say('PRIVATE NAS PROXY TEST FINISHED: ' + str(len(reports)) + ' routes checked; ' + str(attention) + ' need attention.')
        say('Temporary proxy and copied data removed. Existing NAS NPM, OptiPlex, public routing, jail configuration and prepared candidate retained.')
        say('Access-list IDs/responses are reported; browser credentials, external bans and media/WebSocket behaviour are separate acceptance checks.')
        say('Small result record: ' + str(work / 'result.json'))


def load_helpers():
    url = 'https://raw.githubusercontent.com/sawdoctor/nas-backup-auth/' + HELPER_PIN + '/scripts/prepare-nas-npm-cutover.py'
    with urllib.request.urlopen(url, timeout=30) as response:
        data = response.read(128 * 1024 + 1)
    if sha(data) != HELPER_SHA:
        raise RuntimeError('The pinned offline-candidate validator failed its integrity check.')
    complete = types.ModuleType('_accepted_npm_candidate')
    exec(compile(data, url, 'exec'), complete.__dict__)
    return complete, *complete.load_helpers()


def main():
    if sys.argv[1:] == ['--worker']:
        def interrupted(signum, frame):
            raise RuntimeError('The bounded private trial was interrupted; cleanup was requested.')
        signal.signal(signal.SIGTERM, interrupted)
        try:
            run_trial(*load_helpers())
        finally:
            path = Path(sys.argv[0])
            if path.parent == Path('/run') and path.name.startswith('nas-npm-private-'):
                path.unlink(missing_ok=True)
        return
    if sys.argv[1:] or os.geteuid() != 0 or b'inet 192.168.0.220/' not in command('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo and no arguments on the NAS.')
    if subprocess.run(['systemctl', 'is-active', '--quiet', 'nas-npm-proxy-test.service'], capture_output=True).returncode == 0:
        say('Private proxy test is already running; check its journal.')
        return
    source = globals().get('INSTALL_SOURCE')
    if not isinstance(source, str) or not source.startswith('#!/usr/bin/env python3\n'):
        raise RuntimeError('The complete pinned test installer source is required.')
    fd, path = tempfile.mkstemp(prefix='nas-npm-private-', suffix='.py', dir='/run')
    with os.fdopen(fd, 'w') as stream:
        os.fchmod(stream.fileno(), 0o700)
        stream.write(source)
    try:
        subprocess.run(['systemctl', 'reset-failed', 'nas-npm-proxy-test.service'], capture_output=True)
        command('systemd-run', '--unit=nas-npm-proxy-test', '--collect', '--description=Test NAS NPM privately with certificate operations held',
                '--property=Type=exec', '--property=UMask=0077', '--property=RuntimeMaxSec=8min',
                '--property=TimeoutStopSec=45s', '--property=KillMode=mixed', '/usr/bin/python3', path, '--worker')
    except BaseException:
        Path(path).unlink(missing_ok=True)
        raise
    say('Private NAS proxy test started in systemd. Closing SSH is safe.')
    say('Progress: sudo journalctl -u nas-npm-proxy-test.service -n 40 --no-pager -o cat')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        if isinstance(error, RuntimeError):
            raise SystemExit('STOP: ' + str(error))
        raise SystemExit('STOP: Private proxy test failed (' + type(error).__name__ + '); private details withheld.')
