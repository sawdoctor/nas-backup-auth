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
import stat
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
CURRENT_PIN = '13907d84037563a84d221f0c9032628efc35cc6d'
CURRENT_SHA = '256dd678f45c1da6143625b16319884a1ecf8775c6068edefb64a2ebf326ae8f'
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


def environment(values):
    result = {}
    for value in values or []:
        key, separator, data = value.partition('=')
        if not separator or key in result:
            raise RuntimeError('The current proxy environment has an unexpected form.')
        result[key] = data
    return result


def trial_model(model, current, folder, guard):
    result = copy.deepcopy(model)
    if set(result.get('services', {})) != {'npm'} or set(result.get('networks', {})) != {'default'}:
        raise RuntimeError('The candidate service/network structure differs.')
    service = result['services']['npm']
    if service.get('container_name') != 'npm-nas':
        raise RuntimeError('The candidate proxy name differs.')
    # Compose config JSON escapes dollars for replay. Use actual runtime values
    # for configured env/labels/commands, then escape once when writing YAML.
    config = current['Config']
    active_env = environment(config.get('Env'))
    for key, value in service.get('environment', {}).items():
        if key not in active_env:
            if value is not None:
                raise RuntimeError('A configured environment variable is absent from the current proxy.')
        else:
            service['environment'][key] = active_env[key]
    for key in service.get('labels', {}):
        if key not in config.get('Labels', {}):
            raise RuntimeError('A configured label is absent from the current proxy.')
        service['labels'][key] = config['Labels'][key]
    for field, runtime in (('command', 'Cmd'), ('entrypoint', 'Entrypoint')):
        if service.get(field) is not None:
            if config.get(runtime) is None:
                raise RuntimeError('A configured command differs from the current proxy.')
            service[field] = config[runtime]
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


def compose_comparable(model):
    """Remove only observed optional zero/default fields, never settings."""
    result = copy.deepcopy({key: model.get(key) for key in ('services', 'networks')})
    for service in result['services'].values():
        service.setdefault('command', None)
        service.setdefault('entrypoint', None)
        for mount in service.get('volumes', []):
            if mount.get('type') == 'bind' and isinstance(mount.get('bind'), dict):
                if mount['bind'].get('create_host_path') is False:
                    del mount['bind']['create_host_path']
                if not mount['bind']:
                    del mount['bind']
    for network in result['networks'].values():
        if network.get('ipam') == {}:
            del network['ipam']
    return result


def difference_paths(a, b, path=''):
    if type(a) is not type(b):
        return [path]
    if isinstance(a, dict):
        found = []
        for key in sorted(set(a) | set(b)):
            child = path + '/' + key
            found += [child] if key not in a or key not in b else difference_paths(a[key], b[key], child)
        return found
    if isinstance(a, list):
        if len(a) != len(b):
            return [path + '/length']
        return [p for i, (x, y) in enumerate(zip(a, b)) for p in difference_paths(x, y, path + '/' + str(i))]
    return [] if a == b else [path]


def validate_compose(wanted, rendered, escape):
    # The native JSON output is itself replayable Compose data, including $$.
    before, after = compose_comparable(escape(wanted)), compose_comparable(rendered)
    changes = difference_paths(before, after)
    if changes:
        raise RuntimeError('The private-test Compose round trip differs at ' + ', '.join(p[:180] for p in changes[:10]) + '; values withheld.')


def routes_in(database, current=False):
    with contextlib.closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)) as db:
        db.execute('PRAGMA query_only=ON')
        rows = db.execute('SELECT id,domain_names,forward_host,forward_port,access_list_id '
                          'FROM proxy_host WHERE is_deleted=0 AND enabled=1 ORDER BY id').fetchall()
    result = []
    for identity, names, host, port, acl in rows:
        names = json.loads(names)
        if (len(names) != 1 or not re.fullmatch(r'[A-Za-z0-9-]+\.sawdoctor\.uk', names[0])
                or names[0].lower() in (('soundspan.sawdoctor.uk', 'chaptarr.sawdoctor.uk') if current else ('soundspan.sawdoctor.uk',))
                or host not in ('192.168.0.29', '192.168.0.220')):
            raise RuntimeError('An unexpected private-test route needs review.')
        result.append({'id': identity, 'domain': names[0], 'upstream': host, 'port': port, 'accessList': acl})
    count = 28 if current else 29
    if len(result) != count or len({r['domain'].lower() for r in result}) != count:
        raise RuntimeError('The candidate no longer contains the ' + str(count) + ' reviewed routes.')
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


def error_log_offset(folder):
    path = folder / 'data/logs/proxy-host-2_error.log'
    if not path.exists():
        return 0
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise RuntimeError('The temporary Usenet error log is not a regular file.')
    return info.st_size


def fresh_usenet_errors(folder, offset):
    path = folder / 'data/logs/proxy-host-2_error.log'
    if not path.exists():
        return [], offset
    with path.open('rb') as stream:
        info = os.fstat(stream.fileno())
        if path.is_symlink() or not stat.S_ISREG(info.st_mode):
            raise RuntimeError('The temporary Usenet error log changed type.')
        stream.seek(max(offset if info.st_size >= offset else 0, info.st_size - 16384))
        data = stream.read(16384)
        end = stream.tell()
    if data and ERROR_LOG is not None:
        previous = ERROR_LOG.read_bytes() if ERROR_LOG.exists() else b''
        ERROR_LOG.write_bytes((previous + b'\nNEW USENET NGINX ERRORS:\n' + data)[-1024**2:])
        ERROR_LOG.chmod(0o600)
    categories = (
        ('could not be resolved', 'dns-resolution'),
        ('host not found', 'dns-resolution'),
        ('no resolver defined', 'resolver-not-configured'),
        ('connect() failed', 'upstream-connect-failed'),
        ('upstream timed out', 'upstream-timeout'),
        ('upstream prematurely closed connection', 'upstream-closed-connection'),
        ('no live upstreams', 'no-live-upstreams'),
        ('upstream sent invalid header', 'invalid-upstream-header'),
        ('SSL_do_handshake', 'upstream-tls-handshake'),
    )
    summaries = []
    for line in data.decode(errors='replace').splitlines()[-40:]:
        summary = {'categories': sorted({value for needle, value in categories if needle in line}),
                   'referencesOriginalDockerName': bool(re.search(r'\busenet-ultimate\b(?!-nas)', line)),
                   'referencesNasIp': '192.168.0.220' in line}
        if not summary['categories']:
            summary['categories'] = ['other-nginx-error']
        if summary not in summaries:
            summaries.append(summary)
    return summaries, end


def diagnose_usenet(row, folder, offset):
    if (row['id'], row['domain'].lower(), row['upstream'], row['port'], row['accessList']) != (
            2, 'usenet.sawdoctor.uk', '192.168.0.220', 1337, 0):
        raise RuntimeError('The focused Usenet route identity differs.')
    attempts = []
    started = time.monotonic()
    for attempt in (1, 2):
        if attempt == 2:
            time.sleep(2)  # Diagnostic comparison after reload, not a production delay.
        result = request_route(row, folder)
        errors, offset = fresh_usenet_errors(folder, offset)
        attempts.append({**result, 'attempt': attempt, 'elapsedMs': round((time.monotonic() - started) * 1000),
                         'newNginxErrors': errors})
        say('USENET ATTEMPT ' + str(attempt) + ': HTTPS=' + ('trusted' if result['responseReceivedWithTrustedTls'] else 'FAILED')
            + '; HTTP=' + str(result['httpStatus']) + '; curlExit=' + str(result['curlExit'])
            + '; newNginxErrors=' + json.dumps(errors, separators=(',', ':')))
    return {**attempts[-1], 'attempts': attempts}


WORKER_READINESS = r'''
function nginxWorkers(procRoot = '/proc') {
  const result = new Set();
  for (const pid of fs.readdirSync(procRoot).filter(name => /^\d+$/.test(name))) {
    try {
      const command = fs.readFileSync(procRoot + '/' + pid + '/cmdline', 'utf8').replace(/\0/g, ' ').trim();
      if (!command.startsWith('nginx: worker process')) continue;
      const status = fs.readFileSync(procRoot + '/' + pid + '/stat', 'utf8');
      const fields = status.slice(status.lastIndexOf(')') + 2).trim().split(/\s+/);
      if (!/^\d+$/.test(fields[19] || '')) throw Error('Nginx worker start identity unavailable');
      result.add(pid + ':' + fields[19]);
    } catch (error) {
      if (!['ENOENT', 'ESRCH'].includes(error.code)) throw error;
    }
  }
  return result;
}
async function waitForNginxWorkers(before, options = {}) {
  if (!before.size) throw Error('No baseline Nginx workers were identified');
  const read = options.read || (() => nginxWorkers());
  const now = options.now || Date.now;
  const pause = options.pause || (ms => new Promise(resolve => setTimeout(resolve, ms)));
  const deadline = now() + (options.timeoutMs || 15000);
  while (now() < deadline) {
    const after = read();
    if (after.size && [...before].every(token => !after.has(token))) return;
    await pause(50);
  }
  throw Error('New Nginx workers did not replace the old generation within the readiness bound');
}
'''


RENDER = r'''
import fs from 'node:fs';
import proxy from './internal/proxy-host.js';
import nginx from './internal/nginx.js';
import db from './db.js';
''' + WORKER_READINESS + r'''
const expectedRouteCount = 29;
const retiredDomains = new Set(["soundspan.sawdoctor.uk"]);
try {
  const access = {can: async () => ({permission_visibility: 'all'})};
  const rows = (await proxy.getAll(access, ['owner', 'certificate', 'access_list.[clients,items]'])).filter(h => h.enabled);
  if (rows.length !== expectedRouteCount || rows.some(h => h.domain_names.some(n => retiredDomains.has(n.toLowerCase())))) throw Error('Route count/retirement differs');
  await nginx.bulkGenerateConfigs('proxy_host', rows);
  for (const row of rows) {
    const text = fs.readFileSync('/data/nginx/proxy_host/' + row.id + '.conf', 'utf8');
    const host = text.match(/^\s*set\s+\$server\s+["']([^"']+)["'];/m);
    const port = text.match(/^\s*set\s+\$port\s+(\d+);/m);
    if (!host || host[1] !== row.forward_host || !port || Number(port[1]) !== row.forward_port) throw Error('Rendered upstream differs');
  }
  await nginx.test();
  const workersBeforeReload = nginxWorkers();
  await nginx.reload();
  await waitForNginxWorkers(workersBeforeReload);
  console.log('NPM_PRIVATE_NEW_WORKERS_READY');
  console.log('NPM_PRIVATE_ROUTES_RENDERED=' + rows.length);
} catch (error) {
  console.error(error);
  process.exitCode = 1;
} finally {
  await db().destroy();
}
'''


def render_code(current=False):
    return (RENDER.replace('const expectedRouteCount = 29;', 'const expectedRouteCount = 28;', 1)
            .replace('const retiredDomains = new Set(["soundspan.sawdoctor.uk"]);',
                     'const retiredDomains = new Set(["soundspan.sawdoctor.uk","chaptarr.sawdoctor.uk"]);', 1)) if current else RENDER


def validate_current_candidate(candidate, record, current, stage, source, complete, routes, restore):
    if ({p.name for p in candidate.iterdir()} != stage.CONTENTS or record.get('format') != stage.FORMAT
            or record.get('status') != 'current-offline-not-activated' or record.get('nasImage') != current['Image']
            or record.get('retiredDomains') != stage.RETIRED or record.get('counts', {}).get('proxy_host') != 28
            or record.get('shelfmarkAudio', {}).get('certificateId') != 86):
        raise RuntimeError('The accepted current 28-route candidate identity differs.')
    metadata = {name: sha(routes.read(candidate / name, 64 * 1024**2 if name == 'source-database.sqlite' else 16 * 1024**2))
                for name in sorted(stage.CONTENTS - {'payload'})}
    ready = record.get('sourceExport', {})
    if (ready.get('format') != stage.EXPORT_FORMAT or ready.get('createdUtc') != record.get('sourceSnapshot')
            or metadata['source-manifest.json'] != ready.get('manifestSha256')
            or metadata['source-inventory.json'] != ready.get('inventorySha256')
            or metadata['source-database.sqlite'] != record.get('sourceDatabaseSha256')):
        raise RuntimeError('The preserved current source NPM metadata differs.')
    manifest = json.loads(routes.read(candidate / 'source-manifest.json'))
    if (manifest.get('sourceHost') != '192.168.0.29' or manifest.get('container', {}).get('Image') != source.SOURCE_IMAGE
            or manifest.get('counts') != record['counts'] or manifest.get('shelfmarkAudio') != record['shelfmarkAudio']):
        raise RuntimeError('The current NPM source report changed.')
    with contextlib.closing(sqlite3.connect((candidate / 'source-database.sqlite').as_uri() + '?mode=ro', uri=True)) as original, \
            contextlib.closing(sqlite3.connect((candidate / 'payload/data/database.sqlite').as_uri() + '?mode=ro', uri=True)) as adjusted:
        changes = routes.edits(routes.routes(original))
        if changes != record.get('changes'):
            raise RuntimeError('The reviewed current 21-address edit plan changed.')
        routes.compare_all(original, adjusted, changes)
    counts, shelfmark, checked = source.validate_policy(candidate / 'payload/data/database.sqlite', candidate / 'payload')
    if (counts != record['counts'] or shelfmark != record['shelfmarkAudio']
            or checked != record.get('checkedCertificateKeyPairs')):
        raise RuntimeError('The current NPM policy/certificate report changed.')
    stored, host, model = complete.live_stack(routes, restore, current)
    if (str(host) != record.get('existingStackPath') or sha(stored['text'].encode()) != record.get('existingStackSha256')
            or sha(json.dumps(stored['env'], sort_keys=True).encode()) != record.get('existingStackEnvSha256')):
        raise RuntimeError('The live NAS stack changed since current-candidate preparation.')
    return metadata


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


def run_trial(complete, routes, restore, usenet_only=False, current_tools=None):
    global ERROR_LOG
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in routes.run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the NAS.')
    routes.mounted(routes.APP, routes.APP_UUID)
    routes.mounted(routes.BACKUP, routes.BACKUP_UUID)
    fresh = current_tools is not None
    candidate = routes.APP / ('compose/npm-restore/cutover-current' if fresh else 'compose/npm-restore/cutover')
    work = routes.APP / ('compose/npm-restore/proxy-test-current' if fresh else
                        'compose/npm-restore/proxy-test-usenet' if usenet_only else 'compose/npm-restore/proxy-test')
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
        metadata_before = None
        if fresh:
            stage, source_validator = current_tools
        elif (record.get('format') != complete.FORMAT or record.get('status') != 'complete-offline-not-activated'
                or record.get('nasImage') != current['Image'] or record.get('retiredService') != complete.RETIRED):
            raise RuntimeError('The accepted complete offline candidate identity differs.')
        inventory_path = candidate / 'payload-inventory.json'
        expected = json.loads(routes.read(inventory_path, 16 * 1024**2))
        if (sha(routes.read(inventory_path, 16 * 1024**2)) != record['payloadInventorySha256']
                or complete.file_digest(candidate / 'ready.yaml') != record['readySha256']
                or complete.inventory(candidate / 'payload') != expected):
            raise RuntimeError('The immutable offline candidate changed; it was retained.')
        if fresh:
            metadata_before = validate_current_candidate(candidate, record, current, stage, source_validator, complete, routes, restore)
        rows = routes_in(candidate / 'payload/data/database.sqlite', current=fresh)
        if usenet_only:
            rows = [row for row in rows if row['id'] == 2 and row['domain'].lower() == 'usenet.sawdoctor.uk']
            if len(rows) != 1:
                raise RuntimeError('The reviewed Usenet route is unavailable.')
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
            copied = complete.inventory(folder)
            if fresh and copied != expected:
                restored = stage.restore_copied_modes(folder, expected, copied)
                if restored:
                    say('Restored ' + str(restored) + ' exact source modes in the disposable trial copy; rechecking...')
                    copied = complete.inventory(folder)
            if copied != expected:
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
            validate_compose(wanted, rendered, complete.escaped)
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
            if environment(trial['Config'].get('Env')) != environment(current['Config'].get('Env')):
                raise RuntimeError('The temporary proxy environment differs; trial was stopped and private values withheld.')
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
            offset = error_log_offset(folder) if usenet_only else 0
            route_count = 28 if fresh else 29
            say('Regenerating the ' + str(route_count) + ' trial proxy files and waiting for new Nginx workers...')
            output = command('docker', 'exec', '-i', '--workdir', '/app', NAME, 'node', '--input-type=module', stdin=render_code(fresh).encode(), timeout=90)
            if (('NPM_PRIVATE_ROUTES_RENDERED=' + str(route_count)).encode() not in output
                    or b'NPM_PRIVATE_NEW_WORKERS_READY' not in output):
                raise RuntimeError('The regenerated trial route count was not confirmed.')
            say('New Nginx worker generation is ready; starting strict HTTPS route checks.')
            for row in rows:
                result = diagnose_usenet(row, folder, offset) if usenet_only else request_route(row, folder)
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
        if fresh:
            metadata_after = {name: sha(routes.read(candidate / name, 64 * 1024**2 if name == 'source-database.sqlite' else 16 * 1024**2))
                              for name in metadata_before}
            if metadata_after != metadata_before:
                raise RuntimeError('The accepted current candidate metadata changed during the test.')
        attention = sum(r['needsAttention'] for r in reports)
        result = {'format': FORMAT, 'status': 'needs-attention' if attention else 'route-responses-checked',
                  'testedUtc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                  'sourceSnapshot': record['sourceSnapshot'], 'automaticRenewalHeld': True,
                  'certificateCreateAndRenewHeld': True, 'temporaryContainerRemoved': removed,
                  'temporaryPayloadRemoved': not folder.exists(), 'existingNasProxyUnchanged': True,
                  'candidateUnchanged': True, 'routes': reports,
                  'focusedUsenetDiagnostic': usenet_only,
                  'currentCandidate': fresh, 'candidatePath': str(candidate), 'newNginxWorkerGenerationReady': True,
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


def load_current_helpers():
    url = 'https://raw.githubusercontent.com/sawdoctor/nas-backup-auth/' + CURRENT_PIN + '/scripts/prepare-nas-current-npm.py'
    with urllib.request.urlopen(url, timeout=30) as response:
        data = response.read(128 * 1024 + 1)
    if sha(data) != CURRENT_SHA:
        raise RuntimeError('The pinned current-candidate validator failed its integrity check.')
    stage = types.ModuleType('_accepted_current_npm_candidate')
    exec(compile(data, url, 'exec'), stage.__dict__)
    source, complete, old_private, routes, restore = stage.load_helpers()
    return complete, routes, restore, (stage, source)


def main():
    if sys.argv[1:] in (['--worker'], ['--worker-usenet'], ['--worker-current']):
        def interrupted(signum, frame):
            raise RuntimeError('The bounded private trial was interrupted; cleanup was requested.')
        signal.signal(signal.SIGTERM, interrupted)
        try:
            if sys.argv[1:] == ['--worker-current']:
                complete, routes, restore, current_tools = load_current_helpers()
                run_trial(complete, routes, restore, current_tools=current_tools)
            else:
                run_trial(*load_helpers(), usenet_only=sys.argv[1:] == ['--worker-usenet'])
        finally:
            path = Path(sys.argv[0])
            if path.parent == Path('/run') and path.name.startswith('nas-npm-private-'):
                path.unlink(missing_ok=True)
        return
    if sys.argv[1:] or os.geteuid() != 0 or b'inet 192.168.0.220/' not in command('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo and no arguments on the NAS.')
    usenet_only = globals().get('USENET_ONLY') is True
    fresh = globals().get('CURRENT_CANDIDATE') is True
    if fresh and usenet_only:
        raise RuntimeError('Choose either the current 28-route test or the earlier focused diagnostic.')
    unit = 'nas-npm-current-test' if fresh else 'nas-npm-usenet-test' if usenet_only else 'nas-npm-proxy-test'
    for active in ('nas-npm-proxy-test', 'nas-npm-usenet-test', 'nas-npm-current-test'):
        if subprocess.run(['systemctl', 'is-active', '--quiet', active + '.service'], capture_output=True).returncode == 0:
            say('A private proxy test is already running; check its journal.')
            return
    source = globals().get('INSTALL_SOURCE')
    if not isinstance(source, str) or not source.startswith('#!/usr/bin/env python3\n'):
        raise RuntimeError('The complete pinned test installer source is required.')
    fd, path = tempfile.mkstemp(prefix='nas-npm-private-', suffix='.py', dir='/run')
    with os.fdopen(fd, 'w') as stream:
        os.fchmod(stream.fileno(), 0o700)
        stream.write(source)
    try:
        subprocess.run(['systemctl', 'reset-failed', unit + '.service'], capture_output=True)
        command('systemd-run', '--unit=' + unit, '--collect', '--description=Test NAS NPM privately with certificate operations held',
                '--property=Type=exec', '--property=UMask=0077', '--property=RuntimeMaxSec=8min',
                '--property=TimeoutStopSec=45s', '--property=KillMode=mixed', '/usr/bin/python3', path,
                '--worker-current' if fresh else '--worker-usenet' if usenet_only else '--worker')
    except BaseException:
        Path(path).unlink(missing_ok=True)
        raise
    say(('Current 28-route private proxy test' if fresh else 'Focused Usenet proxy test' if usenet_only else 'Private NAS proxy test')
        + ' started in systemd. Closing SSH is safe.')
    say('Progress: sudo journalctl -u ' + unit + '.service -n 30 --no-pager -o cat')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        if isinstance(error, RuntimeError):
            raise SystemExit('STOP: ' + str(error))
        raise SystemExit('STOP: Private proxy test failed (' + type(error).__name__ + '); private details withheld.')
