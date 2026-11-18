#!/usr/bin/env python3
"""Return certificate renewal to stock NAS NPM, on its current local image."""
import copy
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tarfile
import time
import uuid
import yaml

APP = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
BASE = APP / 'compose/production-cutover'
WORK = BASE / 'npm-renewal-handover'
SELF = WORK / 'worker.py'
STATE = WORK / 'state.json'
UNIT = 'nas-production-npm-renewal.service'
FORMAT = 'sawdoctor-current-nas-npm-renewal-v1'
HOST = BASE / 'host-job-handover/worker.py'
HOST_SHA = 'ab8994740c921b82e2fa206d2f6242b313c4160fb33b38d1e4dfa38a9ef5576f'
STACK = APP / 'appdata/dockmon/stacks/npm-nas/compose.yaml'
STACK_SHA = '839bc9a022a7030b9cae01862fc9dd359119115a5c6286842cb2e3cb778b6cbf'
GUARD = APP / 'compose/npm-restore/lan-activation/certificate-held.js'
GUARD_SHA = '168fa9d2db74b89db6571dae662f0e014f32fa7be471d2cfa9813bffceb16f27'
MODULE = '/app/internal/certificate.js'
IMAGE = 'sha256:c41c0570868e42a76cf0d406e47c0156704a7ca45feba0971aeb87dead4ec58f'
DATABASE = APP / 'appdata/npm/data/database.sqlite'


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def say(value):
    print(value, flush=True)


def controllers():
    require(not any(p.is_symlink() for p in (HOST, *HOST.parents)) and sha(HOST.read_bytes()) == HOST_SHA,
            'The accepted current host-job controller differs.')
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('renewal_host_jobs', HOST)
    host = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host)
    return host, *host.controllers()


def run(native, *args, stdin=None, timeout=60):
    result = subprocess.run(args, input=stdin, capture_output=True, timeout=timeout)
    if result.returncode:
        native.atomic(WORK / 'private-command-error.log', (result.stdout + b'\n' + result.stderr)[-1024**2:])
        raise RuntimeError('A NAS renewal handover command failed; bounded diagnostics retained privately.')
    return result.stdout


def compose(native, path, *args, project='npm-nas'):
    return run(native, 'docker', 'compose', '-p', project, '-f', str(path), *args, timeout=180)


def candidate_model(original):
    result = copy.deepcopy(original)
    require(set(result.get('services', {})) == {'npm'}, 'The current NPM service definition differs.')
    service = result['services']['npm']
    require(service.get('container_name') == 'npm-nas', 'The existing NPM container owner differs.')
    volumes = service.get('volumes', [])
    matches = [m for m in volumes if isinstance(m, dict) and m.get('target') == MODULE]
    require(len(matches) == 1 and matches[0].get('type') == 'bind'
            and matches[0].get('source') == str(GUARD) and matches[0].get('read_only') is True,
            'The current certificate-module hold differs; no proxy changed.')
    service['volumes'] = [m for m in volumes if m is not matches[0]]
    require({m.get('target') for m in service['volumes']} == {'/data', '/etc/letsencrypt'},
            'Unexpected NPM persistent mounts require review.')
    return result


def unstarted_model(candidate, name):
    result = copy.deepcopy(candidate)
    require(set(result.get('networks', {})) == {'default'}
            and result['networks']['default'].get('name') == 'npm-nas_default',
            'The existing NPM network definition differs.')
    result['services']['npm']['container_name'] = name
    # The production stack still owns this existing network. The unstarted
    # comparison project must reference it, never adopt/recreate it.
    result['networks'] = {'default': {'external': True, 'name': 'npm-nas_default'}}
    return result


def env(values):
    result = {}
    for value in values or []:
        key, sep, data = value.partition('=')
        require(sep and key not in result, 'The current NPM environment is ambiguous.')
        result[key] = data
    return result


def runtime_signature(row):
    config = copy.deepcopy(row['Config'])
    hostname = config.get('Hostname')
    if hostname and re.fullmatch(r'[a-f0-9]{12}', hostname):
        config['Hostname'] = '<generated>'
    config['Env'] = env(config.get('Env'))
    config['Labels'] = {k: v for k, v in (config.get('Labels') or {}).items()
                        if not k.startswith('com.docker.compose.')}
    host = copy.deepcopy(row['HostConfig'])
    # Inspect exposes the same mounts through two Docker API representations.
    # Compare the actual bound roots/flags below instead of their input syntax.
    host.pop('Binds', None)
    host.pop('Mounts', None)
    for key in ('Dns', 'DnsOptions', 'DnsSearch'):
        if host.get(key) in (None, []):
            host[key] = []
    mounts = sorted([{k: m.get(k) for k in ('Type', 'Source', 'Destination', 'RW', 'Propagation')}
                     for m in row['Mounts'] if m['Destination'] != MODULE], key=lambda m: m['Destination'])
    networks = {name: {'id': n['NetworkID'], 'aliases': sorted(set(a for a in n.get('Aliases') or []
                    if a not in (row['Id'], row['Id'][:12], row['Name'].lstrip('/')))),
                     'ipam': n.get('IPAMConfig'), 'links': n.get('Links'), 'driver': n.get('DriverOpts')}
                for name, n in row['NetworkSettings']['Networks'].items()}
    # The stable npm-nas name is explicitly checked separately; the unstarted
    # probe necessarily has its own unique container name.
    return {'image': row['Image'], 'config': config, 'host': host, 'mounts': mounts, 'networks': networks}


def verify_runtime(before, after, unstarted=False):
    left, right = runtime_signature(before), runtime_signature(after)
    if unstarted:
        require(after.get('State', {}).get('Status') == 'created' and not after.get('State', {}).get('Running'),
                'Only an unstarted probe may omit assigned network IDs.')
        require(set(left['networks']) == set(right['networks']), 'The unstarted probe network names differ.')
        for name in left['networks']:
            # Docker assigns endpoint IDs/addresses when the container starts.
            right['networks'][name]['id'] = left['networks'][name]['id']
    # Every stable existing name must be represented on the recreated container.
    for name, old_net in before['NetworkSettings']['Networks'].items():
        old = set(old_net.get('Aliases') or []) - {before['Id'], before['Id'][:12], before['Name'].lstrip('/')}
        new = set(after['NetworkSettings']['Networks'].get(name, {}).get('Aliases') or [])
        require(old <= new, 'A stable NPM network alias would change.')
    differences = [key for key in left if left[key] != right[key]]
    detail = {group: sorted(k for k in set(left[group]) | set(right[group])
                           if left[group].get(k) != right[group].get(k))
              for group in ('config', 'host') if group in differences}
    if 'config' in differences and left['config'].get('Env') != right['config'].get('Env'):
        old_env, new_env = left['config'].get('Env', {}), right['config'].get('Env', {})
        detail['environmentNames'] = sorted(k for k in set(old_env) | set(new_env) if old_env.get(k) != new_env.get(k))
    require(not differences, 'The current NPM runtime differs beyond the certificate hold (field names only): '
            + json.dumps({'groups': differences, 'fields': detail}, sort_keys=True))


def stock_file(native, container, path):
    data = run(native, 'docker', 'cp', container + ':' + path, '-', timeout=30)
    require(len(data) <= 2 * 1024**2, 'The stock-image file copy exceeded its bound.')
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as archive:
        files = [m for m in archive.getmembers() if m.isfile()]
        require(len(files) == 1 and files[0].size <= 1024**2, 'The stock-image file copy is not one bounded regular file.')
        return archive.extractfile(files[0]).read()


def verify_stock(source):
    text = source.decode()
    require('NAS_NPM_TRIAL_CERT_HOLD' not in text and 'NAS PRIVATE TRIAL:' not in text
            and 'Let\'s Encrypt Renewal Timer initialized' in text
            and 'internalCertificate.processExpiringHosts' in text and 'setInterval(' in text
            and re.search(r'\brenew\s*:\s*async\s*\(access,\s*data\)', text),
            'The current image stock renewal implementation requires separate review.')


def database_snapshot():
    connection = sqlite3.connect(DATABASE.as_uri() + '?mode=ro', uri=True, timeout=5)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute('PRAGMA query_only=ON')
        result = {}
        for table in ('user', 'user_permission', 'auth', 'access_list', 'access_list_auth', 'access_list_client',
                      'proxy_host', 'redirection_host', 'dead_host', 'stream', 'setting', 'certificate'):
            columns = {r[1] for r in connection.execute('PRAGMA table_info(' + table + ')')}
            if not columns:
                continue
            values = []
            for row in connection.execute('SELECT * FROM ' + table):
                item = dict(row)
                if table == 'certificate':
                    for field in ('expires_on', 'modified_on'):
                        item.pop(field, None)
                values.append(item)
            result[table] = sorted(values, key=lambda r: json.dumps(r, sort_keys=True, default=str))
        return result
    finally:
        connection.close()


def certificate_status():
    connection = sqlite3.connect(DATABASE.as_uri() + '?mode=ro', uri=True, timeout=5)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute('PRAGMA query_only=ON')
        proxies = [dict(r) for r in connection.execute(
            'SELECT id,domain_names,certificate_id FROM proxy_host WHERE is_deleted=0 AND enabled=1 AND certificate_id>0')]
        certificates = {r['id']: dict(r) for r in connection.execute(
            'SELECT id,provider,expires_on,domain_names FROM certificate WHERE is_deleted=0')}
    finally:
        connection.close()
    now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    result = []
    for identity in sorted({r['certificate_id'] for r in proxies}):
        item = certificates[identity]
        expires = dt.datetime.fromisoformat(item['expires_on'])
        result.append({'id': identity, 'domainNames': json.loads(item['domain_names']),
                       'expires': item['expires_on'], 'expired': expires < now,
                       'proxyIds': [r['id'] for r in proxies if r['certificate_id'] == identity]})
    return result


def api_ready(native):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        result = subprocess.run(['curl', '--disable', '--noproxy', '*', '-sS', '--max-time', '3',
                                 '-o', '/dev/null', '-w', '%{http_code}', 'http://192.168.0.220:10081/api/'],
                                capture_output=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip() == b'200':
            run(native, 'docker', 'exec', 'npm-nas', 'nginx', '-t', timeout=20)
            return
        time.sleep(2)
    raise RuntimeError('NPM backend did not recover within its bounded readiness check.')


def logs(native, since):
    # Docker's stderr stream can contain the same application log lines.
    result2 = subprocess.run(['docker', 'logs', '--since', since, 'npm-nas'], capture_output=True, timeout=20)
    require(result2.returncode == 0, 'The current NPM startup log is unavailable.')
    data = (result2.stdout + result2.stderr)[-1024**2:]
    native.atomic(WORK / 'private-renewal.log', data)
    return data.decode(errors='replace')


def proxy_checks(context):
    choices = {'homepage.sawdoctor.uk', 'request.sawdoctor.uk', 'seerr.sawdoctor.uk'}
    names = sorted({name for item in context if not item['expired'] for name in item['domainNames'] if name in choices})
    result = {}
    for name in names:
        probe = subprocess.run(['curl', '--disable', '--noproxy', '*', '--resolve', name + ':10443:192.168.0.220',
                                '--max-time', '6', '-sS', '-o', '/dev/null', '-w', '%{http_code}',
                                'https://' + name + ':10443/'], capture_output=True, timeout=8)
        code = probe.stdout.decode().strip()
        if probe.returncode == 0 and re.fullmatch(r'[234][0-9]{2}', code):
            result[name] = code
    return result


def finish_proof(native, record):
    api_ready(native)
    current = native.catalog()['npm-nas']
    require(current['Image'] == record['image'] and all(m['Destination'] != MODULE for m in current['Mounts']),
            'The current NPM image/stock module binding differs.')
    checksum = run(native, 'docker', 'exec', 'npm-nas', 'node', '-e',
                   "console.log(require('crypto').createHash('sha256').update(require('fs').readFileSync('/app/internal/certificate.js')).digest('hex'))").decode().strip()
    require(checksum == record['stockModuleSha256'], 'The running certificate module differs from the current image stock file.')
    deadline = time.monotonic() + 40
    while True:
        text = logs(native, record['startedUtc'])
        if "Let's Encrypt Renewal Timer initialized" in text and 'Renewing SSL certs expiring within' in text:
            break
        require(time.monotonic() < deadline, 'Stock renewal timer startup evidence is not yet available.')
        time.sleep(2)
    record.update(phase='renewal-owner-active', renewalTimerObserved=True)
    native.atomic(STATE, record)
    say('NAS NPM STOCK RENEWAL OWNER ACTIVE. Same image, storage, routes and access controls retained.')


def worker(host, boot, backup, native):
    with native.lock(BASE / '.run.lock'):
        record = json.loads(native.read(STATE)) if STATE.exists() else None
        with boot.boot_lock(native):
            main, rows = backup.preflight(native)
            require(json.loads(native.read(host.STATE)).get('phase') == 'complete', 'The reviewed host schedules are not complete.')
            before = rows['npm-nas']
            require(before['State']['Running'] and before['Image'] == IMAGE, 'The reviewed current NPM image changed; no pull or downgrade.')
            native.held(main['proof'])
            if record:
                require(record.get('format') == FORMAT and record.get('cutoverId') == main['proof']['cutoverId'],
                        'The retained renewal handover identity differs.')
                require(sha(native.read(STACK)) == record['afterStackSha256'], 'The accepted renewal stack changed.')
                finish_proof(native, record)
            else:
                require(sha(native.read(STACK)) == STACK_SHA and sha(native.read(GUARD)) == GUARD_SHA,
                        'The reviewed current NPM stack/hold changed; retained.')
                require(any(m.get('Source') == str(GUARD) and m.get('Destination') == MODULE and not m.get('RW')
                            for m in before['Mounts']), 'The reviewed current module hold is unavailable.')
                old_text = native.read(STACK)
                original = yaml.safe_load(old_text)
                require('hostname' not in original['services']['npm'], 'An explicitly configured hostname requires its own comparison.')
                candidate = candidate_model(original)
                new_text = yaml.safe_dump(candidate, sort_keys=False).encode()
                require(yaml.safe_load(new_text) == candidate, 'The candidate NPM definition did not round-trip.')
                proposed = WORK / 'candidate.yaml'
                native.atomic(proposed, new_text)
                reference = candidate['services']['npm']['image']
                require(json.loads(run(native, 'docker', 'image', 'inspect', reference))[0]['Id'] == IMAGE,
                        'The existing NPM image tag points elsewhere; no image change requested.')
                probe_name = 'npm-renewal-probe-' + uuid.uuid4().hex[:12]
                probe_model = unstarted_model(candidate, probe_name)
                probe_path = WORK / 'unstarted-probe.yaml'
                native.atomic(probe_path, yaml.safe_dump(probe_model, sort_keys=False).encode())
                probe_id = None
                try:
                    compose(native, probe_path, 'create', '--no-build', '--pull', 'never', 'npm', project=probe_name)
                    probe = json.loads(run(native, 'docker', 'inspect', probe_name))[0]
                    probe_id = probe['Id']
                    require(probe['State']['Status'] == 'created' and not probe['State']['Running'],
                            'The preflight probe must remain unstarted.')
                    verify_runtime(before, probe, unstarted=True)
                    stock = stock_file(native, probe_id, MODULE)
                    verify_stock(stock)
                    run(native, 'docker', 'exec', '-i', 'npm-nas', 'node', '--input-type=module', '--check', stdin=stock)
                finally:
                    if not probe_id:
                        cleanup = subprocess.run(['docker', 'inspect', probe_name], capture_output=True, timeout=20)
                        if cleanup.returncode == 0:
                            existing = json.loads(cleanup.stdout)[0]
                            require(existing['State']['Status'] == 'created'
                                    and existing['Config'].get('Labels', {}).get('com.docker.compose.project') == probe_name,
                                    'An unrecognized preflight container was retained.')
                            probe_id = existing['Id']
                    if probe_id:
                        run(native, 'docker', 'rm', '-v', probe_id, timeout=30)
                say('UNSTARTED NPM PREFLIGHT PASSED. Current image/configuration and stock certificate worker verified; probe removed.')
                protected = database_snapshot()
                native.atomic(WORK / 'protected-before.json', protected)
                native.atomic(WORK / 'compose.before.yaml', old_text)
                context = certificate_status()
                say('CURRENT ENABLED-PROXY CERTIFICATES: ' + json.dumps(context, sort_keys=True))
                baseline_https = proxy_checks(context)
                require(baseline_https, 'No selected existing HTTPS route passed its pre-change certificate check.')
                say('EXISTING LOCAL HTTPS ROUTES: ' + json.dumps(baseline_https, sort_keys=True))
                record = {'format': FORMAT, 'cutoverId': main['proof']['cutoverId'], 'phase': 'prepared',
                          'image': IMAGE, 'beforeStackSha256': sha(old_text), 'afterStackSha256': sha(new_text),
                          'stockModuleSha256': sha(stock), 'originalExpiredIds': [r['id'] for r in context if r['expired']],
                          'startedUtc': dt.datetime.now(dt.timezone.utc).isoformat()}
                native.atomic(STATE, record)
                others = {name: (r['Id'], r['Image'], r['State'].get('StartedAt')) for name, r in rows.items() if name != 'npm-nas'}
                native.atomic(STACK, new_text, mode=0o600)
                try:
                    compose(native, STACK, 'up', '-d', '--no-deps', '--force-recreate', '--no-build', '--pull', 'never', 'npm')
                    after = native.catalog()['npm-nas']
                    require(after['Name'] == '/npm-nas', 'The recreated NPM owner differs.')
                    verify_runtime(before, after)
                    finish_proof(native, record)
                    require(proxy_checks(context) == baseline_https, 'A selected existing HTTPS route changed after NPM handover.')
                    require(database_snapshot() == protected, 'A protected NPM route/user/access/certificate setting changed; current data retained.')
                    require({name: (r['Id'], r['Image'], r['State'].get('StartedAt'))
                             for name, r in native.catalog().items() if name != 'npm-nas'} == others,
                            'An unrelated application changed during NPM handover; current data retained.')
                except BaseException:
                    # Restore only the Compose/guard owner, never overwrite keys,
                    # the database, or certificates already legitimately renewed.
                    native.atomic(STACK, old_text, mode=0o600)
                    compose(native, STACK, 'up', '-d', '--no-deps', '--force-recreate', '--no-build', '--pull', 'never', 'npm')
                    record['phase'] = 'needs-review-held-proxy-restored'
                    native.atomic(STATE, record)
                    raise
        # Native NPM owns the normal sequential renewal batch. Never run a
        # second certbot/force-renew process or hold BACKUP_LOCK while waiting.
        deadline = time.monotonic() + 300
        while True:
            current = certificate_status()
            expired = [r for r in current if r['expired']]
            text = logs(native, record['startedUtc'])
            if not expired or 'Completed SSL cert renew process' in text or time.monotonic() >= deadline:
                break
            say('NPM automatic renewal is running; enabled-proxy expired certificate IDs: ' + json.dumps([r['id'] for r in expired]))
            time.sleep(15)
        record.update(phase='complete', currentCertificates=current, activeExpiredCertificates=expired,
                      normalRenewalPassFinished='Completed SSL cert renew process' in text,
                      sourceFrozen=True, forcedRenewalRequested=False)
        native.atomic(STATE, record)
    say('NAS NPM RENEWAL HANDOVER COMPLETE. Stock renewal timer active on the same current NAS image.')
    say('ENABLED-PROXY CERTIFICATE RESULT: ' + json.dumps(current, sort_keys=True))
    if expired:
        say('CERTIFICATE FOLLOW-UP: ' + json.dumps(expired, sort_keys=True))
        say('The stock timer remains active; existing expired-route certificates above still need their own outcome checked.')
    else:
        say('ALL ENABLED-PROXY CERTIFICATES CURRENT. No expired certificate remains referenced by an enabled proxy.')
    say('No Force SSL/HSTS, DNS, router, admin exposure, image update or certificate deletion requested. Source production remains frozen.')


def main():
    os.umask(0o077)
    host, boot, backup, native = controllers()
    native.safe(WORK)
    WORK.mkdir(mode=0o700, exist_ok=True)
    if sys.argv[1:] == ['--worker']:
        worker(host, boot, backup, native)
        return
    require(not sys.argv[1:] and globals().get('RESUME_APPROVED_NPM_RENEWAL') is True,
            'The approved NAS renewal handover flag is required.')
    source = globals().get('INSTALL_SOURCE')
    require(isinstance(source, str), 'The complete NAS renewal handover source is required.')
    with native.lock(BASE / '.run.lock'):
        if host.status(native, UNIT)['ActiveState'] in ('active', 'activating', 'deactivating'):
            say('The NAS renewal handover is already running.')
            return
        if SELF.exists():
            require(native.read(SELF) == source.encode(), 'A different existing renewal worker was retained.')
        else:
            native.atomic(SELF, source.encode(), mode=0o700)
        subprocess.run(['systemctl', 'reset-failed', UNIT], capture_output=True)
        native.run('systemd-run', '--unit=' + UNIT, '--collect', '--property=Type=exec', '--property=UMask=0077',
                   '--property=RuntimeMaxSec=20min', '--description=Restore stock current NAS NPM certificate renewal',
                   '/usr/bin/python3', '-u', str(SELF), '--worker')
    say('NAS NPM renewal handover started in systemd. Closing SSH is safe; NPM briefly recreates on its existing ports.')
    say('Progress: sudo journalctl -u ' + UNIT + ' -f -n 40 --no-pager -o cat')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        message = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        say('STOP: ' + message + ' Current certificates, data and source freeze retained.')
        raise SystemExit(1)
