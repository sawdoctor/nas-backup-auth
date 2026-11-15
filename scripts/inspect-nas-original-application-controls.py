#!/usr/bin/env python3
"""Compare frozen original application controls with current NAS settings.

Only bounded private temporary database copies and a sanitized report are
written. No application/service, live database, image or schedule is changed.
"""
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse

APP = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
BASE = APP / 'compose/production-cutover'
WORK = BASE / 'application-control-review'
SELF = WORK / 'worker.py'
BOOT = BASE / 'boot-handover/worker.py'
BOOT_SHA = '971ae70c0a6de64de1420ef7e26d1ec21f8861d8fa3c8b4eb2baeb5fd03f48ed'
UNIT = 'nas-original-application-controls.service'
FORMAT = 'sawdoctor-original-application-controls-v1'
MODES = ('missing_enabled', 'cutoff_enabled', 'upgrade_enabled')
DATABASES = {'houndarr': 'houndarr.db', 'uptime-kuma': 'kuma.db', 'wizarr': 'database/database.db'}
LIMIT = 512 * 1024**2
PORTS = {32400: 32400, 8989: 8989, 7878: 7878, 7879: 7879, 9696: 9696,
         1337: 1337, 5055: 5055, 8080: 8082, 8081: 8081, 8082: 8082,
         3002: 3002, 3001: 3001, 7330: 7330, 61208: 61208, 8765: 8765,
         8877: 8877, 5690: 5690, 8085: 8085, 13378: 13378, 5000: 5000,
         8484: 8484, 8084: 8084, 8086: 8086}


def say(value): print(value, flush=True)
def sha(body): return hashlib.sha256(body).hexdigest()


def controllers():
    sys.dont_write_bytecode = True
    if any(path.is_symlink() for path in (BOOT, *BOOT.parents)) or sha(BOOT.read_bytes()) != BOOT_SHA:
        raise RuntimeError('The accepted boot controller changed.')
    spec = importlib.util.spec_from_file_location('original_controls_boot', BOOT)
    boot = importlib.util.module_from_spec(spec); spec.loader.exec_module(boot)
    startup, release, backup, native = boot.controllers()
    return boot, backup, native


def current_database(row, relative, native):
    found = set()
    for mount in row['Mounts']:
        if mount.get('Type') != 'bind': continue
        root = Path(mount['Source']); native.safe(root)
        if not root.is_relative_to(APP / 'appdata'): continue
        choices = (root,) if root.is_file() and root.name == Path(relative).name else (root / relative,)
        for candidate in choices:
            native.safe(candidate)
            if candidate.is_file(): found.add(candidate)
    if len(found) != 1: raise RuntimeError('A current application database is missing or ambiguous.')
    return found.pop()


@contextlib.contextmanager
def database(path):
    with contextlib.closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=5)) as db:
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA query_only=ON'); db.execute('BEGIN')
        if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
            raise RuntimeError('A selected database failed integrity checking.')
        try: yield db
        finally: db.rollback()


def rows(db, table, required, optional=()):
    columns = {row[1] for row in db.execute('PRAGMA table_info("' + table + '")')}
    if not set(required) <= columns: raise RuntimeError('A selected application control schema changed.')
    fields = [*required, *(field for field in optional if field in columns)]
    result = [dict(row) for row in db.execute('SELECT ' + ','.join('"' + field + '"' for field in fields)
                                             + ' FROM "' + table + '" LIMIT 1001')]
    if len(result) > 1000: raise RuntimeError('A control table exceeds its review bound.')
    return result


def flag(value):
    if type(value) not in (int, bool) or value not in (0, 1):
        raise RuntimeError('A control is not an original boolean setting.')
    return bool(value)


def arr_identity(value):
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in ('http', 'https') or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise RuntimeError('An Arr endpoint needs private review.')
    if parsed.hostname in ('192.168.0.29', '192.168.0.220'):
        app = {7878: 'radarr', 7879: 'radarr4k', 8989: 'sonarr'}.get(parsed.port)
    else:
        app = {('radarr', 7878): 'radarr', ('radarr4k', 7878): 'radarr4k', ('sonarr', 8989): 'sonarr'}.get((parsed.hostname, parsed.port))
    if app is None or parsed.path.rstrip('/'):
        raise RuntimeError('An Arr endpoint is outside the three reviewed applications.')
    return app


def houndarr(original, current):
    fields = ('id', 'url', 'enabled', *MODES)
    old = {row['id']: row for row in rows(original, 'instances', fields)}
    now = {row['id']: row for row in rows(current, 'instances', fields)}
    result = []
    for identity in sorted(old.keys() | now.keys()):
        if identity not in old or identity not in now:
            result.append({'id': identity, 'sameInstance': False}); continue
        source, live = old[identity], now[identity]
        result.append({'id': identity, 'application': arr_identity(live['url']),
                       'sameInstance': arr_identity(source['url']) == arr_identity(live['url']),
                       'source': {field: flag(source[field]) for field in ('enabled', *MODES)},
                       'current': {field: flag(live[field]) for field in ('enabled', *MODES)}})
    return {'instances': result, 'preserveCurrentInstanceEnables': True}


def retarget(value):
    if not isinstance(value, str) or not value.startswith(('http://', 'https://')): return value
    parsed = urllib.parse.urlsplit(value)
    if parsed.hostname != '192.168.0.29' or parsed.port not in PORTS: return value
    if parsed.username or parsed.password: raise RuntimeError('A monitor endpoint needs private review.')
    return parsed._replace(netloc='192.168.0.220:' + str(PORTS[parsed.port])).geturl()


def kuma(original, current):
    monitors = ('id', 'name', 'type', 'active')
    extra = ('url', 'hostname', 'port')
    old = {row['id']: row for row in rows(original, 'monitor', monitors, extra)}
    now = {row['id']: row for row in rows(current, 'monitor', monitors, extra)}
    mismatches = []
    for identity in sorted(old.keys() | now.keys()):
        if identity not in old or identity not in now: mismatches.append(identity); continue
        expected = dict(old[identity]); expected.pop('active')
        if 'url' in expected: expected['url'] = retarget(expected['url'])
        if expected.get('hostname') == '192.168.0.29' and expected.get('port') in PORTS:
            expected['hostname'] = '192.168.0.220'; expected['port'] = PORTS[expected['port']]
        live = dict(now[identity]); live.pop('active')
        if expected != live: mismatches.append(identity)
    notify_fields = ('id', 'active', 'is_default', 'name', 'config')
    old_n = {row['id']: row for row in rows(original, 'notification', notify_fields)}
    now_n = {row['id']: row for row in rows(current, 'notification', notify_fields)}
    notification_mismatches = sorted(identity for identity in old_n.keys() | now_n.keys()
        if identity not in old_n or identity not in now_n
        or (old_n[identity]['name'], old_n[identity]['config']) != (now_n[identity]['name'], now_n[identity]['config']))
    links = lambda db: sorted((row['monitor_id'], row['notification_id'])
                             for row in rows(db, 'monitor_notification', ('monitor_id', 'notification_id')))
    return {'sourceActiveMonitorIds': sorted(key for key, row in old.items() if flag(row['active'])),
            'currentActiveMonitorIds': sorted(key for key, row in now.items() if flag(row['active'])),
            'monitorIdentityMismatchIds': mismatches,
            'sourceNotifications': [{'id': key, 'active': flag(row['active']), 'default': flag(row['is_default'])}
                                    for key, row in sorted(old_n.items())],
            'currentNotifications': [{'id': key, 'active': flag(row['active']), 'default': flag(row['is_default'])}
                                     for key, row in sorted(now_n.items())],
            'notificationIdentityMismatchIds': notification_mismatches,
            'sourceLinks': links(original), 'currentLinks': links(current)}


def environment(row, schedule=False):
    env = dict(item.split('=', 1) for item in row['Config'].get('Env', []) if '=' in item)
    names = ('SPEEDTEST_SCHEDULE',) if schedule else ('FLASK_SKIP_SCHEDULER', 'WIZARR_DISABLE_SCHEDULER')
    result = {}
    for name in names:
        value = env.get(name)
        if value is None: result[name] = 'not set'
        elif schedule:
            result[name] = value if len(value) <= 120 and re.fullmatch(r'[0-9*,/\s-]*', value) else 'value withheld; schedule review required'
        else: result[name] = value.lower() if value.lower() in ('', '0', '1', 'true', 'false') else 'value withheld'
    return result


def source_checks(native, raw, core):
    allowed = {str(PurePosixPath('data/support.' + name) / relative) + suffix
               for name, relative in DATABASES.items() for suffix in ('', '-wal')}
    checks = {}; native.safe(raw / 'SHA256SUMS')
    with (raw / 'SHA256SUMS').open(encoding='utf-8', errors='surrogateescape') as stream:
        for line in stream:
            if len(line) > 65536: raise RuntimeError('An original checksum record exceeds its bound.')
            name, digest = core.parse_checksum(line)
            if name in allowed:
                if name in checks: raise RuntimeError('An original application checksum is duplicated.')
                checks[name] = digest
    for name, relative in DATABASES.items():
        if str(PurePosixPath('data/support.' + name) / relative) not in checks:
            raise RuntimeError('An original application database checksum is unavailable: ' + name)
    return checks


def copy_member(source, target, size, digest):
    if not 0 <= size <= LIMIT: raise RuntimeError('An original database copy exceeds its bound.')
    if shutil.disk_usage(target.parent).free < size + 256 * 1024**2:
        raise RuntimeError('The bounded private database copy lacks its disk reserve.')
    value = hashlib.sha256(); received = 0
    with target.open('xb') as output:
        while block := source.read(1024**2):
            received += len(block)
            if received > size: raise RuntimeError('An original database copy exceeded its declared size.')
            output.write(block); value.update(block)
    if received != size or value.hexdigest() != digest:
        raise RuntimeError('An original database copy failed its frozen checksum.')


def frozen_databases(native, raw, proof, checks, folder):
    targets = {}
    for name in checks:
        relative = PurePosixPath(name)
        target = folder / relative.relative_to('data')
        target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        targets[name] = target
        candidate = raw / name; native.safe(candidate)
        if candidate.is_file() and candidate.stat().st_size <= LIMIT and native.digest(candidate) == checks[name]:
            with candidate.open('rb') as source: copy_member(source, target, candidate.stat().st_size, checks[name])
    missing = {name for name, target in targets.items() if not target.exists()}
    if missing:
        archive = native.BACKUP / 'migration/production-handover/frozen' / proof['cutoverId'] / 'export.tar.zst'
        native.safe(archive)
        if archive.stat().st_size != proof['archiveBytes']: raise RuntimeError('The retained verified frozen archive size differs.')
        say('Reading only original application databases/WAL from the retained frozen archive...')
        process = subprocess.Popen(['zstd', '-dc', '--', str(archive)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            with tarfile.open(fileobj=process.stdout, mode='r|') as source:
                for member in source:
                    name = str(PurePosixPath(member.name))
                    if name not in missing: continue
                    if not member.isfile(): raise RuntimeError('An original application database member is symbolic or special.')
                    with source.extractfile(member) as original:
                        copy_member(original, targets[name], member.size, checks[name])
                    missing.remove(name)
                    if not missing: break
            if missing: raise RuntimeError('A selected original application database member is unavailable.')
        finally:
            process.stdout.close()
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=10)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=10)
    return {name: folder / ('support.' + name) / relative for name, relative in DATABASES.items()}


def inspect(boot, backup, native):
    with boot.boot_lock(native):
        record = json.loads(native.read(boot.RECORD)); main = json.loads(native.read(native.STATE))
        accepted = json.loads(native.read(boot.ACCEPTED)); proof = main['proof']; native.validate_proof(proof)
        if record.get('phase') != 'complete' or record.get('cutoverId') != proof['cutoverId'] or accepted != {'format': boot.FORMAT, 'cutoverId': proof['cutoverId']}:
            raise RuntimeError('The accepted current NAS boot ownership differs.')
        for unit in ('nas-production-plex.service', 'nas-media-boot.service', 'nas-books.service'):
            status = backup.unit(native, unit)
            if status.get('ActiveState') != 'active' or status.get('Result') != 'success':
                raise RuntimeError('A current NAS boot owner has not completed: ' + unit)
        raw = Path(main['raw'])
        if raw != BASE / proof['cutoverId'] / 'incoming' or native.digest(raw / 'manifest.json') != proof['manifestSha256']:
            raise RuntimeError('The retained original source manifest differs.')
        manifest = json.loads(native.read(raw / 'manifest.json'))
        if any(manifest.get(key) != value for key, value in {'format': native.SOURCE_FORMAT, 'scope': 'production-frozen',
               'sourceHost': '192.168.0.29', 'sourceDockerStopped': True, 'cutoverId': proof['cutoverId']}.items()):
            raise RuntimeError('The original source capture is not the accepted common frozen point.')
        source = {row['Name'].lstrip('/'): row for row in manifest['containers']}; current = native.catalog()
        for name in (*DATABASES, 'speedtest-tracker'):
            if name not in source or name + '-nas' not in current: raise RuntimeError('An original/current support application is unavailable.')
        for name in DATABASES:
            descriptor = manifest['dataRoots'].get('support.' + name, {})
            if descriptor.get('snapshot') != 'data/support.' + name or descriptor.get('kind') != 'directory':
                raise RuntimeError('An original support database root needs review: ' + name)
            destination = '/data' if name in ('houndarr', 'wizarr') else '/app/data'
            binds = [mount for mount in source[name]['Mounts'] if mount['Destination'] == destination and mount.get('Type') == 'bind']
            if len(binds) != 1 or binds[0]['Source'] != descriptor.get('source'):
                raise RuntimeError('An original support database binding differs: ' + name)
        checks = source_checks(native, raw, native.helpers()['core'])
        results = {}
        with tempfile.TemporaryDirectory(prefix='.original-controls-', dir=WORK) as temporary:
            originals = frozen_databases(native, raw, proof, checks, Path(temporary))
            for name, compare in (('houndarr', houndarr), ('uptime-kuma', kuma)):
                try:
                    with database(originals[name]) as original, database(current_database(current[name + '-nas'], DATABASES[name], native)) as live:
                        results[name] = compare(original, live)
                except Exception as error: results[name] = {'notVerified': type(error).__name__}
                say(name.upper() + ': ' + json.dumps(results[name], sort_keys=True))
            name = 'wizarr'; result = {'sourceEnvironment': environment(source[name]), 'currentEnvironment': environment(current[name + '-nas'])}
            try:
                def ldap(db): return sorted(row['id'] for row in rows(db, 'ldap_configuration', ('id', 'enabled')) if flag(row['enabled']))
                with database(originals[name]) as original, database(current_database(current[name + '-nas'], DATABASES[name], native)) as live:
                    result.update({'sourceEnabledLdapIds': ldap(original), 'currentEnabledLdapIds': ldap(live)})
            except Exception as error: result['ldapNotVerified'] = type(error).__name__
            results[name] = result; say('WIZARR: ' + json.dumps(result, sort_keys=True))
        results['speedtest-tracker'] = {'source': environment(source['speedtest-tracker'], True),
                                       'current': environment(current['speedtest-tracker-nas'], True)}
        say('SPEEDTEST: ' + json.dumps(results['speedtest-tracker'], sort_keys=True))
        report = {'format': FORMAT, 'cutoverId': proof['cutoverId'], 'nasBootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                  'sourceFrozenUtc': proof['frozenUtc'], 'results': results}
        native.atomic(WORK / 'report.json', report)
    say('ORIGINAL APPLICATION CONTROL COMPARISON COMPLETE. No live settings, services, images or data changed.')
    say('Original/current flags and links only; credentials withheld. Private temporary database copies removed.')
    say('Tracearr original PostgreSQL controls and remaining host jobs/NPM renewal need separate review.')
    say('Small comparison record: ' + str(WORK / 'report.json'))


def main():
    os.umask(0o077); boot, backup, native = controllers(); native.safe(WORK)
    WORK.mkdir(mode=0o700, exist_ok=True)
    if sys.argv[1:] == ['--worker']:
        with native.lock(BASE / '.run.lock'): inspect(boot, backup, native)
        return
    if sys.argv[1:]: raise RuntimeError('Unsupported original-control review action.')
    source = globals().get('INSTALL_SOURCE')
    if not isinstance(source, str): raise RuntimeError('The complete reviewed source is required.')
    with native.lock(BASE / '.run.lock'):
        if backup.unit(native, UNIT).get('ActiveState') in ('active', 'activating', 'deactivating'):
            say('Original application control comparison is already running.'); return
        if SELF.exists() and native.read(SELF) != source.encode(): raise RuntimeError('A different review worker was retained.')
        if not SELF.exists(): native.atomic(SELF, source.encode(), mode=0o700)
        subprocess.run(['systemctl', 'reset-failed', UNIT], capture_output=True)
        native.run('systemd-run', '--unit=' + UNIT, '--collect', '--property=Type=exec', '--property=UMask=0077',
                   '--property=RuntimeMaxSec=40min', '--description=Compare original frozen application controls with current NAS settings',
                   '/usr/bin/python3', '-u', str(SELF), '--worker')
    say('Original/current application control comparison started in systemd. Closing SSH is safe.')
    say('Progress: sudo journalctl -u ' + UNIT + ' -f -n 30 --no-pager -o cat')


if __name__ == '__main__':
    try: main()
    except Exception as error:
        say('STOP: ' + type(error).__name__ + '. No application control was changed; inspect the selected source/schema before retrying.')
        raise SystemExit(1)
