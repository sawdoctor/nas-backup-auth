#!/usr/bin/env python3
"""Review remaining Kuma controls and locate HBA collection ownership.

No application or collector is restarted, and no schedule/alert is enabled.
Existing collector source is copied privately through the normal backup
remote so its implementation can be reviewed without publishing its text.
"""
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.parse

BASE = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6/compose/production-cutover')
ACCEPT = BASE / 'application-control-handover/accept-current.py'
ACCEPT_SHA = 'ab8fd08a176190e1ad5f68c51ed0197a7df9ff97d1e51192f743ae700b7211e7'
WORK = BASE / 'kuma-control-review'
SELF = WORK / 'worker.py'
UNIT = 'nas-kuma-hba-review.service'
FORMAT = 'sawdoctor-nas-kuma-hba-review-v1'
HBA = Path('/usr/local/sbin/hba-temp-collect')
REMOTE = 'gdrive:nas-backups/openmediavault/migration-review/nas-hba-temperature-20261116.txt'
SOURCE_ACTIVE = {2, 3, 6, 7, 8, 9, 10, 14, 16, 17, 18, 21, 22, 23, 24, 27, 28}
PAUSED_REPLACEMENTS = {22, 24}


def say(value): print(value, flush=True)


def controllers():
    sys.dont_write_bytecode = True
    if any(path.is_symlink() for path in (ACCEPT, *ACCEPT.parents)) or hashlib.sha256(ACCEPT.read_bytes()).hexdigest() != ACCEPT_SHA:
        raise RuntimeError('The accepted current-application helper changed.')
    spec = importlib.util.spec_from_file_location('accepted_current_apps', ACCEPT)
    accepted = importlib.util.module_from_spec(spec); spec.loader.exec_module(accepted)
    return accepted, *accepted.controllers()


def table(db, name, review):
    columns = [row[1] for row in db.execute('PRAGMA table_info("' + name + '")')]
    if not columns: raise RuntimeError('A required Kuma table is unavailable.')
    return review.rows(db, name, tuple(columns))


def origin(value):
    parsed = urllib.parse.urlsplit(value or '')
    if parsed.scheme not in ('http', 'https') or not parsed.hostname: return None
    return parsed.scheme + '://' + parsed.hostname + (':' + str(parsed.port) if parsed.port else '')


def desired_endpoint(source, review):
    result = {key: source.get(key) for key in ('url', 'hostname', 'port')}
    result['url'] = review.retarget(result['url'])
    if source['id'] == 6:
        parsed = urllib.parse.urlsplit(source.get('url') or '')
        if parsed.scheme != 'http' or parsed.hostname != '192.168.0.29' or parsed.port != 81 or parsed.username or parsed.password:
            raise RuntimeError('The original NPM monitor is not the reviewed private endpoint.')
        result['url'] = parsed._replace(netloc='192.168.0.220:10081').geturl()
    if result['hostname'] == '192.168.0.29' and result['port'] in review.PORTS:
        result['hostname'] = '192.168.0.220'; result['port'] = review.PORTS[result['port']]
    return result


def summarize_kuma(source, current, review):
    old = {row['id']: row for row in source['monitor']}; now = {row['id']: row for row in current['monitor']}
    if old.keys() != now.keys() or len(now) != 25:
        raise RuntimeError('The reviewed set of 25 Kuma monitors changed; current monitors retained.')
    if {key for key, row in old.items() if review.flag(row['active'])} != SOURCE_ACTIVE:
        raise RuntimeError('Original active-monitor choices differ from the native review.')
    entries = []
    for identity in sorted(old):
        a, b = old[identity], now[identity]
        if (a['name'], a['type']) != (b['name'], b['type']): raise RuntimeError('A current monitor identity changed.')
        target = desired_endpoint(a, review)
        extra_changes = sorted(key for key in a.keys() & b.keys() if key not in {'active', 'url', 'hostname', 'port'} and a[key] != b[key])
        desired_active = identity in SOURCE_ACTIVE - PAUSED_REPLACEMENTS
        reason = 'source active on NAS' if desired_active else 'originally paused'
        if identity in PAUSED_REPLACEMENTS: reason = 'Jellyfin absent / Dockhand deferred; retain paused'
        statuses = b.get('accepted_statuscodes')
        try:
            parsed = json.loads(statuses) if isinstance(statuses, str) else statuses
            statuses = parsed if isinstance(parsed, list) and all(isinstance(item, str) and re.fullmatch(r'[0-9-]{3,7}', item) for item in parsed) else 'withheld/unavailable'
        except (ValueError, TypeError): statuses = 'withheld/unavailable'
        entries.append({'id': identity, 'name': b['name'][:100], 'type': b['type'], 'currentActive': review.flag(b['active']),
            'proposedActive': desired_active, 'reason': reason,
            'currentOrigin': origin(b.get('url')), 'proposedOrigin': origin(target['url']),
            'endpointChanges': sorted(key for key in target if b.get(key) != target[key]),
            'otherSourceCurrentDifferentFieldNames': extra_changes,
            'httpMethod': b.get('method') if b.get('method') in ('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE') else 'not reported',
            'acceptedStatusCodes': statuses, 'ignoreTls': bool(b.get('ignore_tls'))})
    old_n = {row['id']: row for row in source['notification']}; now_n = {row['id']: row for row in current['notification']}
    notifications = []
    for identity in sorted(old_n.keys() | now_n.keys()):
        a, b = old_n.get(identity), now_n.get(identity)
        if a is None or b is None: raise RuntimeError('An existing notification identity changed.')
        notifications.append({'id': identity, 'sameNameAndConfiguration': (a['name'], a['config']) == (b['name'], b['config']),
            'sourceActive': review.flag(a['active']), 'currentActive': review.flag(b['active']),
            'sourceDefault': review.flag(a['is_default']), 'currentDefault': review.flag(b['is_default'])})
    links = lambda rows: sorted([row['monitor_id'], row['notification_id']] for row in rows)
    return {'monitors': entries, 'notifications': notifications, 'sourceNotificationLinks': links(source['monitor_notification']),
        'currentNotificationLinks': links(current['monitor_notification']), 'proposedActiveIds': sorted(SOURCE_ACTIVE - PAUSED_REPLACEMENTS)}


def bounded(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 512 * 1024: return None
    return path.read_bytes()


def unit_info(native, backup, name):
    result = backup.unit(native, name)
    extra = native.run('systemctl', 'show', '--no-pager', '--full', name, '-p', 'UnitFileState',
        '-p', 'ConditionResult', '-p', 'DropInPaths', '-p', 'NextElapseUSecRealtime')
    result.update(line.split('=', 1) for line in extra.splitlines() if '=' in line)
    return result


def hba_review(native, backup):
    source = bounded(HBA)
    paths = {Path('/etc/crontab')}
    for folder in ('/etc/cron.d', '/var/spool/cron/crontabs', '/var/lib/openmediavault/cron.d',
                   '/etc/cron.hourly', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.monthly'):
        paths.update(Path(folder).glob('*'))
    for folder in ('/etc/systemd/system', '/usr/local/lib/systemd/system', '/usr/lib/systemd/system'):
        paths.update(path for path in Path(folder).rglob('*') if path.suffix == '.conf' or path.suffix in ('.service', '.timer'))
    matched = []; private = []
    if source is not None:
        private.append({'path': str(HBA), 'sha256': hashlib.sha256(source).hexdigest(), 'content': source.decode(errors='replace')})
    for path in sorted(paths):
        body = bounded(path)
        if body is None or not any(term in body for term in (b'hba-temp-collect', b'/run/hba-temp')): continue
        text = body.decode(errors='replace'); active_lines = [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith(('#', ';'))]
        matched.append({'path': str(path), 'sha256': hashlib.sha256(body).hexdigest(),
            'activeReference': any('hba-temp-collect' in line or '/run/hba-temp' in line for line in active_lines)})
        private.append({'path': str(path), 'sha256': hashlib.sha256(body).hexdigest(), 'content': text})
    units = {}
    for row in matched:
        path = Path(row['path']); name = path.name
        if path.suffix == '.conf' and path.parent.name.endswith('.service.d'): name = path.parent.name.removesuffix('.d')
        if name.endswith(('.service', '.timer')):
            units[name] = unit_info(native, backup, name)
            if name.endswith('.service'): units[name.removesuffix('.service') + '.timer'] = unit_info(native, backup, name.removesuffix('.service') + '.timer')
    cache = Path('/run/hba-temp'); data = bounded(cache)
    value = data.decode(errors='replace').strip() if data is not None else ''
    result = {'collectorPresent': source is not None, 'collectorSha256': hashlib.sha256(source).hexdigest() if source is not None else None,
        'cachePresent': data is not None, 'cacheValue': value if re.fullmatch(r'[0-9. Cc°-]{1,30}', value) else 'withheld/unavailable',
        'cacheModifiedUtc': datetime.datetime.fromtimestamp(cache.stat().st_mtime, datetime.timezone.utc).isoformat() if data is not None else None,
        'schedulerReferences': matched, 'relatedUnits': units, 'cron': unit_info(native, backup, 'cron.service'),
        'collectorExecutedByReview': False}
    payload = (json.dumps({'format': FORMAT, 'purpose': 'private HBA collector and matching schedule source review', 'files': private}, indent=2) + '\n').encode()
    if len(payload) > 2 * 1024**2: raise RuntimeError('The selected private collector review exceeds its bound.')
    native.atomic(WORK / 'hba-private-source.json', payload)
    return result, payload


def worker(accepted, resume, old, review, boot, backup, native, startup):
    with boot.boot_lock(native):
        main, current = backup.preflight(native)
        completion = json.loads(native.read(accepted.STATE))
        if completion.get('format') != accepted.FORMAT or completion.get('phase') != 'complete' or completion.get('cutoverId') != main['proof']['cutoverId']:
            raise RuntimeError('The current application handover is not complete.')
        raw = Path(main['raw']); proof = main['proof']
        if native.digest(raw / 'manifest.json') != proof['manifestSha256']: raise RuntimeError('The retained original manifest differs.')
        checks = review.source_checks(native, raw, native.helpers()['core'])
        checks = {key: value for key, value in checks.items() if key.startswith('data/support.uptime-kuma/')}
        with tempfile.TemporaryDirectory(prefix='.kuma-original-', dir=WORK) as temporary:
            original = review.frozen_databases(native, raw, proof, checks, Path(temporary))['uptime-kuma']
            current_path = review.current_database(current['uptime-kuma-nas'], 'kuma.db', native)
            with review.database(original) as source_db, review.database(current_path) as live_db:
                source = {name: table(source_db, name, review) for name in ('monitor', 'notification', 'monitor_notification')}
                live = {name: table(live_db, name, review) for name in source}
            result = summarize_kuma(source, live, review)
        result['currentImage'] = current['uptime-kuma-nas']['Config']['Image']
        result['currentImageId'] = current['uptime-kuma-nas']['Image']
        native.atomic(WORK / 'kuma-review.json', {'format': FORMAT, 'cutoverId': proof['cutoverId'], **result})
        say('KUMA SCOPED REVIEW (no controls changed): ' + json.dumps(result, sort_keys=True))
        hba, payload = hba_review(native, backup)
        native.atomic(WORK / 'hba-review.json', hba)
        say('HBA SCHEDULING REVIEW (collector not executed): ' + json.dumps(hba, sort_keys=True))
    # Existing backup remote only; no settings/credentials/sharing changed.
    result = subprocess.run(['rclone', '--config', '/root/.config/rclone/rclone.conf', 'copyto', str(WORK / 'hba-private-source.json'), REMOTE,
        '--tpslimit', '2', '--retries', '2'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
    say('PRIVATE HBA SOURCE REVIEW: uploaded=' + str(result.returncode == 0) + '; SHA256=' + hashlib.sha256(payload).hexdigest())
    say('KUMA/HBA REVIEW COMPLETE. No app/collector execution, alert or schedule activation, container change, data restore or global cron release.')


def main():
    os.umask(0o077); args = controllers(); accepted, resume, old, review, boot, backup, native, startup = args
    native.safe(WORK); WORK.mkdir(mode=0o700, exist_ok=True)
    if sys.argv[1:] == ['--worker']:
        with native.lock(BASE / '.run.lock'): worker(*args)
        return
    if sys.argv[1:]: raise RuntimeError('Unexpected review arguments.')
    source = globals().get('INSTALL_SOURCE')
    if not isinstance(source, str): raise RuntimeError('The complete review source is required.')
    with native.lock(BASE / '.run.lock'):
        if backup.unit(native, UNIT).get('ActiveState') in ('active', 'activating', 'deactivating'):
            say('The scoped review is already running.'); return
        if SELF.exists() and native.read(SELF) != source.encode(): raise RuntimeError('A different existing review helper was retained.')
        if not SELF.exists(): native.atomic(SELF, source.encode(), mode=0o700)
        subprocess.run(['systemctl', 'reset-failed', UNIT], capture_output=True)
        native.run('systemd-run', '--unit=' + UNIT, '--collect', '--property=Type=exec', '--property=UMask=0077', '--property=RuntimeMaxSec=10min',
            '--description=Review original Kuma controls and NAS HBA collector scheduling', '/usr/bin/python3', '-u', str(SELF), '--worker')
    say('Scoped Kuma/HBA review started. Closing SSH is safe.')
    say('Progress: sudo journalctl -u ' + UNIT + ' -f -n 20 --no-pager -o cat')


if __name__ == '__main__':
    try: main()
    except Exception as error:
        say('STOP: ' + type(error).__name__ + '. Review incomplete; current applications and schedules retained.'); raise SystemExit(1)
