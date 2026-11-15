#!/usr/bin/env python3
"""Read current NAS staging switches; no configuration or service changes.

Only allowlisted flags, counts, endpoint hosts and lifecycle metadata are
printed. Application credentials, notification bodies and full configs stay
private. Current upgraded containers and user edits are authoritative.
"""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import urllib.parse
import xml.etree.ElementTree as ET

APP = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
BASE = APP / 'compose/production-cutover'
UNITS = Path('/etc/systemd/system')
DROPIN = '96-sawdoctor-production-import.conf'
RECOVERY = Path('/usr/local/sbin/nas-media-recovery')
RECOVERY_SHA = '618eb118dece842df2657b9f586fe64cebf1acbda5dc02361c01e99d9b575b2d'
FLAGS = ('enabled', 'missing_enabled', 'cutoff_enabled', 'upgrade_enabled')
TRACE_SETTINGS = ('pollerEnabled', 'mobileEnabled', 'backupScheduleType',
                  'imagePrecacheEnabled', 'pluginUpdateCheckEnabled', 'serverUpdateCheckEnabled')


def run(*args, input=None, timeout=20):
    result = subprocess.run(args, input=input, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('A read-only query was unavailable; command output was not disclosed.')
    return result.stdout.strip()


def show(label, function):
    try: value = function()
    except Exception as error: value = {'notVerified': type(error).__name__}
    print(label + ': ' + json.dumps(value, sort_keys=True), flush=True)


def read_json(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024**2:
        raise RuntimeError('A bounded migration record is unavailable.')
    return json.loads(path.read_bytes())


def database_path(row, relatives):
    found = set()
    for bind in row.get('Mounts', []):
        if bind.get('Type') != 'bind': continue
        source = Path(bind['Source']).resolve(strict=True)
        if not source.is_relative_to(APP / 'appdata'): continue
        choices = [source] if source.is_file() and source.name in {Path(x).name for x in relatives} else []
        if source.is_dir(): choices += [source / relative for relative in relatives]
        for candidate in choices:
            if candidate.is_file():
                resolved = candidate.resolve(strict=True)
                if resolved.is_relative_to(APP / 'appdata'): found.add(resolved)
    if len(found) != 1: raise RuntimeError('The current bound database is missing or ambiguous.')
    return found.pop()


@contextlib.contextmanager
def database(row, relatives):
    path = database_path(row, relatives)
    with contextlib.closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=3)) as db:
        db.execute('PRAGMA query_only=ON'); db.execute('BEGIN')
        try: yield db
        finally: db.rollback()


def columns(db, table):
    return {item[1] for item in db.execute('PRAGMA table_info("' + table + '")')}


def counts(db, table, field):
    if field not in columns(db, table): return {'notVerified': 'missing table/field'}
    total, enabled = db.execute('SELECT COUNT(*),COALESCE(SUM("' + field + '"<>0),0) FROM "' + table + '"').fetchone()
    return {'total': total, 'enabled': enabled}


def endpoint(value):
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname: return 'unrecognized'
    # Never disclose userinfo, paths, fragments or query-string credentials.
    return parsed.scheme + '://' + parsed.hostname + (':' + str(parsed.port) if parsed.port else '')


def houndarr(row):
    with database(row, ('houndarr.db',)) as db:
        fields = columns(db, 'instances')
        chosen = [name for name in ('id', 'url', *FLAGS) if name in fields]
        if not chosen or not set(FLAGS) <= fields: raise RuntimeError('Houndarr flag schema changed.')
        result = []
        for record in db.execute('SELECT ' + ','.join('"' + key + '"' for key in chosen) + ' FROM instances LIMIT 30'):
            values = dict(zip(chosen, record))
            result.append({'id': values.get('id'), 'endpoint': endpoint(values['url']) if 'url' in values else 'not recorded',
                           **{name: bool(values[name]) for name in FLAGS}})
        return result


def kuma(row):
    with database(row, ('kuma.db',)) as db:
        tables = {x[0] for x in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        return {'monitors': counts(db, 'monitor', 'active'), 'notifications': counts(db, 'notification', 'active'),
                'monitorNotificationLinks': db.execute('SELECT COUNT(*) FROM monitor_notification').fetchone()[0]
                if 'monitor_notification' in tables else 'not verified'}


def environment_flags(row, names):
    env = dict(item.split('=', 1) for item in row['Config'].get('Env', []) if '=' in item)
    result = {}
    for name in names:
        value = env.get(name)
        if value is None: result[name] = 'not set'
        elif name == 'SPEEDTEST_SCHEDULE': result[name] = 'blank/disabled' if not value.strip() else 'set'
        elif value.strip().lower() in ('0', '1', 'true', 'false', ''): result[name] = value.strip().lower()
        else: result[name] = 'set; value withheld'
    return result


def wizarr(row):
    result = environment_flags(row, ('FLASK_SKIP_SCHEDULER', 'WIZARR_DISABLE_SCHEDULER'))
    try:
        with database(row, ('database/database.db', 'database.db')) as db:
            result['ldap'] = counts(db, 'ldap_configuration', 'enabled')
    except Exception as error: result['ldap'] = {'notVerified': type(error).__name__}
    return result


def dockmon(row):
    fields = {'global_settings': ('default_auto_restart', 'auto_update_enabled_default', 'prune_images_enabled'),
              'auto_restart_configs': ('enabled',), 'container_updates': ('auto_update_enabled',),
              'container_http_health_checks': ('auto_restart_on_failure',)}
    with database(row, ('dockmon.db',)) as db:
        return {table + '.' + field: counts(db, table, field) for table, names in fields.items() for field in names}


def plex(row):
    roots = [Path(bind['Source']) for bind in row['Mounts'] if bind.get('Type') == 'bind' and bind['Destination'] == '/config']
    if len(roots) != 1: raise RuntimeError('The current Plex config binding is ambiguous.')
    path = roots[0] / 'Library/Application Support/Plex Media Server/Preferences.xml'
    if path.stat().st_size > 2 * 1024**2: raise RuntimeError('The Plex preferences exceed their expected bound.')
    prefs = ET.fromstring(path.read_bytes())
    return {name: prefs.get(name, 'not explicitly set') for name in ('autoEmptyTrash',
        'FSEventLibraryUpdatesEnabled', 'FSEventLibraryPartialScanEnabled', 'ScheduledLibraryUpdatesEnabled', 'ScheduledLibraryUpdateInterval')}


def trace_controls():
    def psql(query):
        sql = "BEGIN READ ONLY; SET LOCAL statement_timeout='5s';\n" + query + '\nCOMMIT;'
        return run('docker', 'exec', '-i', 'tracearr-db-nas', 'sh', '-c',
                   'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -X -q -t -A -v ON_ERROR_STOP=1',
                   input=sql, timeout=20)
    schema = json.loads(psql("SELECT COALESCE(json_object_agg(table_name,fields),'{}'::json) FROM "
        "(SELECT table_name,json_agg(column_name) AS fields FROM information_schema.columns "
        "WHERE table_schema='public' GROUP BY table_name) s;"))
    pieces = []
    if set(('name', 'value')) <= set(schema.get('settings', [])):
        names = ','.join("'" + key + "'" for key in TRACE_SETTINGS)
        pieces += ["'settings', (SELECT COALESCE(json_object_agg(name,value),'{}'::json) FROM public.settings WHERE name IN (" + names + '))']
    controls = {'automations': ('is_active',), 'rules': ('is_active',), 'destinations': ('enabled',),
                'newsletters': ('enabled',), 'request_services': ('enabled',),
                'notification_preferences': ('push_enabled',),
                'notification_channel_routing': ('discord_enabled', 'webhook_enabled', 'push_enabled')}
    for table, fields in controls.items():
        for field in fields:
            if field not in schema.get(table, []): continue
            pieces += ["'" + table + '.' + field + "', (SELECT json_build_object('total',COUNT(*),'enabled',"
                       'COUNT(*) FILTER (WHERE "' + field + '" IS TRUE)) FROM public."' + table + '")']
    if not pieces: raise RuntimeError('Tracearr controls were not recognized.')
    result = json.loads(psql('SELECT json_build_object(' + ','.join(pieces) + ');'))
    allowed_schedule = {'disabled', 'daily', 'weekly', 'monthly', 'manual', 'hourly', 'custom'}
    result['settings'] = {name: value if isinstance(value, bool) or value is None
                         or (name == 'backupScheduleType' and isinstance(value, str) and value in allowed_schedule)
                         else 'value withheld; schema/value review required'
                         for name, value in result.get('settings', {}).items()}
    result['settingsNotFound'] = sorted(set(TRACE_SETTINGS) - set(result['settings']))
    return result


def unit_properties(name):
    text = run('systemctl', 'show', '--no-pager', '--full', name, '-p', 'LoadState', '-p', 'ActiveState',
               '-p', 'SubState', '-p', 'UnitFileState', '-p', 'NextElapseUSecRealtime')
    return dict(line.split('=', 1) for line in text.splitlines() if '=' in line)


def backup_recovery(rows):
    record = read_json(BASE / 'backup-handover/state.json')
    differences = []
    for old in record['runningBefore']:
        current = rows.get(old['name'])
        if current is None:
            differences.append({'name': old['name'], 'missing': True}); continue
        if current['Id'] != old['id'] or current['Image'] != old['image'] or not current['State']['Running']:
            differences.append({'name': old['name'], 'sameContainer': current['Id'] == old['id'],
                'sameImage': current['Image'] == old['image'], 'running': current['State']['Running'],
                'createdUtc': current['Created'], 'startedUtc': current['State']['StartedAt']})
    pending = Path('/var/lib/sawdoctor-nas-backup/running-containers')
    return {'handoverPhase': record['phase'], 'differences': differences,
            'pendingRecoveryIds': len(pending.read_text().split()) if pending.exists() else 0}


def media_status(rows):
    body = RECOVERY.read_bytes()
    if RECOVERY.is_symlink() or hashlib.sha256(body).hexdigest() != RECOVERY_SHA:
        raise RuntimeError('The reviewed mount checker differs.')
    helper = {'__name__': 'audit_media_recovery', '__file__': str(RECOVERY)}
    exec(compile(body, str(RECOVERY), 'exec'), helper)
    mounts = helper['host_mounts'](); result = []
    for row in rows.values():
        if row['State']['Running'] and helper['dependencies'](row):
            ready = helper['ready'](row, mounts)
            if not ready or helper['stale_bindings'](row, mounts):
                result.append({'name': row['Name'].lstrip('/'), 'hostReady': ready})
    return {'unavailableOrStale': result}


def main():
    if os.geteuid() != 0 or not APP.is_mount() or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220.')
    ids = run('docker', 'ps', '-aq').split()
    rows = {row['Name'].lstrip('/'): row for row in json.loads(run('docker', 'inspect', *ids))} if ids else {}
    show('HOUNDARR instances and search modes', lambda: houndarr(rows['houndarr-nas']))
    show('KUMA monitors and alerts', lambda: kuma(rows['uptime-kuma-nas']))
    show('WIZARR scheduler overrides', lambda: wizarr(rows['wizarr-nas']))
    show('SPEEDTEST scheduled tests', lambda: environment_flags(rows['speedtest-tracker-nas'], ('SPEEDTEST_SCHEDULE',)))
    show('TRACEARR current controls', trace_controls)
    show('PLEX library switches', lambda: plex(rows['plex-nas']))
    show('DOCKMON automatic actions (intentionally off)', lambda: dockmon(rows['dockmon']))
    show('NPM certificate hold', lambda: {'guardMountPresent': any(
        bind.get('Destination') == '/app/internal/certificate.js' and Path(bind.get('Source', '')).name == 'certificate-held.js'
        for bind in rows['npm-nas'].get('Mounts', []))})
    show('BACKUP recovery assessment', lambda: backup_recovery(rows))
    show('MIGRATION general hold', lambda: {'phase': read_json(BASE / 'state.json').get('phase'),
                                          'importGuardPresent': (BASE / 'import-active').exists()})
    show('MEDIA current bindings', lambda: media_status(rows))
    show('CONTAINERS restart disabled', lambda: sorted(name for name, row in rows.items()
        if row['HostConfig']['RestartPolicy']['Name'] in ('no', '')))
    show('CONTAINERS not running', lambda: {name: row['State']['Status'] for name, row in rows.items() if not row['State']['Running']})
    show('REMAINING import overrides', lambda: sorted(path.parent.name.removesuffix('.d')
        for path in UNITS.glob('*.d/' + DROPIN)))
    timers = {line.split()[0] for line in run('systemctl', 'list-unit-files', 'nas-*.timer', '--no-legend', '--no-pager').splitlines() if line.split()}
    for name in sorted(timers | {'cron.service', 'nas-books.service', 'nas-production-plex.service', 'nas-media-boot.service'}):
        show('UNIT ' + name, lambda name=name: unit_properties(name))
    print('CURRENT NAS HOLD AUDIT COMPLETE. No settings, services, images or application data were changed.', flush=True)


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print('STOP: Current audit could not complete (' + type(error).__name__ + '); no settings or services changed.', flush=True)
        raise SystemExit(1)
