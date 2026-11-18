#!/usr/bin/env python3
"""Capture only the remaining NAS cron/job/renewal definitions for private review.

Does not run collectors, provisioners, archivers, watchdogs or certificate actions.
No service state, application data, scheduling or sharing setting is changed.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import tempfile

APP = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
BASE = APP / 'compose/production-cutover'
WORK = BASE / 'remaining-host-owner-review'
REMOTE = 'gdrive:nas-backups/openmediavault/migration-review/nas-final-host-owners-20261118.txt'
FORMAT = 'sawdoctor-nas-final-host-owners-review-v1'
JOBS = ('nas-abs-user-provisioner', 'nas-flora-queue-watch',
        'nas-torbox-audiobook-archive', 'nas-torbox-watch')
UNITS = ('cron.service', 'anacron.service', 'anacron.timer', 'nas-hba-temperature-bridge.timer',
         'nas-backup.timer', 'nas-media-recovery.timer', 'nas-production-import-guard.service') + tuple(
             name + suffix for name in JOBS for suffix in ('.service', '.timer'))
HELPERS = ('/usr/local/sbin/nas-abs-user-provisioner', '/usr/local/sbin/nas-flora-queue-watch',
           '/usr/local/sbin/nas-torbox-media', '/usr/local/sbin/hba-temp-collect')
REFERENCES = re.compile(r'(?<![A-Za-z0-9_])/(?:usr/local/(?:bin|sbin|libexec)|home/sawdoctor/scripts|var/lib/openmediavault/cron.d)/[A-Za-z0-9_.@+/-]+')
PROPERTIES = ('Id', 'LoadState', 'ActiveState', 'SubState', 'Result', 'UnitFileState',
              'ConditionResult', 'DropInPaths', 'FragmentPath', 'NextElapseUSecRealtime')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(value, message):
    if not value:
        raise RuntimeError(message)


def say(label, value):
    print(label + ': ' + json.dumps(value, sort_keys=True), flush=True)


def read(path, limit=1024**2):
    path = Path(path)
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'A review input is symbolic; existing files retained.')
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, 'A review input exceeds its regular-file bound.')
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    require(len(data) <= limit and all(getattr(before, k) == getattr(after, k)
            for k in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns')), 'A review input changed during capture.')
    return data


def command(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    require(result.returncode == 0, 'A read-only inventory command failed; raw output withheld.')
    return result.stdout


def unit_status(name):
    args = ['systemctl', 'show', '--no-pager', name]
    for prop in PROPERTIES:
        args += ['-p', prop]
    result = subprocess.run(args, capture_output=True, text=True, timeout=20)
    require(result.returncode in (0, 1, 4), 'A unit inventory query failed; raw output withheld.')
    values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    if not values:
        values = {'Id': name, 'LoadState': 'unavailable'}
    return values


def cron_summary(source, text, owner=None):
    result = []
    for number, original in enumerate(text.splitlines(), 1):
        line = original.strip()
        if not line or line.startswith('#') or re.match(r'^[A-Za-z_][A-Za-z0-9_]*\s*=', line):
            continue
        fields = (1 if line.startswith('@') else 5) + (0 if owner else 1)
        parts = line.split(None, fields)
        if len(parts) != fields + 1:
            result.append({'file': source, 'line': number, 'unparsed': True})
            continue
        schedule = ' '.join(parts[:1 if line.startswith('@') else 5])
        safe_schedule = schedule if re.fullmatch(r'[A-Za-z0-9*/,@: .-]{1,100}', schedule) else 'withheld'
        user = owner or parts[fields - 1]
        result.append({'file': source, 'line': number, 'schedule': safe_schedule,
                       'user': user if re.fullmatch(r'[A-Za-z0-9_-]{1,40}', user) else 'withheld',
                       'scripts': sorted(set(REFERENCES.findall(parts[-1])))})
    return result


def setting_summary(path):
    data = json.loads(read(path))
    result = {'keys': sorted(data)}
    for name in ('ABS_URL', 'PODCAST_HOST_ROOT', 'PODCAST_ABS_ROOT'):
        if name in data:
            value = str(data[name])
            result[name] = value if name != 'ABS_URL' or value == 'http://192.168.0.220:13378' else 'unexpected/withheld'
    return result


def archive_summary(path):
    data = json.loads(read(path, 4 * 1024**2))
    return {'version': data.get('version'), **{key + 'Count': len(data.get(key, {}))
            for key in ('origins', 'backups') if isinstance(data.get(key), dict)}}


def npm_summary(row):
    labels = row.get('Config', {}).get('Labels') or {}
    return {'running': row.get('State', {}).get('Running'), 'image': row.get('Config', {}).get('Image'),
            'imageId': row.get('Image'), 'compose': {key: value for key, value in labels.items()
                if key in ('com.docker.compose.project', 'com.docker.compose.service',
                           'com.docker.compose.project.config_files', 'com.docker.compose.project.working_dir')},
            'mounts': [{key: mount.get(key) for key in ('Type', 'Source', 'Destination', 'RW')}
                       for mount in row.get('Mounts', [])],
            'ports': row.get('HostConfig', {}).get('PortBindings')}


def collect():
    require(os.geteuid() == 0 and APP.is_mount(), 'Run with sudo on the mounted NAS.')
    require('inet 192.168.0.220/' in command('ip', '-4', 'addr', 'show'), 'This review belongs on NAS 192.168.0.220.')
    accepted = json.loads(read(BASE / 'tracearr-control-handover/state.json'))
    require(accepted.get('phase') == 'complete', 'The existing Tracearr restoration is not recorded complete.')
    require(unit_status('nas-backup.service').get('ActiveState') not in ('active', 'activating', 'deactivating'),
            'The normal backup is busy; retain it and retry this read-only review afterward.')
    report = {'format': FORMAT, 'createdUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'tracearrComplete': True, 'units': {}, 'files': [], 'cron': [], 'missing': [], 'settings': {}}
    seen = set()
    def add(path, follow=False):
        path = Path(path)
        if str(path) in seen:
            return
        seen.add(str(path))
        if not path.exists():
            report['missing'].append(str(path))
            return
        if path.is_symlink():
            report.setdefault('links', []).append({'path': str(path), 'target': os.readlink(path)})
            return
        require(len(report['files']) < 160, 'The remaining-owner source bundle exceeded its file bound.')
        data = read(path)
        try:
            text = data.decode('utf-8')
        except UnicodeDecodeError:
            report.setdefault('binaryReferences', []).append({'path': str(path), 'sha256': sha(data)})
            return
        report['files'].append({'path': str(path), 'sha256': sha(data), 'content': text})
        if follow:
            for reference in sorted(set(REFERENCES.findall(text))):
                # Only literal local scripts; no configuration/secrets files or binaries.
                target = Path(reference)
                if target.suffix in ('.env', '.conf', '.json') or target.name in ('lsiutil', 'infinidysk-rclone'):
                    continue
                add(target, follow=False)
    for name in UNITS:
        status = unit_status(name)
        report['units'][name] = status
        fragment = status.get('FragmentPath')
        if fragment:
            add(fragment, follow=True)
        for path in status.get('DropInPaths', '').split():
            add(path)
    for path in HELPERS:
        add(path, follow=True)
    roots = [Path('/etc/crontab'), Path('/etc/anacrontab')]
    roots += sorted(path for path in Path('/etc/cron.d').glob('*') if path.is_file() and not path.name.startswith('.'))
    roots += sorted(path for path in Path('/var/spool/cron/crontabs').glob('*') if path.is_file())
    for path in roots:
        add(path, follow=True)
        if path.exists() and not path.is_symlink() and path.name != 'anacrontab':
            owner = path.name if path.parent == Path('/var/spool/cron/crontabs') else None
            report['cron'] += cron_summary(str(path), read(path).decode(), owner)
    for folder in ('hourly', 'daily', 'weekly', 'monthly'):
        for path in sorted(Path('/etc/cron.' + folder).glob('*')):
            if path.is_file() and os.access(path, os.X_OK) and re.fullmatch(r'[A-Za-z0-9_-]+', path.name):
                add(path, follow=True)
    for path in sorted(Path('/var/lib/openmediavault/cron.d').glob('*')):
        if path.is_file():
            add(path, follow=True)
    jobs = APP / 'appdata/host-jobs'
    for name in ('abs-user-provisioner', 'flora-queue-watch', 'torbox-audiobook-archive'):
        root = jobs / name
        if not root.is_dir():
            report['missing'].append(str(root))
            continue
        for path in sorted(root.rglob('*')):
            if path.is_file() and path.suffix in ('.py', '.sh') and '__pycache__' not in path.parts:
                add(path)
    settings = jobs / 'abs-user-provisioner/settings.json'
    if settings.exists():
        report['settings']['abs'] = setting_summary(settings)
    ledger = jobs / 'torbox-audiobook-archive/state/archive-state.json'
    if ledger.exists():
        report['settings']['archiveLedger'] = archive_summary(ledger)
    for relative in ('flora-queue-watch/prepared.json', 'torbox-audiobook-archive/install.json'):
        path = jobs / relative
        if path.exists():
            add(path)
    # Environment-file names only; private API values and rclone credentials are omitted.
    environment = jobs / 'torbox-audiobook-archive/archive.env'
    if environment.exists():
        report['settings']['archiveEnvironmentKeys'] = sorted(set(re.findall(
            r'^([A-Za-z_][A-Za-z0-9_]*)=', read(environment).decode(), re.M)))
    row = json.loads(command('docker', 'inspect', 'npm-nas'))[0]
    report['npm'] = npm_summary(row)
    for mount in row.get('Mounts', []):
        if mount.get('Destination') == '/app/internal/certificate.js' and mount.get('Type') == 'bind':
            add(mount['Source'])
    config_files = report['npm']['compose'].get('com.docker.compose.project.config_files', '')
    for path in config_files.split(','):
        if path:
            add(path)
    data_roots = [Path(m['Source']) for m in row.get('Mounts', [])
                  if m.get('Destination') == '/data' and m.get('Type') == 'bind']
    if len(data_roots) == 1 and (data_roots[0] / 'database.sqlite').is_file():
        db = data_roots[0] / 'database.sqlite'
        connection = sqlite3.connect(db.as_uri() + '?mode=ro', uri=True, timeout=5)
        try:
            connection.execute('PRAGMA query_only=ON')
            columns = {r[1] for r in connection.execute('PRAGMA table_info(certificate)')}
            fields = [name for name in ('id', 'provider', 'expires_on', 'is_deleted') if name in columns]
            if fields:
                report['npm']['certificates'] = [dict(zip(fields, values)) for values in connection.execute(
                    'SELECT ' + ','.join(fields) + ' FROM certificate ORDER BY id LIMIT 100')]
        finally:
            connection.close()
    return report


def main():
    os.umask(0o077)
    report = collect()
    payload = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode()
    require(len(payload) <= 4 * 1024**2, 'The remaining-owner private review exceeded its size bound.')
    require(not any(p.is_symlink() for p in (WORK, *WORK.parents)), 'The private review destination is symbolic.')
    WORK.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = WORK / 'private-review.json'
    with tempfile.NamedTemporaryFile(dir=WORK, delete=False) as output:
        temporary = Path(output.name)
        try:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
    say('HOST JOB STATES', {name: {key: row.get(key) for key in ('ActiveState', 'UnitFileState', 'ConditionResult')}
                            for name, row in report['units'].items()})
    say('CRON SCHEDULES (arguments withheld)', report['cron'])
    say('HOST JOB SETTINGS (no credentials)', report['settings'])
    say('NPM RENEWAL OWNER', {'running': report['npm']['running'], 'image': report['npm']['image'],
                            'imageId': report['npm']['imageId'], 'certificates': report['npm'].get('certificates', []),
                            'guardMounts': [m for m in report['npm']['mounts']
                                            if m['Destination'] == '/app/internal/certificate.js']})
    result = subprocess.run(['rclone', '--config', '/root/.config/rclone/rclone.conf',
                             'copyto', str(path), REMOTE, '--tpslimit', '2', '--retries', '2',
                             '--contimeout', '10s', '--timeout', '45s'], capture_output=True, timeout=120)
    require(result.returncode == 0, 'Private source upload failed; local review retained and all jobs remain unchanged.')
    say('PRIVATE REMAINING-OWNER SOURCE READY', {'files': len(report['files']), 'sha256': sha(payload),
                                              'missing': report['missing']})
    print('REMAINING OWNER REVIEW COMPLETE. No job/collector executed; no service, schedule, certificate or application changed.', flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        message = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        raise SystemExit('STOP: ' + message)
