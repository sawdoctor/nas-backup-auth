#!/usr/bin/env python3
"""Observe current NAS backups/jobs and inventory cleanup/comparison targets."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time

APP = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
BACKUP = Path('/srv/dev-disk-by-uuid-631e3391-6a42-4158-9aa4-f7718ba0e7e9')
BASE = APP / 'compose/production-cutover'
WORK = BASE / 'post-migration-review'
SELF = WORK / 'worker.py'
UNIT = 'nas-post-migration-review.service'
JOBS = ('nas-abs-user-provisioner', 'nas-flora-queue-watch', 'nas-torbox-watch', 'nas-torbox-audiobook-archive')
PROPS = ('Id', 'LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'Result', 'ExecMainStatus',
         'ConditionResult', 'ExecMainStartTimestamp', 'ExecMainExitTimestamp', 'LastTriggerUSec',
         'NextElapseUSecRealtime', 'DropInPaths')
CLOUD = 'gdrive:nas-backups/openmediavault/sets/'


def run(*args, timeout=30):
    return subprocess.run(args, capture_output=True, timeout=timeout)


def checked(*args, timeout=30):
    result = run(*args, timeout=timeout)
    if result.returncode:
        if WORK.is_dir():
            atomic(WORK / 'private-command-error.json', {'program': Path(args[0]).name,
                   'arguments': list(args[1:]), 'status': result.returncode,
                   'stdout': result.stdout[-65536:].decode(errors='replace'),
                   'stderr': result.stderr[-65536:].decode(errors='replace')})
        raise RuntimeError('command_failed_' + Path(args[0]).name)
    return result.stdout


def safe(path):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise RuntimeError('symbolic_input_retained')


def small(path, limit=4 * 1024**2):
    safe(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise RuntimeError('input_type_or_size')
    return path.read_bytes()


def atomic(path, value, mode=0o600):
    safe(path)
    body = value if isinstance(value, bytes) else (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    fd, name = tempfile.mkstemp(dir=path.parent, prefix='.review-')
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(body); stream.flush(); os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name): os.unlink(name)


def show_units():
    names = ['cron.service', 'anacron.timer', 'nas-backup.service', 'nas-backup.timer',
             'nas-backup-resume.service', 'nas-media-recovery.service', 'nas-media-recovery.timer',
             'nas-production-plex.service', 'nas-books.service', 'nas-media-boot.service',
             'nas-hba-temperature-bridge.timer']
    names += [job + suffix for job in JOBS for suffix in ('.service', '.timer')]
    args = ['systemctl', 'show', '--no-pager', *names]
    for field in PROPS: args += ['-p', field]
    result = run(*args)
    if result.returncode not in (0, 1, 4): raise RuntimeError('unit_query_failed')
    units = {}
    for block in result.stdout.decode().split('\n\n'):
        row = dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
        if row.get('Id'): units[row['Id']] = row
    return units


def job_state(service, timer):
    if timer.get('ActiveState') != 'active' or timer.get('UnitFileState') != 'enabled':
        return 'timer_needs_review'
    if service.get('ActiveState') in ('active', 'activating', 'deactivating'):
        return 'running_now'
    if not service.get('ExecMainExitTimestamp'):
        return 'no_completed_run_recorded'
    if service.get('ExecMainStatus') == '75' and service.get('Result') == 'success':
        return 'last_attempt_skipped_backup_lock'
    return 'last_run_success' if service.get('Result') == 'success' and service.get('ExecMainStatus') == '0' else 'last_run_needs_review'


def compare_metadata(local, remote):
    remote_files = {r['Path']: r['Size'] for r in remote if not r.get('IsDir')}
    # The uploaded marker is created locally only after the worker's cloud check.
    expected = {name: size for name, size in local.items() if name != '_UPLOADED'}
    return sorted(name for name, size in expected.items() if remote_files.get(name) != size)


def backup_journal():
    data = checked('journalctl', '-u', 'nas-backup.service', '--since', '48 hours ago',
                   '-n', '2500', '--no-pager', '-o', 'json')
    completed = []; cloud_checks = 0
    for line in data.decode(errors='replace').splitlines():
        try: row = json.loads(line)
        except ValueError: continue
        message = row.get('MESSAGE', '')
        if not isinstance(message, str): continue
        if '0 differences found' in message: cloud_checks += 1
        if 'BACKUP COMPLETE:' in message:
            completed.append({'setNames': sorted(set(re.findall(r'nas-[0-9]{8}T[0-9]{6}Z', message))),
                              'journalTimestampUs': row.get('__REALTIME_TIMESTAMP')})
    return {'completedBackupEvents48h': completed, 'zeroDifferenceCloudCheckMessages48h': cloud_checks}


def cron_inventory():
    paths = [Path('/etc/crontab'), *Path('/etc/cron.d').glob('*'),
             *Path('/var/spool/cron/crontabs').glob('*')]
    result = []
    for path in sorted(paths):
        if not path.is_file() or path.is_symlink(): continue
        schedules = []
        for line in small(path).decode(errors='replace').splitlines():
            text = line.strip()
            if not text or text.startswith('#'): continue
            fields = text.split()
            if len(fields) >= 6 and re.fullmatch(r'[0-9*/,@A-Za-z-]+', fields[0]):
                if fields[0].startswith('@'): schedules.append(fields[0])
                elif all(re.fullmatch(r'[0-9*/,-]+', p) for p in fields[:5]):
                    schedules.append(' '.join(fields[:5]))
        result.append({'file': str(path), 'schedules': schedules})
    return result


def backup_proof(rows):
    sets = BACKUP / 'backups/sets'; safe(sets)
    candidates = sorted(p for p in sets.iterdir() if re.fullmatch(r'nas-[0-9]{8}T[0-9]{6}Z', p.name)
                        and p.is_dir() and not p.is_symlink())
    result = {'sets': [{'name': p.name, 'complete': (p / '_COMPLETE').is_file(),
                       'uploaded': (p / '_UPLOADED').is_file()} for p in candidates]}
    completed = [p for p in candidates if (p / '_COMPLETE').is_file() and (p / '_UPLOADED').is_file()]
    if not completed: return dict(result, currentBackupConfirmed=False, reason='no_completed_uploaded_set')
    latest = completed[-1]
    if small(latest / '_COMPLETE') != b'Sawdoctor NAS backup v1\n':
        raise RuntimeError('backup_marker_differs')
    inventory = {}
    for parent, directories, files in os.walk(latest, followlinks=False):
        for name in directories: safe(Path(parent) / name)
        for name in files:
            path = Path(parent) / name; safe(path)
            inventory[path.relative_to(latest).as_posix()] = path.stat().st_size
            if len(inventory) > 4096: raise RuntimeError('backup_inventory_bound')
    manifest = small(latest / 'SHA256SUMS')
    args = ('rclone', '--config', '/root/.config/rclone/rclone.conf')
    remote = json.loads(checked(*args, 'lsjson', CLOUD + latest.name, '--recursive', '--files-only', timeout=90))
    copied_manifest = checked(*args, 'cat', CLOUD + latest.name + '/SHA256SUMS', timeout=45)
    different = compare_metadata(inventory, remote)
    recorded = json.loads(small(latest / 'containers.json', 16 * 1024**2))
    plex = next((r for r in recorded if r.get('Name') == '/plex-nas'), None)
    age_hours = round((time.time() - (latest / '_COMPLETE').stat().st_mtime) / 3600, 2)
    local = rows['nas-backup.service']
    result.update(latestSet=latest.name, completedAgeHours=age_hours, cloudFileCount=len(remote),
                  cloudSizeMismatchNames=different, checksumManifestMatchesCloud=(manifest == copied_manifest),
                  plexContainerRecorded=plex is not None, applicationArchivePresent='applications.tar.zst' in inventory,
                  localUploadedMarkerPresent=True, localFiles=len(inventory),
                  applicationArchiveGiB=round(inventory.get('applications.tar.zst', 0) / 1024**3, 2),
                  currentBackupConfirmed=(age_hours < 36 and not different and manifest == copied_manifest
                      and plex is not None and 'applications.tar.zst' in inventory
                      and local.get('Result') == 'success' and local.get('ActiveState') == 'inactive'))
    result['verificationScope'] = 'Existing successful worker/complete-uploaded markers, fresh SSD set, cloud sizes and exact checksum manifest; no fresh full archive hash or restore.'
    return result


def disk_and_cleanup(containers):
    paths = [APP / 'migration', BACKUP / 'migration', BASE,
             BASE / 'books-handover/rollback', BASE / 'kometa-handover/rollback',
             APP / 'compose/plex-nas/recovery/before-standby-refresh',
             APP / 'compose/infinidysk-nas/recovery/before-latest']
    inventory = []
    for path in paths:
        if not path.exists() or path.is_symlink(): continue
        response = run('du', '-x', '-s', '-B1', '--', str(path), timeout=45)
        size = int(response.stdout.split()[0]) if response.returncode == 0 and response.stdout.split() else None
        references = sorted({r['Name'].lstrip('/') for r in containers for m in r.get('Mounts', [])
                             if m.get('Source') and Path(m['Source']).is_relative_to(path)})
        inventory.append({'path': str(path), 'GiB': round(size / 1024**3, 2) if size is not None else None,
                          'containerReferences': references, 'deletionAuthorizedByThisReport': False})
    transfers = []
    for name in ('core-optiplex', 'books-optiplex', 'support-optiplex', 'plex-npm-optiplex'):
        path = APP / 'migration' / name / 'export.tar.zst'
        if path.is_file() and not path.is_symlink():
            transfers.append({'bundle': name, 'GiB': round(path.stat().st_size / 1024**3, 2)})
    disks = {}
    for path in (Path('/'), APP, BACKUP, Path('/srv/dev-disk-by-uuid-1f12a22e-5cfe-4b02-8d4b-48e9bf5fec6a')):
        v = os.statvfs(path)
        disks[str(path)] = {'freeGiB': round(v.f_bavail * v.f_frsize / 1024**3, 2),
                            'usedPercent': round(100 * (v.f_blocks - v.f_bfree) / v.f_blocks, 1)}
    return {'disks': disks, 'reviewRoots': inventory, 'compressedTransferCandidates': transfers,
            'danglingImages': checked('docker', 'image', 'ls', '--filter', 'dangling=true', '--format', '{{.ID}} {{.Size}}').decode().splitlines()}


def retired_proxy():
    database = APP / 'appdata/npm/data/database.sqlite'; safe(database)
    connection = sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=5)
    try:
        connection.execute('PRAGMA query_only=ON')
        row = connection.execute('SELECT id,enabled,is_deleted,domain_names,certificate_id,forward_host,forward_port FROM proxy_host WHERE id=30').fetchone()
        if not row: return {'listenarrProxyPresent': False}
        if json.loads(row[3]) != ['listenarr.sawdoctor.uk']:
            return {'listenarrProxyPresent': 'identity_changed_no_cleanup'}
        uses = []
        for table in ('proxy_host', 'redirection_host', 'dead_host', 'stream'):
            columns = {r[1] for r in connection.execute('PRAGMA table_info(' + table + ')')}
            if not {'id', 'certificate_id'} <= columns: continue
            where = 'certificate_id=?' + (' AND is_deleted=0' if 'is_deleted' in columns else '')
            uses += [{'table': table, 'id': value[0]} for value in connection.execute('SELECT id FROM ' + table + ' WHERE ' + where, (row[4],))]
        return {'listenarrProxyPresent': True, 'id': row[0], 'enabled': bool(row[1]), 'deleted': bool(row[2]),
                'certificateId': row[4], 'target': str(row[5]) + ':' + str(row[6]), 'certificateReferences': uses}
    finally:
        connection.close()


def resources():
    memory = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    samples = [json.loads(line) for line in checked('docker', 'stats', '--no-stream', '--format', '{{json .}}').decode().splitlines()]
    return {'memory': {key: memory[key].strip() for key in ('MemTotal', 'MemAvailable', 'SwapTotal', 'SwapFree')},
            'baselineContainers': [{key: row.get(key) for key in ('Name', 'CPUPerc', 'MemUsage', 'MemPerc', 'PIDs')}
                                   for row in samples if any(value in row.get('Name', '')
                                   for value in ('dockmon', 'infinidysk', 'silo', 'plex'))]}


def part(label, function, report):
    print('Checking ' + label + '...', flush=True)
    try: value = function()
    except Exception as error:
        value = {'needsReview': True, 'errorClass': type(error).__name__}
        if isinstance(error, RuntimeError): value['reason'] = str(error)
    report[label] = value
    print(label.upper() + ': ' + json.dumps(value, sort_keys=True), flush=True)
    atomic(WORK / 'report.json', report)


def worker():
    report = {'format': 'sawdoctor-post-migration-current-review-v1', 'checkedUtc': dt.datetime.now(dt.timezone.utc).isoformat()}
    rows = show_units(); report['units'] = rows
    for name, row in rows.items(): print('UNIT ' + name + ': ' + json.dumps(row, sort_keys=True), flush=True)
    ids = checked('docker', 'container', 'ls', '-aq').decode().split()
    containers = json.loads(checked('docker', 'inspect', *ids)) if ids else []
    part('scheduled_jobs', lambda: {job: job_state(rows.get(job + '.service', {}), rows.get(job + '.timer', {})) for job in JOBS}, report)
    part('backup_proof', lambda: backup_proof(rows), report)
    part('backup_journal', backup_journal, report)
    part('cron_inventory', cron_inventory, report)
    part('container_health', lambda: [{'name': r['Name'].lstrip('/'), 'state': r['State']['Status'],
         'health': r['State'].get('Health', {}).get('Status', 'none')} for r in containers], report)
    part('media_recovery', lambda: checked('/usr/local/sbin/nas-media-recovery', 'check', timeout=40).decode().strip(), report)
    part('hba', lambda: {'temperatureC': int(small(Path('/run/hba-temp')).strip()),
         'cacheAgeSeconds': round(time.time() - Path('/run/hba-temp').stat().st_mtime),
         'cronActive': rows['cron.service'].get('ActiveState') == 'active'}, report)
    part('cleanup_inventory', lambda: disk_and_cleanup(containers), report)
    part('retired_proxy', retired_proxy, report)
    part('resources', resources, report)
    part('comparison_environment', lambda: {'dockerSocketGid': Path('/var/run/docker.sock').stat().st_gid,
         'backupProgramSha256': hashlib.sha256(small(Path('/usr/local/sbin/nas-backup'))).hexdigest(),
         'containers': [{'name': r['Name'].lstrip('/'), 'image': r['Config']['Image'],
                         'ports': r['HostConfig'].get('PortBindings'),
                         'composeFiles': (r['Config'].get('Labels') or {}).get('com.docker.compose.project.config_files')}
                        for r in containers if any(s in r['Name'].lower() for s in ('dockhand', 'dockmon', 'infinidysk', 'silo'))],
         'candidatePorts': {str(port): port_available(port) for port in (3180, 3300)}}, report)
    part('remaining_import_overrides', lambda: sorted(str(p) for p in Path('/etc/systemd/system').glob('*.d/96-sawdoctor-production-import.conf')), report)
    part('other_backup_timers', lambda: checked('systemctl', 'list-timers', '--all', '--no-pager', '--full', '*backup*').decode(), report)
    part('failed_units', lambda: checked('systemctl', '--failed', '--no-pager', '--plain', '--no-legend').decode(), report)
    final_rows = show_units()
    report['backupStateAtEnd'] = final_rows['nas-backup.service']
    report['backupChangedDuringReview'] = rows['nas-backup.service'] != final_rows['nas-backup.service']
    atomic(WORK / 'report.json', report)
    print('NAS CURRENT REVIEW COMPLETE. No backup/job run, app restart, image pull or deletion requested.', flush=True)
    print('Report: ' + str(WORK / 'report.json'), flush=True)


def port_available(port):
    try:
        with socket.socket() as connection: connection.bind(('192.168.0.220', port))
        return True
    except OSError: return False


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in checked('ip', '-4', 'addr', 'show').decode():
        raise RuntimeError('run_with_sudo_on_NAS')
    if not APP.is_mount() or not BACKUP.is_mount(): raise RuntimeError('required_SSD_unavailable')
    safe(WORK); WORK.mkdir(mode=0o700, exist_ok=True)
    if sys.argv[1:] == ['--worker']:
        worker(); return
    if sys.argv[1:]: raise RuntimeError('unsupported_review_action')
    source = globals().get('INSTALL_SOURCE')
    if not isinstance(source, str): raise RuntimeError('complete_review_source_required')
    state = run('systemctl', 'show', UNIT, '-p', 'ActiveState', '--value').stdout.strip()
    if state in (b'active', b'activating', b'deactivating'):
        print('The current NAS review is already running.'); return
    if SELF.exists() and small(SELF) != source.encode(): raise RuntimeError('different_review_worker_retained')
    atomic(SELF, source.encode(), 0o700)
    run('systemctl', 'reset-failed', UNIT)
    checked('systemd-run', '--unit=' + UNIT, '--collect', '--property=Type=exec', '--property=UMask=0077',
            '--property=RuntimeMaxSec=12min', '--description=Review current NAS backup jobs and cleanup candidates',
            '/usr/bin/python3', '-u', str(SELF), '--worker')
    print('Current NAS review started in systemd. Closing SSH is safe.')
    print('Progress: sudo journalctl -u ' + UNIT + ' -f -n 60 --no-pager -o cat')


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print('STOP: current review could not finish (' + type(error).__name__ + '); production retained.', flush=True)
        raise SystemExit(1)
