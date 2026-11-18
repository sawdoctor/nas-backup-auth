#!/usr/bin/env python3
"""Restore reviewed NAS host schedules; retain source freeze and NPM hold."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import sqlite3
import subprocess
import sys
import time

APP = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
BASE = APP / 'compose/production-cutover'
WORK = BASE / 'host-job-handover'
SELF = WORK / 'worker.py'
STATE = WORK / 'state.json'
UNIT = 'nas-production-host-jobs.service'
FORMAT = 'sawdoctor-reviewed-nas-host-jobs-v1'
REPORT = BASE / 'remaining-host-owner-review/private-review.json'
REPORT_SHA = '73ff1f6fead44c90af0bdd6c594379b2eb1382921277c9dfeaeed151b89a4110'
BOOT = BASE / 'boot-handover/worker.py'
BOOT_SHA = '971ae70c0a6de64de1420ef7e26d1ec21f8861d8fa3c8b4eb2baeb5fd03f48ed'
LOCK = Path('/run/lock/sawdoctor-nas-backup.lock')
HOLD_NAME = '96-sawdoctor-production-import.conf'
HOLD_SHA = '6fd9f38ca3e97a1735c41dd7fdb91376f3da3d5aa5b68393587fa5b296b1a395'
JOBS = ('nas-abs-user-provisioner', 'nas-flora-queue-watch', 'nas-torbox-watch', 'nas-torbox-audiobook-archive')
DATA = APP / 'appdata/host-jobs'
ARCHIVE = DATA / 'torbox-audiobook-archive'
ARCHIVE_PROGRAM = ARCHIVE / 'runtime/scripts/torbox_audiobook_archive.py'
ARCHIVE_DROP = Path('/etc/systemd/system/nas-torbox-audiobook-archive.service.d/98-sawdoctor-backup-lock.conf')
BRIDGE = 'nas-hba-temperature-bridge'
HBA_CACHE = Path('/run/hba-temp')
HBA_JOB = '/var/lib/openmediavault/cron.d/userdefined-5afc8576-fdb1-4fc9-b9f5-272c5f6d474e'


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def say(value):
    print(value, flush=True)


def controllers():
    require(not any(p.is_symlink() for p in (BOOT, *BOOT.parents)) and sha(BOOT.read_bytes()) == BOOT_SHA,
            'The accepted NAS boot controller changed.')
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('host_jobs_boot', BOOT)
    boot = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(boot)
    startup, release, backup, native = boot.controllers()
    return boot, backup, native


def status(native, name):
    result = subprocess.run(['systemctl', 'show', '--no-pager', name, '-p', 'ActiveState', '-p', 'SubState',
                             '-p', 'Result', '-p', 'ExecMainStatus', '-p', 'UnitFileState', '-p', 'DropInPaths',
                             '-p', 'NextElapseUSecRealtime', '-p', 'LastTriggerUSec'],
                            capture_output=True, text=True, timeout=20)
    require(result.returncode in (0, 1, 4), 'A host-job unit query failed; raw output withheld.')
    values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    require(values.get('ActiveState') in ('active', 'inactive', 'failed', 'activating', 'deactivating'),
            'The state of a host-job unit is unavailable: ' + name)
    return values


def hold_path(name):
    return Path('/etc/systemd/system') / (name + '.d') / HOLD_NAME


def job_unit(name):
    return name in {job + suffix for job in JOBS for suffix in ('.service', '.timer')}


def cron_paths():
    paths = {Path('/etc/crontab'), Path('/etc/anacrontab')}
    for folder in ('/etc/cron.d', '/var/spool/cron/crontabs', '/var/lib/openmediavault/cron.d'):
        paths.update(p for p in Path(folder).glob('*') if p.is_file() and not p.name.startswith('.'))
    for interval in ('hourly', 'daily', 'weekly', 'monthly'):
        paths.update(p for p in Path('/etc/cron.' + interval).glob('*')
                     if p.is_file() and os.access(p, os.X_OK) and re.fullmatch(r'[A-Za-z0-9_-]+', p.name))
    return {str(p) for p in paths if p.exists()}


def archive_drop():
    return ('# ' + FORMAT + '\n[Service]\nExecStart=\nExecStart=/usr/bin/flock --nonblock '
            '--conflict-exit-code 75 ' + str(LOCK) + ' /usr/bin/python3 ' + str(ARCHIVE_PROGRAM)
            + ' --apply\nSuccessExitStatus=75\n').encode()


def validate_review(native, record):
    require(sha(native.read(REPORT)) == REPORT_SHA, 'The accepted remaining-owner review changed.')
    report = json.loads(native.read(REPORT))
    require(report.get('format') == 'sawdoctor-nas-final-host-owners-review-v1' and not report.get('missing'),
            'The complete native remaining-owner review is required.')
    files = {f['path']: f for f in report['files']}
    reviewed_cron = {p for p in files if p.startswith(('/etc/cron', '/var/spool/cron/', '/var/lib/openmediavault/cron.d/'))
                     or p == '/etc/anacrontab'}
    require(cron_paths() == reviewed_cron, 'The cron/OMV job inventory changed; existing schedules retained.')
    for path, item in files.items():
        p = Path(path)
        selected = path in reviewed_cron or path.startswith(str(DATA) + '/') or path.startswith('/usr/local/sbin/')
        selected = selected or (path.startswith('/etc/systemd/system/') and (
            job_unit(p.name) or any('/' + job + suffix + '.d/' in path for job in JOBS for suffix in ('.service', '.timer'))
            or path == str(hold_path('cron.service'))))
        if not selected:
            continue
        if p.name == HOLD_NAME and not p.exists():
            require(record is not None and (WORK / 'retained' / (p.parent.name + '.conf')).exists(),
                    'An import hold disappeared outside this recorded handover.')
            continue
        require(sha(native.read(p)) == item['sha256'], 'A reviewed host-job/cron definition changed: ' + p.name)
    for job in JOBS:
        for suffix in ('.service', '.timer'):
            props = status(native, job + suffix)
            allowed = {str(hold_path(job + suffix))}
            if job == 'nas-torbox-audiobook-archive' and suffix == '.service':
                allowed.add(str(ARCHIVE_DROP))
            require(set(props.get('DropInPaths', '').split()) <= allowed,
                    'A remaining job has an additional runtime override: ' + job)
    dispatcher = native.read(Path('/etc/cron.d/openmediavault-userdefined')).decode()
    require(('*/1 */1 * * * root ' + HBA_JOB + ' >/dev/null 2>&1') in dispatcher,
            'The original one-minute OMV HBA dispatcher differs.')
    if ARCHIVE_DROP.exists():
        require(native.read(ARCHIVE_DROP) == archive_drop(), 'An unrelated archive locking override was retained.')
    return report


def archive_environment(native):
    installed = json.loads(native.read(ARCHIVE / 'install.json'))
    expected = installed['environment']
    actual = {}
    for line in native.read(ARCHIVE / 'archive.env').decode().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        key, sep, text = line.partition('=')
        require(sep and key not in actual and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', key),
                'The archive environment syntax differs; values withheld.')
        parts = shlex.split(text)
        require(len(parts) == 1, 'The archive environment quoting differs; values withheld.')
        actual[key] = parts[0]
    require(actual == expected, 'The archive runtime environment differs from its reviewed installed settings.')
    require(actual.get('TORBOX_ARCHIVE_MAX_BACKUPS') == '2'
            and actual.get('TORBOX_VAULT_REMOTE') == 'gdrive:Shelfmark-TorBox-Archive'
            and actual.get('TORBOX_SOURCE_REMOTE') == 'torbox-audiobooks:'
            and actual.get('TORBOX_MOUNT_PATH') == '/mnt/torbox-audiobooks'
            and actual.get('TORBOX_VAULT_MOUNT') == '/mnt/gdrive-torbox-archive'
            and actual.get('TORBOX_ARCHIVE_STATE_DIR') == str(ARCHIVE / 'state'),
            'A reviewed archive policy/path differs; values withheld.')
    for key in ('TORBOX_AUDIOBOOK_LIBRARY', 'SHELFMARK_CONFIG_DIR'):
        p = Path(actual[key])
        require(p.is_dir() and not p.is_symlink() and p.resolve().is_relative_to((APP / 'appdata/books-nas').resolve()),
                'A current NAS book directory is unavailable; no archive action.')
    for path in ('/mnt/torbox-audiobooks', '/mnt/gdrive-torbox-archive'):
        require(Path(path).is_mount(), 'A required audiobook source/vault mount is unavailable.')
    ledger = json.loads(native.read(ARCHIVE / 'state/archive-state.json'))
    require(ledger.get('version') == 1 and isinstance(ledger.get('origins'), dict)
            and isinstance(ledger.get('backups'), dict) and len(ledger['backups']) >= 54,
            'The retained archive ledger is unavailable/incomplete; no empty state created.')
    return actual


def read_plan(native, name, args, prefix='', env=None, timeout=90):
    result = subprocess.run(args, capture_output=True, text=True, env=env, timeout=timeout)
    native.atomic(WORK / ('private-' + name + '-plan.log'), (result.stdout + '\n' + result.stderr).encode())
    raw = result.stdout.strip()
    if prefix:
        require(raw.startswith(prefix), 'A read-only ' + name + ' plan did not return its expected summary.')
        raw = raw[len(prefix):]
    try:
        data = json.loads(raw)
    except ValueError:
        raise RuntimeError('A read-only ' + name + ' plan failed; private diagnostics retained.') from None
    return result.returncode, data


def archive_plan_summary(code, data):
    keys = ('already_protected', 'pending_protection', 'unmatched_links', 'errors', 'vault_links_need_review')
    require(code in (0, 1) and data.get('mode') == 'plan' and all(isinstance(data.get(key), list) for key in keys),
            'The existing archiver did not return a read-only plan.')
    require(not data['errors'] and not data['unmatched_links'] and not data['vault_links_need_review'],
            'The archive plan has unresolved API/link errors; current data and paused archive retained.')
    # Pending AirLock protection is precisely the original scheduled job's work.
    return {key: len(data[key]) for key in keys}


def plans(native):
    code, abs_plan = read_plan(native, 'abs', ['/usr/bin/python3', '/usr/local/sbin/nas-abs-user-provisioner', '--plan'],
                              'Read-only plan: ')
    require(code == 0 and set(abs_plan) == {'active_members', 'shared_libraries', 'private_libraries_to_create', 'permission_updates'}
            and all(type(v) is int and v >= 0 for v in abs_plan.values()) and abs_plan['shared_libraries'] > 0,
            'The current NAS Audiobookshelf API/private-library plan needs review.')
    say('ABS CURRENT READ-ONLY PLAN: ' + json.dumps(abs_plan, sort_keys=True))
    code, flora = read_plan(native, 'flora', ['/usr/local/sbin/nas-flora-queue-watch', '--plan'],
                            'Read-only NAS queue/Kuma plan: ')
    require(code == 0 and flora.get('stopInfinidysk') is False and flora.get('matchingNasKumaPushMonitors') == 1,
            'The current queue/Kuma read-only plan needs review.')
    say('FLORA CURRENT READ-ONLY PLAN: ' + json.dumps(flora, sort_keys=True))
    env = archive_environment(native)
    code, data = read_plan(native, 'archive', ['/usr/bin/python3', str(ARCHIVE_PROGRAM)], env=env, timeout=240)
    say('ARCHIVE PLAN COUNTS: ' + json.dumps({key: len(data[key]) for key in (
        'already_protected', 'pending_protection', 'unmatched_links', 'errors', 'vault_links_need_review')
        if isinstance(data.get(key), list)}, sort_keys=True))
    summary = archive_plan_summary(code, data)
    say('ARCHIVE CURRENT READ-ONLY PLAN: ' + json.dumps(summary, sort_keys=True))
    return {'abs': abs_plan, 'flora': flora, 'archive': summary}


def release_hold(native, name):
    path = hold_path(name)
    retained = WORK / 'retained' / (name + '.d.conf')
    if path.exists():
        data = native.read(path)
        require(sha(data) == HOLD_SHA, 'A selected import condition differs: ' + name)
        if retained.exists():
            require(native.read(retained) == data, 'The retained original import condition differs.')
        else:
            native.atomic(retained, data, mode=0o644)
        path.unlink()
    else:
        require(retained.exists() and sha(native.read(retained)) == HOLD_SHA,
                'A selected import condition is missing without a retained handover copy.')


def cache_snapshot():
    if not HBA_CACHE.exists() or HBA_CACHE.is_symlink():
        return None
    s = HBA_CACHE.stat()
    text = HBA_CACHE.read_text().strip()
    if s.st_size > 32 or not text.isascii() or not text.isdigit() or not 0 <= int(text) <= 200:
        return None
    return {'inode': s.st_ino, 'mtime': s.st_mtime_ns, 'temperatureC': int(text)}


def restore_cron(native, record):
    if 'cron' in record['completed']:
        require(status(native, 'cron.service')['ActiveState'] == 'active'
                and status(native, BRIDGE + '.timer')['ActiveState'] == 'inactive', 'Accepted cron/HBA ownership changed.')
        return
    native.run('systemctl', 'disable', '--now', BRIDGE + '.timer')
    deadline = time.monotonic() + 40
    while status(native, BRIDGE + '.service')['ActiveState'] in ('active', 'activating', 'deactivating'):
        require(time.monotonic() < deadline, 'The final bridge collection is still running; cron remains held.')
        time.sleep(1)
    before = cache_snapshot()
    started = time.time_ns()
    try:
        release_hold(native, 'cron.service')
        native.run('systemctl', 'daemon-reload')
        native.run('systemctl', 'start', 'cron.service')
        say('CRON RESTORED. Waiting for an original OMV-scheduled HBA reading...')
        deadline = time.monotonic() + 100
        while True:
            current = cache_snapshot()
            if current and current != before and current['mtime'] >= started - 1_000_000_000:
                break
            require(time.monotonic() < deadline, 'No fresh original OMV-scheduled HBA reading was observed.')
            time.sleep(2)
        require(status(native, 'cron.service')['ActiveState'] == 'active'
                and status(native, BRIDGE + '.timer')['ActiveState'] == 'inactive', 'The final HBA owner check differs.')
    except BaseException:
        native.run('systemctl', 'stop', 'cron.service')
        original = WORK / 'retained/cron.service.d.conf'
        if original.exists():
            native.atomic(hold_path('cron.service'), native.read(original), mode=0o644)
        native.run('systemctl', 'daemon-reload')
        native.run('systemctl', 'enable', '--now', BRIDGE + '.timer')
        raise
    record['hbaCronReading'] = current
    record['completed'].append('cron')
    native.atomic(STATE, record)
    say('ORIGINAL OMV HBA COLLECTION VERIFIED: ' + str(current['temperatureC']) + ' C; temporary bridge disabled.')


def restore_job(native, name, record):
    if name in record['completed']:
        require(status(native, name + '.timer')['ActiveState'] == 'active', 'An accepted host timer changed: ' + name)
        return
    if name == 'nas-torbox-audiobook-archive':
        native.atomic(ARCHIVE_DROP, archive_drop(), mode=0o644)
    release_hold(native, name + '.service')
    release_hold(native, name + '.timer')
    native.run('systemctl', 'daemon-reload')
    if name != 'nas-torbox-audiobook-archive':
        # Workers own the shared backup lock: no enclosing backup lock here.
        native.run('systemctl', 'start', name + '.service', timeout=660)
        outcome = status(native, name + '.service')
        require(outcome.get('Result') == 'success', 'A restored host job failed; completed jobs retained: ' + name)
        record.setdefault('firstResults', {})[name] = outcome.get('ExecMainStatus')
    native.run('systemctl', 'enable', '--now', name + '.timer')
    require(status(native, name + '.timer')['ActiveState'] == 'active'
            and status(native, name + '.timer')['UnitFileState'] == 'enabled', 'A restored host timer is not active: ' + name)
    record['completed'].append(name)
    native.atomic(STATE, record)
    say('HOST SCHEDULE RESTORED: ' + name + ('; archive transfers run under the shared backup lock.'
                                          if name == 'nas-torbox-audiobook-archive' else '; first run passed.'))


def certificate_usage(connection):
    usage = {}
    for table in ('proxy_host', 'redirection_host', 'dead_host', 'stream'):
        columns = {r[1] for r in connection.execute('PRAGMA table_info(' + table + ')')}
        if not {'id', 'certificate_id'}.issubset(columns):
            continue
        where = ['certificate_id > 0']
        if 'is_deleted' in columns:
            where.append('is_deleted = 0')
        if 'enabled' in columns:
            where.append('enabled = 1')
        for identity, cert in connection.execute('SELECT id, certificate_id FROM ' + table + ' WHERE ' + ' AND '.join(where)):
            usage.setdefault(int(cert), []).append({'table': table, 'id': identity})
    columns = {r[1] for r in connection.execute('PRAGMA table_info(certificate)')}
    require({'id', 'expires_on', 'provider'}.issubset(columns), 'The current NPM certificate schema differs.')
    return [{'id': identity, 'provider': provider, 'databaseExpires': expires, 'activeUses': usage[identity]}
            for identity, provider, expires in connection.execute('SELECT id, provider, expires_on FROM certificate ORDER BY id')
            if identity in usage]


def renewal_context(native):
    row = native.catalog()['npm-nas']
    binds = {m['Destination']: Path(m['Source']) for m in row['Mounts'] if m.get('Type') == 'bind'}
    require(binds.get('/data') == APP / 'appdata/npm/data'
            and binds.get('/etc/letsencrypt') == APP / 'appdata/npm/letsencrypt', 'NPM storage requires separate review.')
    connection = sqlite3.connect((binds['/data'] / 'database.sqlite').as_uri() + '?mode=ro', uri=True, timeout=5)
    try:
        connection.execute('PRAGMA query_only=ON')
        certificates = certificate_usage(connection)
    finally:
        connection.close()
    for item in certificates:
        cert = binds['/etc/letsencrypt'] / ('live/npm-' + str(item['id'])) / 'fullchain.pem'
        actual = cert.resolve()
        if actual.is_relative_to(binds['/etc/letsencrypt'].resolve()) and actual.is_file():
            result = subprocess.run(['openssl', 'x509', '-in', str(actual), '-noout', '-enddate'],
                                    capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout.startswith('notAfter='):
                item['actualCertificateExpires'] = result.stdout.strip().split('=', 1)[1]
    proof = {'image': row['Image'], 'certificatesUsedByEnabledHosts': certificates,
             'certificateGuardPresent': '/app/internal/certificate.js' in binds}
    native.atomic(WORK / 'npm-current-renewal-context.json', proof)
    say('NPM ACTIVE CERTIFICATE USAGE (read-only): ' + json.dumps(proof, sort_keys=True))


def worker(boot, backup, native):
    with native.lock(BASE / '.run.lock'):
        with boot.boot_lock(native):
            main, rows = backup.preflight(native)
            accepted = json.loads(native.read(BASE / 'tracearr-control-handover/state.json'))
            require(accepted.get('phase') == 'complete', 'Tracearr restoration must already be complete.')
            record = json.loads(native.read(STATE)) if STATE.exists() else None
            if record:
                require(record.get('format') == FORMAT and record.get('cutoverId') == main['proof']['cutoverId'],
                        'The existing host-job handover identity differs.')
            validate_review(native, record)
            before = {name: (r['Id'], r['Image'], r['State'].get('StartedAt')) for name, r in rows.items()}
        # All API/plan workers and systemd jobs below run outside BACKUP_LOCK.
        if record is None:
            checked = plans(native)
            record = {'format': FORMAT, 'cutoverId': main['proof']['cutoverId'], 'phase': 'prepared',
                      'completed': [], 'plans': checked, 'archiveTransfersVerified': False}
            native.atomic(STATE, record)
        for parent in (WORK / 'retained', ARCHIVE_DROP.parent):
            native.safe(parent)
            parent.mkdir(mode=0o755 if parent == ARCHIVE_DROP.parent else 0o700, exist_ok=True)
        # The source remains frozen; remove only reviewed individual conditions.
        restore_cron(native, record)
        for name in JOBS:
            restore_job(native, name, record)
        current = native.catalog()
        require({name: (r['Id'], r['Image'], r['State'].get('StartedAt')) for name, r in current.items()} == before,
                'An application runtime changed during host-job restoration; progressed schedules retained for review.')
        final = {name: status(native, name + '.timer') for name in JOBS}
        require(native.ACTIVE.exists(), 'The separate final migration/NPM hold marker disappeared.')
        native.held(main['proof'])
        record.update(phase='complete', timers=final, sourceFrozen=True, npmRenewalStillHeld=True)
        native.atomic(STATE, record)
    say('REVIEWED NAS HOST SCHEDULES RESTORED. Cron/HBA and all four existing NAS job timers active.')
    say('ABS/Flora/TorBox watchdog first runs passed. Audiobook archive first transfer may still be running; no completed cloud transfer claimed.')
    say('Original Flora push-monitor pause retained. No InfiniDysk stop/restart behavior added.')
    say('Current application images/data, normal backup/recovery timers, NPM renewal hold and source freeze retained.')
    say('ARCHIVE CURRENT JOB STATE: ' + json.dumps(status(native, 'nas-torbox-audiobook-archive.service'), sort_keys=True))
    try:
        renewal_context(native)
    except Exception:
        say('Optional active-certificate readout unavailable; completed host schedules retained.')
    say('Remaining: NAS-only NPM certificate renewal, book functionality and final acceptance.')


def main():
    os.umask(0o077)
    boot, backup, native = controllers()
    native.safe(WORK)
    WORK.mkdir(mode=0o700, exist_ok=True)
    if sys.argv[1:] == ['--worker']:
        worker(boot, backup, native)
        return
    require(not sys.argv[1:] and globals().get('RESTORE_APPROVED_HOST_JOBS') is True,
            'The approved host schedule restoration flag is required.')
    source = globals().get('INSTALL_SOURCE')
    require(isinstance(source, str), 'The complete host schedule restoration source is required.')
    with native.lock(BASE / '.run.lock'):
        if status(native, UNIT)['ActiveState'] in ('active', 'activating', 'deactivating'):
            say('Existing host schedule restoration is already running.')
            return
        if SELF.exists():
            require(native.read(SELF) == source.encode(), 'A different existing host schedule worker was retained.')
        else:
            native.atomic(SELF, source.encode(), mode=0o700)
        subprocess.run(['systemctl', 'reset-failed', UNIT], capture_output=True)
        native.run('systemd-run', '--unit=' + UNIT, '--collect', '--property=Type=exec', '--property=UMask=0077',
                   '--property=RuntimeMaxSec=30min', '--description=Restore reviewed current NAS host schedules',
                   '/usr/bin/python3', '-u', str(SELF), '--worker')
    say('Reviewed host schedule restoration started in systemd. Closing SSH is safe.')
    say('Progress: sudo journalctl -u ' + UNIT + ' -f -n 35 --no-pager -o cat')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        message = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        say('STOP: ' + message + ' Completed steps and all current application data/images retained.')
        raise SystemExit(1)
