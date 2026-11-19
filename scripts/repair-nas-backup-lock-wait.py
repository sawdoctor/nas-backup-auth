#!/usr/bin/env python3
"""Confirm the exact lock-collision failure, then wait/retry the normal backup."""
import contextlib
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

APP = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
BACKUP = Path('/srv/dev-disk-by-uuid-631e3391-6a42-4158-9aa4-f7718ba0e7e9')
BASE = APP / 'compose/production-cutover'
WORK = BASE / 'backup-lock-wait-repair'
SELF = WORK / 'worker.py'
STATE = WORK / 'state.json'
PROGRAM = Path('/usr/local/sbin/nas-backup')
BEFORE_SHA = 'c73df0bd8860f4366806546e4ddd076b7cdd6434ff700e6c76d6adc21c073d3b'
AFTER_SHA = '5ef9016a0b61870531599b6cfa2f908247428559e7cd4c54ac6ce9ff38f1142f'
OLD = b"flock -n 9 || { echo 'Another NAS backup/recovery is running.'; exit 1; }\n"
NEW = b"echo 'Waiting up to 30 minutes for the NAS backup/recovery lock...'\nflock -w 1800 9 || { echo 'NAS backup/recovery lock was not released within 30 minutes.'; exit 1; }\n"
FAILURE = 'Another NAS backup/recovery is running.'
UNIT = 'nas-backup-lock-wait-repair.service'
AUDIT = BASE / 'post-migration-review/worker.py'
AUDIT_SHA = '7c6e6dec98c16d9662bace4cbe5a04b919dfde2d171918a28298b1f5eb40b6d6'
FORMAT = 'sawdoctor-backup-lock-wait-repair-v1'
REMOTE = 'gdrive:nas-backups/openmediavault/migration-review/nas-backup-lock-diagnostic-20261119.txt'


def require(value, message):
    if not value: raise RuntimeError(message)


def sha(body): return hashlib.sha256(body).hexdigest()
def say(message): print(message, flush=True)
def now(): return dt.datetime.now(dt.timezone.utc).isoformat()


def safe(path):
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'A symbolic repair path was retained.')


def read(path):
    safe(path); info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_size < 4 * 1024**2, 'A bounded regular repair input is required.')
    return path.read_bytes()


def atomic(path, value, reference=None, mode=0o600):
    safe(path)
    body = value if isinstance(value, bytes) else (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    info = reference.stat() if reference else None
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.repair-')
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), stat.S_IMODE(info.st_mode) if info else mode)
            if info: os.fchown(stream.fileno(), info.st_uid, info.st_gid)
            stream.write(body); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def command(*args, timeout=30):
    result = subprocess.run(args, capture_output=True, timeout=timeout)
    if result.returncode:
        atomic(WORK / 'private-command-error.json', {'command': list(args), 'status': result.returncode,
               'stdout': result.stdout[-65536:].decode(errors='replace'), 'stderr': result.stderr[-65536:].decode(errors='replace')})
        raise RuntimeError('A repair command failed; bounded private diagnostics retained.')
    return result.stdout


def properties(unit):
    names = ('Id', 'ActiveState', 'SubState', 'Result', 'ExecMainStatus', 'ExecMainStartTimestamp',
             'ExecMainExitTimestamp', 'InvocationID', 'TimeoutStartUSec', 'ExecStart')
    args = ['systemctl', 'show', '--no-pager', unit]
    for name in names: args += ['-p', name]
    result = subprocess.run(args, capture_output=True, timeout=15)
    require(result.returncode in (0, 1, 4), 'The current backup unit could not be read.')
    return dict(line.split('=', 1) for line in result.stdout.decode().splitlines() if '=' in line)


def timeout_seconds(value):
    if value == 'infinity': return math.inf
    units = {'us': 1e-6, 'ms': .001, 's': 1, 'min': 60, 'h': 3600, 'd': 86400}
    tokens = re.findall(r'(\d+(?:\.\d+)?)\s*(us|ms|min|s|h|d)', value)
    require(tokens and re.sub(r'\d+(?:\.\d+)?\s*(?:us|ms|min|s|h|d)', '', value).strip() == '',
            'The current backup unit timeout needs review.')
    return sum(float(number) * units[unit] for number, unit in tokens)


def patch_lines(body):
    require(body.count(OLD) == 1, 'The exact reviewed backup lock line differs.')
    return body.replace(OLD, NEW, 1)


def collision_confirmed(journal):
    return any(line.strip() == FAILURE for line in journal.splitlines())


def new_run(current, record):
    value = current.get('ExecMainStartTimestamp')
    return bool(value and value not in ('n/a', '0') and value != record['backupStartBefore'])


def capture(current):
    invocation = current.get('InvocationID', '')
    args = ['journalctl', '-u', 'nas-backup.service', '--no-pager', '-o', 'cat', '-n', '150']
    if re.fullmatch('[a-f0-9]{32}', invocation): args.append('_SYSTEMD_INVOCATION_ID=' + invocation)
    else: args += ['--since', 'today']
    journal = command(*args).decode(errors='replace')
    others = {name: properties(name) for name in ('nas-media-recovery.service', 'nas-torbox-audiobook-archive.service')}
    owners = subprocess.run(['lslocks', '--json', '-o', 'PID,COMMAND,TYPE,MODE,PATH'], capture_output=True, timeout=15)
    locks = []
    if owners.returncode == 0:
        try:
            locks = [row for row in json.loads(owners.stdout).get('locks', [])
                     if row.get('path') == '/run/lock/sawdoctor-nas-backup.lock']
        except ValueError: pass
    diagnostic = {'checkedUtc': now(), 'backup': current, 'relatedUnits': others, 'lockOwners': locks, 'journal': journal}
    payload = (json.dumps(diagnostic, sort_keys=True, indent=2) + '\n').encode()
    atomic(WORK / 'private-diagnostic.json', payload)
    say('BACKUP STATUS: ' + json.dumps({k: v for k, v in current.items() if k != 'ExecStart'}, sort_keys=True))
    say('SHARED LOCK OWNERS: ' + json.dumps(locks, sort_keys=True))
    for name, row in others.items():
        say('RELATED JOB ' + name + ': ' + json.dumps({k: v for k, v in row.items() if k != 'ExecStart'}, sort_keys=True))
    return journal, payload


def upload_diagnostic(payload):
    result = subprocess.run(['rclone', '--config', '/root/.config/rclone/rclone.conf', 'copyto',
                             str(WORK / 'private-diagnostic.json'), REMOTE, '--retries', '2',
                             '--contimeout', '10s', '--timeout', '45s'], capture_output=True, timeout=120)
    if result.returncode == 0: say('PRIVATE BACKUP DIAGNOSTIC READY: ' + sha(payload))
    else: say('Bounded backup diagnostic retained locally; upload unavailable.')


@contextlib.contextmanager
def repair_lock():
    path = BASE / '.run.lock'; safe(path)
    with path.open('a') as stream:
        try: fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise RuntimeError('Another NAS configuration operation is running; retained.') from None
        yield


def prepare():
    with repair_lock():
        record = json.loads(read(STATE)) if STATE.exists() else None
        body = read(PROGRAM)
        if record:
            require(record.get('format') == FORMAT and sha(body) == AFTER_SHA, 'The retained backup repair changed.')
            return record
        require(sha(body) == BEFORE_SHA, 'The current backup differs from the exact reviewed failed version.')
        current = properties('nas-backup.service')
        require(current.get('ActiveState') == 'failed' and current.get('Result') == 'exit-code'
                and current.get('ExecMainStatus') == '1', 'The selected failed backup is no longer current; no repair applied.')
        journal, payload = capture(current)
        if not collision_confirmed(journal):
            upload_diagnostic(payload)
            raise RuntimeError('The native journal does not confirm the exact shared-lock collision. No backup code changed.')
        say('NATIVE BACKUP FAILURE CONFIRMED: ' + FAILURE)
        require('path=/usr/local/sbin/nas-backup ;' in current.get('ExecStart', ''),
                'The existing backup service command differs.')
        require(timeout_seconds(current.get('TimeoutStartUSec', '')) >= 7200,
                'The existing backup service timeout needs review before adding a bounded lock wait.')
        proposed = patch_lines(body)
        require(sha(proposed) == AFTER_SHA, 'The narrowly corrected backup checksum differs.')
        syntax = subprocess.run(['bash', '-n'], input=proposed, capture_output=True, timeout=10)
        require(syntax.returncode == 0, 'The corrected backup shell syntax failed.')
        atomic(WORK / 'nas-backup.before', body, mode=0o700)
        require(read(PROGRAM) == body, 'The backup changed before its lock correction.')
        record = {'format': FORMAT, 'phase': 'prepared', 'createdUtc': now(), 'beforeSha256': BEFORE_SHA,
                  'afterSha256': AFTER_SHA, 'failedInvocationId': current.get('InvocationID'),
                  'backupStartBefore': current.get('ExecMainStartTimestamp')}
        atomic(STATE, record)
        atomic(PROGRAM, proposed, reference=PROGRAM)
        require(sha(read(PROGRAM)) == AFTER_SHA, 'The installed backup lock correction did not verify.')
        record['phase'] = 'patched'; atomic(STATE, record)
        say('BACKUP LOCK WAIT CORRECTED: same existing lock; wait up to 30 minutes instead of immediately losing the nightly run.')
        say('Backup contents, retention, cloud settings, schedule and application recovery commands retained.')
        return record


def monitor(record):
    if record.get('phase') == 'complete':
        say('The accepted backup lock correction is already complete.'); return
    current = properties('nas-backup.service')
    already_started = new_run(current, record)
    if not already_started:
        # Do not hold either configuration/backup lock while starting this
        # existing lock-owning service. systemd coalesces duplicate starts.
        record.update(runRequested=True, requestedUtc=now()); atomic(STATE, record)
        command('systemctl', 'reset-failed', 'nas-backup.service')
        command('systemctl', 'start', '--no-block', 'nas-backup.service')
    deadline = time.monotonic() + 7 * 3600
    while time.monotonic() < deadline:
        current = properties('nas-backup.service')
        started = new_run(current, record)
        active = current.get('ActiveState') in ('active', 'activating', 'deactivating')
        if started and not active:
            if current.get('Result') != 'success' or current.get('ExecMainStatus') != '0':
                journal, payload = capture(current); upload_diagnostic(payload)
                raise RuntimeError('The normal backup retry failed; corrected locking and current data retained for the recorded cause.')
            break
        say('Existing normal NAS backup: ' + current.get('ActiveState', 'unknown') + '/' + current.get('SubState', '')
            + '; waiting for the lock or normal SSD/cloud completion. Closing SSH is safe.')
        time.sleep(30)
    else: raise RuntimeError('The normal backup is still pending after the bounded monitor; no job or application was killed.')
    require(sha(read(AUDIT)) == AUDIT_SHA, 'The existing current backup verifier changed.')
    spec = importlib.util.spec_from_file_location('backup_wait_existing_audit', AUDIT)
    audit = importlib.util.module_from_spec(spec); spec.loader.exec_module(audit)
    rows = audit.show_units(); proof = audit.backup_proof(rows)
    require(proof.get('currentBackupConfirmed') is True, 'The normal backup returned success but its current SSD/cloud proof needs review.')
    complete = BACKUP / 'backups/sets' / proof['latestSet'] / '_COMPLETE'
    require(complete.stat().st_mtime >= dt.datetime.fromisoformat(record['requestedUtc']).timestamp() - 2,
            'The selected completed backup predates this normal retry.')
    ids = command('docker', 'ps', '-aq').decode().split()
    containers = json.loads(command('docker', 'inspect', *ids)) if ids else []
    stopped = [row['Name'].lstrip('/') for row in containers if not row['State']['Running']]
    recovery_file = Path('/var/lib/sawdoctor-nas-backup/running-containers')
    pending = bool(recovery_file.exists() and recovery_file.stat().st_size)
    record.update(phase='complete' if not stopped and not pending else 'backup-complete-recovery-review', completedUtc=now(), backupProof=proof,
                  stoppedContainers=stopped, pendingBackupRecoveryRecord=pending)
    atomic(STATE, record)
    say('NAS NORMAL BACKUP RETRY COMPLETE: ' + json.dumps(proof, sort_keys=True))
    say('POST-BACKUP CONTAINERS: ' + json.dumps({'stopped': stopped, 'pendingRecoveryRecord': pending}, sort_keys=True))
    if not stopped and not pending:
        say('NAS BACKUP LOCK REPAIR ACCEPTED. New normal SSD/Google Drive backup verified; existing nightly timer retained.')
    else:
        say('NORMAL SSD/CLOUD BACKUP VERIFIED; APPLICATION RECOVERY NEEDS REVIEW. Current recovery records retained.')
    say('Cleanup, Dockhand comparison and isolated InfiniDysk 2 test remain separate next steps.')


def main():
    os.umask(0o077)
    require(os.geteuid() == 0 and 'inet 192.168.0.220/' in subprocess.check_output(['ip', '-4', 'addr', 'show'], text=True),
            'Run with sudo on the NAS.')
    require(APP.is_mount() and BACKUP.is_mount(), 'The application and backup SSDs must be mounted.')
    safe(WORK); WORK.mkdir(mode=0o700, exist_ok=True)
    if sys.argv[1:] == ['--worker']:
        monitor(prepare()); return
    require(not sys.argv[1:] and globals().get('REPAIR_APPROVED_BACKUP_LOCK_WAIT') is True,
            'The approved current backup lock correction is required.')
    source = globals().get('INSTALL_SOURCE'); require(isinstance(source, str), 'Complete pinned repair source required.')
    with repair_lock():
        active = properties(UNIT).get('ActiveState')
        if active in ('active', 'activating', 'deactivating'):
            say('The guarded backup repair is already running.'); return
        if SELF.exists(): require(read(SELF) == source.encode(), 'A different existing repair worker was retained.')
        else: atomic(SELF, source.encode(), mode=0o700)
        subprocess.run(['systemctl', 'reset-failed', UNIT], capture_output=True)
        command('systemd-run', '--unit=' + UNIT, '--collect', '--property=Type=exec', '--property=UMask=0077',
                '--property=RuntimeMaxSec=8h', '--description=Confirm shared lock failure and retry existing NAS backup',
                '/usr/bin/python3', '-u', str(SELF), '--worker')
    say('Guarded NAS backup correction started. Closing SSH is safe.')
    say('Only a confirmed lock collision permits the one-line correction; the existing normal backup then runs.')
    say('The normal backup briefly stops applications for its consistent archive, then restores them as usual.')
    say('Progress: sudo journalctl -u ' + UNIT + ' -f -n 30 --no-pager -o cat')


if __name__ == '__main__':
    try: main()
    except Exception as error:
        message = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        say('STOP: ' + message + ' Current application data, certificates and source freeze retained.')
        raise SystemExit(1)
