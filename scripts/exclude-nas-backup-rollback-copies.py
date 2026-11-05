#!/usr/bin/env python3
"""Exclude two retained migration rollback trees from future normal NAS backups."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

SIGNATURE = 'Sawdoctor NAS backup rollback exclusions v1'
SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
WORKER = Path('/usr/local/sbin/nas-backup')
LOCK = Path('/run/lock/sawdoctor-nas-backup.lock')
WORK = SSD / 'compose/backup-scope'
BEFORE_SHA = 'f4b447ed58e0a2654095881a3c2d1ac5fa8dcc0abc36e09f81fbb598e6d4fafb'
EXCLUSIONS = (
    'compose/plex-nas/recovery/before-standby-refresh',
    'compose/infinidysk-nas/recovery/before-latest',
)
ANCHOR = "  --exclude='appdata/silo/download-artifacts/*' \\\n"


def digest(value):
    return hashlib.sha256(value).hexdigest()


def patch(original):
    text = original.decode('utf-8')
    addition = ''.join("  --exclude='" + path + "' \\\n" for path in EXCLUSIONS)
    if text.count(ANCHOR) != 1:
        raise RuntimeError('The existing backup archive selection differs; it was retained.')
    if addition in text:
        restored = text.replace(addition, '', 1).encode()
        expected = restored.decode().replace(ANCHOR, ANCHOR + addition, 1).encode()
        if digest(restored) != BEFORE_SHA or original != expected:
            raise RuntimeError('The backup differs beyond the reviewed exclusions; it was retained.')
        return original
    if digest(original) != BEFORE_SHA:
        raise RuntimeError('The installed backup differs from the reviewed mount-aware worker; it was retained.')
    return text.replace(ANCHOR, ANCHOR + addition, 1).encode()


def no_symlinks(path):
    for item in (path, *path.parents):
        if item.is_symlink():
            raise RuntimeError('An unexpected symbolic installer path was retained: ' + str(item))


def atomic(path, data, mode=0o600, owner=None):
    no_symlinks(path)
    fd, temporary = tempfile.mkstemp(prefix='.backup-scope-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            os.fchmod(output.fileno(), mode)
            if owner is not None:
                os.fchown(output.fileno(), *owner)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def install_locked():
    no_symlinks(WORKER)
    no_symlinks(WORK)
    if not WORKER.is_file():
        raise RuntimeError('The existing NAS backup worker is missing.')
    original = WORKER.read_bytes()
    proposed = patch(original)
    for unit in ('nas-backup.service', 'nas-backup-resume.service', 'nas-backup-upload.service'):
        result = subprocess.run(
            ['systemctl', 'show', '--no-pager', unit, '-p', 'ActiveState', '--value'],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
        if result.returncode and unit != 'nas-backup-upload.service':
            raise RuntimeError('The NAS backup service state could not be checked; the worker was retained.')
        if result.stdout.strip() in ('active', 'activating', 'deactivating'):
            # The oneshot resume unit normally stays active after completing.
            if unit == 'nas-backup-resume.service':
                substate = subprocess.check_output(
                    ['systemctl', 'show', '--no-pager', unit, '-p', 'SubState', '--value'],
                    text=True, timeout=10).strip()
                if result.stdout.strip() == 'active' and substate == 'exited':
                    continue
            raise RuntimeError('A NAS backup operation is active; let it finish before retrying.')
    syntax = subprocess.run(['/bin/bash', '-n'], input=proposed, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=10)
    if syntax.returncode:
        raise RuntimeError('The proposed backup did not pass its shell syntax check.')
    marker = WORK / '.owner'
    if WORK.exists():
        if not WORK.is_dir() or marker.is_symlink() or not marker.is_file() or marker.read_text() != SIGNATURE:
            raise RuntimeError('An unrelated backup-scope folder was retained.')
    else:
        WORK.mkdir(mode=0o700)
        atomic(marker, SIGNATURE.encode())
    recovery = WORK / 'recovery'
    no_symlinks(recovery)
    recovery.mkdir(mode=0o700, exist_ok=True)
    before = recovery / 'nas-backup.before'
    no_symlinks(before)
    if before.exists():
        if not before.is_file() or digest(before.read_bytes()) != BEFORE_SHA:
            raise RuntimeError('The original backup recovery copy differs; it was retained.')
    elif original != proposed:
        atomic(before, original, 0o700)
    else:
        raise RuntimeError('The expected original backup recovery copy is missing.')
    if WORKER.read_bytes() != original:
        raise RuntimeError('The NAS backup changed during review; it was retained.')
    if proposed != original:
        info = WORKER.stat()
        atomic(WORKER, proposed, stat.S_IMODE(info.st_mode), (info.st_uid, info.st_gid))
    if WORKER.read_bytes() != proposed:
        raise RuntimeError('The backup update could not be verified; the recovery copy was retained.')
    record = {'format': SIGNATURE, 'beforeSha256': BEFORE_SHA,
              'afterSha256': digest(proposed), 'excludedPaths': list(EXCLUSIONS)}
    atomic(WORK / 'applied.json', (json.dumps(record, indent=2) + '\n').encode())
    print('NAS BACKUP SCOPE UPDATED: two old rollback trees excluded from future normal backups.')
    print('Live Plex/InfiniDysk data, custom code, trial records, mount recovery and three-set retention retained.')
    print('Existing backups and rollback trees were not deleted. No backup, image pull or service restart was started.')
    print('One small original-script recovery copy: ' + str(before))
    print('Updated worker SHA256: ' + digest(proposed))


def main():
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in subprocess.check_output(
            ['ip', '-4', 'addr', 'show'], text=True, timeout=10):
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220.')
    if not SSD.is_mount():
        raise RuntimeError('The NAS application SSD is not mounted.')
    no_symlinks(LOCK)
    with LOCK.open('a') as locked:
        try:
            fcntl.flock(locked, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('The NAS backup/migration lock is busy; let the current operation finish.') from None
        install_locked()


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit('STOP: ' + str(error))
