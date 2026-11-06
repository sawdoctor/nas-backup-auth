#!/usr/bin/env python3
"""Relocate verified normal NAS backup sets to the identified backup SSD."""
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

OLD_UUID = 'e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6'
NEW_UUID = '631e3391-6a42-4158-9aa4-f7718ba0e7e9'
OLD_VOLUME = Path('/srv/dev-disk-by-uuid-' + OLD_UUID)
NEW_VOLUME = Path('/srv/dev-disk-by-uuid-' + NEW_UUID)
SOURCE = OLD_VOLUME / 'backups'
TARGET = NEW_VOLUME / 'backups'
STAGING = NEW_VOLUME / '.nas-normal-backup-transfer'
WORK = Path('/var/lib/sawdoctor-backup-disk-move')
LOCK = Path('/run/lock/sawdoctor-nas-backup.lock')
BACKUP = Path('/usr/local/sbin/nas-backup')
BACKUP_SHA = '1b3cbdf0446bf95ecbaea26cb2a9c1a0c63a2687fd725ae0ad9ab0f1d7693133'
RETRY = Path('/usr/local/sbin/nas-backup-retry-upload')
RETRY_BEFORE_SHA = 'a0e6ee669db6c2afe82b1016fb7447edb0c4fc8e4a6ff7151b351a3c0b8ae57a'
RETRY_AFTER_SHA = '0edbec73a149d1875401e3a6d3bf0be659bf8a08836b05f692cde08c033217e3'
RETRY_ANCHOR = ('ssd=' + str(OLD_VOLUME) + '\nmountpoint -q "$ssd"\nroot="$ssd/backups/sets"\n').encode()
RETRY_NEW = ('backup_volume=' + str(NEW_VOLUME) + '\nmountpoint -q "$backup_volume"\nroot="$backup_volume/backups/sets"\n').encode()
FORMAT = 'sawdoctor-normal-backup-disk-move-v1'
UNIT = 'nas-backup-disk-move'
MARKER = b'Sawdoctor NAS backup v1\n'
PHASES = {'copying', 'activating', 'activated', 'removing-old-payload', 'complete'}


def say(value):
    print(value, flush=True)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def no_links(path):
    for item in (path, *path.parents):
        if item.is_symlink():
            raise RuntimeError('An unexpected symbolic operation path was retained.')


def run(*args, timeout=30):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('A backup-transfer command failed; no unverified source copy was removed.')
    return result.stdout


def atomic(path, data, mode=0o600):
    no_links(path)
    fd, name = tempfile.mkstemp(prefix='.backup-transfer-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            os.fchmod(output.fileno(), mode)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def write_json(path, value):
    atomic(path, (json.dumps(value, indent=2, sort_keys=True) + '\n').encode())


def mount_check(volume, uuid, serial):
    no_links(volume)
    if not volume.is_mount():
        raise RuntimeError('An expected NAS backup/source SSD is not mounted.')
    fields = run('findmnt', '-rn', '--mountpoint', str(volume), '-o', 'UUID,FSTYPE,SOURCE').split()
    if len(fields) != 3 or fields[:2] != [uuid, 'ext4'] or not fields[2].startswith('/dev/'):
        raise RuntimeError('An expected NAS SSD filesystem identity differs.')
    parent = run('lsblk', '-dnro', 'PKNAME', fields[2]).strip()
    if not re.fullmatch(r'[a-zA-Z0-9]+', parent):
        raise RuntimeError('The NAS SSD parent device could not be identified.')
    if run('lsblk', '-dnro', 'SERIAL', '/dev/' + parent).strip() != serial:
        raise RuntimeError('The NAS SSD serial differs from the positively identified drive.')


def no_nested_mounts(root):
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        point = re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), line.split()[4])
        path = Path(point)
        if path == root or path.is_relative_to(root):
            raise RuntimeError('A nested or unexpected backup-directory mount was retained.')


def destination():
    script = '''set -eo pipefail
set +u
. /etc/default/openmediavault
. /usr/share/openmediavault/scripts/helper-functions
backup_ref=$(omv_config_get /config/system/backup/sharedfolderref)
printf '%s\\0%s\\0%s' "$(omv_get_sharedfolder_path "$backup_ref")" "$(omv_get_sharedfolder_mount_dir "$backup_ref")" "$(omv_config_get /config/system/backup/method)"
'''
    values = run('/bin/bash', '-c', script).split('\0')
    if len(values) != 3 or values[2] != 'fsarchiver':
        raise RuntimeError('Select the mounted FIKWOT backups folder and fsarchiver in OMV first.')
    paths = [Path(item) for item in values[:2]]
    for path in paths:
        no_links(path)
    try:
        resolved = [path.resolve(strict=True) for path in paths]
    except OSError:
        raise RuntimeError('The selected OMV backup path is unavailable.') from None
    if not all(path.is_absolute() for path in paths) or resolved != [TARGET, NEW_VOLUME]:
        raise RuntimeError('Select the mounted FIKWOT backups folder and fsarchiver in OMV first.')


def retry_patch(data):
    if sha(data) == RETRY_AFTER_SHA:
        return data
    if sha(data) != RETRY_BEFORE_SHA or data.count(RETRY_ANCHOR) != 1:
        raise RuntimeError('The upload-retry helper differs; it was retained for review.')
    changed = data.replace(RETRY_ANCHOR, RETRY_NEW, 1)
    if sha(changed) != RETRY_AFTER_SHA:
        raise RuntimeError('The upload-retry path change did not match its reviewed identity.')
    return changed


def load_state():
    no_links(WORK)
    if not WORK.exists():
        return None
    if not WORK.is_dir() or WORK.stat().st_uid != 0:
        raise RuntimeError('The backup-transfer state directory differs.')
    path = WORK / 'result.json'
    no_links(path)
    if not path.is_file() or path.stat().st_size > 1024**2:
        raise RuntimeError('An existing transfer directory lacks a valid small operation record.')
    record = json.loads(path.read_text())
    if (record.get('format') != FORMAT or record.get('source') != str(SOURCE)
            or record.get('target') != str(TARGET) or record.get('phase') not in PHASES):
        raise RuntimeError('An unrelated backup-transfer record was retained.')
    return record


def empty_directory_tree(path):
    return all(not child.is_symlink() and child.is_dir() and empty_directory_tree(child)
               for child in path.iterdir())


def remove_empty_children(path):
    for child in path.iterdir():
        if child.is_symlink() or not child.is_dir():
            raise RuntimeError('The new backup folder acquired files during activation; source retained.')
        remove_empty_children(child)
        child.rmdir()


def preflight():
    mount_check(OLD_VOLUME, OLD_UUID, '557S10A2T9UW')
    mount_check(NEW_VOLUME, NEW_UUID, '26060336624000699')
    if OLD_VOLUME.stat().st_dev == NEW_VOLUME.stat().st_dev:
        raise RuntimeError('The backup destination must be a separate SSD.')
    for path, volume in ((SOURCE, OLD_VOLUME), (TARGET, NEW_VOLUME)):
        no_links(path)
        if not path.is_dir() or path.stat().st_dev != volume.stat().st_dev:
            raise RuntimeError('An expected backup folder is unavailable on its SSD.')
        no_nested_mounts(path)
    no_links(BACKUP)
    if sha(BACKUP.read_bytes()) != BACKUP_SHA:
        raise RuntimeError('The normal NAS backup worker differs from the verified version.')
    destination()
    proposed = None
    no_links(RETRY)
    if RETRY.exists():
        if not RETRY.is_file() or RETRY.stat().st_uid != 0:
            raise RuntimeError('The upload-retry helper ownership/type differs.')
        proposed = retry_patch(RETRY.read_bytes())
    state = load_state()
    if not empty_directory_tree(TARGET) and (not state or state['phase'] == 'copying'):
        raise RuntimeError('The new backup folder is nonempty; existing destination files were retained.')
    no_links(STAGING)
    if STAGING.exists() and (not state or not STAGING.is_dir()
                            or STAGING.stat().st_uid != 0
                            or stat.S_IMODE(STAGING.stat().st_mode) != 0o700):
        raise RuntimeError('An unrelated transfer staging path was retained.')
    if STAGING.exists():
        no_nested_mounts(STAGING)
    if not shutil.which('cp'):
        raise RuntimeError('The existing GNU copy tool is unavailable.')
    return state, proposed


def tree(root, hashes=True, label=None):
    device = root.stat().st_dev
    result = {}
    links = {}
    cache = {}
    report = time.monotonic() + 30

    def visit(path):
        nonlocal report
        before = path.lstat()
        relative = str(path.relative_to(root))
        if before.st_dev != device:
            raise RuntimeError('A different filesystem was encountered inside the backup tree.')
        row = {'mode': stat.S_IMODE(before.st_mode), 'uid': before.st_uid, 'gid': before.st_gid,
               'mtime': before.st_mtime_ns, 'ctime': before.st_ctime_ns,
               'xattrs': {name: os.getxattr(path, name, follow_symlinks=False).hex()
                         for name in sorted(os.listxattr(path, follow_symlinks=False))}}
        if stat.S_ISREG(before.st_mode):
            row.update(kind='file', size=before.st_size)
            identity = (before.st_dev, before.st_ino)
            row['group'] = links.setdefault(identity, relative)
            if hashes:
                if identity not in cache:
                    digest = hashlib.sha256()
                    with path.open('rb') as source:
                        for block in iter(lambda: source.read(4 * 1024**2), b''):
                            digest.update(block)
                            if label and time.monotonic() >= report:
                                say(label + ': checked ' + str(len(result)) + ' entries so far...')
                                report = time.monotonic() + 30
                    cache[identity] = digest.hexdigest()
                row['sha256'] = cache[identity]
        elif stat.S_ISLNK(before.st_mode):
            row.update(kind='link', target=os.readlink(path))
        elif stat.S_ISDIR(before.st_mode):
            row['kind'] = 'directory'
        else:
            raise RuntimeError('A special device/socket inside the backup tree needs review.')
        after = path.lstat()
        if any(getattr(before, key) != getattr(after, key) for key in
               ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
            raise RuntimeError('A backup entry changed while being read; its source was retained.')
        result[relative] = row
        if row['kind'] == 'directory':
            for child in sorted(path.iterdir()):
                visit(child)

    visit(root)
    return result


def comparable(records, *, hashes=True, ignore_root=False):
    ignored = {'ctime'} | (set() if hashes else {'sha256'})
    return {path: {key: value for key, value in row.items() if key not in ignored}
            for path, row in records.items() if not (ignore_root and path == '.')}


def verify_copy(original, copied):
    if comparable(original, ignore_root=True) != comparable(copied, ignore_root=True):
        raise RuntimeError('Copied checksums, metadata, links or hard-link groups differ; source retained.')


def verify_backup_sets(root, manifest):
    if manifest.get('sets', {}).get('kind') != 'directory' or (root / 'sets').is_symlink():
        raise RuntimeError('The expected ordinary backup-set directory is unavailable.')
    count = 0
    for folder in sorted((root / 'sets').iterdir()):
        if not re.fullmatch(r'nas-[0-9]{8}T[0-9]{6}Z', folder.name):
            continue
        prefix = str(folder.relative_to(root)) + '/'
        marker = manifest.get(prefix + '_COMPLETE', {})
        if (folder.is_symlink() or not folder.is_dir() or marker.get('kind') != 'file'
                or marker.get('size') != len(MARKER) or (folder / '_COMPLETE').read_bytes() != MARKER):
            raise RuntimeError('A retained normal backup set has an unexpected completion record.')
        checks = folder / 'SHA256SUMS'
        if (manifest.get(prefix + 'SHA256SUMS', {}).get('kind') != 'file'
                or checks.is_symlink() or checks.stat().st_size > 4 * 1024**2):
            raise RuntimeError('A backup checksum list differs from the expected small regular file.')
        names = set()
        for line in checks.read_text().splitlines():
            match = re.fullmatch(r'([0-9a-f]{64}) [ *](\./[^\r\n]+)', line)
            if not match:
                raise RuntimeError('A retained backup checksum line has unsupported syntax.')
            name = PurePosixPath(match[2])
            if '..' in name.parts or name.is_absolute() or str(name) in names:
                raise RuntimeError('A retained backup checksum path is unsafe or repeated.')
            names.add(str(name))
            relative = str((folder / str(name)).relative_to(root))
            if manifest.get(relative, {}).get('sha256') != match[1]:
                raise RuntimeError('A retained backup failed its original SHA256 checksum list.')
        if not {'applications.tar.zst', 'RESTORE.txt', 'backup-script'}.issubset(names):
            raise RuntimeError('A retained backup lacks required recovery checksums.')
        count += 1
    if not count:
        raise RuntimeError('No completed normal NAS backup sets were found.')
    return count


def record(phase, **extra):
    value = {'format': FORMAT, 'phase': phase, 'source': str(SOURCE), 'target': str(TARGET),
             'updatedUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
             'normalBackupWorkerSha256': BACKUP_SHA, 'applicationServicesChanged': False,
             'cloudSettingsChanged': False, 'retentionChanged': False,
             'standbySnapshotsMoved': False, **extra}
    write_json(WORK / 'result.json', value)


def copy_payload():
    STAGING.mkdir(mode=0o700, exist_ok=True)
    payload = STAGING / 'payload'
    no_links(payload)
    if payload.exists():
        no_nested_mounts(payload)
        shutil.rmtree(payload)
    payload.mkdir(mode=0o700)
    say('Copying existing normal backup files with ownership, ACLs, xattrs and hard links...')
    with (WORK / 'private-error.log').open('w') as errors:
        child = subprocess.Popen(['cp', '-a', '--reflink=never', '--sparse=always', '--',
                                  str(SOURCE) + '/.', str(payload) + '/'],
                                 stdout=errors, stderr=errors)
        deadline = time.monotonic() + 3600
        report = time.monotonic() + 30
        try:
            while child.poll() is None:
                if time.monotonic() >= deadline:
                    raise RuntimeError('The bounded copy time expired; original backups are retained.')
                if time.monotonic() >= report:
                    allocated = int(run('du', '-sx', '-B1', str(payload)).split()[0])
                    say('Copied approximately ' + str(allocated // 1024**2) + ' MiB...')
                    report = time.monotonic() + 30
                time.sleep(1)
            if child.returncode:
                raise RuntimeError('The copy command failed; source retained. Private details: ' + str(WORK / 'private-error.log'))
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=15)
    return payload


def install_retry(proposed):
    if proposed is None:
        return
    current = RETRY.read_bytes()
    if current == proposed:
        return
    if sha(current) != RETRY_BEFORE_SHA:
        raise RuntimeError('The upload-retry helper changed during transfer; source retained.')
    previous = WORK / 'upload-retry.before'
    no_links(previous)
    if previous.exists() and previous.read_bytes() != current:
        raise RuntimeError('A different helper recovery copy was retained.')
    if not previous.exists():
        atomic(previous, current)
    info = RETRY.stat()
    atomic(RETRY, proposed, stat.S_IMODE(info.st_mode))
    os.chown(RETRY, info.st_uid, info.st_gid)
    if sha(RETRY.read_bytes()) != RETRY_AFTER_SHA:
        raise RuntimeError('The updated upload-retry helper did not verify.')


def verify_remaining_source(original, remaining):
    if set(remaining) - set(original):
        raise RuntimeError('New files appeared in the original backup folder; they were retained.')
    for path, row in remaining.items():
        if row['kind'] != original[path]['kind']:
            raise RuntimeError('An original backup entry changed type before cleanup; source retained.')
        if path == '.' or row['kind'] == 'directory':
            continue
        ignored = {'ctime', 'group'}
        if ({key: value for key, value in row.items() if key not in ignored}
                != {key: value for key, value in original[path].items() if key not in ignored}):
            raise RuntimeError('An original backup changed before cleanup; source retained.')


def transfer_locked():
    state, proposed = preflight()
    if state and state['phase'] == 'complete':
        if any(SOURCE.iterdir()):
            raise RuntimeError('The completed transfer now has unexpected new files at its old location.')
        if not (TARGET / 'sets').is_dir():
            raise RuntimeError('The completed transfer backup directory is unavailable.')
        say('The normal NAS backup relocation is already complete.')
        return
    if state:
        manifest_path = WORK / 'manifest.json'
        no_links(manifest_path)
        if not manifest_path.is_file() or manifest_path.stat().st_size > 64 * 1024**2:
            raise RuntimeError('The saved transfer manifest is unavailable or too large.')
        original = json.loads(manifest_path.read_text())
    else:
        say('Reading original backup checksums and file metadata; no new archive is created...')
        original = tree(SOURCE, label='Source SHA256 verification')
        verify_backup_sets(SOURCE, original)
        needed = int(run('du', '-sx', '-B1', str(SOURCE)).split()[0])
        if shutil.disk_usage(NEW_VOLUME).free < needed + 5 * 1024**3:
            raise RuntimeError('The backup SSD has insufficient verified-copy space.')
        WORK.mkdir(mode=0o700)
        write_json(WORK / 'manifest.json', original)
        record('copying', sourceAllocatedBytes=needed)
    if not state or state['phase'] == 'copying' or (state['phase'] == 'activating' and empty_directory_tree(TARGET)):
        if comparable(original, hashes=False) != comparable(tree(SOURCE, hashes=False), hashes=False):
            raise RuntimeError('The original backup tree changed before copying; source retained.')
        payload = copy_payload()
        say('Verifying every copied regular file against its original SHA256 and comparing metadata/links...')
        copied = tree(payload, label='Destination SHA256 verification')
        verify_copy(original, copied)
        verify_backup_sets(payload, copied)
        if comparable(original, hashes=False) != comparable(tree(SOURCE, hashes=False), hashes=False):
            raise RuntimeError('The original backup tree changed during copying; source retained.')
        destination()
        if not empty_directory_tree(TARGET):
            raise RuntimeError('The destination changed during copying; both copies were retained.')
        os.chmod(payload, 0o700)
        os.chown(payload, 0, TARGET.stat().st_gid)
        record('activating')
        no_nested_mounts(TARGET)
        remove_empty_children(TARGET)
        os.replace(payload, TARGET)
        record('activated')
        STAGING.rmdir()
    else:
        say('Rechecking the previously activated backup copy before finishing its cleanup...')
        copied = tree(TARGET, label='Destination SHA256 recheck')
        verify_copy(original, copied)
        verify_backup_sets(TARGET, copied)
        if STAGING.exists():
            no_nested_mounts(STAGING)
            shutil.rmtree(STAGING)
    install_retry(proposed)
    preflight()
    say('Flushing the verified backup SSD before removing the old payload...')
    run('sync', '-f', str(TARGET), timeout=300)
    say('Copied normal backups verified. Freeing only their matching old payload...')
    remaining = tree(SOURCE, label='Final source SHA256 check')
    verify_remaining_source(original, remaining)
    no_nested_mounts(SOURCE)
    record('removing-old-payload')
    for path in list(SOURCE.iterdir()):
        if path.is_symlink() or path.is_file():
            path.unlink()
        else:
            shutil.rmtree(path)
    run('sync', '-f', str(SOURCE), timeout=300)
    record('complete', verifiedBackupSets=verify_backup_sets(TARGET, copied),
           oldBackupFolderRetainedEmpty=True, uploadRetryUpdated=proposed is not None)
    say('NAS NORMAL BACKUPS MOVED AND VERIFIED: ' + str(TARGET))
    say('Old backup payload removed after checksum verification; its empty OMV folder is retained.')
    say('Applications, GDrive uploads, retention, timers and standby snapshots were retained.')
    say('Small operation record: ' + str(WORK / 'result.json'))


def guard():
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the NAS.')


def main():
    os.umask(0o077)
    guard()
    if sys.argv[1:] == ['--worker']:
        signal.signal(signal.SIGTERM, lambda _number, _frame: sys.exit(143))
        no_links(LOCK)
        fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError('NAS backup/recovery is busy; retry this transfer later.') from None
            transfer_locked()
        return
    if sys.argv[1:]:
        raise RuntimeError('Unknown normal-backup transfer operation.')
    status = subprocess.run(['systemctl', 'show', UNIT + '.service', '-p', 'LoadState', '-p', 'ActiveState'],
                            capture_output=True, text=True, timeout=15)
    state = dict(line.split('=', 1) for line in status.stdout.splitlines() if '=' in line)
    if (status.returncode not in (0, 1) or state.get('LoadState') not in ('loaded', 'not-found')
            or state.get('ActiveState') not in ('active', 'activating', 'deactivating', 'inactive', 'failed')):
        raise RuntimeError('The background backup-transfer service state is unavailable.')
    if state['ActiveState'] in ('active', 'activating', 'deactivating'):
        say('The normal NAS backup transfer is already running.')
        return
    source = globals().get('INSTALL_SOURCE')
    if source is None and '__file__' in globals():
        source = Path(__file__).read_text()
    if not source:
        raise RuntimeError('Use the complete reviewed transfer command.')
    folder = Path(tempfile.mkdtemp(prefix=UNIT + '-', dir='/run'))
    worker = folder / 'worker.py'
    worker.write_text(source)
    worker.chmod(0o600)
    try:
        run('systemd-run', '--unit=' + UNIT, '--collect', '--property=Type=exec',
            '--property=UMask=0077', '--property=Nice=10', '--property=IOSchedulingClass=idle',
            '--property=RuntimeMaxSec=90min', '--property=TimeoutStopSec=30s',
            '--description=Copy verify and relocate existing NAS normal backups to FIKWOT SSD',
            '/usr/bin/python3', '-u', str(worker), '--worker')
    except BaseException:
        worker.unlink(missing_ok=True)
        folder.rmdir()
        raise
    say('NAS normal-backup transfer started in systemd. Closing SSH is safe.')
    say('Progress: sudo journalctl -u ' + UNIT + '.service -n 20 --no-pager -o cat')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        say('STOP: ' + (str(error) if isinstance(error, RuntimeError) else type(error).__name__))
        sys.exit(1)
    finally:
        if sys.argv[1:] == ['--worker'] and '__file__' in globals():
            path = Path(__file__)
            if path.parent.parent == Path('/run') and path.parent.name.startswith(UNIT + '-') and path.name == 'worker.py':
                path.unlink(missing_ok=True)
                path.parent.rmdir()
