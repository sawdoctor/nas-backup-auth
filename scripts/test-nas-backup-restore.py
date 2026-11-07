#!/usr/bin/env python3
"""Test selected NAS backup restores in temporary storage, without live changes."""
import contextlib
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile

BACKUP_UUID = '631e3391-6a42-4158-9aa4-f7718ba0e7e9'
SSD = Path('/srv/dev-disk-by-uuid-' + BACKUP_UUID)
SETS = SSD / 'backups/sets'
WORK = SSD / 'backups/restore-check'
LOCK = Path('/run/lock/sawdoctor-nas-backup.lock')
UNIT = 'nas-backup-restore-test'
MARKER = b'Sawdoctor NAS backup v1\n'
CLOUD = 'gdrive:nas-backups/openmediavault/sets'
DB = 'appdata/infinidysk-nas/config/db.sqlite'
CONFIGS = frozenset('appdata/dockmon/stacks/infinidysk-nas/' + name
                    for name in ('compose.yaml', 'compose.yml', 'compose.json'))
MAX_DB = 2 * 1024**3
MAX_WAL = 256 * 1024**2
FORMAT = 'sawdoctor-nas-backup-sample-restore-v1'


class RestoreError(RuntimeError):
    pass


def say(message):
    print(message, flush=True)


def regular(path):
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise RestoreError('A symbolic backup path was rejected.')
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_dev != SSD.stat().st_dev:
        raise RestoreError('The expected local backup file is unavailable.')
    return info


def small(path, limit=1024**2):
    if regular(path).st_size > limit:
        raise RestoreError('A backup control file exceeds its expected size.')
    return path.read_bytes()


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(4 * 1024**2), b''):
            value.update(block)
    return value.hexdigest()


def sums(data):
    result = {}
    for line in data.decode('utf-8').splitlines():
        match = re.fullmatch(r'([a-f0-9]{64}) [ *](\./[^\r\n]+)', line)
        if not match:
            raise RestoreError('The backup checksum list has unsupported syntax.')
        path = PurePosixPath(match[2])
        if '..' in path.parts or path.is_absolute() or str(path) in result:
            raise RestoreError('The backup checksum list has an unsafe or repeated name.')
        result[str(path)] = match[1]
    for name in ('applications.tar.zst', 'RESTORE.txt', 'backup-script'):
        if name not in result:
            raise RestoreError('A required backup checksum is missing.')
    return result


def newest_set():
    candidates = []
    if SETS.is_symlink() or not SETS.is_dir():
        raise RestoreError('The normal NAS backup directory is unavailable.')
    for path in SETS.iterdir():
        if re.fullmatch(r'nas-[0-9]{8}T[0-9]{6}Z', path.name) and path.is_dir() and not path.is_symlink():
            if (path / '_COMPLETE').exists() and (path / '_UPLOADED').exists():
                if small(path / '_COMPLETE') != MARKER:
                    raise RestoreError('A completed backup marker differs.')
                regular(path / '_UPLOADED')
                candidates.append(path)
    if not candidates:
        raise RestoreError('No completed, uploaded normal NAS backup is available.')
    return max(candidates, key=lambda path: path.name)


def cloud_read(backup, name, expected):
    result = subprocess.run([
        'rclone', '--config', '/root/.config/rclone/rclone.conf',
        '--contimeout', '10s', '--timeout', '30s', '--retries', '1',
        '--low-level-retries', '2', 'cat', CLOUD + '/' + backup.name + '/' + name,
        '--head', str(len(expected) + 1)], capture_output=True, timeout=90)
    if result.returncode or result.stdout != expected:
        raise RestoreError('A cloud recovery-file readback failed or differs; live data was retained.')


def copy_member(archive, member, destination, limit):
    if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or not 0 <= member.size <= limit:
        raise RestoreError('A selected restore member has an unexpected type or size.')
    source = archive.extractfile(member)
    if source is None:
        raise RestoreError('A selected backup member could not be read.')
    with source, destination.open('xb') as output:
        shutil.copyfileobj(source, output, 1024**2)
    if destination.stat().st_size != member.size:
        raise RestoreError('A selected restore member is truncated.')


def restore_samples(archive_path, target):
    found = set()
    config_name = None
    link_target = None
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(['zstd', '-d', '-c', '--', str(archive_path)],
                                   stdout=subprocess.PIPE, stderr=errors)
        try:
            with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
                while True:
                    member = archive.next()
                    if member is None:
                        break
                    relative = PurePosixPath(member.name)
                    if relative.is_absolute() or '..' in relative.parts:
                        raise RestoreError('An unsafe archive member was rejected.')
                    name = str(relative)
                    if name in (DB, DB + '-wal') or name in CONFIGS:
                        if name in found or (name in CONFIGS and config_name is not None):
                            raise RestoreError('A selected backup member is repeated.')
                        found.add(name)
                        if name == DB:
                            destination, limit = target / 'db.sqlite', MAX_DB
                        elif name == DB + '-wal':
                            destination, limit = target / 'db.sqlite-wal', MAX_WAL
                        else:
                            destination, limit = target / 'compose-sample', 2 * 1024**2
                            config_name = name
                        copy_member(archive, member, destination, limit)
                    elif (link_target is None and member.issym()
                          and name.startswith('appdata/infinidysk-nas/library/')
                          and relative.suffix.lower() in ('.mkv', '.mp4', '.m4v', '.avi', '.ts')):
                        link_target = member.linkname
                        os.symlink(link_target, target / 'library-link')
                    # next() is used directly so old member objects need not accumulate.
                    archive.members.clear()
            while process.stdout.read(1024**2):
                pass
            process.stdout.close()
            if process.wait(timeout=30):
                raise RestoreError('The application archive did not fully decompress.')
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
            if process.stdout is not None:
                process.stdout.close()
    if DB not in found or config_name is None or link_target is None:
        raise RestoreError('The expected database, Dockmon definition or library symlink is missing.')
    if os.readlink(target / 'library-link') != link_target:
        raise RestoreError('The sample library link target was not preserved.')
    return config_name, DB + '-wal' in found


def check_database(path):
    with contextlib.closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=15)) as connection:
        connection.execute('PRAGMA query_only=ON')
        if connection.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
            raise RestoreError('The restored InfiniDysk database failed its integrity check.')
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {'DavItems', 'NzbNames'} <= tables:
            raise RestoreError('The restored database lacks its expected catalogue tables.')
        count = connection.execute('SELECT COUNT(*) FROM DavItems').fetchone()[0]
        if count < 1:
            raise RestoreError('The restored catalogue has no file records.')
        return count


def check_compose(path):
    import yaml
    document = yaml.safe_load(path.read_text())
    services = document.get('services', {}) if isinstance(document, dict) else {}
    matches = [item for item in services.values()
               if isinstance(item, dict) and item.get('container_name') == 'infinidysk-nas']
    if len(matches) != 1 or not matches[0].get('image'):
        raise RestoreError('The restored Compose definition lacks the expected NAS service.')


def write_record(record):
    WORK.mkdir(mode=0o700, parents=True, exist_ok=True)
    if WORK.is_symlink() or not WORK.is_dir():
        raise RestoreError('The restore-result directory is unavailable.')
    with tempfile.NamedTemporaryFile(mode='w', dir=WORK, delete=False) as output:
        temporary = Path(output.name)
        try:
            json.dump(record, output, indent=2)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
            output.close()
            temporary.replace(WORK / 'result.json')
        finally:
            temporary.unlink(missing_ok=True)


def test_locked():
    backup = newest_set()
    write_record({'format': FORMAT, 'phase': 'checking', 'backupSet': backup.name,
                  'startedUtc': datetime.datetime.now(datetime.timezone.utc).isoformat()})
    archive = backup / 'applications.tar.zst'
    before = regular(archive)
    manifest = small(backup / 'SHA256SUMS')
    expected = sums(manifest)
    say('Testing normal NAS backup: ' + backup.name)
    say('Verifying the application archive SHA256 without making another archive...')
    if digest(archive) != expected['applications.tar.zst']:
        raise RestoreError('The application archive checksum differs.')
    for name in ('RESTORE.txt', 'backup-script'):
        if hashlib.sha256(small(backup / name)).hexdigest() != expected[name]:
            raise RestoreError('A local recovery-file checksum differs.')
    say('Reading back the small recovery files and checksum list from Google Drive...')
    for name in ('SHA256SUMS', '_COMPLETE', 'RESTORE.txt', 'backup-script'):
        cloud_read(backup, name, small(backup / name))
    if shutil.disk_usage(SSD).free < MAX_DB + MAX_WAL + 1024**3:
        raise RestoreError('Insufficient free space for the bounded temporary restore.')
    say('Restoring one database, its WAL if present, a Dockmon definition and one symlink into temporary storage...')
    with tempfile.TemporaryDirectory(prefix='.nas-sample-restore-', dir=SETS.parent) as name:
        target = Path(name)
        config_name, wal = restore_samples(archive, target)
        restored_bytes = sum(path.lstat().st_size for path in target.iterdir() if not path.is_symlink())
        count = check_database(target / 'db.sqlite')
        check_compose(target / 'compose-sample')
        say('Restored InfiniDysk database: integrity_check=ok; catalogue rows=' + str(count))
        say('Restored Dockmon definition parses; sample symlink target retained without reading video.')
    after = regular(archive)
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if any(getattr(before, key) != getattr(after, key) for key in fields):
        raise RestoreError('The backup archive changed during the sample check.')
    record = {'format': FORMAT, 'phase': 'complete', 'backupSet': backup.name,
              'completedUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'archiveSha256': expected['applications.tar.zst'], 'archiveBytes': before.st_size,
              'restoredBytes': restored_bytes, 'databaseRows': count, 'walRestored': wal,
              'composeMember': config_name, 'cloudRecoveryFilesMatched': 4,
              'temporaryCopiesRemoved': True, 'fullOsRestoreTested': False,
              'fullCloudApplicationArchiveDownloaded': False, 'applicationsStarted': False}
    write_record(record)
    say('NAS BACKUP SAMPLE RESTORE PASSED. Temporary restored copies removed.')
    say('Live data and services were retained. This sample does not test a full OS restore or a full cloud archive download.')
    say('Small result record: ' + str(WORK / 'result.json'))


def guard():
    if os.geteuid() != 0:
        raise RestoreError('Run with sudo on the NAS.')
    addresses = subprocess.check_output(['ip', '-4', 'addr', 'show'], text=True, timeout=15)
    if 'inet 192.168.0.220/' not in addresses or not SSD.is_mount() or SSD.is_symlink():
        raise RestoreError('The expected NAS and mounted FIKWOT backup SSD are required.')
    identity = subprocess.check_output(['findmnt', '-rn', '--mountpoint', str(SSD),
                                        '-o', 'UUID,FSTYPE'], text=True, timeout=15).split()
    if identity != [BACKUP_UUID, 'ext4']:
        raise RestoreError('The backup SSD filesystem identity differs; no restore was started.')
    for program in ('zstd', 'rclone'):
        if not shutil.which(program):
            raise RestoreError('A required existing restore program is unavailable.')


def main():
    os.umask(0o077)
    guard()
    if sys.argv[1:] == ['--worker']:
        def terminate(_number, _frame):
            raise SystemExit(143)
        signal.signal(signal.SIGTERM, terminate)
        fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RestoreError('NAS backup/recovery is busy; retry this sample test later.') from None
            try:
                test_locked()
            except BaseException as error:
                write_record({'format': FORMAT, 'phase': 'stopped',
                              'stoppedUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                              'errorType': type(error).__name__, 'applicationsStarted': False})
                raise
        return
    if sys.argv[1:]:
        raise RestoreError('Unknown sample restore operation.')
    active = subprocess.run(['systemctl', 'show', UNIT + '.service', '-p', 'ActiveState', '--value'],
                            capture_output=True, text=True, timeout=15)
    if active.stdout.strip() in ('active', 'activating', 'deactivating'):
        say('The NAS backup sample restore is already running.')
        return
    source = globals().get('INSTALL_SOURCE')
    if source is None and '__file__' in globals():
        source = Path(__file__).read_text()
    if not source:
        raise RestoreError('Use the complete reviewed sample restore command.')
    run_dir = Path(tempfile.mkdtemp(prefix='nas-backup-restore-test-', dir='/run'))
    worker = run_dir / 'worker.py'
    worker.write_text(source)
    worker.chmod(0o600)
    try:
        subprocess.run(['systemd-run', '--unit=' + UNIT, '--collect', '--property=Type=exec',
                        '--property=UMask=0077', '--property=Nice=10', '--property=IOSchedulingClass=idle',
                        '--property=RuntimeMaxSec=30min', '--property=TimeoutStopSec=30s',
                        '--description=Test a normal NAS backup in temporary storage',
                        '/usr/bin/python3', '-u', str(worker), '--worker'],
                       check=True, timeout=30, capture_output=True)
    except BaseException:
        worker.unlink(missing_ok=True)
        run_dir.rmdir()
        raise
    say('NAS backup sample restore started in systemd. Closing SSH is safe.')
    say('Progress: sudo journalctl -u ' + UNIT + '.service -n 20 --no-pager -o cat')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        say('STOP: ' + (str(error) if isinstance(error, RestoreError) else type(error).__name__) +
            '; no live restore or application start was performed.')
        sys.exit(1)
    finally:
        if sys.argv[1:] == ['--worker'] and '__file__' in globals():
            executable = Path(__file__)
            if (executable.parent.parent == Path('/run')
                    and executable.parent.name.startswith('nas-backup-restore-test-')
                    and executable.name == 'worker.py' and not executable.is_symlink()):
                executable.unlink(missing_ok=True)
                executable.parent.rmdir()
