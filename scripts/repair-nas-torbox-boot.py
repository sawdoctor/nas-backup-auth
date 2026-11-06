#!/usr/bin/env python3
"""Allow only empty standard TorBox folders under the existing NAS FUSE mount."""
import contextlib
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile

SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
WORKER = Path('/usr/local/sbin/nas-torbox-media')
LOCK = Path('/run/lock/sawdoctor-nas-backup.lock')
RECOVERY = SSD / 'compose/torbox-media-center-nas/recovery/empty-folders'
PENDING = Path('/run/nas-torbox-media/backup-resume.json')
SERVICE = 'nas-torbox-media.service'
UNIT = 'nas-torbox-boot-repair'
BEFORE_SHA = '83ea3a55902c143caf579c28244987ad00e024557b53f0dbfec8f4b30dbe70d7'
AFTER_SHA = '5872d4a12c65b2d0feb78f9cb4b562dbef4af69a2831f0f47f57d30b702990ca'
OLD = """        if any(MOUNT.iterdir()):
            raise RuntimeError('The unmounted TorBox directory contains local files; leaving them untouched.')
"""
NEW = """        # Empty standard folders may remain below the FUSE mount after shutdown.
        # Keep them in place; refuse every file, link, mount or unexpected entry.
        for entry in MOUNT.iterdir():
            if (entry.name not in ('movies', 'series') or entry.is_symlink()
                    or not entry.is_dir() or mounts(entry) or any(entry.iterdir())):
                raise RuntimeError('The unmounted TorBox directory contains local files or unexpected entries; leaving them untouched.')
"""


def say(message):
    print(message, flush=True)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def no_links(path):
    for item in (path, *path.parents):
        if item.is_symlink():
            raise RuntimeError('An unexpected symbolic repair path was retained.')


def regular(path):
    no_links(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise RuntimeError('The expected regular repair file is unavailable.')
    return info


def run(*args, timeout=30):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('A repair check or service command failed; read the TorBox service journal for details.')
    return result.stdout


def atomic(path, data, mode=0o600, owner=None):
    no_links(path)
    fd, name = tempfile.mkstemp(prefix='.torbox-boot-repair-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            os.fchmod(output.fileno(), mode)
            if owner:
                os.fchown(output.fileno(), *owner)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def record(phase):
    atomic(RECOVERY / 'result.json', (json.dumps({
        'format': 'sawdoctor-nas-torbox-empty-folders-v1', 'phase': phase,
        'updatedUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'beforeSha256': BEFORE_SHA, 'afterSha256': AFTER_SHA,
        'quotaSettingsChanged': False, 'sourceChanged': False,
        'mountDirectoriesRemoved': False}, indent=2) + '\n').encode())


def patched(original):
    current = sha(original)
    if current == AFTER_SHA:
        return original
    if current != BEFORE_SHA or original.count(OLD.encode()) != 1:
        raise RuntimeError('The installed TorBox worker differs from the reviewed version; it was retained.')
    result = original.replace(OLD.encode(), NEW.encode(), 1)
    compile(result, str(WORKER), 'exec')
    if sha(result) != AFTER_SHA:
        raise RuntimeError('The repaired worker failed its identity check.')
    return result


def plex_stopped():
    state = json.loads(run('docker', 'inspect', '--format', '{{json .State}}', 'plex-nas'))
    if state.get('Running') or state.get('Paused'):
        raise RuntimeError('NAS Plex is running; retain it for a coordinated media change.')


def patch_locked():
    plex_stopped()
    active = run('systemctl', 'show', SERVICE, '-p', 'ActiveState', '--value').strip()
    if active not in ('inactive', 'failed', 'active'):
        raise RuntimeError('The NAS TorBox service is busy; retry after it finishes.')
    if PENDING.exists():
        regular(PENDING)
        pending = json.loads(PENDING.read_text())
        if pending.get('format') != 'Sawdoctor NAS TorBox CAM runtime v1' or pending.get('consumers') != []:
            raise RuntimeError('Pending CAM consumer recovery needs review before this repair.')
    info = regular(WORKER)
    original = WORKER.read_bytes()
    replacement = patched(original)
    no_links(RECOVERY)
    RECOVERY.mkdir(mode=0o700, parents=True, exist_ok=True)
    saved = RECOVERY / 'nas-torbox-media.before'
    if saved.exists():
        regular(saved)
        if sha(saved.read_bytes()) != BEFORE_SHA:
            raise RuntimeError('The prior worker recovery copy differs; it was retained.')
    elif sha(original) == BEFORE_SHA:
        atomic(saved, original)
    else:
        raise RuntimeError('The repaired worker has no verified original recovery copy.')
    if WORKER.read_bytes() != original:
        raise RuntimeError('The worker changed during preparation; it was retained.')
    if replacement != original:
        atomic(WORKER, replacement, stat.S_IMODE(info.st_mode), (info.st_uid, info.st_gid))
    if sha(WORKER.read_bytes()) != AFTER_SHA:
        raise RuntimeError('The installed repair did not verify.')
    record('patched')


def fuse_ready():
    for line in reversed(Path('/proc/self/mountinfo').read_text().splitlines()):
        left, right = line.split(' - ', 1)
        if left.split()[4] == '/mnt/torbox-media':
            fields = right.split()
            return fields[0] == 'fuse.main.py' or (fields[0] == 'fuse' and 'main.py' in fields[1])
    return False


def repair():
    say('Updating only the verified NAS TorBox empty-folder guard...')
    no_links(LOCK)
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('NAS backup/recovery is busy; retry this repair later.') from None
        patch_locked()
    # The service takes this lock itself. Release it BEFORE asking systemd to start.
    say('Guard updated. Starting the existing NAS TorBox service...')
    try:
        run('systemctl', 'start', SERVICE, timeout=660)
        if run('systemctl', 'show', SERVICE, '-p', 'ActiveState', '--value').strip() != 'active' or not fuse_ready():
            raise RuntimeError('The repaired NAS TorBox mount is not ready; inspect its service journal.')
        plex_stopped()
        record('complete')
    except BaseException:
        record('start-needs-review')
        raise
    say('NAS TORBOX BOOT GUARD REPAIRED. Existing FUSE service is active.')
    say('Only empty movies/series folders are accepted. No mount-folder entries were removed.')
    say('NAS Plex remains stopped. Compose, images, playback patches, quotas and OptiPlex were retained.')
    say('One small original-worker recovery copy: ' + str(RECOVERY / 'nas-torbox-media.before'))


def guard():
    if os.geteuid() != 0:
        raise RuntimeError('Run with sudo on the NAS.')
    if 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show') or not SSD.is_mount():
        raise RuntimeError('The expected NAS and mounted application SSD are required.')
    no_links(SSD)


def main():
    os.umask(0o077)
    guard()
    if sys.argv[1:] == ['--worker']:
        def terminate(_number, _frame):
            raise SystemExit(143)
        signal.signal(signal.SIGTERM, terminate)
        repair()
        return
    if sys.argv[1:]:
        raise RuntimeError('Unknown TorBox boot repair operation.')
    status = subprocess.run(['systemctl', 'show', UNIT + '.service', '-p', 'LoadState', '-p', 'ActiveState'],
                            capture_output=True, text=True, timeout=30)
    values = dict(line.split('=', 1) for line in status.stdout.splitlines() if '=' in line)
    active = values.get('ActiveState')
    if (status.returncode not in (0, 1) or values.get('LoadState') not in ('loaded', 'not-found')
            or active not in ('active', 'activating', 'deactivating', 'inactive', 'failed')
            or (values['LoadState'] == 'not-found' and active != 'inactive')):
        raise RuntimeError('The background repair service state could not be established.')
    if active in ('active', 'activating', 'deactivating'):
        say('The NAS TorBox boot repair is already running.')
        return
    source = globals().get('INSTALL_SOURCE')
    if source is None and '__file__' in globals():
        source = Path(__file__).read_text()
    if not source:
        raise RuntimeError('Use the complete reviewed repair command.')
    folder = Path(tempfile.mkdtemp(prefix='nas-torbox-boot-repair-', dir='/run'))
    worker = folder / 'worker.py'
    worker.write_text(source)
    worker.chmod(0o600)
    try:
        run('systemd-run', '--unit=' + UNIT, '--collect', '--property=Type=exec',
            '--property=UMask=0077', '--property=RuntimeMaxSec=15min',
            '--description=Repair NAS TorBox boot handling of empty standard folders',
            '/usr/bin/python3', '-u', str(worker), '--worker')
    except BaseException:
        worker.unlink(missing_ok=True)
        folder.rmdir()
        raise
    say('NAS TorBox boot repair started in systemd. Closing SSH is safe.')
    say('Check: sudo journalctl -u ' + UNIT + '.service -u ' + SERVICE + ' -n 25 --no-pager -o cat')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        say('STOP: ' + (str(error) if isinstance(error, RuntimeError) else type(error).__name__))
        sys.exit(1)
    finally:
        if sys.argv[1:] == ['--worker'] and '__file__' in globals():
            executable = Path(__file__)
            if (executable.parent.parent == Path('/run')
                    and executable.parent.name.startswith('nas-torbox-boot-repair-')
                    and executable.name == 'worker.py' and not executable.is_symlink()):
                executable.unlink(missing_ok=True)
                executable.parent.rmdir()
