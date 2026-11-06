#!/usr/bin/env python3
"""Remove four redundant compressed transfers after verifying retained snapshots."""
import contextlib
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile

SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
LOCK = Path('/run/lock/sawdoctor-nas-backup.lock')
UNIT = 'nas-transfer-archive-cleanup'
FORMAT = 'sawdoctor-nas-transfer-archive-cleanup-v1'
BUNDLES = {
    'core-optiplex': 'sawdoctor-core-export-v1',
    'books-optiplex': 'sawdoctor-books-export-v1',
    'support-optiplex': 'sawdoctor-support-export-v1',
    'plex-npm-optiplex': 'sawdoctor-plex-npm-export-v1',
}


def say(message):
    print(message, flush=True)


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def no_symlinks(path):
    for item in (path, *path.parents):
        if item.is_symlink():
            raise RuntimeError('An unexpected symbolic cleanup path was retained.')


def regular(path):
    no_symlinks(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_dev != SSD.stat().st_dev:
        raise RuntimeError('An unexpected cleanup file or filesystem was retained.')
    return info


def fingerprint(path):
    value = regular(path)
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(4 * 1024**2), b''):
            result.update(block)
    return result.hexdigest()


def atomic(path, value):
    no_symlinks(path)
    fd, name = tempfile.mkstemp(prefix='.record-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as output:
            json.dump(value, output, indent=2)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def directory(path):
    no_symlinks(path)
    if not path.is_dir() or path.stat().st_dev != SSD.stat().st_dev:
        raise RuntimeError('The expected SSD directory is unavailable.')


def lock_file(stack, path):
    no_symlinks(path)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    stream = stack.enter_context(os.fdopen(fd, 'a'))
    try:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise RuntimeError('A backup, transfer or cleanup is active; no further files were removed.') from None


def guard():
    if os.geteuid() != 0:
        raise RuntimeError('Run with sudo on the NAS.')
    addresses = subprocess.check_output(['ip', '-4', 'addr', 'show'], text=True, timeout=15)
    if 'inet 192.168.0.220/' not in addresses:
        raise RuntimeError('Run only on the NAS at 192.168.0.220.')
    no_symlinks(SSD)
    if not SSD.is_mount():
        raise RuntimeError('The NAS application SSD is not mounted.')
    for program in ('tar', 'zstd', 'sha256sum'):
        if not shutil.which(program):
            raise RuntimeError('A required existing verification program is unavailable.')


def verify_checksums_paths(snapshot, checksums):
    # GNU checksum input must not follow a replaced link into a streaming mount.
    count = 0
    with checksums.open() as source:
        for line in source:
            if not re.match(r'^[a-f0-9]{64} [ *]', line):
                raise RuntimeError('Unsupported checksum syntax; all archives were retained.')
            name = line[66:].removesuffix('\n')
            relative = PurePosixPath(name)
            if relative.is_absolute() or '..' in relative.parts or not relative.parts:
                raise RuntimeError('An unsafe checksum path was retained.')
            regular(snapshot / relative)
            count += 1
    if count < 3:
        raise RuntimeError('The saved snapshot checksum list is incomplete.')


def checked(command, snapshot, error_path):
    no_symlinks(error_path)
    with error_path.open('wb') as errors:
        result = subprocess.run(command, cwd=snapshot, stdout=errors, stderr=errors,
                                timeout=7200, check=False)
    if result.returncode:
        raise RuntimeError('Snapshot comparison failed; all candidate archives were retained. '
                           'Private details: ' + str(error_path))
    error_path.unlink()


def verify_bundle(stage, expected_format, error_path):
    directory(stage)
    archive = stage / 'export.tar.zst'
    if not archive.exists() and not archive.is_symlink():
        say(stage.name + ': compressed archive already absent; retained snapshot unchanged.')
        return None
    snapshot = stage / 'snapshot'
    directory(snapshot)
    paths = [archive, stage / 'staged.json', snapshot / 'manifest.json', snapshot / 'SHA256SUMS']
    saved = {str(path): fingerprint(path) for path in paths}
    marker = json.loads(paths[1].read_text())
    manifest = json.loads(paths[2].read_text())
    expected_hash = marker.get('archiveSha256', '')
    if (not re.fullmatch('[a-f0-9]{64}', expected_hash)
            or manifest.get('format') != expected_format
            or manifest.get('sourceHost') != '192.168.0.29'
            or not manifest.get('createdUtc')
            or marker.get('createdUtc') != manifest.get('createdUtc')):
        raise RuntimeError('The saved transfer identity differs; all archives were retained.')
    say(stage.name + ': checking the compressed archive identity...')
    if digest(archive) != expected_hash:
        raise RuntimeError('A compressed archive checksum differs; all archives were retained.')
    verify_checksums_paths(snapshot, paths[3])
    say(stage.name + ': verifying retained file checksums...')
    checked(['sha256sum', '--quiet', '--strict', '-c', 'SHA256SUMS'], snapshot, error_path)
    say(stage.name + ': comparing archive contents, links and saved metadata...')
    checked(['tar', '--compare', '--numeric-owner', '--acls', '--xattrs',
             '-I', 'zstd', '-f', str(archive)], snapshot, error_path)
    for path, before in saved.items():
        if fingerprint(Path(path)) != before:
            raise RuntimeError('A transfer changed during verification; all archives were retained.')
    return {'archive': str(archive), 'snapshot': str(snapshot),
            'sha256': expected_hash, 'archiveBytes': saved[str(archive)][2],
            'createdUtc': manifest['createdUtc'], 'status': 'verified', 'fingerprints': saved}


def cleanup_locked():
    directory(SSD / 'migration')
    audit = SSD / 'migration/transfer-archive-cleanup'
    no_symlinks(audit)
    audit.mkdir(mode=0o700, exist_ok=True)
    directory(audit)
    record_path = audit / 'record.json'
    if record_path.exists():
        regular(record_path)
        if json.loads(record_path.read_text()).get('format') != FORMAT:
            raise RuntimeError('An unrelated cleanup record was retained.')
    record = {'format': FORMAT, 'startedUtc': now(), 'phase': 'verifying',
              'items': [], 'removedBytes': 0}
    try:
        with contextlib.ExitStack() as stack:
            for name in BUNDLES:
                stage = SSD / 'migration' / name
                directory(stage)
                lock_file(stack, stage / '.copy.lock')
            plans = []
            for name, expected_format in BUNDLES.items():
                plan = verify_bundle(SSD / 'migration' / name, expected_format, audit / 'private-error.log')
                if plan:
                    plans.append(plan)
            if not plans:
                say('All four compressed archives are already absent. No data was removed; prior cleanup record retained.')
                subprocess.run(['df', '-h', str(SSD)], check=True, timeout=15)
                return
            # Every present candidate must verify before the first deletion.
            record['items'] = [{k: v for k, v in plan.items() if k != 'fingerprints'} for plan in plans]
            record['phase'] = 'verified'
            atomic(record_path, record)
            for plan in plans:
                for path, before in plan['fingerprints'].items():
                    if fingerprint(Path(path)) != before:
                        raise RuntimeError('A verified transfer changed before cleanup; remaining archives retained.')
            free_before = shutil.disk_usage(SSD).free
            for plan, item in zip(plans, record['items']):
                archive = Path(plan['archive'])
                if fingerprint(archive) != plan['fingerprints'][str(archive)]:
                    raise RuntimeError('An archive changed before removal; remaining archives retained.')
                item['status'] = 'removing'
                atomic(record_path, record)
                archive.unlink()  # The only persistent data removal in this program.
                item['status'] = 'removed'
                record['removedBytes'] += plan['archiveBytes']
                atomic(record_path, record)
                say(archive.parent.name + ': redundant compressed archive removed; snapshot retained.')
            record.update(phase='complete', completedUtc=now(),
                          freeBytesBefore=free_before, freeBytesAfter=shutil.disk_usage(SSD).free)
            atomic(record_path, record)
    except BaseException as error:
        record.update(phase='stopped', stoppedUtc=now(), errorType=type(error).__name__)
        atomic(record_path, record)
        raise
    say('NAS TRANSFER ARCHIVE CLEANUP COMPLETE: removed ' +
        str(round(record['removedBytes'] / 1024**3, 2)) + ' GiB of redundant archives.')
    say('Extracted snapshots, exact image archives, live appdata, backup sets and recovery trees retained.')
    say('InfiniDysk initial export and nightly standby were outside this cleanup.')
    subprocess.run(['df', '-h', str(SSD)], check=True, timeout=15)


def main():
    os.umask(0o077)
    guard()
    if sys.argv[1:] == ['--worker']:
        with contextlib.ExitStack() as stack:
            lock_file(stack, LOCK)
            cleanup_locked()
        return
    if sys.argv[1:]:
        raise RuntimeError('Unknown cleanup operation.')
    active = subprocess.run(['systemctl', 'show', UNIT + '.service', '-p', 'ActiveState', '--value'],
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15)
    if active.stdout.strip() in ('active', 'activating', 'deactivating'):
        say('The NAS transfer archive cleanup is already running.')
        return
    source = globals().get('INSTALL_SOURCE')
    if source is None and '__file__' in globals():
        source = Path(__file__).read_text()
    if not source:
        raise RuntimeError('Use the complete reviewed cleanup command.')
    run_dir = Path(tempfile.mkdtemp(prefix='nas-transfer-archive-cleanup-', dir='/run'))
    worker = run_dir / 'worker.py'
    worker.write_text(source)
    worker.chmod(0o600)
    try:
        subprocess.run(['systemd-run', '--unit=' + UNIT, '--collect',
                        '--property=Type=exec', '--property=UMask=0077', '--property=Nice=10',
                        '--description=Verify retained snapshots and remove redundant NAS transfer archives',
                        '/usr/bin/python3', '-u', str(worker), '--worker'], check=True, timeout=30)
    except BaseException:
        worker.unlink(missing_ok=True)
        run_dir.rmdir()
        raise
    say('NAS archive verification and cleanup started in systemd. Closing SSH is safe.')
    say('Progress: sudo journalctl -u ' + UNIT + '.service -n 20 --no-pager -o cat')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        say('STOP: ' + (str(error) if isinstance(error, RuntimeError) else type(error).__name__))
        sys.exit(1)
    finally:
        # Only the temporary executable in /run is removed, never an installed helper.
        if sys.argv[1:] == ['--worker'] and '__file__' in globals():
            executable = Path(__file__)
            if (executable.parent.parent == Path('/run')
                    and executable.parent.name.startswith('nas-transfer-archive-cleanup-')
                    and executable.name == 'worker.py' and not executable.is_symlink()):
                executable.unlink(missing_ok=True)
                executable.parent.rmdir()
