#!/usr/bin/env python3
"""Refresh only the two existing private working trees; never freeze production.

The resulting copies are deliberately NOT a backup or an import source. A later
coordinated stop and checksum delta must establish a common frozen source point.
No existing transfer archive, received snapshot or recovery copy is removed.
"""
import contextlib
import datetime as dt
import fcntl
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import subprocess
import sys
import tempfile

FORMAT = 'sawdoctor-production-live-precopy-v1'
BASE = Path('/var/lib/sawdoctor-production-precopy')
WORKER = BASE / 'worker.py'
SEED = Path('/var/lib/sawdoctor-plex-handover')
APPS = Path('/var/lib/sawdoctor-migration-standby')
STANDBY = Path('/usr/local/sbin/nas-migration-standby')
BACKUP_LOCK = Path('/run/lock/plex-daily-backup.lock')
STANDBY_SHA = 'f320f99ad7d07c2db77cc34a937d6b4d831f3b9c7fd8f135351b0dece082fd92'
SEED_SHA = 'c776af1c4cff9890bf1306d889ba7cf946a2447974cc99eaf9dcda650152434f'
WATCH_SHA = '8f3531b26fc3f822067664d3310761e970f7ab7bab97189f927b2cb042d3e73a'
UNIT = 'optiplex-production-precopy.service'
MAX_SOURCE_BYTES = 96 * 1024**3
PENDING = (
    Path('/var/lib/sawdoctor-plex-production-hold/hold.json'),
    Path('/var/lib/sawdoctor-plex-trial/hold.json'),
    APPS / 'resume.json', APPS / 'paused-timers.json',
    Path('/var/lib/sawdoctor-nas-plex-npm-export/resume.json'),
    Path('/run/plex-daily-backup-active'),
)


def say(value):
    print(value, flush=True)


def safe(path):
    path = Path(path)
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise RuntimeError('A symbolic working/input path was retained: ' + path.name)


def read(path, limit=2 * 1024**2):
    safe(path)
    if not path.is_file() or path.stat().st_size > limit:
        raise RuntimeError('A required bounded working record is unavailable: ' + path.name)
    return path.read_bytes()


def atomic(path, data):
    safe(path)
    if not isinstance(data, bytes):
        data = (json.dumps(data, indent=2) + '\n').encode()
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(name, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        Path(name).unlink(missing_ok=True)


def run(*args, timeout=30):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('A precopy query failed: ' + args[0] + '; private output withheld.')
    return result.stdout


def load(path, expected, name):
    data = read(path)
    if hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError('A reviewed helper changed: ' + path.name)
    sys.dont_write_bytecode = True
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    value = importlib.util.module_from_spec(spec)
    loader.exec_module(value)
    return value


def owner():
    safe(BASE)
    marker = BASE / 'owner.json'
    if BASE.exists():
        if json.loads(read(marker)) != {'format': FORMAT}:
            raise RuntimeError('An unrecognized refresh directory was retained.')
    else:
        BASE.mkdir(mode=0o700)
        atomic(marker, {'format': FORMAT})


def seed_record(previous, before, roots):
    """A legitimate backup restart is allowed; changed identity or final state is not."""
    if (previous.get('format') != 'sawdoctor-plex-handover-precopy-v1'
            or previous.get('phase') not in ('seeding', 'seeded-running-not-frozen')
            or previous.get('consistentSnapshot') is not False
            or previous.get('sourceStopPerformed') is not False
            or previous.get('sourceRoots') != roots
            or previous.get('container', {}).get('Id') != before['Id']
            or previous.get('container', {}).get('Image') != before['Image']):
        raise RuntimeError('The old Plex seed advanced or changed identity; it was retained.')
    return {**previous, 'phase': 'seeding', 'container': before,
            'consistentSnapshot': False, 'sourceStopPerformed': False,
            'refreshStartedUtc': dt.datetime.now(dt.timezone.utc).isoformat()}


def validate_work(work, roots, standby_format):
    safe(work)
    if (not work.is_dir() or work.is_mount()
            or read(work / '.standby-owner').decode() != standby_format):
        raise RuntimeError('The existing application working tree is not owned by the nightly job.')
    for label, entry in roots.items():
        relative = PurePosixPath(entry['snapshot'])
        if (len(relative.parts) != 2 or relative.parts[0] not in ('data', 'files')
                or relative.parts[1] != label or relative.is_absolute()
                or '..' in relative.parts):
            raise RuntimeError('A working-tree destination is outside its reviewed root.')
        target = work.joinpath(*relative.parts)
        safe(target)
        if target.is_mount():
            raise RuntimeError('A working-tree destination unexpectedly became a mount.')


def reject_nested_mounts(roots, mountinfo=None):
    if mountinfo is None:
        mountinfo = Path('/proc/self/mountinfo').read_text()
    for line in mountinfo.splitlines():
        field = line.split()[4]
        field = re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), field)
        target = Path(field)
        if any(target.is_relative_to(root) for root in roots):
            raise RuntimeError('A mounted filesystem exists inside a private working tree; retained.')


def retire_work_checksums(work):
    """Retain old small manifests without leaving cold-copy labels on live files."""
    saved = BASE / 'metadata-before-first-refresh'
    for name in ('manifest.json', 'SHA256SUMS'):
        source = work / name
        safe(source)
        if not source.exists():
            continue
        if source.is_mount() or not source.is_file():
            raise RuntimeError('An unexpected working manifest was retained.')
        saved.mkdir(mode=0o700, exist_ok=True)
        safe(saved)
        destination = saved / name
        safe(destination)
        if destination.exists():
            # A subsequent complete nightly job may publish new metadata. Do not
            # overwrite the prior record or silently discard the newer record.
            raise RuntimeError('A newer nightly working manifest exists; review before refreshing again.')
        os.replace(source, destination)


def refresh():
    owner()
    with contextlib.ExitStack() as stack:
        for path in (BASE / '.run.lock', SEED / '.run.lock',
                     BACKUP_LOCK, APPS / '.run.lock'):
            safe(path)
            stream = stack.enter_context(path.open('a'))
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError('A backup, snapshot or precopy is busy; retry after it finishes.') from None
        if any(p.exists() or p.is_symlink() for p in PENDING):
            raise RuntimeError('A hold or recovery is pending; all working data was retained.')
        seed = load(SEED / 'worker.py', SEED_SHA, 'refresh_existing_plex_seed')
        nightly = load(STANDBY, STANDBY_SHA, 'refresh_existing_standby')
        nightly.BASE = APPS
        seed.EXPECTED['/usr/local/sbin/media-mount-watch.sh'] = WATCH_SHA
        seed.EXPECTED[str(STANDBY)] = STANDBY_SHA
        seed.source_checks()
        before = seed.container()
        if json.loads(read(SEED / 'owner.json')) != {'format': seed.FORMAT}:
            raise RuntimeError('The existing private Plex working tree is unrecognized.')
        allowed = {'owner.json', 'worker.py', '.run.lock', 'state.json', 'payload', 'private-copy.log'}
        if {p.name for p in SEED.iterdir()} - allowed:
            raise RuntimeError('Later Plex handover/recovery files exist; they were retained.')
        state = seed_record(json.loads(read(SEED / 'state.json')), before,
                            {k: str(v) for k, v in seed.ROOTS.items()})
        payload = SEED / 'payload'
        safe(payload)
        if (not payload.is_dir() or payload.is_mount()
                or {p.name for p in payload.iterdir()} != set(seed.ROOTS)):
            raise RuntimeError('The existing Plex working payload differs; it was retained.')
        for leaf in seed.ROOTS:
            safe(payload / leaf)
            if not (payload / leaf).is_dir() or (payload / leaf).is_mount():
                raise RuntimeError('An existing Plex working root differs; it was retained.')
        catalog = nightly.inspect_source()
        nightly.validate_source_networks(catalog)
        roots = nightly.data_roots(catalog)
        work = APPS / 'snapshot-work'
        validate_work(work, roots, nightly.FORMAT)
        reject_nested_mounts((work, payload))
        source_bytes = sum(seed.size(p) for p in seed.ROOTS.values())
        source_bytes += sum(int(nightly.run('du', '-sbx', '--', entry['source']).split()[0])
                            for entry in roots.values())
        free = shutil.disk_usage(BASE).free
        if source_bytes > MAX_SOURCE_BYTES or free < source_bytes + 4 * 1024**3:
            raise RuntimeError('The bounded incremental refresh needs more free source space.')
        say('Refreshing existing live working trees: approximately ' +
            str(round(source_bytes / 1024**3, 1)) + ' GiB selected; ' +
            str(round(free / 1024**3, 1)) + ' GiB free. No new archive is created.')
        # Invalidate old cold-copy labels BEFORE the first rsync. Existing
        # published archives, their ready.json, and received snapshots are untouched.
        retire_work_checksums(work)
        seed.atomic(SEED / 'state.json', (json.dumps(state, indent=2) + '\n').encode())
        atomic(BASE / 'state.json', {'format': FORMAT, 'phase': 'refreshing',
               'consistentSnapshot': False, 'sourceStopPerformed': False})
        for leaf, source in seed.ROOTS.items():
            say('Refreshing current live Plex working root: ' + leaf)
            seed.copy_root(source, payload / leaf)
        for label, entry in roots.items():
            say('Refreshing current live application working root: ' + label)
            nightly.copy_roots(work, {label: entry}, live=True)
        seed.source_checks()
        if seed.container() != before:
            raise RuntimeError('Plex changed during the live refresh; working files remain NOT FROZEN.')
        current = nightly.inspect_source()
        if any(current[n]['Id'] != c['Id'] or current[n]['Image'] != c['Image']
               for n, c in catalog.items()):
            raise RuntimeError('An application changed identity; working files remain NOT FROZEN.')
        completed = dt.datetime.now(dt.timezone.utc).isoformat()
        state.update(phase='seeded-running-not-frozen', sourceHelperSha256=seed.EXPECTED,
                     copiedBytes=seed.size(payload), completedUtc=completed)
        seed.atomic(SEED / 'state.json', (json.dumps(state, indent=2) + '\n').encode())
        result = {'format': FORMAT, 'phase': 'live-precopy-ready-NOT-FROZEN',
                  'completedUtc': completed, 'consistentSnapshot': False,
                  'sourceStopPerformed': False, 'newArchiveCreated': False,
                  'plexWorkingTree': str(payload), 'applicationWorkingTree': str(work)}
        atomic(BASE / 'state.json', result)
    say('CURRENT PRODUCTION LIVE PRECOPY REFRESHED. Plex and applications remain running.')
    say('Plex configuration/history, InfiniDysk, library links and application working trees refreshed.')
    say('NOT FROZEN: a coordinated stop and final checksum delta are still required before import.')
    say('No NAS data, production configuration, timer, restart policy, route or existing archive changed.')
    say('Operation record: ' + str(BASE / 'state.json'))


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or 'inet 192.168.0.29/' not in run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the OptiPlex.')
    if sys.argv[1:] == ['--worker']:
        def interrupted(signum, frame):
            raise RuntimeError('The refresh was interrupted; working data remains NOT FROZEN.')
        signal.signal(signal.SIGTERM, interrupted)
        refresh()
        return
    if sys.argv[1:]:
        raise RuntimeError('No installer arguments are expected.')
    owner()
    source = globals().get('INSTALL_SOURCE')
    if not isinstance(source, str):
        if Path(__file__).resolve() != WORKER:
            raise RuntimeError('The pinned refresh source is required.')
        source = WORKER.read_text()
    if WORKER.exists() and read(WORKER) != source.encode():
        raise RuntimeError('A different refresh worker exists; it was retained.')
    if not WORKER.exists():
        atomic(WORKER, source.encode())
    active = subprocess.run(['systemctl', 'is-active', '--quiet', UNIT], capture_output=True)
    if active.returncode == 0:
        say('The live precopy refresh is already running; check its journal.')
        return
    subprocess.run(['systemctl', 'reset-failed', UNIT], capture_output=True)
    run('systemd-run', '--unit=' + UNIT.removesuffix('.service'), '--collect',
        '--description=Refresh existing production working trees without stopping applications',
        '--property=Type=exec', '--property=UMask=0077', '--property=Nice=10',
        '--property=IOSchedulingClass=idle', '--property=RuntimeMaxSec=3h',
        '--property=TimeoutStopSec=30s', '--property=KillMode=mixed',
        '/usr/bin/python3', str(WORKER), '--worker')
    say('Current production live precopy refresh started in systemd. Closing SSH is safe.')
    say('Progress: sudo journalctl -u ' + UNIT + ' -n 15 --no-pager -o cat')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('STOP: ' + (str(error) if isinstance(error, RuntimeError)
                         else 'Refresh failed (' + type(error).__name__ + '); private details withheld.'))
