#!/usr/bin/env python3
"""Precopy current Plex configuration privately while production stays running."""
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time

FORMAT = 'sawdoctor-plex-handover-precopy-v1'
BASE = Path('/var/lib/sawdoctor-plex-handover')
WORKER = BASE / 'worker.py'
ROOTS = {'plex-config': Path('/home/sawdoctor/docker/plex/config'),
         'flora-test-library': Path('/home/sawdoctor/plex2ultimate/flora-test-library')}
SOURCE_IMAGE = 'sha256:0c2f1122a4275efeea953a9882359f3809b27279d3c3022392e8e610a2eccc67'
LOCKS = (Path('/run/lock/plex-daily-backup.lock'), Path('/var/lib/sawdoctor-migration-standby/.run.lock'))
EXPECTED = {
    '/usr/local/sbin/nas-plex-trial': '34198d7cd3020989f51b6fc061ac0b152cb62a8274ca6c06494d06ace53775fd',
    '/usr/local/sbin/plex-safe-start': '1cc5fcf6e6d80c87600f7710edd8847d63bb0ac49f7e5b2a32bb9c541c46b0c0',
    '/usr/local/sbin/plex-safe-restart': '573d8c41e4aa49e8979d7aa17dc615604f69dbe9e369c1d10c5dd1203288db23',
    '/usr/local/sbin/plex-backup-post': 'aa12775f32f502a3322e36742a344755f6b4fcba4f997dccd87b689514ea29b6',
    '/usr/local/bin/plex-daily-backup.sh': '2b940406adc76ad6a316d5739f4f64c79c0f54cddc54083d4dae4dc27fdd9e66',
    '/usr/local/sbin/media-last-start': 'e73e4d57db65970d91254d294fb112f6afea2c7d5b92f41e29be8da4200c9d59',
    '/usr/local/sbin/media-mount-guard': '911d2873749c688c3ae1e715adc2bdf212d0b0ab09a164f0e424295f49b923aa',
    '/usr/local/sbin/media-mount-watch.sh': '6f05577843fa17ae7db7cb3d6dafdc63cc850f8b4b364f0634957151af99ef6a',
    '/usr/local/sbin/media-mount-recover.sh': '97fe6cca51b456731f606f801b2faf4904e0b31562f1d12e52501b8a209b7e0d',
    '/usr/local/sbin/plex-api-watch': '4b497787247ea8f67dbf1063122b0cedeb678962063ba3aa4c033a6e14b61ae7',
    '/usr/local/sbin/tmc-deadlock-watch': '1d90290a712f5b2954603de26848ddf0c3fb14a11618ab38ed49ffd675a63ec0',
    '/usr/local/sbin/docker-postboot-fix': '621f715ff266af3c5a59d892f1ab6ace1cb90905ebb6b2335e15696987a6b0b3',
    '/usr/local/sbin/lan-container-start.sh': '43671bb9d55da98095a69e59240c08f88f6ed4da5253c40ecb6e37578e2330aa',
    '/usr/local/sbin/nas-migration-standby': '0d1154b7c1a3d6534e5f22e4ad1313433f043e03beb43609b98e251978998901',
}
PENDING = tuple(map(Path, ('/var/lib/sawdoctor-plex-trial/hold.json',
    '/var/lib/sawdoctor-migration-standby/resume.json', '/var/lib/sawdoctor-migration-standby/paused-timers.json',
    '/var/lib/sawdoctor-nas-plex-npm-export/resume.json', '/run/plex-daily-backup-active')))


def say(value):
    print(value, flush=True)


def safe(path):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise RuntimeError('An unexpected symbolic staging/input path was retained.')


def atomic(path, data):
    safe(path)
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def run(*args, timeout=30):
    result = subprocess.run(args, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('A Plex precopy query failed; private output was withheld.')
    return result.stdout


def owner():
    safe(BASE)
    marker = BASE / 'owner.json'
    if BASE.exists():
        safe(marker)
        if not marker.is_file() or json.loads(marker.read_text()) != {'format': FORMAT}:
            raise RuntimeError('An unrecognized Plex staging directory was retained.')
    else:
        BASE.mkdir(mode=0o700)
        atomic(marker, (json.dumps({'format': FORMAT}) + '\n').encode())


def container():
    rows = json.loads(run('docker', 'inspect', 'plex'))
    if len(rows) != 1:
        raise RuntimeError('The source Plex container is unavailable.')
    row = rows[0]
    if (row.get('Name') != '/plex' or row['Image'] != SOURCE_IMAGE or row['State']['Status'] != 'running'
            or row['HostConfig']['NetworkMode'] != 'host'
            or row['HostConfig']['RestartPolicy'] != {'Name': 'on-failure', 'MaximumRetryCount': 5}):
        raise RuntimeError('The current source Plex state/image/restart/network differs; it was retained.')
    for target, label in (('/config', 'plex-config'), ('/flora-test-library', 'flora-test-library')):
        matches = [m for m in row['Mounts'] if m['Destination'] == target]
        if len(matches) != 1 or matches[0].get('Type') != 'bind' or matches[0].get('Source') != str(ROOTS[label]):
            raise RuntimeError('An existing source Plex configuration binding differs.')
    return {key: row[key] for key in ('Id', 'Image')} | {'startedAt': row['State']['StartedAt']}


def source_checks():
    if any(p.exists() or p.is_symlink() for p in PENDING):
        raise RuntimeError('Source backup/recovery or a Plex hold is pending; no copy was started.')
    for name, expected in EXPECTED.items():
        path = Path(name); safe(path)
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise RuntimeError('A source helper changed after the current handover check: ' + path.name)
    for path in ROOTS.values():
        safe(path)
        if not path.is_dir() or run('findmnt', '-rn', '-T', str(path), '-o', 'FSTYPE').strip() not in (b'ext4', b'xfs', b'btrfs'):
            raise RuntimeError('An expected local Plex source directory is unavailable.')
    db = ROOTS['plex-config'] / 'Library/Application Support/Plex Media Server/Plug-in Support/Databases/com.plexapp.plugins.library.db'
    safe(db)
    if not db.is_file() or db.stat().st_size < 4096:
        raise RuntimeError('The existing Plex library database is unavailable; source retained.')


def size(path):
    return int(run('du', '-sbx', '--', str(path), timeout=120).split()[0])


def copy_root(source, target):
    # --delete applies only to this operation-owned private target. No production
    # destination is passed to rsync, and live file disappearance is tolerated.
    safe(target)
    if target.parent != BASE / 'payload' or target.name not in ROOTS or target.is_mount():
        raise RuntimeError('The private precopy destination differs; current data was retained.')
    target.mkdir(mode=0o700, exist_ok=True)
    args = ['rsync', '-aHAX', '--numeric-ids', '--one-file-system', '--no-devices', '--no-specials', '--delete',
            '--', str(source) + '/', str(target) + '/']
    log = BASE / 'private-copy.log'; safe(log)
    with log.open('wb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        with subprocess.Popen(args, stdout=stream, stderr=stream) as process:
            deadline = time.monotonic() + 3600
            try:
                while True:
                    try:
                        status = process.wait(timeout=30)
                        break
                    except subprocess.TimeoutExpired:
                        if time.monotonic() >= deadline:
                            raise RuntimeError('The live precopy exceeded its one-hour root limit.')
                        say('Private Plex precopy contains approximately ' + str(size(BASE / 'payload') // 1024**2) + ' MiB...')
                if status not in (0, 24):
                    raise RuntimeError('The live Plex precopy failed; partial private files were retained for retry.')
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill(); process.wait(timeout=10)


def prepare():
    owner()
    allowed = {'owner.json', 'worker.py', '.run.lock', 'state.json', 'payload', 'private-copy.log'}
    if {p.name for p in BASE.iterdir()} - allowed:
        raise RuntimeError('The staging directory contains later handover/recovery files; they were retained.')
    state_path = BASE / 'state.json'; safe(state_path)
    previous = json.loads(state_path.read_text()) if state_path.exists() else None
    if previous is not None and (previous.get('format') != FORMAT or previous.get('phase') not in ('seeding', 'seeded-running-not-frozen')):
        raise RuntimeError('An existing handover operation has progressed beyond precopy; it was retained.')
    with contextlib.ExitStack() as stack:
        for path in (BASE / '.run.lock', *LOCKS):
            safe(path)
            handle = stack.enter_context(path.open('a'))
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError('A source backup/standby/precopy is busy; retry later.') from None
        source_checks(); before = container()
        if previous:
            if previous.get('container') != before or previous.get('sourceRoots') != {k: str(v) for k, v in ROOTS.items()}:
                raise RuntimeError('The source Plex container or staging roots changed; existing files were retained.')
            if previous['phase'] == 'seeded-running-not-frozen':
                say('The single private Plex precopy is already prepared; no extra copy or restart was performed.')
                return
        payload = BASE / 'payload'; safe(payload)
        if payload.exists() and previous is None:
            raise RuntimeError('An unrecorded private Plex copy exists; it was retained.')
        if payload.exists() and {p.name for p in payload.iterdir()} - set(ROOTS):
            raise RuntimeError('The private copy contains unexpected roots; it was retained.')
        source_bytes = sum(size(path) for path in ROOTS.values())
        # Reserve room for the single precopy plus its later compressed export.
        if source_bytes > 64 * 1024**3 or shutil.disk_usage(BASE).free < 2 * source_bytes + 2 * 1024**3:
            raise RuntimeError('More free source disk space is needed for the bounded Plex handover copy/export.')
        state = {'format': FORMAT, 'phase': 'seeding', 'container': before,
                 'sourceRoots': {k: str(v) for k, v in ROOTS.items()}, 'sourceHelperSha256': EXPECTED,
                 'sourceBytes': source_bytes, 'createdUtc': dt.datetime.now(dt.timezone.utc).isoformat(),
                 'consistentSnapshot': False, 'sourceStopPerformed': False}
        atomic(state_path, (json.dumps(state, indent=2) + '\n').encode())
        payload.mkdir(mode=0o700, exist_ok=True)
        for name, source in ROOTS.items():
            say('Precopying ' + name + ' while source Plex stays running...')
            copy_root(source, payload / name)
        source_checks()
        if container() != before:
            raise RuntimeError('Source Plex restarted or changed during the live copy; copied files were retained for review.')
        state.update(phase='seeded-running-not-frozen', copiedBytes=size(payload),
                     completedUtc=dt.datetime.now(dt.timezone.utc).isoformat())
        atomic(state_path, (json.dumps(state, indent=2) + '\n').encode())
    say('PLEX HANDOVER PRECOPY READY. Production Plex remains running with its original identity and restart policy.')
    say('One private staging copy retained. This is a live precopy, not a consistent backup or activated NAS restore.')
    say('No container/image/route/timer/helper changes were made. Final consistent copy and coordinated source hold remain pending.')
    say('Small operation record: ' + str(state_path))


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or b'inet 192.168.0.29/' not in run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the OptiPlex, SSH port48222.')
    if sys.argv[1:] == ['--worker']:
        def interrupted(signum, frame):
            raise RuntimeError('The live precopy was interrupted; partial private files remain retryable.')
        signal.signal(signal.SIGTERM, interrupted)
        prepare(); return
    if sys.argv[1:]:
        raise RuntimeError('No installer arguments are expected.')
    owner()
    source = globals().get('INSTALL_SOURCE')
    if not isinstance(source, str):
        if Path(__file__).resolve() != WORKER:
            raise RuntimeError('The complete pinned precopy installer source is required.')
        source = WORKER.read_text()
    safe(WORKER)
    if WORKER.exists() and WORKER.read_bytes() != source.encode():
        raise RuntimeError('A different handover worker exists; it was retained.')
    if not WORKER.exists():
        atomic(WORKER, source.encode()); WORKER.chmod(0o700)
    unit = 'plex-handover-precopy'
    if subprocess.run(['systemctl', 'is-active', '--quiet', unit + '.service'], capture_output=True).returncode == 0:
        say('The private Plex precopy is already running; check its journal.'); return
    subprocess.run(['systemctl', 'reset-failed', unit + '.service'], capture_output=True)
    run('systemd-run', '--unit=' + unit, '--collect', '--description=Precopy current Plex config privately without stopping production',
        '--property=Type=exec', '--property=UMask=0077', '--property=Nice=10', '--property=IOSchedulingClass=idle',
        '--property=RuntimeMaxSec=90min', '--property=TimeoutStopSec=30s', '--property=KillMode=mixed',
        '/usr/bin/python3', str(WORKER), '--worker')
    say('Private Plex handover precopy started in systemd. Plex stays running; closing SSH is safe.')
    say('Progress: sudo journalctl -u plex-handover-precopy.service -n 20 --no-pager -o cat')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('STOP: ' + (str(error) if isinstance(error, RuntimeError)
                                   else 'Plex precopy failed (' + type(error).__name__ + '); private details withheld.'))
