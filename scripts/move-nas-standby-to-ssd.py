#!/usr/bin/env python3
"""Move verified NAS standby snapshots and their two installed readers together."""
import configparser
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
import stat
import subprocess
import sys
import tempfile
import types
import urllib.request

OLD_UUID = 'e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6'
NEW_UUID = '631e3391-6a42-4158-9aa4-f7718ba0e7e9'
OLD_VOLUME = Path('/srv/dev-disk-by-uuid-' + OLD_UUID)
NEW_VOLUME = Path('/srv/dev-disk-by-uuid-' + NEW_UUID)
SOURCE = OLD_VOLUME / 'migration/nightly-standby'
TARGET = NEW_VOLUME / 'migration/nightly-standby'
STAGING = NEW_VOLUME / '.nas-standby-transfer'
WORK = Path('/var/lib/sawdoctor-standby-disk-move')
LOCK = Path('/run/lock/sawdoctor-nas-backup.lock')
RECEIVER = Path('/usr/local/sbin/nas-migration-standby')
TRIAL = Path('/usr/local/sbin/nas-plex-trial')
SERVICE = Path('/etc/systemd/system/nas-migration-standby.service')
RECEIVER_SHA = 'aaf6832e69df9ddb9fc990047d5c56003f5ffdb6fef458f732e0e6aa1e6c13d2'
TRIAL_SHA = '34198d7cd3020989f51b6fc061ac0b152cb62a8274ca6c06494d06ace53775fd'
ENGINE_SHA = '58f52f9362bb25c3f64efc821a1b11d89c82134331a91a85c7c8c98ba6a348f4'
ENGINE_URL = 'https://raw.githubusercontent.com/sawdoctor/nas-backup-auth/7771167f70423c1635873ca124a519b329e0d2c8/scripts/move-nas-backups-to-ssd.py'
FORMAT = 'sawdoctor-nas-standby-disk-move-v1'
SNAPSHOT_FORMAT = 'sawdoctor-migration-standby-v1'
UNIT = 'nas-standby-disk-move'
PHASES = {'copying', 'activating', 'activated', 'configured', 'removing-old-payload', 'complete'}
MAX_CHECKSUM_LINE = 64 * 1024


def say(value):
    print(value, flush=True)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load_engine(data=None):
    if data is None:
        say('Loading the pinned copy/checksum code used for the completed normal-backup move...')
        with urllib.request.urlopen(ENGINE_URL, timeout=30) as response:
            data = response.read(262144)
    if sha(data) != ENGINE_SHA:
        raise RuntimeError('The reviewed transfer-code integrity check failed.')
    value = types.ModuleType('reviewed_standby_copy_engine')
    exec(compile(data, ENGINE_URL, 'exec'), value.__dict__)
    value.SOURCE, value.TARGET, value.STAGING, value.WORK = SOURCE, TARGET, STAGING, WORK
    value.say = lambda message: say(message.replace('normal backup', 'standby snapshot'))
    return value


def receiver_patch(data):
    if sha(data) != RECEIVER_SHA:
        raise RuntimeError('The installed NAS standby receiver differs from the reviewed copy.')
    old = b"NAS_BASE = SSD / 'migration/nightly-standby'"
    new = ("NAS_BASE = Path('" + str(TARGET) + "')").encode()
    guard = b"    if ROLE=='nas' and not SSD.is_mount():raise RuntimeError('The NAS SSD must be mounted.')"
    added = ("\n    if ROLE=='nas':\n"
             "        backup_volume = Path('" + str(NEW_VOLUME) + "')\n"
             "        if (backup_volume.is_symlink() or not backup_volume.is_mount()\n"
             "            or run('findmnt','-rn','--mountpoint',str(backup_volume),'-o','UUID,FSTYPE').split()\n"
             "                != ['" + NEW_UUID + "','ext4']):\n"
             "            raise RuntimeError('The FIKWOT standby SSD must be mounted with its expected UUID.')").encode()
    if data.count(old) != 1 or data.count(guard) != 1:
        raise RuntimeError('The reviewed receiver path/guard anchors differ.')
    result = data.replace(old, new, 1).replace(guard, guard + added, 1)
    compile(result, str(RECEIVER), 'exec')
    return result


def trial_patch(data):
    if sha(data) != TRIAL_SHA:
        raise RuntimeError('The NAS Plex trial helper differs from the reviewed copy.')
    old = b"    snapshot = SSD / 'migration/nightly-standby/snapshots' / stamp"
    new = ("    standby_volume = Path('" + str(NEW_VOLUME) + "')\n"
           "    if (standby_volume.is_symlink() or not standby_volume.is_mount()\n"
           "        or run('findmnt','-rn','--mountpoint',str(standby_volume),'-o','UUID,FSTYPE').split()\n"
           "            != ['" + NEW_UUID + "','ext4']):\n"
           "        raise RuntimeError('The FIKWOT standby SSD must be mounted for this NAS trial.')\n"
           "    snapshot = standby_volume / 'migration/nightly-standby/snapshots' / stamp").encode()
    if data.count(old) != 1:
        raise RuntimeError('The reviewed NAS trial snapshot anchor differs.')
    result = data.replace(old, new, 1)
    compile(result, str(TRIAL), 'exec')
    return result


def service_patch(data):
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    parser.read_string(data.decode())
    expected = {
        'Unit': {'Description': 'Refresh private migration standby snapshot (nas)',
                 'Requires': 'network-online.target', 'After': 'network-online.target network-online.target',
                 'RequiresMountsFor': str(OLD_VOLUME)},
        'Service': {'Type': 'oneshot', 'UMask': '0077', 'ExecStart': str(RECEIVER) + ' receive',
                    'TimeoutStartSec': '6h', 'TimeoutStopSec': '8min', 'Nice': '10',
                    'IOSchedulingClass': 'idle'}}
    if (parser.defaults() or set(parser.sections()) != set(expected)
            or any(dict(parser[section]) != values for section, values in expected.items())):
        raise RuntimeError('The NAS receiver unit differs from the supplied definition.')
    old = ('RequiresMountsFor=' + str(OLD_VOLUME) + '\n').encode()
    if data.count(old) != 1:
        raise RuntimeError('The receiver mount-dependency anchor differs.')
    return data.replace(old, ('RequiresMountsFor=' + str(OLD_VOLUME) + ' ' + str(NEW_VOLUME) + '\n').encode(), 1)


def small_json(e, path, limit=16 * 1024**2):
    e.no_links(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise RuntimeError('A standby control file is unavailable or too large.')
    return json.loads(path.read_text())


def verify_checksum_list(e, checks, prefix, manifest):
    """Stream a list bounded by its inventoried members, not arbitrary file size."""
    e.no_links(checks)
    expected = manifest.get(prefix + 'SHA256SUMS', {})
    if expected.get('kind') != 'file':
        raise RuntimeError('A standby checksum list is not an inventoried regular file.')
    descriptor = os.open(checks, os.O_RDONLY | os.O_NOFOLLOW)
    names_checked = set()
    digest = hashlib.sha256()
    with os.fdopen(descriptor, 'rb') as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_size != expected['size']
                or before.st_mtime_ns != expected['mtime'] or before.st_ctime_ns != expected['ctime']):
            raise RuntimeError('A standby checksum list changed since its inventory; source retained.')
        say(checks.parent.name + ': streaming checksum list (' + str(before.st_size // 1024**2) + ' MiB)...')
        while True:
            raw = source.readline(MAX_CHECKSUM_LINE + 1)
            if not raw:
                break
            if len(raw) > MAX_CHECKSUM_LINE:
                raise RuntimeError('A standby checksum line exceeds the supported path length.')
            digest.update(raw)
            line = os.fsdecode(raw[:-1] if raw.endswith(b'\n') else raw)
            match = re.fullmatch(r'([0-9a-f]{64}) [ *](\./[^\r\n]+)', line)
            if not match:
                raise RuntimeError('A standby checksum line needs review.')
            path = PurePosixPath(match[2])
            if path.is_absolute() or '..' in path.parts or str(path) in names_checked:
                raise RuntimeError('An unsafe/repeated standby checksum path was retained.')
            member = manifest.get(prefix + str(path), {})
            if member.get('kind') != 'file' or member.get('sha256') != match[1]:
                raise RuntimeError('A standby file failed its original checksum; both copies retained.')
            # Every unique name must match the already-hashed file inventory,
            # so the inventory itself bounds how many lines can be accepted.
            names_checked.add(str(path))
        after = os.fstat(source.fileno())
        if any(getattr(before, name) != getattr(after, name) for name in
               ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
            raise RuntimeError('A standby checksum list changed during verification; source retained.')
    if digest.hexdigest() != expected['sha256']:
        raise RuntimeError('The standby checksum list digest differs from its original inventory.')
    if 'manifest.json' not in names_checked:
        raise RuntimeError('A standby checksum list lacks its required source manifest.')
    return len(names_checked)


def verify_snapshots(e, root, manifest):
    snapshots = root / 'snapshots'
    if manifest.get('snapshots', {}).get('kind') != 'directory':
        raise RuntimeError('The standby snapshot directory is unavailable.')
    names = []
    full = []
    for folder in sorted(snapshots.iterdir()):
        if not re.fullmatch(r'[0-9]{8}T[0-9]{6}Z', folder.name) or folder.is_symlink() or not folder.is_dir():
            raise RuntimeError('An unexpected standby snapshot entry was retained for review.')
        prefix = str(folder.relative_to(root)) + '/'
        verified = small_json(e, folder / '_VERIFIED.json')
        source = small_json(e, folder / 'manifest.json')
        if (verified.get('format') != SNAPSHOT_FORMAT or verified.get('createdUtc') != folder.name
                or not re.fullmatch('[a-f0-9]{64}', str(verified.get('sha256', '')))
                or source.get('format') != SNAPSHOT_FORMAT or source.get('scope') != 'standby-only'
                or source.get('sourceHost') != '192.168.0.29' or source.get('createdUtc') != folder.name):
            raise RuntimeError('A retained standby identity/verification record differs.')
        checks = folder / 'SHA256SUMS'
        verify_checksum_list(e, checks, prefix, manifest)
        names.append(folder.name)
        if manifest.get(prefix + 'data/plex-config', {}).get('kind') == 'directory':
            full.append(folder.name)
    if not names or not full:
        raise RuntimeError('The last full Plex rollback snapshot must be retained.')
    current = small_json(e, root / 'current.json')
    stamp = current.get('createdUtc')
    if stamp not in names or current.get('snapshot') != str(root / 'snapshots' / stamp):
        raise RuntimeError('The current standby snapshot index points outside its expected root.')
    if {key: value for key, value in current.items() if key != 'snapshot'} != small_json(e, snapshots / stamp / '_VERIFIED.json'):
        raise RuntimeError('The current standby index differs from its verified snapshot.')
    return {'snapshots': names, 'fullPlexSnapshots': full, 'current': current}


def status(e, unit, allow_missing=False):
    result = subprocess.run(['systemctl', 'show', unit, '-p', 'LoadState', '-p', 'ActiveState',
                             '-p', 'FragmentPath', '-p', 'DropInPaths', '-p', 'RequiresMountsFor'],
                            capture_output=True, text=True, timeout=15)
    value = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    if allow_missing and result.returncode in (0, 1) and value.get('LoadState') == 'not-found' and value.get('ActiveState') == 'inactive':
        return value
    if result.returncode or value.get('LoadState') != 'loaded' or value.get('ActiveState') not in ('inactive', 'failed'):
        raise RuntimeError('A related NAS job is busy or unavailable: ' + unit)
    return value


def preflight(e):
    e.mount_check(OLD_VOLUME, OLD_UUID, '557S10A2T9UW')
    e.mount_check(NEW_VOLUME, NEW_UUID, '26060336624000699')
    if OLD_VOLUME.stat().st_dev == NEW_VOLUME.stat().st_dev:
        raise RuntimeError('Standby snapshots must move onto a separate SSD.')
    for root, volume in ((SOURCE, OLD_VOLUME), (TARGET, NEW_VOLUME), (STAGING, NEW_VOLUME)):
        e.no_links(root)
        if root.exists():
            if not root.is_dir() or root.stat().st_dev != volume.stat().st_dev:
                raise RuntimeError('A standby operation directory is on the wrong filesystem.')
            e.no_nested_mounts(root)
    if not SOURCE.is_dir():
        raise RuntimeError('The original standby directory is unavailable.')
    readers = set()
    for directory in ('/usr/local/sbin', '/usr/local/bin', '/etc/systemd/system'):
        for path in Path(directory).rglob('*'):
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024**2:
                continue
            if b'nightly-standby' in path.read_bytes():
                readers.add(path)
    if readers != {RECEIVER, TRIAL}:
        raise RuntimeError('The installed standby-reader inventory changed; review it before moving.')
    unit = status(e, SERVICE.name)
    if unit.get('FragmentPath') != str(SERVICE) or unit.get('DropInPaths'):
        raise RuntimeError('An unexpected NAS standby unit override needs review.')
    status(e, 'nas-backup.service')
    for name in ('nas-migration-standby-install.service', 'nas-plex-trial-start.service', 'nas-plex-trial-stop.service'):
        status(e, name, allow_missing=True)
    plex = json.loads(e.run('docker', 'inspect', 'plex-nas'))
    if len(plex) != 1 or plex[0]['State']['Running']:
        raise RuntimeError('NAS Plex must remain stopped during its standby reference update.')
    e.no_links(WORK)
    record = WORK / 'result.json'
    if not WORK.exists():
        if STAGING.exists() or (TARGET.exists() and any(TARGET.iterdir())):
            raise RuntimeError('An existing standby destination/staging tree was retained.')
        return None
    if not WORK.is_dir() or WORK.stat().st_uid != 0:
        raise RuntimeError('The standby relocation state directory differs.')
    value = small_json(e, record)
    if (value.get('format') != FORMAT or value.get('source') != str(SOURCE)
            or value.get('target') != str(TARGET) or value.get('phase') not in PHASES):
        raise RuntimeError('An unrelated standby relocation record was retained.')
    if STAGING.exists() and (STAGING.stat().st_uid != 0 or stat.S_IMODE(STAGING.stat().st_mode) != 0o700):
        raise RuntimeError('The private standby staging directory differs.')
    return value


def record(e, phase, **extra):
    e.write_json(WORK / 'result.json', {'format': FORMAT, 'phase': phase,
        'source': str(SOURCE), 'target': str(TARGET),
        'updatedUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'applicationsStopped': False, 'sourceOptiplexChanged': False,
        'timersChanged': False, 'retentionChanged': False, **extra})


def controls(e, state):
    result = {}
    for path, expected, patcher in ((RECEIVER, RECEIVER_SHA, receiver_patch),
                                     (TRIAL, TRIAL_SHA, trial_patch), (SERVICE, None, service_patch)):
        e.no_links(path)
        if not path.is_file() or path.stat().st_uid != 0:
            raise RuntimeError('An installed standby reader/unit type or owner differs.')
        current = path.read_bytes()
        previous = WORK / (path.name + '.before')
        if state:
            e.no_links(previous)
        original = previous.read_bytes() if state else current
        if expected and sha(original) != expected:
            raise RuntimeError('A saved installed-reader identity differs.')
        proposed = patcher(original)
        if current not in (original, proposed):
            raise RuntimeError('An installed reader/unit changed during relocation; snapshots retained.')
        result[path] = (original, proposed)
    return result


def replace_control(e, path, original, proposed):
    current = path.read_bytes()
    if current == proposed:
        return
    if current != original:
        raise RuntimeError('A standby reader changed before activation; snapshots retained.')
    info = path.stat()
    descriptor, name = tempfile.mkstemp(prefix='.standby-reader-', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(proposed); output.flush(); os.fsync(output.fileno())
        os.chown(temporary, info.st_uid, info.st_gid)
        shutil.copystat(path, temporary)
        fd = os.open(temporary, os.O_RDONLY)
        try: os.fsync(fd)
        finally: os.close(fd)
        os.replace(temporary, path)
        fd = os.open(path.parent, os.O_DIRECTORY | os.O_RDONLY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        temporary.unlink(missing_ok=True)
    if path.read_bytes() != proposed:
        raise RuntimeError('The installed standby reader did not verify.')


def acquire(e, stack, path):
    e.no_links(path)
    handle = stack.enter_context(os.fdopen(os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600), 'a'))
    try: fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise RuntimeError('A backup/standby/trial already owns a required lock; retry later.') from None


def transfer_locked(e, stack):
    state = preflight(e)
    config = controls(e, state)
    if state and state['phase'] == 'complete':
        if any(path.name != '.run.lock' for path in SOURCE.iterdir()):
            raise RuntimeError('New files appeared in the retired standby directory; they were retained.')
        if any(path.read_bytes() != proposed for path, (_, proposed) in config.items()):
            raise RuntimeError('Completed standby reader configuration changed.')
        if not TARGET.is_dir() or not (TARGET / 'current.json').is_file():
            raise RuntimeError('The completed standby destination is unavailable.')
        say('The standby snapshot relocation is already complete.'); return
    if state:
        saved = small_json(e, WORK / 'source-manifest.json', limit=512 * 1024**2)
    else:
        say('Verifying both retained snapshots against their original checksum lists...')
        saved = e.tree(SOURCE, label='Original standby SHA256 verification')
        summary = verify_snapshots(e, SOURCE, saved)
        needed = int(e.run('du', '-sx', '-B1', str(SOURCE)).split()[0])
        if shutil.disk_usage(NEW_VOLUME).free < needed + 5 * 1024**3:
            raise RuntimeError('The backup SSD lacks sufficient space for the verified snapshot copy.')
        WORK.mkdir(mode=0o700)
        for path, (original, _) in config.items():
            e.atomic(WORK / (path.name + '.before'), original)
        e.write_json(WORK / 'source-manifest.json', saved)
        e.write_json(WORK / 'snapshot-summary.json', summary)
        record(e, 'copying', allocatedBytes=needed)
    phase = state['phase'] if state else 'copying'
    if phase == 'copying':
        if TARGET.exists() and any(TARGET.iterdir()):
            raise RuntimeError('The standby destination acquired files; both copies were retained.')
        if e.comparable(saved, hashes=False) != e.comparable(e.tree(SOURCE, hashes=False), hashes=False):
            raise RuntimeError('The original standby changed before copying; it was retained.')
        TARGET.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload = e.copy_payload()
        copied = e.tree(payload, label='Copied standby SHA256 verification')
        e.verify_copy(saved, copied)
        # The only changed data file is the external current.json locator.
        current = small_json(e, payload / 'current.json')
        current['snapshot'] = str(TARGET / 'snapshots' / current['createdUtc'])
        e.write_json(payload / 'current.json', current)
        expected = e.tree(payload, label='Prepared standby SHA256 verification')
        e.write_json(WORK / 'target-manifest.json', expected)
        if e.comparable(saved, hashes=False) != e.comparable(e.tree(SOURCE, hashes=False), hashes=False):
            raise RuntimeError('The original standby changed during copying; it was retained.')
        preflight(e)
        record(e, 'activating')
        phase = 'activating'
    if phase == 'activating':
        payload = STAGING / 'payload'
        e.no_links(payload)
        if payload.is_dir():
            if TARGET.exists():
                if any(TARGET.iterdir()):
                    raise RuntimeError('An existing standby destination was retained.')
                TARGET.rmdir()
            os.rename(payload, TARGET)
        elif not TARGET.is_dir():
            raise RuntimeError('The previously activated standby copy is unavailable.')
        record(e, 'activated')
    acquire(e, stack, TARGET / '.run.lock')
    say('Rechecking the new snapshot location before updating its installed readers...')
    expected = small_json(e, WORK / 'target-manifest.json', limit=512 * 1024**2)
    actual = e.tree(TARGET, label='Activated standby SHA256 verification')
    e.verify_copy(expected, actual)
    summary = verify_snapshots(e, TARGET, actual)
    say('Flushing the verified snapshot location before changing its installed readers...')
    e.run('sync', '-f', str(TARGET), timeout=300)
    for path, (original, proposed) in config.items():
        replace_control(e, path, original, proposed)
    e.run('systemctl', 'daemon-reload')
    info = status(e, SERVICE.name)
    if (info.get('FragmentPath') != str(SERVICE) or info.get('DropInPaths')
            or set(info.get('RequiresMountsFor', '').split()) != {str(OLD_VOLUME), str(NEW_VOLUME)}):
        raise RuntimeError('The new standby mount dependencies did not verify; old payload retained.')
    if any(path.read_bytes() != proposed for path, (_, proposed) in config.items()):
        raise RuntimeError('A standby reader configuration changed; old payload retained.')
    record(e, 'configured')
    e.mount_check(OLD_VOLUME, OLD_UUID, '557S10A2T9UW')
    e.mount_check(NEW_VOLUME, NEW_UUID, '26060336624000699')
    say('Flushing the verified FIKWOT snapshots before freeing their old payload...')
    e.run('sync', '-f', str(TARGET), timeout=300)
    remaining = e.tree(SOURCE, label='Final original standby SHA256 check')
    e.verify_remaining_source(saved, remaining)
    # Recheck immediately before deletion, after the potentially long source
    # checksum pass, so a detached/replaced destination cannot trigger cleanup.
    e.mount_check(OLD_VOLUME, OLD_UUID, '557S10A2T9UW')
    e.mount_check(NEW_VOLUME, NEW_UUID, '26060336624000699')
    e.no_nested_mounts(TARGET)
    if (e.comparable(expected, hashes=False, ignore_root=True)
            != e.comparable(e.tree(TARGET, hashes=False), hashes=False, ignore_root=True)):
        raise RuntimeError('The verified destination changed before cleanup; old snapshots retained.')
    e.no_nested_mounts(SOURCE)
    record(e, 'removing-old-payload')
    for path in list(SOURCE.iterdir()):
        if path.name == '.run.lock':
            continue
        if path.is_symlink() or path.is_file(): path.unlink()
        else: shutil.rmtree(path)
    e.run('sync', '-f', str(SOURCE), timeout=300)
    if STAGING.exists():
        e.no_nested_mounts(STAGING)
        shutil.rmtree(STAGING)
    record(e, 'complete', snapshots=summary['snapshots'], fullPlexSnapshots=summary['fullPlexSnapshots'],
           currentSnapshot=summary['current']['createdUtc'], readersSha256={str(path): sha(value[1]) for path, value in config.items()},
           oldDirectoryRetainsOnlyLock=True)
    say('NAS STANDBY SNAPSHOTS MOVED AND VERIFIED: ' + str(TARGET))
    say('Current lean snapshot and full Plex rollback retained; receiver and NAS trial references updated.')
    say('Old snapshot payload removed after verification. Applications, OptiPlex, timers and retention retained.')
    say('Small operation record: ' + str(WORK / 'result.json'))


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in subprocess.check_output(['ip', '-4', 'addr', 'show'], text=True, timeout=15):
        raise RuntimeError('Run with sudo on the NAS.')
    if sys.argv[1:] == ['--worker']:
        signal.signal(signal.SIGTERM, lambda _number, _frame: sys.exit(143))
        e = load_engine()
        # Take the existing backup lock, then the existing standby lock; never
        # invoke either worker CLI while holding their locks.
        with contextlib.ExitStack() as stack:
            acquire(e, stack, LOCK)
            e.no_links(SOURCE)
            if not SOURCE.is_dir(): raise RuntimeError('The original standby directory is unavailable.')
            acquire(e, stack, SOURCE / '.run.lock')
            transfer_locked(e, stack)
        return
    if sys.argv[1:]: raise RuntimeError('Unknown standby relocation operation.')
    result = subprocess.run(['systemctl', 'show', UNIT + '.service', '-p', 'LoadState', '-p', 'ActiveState'],
                            capture_output=True, text=True, timeout=15)
    value = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    if (result.returncode not in (0, 1) or value.get('LoadState') not in ('loaded', 'not-found')
            or value.get('ActiveState') not in ('active', 'activating', 'deactivating', 'inactive', 'failed')):
        raise RuntimeError('The background standby relocation state is unavailable.')
    if value['ActiveState'] in ('active', 'activating', 'deactivating'):
        say('Standby relocation is already running.'); return
    source = globals().get('INSTALL_SOURCE')
    if source is None and '__file__' in globals(): source = Path(__file__).read_text()
    if not source: raise RuntimeError('Use the complete pinned standby relocation command.')
    directory = Path(tempfile.mkdtemp(prefix=UNIT + '-', dir='/run'))
    worker = directory / 'worker.py'; worker.write_text(source); worker.chmod(0o600)
    try:
        subprocess.run(['systemd-run', '--unit=' + UNIT, '--collect', '--property=Type=exec',
            '--property=UMask=0077', '--property=Nice=10', '--property=IOSchedulingClass=idle',
            '--property=RuntimeMaxSec=2h', '--property=TimeoutStopSec=30s',
            '--description=Verify and relocate NAS standby snapshots to FIKWOT SSD',
            '/usr/bin/python3', '-u', str(worker), '--worker'], capture_output=True, check=True, timeout=30)
    except BaseException:
        worker.unlink(missing_ok=True); directory.rmdir(); raise
    say('NAS standby relocation started in systemd. Closing SSH is safe.')
    say('Progress: sudo journalctl -u ' + UNIT + '.service -n 20 --no-pager -o cat')


if __name__ == '__main__':
    try: main()
    except Exception as error:
        say('STOP: ' + (str(error) if isinstance(error, RuntimeError) else type(error).__name__))
        sys.exit(1)
    finally:
        if sys.argv[1:] == ['--worker'] and '__file__' in globals():
            path = Path(__file__)
            if path.parent.parent == Path('/run') and path.parent.name.startswith(UNIT + '-') and path.name == 'worker.py':
                path.unlink(missing_ok=True); path.parent.rmdir()
