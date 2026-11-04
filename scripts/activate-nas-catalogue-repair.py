#!/usr/bin/env python3
"""Sawdoctor NAS additive catalogue activation v1.

Only the reviewed 84 catalogue rows, 34 NZB names and 41 links are eligible.
Rebases against the current NAS database. Never installs the stale candidate.
"""
import contextlib
import datetime as dt
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request

SIGNATURE = 'Sawdoctor NAS additive catalogue activation v1'
SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
CONFIG = SSD / 'appdata/infinidysk-nas/config'
LIBRARY = SSD / 'appdata/infinidysk-nas/library'
PREPARED = SSD / 'compose/infinidysk-nas/recovery/catalogue-additions'
RECOVERY = PREPARED / 'activation'
STATE = RECOVERY / 'state.json'
MAINTENANCE = RECOVERY / 'maintenance.json'
LOCK = Path('/run/lock/sawdoctor-nas-backup.lock')
WORKER = Path('/usr/local/sbin/nas-catalogue-activate')
HELPER = Path('/run/nas-catalogue-prepare.py')
HELPER_SHA = 'd1b6f29553dfabf436a7d4baeae35cf42745e4ad525f83f521a838937a0adacf'
BOOT_UNIT = Path('/etc/systemd/system/nas-catalogue-resume.service')
NAME = 'infinidysk-nas'
BINARY = Path('/usr/local/libexec/infinidysk-rclone')
EXPECTED = {'DavItems': 84, 'DavMultipartFiles': 0, 'DavNzbFiles': 0, 'DavRarFiles': 0,
            'HistoryItems': 0, 'NzbNames': 34, 'metadataBlobsPrepared': 75,
            'nasOnlyPathsPreserved': 17, 'possibleTestEntriesForReview': 0,
            'sourceLinksToAdd': 41, 'sourceRowsWithPrunedHistory': 0}


def log(message): print(message, flush=True)


def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


def write_json(path, value):
    if path.is_symlink(): raise RuntimeError('An unexpected symbolic recovery record was retained.')
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write((json.dumps(value, indent=2) + '\n').encode())
            stream.flush(); os.fsync(stream.fileno()); temporary.chmod(0o600)
            temporary.replace(path); fsync_directory(path.parent)
        finally: temporary.unlink(missing_ok=True)


def run(*args, timeout=45, allowed=(0,)):
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    if result.returncode not in allowed:
        if RECOVERY.is_dir():
            write_json(RECOVERY / 'private-command-error.json', {'args': args, 'stdout': result.stdout, 'stderr': result.stderr})
        raise RuntimeError('A NAS catalogue command failed; private diagnostics were retained.')
    return result.stdout


def helper():
    import hashlib
    if HELPER.is_symlink() or not HELPER.is_file() or hashlib.sha256(HELPER.read_bytes()).hexdigest() != HELPER_SHA:
        raise RuntimeError('Rerun the pinned preparation bootstrap to restore its reviewed temporary helper.')
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('catalogue_preparation_reviewed', HELPER)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def inspect_backend(expected=None):
    row = json.loads(run('docker', 'inspect', NAME))[0]
    env = dict(item.split('=', 1) for item in row['Config'].get('Env', []) if '=' in item)
    labels = row['Config'].get('Labels') or {}
    if (row['Name'] != '/' + NAME or labels.get('com.docker.compose.project') != NAME
            or env.get('DATABASE_PROVIDER', 'sqlite').lower() not in ('', 'sqlite')
            or not any(mount['Source'] == str(CONFIG) and mount['Destination'] == '/config' for mount in row['Mounts'])):
        raise RuntimeError('The NAS InfiniDysk identity or SQLite binding differs.')
    if expected and (row['Id'] != expected['containerId'] or row['Image'] != expected['imageId']):
        raise RuntimeError('The NAS container or image changed; the current configuration was retained.')
    return row


def mount_record():
    fields = run('findmnt', '-rn', '--mountpoint', '/mnt/nzbdav', '-o', 'ID,FSTYPE,SOURCE').split()
    if len(fields) != 3 or fields[1:] != ['fuse.rclone', 'nzbdav:']:
        raise RuntimeError('The existing NAS InfiniDysk rclone mount is required.')
    return fields


def wait_ready(record, timeout=180):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = inspect_backend(record)
        if row['State']['Running']:
            try:
                for port, endpoint in ((8081, '/healthz'), (8082, '/health')):
                    with opener.open('http://192.168.0.220:' + str(port) + endpoint, timeout=3) as response:
                        if response.status != 200: raise OSError()
                return
            except OSError: pass
        time.sleep(2)
    raise RuntimeError('NAS InfiniDysk has not passed its health checks. Its data and recovery record were retained.')


def save_state(record, maintenance=False):
    write_json(STATE, record)
    if maintenance: write_json(MAINTENANCE, record)


def ensure_backend(record):
    row = inspect_backend(record)
    if not row['State']['Running']: run('docker', 'start', record['containerId'], timeout=90)
    wait_ready(record)
    record['paused'] = False
    save_state(record)
    MAINTENANCE.unlink(missing_ok=True); fsync_directory(RECOVERY)


def safe_parent(root, relative, create=False):
    path = Path(relative)
    if path.is_absolute() or not path.parts or '..' in path.parts or '.' in path.parts:
        raise RuntimeError('An unreviewed relative data path was retained.')
    current = root
    profile = root.stat()
    for part in path.parts:
        current = current / part
        try: value = current.lstat()
        except FileNotFoundError:
            if not create: continue
            current.mkdir(mode=0o700)
            os.chown(current, profile.st_uid, profile.st_gid)
            current.chmod(stat.S_IMODE(profile.st_mode))
            fsync_directory(current.parent); value = current.lstat()
        if not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode):
            raise RuntimeError('A symbolic or non-directory data ancestor was retained.')
    return current


def validate_links(plan, module):
    if len(plan['links']) != EXPECTED['sourceLinksToAdd']: raise RuntimeError('The reviewed link count differs.')
    for name, target in plan['links'].items():
        path = Path(name)
        if path.is_absolute() or len(path.parts) < 2 or path.parts[0] not in ('movies', 'movies-4k', 'tv') or '..' in path.parts:
            raise RuntimeError('A planned library path is outside the reviewed categories.')
        module.file_id(name, target)
        safe_parent(LIBRARY, path.parent)
        destination = LIBRARY / name
        if os.path.lexists(destination) and (not destination.is_symlink() or os.readlink(destination) != target):
            raise RuntimeError('An existing NAS library item differs; it was retained.')


def load_plan(module):
    if PREPARED.is_symlink() or (PREPARED / 'plan.json').is_symlink():
        raise RuntimeError('An unexpected symbolic preparation path was retained.')
    plan = json.loads((PREPARED / 'plan.json').read_text())
    if plan.get('format') != module.SIGNATURE or plan.get('counts') != EXPECTED or plan.get('activationStatus') != 'not-activated':
        raise RuntimeError('The preparation differs from the reviewed 41-link, zero-history-job repair.')
    if (set(plan['additions']) != set(module.TABLES)
            or any(len(plan['additions'][table]) != EXPECTED[table] for table in module.TABLES)
            or len(plan['blobSha256']) != EXPECTED['metadataBlobsPrepared']
            or any(item['possibleTestLabel'] for item in plan['testEntryReview'])):
        raise RuntimeError('The prepared additions or test-entry review differ.')
    seeds = {module.file_id(name, target) for name, target in plan['links'].items()}
    files = [row for row in plan['additions']['DavItems'] if row['Type'] == 2]
    references = {module.identifier(row[column]) for row in plan['additions']['DavItems']
                  for column in ('FileBlobId', 'NzbBlobId') if row.get(column)}
    if (len(seeds) != EXPECTED['sourceLinksToAdd'] or {module.identifier(row['Id']) for row in files} != seeds
            or any(row['Type'] not in (1, 2) for row in plan['additions']['DavItems'])
            or references != set(plan['blobSha256'])
            or any(not isinstance(row.get('FileSize'), int) or row['FileSize'] <= 0 for row in files)):
        raise RuntimeError('The prepared file IDs and metadata references differ from the reviewed scope.')
    if module.digest(PREPARED / 'candidate.sqlite') != plan['candidateSha256'] or module.digest(PREPARED / 'baseline.sqlite') != plan['baselineSha256']:
        raise RuntimeError('A prepared database copy failed its saved checksum.')
    for key, expected in plan['blobSha256'].items():
        if module.identifier(key) != key or module.digest(PREPARED / module.blob_relative(key)) != expected:
            raise RuntimeError('A prepared metadata blob failed verification.')
        destination = CONFIG / module.blob_relative(key)
        safe_parent(CONFIG, module.blob_relative(key).parent)
        if os.path.lexists(destination) and module.digest(destination) != expected:
            raise RuntimeError('A metadata blob already has different NAS contents; it was retained.')
    validate_links(plan, module)
    return plan


def pending_additions(plan, current, original, module):
    result = {table: [] for table in module.TABLES}
    current_dav = module.rows(current, 'DavItems'); baseline_dav = module.rows(original, 'DavItems')
    planned_dav = {module.identifier(row['Id']): row for row in plan['additions']['DavItems']}
    paths = {row['Path']: key for key, row in current_dav.items()}
    structural = ('ParentId', 'Name', 'Type', 'SubType', 'Path')
    def same(left, right):
        return all((module.identifier(left.get(key)) == module.identifier(right.get(key))) if key == 'ParentId'
                   else left.get(key) == right.get(key) for key in structural)
    for key, row in planned_dav.items():
        if key in current_dav:
            if not same(row, current_dav[key]): raise RuntimeError('An already present NAS item has different structural metadata.')
            continue
        if row['Path'] in paths: raise RuntimeError('A source path now belongs to another NAS item; it was retained.')
        parent = module.identifier(row.get('ParentId')); seen = set()
        while parent is not None:
            if parent in seen or len(seen) > 100: raise RuntimeError('A catalogue ancestor cycle was retained.')
            seen.add(parent)
            if parent in planned_dav:
                ancestor = planned_dav[parent]
            elif parent in current_dav and parent in baseline_dav:
                ancestor = current_dav[parent]
                if not same(ancestor, baseline_dav[parent]): raise RuntimeError('A NAS catalogue ancestor changed after preparation.')
            else: raise RuntimeError('A required NAS catalogue ancestor is no longer present.')
            parent = module.identifier(ancestor.get('ParentId'))
        result['DavItems'].append(row)
    existing_names = module.rows(current, 'NzbNames')
    result['NzbNames'] = [row for row in plan['additions']['NzbNames'] if module.identifier(row['Id']) not in existing_names]
    checks = (('BlobCleanupItems', set(plan['blobSha256'])), ('NzbBlobCleanupItems', set(plan['blobSha256'])),
              ('DavCleanupItems', set(planned_dav)))
    for table, keys in checks:
        if current.execute('SELECT 1 FROM sqlite_master WHERE type=\'table\' AND name=?', (table,)).fetchone():
            if any(module.identifier(row[0]) in keys for row in current.execute('SELECT Id FROM "' + table + '"')):
                raise RuntimeError('A reviewed item now has a pending NAS cleanup request; it was retained.')
    return result


def fresh_snapshot(module, path):
    for item in (path, Path(str(path) + '-wal'), Path(str(path) + '-shm')):
        if item.is_symlink(): raise RuntimeError('An unexpected symbolic temporary database was retained.')
        item.unlink(missing_ok=True)
    with contextlib.closing(module.read_only(CONFIG / 'db.sqlite')) as current, contextlib.closing(sqlite3.connect(path)) as copy:
        deadline = time.monotonic() + 90
        def progress(status, remaining, total):
            if time.monotonic() > deadline: raise RuntimeError('The fresh NAS database copy timed out.')
        current.backup(copy, pages=512, progress=progress, sleep=0.05)
        copy.execute('PRAGMA journal_mode=DELETE')
        if copy.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise RuntimeError('The fresh NAS database copy failed integrity checks.')


def first_backup(module, latest, record):
    destination = RECOVERY / 'before-activation.sqlite'
    if not destination.exists():
        with tempfile.NamedTemporaryFile(dir=RECOVERY, delete=False) as stream:
            temporary = Path(stream.name)
            try:
                with latest.open('rb') as source: shutil.copyfileobj(source, stream)
                stream.flush(); os.fsync(stream.fileno()); os.fchmod(stream.fileno(), 0o600)
                os.link(temporary, destination); fsync_directory(RECOVERY)
            finally: temporary.unlink(missing_ok=True)
    checksum = module.digest(destination)
    if record.get('beforeActivationSha256') not in (None, checksum):
        raise RuntimeError('The saved pre-activation database copy differs; it was retained for review.')
    with contextlib.closing(module.read_only(destination)) as database:
        if database.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
            raise RuntimeError('The saved pre-activation database copy failed its integrity check.')
    record['beforeActivationSha256'] = checksum; save_state(record, maintenance=True)


def file_profile(module):
    directory = (CONFIG / 'blobs').stat()
    with contextlib.closing(module.read_only(CONFIG / 'db.sqlite')) as database:
        for row in database.execute('SELECT FileBlobId FROM DavItems WHERE FileBlobId IS NOT NULL LIMIT 100'):
            file = CONFIG / module.blob_relative(module.identifier(row[0]))
            if file.is_file() and not file.is_symlink():
                value = file.stat(); return directory, value
    return directory, (CONFIG / 'db.sqlite').stat()


def install_blobs(plan, module, record):
    directory_profile, profile = file_profile(module)
    touched = set()
    for key, expected in plan['blobSha256'].items():
        relative = module.blob_relative(key); destination = CONFIG / relative
        if os.path.lexists(destination):
            if module.digest(destination) != expected: raise RuntimeError('A NAS blob changed during activation; it was retained.')
            continue
        current = CONFIG / 'blobs'
        for part in relative.parts[1:-1]:
            child = current / part
            try: value = child.lstat()
            except FileNotFoundError:
                child.mkdir(mode=0o700); os.chown(child, directory_profile.st_uid, directory_profile.st_gid)
                child.chmod(stat.S_IMODE(directory_profile.st_mode)); touched.add(current)
                value = child.lstat()
            if not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode):
                raise RuntimeError('A NAS blob directory changed during activation.')
            current = child
        with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as temporary:
            path = Path(temporary.name)
            try:
                with (PREPARED / relative).open('rb') as source: shutil.copyfileobj(source, temporary)
                temporary.flush(); os.fchown(temporary.fileno(), profile.st_uid, profile.st_gid)
                os.fchmod(temporary.fileno(), stat.S_IMODE(profile.st_mode)); os.fsync(temporary.fileno())
                if module.digest(path) != expected: raise RuntimeError('A staged metadata blob failed verification.')
                try: os.link(path, destination)
                except FileExistsError:
                    if module.digest(destination) != expected: raise RuntimeError('An existing NAS metadata blob was retained.')
                else: record['installedBlobKeys'].append(key)
                touched.add(destination.parent)
            finally: path.unlink(missing_ok=True)
    for directory in sorted(touched, key=lambda value: len(value.parts), reverse=True): fsync_directory(directory)
    save_state(record, maintenance=True)


def flush_directory_cache():
    pid = int(run('systemctl', 'show', 'nas-infinidysk-rclone.service', '-p', 'MainPID', '--value').strip())
    if pid <= 1: raise RuntimeError('The expected NAS rclone process is unavailable.')
    descriptor = os.pidfd_open(pid)
    try:
        process = Path('/proc') / str(pid)
        args = (process / 'cmdline').read_bytes().split(b'\0')
        if ((process / 'exe').resolve() != BINARY.resolve() or b'mount' not in args
                or b'nzbdav:' not in args or b'/mnt/nzbdav' not in args):
            raise RuntimeError('The NAS rclone process does not match the reviewed mount.')
        signal.pidfd_send_signal(descriptor, signal.SIGHUP)
    finally: os.close(descriptor)


def verify_metadata(plan, module):
    targets = {target: module.file_id(name, target) for name, target in plan['links'].items()}
    with contextlib.closing(module.read_only(CONFIG / 'db.sqlite')) as database:
        records = module.rows(database, 'DavItems', set(targets.values()))
    remaining = dict(targets); deadline = time.monotonic() + 90
    while remaining and time.monotonic() < deadline:
        for target, key in list(remaining.items()):
            if time.monotonic() >= deadline: break
            try:
                probe = subprocess.run(['stat', '-L', '--printf=%f:%s', '--', target], text=True,
                                       capture_output=True, timeout=6)
                mode, size = probe.stdout.strip().split(':', 1)
                if probe.returncode == 0 and stat.S_ISREG(int(mode, 16)) and int(size) == records[key]['FileSize'] and int(size) > 0:
                    remaining.pop(target)
            except (ValueError, KeyError, subprocess.TimeoutExpired): pass
        if remaining: time.sleep(2)
    if remaining:
        write_json(RECOVERY / 'metadata-pending.json', {'targets': list(remaining)})
        raise RuntimeError('Some restored IDs are not visible through the existing NAS mount yet; additions were retained for a safe retry.')
    return len(targets)


def add_links(plan, record):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    root = os.open(LIBRARY, flags)
    try:
        for name, target in plan['links'].items():
            parts = Path(name).parts; parent = os.dup(root)
            try:
                profile = None
                for component in parts[:-1]:
                    try: child = os.open(component, flags, dir_fd=parent)
                    except FileNotFoundError:
                        if profile is None: raise RuntimeError('An expected NAS library category is missing.')
                        os.mkdir(component, mode=0o700, dir_fd=parent)
                        child = os.open(component, flags, dir_fd=parent)
                        os.fchown(child, profile.st_uid, profile.st_gid); os.fchmod(child, stat.S_IMODE(profile.st_mode))
                        os.fsync(parent)
                    os.close(parent); parent = child
                    if profile is None: profile = os.fstat(parent)
                try: os.symlink(target, parts[-1], dir_fd=parent)
                except FileExistsError:
                    if os.readlink(parts[-1], dir_fd=parent) != target:
                        raise RuntimeError('An existing NAS library item was retained; it will not be overwritten.')
                else:
                    os.chown(parts[-1], profile.st_uid, profile.st_gid, dir_fd=parent, follow_symlinks=False)
                    os.fsync(parent); record['createdLinks'].append(name); save_state(record)
            finally: os.close(parent)
    finally: os.close(root)


def activate():
    module = helper()
    log('Waiting for the NAS backup lock; OptiPlex Plex is not touched...')
    with LOCK.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        plan = load_plan(module); current = inspect_backend()
        if not current['State']['Running']: raise RuntimeError('The NAS backend must be running before activation.')
        plex = json.loads(run('docker', 'inspect', 'plex-nas'))[0]
        if plex['State']['Running']: raise RuntimeError('Keep NAS Plex stopped during catalogue preparation.')
        initial_mount = mount_record(); before_links = module.inventory(LIBRARY)
        RECOVERY.mkdir(parents=True, exist_ok=True, mode=0o700)
        old = json.loads(STATE.read_text()) if STATE.exists() else None
        plan_sha = module.digest(PREPARED / 'plan.json')
        if old and (old.get('format') != SIGNATURE or old.get('planSha256') != plan_sha):
            raise RuntimeError('An unrelated activation record was retained.')
        record = old or {'format': SIGNATURE, 'planSha256': plan_sha, 'containerId': current['Id'], 'imageId': current['Image'],
                        'installedBlobKeys': [], 'createdLinks': [], 'paused': False, 'phase': 'preflight'}
        inspect_backend(record); save_state(record)
        if old and old.get('phase') == 'complete': log('This additive repair is already complete; existing NAS changes were retained.'); return
        if shutil.disk_usage(RECOVERY).free < (CONFIG / 'db.sqlite').stat().st_size * 4 + 1024**3:
            raise RuntimeError('More free NAS SSD space is required before activation.')
        latest = RECOVERY / 'latest-baseline.sqlite'
        fresh_snapshot(module, latest)
        with contextlib.closing(module.read_only(latest)) as live, contextlib.closing(module.read_only(PREPARED / 'baseline.sqlite')) as original:
            pending = pending_additions(plan, live, original, module)
        stopped = False
        try:
            if any(pending.values()):
                log('Briefly stopping NAS InfiniDysk and capturing its latest database state...')
                record.update(paused=True, phase='stopping-backend'); save_state(record, maintenance=True); stopped = True
                run('docker', 'stop', '--timeout', '45', record['containerId'], timeout=75)
                if inspect_backend(record)['State']['Running']: raise RuntimeError('The NAS backend did not stop; no rows were inserted.')
                fresh_snapshot(module, latest)
                first_backup(module, latest, record)
                with contextlib.closing(module.read_only(latest)) as live, contextlib.closing(module.read_only(PREPARED / 'baseline.sqlite')) as original:
                    pending = pending_additions(plan, live, original, module)
                rebased = RECOVERY / 'rebased.sqlite'; shutil.copy2(latest, rebased)
                with contextlib.closing(sqlite3.connect(rebased.as_uri(), uri=True)) as test:
                    test.execute('PRAGMA journal_mode=DELETE')
                    module.insert_additions(test, pending); module.verify_preserved(test, latest, pending)
                log('Fresh NAS candidate passed: every current NAS row is retained. Installing only missing metadata...')
                install_blobs(plan, module, record)
                if inspect_backend(record)['State']['Running']: raise RuntimeError('The NAS backend restarted unexpectedly; its database was retained.')
                record['phase'] = 'committing-additions'; save_state(record, maintenance=True)
                with contextlib.closing(sqlite3.connect((CONFIG / 'db.sqlite').as_uri() + '?mode=rw', uri=True)) as live:
                    live.execute('PRAGMA synchronous=FULL')
                    module.insert_additions(live, pending); module.verify_preserved(live, latest, pending)
                record['phase'] = 'database-applied'; record['insertedRows'] = pending; save_state(record, maintenance=True)
                log('Starting the same NAS InfiniDysk container and checking frontend/backend health...')
                ensure_backend(record); stopped = False
            else:
                log('The reviewed catalogue records are already present; continuing without another restart.')
                wait_ready(record)
            if mount_record() != initial_mount: raise RuntimeError('The NAS mount generation changed; metadata was retained for review.')
            log('Refreshing the existing mount directory cache and checking the 41 restored IDs...')
            flush_directory_cache(); verified = verify_metadata(plan, module)
            validate_links(plan, module); add_links(plan, record)
            after = module.inventory(LIBRARY)
            if any(after.get(name) != target for name, target in before_links.items()):
                raise RuntimeError('An existing NAS link changed during activation; no existing links were overwritten by this helper.')
            if any(after.get(name) != target for name, target in plan['links'].items()):
                raise RuntimeError('A restored library link did not pass its final check.')
            record.update(phase='complete', paused=False, completedUtc=dt.datetime.now(dt.timezone.utc).isoformat(),
                          verifiedSourceTargets=verified, preExistingNasPathsRetained=len(before_links), restoredLibraryPaths=len(plan['links']))
            save_state(record)
            MAINTENANCE.unlink(missing_ok=True); fsync_directory(RECOVERY)
        except BaseException:
            record['phase'] = 'needs-resume'; save_state(record, maintenance=record.get('paused', False))
            raise
        finally:
            if stopped or record.get('paused'):
                log('Restoring NAS InfiniDysk after the interrupted activation...')
                ensure_backend(record)
    log('NAS CATALOGUE REPAIR ACTIVE: 41 library paths and their mounted metadata verified.')
    log('Current NAS settings, existing library paths, image and mount were retained. OptiPlex Plex was not changed; NAS Plex remains stopped.')
    log('One pre-activation database copy and the operation record are retained in ' + str(RECOVERY))
    log('Next: play one restored title through NAS Silo. This metadata check does not replace a video-playback test.')


def recover():
    if not MAINTENANCE.exists():
        if STATE.exists() and json.loads(STATE.read_text()).get('phase') == 'complete': cleanup()
        return
    with LOCK.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        record = json.loads(MAINTENANCE.read_text())
        if record.get('format') != SIGNATURE: raise RuntimeError('An unrelated maintenance marker was retained.')
        if record.get('paused'):
            log('Recovering only the recorded NAS InfiniDysk container; no database rollback is performed...')
            record['phase'] = 'needs-resume'; ensure_backend(record)


def boot_text():
    return f'''# {SIGNATURE}
[Unit]
Description=Recover NAS InfiniDysk after interrupted catalogue activation
Requires=docker.service
After=docker.service
RequiresMountsFor={SSD}
ConditionPathExists={MAINTENANCE}
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {WORKER} recover
TimeoutStartSec=5min
Restart=on-failure
RestartSec=15s

[Install]
WantedBy=multi-user.target
'''


def cleanup():
    if BOOT_UNIT.is_file() and not BOOT_UNIT.is_symlink() and SIGNATURE in BOOT_UNIT.read_text():
        run('systemctl', 'disable', BOOT_UNIT.name, allowed=(0, 1))
        BOOT_UNIT.unlink(); run('systemctl', 'daemon-reload')
    if WORKER.is_file() and not WORKER.is_symlink() and SIGNATURE in WORKER.read_text(): WORKER.unlink()
    if HELPER.is_file() and not HELPER.is_symlink():
        import hashlib
        if hashlib.sha256(HELPER.read_bytes()).hexdigest() == HELPER_SHA: HELPER.unlink()


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show') or not SSD.is_mount():
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220 with its application SSD mounted.')
    if any(path.is_symlink() for path in (CONFIG, LIBRARY, RECOVERY, STATE, MAINTENANCE)):
        raise RuntimeError('An unexpected symbolic NAS data path was retained.')
    if sys.argv[1:] == ['activate']: activate(); return
    if sys.argv[1:] == ['recover']: recover(); return
    if sys.argv[1:]: raise RuntimeError('Unknown catalogue activation operation.')
    if run('systemctl', 'is-active', 'nas-catalogue-activate.service', allowed=(0, 3, 4)).strip() in ('active', 'activating', 'deactivating'):
        log('NAS catalogue activation is already running.'); return
    if STATE.is_file() and json.loads(STATE.read_text()).get('phase') == 'complete':
        log('The reviewed catalogue repair is already complete. Existing NAS settings were retained.'); return
    module = helper(); load_plan(module)
    source = globals().get('INSTALL_SOURCE')
    if not source: raise RuntimeError('Use the complete provided activation command.')
    for path in (WORKER, BOOT_UNIT):
        if path.is_symlink() or (path.exists() and SIGNATURE not in path.read_text()):
            raise RuntimeError('An unrelated runtime helper or unit was retained.')
    module.atomic(WORKER, source, 0o700); fsync_directory(WORKER.parent)
    module.atomic(BOOT_UNIT, boot_text(), 0o644); fsync_directory(BOOT_UNIT.parent)
    run('systemctl', 'daemon-reload'); run('systemctl', 'enable', BOOT_UNIT.name)
    run('systemctl', 'reset-failed', 'nas-catalogue-activate.service', allowed=(0, 1))
    run('systemd-run', '--unit=nas-catalogue-activate', '--collect',
        '--property=ExecStopPost=/usr/bin/python3 ' + str(WORKER) + ' recover',
        '--property=RuntimeMaxSec=15min', '--property=TimeoutStopSec=5min',
        '--description=Activate reviewed additive NAS media catalogue repair',
        '/usr/bin/python3', '-u', str(WORKER), 'activate')
    log('NAS catalogue activation started. Closing SSH is safe. Only NAS InfiniDysk may briefly interrupt NAS playback.')
    log('Check: sudo journalctl -u nas-catalogue-activate.service -n 25 --no-pager -o cat')


if __name__ == '__main__':
    def interrupted(number, frame): raise SystemExit(128 + number)
    for number in (signal.SIGTERM, signal.SIGHUP): signal.signal(number, interrupted)
    try: main()
    except RuntimeError as error: raise SystemExit('STOP: ' + str(error))
    except Exception as error: raise SystemExit('STOP: NAS catalogue activation could not finish (' + type(error).__name__ + '); recovery records were retained.') from None
