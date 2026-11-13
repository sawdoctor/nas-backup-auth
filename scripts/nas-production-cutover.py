#!/usr/bin/env python3
"""Paired frozen-source receiver and journalled NAS Plex/core import.

Default action prepares only. Receive and import are separate explicit actions;
neither starts a source hold. Every production start needs the same live source
hold proof. Recovery copies and the single frozen archive are never pruned here.
"""
import base64
import contextlib
import datetime as dt
import fcntl
import hashlib
import hmac
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import xml.etree.ElementTree as ET

APP = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
BACKUP = Path('/srv/dev-disk-by-uuid-631e3391-6a42-4158-9aa4-f7718ba0e7e9')
SCRATCH = Path('/srv/dev-disk-by-uuid-1f12a22e-5cfe-4b02-8d4b-48e9bf5fec6a')
BASE = APP / 'compose/production-cutover'
WORKER = BASE / 'worker.py'
PLAN = BASE / 'plan.json'
STATE = BASE / 'state.json'
ACTIVE = BASE / 'import-active'
FORMAT = 'sawdoctor-nas-production-cutover-v1'
SOURCE_FORMAT = 'sawdoctor-production-cutover-v1'
CORE_BASE = BACKUP / 'migration/production-handover/core-preparation'
HELPERS = {
    'core': (CORE_BASE / 'worker.py', 'f9ebaa67446d43e93cdbf4ee3088fb326b09bf6656c4ad13ee7142d0d92f8b84'),
    'cache': (CORE_BASE / 'cache-source-images.py', 'ab359ea2c9c100cb27e7ba92a4b52605a886c604935679d3579fd828718a8ae4'),
    'recovery': (Path('/usr/local/sbin/nas-media-recovery'), '618eb118dece842df2657b9f586fe64cebf1acbda5dc02361c01e99d9b575b2d'),
}
KEY = Path('/root/.ssh/nas-infinidysk-transfer')
HOST_KEY = '192.168.0.29 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGI1/hObYOUSPIqGKLePC0eEFvCc8Uoyv+YOmBbVPbgW\n'
PLEX_SOURCE_IMAGE = 'sha256:0c2f1122a4275efeea953a9882359f3809b27279d3c3022392e8e610a2eccc67'
PLEX_NAS_IMAGE = 'sha256:216d2576da930843270d578033551f3951a2bc3aa193264959be1402e6a9e86a'
PREFS = Path('Library/Application Support/Plex Media Server/Preferences.xml')
DB = Path('Library/Application Support/Plex Media Server/Plug-in Support/Databases/com.plexapp.plugins.library.db')
LIBRARY = APP / 'appdata/infinidysk-nas/library'
MAX_BYTES = 96 * 1024**3
RESERVE = 4 * 1024**3
UNITS = Path('/etc/systemd/system')
DROPIN = '96-sawdoctor-production-import.conf'
CONDITION = '# ' + FORMAT + '\n[Unit]\nConditionPathExists=!' + str(ACTIVE) + '\n'
RCLONE = 'nas-infinidysk-rclone.service'
BACKUP_LOCK = Path('/run/lock/sawdoctor-nas-backup.lock')
BOOT = UNITS / 'nas-production-import-guard.service'
PLEX_BOOT = UNITS / 'nas-production-plex.service'
BACKUP_WORKER = Path('/usr/local/sbin/nas-backup')
BACKUP_SHA = '1b3cbdf0446bf95ecbaea26cb2a9c1a0c63a2687fd725ae0ad9ab0f1d7693133'


def say(value): print(value, flush=True)
def sha(value): return hashlib.sha256(value).hexdigest()


def safe(path):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise RuntimeError('A symbolic import/control path was retained: ' + path.name)


def read(path, limit=32 * 1024**2):
    safe(path)
    if not path.is_file() or path.stat().st_size > limit:
        raise RuntimeError('A required bounded import record is unavailable: ' + path.name)
    return path.read_bytes()


def digest(path):
    safe(path); value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(4 * 1024**2), b''): value.update(block)
    return value.hexdigest()


def atomic(path, value, reference=None, mode=0o600):
    safe(path)
    if not isinstance(value, bytes): value = (json.dumps(value, indent=2) + '\n').encode()
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(value); stream.flush(); os.fsync(stream.fileno()); os.fchmod(stream.fileno(), mode)
        if reference:
            shutil.copystat(reference, name); info = reference.stat(); os.chown(name, info.st_uid, info.st_gid)
        os.replace(name, path); sync_dir(path.parent)
    finally: Path(name).unlink(missing_ok=True)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def run(*args, timeout=45, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout, **kwargs)
    if result.returncode:
        atomic(BASE / 'private-command-error.json', {'command': args, 'stdout': result.stdout, 'stderr': result.stderr})
        raise RuntimeError('A NAS cutover command failed; private diagnostics retained.')
    return result.stdout


def module(path, expected, name):
    if digest(path) != expected: raise RuntimeError('An accepted helper differs: ' + path.name)
    sys.dont_write_bytecode = True
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    result = importlib.util.module_from_spec(spec); loader.exec_module(result)
    return result


def helpers(): return {k: module(p, s, 'cutover_' + k) for k, (p, s) in HELPERS.items()}


@contextlib.contextmanager
def lock(path):
    safe(path)
    with path.open('a') as stream:
        try: fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise RuntimeError('NAS backup/recovery/import is busy; retry after it finishes.') from None
        yield


def catalog():
    ids = run('docker', 'ps', '-aq', '--no-trunc').split()
    if not ids or len(ids) > 100: raise RuntimeError('The NAS container inventory needs review.')
    return {r['Name'].lstrip('/'): r for r in json.loads(run('docker', 'inspect', *ids))}


def fingerprint(row):
    return {'id': row['Id'], 'image': row['Image'], 'mounts': row['Mounts'],
            'config': sha(json.dumps(row['Config'], sort_keys=True).encode()),
            'hostConfig': sha(json.dumps(row['HostConfig'], sort_keys=True).encode())}


def ssh():
    if not KEY.is_file(): raise RuntimeError('The existing restricted transfer key is unavailable.')
    known = BASE / 'known_hosts'; atomic(known, HOST_KEY.encode())
    return ['ssh', '-nT', '-p', '22', '-i', str(KEY), '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(known),
            '-o', 'ConnectTimeout=15', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3',
            'sawdoctor@192.168.0.29']


def source_status():
    value = run(*ssh(), 'production-cutover-status', timeout=45)
    if len(value) > 8192: raise RuntimeError('The source proof exceeded its bound.')
    result = json.loads(value)
    if result.get('format') != SOURCE_FORMAT: raise RuntimeError('The paired source controller is unavailable.')
    return result


def validate_proof(proof):
    if (proof.get('format') != SOURCE_FORMAT or proof.get('held') is not True
            or not re.fullmatch(r'\d{8}T\d{6}Z-[a-f0-9]{16}', proof.get('cutoverId', ''))
            or any(not re.fullmatch(r'[a-f0-9]{64}', proof.get(k, '')) for k in
                   ('archiveSha256', 'manifestSha256', 'identitySha256', 'receiptKey'))
            or type(proof.get('archiveBytes')) is not int or not 0 < proof['archiveBytes'] <= MAX_BYTES
            or proof.get('payloadLimitBytes') != MAX_BYTES):
        raise RuntimeError('A fully published, guarded source freeze is required; NAS production was not started.')


def held(expected):
    current = source_status(); validate_proof(current)
    if current != expected: raise RuntimeError('The source hold identity changed; NAS production start blocked.')


def config_bind(row, destination):
    choices = [m for m in row['Mounts'] if m['Destination'] == destination and m['Type'] == 'bind']
    if len(choices) != 1: raise RuntimeError('An expected NAS bind is unavailable: ' + destination)
    path = Path(choices[0]['Source']); safe(path)
    if not path.is_relative_to(APP) or not path.is_dir() or path.is_mount():
        raise RuntimeError('A NAS configuration root is outside the application filesystem.')
    return path


def dockmon_database(row):
    root = config_bind(row, '/app/data'); path = root / 'dockmon.db'; safe(path)
    return path


def dockmon_schema(db):
    fields = {'global_settings': ('default_auto_restart', 'auto_update_enabled_default', 'prune_images_enabled'),
              'auto_restart_configs': ('enabled',), 'container_updates': ('auto_update_enabled',),
              'container_http_health_checks': ('auto_restart_on_failure',)}
    for table, columns in fields.items():
        actual = {r[1] for r in db.execute('PRAGMA table_info("' + table + '")')}
        if not set(columns) <= actual: raise RuntimeError('The installed Dockmon automation schema needs review before a hold.')
    return fields


def dockmon_notify(path, backup=None):
    # Writes are allowed only after Dockmon is stopped, and only to the four
    # schema-checked automation controls. Accounts, alerts and notifications stay.
    with contextlib.closing(sqlite3.connect(path.as_uri() + ('?mode=rw' if backup else '?mode=ro'), uri=True)) as db:
        fields = dockmon_schema(db)
        if backup:
            if backup.exists(): raise RuntimeError('An earlier Dockmon recovery database was retained.')
            with contextlib.closing(sqlite3.connect(backup)) as saved: db.backup(saved)
            for table, columns in fields.items():
                db.execute('UPDATE "' + table + '" SET ' + ','.join('"' + c + '"=0' for c in columns))
            db.commit()
        result = {table + '.' + column: db.execute('SELECT count(*) FROM "' + table + '" WHERE "' + column + '"!=0').fetchone()[0]
                  for table, columns in fields.items() for column in columns}
        if backup and any(result.values()): raise RuntimeError('Dockmon notify-only controls did not verify.')
        return result


def plex_compose(row):
    labels = row['Config'].get('Labels') or {}
    if labels.get('com.docker.compose.project') != 'plex-nas': raise RuntimeError('The current Plex Compose project differs.')
    files = labels.get('com.docker.compose.project.config_files', '').split(',')
    if len(files) != 1: raise RuntimeError('A multi-file Plex stack requires review.')
    canonical = APP / 'appdata/dockmon/stacks/plex-nas/compose.yaml'
    path = Path(files[0])
    if path == Path('/app/data/stacks/plex-nas/compose.yaml'): path = canonical
    if path.is_symlink():
        if path != APP / 'compose/plex-nas/compose.json' or os.readlink(path) != str(canonical):
            raise RuntimeError('An unrecognized Plex Compose compatibility link was retained.')
        path = canonical
    safe(path)
    if not path.is_relative_to(APP): raise RuntimeError('The Plex stack is outside the NAS app filesystem.')
    read(path, 2 * 1024**2)
    return path, labels['com.docker.compose.service']


def backup_scope(data):
    anchor = "  --exclude='appdata/silo/download-artifacts/*' \\\n"
    addition = ''.join("  --exclude='compose/production-cutover/*/" + leaf + "' \\\n" for leaf in ('incoming', 'rollback', 'prepared'))
    text = data.decode()
    if sha(data) != BACKUP_SHA or text.count(anchor) != 1: raise RuntimeError('The accepted NAS backup scope differs; production backup ownership needs review.')
    return text.replace(anchor, anchor + addition, 1).encode()


def prepare(source_sha):
    if not re.fullmatch(r'[a-f0-9]{64}', source_sha): raise RuntimeError('The prepared source plan SHA256 is required.')
    if STATE.exists() or ACTIVE.exists(): raise RuntimeError('An existing import/recovery state was retained.')
    h = helpers(); core = h['core']; policy = core.load_policy(); rows = catalog()
    if rows['plex-nas']['State']['Running'] or rows['plex-nas']['HostConfig']['RestartPolicy']['Name'] != 'no':
        raise RuntimeError('NAS Plex must remain stopped with restart=no before preparation.')
    plex = rows['plex-nas']
    expected = {'/config': (APP / 'appdata/plex-nas/config', True),
                '/flora-test-library': (APP / 'appdata/plex-nas/flora-test-library', False),
                '/scratch': (SCRATCH, True), '/mnt/media': (LIBRARY, False),
                '/mnt/nzbdav': (Path('/mnt/nzbdav'), False), '/torbox-cams': (Path('/mnt/torbox-media/movies'), False)}
    actual = {m['Destination']: (Path(m['Source']), m['RW']) for m in plex['Mounts'] if m['Type'] == 'bind'}
    if (actual != expected or len(plex['Mounts']) != 6 or plex['Image'] != PLEX_NAS_IMAGE
            or plex['HostConfig']['NetworkMode'] != 'host' or plex['HostConfig'].get('Privileged')
            or plex['HostConfig'].get('Devices') != [{'PathOnHost': '/dev/dri', 'PathInContainer': '/dev/dri', 'CgroupPermissions': 'rwm'}]):
        raise RuntimeError('The accepted NAS Plex image, six bindings or Intel graphics differ.')
    env = policy.environment(plex['Config'].get('Env', []))
    if env.get('VERSION') != 'docker' or any('192.168.0.29' in v for k, v in env.items() if 'ADVERTISE' in k):
        raise RuntimeError('NAS Plex version/advertised endpoint needs correction before a hold.')
    plex_file, plex_service = plex_compose(plex)
    backup_scope(read(BACKUP_WORKER))
    private = json.loads(read(CORE_BASE / 'current.json')); candidate = Path(private['candidate'])
    if not candidate.is_relative_to(CORE_BASE): raise RuntimeError('The accepted private core candidate path differs.')
    prior = json.loads(read(candidate / 'plan.json')); cached = json.loads(read(candidate / 'image-cache/result.json'))
    if (cached['corePlanSha256'] != digest(candidate / 'plan.json')
            or cached['sourceArchiveSha256'] != prior['sourceArchiveSha256'] or not prior['candidateOnly']):
        raise RuntimeError('The accepted image/data preparation records disagree.')
    source_images = {n: v['sourceImage'] for n, v in cached['images'].items()}
    source_images['plex'] = PLEX_SOURCE_IMAGE
    nas_images = {n: v['nasImage'] for n, v in cached['images'].items()}; nas_images['plex'] = PLEX_NAS_IMAGE
    if set(nas_images) != set(core.NAMES) | {'plex'}: raise RuntimeError('The seven core image mappings are incomplete.')
    run('docker', 'image', 'inspect', *sorted(set(nas_images.values())))
    current = h['recovery'].host_mounts()
    if any(not h['recovery'].ready(rows[n], current) for n in (*core.NAMES.values(), 'plex-nas', 'silo-nas-silo-1')):
        raise RuntimeError('An accepted media mount is unavailable before the hold.')
    if h['recovery'].saved_ids(): raise RuntimeError('NAS backup recovery is still pending.')
    if source_status().get('held'): raise RuntimeError('Source is already held; inspect the existing cutover before preparing again.')
    live = {n: str(config_bind(rows[nas], core.TARGET[n])) for n, nas in core.NAMES.items()}
    live.update({'plex': str(config_bind(plex, '/config')), 'flora': str(config_bind(plex, '/flora-test-library'))})
    live.update({'library/' + c: str(LIBRARY / c) for c in ('movies', 'movies-4k', 'tv')})
    for path in map(Path, live.values()):
        safe(path); core.no_nested_mounts(path)
        if not path.is_dir() or path.stat().st_dev != APP.stat().st_dev: raise RuntimeError('A live rollback root is not on the application SSD.')
    if shutil.disk_usage(APP).free < MAX_BYTES + RESERVE or shutil.disk_usage(BACKUP).free < MAX_BYTES + RESERVE:
        raise RuntimeError('The bounded single-archive/incoming budget and reserve are unavailable.')
    affected = sorted(set(core.NAMES.values()) | {'plex-nas', 'dockmon'} |
                      {n for n, r in rows.items() if '/mnt/nzbdav' in h['recovery'].dependencies(r)})
    result = {'format': FORMAT, 'preparedUtc': dt.datetime.now(dt.timezone.utc).isoformat(),
              'sourcePlanSha256': source_sha, 'sourceImages': source_images, 'nasImages': nas_images,
              'workerSha256': digest(WORKER), 'liveRoots': live,
              'plexCompose': str(plex_file), 'plexService': plex_service, 'plexComposeSha256': digest(plex_file),
              'affected': affected, 'fingerprints': {n: fingerprint(rows[n]) for n in affected},
              'containers': {n: rows[n] for n in affected}, 'dockmonDatabase': str(dockmon_database(rows['dockmon'])),
              'dockmonAutomationEnabledCounts': dockmon_notify(dockmon_database(rows['dockmon'])),
              'corePlan': str(candidate / 'plan.json'), 'corePlanSha256': digest(candidate / 'plan.json')}
    # Validate all current Compose inputs without creating a container or changing data.
    for item in prior['composeProposals']:
        if len(item['sourceFiles']) != 1: raise RuntimeError('A multi-file core Compose project requires a specific restore adapter.')
        for filename, expected_sha in item['sourceFiles'].items():
            if digest(Path(filename)) != expected_sha: raise RuntimeError('A current core Compose input changed; plan needs refreshing.')
    after = catalog()
    if any(fingerprint(after[n]) != fingerprint(rows[n]) for n in affected):
        raise RuntimeError('A NAS runtime changed during preflight; prepare again before a hold.')
    atomic(PLAN, result)
    token = {'format': FORMAT, 'nasPlanSha256': digest(PLAN), 'sourcePlanSha256': source_sha, 'sourceImages': source_images}
    atomic(BASE / 'ready.json', token)
    say('NAS RECEIVE/IMPORT CONTROLS PREPARED. Production and NAS applications remain unchanged.')
    say('Fresh frozen Plex/main-WAL checks, catalogue/blob checks, exact images and journalled rename rollback are required by the importer.')
    say('NAS plan SHA256: ' + digest(PLAN))
    say('Dockmon automation counts (disabled during approved import): ' + json.dumps(result['dockmonAutomationEnabledCounts'], sort_keys=True))
    say('No source hold, container stop, database copy, scan or router change was performed.')
    say('Source approval handoff: ' + base64.urlsafe_b64encode(json.dumps(token, sort_keys=True).encode()).decode())


def approved(expected):
    if digest(PLAN) != expected: raise RuntimeError('The approved NAS plan digest differs.')
    plan = json.loads(read(PLAN))
    if plan.get('format') != FORMAT or plan['workerSha256'] != digest(WORKER): raise RuntimeError('The NAS plan/controller identity differs.')
    return plan


def validate_tar(archive):
    paths, symlinks, regular, hardlinks = set(), set(), set(), []
    total = 0
    process = subprocess.Popen(['zstd', '-dc', '--', str(archive)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        with tarfile.open(fileobj=process.stdout, mode='r|') as stream:
            for member in stream:
                path = PurePosixPath(member.name)
                if (path.is_absolute() or '..' in path.parts or path in paths or
                        not (member.isfile() or member.isdir() or member.issym() or member.islnk())):
                    raise RuntimeError('An unsafe final archive member was retained.')
                paths.add(path)
                if member.isfile(): total += member.size; regular.add(path)
                if total > MAX_BYTES or len(paths) > 2000000: raise RuntimeError('The final export exceeded its payload/member bound.')
                if member.issym(): symlinks.add(path)
                if member.islnk():
                    target = PurePosixPath(member.linkname)
                    if target.is_absolute() or '..' in target.parts: raise RuntimeError('An unsafe archive hard link was retained.')
                    hardlinks.append(target)
        if any(any(p in symlinks for p in path.parents) for path in paths) or any(p not in regular for p in hardlinks):
            raise RuntimeError('An archive member traverses a symbolic or invalid hard link.')
        while process.stdout.read(1024**2): pass
        if process.wait(timeout=30): raise RuntimeError('The final export decompression failed.')
        return total
    finally:
        process.stdout.close()
        if process.poll() is None: process.terminate(); process.wait(timeout=15)


def transfer(proof, archive):
    if archive.exists():
        if archive.stat().st_size != proof['archiveBytes'] or digest(archive) != proof['archiveSha256']:
            raise RuntimeError('A different final transfer archive was retained.')
        return
    part = archive.with_suffix('.partial'); safe(part)
    process = subprocess.Popen(ssh() + ['production-cutover-archive'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    received = 0; report = time.monotonic()
    try:
        with part.open('wb') as stream:
            for block in iter(lambda: process.stdout.read(4 * 1024**2), b''):
                received += len(block)
                if received > proof['archiveBytes'] or shutil.disk_usage(BACKUP).free < RESERVE:
                    raise RuntimeError('Final transfer stopped at its size/reserve bound.')
                stream.write(block)
                if time.monotonic() >= report:
                    say('Received final frozen export: ' + str(received // 1024**2) + ' MiB...'); report = time.monotonic() + 30
            stream.flush(); os.fsync(stream.fileno())
        if process.wait(timeout=30) or received != proof['archiveBytes'] or digest(part) != proof['archiveSha256']:
            raise RuntimeError('The final frozen transfer failed byte/SHA256 verification.')
        part.replace(archive); sync_dir(archive.parent)
    finally:
        process.stdout.close()
        if process.poll() is None: process.terminate(); process.wait(timeout=15)


def verify_files(root, core):
    seen = set(); report = time.monotonic() + 30
    with (root / 'SHA256SUMS').open('r', encoding='utf-8', errors='surrogateescape') as stream:
        for line in stream:
            if len(line) > 65536: raise RuntimeError('An oversized final checksum entry was retained.')
            name, expected = core.parse_checksum(line); path = root / name
            if name in seen or digest(path) != expected: raise RuntimeError('A frozen source file failed SHA256 verification.')
            seen.add(name)
            if time.monotonic() >= report: say('Verified final frozen files: ' + str(len(seen)) + '...'); report = time.monotonic() + 30
    actual = {str(Path(d) / f).removeprefix(str(root) + '/') for d, _, files in os.walk(root, followlinks=False)
              for f in files if (Path(d) / f).is_file() and not (Path(d) / f).is_symlink() and f != 'SHA256SUMS'}
    if actual != seen: raise RuntimeError('The final checksum inventory is incomplete.')
    return len(seen)


def verify_manifest(root, proof, plan):
    if digest(root / 'manifest.json') != proof['manifestSha256']: raise RuntimeError('The frozen manifest digest differs.')
    value = json.loads(read(root / 'manifest.json'))
    if (value.get('format') != SOURCE_FORMAT or value.get('scope') != 'production-frozen'
            or value.get('sourceHost') != '192.168.0.29' or value.get('cutoverId') != proof['cutoverId']
            or value.get('createdUtc') != proof['frozenUtc'] or value.get('plexConfigIncluded') is not True
            or value.get('sourceDockerStopped') is not True or value.get('identitySha256') != proof['identitySha256']):
        raise RuntimeError('The export is not this operation\'s fresh, stopped production capture.')
    rows = {r['Name'].lstrip('/'): r for r in value['containers']}
    if any(rows[n]['Image'] != image for n, image in plan['sourceImages'].items()):
        raise RuntimeError('A frozen source image differs from the pre-approved exact image mapping.')
    plex = root / 'data/plex-config'
    if sha(ET.fromstring(read(plex / PREFS)).get('MachineIdentifier', '').encode()) != proof['identitySha256']:
        raise RuntimeError('The received Plex identity differs from held live production.')
    checks = value['livePlexDatabaseSha256']
    if set(checks) - {'main', '-wal'} or 'main' not in checks: raise RuntimeError('The live Plex database provenance is incomplete.')
    for key in ('main', '-wal'):
        path = plex / (str(DB) + ('' if key == 'main' else key))
        if key in checks:
            if digest(path) != checks[key]: raise RuntimeError('Plex main/WAL differs from the stopped live source; no old-backup fallback is allowed.')
        elif path.exists(): raise RuntimeError('An obsolete Plex WAL was retained.')
    return value


def plex_check(config, image, folder):
    # Only disposable DB copies are opened. This is an actual integrity check,
    # not another --version probe and never a Plex Media Server launch.
    work = folder / 'plex-database-check'; work.mkdir(mode=0o700)
    databases = sorted((config / DB.parent).glob('com.plexapp.plugins.library*.db'))
    if not databases: raise RuntimeError('The received Plex database is unavailable.')
    for database in databases:
        for suffix in ('', '-wal', '-shm', '-journal'):
            path = Path(str(database) + suffix)
            if path.exists(): safe(path); shutil.copy2(path, work / path.name)
    for index, database in enumerate(databases):
        output = run('docker', 'run', '--rm', '--name=nas-plex-db-check-' + str(os.getpid()) + '-' + str(index),
            '--pull=never', '--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
            '--pids-limit=64', '--memory=2g', '--cpus=2', '--mount=type=bind,src=' + str(work) + ',dst=/check',
            '--entrypoint=/usr/lib/plexmediaserver/Plex SQLite', image,
            '/check/' + database.name, 'PRAGMA query_only=ON; PRAGMA temp_store=MEMORY; PRAGMA quick_check;', timeout=900)
        if output.strip() != 'ok': raise RuntimeError('Plex native SQLite integrity check failed; incoming and live data retained.')
    shutil.rmtree(work)


def receive(plan_sha):
    plan = approved(plan_sha); h = helpers(); proof = source_status(); validate_proof(proof)
    if STATE.exists(): raise RuntimeError('A prior receive/import state exists; inspect it before a new receive.')
    folder = BASE / proof['cutoverId']; safe(folder)
    if folder.exists(): raise RuntimeError('A previous incoming attempt was retained; inspect before retrying.')
    state = {'format': FORMAT, 'phase': 'receiving', 'nasPlanSha256': plan_sha,
             'proof': proof, 'folder': str(folder), 'raw': str(folder / 'incoming'),
             'roots': [], 'composes': [], 'units': {}, 'containers': plan['containers']}
    # Record the source return secret before the first transfer. Even a failed
    # download must have an available stopped-NAS receipt/rollback path.
    atomic(STATE, state)
    archive_dir = BACKUP / 'migration/production-handover/frozen' / proof['cutoverId']
    safe(archive_dir); archive_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    if shutil.disk_usage(BACKUP).free < proof['archiveBytes'] + RESERVE: raise RuntimeError('Backup SSD transfer space is insufficient.')
    archive = archive_dir / 'export.tar.zst'; transfer(proof, archive); held(proof)
    unpacked = validate_tar(archive)
    if shutil.disk_usage(APP).free < unpacked + RESERVE: raise RuntimeError('Application SSD incoming space is insufficient.')
    folder.mkdir(mode=0o700); raw = folder / 'incoming'; raw.mkdir(mode=0o700)
    run('tar', '--acls', '--xattrs', '--numeric-owner', '--same-owner', '--same-permissions', '-I', 'zstd', '-xpf', str(archive), '-C', str(raw), timeout=7200)
    count = verify_files(raw, h['core']); manifest = verify_manifest(raw, proof, plan)
    images = {r['Id']: r for r in manifest['images']}
    source_rows = {r['Name'].lstrip('/'): r for r in manifest['containers']}
    for name, nas_id in plan['nasImages'].items():
        local = json.loads(run('docker', 'image', 'inspect', nas_id))[0]
        if not h['cache'].same_image(h['core'], images[source_rows[name]['Image']], local):
            raise RuntimeError('A frozen source image/configuration differs from its cached NAS image: ' + name)
    say('Frozen file SHA256s and current Plex main/WAL provenance passed. Checking Plex databases with its native SQLite tool...')
    plex_check(raw / 'data/plex-config', plan['nasImages']['plex'], folder)
    held(proof)
    state.update({'phase': 'received', 'verifiedFiles': count})
    atomic(STATE, state)
    say('CURRENT FROZEN PRODUCTION RECEIVED AND VERIFIED. NAS live databases and Plex remain unchanged.')
    say('Receive record: ' + str(STATE))


def adapt(state, plan, h, runtime):
    core = h['core']; policy = core.load_policy(); raw = Path(state['raw']); folder = Path(state['folder'])
    manifest = verify_manifest(raw, state['proof'], plan)
    source_rows = {r['Name'].lstrip('/'): r for r in manifest['containers']}
    mappings, live = core.layout(raw, manifest, runtime)
    mappings.update({'plex': 'data/plex-config', 'flora': 'data/flora-test-library'})
    data = folder / 'prepared'; data.mkdir(mode=0o700)
    for name, relative in mappings.items():
        source, target = raw / relative, data / name; safe(source); safe(target)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        source.rename(target)
    coverage = core.library_coverage(data)
    if core.schema(data / 'nzbdav/db.sqlite') != core.schema(live['nzbdav'] / 'db.sqlite'):
        raise RuntimeError('The source/NAS InfiniDysk schema changed; import blocked.')
    env = policy.environment(runtime[core.NAMES['nzbdav']]['Config'].get('Env', []))
    infini = {'apiKey': env.get('FRONTEND_BACKEND_API_KEY') or env.get('NZBDAV_CONFIG__API__KEY'),
              'user': env.get('NZBDAV_CONFIG__WEBDAV__USER'), 'password': env.get('NZBDAV_CONFIG__WEBDAV__PASS')}
    if not all(infini.values()): raise RuntimeError('The accepted private NAS InfiniDysk login is unavailable.')
    keys, ports = {}, dict(policy.PORTS)
    for name in ('sonarr', 'radarr', 'radarr4k', 'prowlarr'):
        keys[name], ports[name] = policy.patch_xml(data, data / name, live[name] / 'config.xml', source_rows[name]['Config'].get('Env', []))
    for name in keys: policy.patch_arr(data, data / name / core.DATABASE[name], name, keys, ports, infini)
    policy.patch_seerr(data, data / 'overseerr', keys, ports)
    policy.patch_ultimate(data, data / 'usenet-ultimate', keys, ports, infini)
    policy.patch_infinidysk(data, data / 'nzbdav/db.sqlite')
    prefs = ET.fromstring(read(data / 'plex' / PREFS))
    for key in ('autoEmptyTrash', 'FSEventLibraryUpdatesEnabled', 'FSEventLibraryPartialScanEnabled', 'ScheduledLibraryUpdatesEnabled'): prefs.set(key, '0')
    if 'PreferredNetworkInterface' in prefs.attrib: prefs.set('PreferredNetworkInterface', '')
    if 'customConnections' in prefs.attrib: prefs.set('customConnections', prefs.get('customConnections').replace('192.168.0.29:', '192.168.0.220:'))
    prefs.set('TranscoderTempDirectory', '/scratch/plex-transcode')
    policy.write(data, data / 'plex' / PREFS, ET.tostring(prefs, encoding='utf-8', xml_declaration=True))
    proposals = core.prepare_composes(folder, runtime, source_rows, policy, infini)
    for item in proposals:
        path = Path(item['candidate']); model = json.loads(read(path))
        for name, nas in core.NAMES.items():
            if runtime[nas]['Config']['Labels']['com.docker.compose.project'] == item['project']:
                service = runtime[nas]['Config']['Labels']['com.docker.compose.service']
                model['services'][service]['image'] = plan['nasImages'][name]
                model['services'][service]['restart'] = 'no'
        atomic(path, model)
        normalized = json.loads(run('docker', 'compose', '-p', item['project'], '-f', str(path), 'config', '--format', 'json'))
        if core.comparable_compose(normalized) != core.comparable_compose(model): raise RuntimeError('The pinned production Compose round trip differs.')
        if len(item['sourceFiles']) != 1: raise RuntimeError('A multi-file Compose change was retained.')
        original = Path(next(iter(item['sourceFiles'])))
        saved = folder / ('compose-before-' + item['project'] + '.yaml'); shutil.copy2(original, saved)
        item.update({'before': str(saved), 'afterSha256': digest(path), 'live': str(original)})
    state.update({'prepared': str(data), 'coverage': coverage, 'composes': proposals, 'phase': 'adapted'})
    atomic(STATE, state)


def unit_state(name):
    return dict(line.split('=', 1) for line in run('systemctl', 'show', name, '-p', 'ActiveState', '-p', 'SubState', '-p', 'MainPID', '-p', 'LoadState').splitlines() if '=' in line)


def guard_units():
    timers = {l.split()[0] for l in run('systemctl', 'list-unit-files', 'nas-*.timer', '--no-legend', '--no-pager').splitlines() if l.split()}
    return sorted(timers | {n.removesuffix('.timer') + '.service' for n in timers} |
                  {'nas-media-boot.service', 'nas-backup-resume.service', 'nas-books.service', 'cron.service'})


def guard_text():
    return ('# ' + FORMAT + '\n[Unit]\nDescription=Keep an interrupted NAS production import stopped\n'
            'After=docker.service\nBefore=nas-media-boot.service nas-books.service\nConditionPathExists=' + str(ACTIVE) + '\n'
            '[Service]\nType=oneshot\nExecStart=/usr/bin/python3 ' + str(WORKER) + ' --recover\n'
            '[Install]\nWantedBy=multi-user.target\n')


def start_command(item):
    return ['docker', 'compose', '-p', item['project'], '-f', item['live'], 'up', '-d', '--no-deps', '--pull', 'never', '--force-recreate']


def guard_install(state):
    units = guard_units()
    for name in units:
        current = unit_state(name)
        if current['ActiveState'] in ('activating', 'deactivating'):
            raise RuntimeError('A NAS automation job is transitioning; import deferred.')
        idle_resume = name == 'nas-backup-resume.service' and current.get('SubState') == 'exited' and current.get('MainPID') == '0'
        if name.endswith('.service') and name not in ('nas-media-boot.service', 'nas-books.service', 'cron.service') and current['ActiveState'] == 'active' and not idle_resume:
            raise RuntimeError('A NAS backup/receive/recovery service is active; import deferred.')
    if not state['units']: state['units'] = {n: unit_state(n) for n in units}; atomic(STATE, state)
    if ACTIVE.exists() and json.loads(read(ACTIVE)) != {'format': FORMAT, 'cutoverId': state['proof']['cutoverId']}:
        raise RuntimeError('A different import guard is active; retained.')
    atomic(ACTIVE, {'format': FORMAT, 'cutoverId': state['proof']['cutoverId']})
    for name in units:
        path = UNITS / (name + '.d') / DROPIN; safe(path)
        if path.exists() and read(path) != CONDITION.encode(): raise RuntimeError('An existing NAS import override was retained.')
        path.parent.mkdir(mode=0o755, exist_ok=True); atomic(path, CONDITION.encode(), mode=0o644)
    if BOOT.exists() and read(BOOT) != guard_text().encode(): raise RuntimeError('An existing NAS import boot guard differs.')
    atomic(BOOT, guard_text().encode(), mode=0o644)
    run('systemctl', 'daemon-reload'); run('systemctl', 'enable', BOOT.name)
    active = [n for n, v in state['units'].items() if v['ActiveState'] == 'active' and (n.endswith('.timer') or n == 'cron.service')]
    if active: run('systemctl', 'stop', *active, timeout=90)


def swap_root(state, incoming, live, rollback):
    for path in (incoming, live, rollback): safe(path)
    if not incoming.is_dir() or not live.is_dir() or rollback.exists(): raise RuntimeError('A stopped root/rollback path differs.')
    if len({p.stat().st_dev for p in (incoming, live, rollback.parent)}) != 1: raise RuntimeError('Atomic root replacement requires one filesystem.')
    item = {'incoming': str(incoming), 'live': str(live), 'before': str(rollback), 'phase': 'planned'}
    state['roots'].append(item); atomic(STATE, state)
    live.rename(rollback); sync_dir(live.parent); sync_dir(rollback.parent)
    item['phase'] = 'saved'; atomic(STATE, state)
    incoming.rename(live); sync_dir(live.parent)
    item['phase'] = 'installed'; atomic(STATE, state)


def stop_affected(state, plan):
    rows = catalog()
    for name in plan['affected']:
        if name in rows:
            run('docker', 'update', '--restart=no', rows[name]['Id'])
            if rows[name]['State']['Running']: run('docker', 'stop', '--timeout', '60', rows[name]['Id'], timeout=90)
    rows = catalog()
    if any(rows[n]['State']['Running'] or rows[n]['HostConfig']['RestartPolicy']['Name'] != 'no' for n in plan['affected'] if n in rows):
        raise RuntimeError('A NAS imported writer/consumer restarted; source return is blocked.')


def wait_plex(config, proof):
    prefs = ET.fromstring(read(config / PREFS)); expected = prefs.get('MachineIdentifier')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({})); deadline = time.monotonic() + 120
    while True:
        try:
            with opener.open('http://127.0.0.1:32400/identity', timeout=3) as response: identity = ET.fromstring(response.read(65536))
            if identity.get('machineIdentifier') != expected or sha(expected.encode()) != proof['identitySha256']:
                raise RuntimeError('The running Plex identity differs from the frozen source.')
            return
        except OSError:
            if time.monotonic() > deadline: raise RuntimeError('Imported NAS Plex did not become ready; rollback remains available.')
            time.sleep(2)


def activate(plan_sha):
    plan = approved(plan_sha); state = json.loads(read(STATE)); h = helpers(); core = h['core']
    if state['phase'] not in ('received', 'adapted') or state['nasPlanSha256'] != plan_sha: raise RuntimeError('A newly verified received export is required before import.')
    held(state['proof']); rows = catalog()
    if any(fingerprint(rows[n]) != value for n, value in plan['fingerprints'].items()):
        raise RuntimeError('The NAS runtime changed since preflight; live data retained.')
    if digest(Path(plan['plexCompose'])) != plan['plexComposeSha256']:
        raise RuntimeError('The accepted Plex stack changed; live data retained.')
    with lock(BACKUP_LOCK):
        if h['recovery'].saved_ids(): raise RuntimeError('NAS backup recovery is pending.')
        if state['phase'] == 'received': adapt(state, plan, h, rows)
        held(state['proof']); guard_install(state)
        state['phase'] = 'importing'; atomic(STATE, state)
        stop_affected(state, plan)
        run('systemctl', 'stop', RCLONE, timeout=90)
        dockmon_notify(Path(plan['dockmonDatabase']), Path(state['folder']) / 'dockmon-before.db')
        for item in state['composes']:
            live = Path(item['live'])
            if digest(live) != item['sourceFiles'][str(live)]: raise RuntimeError('A live Compose file changed before replacement.')
            atomic(live, read(Path(item['candidate'])), reference=Path(item['before']))
        rollback = Path(state['folder']) / 'rollback'; rollback.mkdir(mode=0o700)
        data = Path(state['prepared'])
        for index, (name, live) in enumerate(plan['liveRoots'].items()):
            swap_root(state, data / name, Path(live), rollback / str(index))
        run('sync', '-f', str(APP), timeout=120); held(state['proof'])
        for item in state['composes']:
            services = [s for s in item['services'] if s == rows[core.NAMES['nzbdav']]['Config']['Labels']['com.docker.compose.service']
                        and item['project'] == rows[core.NAMES['nzbdav']]['Config']['Labels']['com.docker.compose.project']]
            if services: run(*start_command(item), *services, timeout=180)
        h['recovery'].backend_ready(seconds=90)
    # The existing mount helper's ExecStartPost takes BACKUP_LOCK itself.
    # Keep persistent automation guards and the operation lock, release only
    # the shared backup lock before asking it to rebind the new backend.
    run('systemctl', 'start', RCLONE, timeout=180)
    with lock(BACKUP_LOCK):
        held(state['proof'])
        for item in state['composes']:
            services = [s for s in item['services'] if not (item['project'] == rows[core.NAMES['nzbdav']]['Config']['Labels']['com.docker.compose.project']
                        and s == rows[core.NAMES['nzbdav']]['Config']['Labels']['com.docker.compose.service'])]
            if services: run(*start_command(item), *services, timeout=240)
        for name in plan['affected']:
            if name in core.NAMES.values() or name in ('dockmon', 'plex-nas'): continue
            if plan['containers'][name]['State']['Running']: run('docker', 'start', name, timeout=90)
        scratch = SCRATCH / 'plex-transcode'; safe(scratch)
        plex_env = core.load_policy().environment(rows['plex-nas']['Config'].get('Env', []))
        uid, gid = int(plex_env['PUID']), int(plex_env['PGID'])
        if not scratch.exists(): scratch.mkdir(mode=0o750); os.chown(scratch, uid, gid)
        if not scratch.is_dir() or scratch.stat().st_uid != uid:
            raise RuntimeError('The NAS Plex scratch directory ownership needs review before starting Plex.')
        held(state['proof']); run('docker', 'start', 'plex-nas', timeout=90)
        wait_plex(Path(plan['liveRoots']['plex']), state['proof'])
        current = catalog(); mounts = h['recovery'].host_mounts()
        for name in (*core.NAMES.values(), 'plex-nas', 'silo-nas-silo-1'):
            if not current[name]['State']['Running'] or not h['recovery'].ready(current[name], mounts) or h['recovery'].stale_bindings(current[name], mounts):
                raise RuntimeError('A production media client is stopped or sees an old FUSE mount: ' + name)
        held(state['proof']); state['phase'] = 'awaiting-acceptance'; atomic(STATE, state)
    say('CURRENT PLEX AND CORE IMPORTED ON NAS. Current source identity and FUSE bindings verified; no forced scan was requested.')
    say('Source remains held. NAS automation and Dockmon remain held until acceptance/commit.')
    say('Now verify router forwards, direct remote playback, library freshness/history and application endpoints. Recovery copies retained.')


def receipt(proof, now=None):
    value = {'cutoverId': proof['cutoverId'], 'stoppedAt': int(time.time() if now is None else now),
             'action': 'nas-production-stopped', 'allImportedWritersStopped': True}
    raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip('=') + '.' + hmac.new(bytes.fromhex(proof['receiptKey']), raw, hashlib.sha256).hexdigest()


def rollback():
    state = json.loads(read(STATE)); plan = approved(state['nasPlanSha256'])
    if state['phase'] in ('committed-core', 'committing'):
        raise RuntimeError('Production commitment started; a later rollback needs a current-state capture and review.')
    with lock(BACKUP_LOCK):
        if not ACTIVE.exists():
            if state['phase'] not in ('receiving', 'received', 'adapted', 'rolled-back-stopped'):
                raise RuntimeError('Import guards are missing; recovery needs review.')
            guard_install(state)
        stop_affected(state, plan); run('systemctl', 'stop', RCLONE, timeout=90)
        for item in reversed(state['roots']):
            incoming, live, before = map(Path, (item['incoming'], item['live'], item['before']))
            for path in (incoming, live, before): safe(path)
            # Reconcile physical paths, including a crash between rename/fsync
            # and recording the next journal phase.
            if before.exists():
                if live.exists():
                    saved_new = before.with_name(before.name + '.imported')
                    if saved_new.exists(): raise RuntimeError('A different imported recovery root was retained.')
                    live.rename(saved_new)
                before.rename(live); sync_dir(live.parent); sync_dir(before.parent)
            elif not live.exists(): raise RuntimeError('A rollback root is unavailable; source remains held.')
            item['phase'] = 'returned'; atomic(STATE, state)
        for item in state['composes']:
            live, saved = Path(item['live']), Path(item['before'])
            if digest(live) not in (digest(saved), item['afterSha256']): raise RuntimeError('An edited production Compose file was retained.')
            atomic(live, read(saved), reference=saved)
        # Do not restart restored NAS test writers before returning the source.
        rows = catalog()
        if any(rows[n]['State']['Running'] for n in plan['affected'] if n in rows): raise RuntimeError('A NAS writer remains running; source-return receipt blocked.')
        with socket.socket() as sock:
            sock.settimeout(2)
            if sock.connect_ex(('192.168.0.220', 32400)) == 0: raise RuntimeError('NAS Plex still responds; receipt blocked.')
        state['phase'] = 'rolled-back-stopped'; atomic(STATE, state)
        say('NAS IMPORT RETURNED TO RETAINED ROOTS; affected NAS writers remain stopped.')
        say('Revert router forwarding before source return. Within ten minutes run on the OptiPlex:')
        say('sudo python3 /var/lib/sawdoctor-production-cutover/worker.py --resume ' + receipt(state['proof']))


def recover():
    if not ACTIVE.exists(): return
    state = json.loads(read(STATE)); plan = approved(state['nasPlanSha256'])
    stop_affected(state, plan)
    say('Interrupted/uncommitted NAS production import retained stopped. Use the recorded rollback; source hold retained.')


def restart_value(policy):
    return policy['Name'] + (':' + str(policy['MaximumRetryCount']) if policy['Name'] == 'on-failure' and policy.get('MaximumRetryCount') else '')


def plex_boot_text():
    return ('# ' + FORMAT + '\n[Unit]\nDescription=Start the accepted production Plex on NAS media mounts\n'
            'Requires=docker.service\nWants=nas-media-boot.service ' + RCLONE + '\n'
            'After=docker.service nas-backup-resume.service nas-media-boot.service ' + RCLONE + ' nas-torbox-media.service\n'
            'RequiresMountsFor=' + str(APP) + ' ' + str(SCRATCH) + '\n'
            'ConditionPathExists=' + str(STATE) + '\nConditionPathExists=!' + str(ACTIVE) + '\n'
            '[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/python3 ' + str(WORKER) + ' --boot-plex\n'
            'TimeoutStartSec=5min\n[Install]\nWantedBy=multi-user.target\n')


def boot_plex():
    state = json.loads(read(STATE)); plan = approved(state['nasPlanSha256'])
    if state['phase'] != 'committed-core' or ACTIVE.exists(): raise RuntimeError('Uncommitted NAS Plex remains stopped.')
    h = helpers(); rows = catalog(); row = rows['plex-nas']
    if row['Image'] != plan['nasImages']['plex'] or row['Mounts'] != plan['containers']['plex-nas']['Mounts']:
        raise RuntimeError('Production Plex image/bindings changed; boot deferred.')
    config = Path(plan['liveRoots']['plex'])
    if sha(ET.fromstring(read(config / PREFS)).get('MachineIdentifier', '').encode()) != state['proof']['identitySha256']:
        raise RuntimeError('Production Plex identity changed; boot deferred.')
    if not h['recovery'].ready(row, h['recovery'].host_mounts()): raise RuntimeError('Production Plex media mounts are unavailable; boot deferred.')
    if not row['State']['Running']: run('docker', 'start', 'plex-nas', timeout=90)
    wait_plex(config, state['proof'])


def commit_core(plan_sha):
    # Explicitly commits only Plex/core ownership after the user's playback
    # acceptance. Auxiliary applications/NPM renewal remain separate checklist
    # tasks; this does not claim that the whole migration is complete.
    plan = approved(plan_sha); state = json.loads(read(STATE)); h = helpers()
    if state['phase'] != 'awaiting-acceptance': raise RuntimeError('Only a tested live NAS core can be committed.')
    with lock(BACKUP_LOCK):
        held(state['proof']); wait_plex(Path(plan['liveRoots']['plex']), state['proof'])
        if any(dockmon_notify(Path(plan['dockmonDatabase'])).values()): raise RuntimeError('Dockmon notify-only settings changed before commitment.')
        backup_before = Path(state['folder']) / 'nas-backup.before'; original = read(BACKUP_WORKER)
        proposed = backup_scope(original)
        if PLEX_BOOT.exists() and read(PLEX_BOOT) != plex_boot_text().encode(): raise RuntimeError('An existing Plex production boot unit differs.')
        for item in state['composes']:
            if digest(Path(item['live'])) != item['afterSha256']: raise RuntimeError('An imported core Compose file changed; commitment deferred.')
        if digest(Path(plan['plexCompose'])) != plan['plexComposeSha256']: raise RuntimeError('The accepted Plex stack changed; commitment deferred.')
        state['phase'] = 'committing'; atomic(STATE, state)
        for item in state['composes']:
            model = json.loads(read(Path(item['live'])))
            for service in item['services']:
                name = model['services'][service]['container_name']
                model['services'][service]['restart'] = restart_value(plan['containers'][name]['HostConfig']['RestartPolicy'])
            atomic(Path(item['live']), model, reference=Path(item['before']))
        plex_file = Path(plan['plexCompose'])
        model = json.loads(run('docker', 'compose', '-p', 'plex-nas', '-f', str(plex_file), 'config', '--format', 'json'))
        model['services'][plan['plexService']]['image'] = plan['nasImages']['plex']
        model['services'][plan['plexService']]['restart'] = 'on-failure:5'
        saved = Path(state['folder']) / 'plex-compose.before'; shutil.copy2(plex_file, saved)
        atomic(plex_file, model, reference=saved)
        for name in plan['affected']:
            policy = 'on-failure:5' if name == 'plex-nas' else restart_value(plan['containers'][name]['HostConfig']['RestartPolicy'])
            run('docker', 'update', '--restart=' + policy, name)
        shutil.copy2(BACKUP_WORKER, backup_before)
        run('bash', '-n', input=proposed.decode())
        atomic(BACKUP_WORKER, proposed, reference=backup_before)
        atomic(PLEX_BOOT, plex_boot_text().encode(), mode=0o644)
        run('systemctl', 'daemon-reload'); run('systemctl', 'enable', PLEX_BOOT.name)
        state.update({'phase': 'committed-core', 'committedUtc': dt.datetime.now(dt.timezone.utc).isoformat(),
                      'remaining': ['NPM/router and certificate renewal ownership', 'Auxiliary source app state and endpoints',
                                    'Kometa production schedule', 'Backup/cloud/sample-restore acceptance']})
        atomic(STATE, state); ACTIVE.unlink(); sync_dir(ACTIVE.parent)
        for name in state['units']:
            path = UNITS / (name + '.d') / DROPIN
            if read(path) != CONDITION.encode(): raise RuntimeError('An import override was edited; it was retained.')
            path.unlink()
        # The old standby receiver expects further source snapshots. Source
        # production is now held, so it must not keep waiting/failing nightly.
        run('systemctl', 'disable', '--now', 'nas-migration-standby.timer')
        run('systemctl', 'daemon-reload')
        resume = [name for name, value in state['units'].items() if value['ActiveState'] == 'active'
                  and (name.endswith('.timer') or name == 'cron.service') and name != 'nas-migration-standby.timer']
        if resume: run('systemctl', 'start', *resume, timeout=90)
        if plan['containers']['dockmon']['State']['Running']: run('docker', 'start', 'dockmon', timeout=90)
    say('NAS PLEX/CORE OWNERSHIP COMMITTED. Normal NAS automation restored; obsolete source standby receiver disabled.')
    say('Plex boot/backup recovery, restart policy and Dockmon notify-only controls retained. Final auxiliary/proxy/backup acceptance remains on the checklist.')


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in subprocess.check_output(['ip', '-4', 'addr', 'show'], text=True):
        raise RuntimeError('Run with sudo on the NAS.')
    if not all(p.is_mount() for p in (APP, BACKUP, SCRATCH)): raise RuntimeError('All three NAS SSD mounts are required.')
    safe(BASE)
    if not BASE.exists(): BASE.mkdir(mode=0o700, parents=True); atomic(BASE / 'owner.json', {'format': FORMAT})
    if json.loads(read(BASE / 'owner.json')) != {'format': FORMAT}: raise RuntimeError('An unrecognized import control folder was retained.')
    args = sys.argv[1:]
    if not args:
        source = globals().get('INSTALL_SOURCE')
        if not isinstance(source, str): raise RuntimeError('The complete pinned installer is required.')
        if WORKER.exists() and read(WORKER) != source.encode(): raise RuntimeError('A different NAS controller was retained.')
        if not WORKER.exists(): atomic(WORKER, source.encode())
        with lock(BASE / '.run.lock'), lock(BACKUP_LOCK): prepare(globals().get('SOURCE_PLAN_SHA256', ''))
        return
    if args == ['--recover']: recover(); return
    if args == ['--boot-plex']:
        with lock(BACKUP_LOCK): boot_plex()
        return
    if len(args) == 2 and args[0] == '--commit-core':
        with lock(BASE / '.run.lock'): commit_core(args[1])
        return
    if args == ['--rollback']:
        with lock(BASE / '.run.lock'): rollback()
        return
    if len(args) == 2 and args[0] in ('--receive', '--activate'):
        approved(args[1])
        unit = 'nas-production-' + args[0][2:]
        run('systemd-run', '--unit=' + unit, '--collect', '--description=Approved NAS frozen production ' + args[0][2:],
            '--property=Type=exec', '--property=UMask=0077', '--property=RuntimeMaxSec=3h', '--property=TimeoutStopSec=30s',
            '/usr/bin/python3', str(WORKER), args[0] + '-worker', args[1])
        say('Approved NAS ' + args[0][2:] + ' started. Follow ' + unit + '.service.'); return
    if len(args) == 2 and args[0] in ('--receive-worker', '--activate-worker'):
        def terminate(signum, frame): raise RuntimeError('NAS cutover interrupted; affected writers will be retained stopped.')
        signal.signal(signal.SIGTERM, terminate)
        with lock(BASE / '.run.lock'):
            (receive if args[0] == '--receive-worker' else activate)(args[1])
        return
    raise RuntimeError('Unsupported NAS cutover action; live data retained.')


if __name__ == '__main__':
    try: main()
    except Exception as error:
        if ACTIVE.exists():
            try: recover()
            except Exception: say('NAS interrupted-import recovery needs review; source hold and original data were retained.')
        raise SystemExit('STOP: ' + (str(error) if isinstance(error, RuntimeError)
                         else 'NAS cutover failed (' + type(error).__name__ + '); private details withheld.'))
