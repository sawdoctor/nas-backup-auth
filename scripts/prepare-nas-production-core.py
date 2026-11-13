#!/usr/bin/env python3
"""Prepare source-authoritative core restore copies outside live NAS appdata.

Rehearses the production endpoint adapters against the latest verified standby.
There is deliberately no activate/start/stop/import action. A new common frozen
source point and a separately reviewed transactional switch remain mandatory.
"""
import contextlib
import copy
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid

FORMAT = 'sawdoctor-nas-production-core-preparation-v1'
APP = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
BACKUP = Path('/srv/dev-disk-by-uuid-631e3391-6a42-4158-9aa4-f7718ba0e7e9')
STANDBY = BACKUP / 'migration/nightly-standby'
BASE = BACKUP / 'migration/production-handover/core-preparation'
WORKER = BASE / 'worker.py'
POLICY = BASE / 'production-policy.py'
POLICY_URL = 'https://raw.githubusercontent.com/sawdoctor/nas-backup-auth/c5dc33f5d2ec8fc29075a86177d35ac545408379/scripts/production-core-policy.py'
POLICY_SHA = 'a0f66984a66a0d402840528c82e5f52437a76e7f14c3fadf06e882887012e6c2'
UNIT = 'nas-production-core-prepare.service'
PRIOR_WORKER_SHA = '24386952b1ace1ccc18eaf321e02c90974c2657df779aaad1cd97335cba1a021'
NAMES = {'sonarr': 'sonarr-nas', 'radarr': 'radarr-nas', 'radarr4k': 'radarr4k-nas',
         'prowlarr': 'prowlarr-nas', 'usenet-ultimate': 'usenet-ultimate-nas',
         'overseerr': 'seerr-nas', 'nzbdav': 'infinidysk-nas'}
TARGET = {name: '/config' for name in NAMES}
TARGET.update({'usenet-ultimate': '/app/config', 'overseerr': '/app/config'})
DATABASE = {'sonarr': 'sonarr.db', 'radarr': 'radarr.db', 'radarr4k': 'radarr.db',
            'prowlarr': 'prowlarr.db', 'nzbdav': 'db.sqlite'}
MEDIA_EXTENSIONS = {'.mkv', '.mp4', '.avi', '.m4v', '.ts', '.strm', '.mov'}
MAX_COPY = 64 * 1024**3


def say(value):
    print(value, flush=True)


def safe(path):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise RuntimeError('A symbolic preparation/input path was retained.')


def read(path, limit=16 * 1024**2):
    safe(path)
    if not path.is_file() or path.stat().st_size > limit:
        raise RuntimeError('A required bounded preparation input is unavailable: ' + path.name)
    return path.read_bytes()


def digest(path):
    safe(path)
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(4 * 1024**2), b''):
            result.update(block)
    return result.hexdigest()


def atomic(path, value):
    safe(path)
    if not isinstance(value, bytes):
        value = (json.dumps(value, indent=2) + '\n').encode()
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(value); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def run(*args, timeout=30):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        if BASE.is_dir():
            atomic(BASE / 'private-command-error.json', {'command': args, 'stdout': result.stdout, 'stderr': result.stderr})
        raise RuntimeError('A production preparation command failed; private details retained.')
    return result.stdout


def owner():
    safe(BASE)
    if BASE.exists():
        if json.loads(read(BASE / 'owner.json')) != {'format': FORMAT}:
            raise RuntimeError('An unrecognized preparation directory was retained.')
    else:
        BASE.mkdir(parents=True, mode=0o700)
        atomic(BASE / 'owner.json', {'format': FORMAT})


def load_policy():
    if digest(POLICY) != POLICY_SHA:
        raise RuntimeError('The pinned production endpoint adapter differs.')
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('production_core_policy', POLICY)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def snapshot():
    record = json.loads(read(STANDBY / 'current.json'))
    stamp = record.get('createdUtc', '')
    if (record.get('format') != 'sawdoctor-migration-standby-v1'
            or record.get('profile') != 'apps-with-external-plex-v1'
            or not re.fullmatch(r'\d{8}T\d{6}Z', stamp)):
        raise RuntimeError('The latest verified application standby identity differs.')
    source = STANDBY / 'snapshots' / stamp
    if record.get('snapshot') != str(source) or json.loads(read(source / '_VERIFIED.json')) != {
            key: value for key, value in record.items() if key != 'snapshot'}:
        raise RuntimeError('The current standby verification marker differs.')
    created = dt.datetime.strptime(stamp, '%Y%m%dT%H%M%SZ').replace(tzinfo=dt.timezone.utc)
    if not -dt.timedelta(minutes=5) <= dt.datetime.now(dt.timezone.utc) - created <= dt.timedelta(hours=36):
        raise RuntimeError('The application standby is older than 36 hours or future-dated.')
    manifest = json.loads(read(source / 'manifest.json'))
    if (manifest.get('format') != record['format'] or manifest.get('sourceHost') != '192.168.0.29'
            or manifest.get('createdUtc') != stamp or manifest.get('scope') != 'standby-only'
            or manifest.get('plexConfigIncluded') is not False):
        raise RuntimeError('The source manifest scope differs.')
    return source, record, manifest


def layout(source, manifest, runtime):
    mappings, live = {}, {}
    for name in NAMES:
        row = runtime[NAMES[name]]
        choices = [m for m in row['Mounts'] if m['Destination'] == TARGET[name] and m['Type'] == 'bind']
        if len(choices) != 1:
            raise RuntimeError('A current NAS configuration binding needs review: ' + name)
        destination = Path(choices[0]['Source']); safe(destination)
        if not destination.is_dir() or not destination.is_relative_to(APP):
            raise RuntimeError('A NAS app configuration is outside the application SSD.')
        label = 'infinidysk-config' if name == 'nzbdav' else 'core.' + name
        entry = manifest['dataRoots'].get(label, {})
        if entry.get('kind') != 'directory' or entry.get('snapshot') != 'data/' + label:
            raise RuntimeError('The source app root differs: ' + name)
        mappings[name] = 'data/' + label
        live[name] = destination
    if manifest['dataRoots'].get('library', {}).get('snapshot') != 'data/library':
        raise RuntimeError('The source library root differs.')
    for category in ('movies', 'movies-4k', 'tv'):
        mappings['library/' + category] = 'data/library/' + category
    for relative in mappings.values():
        path = source / relative; safe(path)
        if not path.is_dir() or path.is_mount():
            raise RuntimeError('A selected local snapshot root is unavailable.')
    return mappings, live


def parse_checksum(line):
    escaped = line.startswith('\\')
    if escaped:
        line = line[1:]
    match = re.fullmatch(r'([a-f0-9]{64}) [ *](.+)\n?', line)
    if not match:
        raise RuntimeError('A snapshot checksum entry needs review.')
    name = match[2].removesuffix('\n')
    if escaped:
        name = re.sub(r'\\([\\nr])', lambda item: {'\\': '\\', 'n': '\n', 'r': '\r'}[item[1]], name)
    name = name.removeprefix('./')
    parts = PurePosixPath(name)
    if parts.is_absolute() or '..' in parts.parts:
        raise RuntimeError('A snapshot checksum path is unsafe.')
    return name, match[1]


def sqlite_shm(path):
    if not path.name.endswith('-shm'):
        return False
    database = Path(str(path)[:-4])
    if database.is_symlink() or not database.is_file():
        return False
    with database.open('rb') as stream:
        return stream.read(16) == b'SQLite format 3\x00'


def verify_copied_files(source, data, mappings):
    checks = source / 'SHA256SUMS'; safe(checks)
    seen = set(); report = time.monotonic() + 30
    with checks.open('r', encoding='utf-8', errors='surrogateescape') as stream:
        for line in stream:
            if len(line) > 65536:
                raise RuntimeError('An oversized snapshot checksum entry was retained.')
            name, expected = parse_checksum(line)
            for label, prefix in mappings.items():
                if not name.startswith(prefix + '/'):
                    continue
                relative = name[len(prefix) + 1:]
                copied = data / label / relative
                if sqlite_shm(copied):
                    continue
                if copied.is_symlink() or digest(copied) != expected:
                    raise RuntimeError('A private source copy failed checksum verification.')
                seen.add(str(copied.relative_to(data)))
            if time.monotonic() >= report:
                say('Verified ' + str(len(seen)) + ' selected copied files...'); report = time.monotonic() + 30
    for label in mappings:
        folder = data / label
        for directory, dirs, files in os.walk(folder, followlinks=False):
            dirs[:] = [d for d in dirs if not (Path(directory) / d).is_symlink()]
            for leaf in files:
                path = Path(directory) / leaf
                if path.is_symlink():
                    continue
                if sqlite_shm(path):
                    path.unlink()  # only volatile coordination files inside our private copy
                elif str(path.relative_to(data)) not in seen:
                    raise RuntimeError('An unchecked regular file exists in the private source copy.')
    return len(seen)


def schema(path):
    safe(path)
    if not path.is_file():
        raise RuntimeError('A required source/NAS schema database is unavailable.')
    with contextlib.closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=20)) as db:
        tables = sorted(row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'") if not row[0].startswith('sqlite_'))
        return {table: db.execute('PRAGMA table_info("' + table.replace('"', '""') + '")').fetchall() for table in tables}


def library_coverage(data):
    wanted = set(); links = 0; physical = 0
    for category in ('movies', 'movies-4k', 'tv'):
        root = data / 'library' / category
        for directory, dirs, files in os.walk(root, followlinks=False):
            if any((Path(directory) / d).is_symlink() for d in dirs):
                raise RuntimeError('A source media directory uses an unsupported symbolic layout.')
            for leaf in files:
                path = Path(directory) / leaf
                if path.suffix.lower() not in MEDIA_EXTENSIONS:
                    continue
                if not path.is_symlink():
                    physical += 1; continue
                relative = path.relative_to(data / 'library')
                target = Path(os.path.normpath(os.path.join('/mnt/media', str(relative.parent), os.readlink(path))))
                try:
                    pieces = target.relative_to('/mnt/nzbdav/.ids').parts
                    identity = str(uuid.UUID(pieces[-1]))
                    if len(pieces) != 6 or ''.join(pieces[:5]).lower() != identity[:5]:
                        raise ValueError()
                except (ValueError, IndexError):
                    raise RuntimeError('A source movie/TV link uses an unsupported ID namespace.') from None
                wanted.add(identity); links += 1
    with contextlib.closing(sqlite3.connect((data / 'nzbdav/db.sqlite').as_uri() + '?mode=ro', uri=True)) as db:
        db.row_factory = sqlite3.Row
        rows = {str(uuid.UUID(row['Id'])): row for row in db.execute('SELECT * FROM DavItems WHERE Type=2')}
        if wanted - rows.keys():
            raise RuntimeError('A source library ID has no matching InfiniDysk file record.')
        blobs = set()
        for identity in wanted:
            for field in ('FileBlobId', 'NzbBlobId'):
                if rows[identity][field]:
                    blobs.add(str(uuid.UUID(rows[identity][field])))
            if not rows[identity]['FileBlobId']:
                raise RuntimeError('A source file record has no file metadata blob.')
    for identity in blobs:
        compact = identity.replace('-', '')
        path = data / 'nzbdav/blobs' / compact[:2] / compact[2:4] / identity
        safe(path)
        if not path.is_file():
            raise RuntimeError('A source file/repair metadata blob is missing from the copied configuration.')
    return {'videoLinks': links, 'physicalVideoFilesRetained': physical,
            'referencedFileIds': len(wanted), 'referencedMetadataBlobs': len(blobs)}


def fingerprint(row):
    return {'id': row['Id'], 'image': row['Image'], 'mounts': row['Mounts'],
            'environmentSha256': hashlib.sha256(json.dumps(row['Config'].get('Env', []), sort_keys=True).encode()).hexdigest()}


def image_content_matches(source, nas):
    layers = source.get('RootFS', {}).get('Layers')
    return bool(layers and layers == nas.get('RootFS', {}).get('Layers')
                and source.get('Os') and source.get('Architecture')
                and all(source.get(k) == nas.get(k) for k in ('Os', 'Architecture'))
                and (source.get('Variant') or '') == (nas.get('Variant') or ''))


def escape_dollars(value):
    if isinstance(value, str):
        return value.replace('$', '$$')
    if isinstance(value, list):
        return [escape_dollars(v) for v in value]
    if isinstance(value, dict):
        return {k: escape_dollars(v) for k, v in value.items()}
    return value


def no_nested_mounts(path):
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        name = re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), line.split()[4])
        if Path(name).is_relative_to(path):
            raise RuntimeError('A filesystem is mounted inside the private candidate; it was retained.')


def comparable_compose(model):
    result = copy.deepcopy(model)
    for service in result.get('services', {}).values():
        service.setdefault('command', None); service.setdefault('entrypoint', None)
        for mount in service.get('volumes', []):
            if mount.get('type') == 'bind' and isinstance(mount.get('bind'), dict):
                if mount['bind'].get('create_host_path') is False:
                    del mount['bind']['create_host_path']
                if not mount['bind']:
                    del mount['bind']
    for network in result.get('networks', {}).values():
        if network.get('ipam') == {}:
            del network['ipam']
    return result


def compose_source(project, filename):
    """Accept only the two installed Dockmon compatibility links, as inputs."""
    path = Path(filename)
    safe(path.parent)
    if path.is_symlink():
        if project not in ('media-core-nas', 'infinidysk-nas'):
            raise RuntimeError('An unrecognized symbolic Compose input was retained.')
        legacy = APP / 'compose' / project / 'compose.json'
        canonical = APP / 'appdata/dockmon/stacks' / project / 'compose.yaml'
        if path != legacy or os.readlink(path) != str(canonical):
            raise RuntimeError('A Dockmon Compose compatibility link differs; it was retained.')
        path = canonical
    safe(path)
    if not path.is_file() or path.stat().st_size > 2 * 1024**2:
        raise RuntimeError('A bounded current Compose source is unavailable.')
    return path


def prepare_composes(candidate, runtime, source_rows, policy, infini):
    groups = {}
    for name, nas_name in NAMES.items():
        row = runtime[nas_name]
        labels = row['Config'].get('Labels') or {}
        project, service = labels.get('com.docker.compose.project'), labels.get('com.docker.compose.service')
        files = labels.get('com.docker.compose.project.config_files', '').split(',')
        if not project or not service or not files or any(not Path(p).is_file() for p in files):
            raise RuntimeError('A NAS service has no usable current Compose source: ' + nas_name)
        if project not in groups:
            command = ['docker', 'compose', '-p', project]
            hashes = {}
            links = {}
            for filename in files:
                path = compose_source(project, filename)
                command += ['-f', filename]; hashes[str(path)] = digest(path)
                if str(path) != filename:
                    links[filename] = str(path)
            document = json.loads(run(*command, 'config', '--format', 'json'))
            groups[project] = {'document': document, 'sourceFiles': hashes,
                               'labelFiles': files, 'sourceLinkTargets': links, 'services': []}
        group = groups[project]
        if files != group['labelFiles']:
            raise RuntimeError('A NAS Compose project has inconsistent source-file labels.')
        if group['document']['services'].get(service, {}).get('container_name') != nas_name:
            raise RuntimeError('A current NAS Compose service identity differs.')
        values = policy.runtime_environment(name, source_rows[name]['Config'].get('Env', []),
                                            row['Config'].get('Env', []), infini)
        # Native `compose config` JSON is replayable and already dollar-escaped.
        # Runtime Config.Env values are literal: escape just the replaced env,
        # retaining untouched labels/commands/mounts exactly as rendered.
        group['document']['services'][service]['environment'] = escape_dollars(values)
        group['services'].append(service)
    result = []
    folder = candidate / 'composes'; folder.mkdir(mode=0o700, exist_ok=True)
    for index, (project, group) in enumerate(sorted(groups.items())):
        path = folder / (str(index) + '.json')
        atomic(path, group['document'])
        normalized = json.loads(run('docker', 'compose', '-p', project, '-f', str(path), 'config', '--format', 'json'))
        if comparable_compose(normalized) != comparable_compose(group['document']):
            raise RuntimeError('A private proposed Compose round trip differs; live files were retained.')
        if (any(str(compose_source(project, filename)) != group['sourceLinkTargets'].get(filename, filename)
                for filename in group['labelFiles'])
                or any(digest(Path(filename)) != expected for filename, expected in group['sourceFiles'].items())):
            raise RuntimeError('A current Compose input changed during preparation; live files retained.')
        result.append({'project': project, 'sourceFiles': group['sourceFiles'], 'candidate': str(path),
                       'sourceFileLabels': group['labelFiles'], 'sourceLinkTargets': group['sourceLinkTargets'],
                       'candidateSha256': digest(path), 'services': group['services']})
    return result


def prepare():
    owner(); policy = load_policy()
    with contextlib.ExitStack() as stack:
        for path in (BASE / '.run.lock', Path('/run/lock/sawdoctor-nas-backup.lock'), STANDBY / '.run.lock'):
            safe(path)
            stream = stack.enter_context(path.open('a'))
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError('NAS backup/receive/preparation is busy; retry once it finishes.') from None
        source, record, manifest = snapshot()
        source_rows = {r['Name'].lstrip('/'): r for r in manifest['containers']}
        runtime = {r['Name'].lstrip('/'): r for r in json.loads(run('docker', 'inspect', *NAMES.values()))}
        source_images = {r['Id']: r for r in manifest.get('images', [])}
        nas_images = {r['Id']: r for r in json.loads(run('docker', 'image', 'inspect',
                             *sorted({r['Image'] for r in runtime.values()})))}
        image_matches = {name: image_content_matches(source_images.get(source_rows[name]['Image'], {}),
                         nas_images[runtime[nas_name]['Image']]) for name, nas_name in NAMES.items()}
        mappings, live = layout(source, manifest, runtime)
        # Catch unexpected inputs before copying or adapting any private database.
        for row in runtime.values():
            labels = row['Config'].get('Labels') or {}
            for filename in labels.get('com.docker.compose.project.config_files', '').split(','):
                compose_source(labels.get('com.docker.compose.project'), filename)
        candidate = BASE / record['createdUtc']; safe(candidate)
        marker = {'format': FORMAT, 'sourceArchiveSha256': record['sha256']}
        if candidate.exists():
            if json.loads(read(candidate / 'owner.json')) != marker:
                raise RuntimeError('A different private restore candidate was retained.')
            if (candidate / 'plan.json').exists():
                plan = json.loads(read(candidate / 'plan.json'))
                if (plan.get('sourceArchiveSha256') != record['sha256']
                        or plan.get('policySha256') != POLICY_SHA):
                    raise RuntimeError('The existing private candidate identity differs.')
                if (any(fingerprint(runtime[n]) != value for n, value in plan['nasContainerFingerprints'].items())
                        or any(digest(Path(item['candidate'])) != item['candidateSha256']
                               or any(digest(Path(filename)) != expected
                                      for filename, expected in item['sourceFiles'].items())
                               or any(str(compose_source(item['project'], filename)) != target
                                      for filename, target in item.get('sourceLinkTargets', {}).items())
                               for item in plan['composeProposals'])):
                    raise RuntimeError('The prepared runtime/Compose inputs changed; existing copies retained.')
                say('Production core candidate already prepared privately for ' + record['createdUtc'] + '. No activation.'); return
        else:
            candidate.mkdir(mode=0o700); atomic(candidate / 'owner.json', marker)
        estimate = sum(int(run('du', '-sbx', '--', str(source / p), timeout=120).split()[0]) for p in mappings.values())
        if estimate > MAX_COPY or shutil.disk_usage(candidate).free < estimate + 4 * 1024**3:
            raise RuntimeError('The private core candidate exceeds its size/free-space bound.')
        data = candidate / 'data'; safe(data); data.mkdir(mode=0o700, exist_ok=True)
        no_nested_mounts(data)
        for label, relative in mappings.items():
            target = data / label; safe(target)
            target.mkdir(mode=0o700, parents=True, exist_ok=True)
            say('Copying existing verified source root privately: ' + label)
            run('rsync', '-aHAX', '--numeric-ids', '--one-file-system', '--no-devices', '--no-specials',
                '--checksum', '--', str(source / relative) + '/', str(target) + '/', timeout=3600)
        say('Verifying selected copied files against the source checksum list...')
        checked = verify_copied_files(source, data, mappings)
        say('Source checksums passed: ' + str(checked) + ' selected files. Checking library IDs and runtime compatibility...')
        coverage = library_coverage(data)
        source_schema = schema(data / 'nzbdav/db.sqlite')
        nas_schema = schema(live['nzbdav'] / 'db.sqlite')
        infini_env = policy.environment(runtime[NAMES['nzbdav']]['Config'].get('Env', []))
        infini = {'apiKey': infini_env.get('FRONTEND_BACKEND_API_KEY') or infini_env.get('NZBDAV_CONFIG__API__KEY'),
                  'user': infini_env.get('NZBDAV_CONFIG__WEBDAV__USER'),
                  'password': infini_env.get('NZBDAV_CONFIG__WEBDAV__PASS')}
        if not all(isinstance(v, str) and v for v in infini.values()):
            raise RuntimeError('The private NAS InfiniDysk runtime login is unavailable; no credentials changed.')
        keys, ports = {}, dict(policy.PORTS)
        for name in ('sonarr', 'radarr', 'radarr4k', 'prowlarr'):
            keys[name], ports[name] = policy.patch_xml(data, data / name, live[name] / 'config.xml',
                                                       source_rows[name]['Config'].get('Env', []))
        changes = {}
        for name in ('sonarr', 'radarr', 'radarr4k', 'prowlarr'):
            changes[name] = policy.patch_arr(data, data / name / DATABASE[name], name, keys, ports, infini)
        policy.patch_seerr(data, data / 'overseerr', keys, ports)
        policy.patch_ultimate(data, data / 'usenet-ultimate', keys, ports, infini)
        changes['infinidyskConfigKeys'] = policy.patch_infinidysk(data, data / 'nzbdav/db.sqlite')
        proposals = prepare_composes(candidate, runtime, source_rows, policy, infini)
        after = {r['Name'].lstrip('/'): r for r in json.loads(run('docker', 'inspect', *NAMES.values()))}
        if any(fingerprint(after[n]) != fingerprint(row) for n, row in runtime.items()):
            raise RuntimeError('A NAS container changed during preparation; private copies retained for review.')
        plan = {'format': FORMAT, 'preparedUtc': dt.datetime.now(dt.timezone.utc).isoformat(),
                'sourceCreatedUtc': record['createdUtc'], 'sourceArchiveSha256': record['sha256'],
                'sourceProfile': record['profile'], 'candidateOnly': True,
                'liveSourceHeld': False, 'activationImplemented': False, 'plexIncluded': False,
                'data': str(data), 'mappings': mappings, 'liveRoots': {k: str(v) for k, v in live.items()},
                'nasContainerFingerprints': {n: fingerprint(row) for n, row in runtime.items()},
                'checkedSourceFiles': checked, 'coverage': coverage, 'infiniSchemaMatches': source_schema == nas_schema,
                'sourceNasImageContentMatches': image_matches,
                'connectionChanges': changes, 'composeProposals': proposals, 'policySha256': POLICY_SHA}
        atomic(candidate / 'plan.json', plan)
        atomic(BASE / 'current.json', {'format': FORMAT, 'candidate': str(candidate),
                                    'sourceCreatedUtc': record['createdUtc'], 'sourceArchiveSha256': record['sha256']})
        say('PRIVATE PRODUCTION CORE PREPARED: ' + json.dumps(coverage, sort_keys=True))
        say('InfiniDysk source/current-NAS schema match: ' + str(plan['infiniSchemaMatches']).lower())
        say('Source/NAS image-content matches: ' + json.dumps(image_matches, sort_keys=True))
        say('Production RSS/search/watchlist/notification/repair settings retained; NAS runtime login retained.')
        say('No live database, library, Compose file, container, mount, timer or route changed.')
        say('No Plex archive copied or created. This is preparation; final frozen delta/import remains required.')
        say('Private plan: ' + str(candidate / 'plan.json'))


def install_worker(source):
    lock = BASE / '.run.lock'; safe(lock)
    with lock.open('a') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Private preparation is running; its worker was retained.') from None
        if WORKER.exists():
            previous = read(WORKER)
            if previous == source:
                return
            if hashlib.sha256(previous).hexdigest() != PRIOR_WORKER_SHA:
                raise RuntimeError('A different preparation worker exists; it was retained.')
            saved = BASE / 'worker.before-dockmon-link-fix.py'; safe(saved)
            if saved.exists() and read(saved) != previous:
                raise RuntimeError('A different earlier preparation worker was retained.')
            if not saved.exists():
                atomic(saved, previous)
        atomic(WORKER, source)


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the NAS.')
    if not APP.is_mount() or not BACKUP.is_mount():
        raise RuntimeError('The existing application and backup SSD mounts are required.')
    if sys.argv[1:] == ['--worker']:
        prepare(); return
    if sys.argv[1:]:
        raise RuntimeError('This preparer has no activation or service-control arguments.')
    owner()
    if subprocess.run(['systemctl', 'is-active', '--quiet', UNIT], capture_output=True).returncode == 0:
        say('The private production preparation is already running; check its journal.'); return
    source = globals().get('INSTALL_SOURCE')
    if not isinstance(source, str):
        if Path(__file__).resolve() != WORKER:
            raise RuntimeError('The pinned complete installer source is required.')
        source = WORKER.read_text()
    install_worker(source.encode())
    if not POLICY.exists():
        body = urllib.request.urlopen(POLICY_URL, timeout=30).read()
        if hashlib.sha256(body).hexdigest() != POLICY_SHA:
            raise RuntimeError('The production adapter download failed its integrity check.')
        atomic(POLICY, body)
    load_policy()
    if subprocess.run(['systemctl', 'is-active', '--quiet', UNIT], capture_output=True).returncode == 0:
        say('The private production preparation is already running; check its journal.'); return
    subprocess.run(['systemctl', 'reset-failed', UNIT], capture_output=True)
    run('systemd-run', '--unit=' + UNIT.removesuffix('.service'), '--collect',
        '--description=Prepare source-authoritative production core privately without changing live NAS services',
        '--property=Type=exec', '--property=UMask=0077', '--property=Nice=10',
        '--property=IOSchedulingClass=idle', '--property=RuntimeMaxSec=3h',
        '--property=TimeoutStopSec=30s', '--property=KillMode=mixed',
        '/usr/bin/python3', str(WORKER), '--worker')
    say('Private NAS production-core preparation started in systemd. Closing SSH is safe.')
    say('Progress: sudo journalctl -u ' + UNIT + ' -n 15 --no-pager -o cat')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('STOP: ' + (str(error) if isinstance(error, RuntimeError)
                         else 'Production preparation failed (' + type(error).__name__ + '); private details withheld.'))
