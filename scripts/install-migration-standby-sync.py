#!/usr/bin/env python3
"""Sawdoctor nightly OptiPlex-to-NAS standby snapshots v1.

Standby data only: this program never restores into running NAS appdata.
The same installer detects the source or NAS by its existing LAN address.
"""
import contextlib
import datetime as dt
import fcntl
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request
import xml.etree.ElementTree as ET

SIGNATURE = 'Sawdoctor nightly migration standby snapshots v1'
FORMAT = 'sawdoctor-migration-standby-v1'
WORKER = Path('/usr/local/sbin/nas-migration-standby')
SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
SOURCE_BASE = Path('/var/lib/sawdoctor-migration-standby')
OUTPUT = Path('/home/sawdoctor/nas-migration-standby')
NAS_BASE = SSD / 'migration/nightly-standby'
READER = Path('/usr/local/sbin/nas-migration-export-read')
UNITS = Path('/etc/systemd/system')
SOURCE_HELPER = Path('/usr/local/sbin/nas-plex-npm-export')
SOURCE_SHA = 'b0fc92712542035bee2cabdb603125c075e99e22ad5d35247c69bd48d57fda2e'
NAS_HELPER = Path('/usr/local/sbin/nas-plex-npm-stage')
NAS_SHA = '29bdb0e6a73ec3e71042b7d4bfd4acf42067d39083a820c088e3cea8a91f21b1'
ROLE = None
BASE = None
APP_NAMES = ('plex', 'npm-app-1', 'kometa', 'houndarr', 'homepage', 'uptime-kuma',
    'speedtest-tracker', 'wizarr', 'tracearr', 'sonarr', 'radarr', 'radarr4k',
    'prowlarr', 'usenet-ultimate', 'overseerr', 'abr-shelfmark-bridge',
    'audiobookrequest', 'audiobookshelf-test', 'kavita', 'sabnzbd-ebooks',
    'shelfmark-ebooks', 'shelfmark-torbox', 'stackarr-ebooks', 'nzbdav',
    'tracearr-redis', 'tracearr-db', 'glances', 'torbox-media-center')
LIVE_STATIC = {'glances', 'torbox-media-center', 'npm-app-1'}
ROOTS = {
    'plex-config': '/home/sawdoctor/docker/plex/config',
    'flora-test-library': '/home/sawdoctor/plex2ultimate/flora-test-library',
    'npm-data': '/home/sawdoctor/docker/npm/data',
    'npm-letsencrypt': '/home/sawdoctor/docker/npm/letsencrypt',
    'infinidysk-config': '/home/sawdoctor/docker/nzbdav/nzbdav-config',
    'library': '/mnt/media',
    'core.sonarr': '/home/sawdoctor/docker/media-apps/sonarr/config',
    'core.radarr': '/home/sawdoctor/docker/media-apps/radarr/config',
    'core.radarr4k': '/home/sawdoctor/docker/media-apps/radarr4k/config',
    'core.overseerr': '/home/sawdoctor/docker/media-apps/overseerr/config',
    'core.prowlarr': '/home/sawdoctor/docker/nzbdav/prowlarr_config',
    'core.usenet-ultimate': '/home/sawdoctor/docker/nzbdav/config',
    'books.abr-shelfmark-bridge': '/home/sawdoctor/docker/abr-shelfmark-bridge',
    'books.audiobookrequest': '/home/sawdoctor/docker/audiobookrequest',
    'books.kavita': '/home/sawdoctor/docker/kavita',
    'books.sabnzbd': '/home/sawdoctor/docker/sabnzbd',
    'books.shelfmark-ebooks': '/home/sawdoctor/docker/shelfmark-ebooks',
    'books.shelfmark-torbox': '/home/sawdoctor/docker/shelfmark-torbox',
    'books.stackarr-shelfmark': '/home/sawdoctor/docker/stackarr-shelfmark',
    'books.torbox-media-center': '/home/sawdoctor/docker/torbox-media-center',
    'books.audiobookshelf-data': '/mnt/usenet_scratch/audiobookshelf-test',
    'books.stable-playback-namespace': '/home/sawdoctor/torbox-recovery-20261011/stable-playback-namespace',
    'books.playback-overrides': '/home/sawdoctor/torbox-recovery-20261011/playback-overrides',
    'support.homepage': '/home/sawdoctor/docker/homepage/config',
    'support.uptime-kuma': '/home/sawdoctor/docker/kuma/data',
    'support.speedtest-tracker': '/home/sawdoctor/docker/speedtest-tracker/config',
    'support.wizarr': '/home/sawdoctor/docker/wizarr/data',
    'support.houndarr': '/home/sawdoctor/docker/houndarr/data',
    'support.kometa': '/home/sawdoctor/docker/kometa/config',
}
VOLUMES = {'support.tracearr': ('tracearr_tracearr_backups', 'tracearr', '/data/backup'),
    'support.tracearr-db': ('tracearr_tracearr_db', 'tracearr-db', '/var/lib/postgresql/data'),
    'support.tracearr-redis': ('tracearr_tracearr_redis', 'tracearr-redis', '/data')}
AUX_TIMERS = ('media-mount-guard.timer', 'media-mount-watch.timer', 'tmc-deadlock-watch.timer',
    'nzbdav-safe-restart.timer', 'torbox-audiobook-archive.timer', 'abs-user-provisioner.timer', 'plex-api-watch.timer')


def log(value):
    print(value, flush=True)


def atomic(path, data, mode=0o600, owner=None):
    if path.is_symlink():
        raise RuntimeError('An unexpected symbolic standby file was retained.')
    if isinstance(data, str):
        data = data.encode()
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
            temporary.chmod(mode)
            if owner:
                os.chown(temporary, *owner)
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def write_json(path, data, owner=None):
    atomic(path, json.dumps(data, indent=2) + '\n', owner=owner)


def run(*args, timeout=120, allowed=(0,), **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout, **kwargs)
    if result.returncode not in allowed:
        if BASE and BASE.is_dir():
            atomic(BASE / 'private-error.log', result.stdout + '\n' + result.stderr)
        raise RuntimeError('A standby snapshot command failed; diagnostic output was saved privately.')
    return result.stdout


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(4 * 1024**2), b''):
            value.update(block)
    return value.hexdigest()


def module(path, expected, name):
    if path.is_symlink() or digest(path) != expected:
        raise RuntimeError('An existing tested migration helper differs from its recorded checksum.')
    sys.dont_write_bytecode = True
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_file_location(name, path, loader=loader)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def inspect_source():
    rows = json.loads(run('docker', 'inspect', *APP_NAMES))
    found = {row['Name'].lstrip('/'): row for row in rows}
    if set(found) != set(APP_NAMES):
        raise RuntimeError('The reviewed OptiPlex application list differs.')
    env = dict(value.split('=', 1) for value in found['npm-app-1']['Config'].get('Env', []) if '=' in value)
    if env.get('DB_MYSQL_HOST') or env.get('DB_POSTGRES_HOST') or env.get('DB_SQLITE_FILE', '/data/database.sqlite') != '/data/database.sqlite':
        raise RuntimeError('The source NPM database configuration differs from the reviewed SQLite installation.')
    env = dict(value.split('=', 1) for value in found['nzbdav']['Config'].get('Env', []) if '=' in value)
    if env.get('DATABASE_PROVIDER', '').lower() not in ('', 'sqlite'):
        raise RuntimeError('The source InfiniDysk database provider differs from the existing SQLite installation.')
    return found


def data_roots(containers):
    result = {name: {'source': value, 'snapshot': 'data/' + name, 'kind': 'directory'} for name, value in ROOTS.items()}
    for label, (volume_name, name, target) in VOLUMES.items():
        records = [row for row in containers[name]['Mounts'] if row['Destination'] == target
                   and row['Type'] == 'volume' and row.get('Name') == volume_name]
        volume = json.loads(run('docker', 'volume', 'inspect', volume_name))[0]
        if len(records) != 1 or volume.get('Driver') != 'local' or volume.get('Options') or volume['Mountpoint'] != records[0]['Source']:
            raise RuntimeError('A Tracearr persistent volume differs from the reviewed source layout.')
        result[label] = {'source': volume['Mountpoint'], 'snapshot': 'data/' + label, 'kind': 'directory'}
    for label, source in (('host.bin', '/usr/local/bin'), ('host.sbin', '/usr/local/sbin'),
                          ('host.units', '/etc/systemd/system'), ('host.scripts', '/home/sawdoctor/scripts'),
                          ('host.airlock', '/usr/local/lib/torbox-audiobooks'),
                          ('host.plex-backup-wrapper', '/usr/local/lib/plex-backup-bin')):
        if Path(source).is_dir():
            result[label] = {'source': source, 'snapshot': 'data/' + label, 'kind': 'directory'}
    files = {'/etc/abs-user-provisioner.env', '/etc/torbox-audiobook-archive.env',
             '/home/sawdoctor/.config/torbox-audiobook-import.conf'}
    for row in containers.values():
        labels = row['Config'].get('Labels') or {}
        files.update(value for value in labels.get('com.docker.compose.project.config_files', '').split(',') if value)
        working = labels.get('com.docker.compose.project.working_dir')
        if working and (Path(working) / '.env').is_file():
            files.add(str(Path(working) / '.env'))
    env = Path('/etc/torbox-audiobook-archive.env')
    if env.is_file():
        for line in env.read_text().splitlines():
            if line.startswith('TORBOX_ARCHIVE_STATE_DIR='):
                state = Path(line.split('=', 1)[1].strip().strip('\"\''))
                if state.is_absolute() and state.is_dir() and not state.is_symlink():
                    if not any(state.is_relative_to(prefix) for prefix in ('/var/lib', '/home/sawdoctor')):
                        raise RuntimeError('The audiobook archive ledger location needs review.')
                    result['host.archive-state'] = {'source': str(state), 'snapshot': 'data/host.archive-state', 'kind': 'directory'}
    for source in sorted(files):
        path = Path(source)
        if path.is_file():
            label = 'file.' + hashlib.sha256(source.encode()).hexdigest()[:16]
            result[label] = {'source': source, 'snapshot': 'files/' + label, 'kind': 'file'}
    for label, entry in result.items():
        path = Path(entry['source'])
        if path.is_symlink() or not path.exists() or run('findmnt', '-n', '-T', str(path), '-o', 'FSTYPE').strip() not in ('ext4', 'xfs', 'btrfs'):
            raise RuntimeError('A recorded local source path is unavailable: ' + label)
    # Require the container configuration mounts to be covered by a copied root.
    required = {'plex': '/config', 'npm-app-1': '/data', 'nzbdav': '/config',
                'sonarr': '/config', 'radarr': '/config', 'radarr4k': '/config',
                'prowlarr': '/config', 'usenet-ultimate': '/app/config', 'overseerr': '/app/config'}
    for name, target in required.items():
        paths = [Path(mount['Source']) for mount in containers[name]['Mounts'] if mount['Destination'] == target and mount['Type'] == 'bind']
        if len(paths) != 1 or not any(paths[0].is_relative_to(entry['source']) for entry in result.values() if entry['kind'] == 'directory'):
            raise RuntimeError('An application configuration binding is outside the copied source roots.')
    return result


def copy_roots(work, roots, live=False):
    for label, entry in roots.items():
        source, target = Path(entry['source']), work / entry['snapshot']
        target.parent.mkdir(parents=True, exist_ok=True)
        if entry['kind'] == 'file':
            shutil.copy2(source, target)
            continue
        target.mkdir(exist_ok=True)
        command = ['rsync', '-aHAX', '--numeric-ids', '--one-file-system', '--no-devices', '--no-specials', '--delete']
        if not live:
            command.append('--checksum')
        if label == 'library':
            command += ['--exclude=/ebooks/***']
        if label == 'books.audiobookshelf-data':
            command += ['--exclude=/rclone-cache/***', '--exclude=/rclone-archive-cache/***',
                        '--exclude=/transcode/***', '--exclude=/metadata/streams/***', '--exclude=/*.log']
        if label == 'plex-config':
            command += ['--exclude=/Library/Application Support/Plex Media Server/Cache/Transcode/***']
        run(*command, '--', str(source) + '/', str(target) + '/', timeout=3600, allowed=(0, 24) if live else (0,))


def source_engine(catalog=None, roots=None):
    engine = module(SOURCE_HELPER, SOURCE_SHA, 'standby_source_engine')
    engine.BASE = SOURCE_BASE; engine.STATE = SOURCE_BASE / 'resume.json'; engine.FORMAT = FORMAT
    engine.say = lambda value: log(value.replace('Pausing Plex and NPM', 'Pausing selected source applications')
                                   .replace('Plex and NPM restored.', 'Source applications restored.'))
    if catalog is None:
        path = SOURCE_BASE / 'catalog.json'
        if not path.exists():
            return engine
        catalog = json.loads(path.read_text())
    engine.IMAGES = {name: catalog[name]['Image'] for name in APP_NAMES if name not in LIVE_STATIC}
    def inspect():
        current = inspect_source()
        for name, original in catalog.items():
            if current[name]['Id'] != original['Id'] or current[name]['Image'] != original['Image']:
                raise RuntimeError('An OptiPlex container changed during standby capture.')
        return {name: current[name] for name in engine.IMAGES}
    engine.inspect_targets = inspect
    if roots is not None:
        def sync(work, live=False):
            copy_roots(work, roots, live)
            if not live:
                snapshot_npm_database(work)
                # Certificate renewal stays owned by the live source proxy.
                # Copy its certificate files again after the database backup.
                copy_roots(work, {'npm-letsencrypt': roots['npm-letsencrypt']})
        engine.sync = sync
    return engine


def snapshot_npm_database(work):
    source = Path(ROOTS['npm-data']) / 'database.sqlite'
    target = work / 'data/npm-data/database.sqlite'
    if source.is_symlink() or target.is_symlink():
        raise RuntimeError('An unexpected symbolic NPM database was retained.')
    stat = source.stat()
    fd, name = tempfile.mkstemp(prefix='.npm-database-', dir=target.parent)
    os.close(fd); temporary = Path(name)
    try:
        live = sqlite3.connect(source.as_uri() + '?mode=ro', uri=True, timeout=30)
        copied = sqlite3.connect(temporary)
        try:
            deadline=time.monotonic()+60
            def progress(status, remaining, total):
                if time.monotonic()>deadline:
                    raise RuntimeError('The online NPM snapshot exceeded its time limit; source recovery will continue.')
            live.backup(copied, pages=1024, sleep=0.05, progress=progress)
            copied.execute('PRAGMA journal_mode=DELETE')
            if copied.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
                raise RuntimeError('The online NPM database snapshot failed its integrity check.')
        finally:
            copied.close(); live.close()
        temporary.chmod(stat.st_mode & 0o777); os.chown(temporary, stat.st_uid, stat.st_gid)
        with temporary.open('rb') as stream:os.fsync(stream.fileno())
        for suffix in ('-wal', '-shm', '-journal'):
            Path(str(target) + suffix).unlink(missing_ok=True)
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)


def restore_aux():
    path = SOURCE_BASE / 'paused-timers.json'
    if not path.exists():
        return
    names = json.loads(path.read_text())
    if not set(names) <= set(AUX_TIMERS):
        raise RuntimeError('The recorded source timer list differs from this snapshot job.')
    for name in names:
        run('systemctl', 'start', name)
    path.unlink()


def source_resume():
    source_engine().resume()
    restore_aux()


def wait_quiet():
    prefs = Path(ROOTS['plex-config']) / 'Library/Application Support/Plex Media Server/Preferences.xml'
    token = ET.parse(prefs).getroot().attrib.get('PlexOnlineToken')
    if not token:
        raise RuntimeError('The private Plex session check needs the existing server token.')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + 7200
    report = 0
    while True:
        request = urllib.request.Request('http://127.0.0.1:32400/status/sessions', headers={'X-Plex-Token': token})
        try:
            with opener.open(request, timeout=10) as response:
                count = int(ET.fromstring(response.read()).attrib.get('size', '-1'))
        except Exception:
            raise RuntimeError('The local Plex session check failed; source applications were not paused.')
        if count == 0:
            return
        if count < 0 or time.monotonic() >= deadline:
            raise RuntimeError('Plex did not become idle within two hours; the previous standby snapshot was retained.')
        if time.monotonic() >= report:
            log('Waiting for Plex playback to finish before the consistent snapshot...'); report = time.monotonic() + 60
        time.sleep(15)


def verify_databases(work, engine):
    engine.verify(work)
    database = sqlite3.connect((work/'data/npm-data/database.sqlite').as_uri()+'?mode=ro',uri=True)
    try:
        referenced=set()
        for table in ('proxy_host','redirection_host','dead_host','stream'):
            fields={row[1] for row in database.execute('PRAGMA table_info("'+table+'")')}
            if 'certificate_id' not in fields:
                continue
            condition='is_deleted=0'+(' AND enabled=1' if 'enabled' in fields else '')
            referenced.update(row[0] for row in database.execute('SELECT certificate_id FROM "'+table+'" WHERE '+condition) if row[0])
        for identity in referenced:
            row=database.execute('SELECT provider FROM certificate WHERE id=? AND is_deleted=0',(identity,)).fetchone()
            if row is None or row[0] not in ('letsencrypt','other'):
                raise RuntimeError('A copied NPM certificate reference is unavailable.')
            root=work/('data/npm-letsencrypt' if row[0]=='letsencrypt' else 'data/npm-data/custom_ssl')
            folder=root/('live/npm-'+str(identity) if row[0]=='letsencrypt' else 'npm-'+str(identity))
            for filename in ('fullchain.pem','privkey.pem'):
                path=folder/filename
                if not path.resolve().is_relative_to(root.resolve()) or not path.is_file() or not path.stat().st_size:
                    raise RuntimeError('A certificate/key referenced by the NPM snapshot is unavailable; the previous snapshot was retained.')
    finally:
        database.close()
    count = 0
    for directory, folders, files in os.walk(work, followlinks=False):
        folders[:] = [name for name in folders if not (Path(directory) / name).is_symlink()]
        for name in files:
            path = Path(directory) / name
            if path.is_symlink() or path.is_relative_to(work / 'data/plex-config'):
                continue
            with path.open('rb') as stream:
                header = stream.read(16)
            if header != b'SQLite format 3\x00':
                continue
            connection = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)
            try:
                connection.execute('PRAGMA query_only=ON')
                if connection.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
                    raise RuntimeError('A copied application database failed its integrity check.')
            finally:
                connection.close()
            count += 1
    log('Additional copied SQLite databases verified: ' + str(count))


def snapshot_source():
    source_resume()
    catalog = inspect_source(); roots = data_roots(catalog)
    if not all(row['State']['Running'] for name, row in catalog.items() if name not in LIVE_STATIC):
        raise RuntimeError('A source application is deliberately stopped; its state was retained for review.')
    work = SOURCE_BASE / 'snapshot-work'
    if work.is_symlink():
        raise RuntimeError('An unexpected symbolic source staging directory was retained.')
    if work.exists() and ((work / '.standby-owner').is_symlink() or not (work / '.standby-owner').is_file()
                          or (work / '.standby-owner').read_text() != FORMAT):
        raise RuntimeError('Unrecognised source staging files were retained.')
    work.mkdir(mode=0o700, exist_ok=True)
    atomic(work / '.standby-owner', FORMAT)
    # Remove only obsolete labels in this job's owned incremental staging.
    for folder in ('data', 'files'):
        parent = work / folder
        if parent.is_dir():
            keep = {Path(entry['snapshot']).name for entry in roots.values() if Path(entry['snapshot']).parent.as_posix() == folder}
            for path in parent.iterdir():
                if path.name not in keep:
                    if path.is_dir() and not path.is_symlink():shutil.rmtree(path)
                    else:path.unlink()
    bytes_needed = sum(int(run('du', '-sbx', '--', entry['source']).split()[0]) for entry in roots.values())
    if shutil.disk_usage(SOURCE_BASE).free < 2 * bytes_needed + 2 * 1024**3:
        raise RuntimeError('The OptiPlex needs more free local space for the consistent standby snapshot.')
    engine = source_engine(catalog, roots)
    engine.check_sqlite_tool()
    write_json(SOURCE_BASE / 'catalog.json', catalog)
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    manifest = {'format': FORMAT, 'sourceHost': '192.168.0.29', 'scope': 'standby-only',
        'createdUtc': stamp, 'dataRoots': roots, 'containers': list(catalog.values()),
        'images': json.loads(run('docker', 'image', 'inspect', *sorted({row['Image'] for row in catalog.values()}))),
        'imageArchivesIncluded': False}
    log('Pre-copying application state, Plex/NPM data, custom host files and library symlinks...')
    copy_roots(work, roots, live=True)
    wait_quiet()
    archive_state = run('systemctl', 'show', '--no-pager', 'torbox-audiobook-archive.service', '-p', 'ActiveState', '--value').strip()
    if archive_state not in ('inactive', 'failed'):
        raise RuntimeError('The source audiobook archive job is busy; no source applications were paused.')
    timers = [name for name in AUX_TIMERS if run('systemctl', 'is-active', name, allowed=(0,3,4)).strip() == 'active']
    write_json(SOURCE_BASE / 'paused-timers.json', timers)
    try:
        for name in timers:
            run('systemctl', 'stop', name)
        log('Pausing the selected source applications briefly for the final consistent copy...')
        def expired(signum, frame):
            raise RuntimeError('The consistent copy exceeded ten minutes; source applications are being restored.')
        previous=signal.signal(signal.SIGALRM, expired)
        try:
            signal.alarm(600)
            engine.cold_copy(work, {name: catalog[name] for name in engine.IMAGES})
        finally:
            signal.alarm(0);signal.signal(signal.SIGALRM,previous)
    finally:
        source_resume()
    log('Source applications and original timers restored. Verifying and compressing the saved copy...')
    stamp=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    manifest['createdUtc']=stamp
    manifest['snapshotState'] = 'copied'
    write_json(work / 'manifest.json', manifest)
    verify_databases(work, engine)
    run('bash', '-o', 'pipefail', '-c',
        'find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS', cwd=work, timeout=1800)
    partial = OUTPUT / 'export.tar.zst.part'
    if partial.is_symlink():
        raise RuntimeError('An unexpected symbolic source archive was retained.')
    run('tar', '--acls', '--xattrs', '--numeric-owner', '--sparse', '--one-file-system',
        '-I', 'zstd -T2 -3', '-cpf', str(partial), '-C', str(work), '.', timeout=7200)
    run('zstd', '-t', '--', str(partial), timeout=1800)
    owner = pwd.getpwnam('sawdoctor'); ids = (owner.pw_uid, owner.pw_gid)
    partial.chmod(0o600); os.chown(partial, *ids)
    size = int(run('du', '-sbx', '--', str(work)).split()[0])
    metadata = {'format': FORMAT, 'createdUtc': stamp, 'sha256': digest(partial),
                'archiveBytes': partial.stat().st_size, 'unpackedBytes': size}
    partial.replace(OUTPUT / 'export.tar.zst')
    write_json(OUTPUT / 'ready.json', metadata, owner=ids)
    log('OPTIPLEX STANDBY SNAPSHOT READY: ' + stamp)
    log('One current transfer archive and one incremental source staging copy retained; existing migration exports were not altered.')


def valid_metadata(value, now=None):
    if (value.get('format') != FORMAT or not re.fullmatch('[a-f0-9]{64}', str(value.get('sha256', '')))
        or not re.fullmatch('[0-9]{8}T[0-9]{6}Z', str(value.get('createdUtc', '')))
        or any(type(value.get(key)) is not int or value[key] <= 0 for key in ('archiveBytes', 'unpackedBytes'))):
        raise RuntimeError('The source standby metadata is invalid.')
    created = dt.datetime.strptime(value['createdUtc'], '%Y%m%dT%H%M%SZ').replace(tzinfo=dt.timezone.utc)
    age = (now or dt.datetime.now(dt.timezone.utc)) - created
    return -dt.timedelta(minutes=5) <= age <= dt.timedelta(hours=6)


def prune_snapshots(root, current):
    finished = []
    for path in root.iterdir():
        if path.is_symlink() or not path.is_dir() or not re.fullmatch('[0-9]{8}T[0-9]{6}Z', path.name):
            continue
        marker = path / '_VERIFIED.json'
        if marker.is_file() and json.loads(marker.read_text()).get('format') == FORMAT:
            finished.append(path)
    for path in sorted(finished)[:-2]:
        if path != current:
            shutil.rmtree(path)


def receive_nas(attempt=0):
    stage = module(NAS_HELPER, NAS_SHA, 'standby_nas_stage')
    if not SSD.is_mount() or not stage.KEY.is_file():
        raise RuntimeError('The existing NAS SSD and restricted transfer key are required.')
    for path in NAS_BASE.glob('.extract-*'):
        marker = path / '.standby-temp-owner'
        if (path.is_dir() and not path.is_symlink() and not path.is_mount()
            and marker.is_file() and not marker.is_symlink() and marker.read_text() == FORMAT):
            shutil.rmtree(path)
    known = NAS_BASE / 'known_hosts'; atomic(known, stage.HOST_KEY)
    ssh = stage.ssh_base(known)
    deadline = time.monotonic() + 10800; report = 0
    while True:
        raw = stage.small_read(ssh + ['standby-ready'])
        metadata = json.loads(raw) if raw else None
        if metadata and valid_metadata(metadata):
            break
        status = stage.small_read(ssh + ['standby-status']) or ''
        if 'ActiveState=failed' in status:
            raise RuntimeError('The OptiPlex snapshot failed; its source service journal has the details.')
        if time.monotonic() >= deadline:
            raise RuntimeError('No fresh source snapshot became available within three hours; existing NAS data was retained.')
        if time.monotonic() >= report:
            log('Waiting for a fresh OptiPlex standby snapshot; NAS test applications continue running...'); report=time.monotonic()+60
        time.sleep(15)
    snapshots = NAS_BASE / 'snapshots'
    if snapshots.is_symlink():
        raise RuntimeError('An unexpected symbolic snapshot directory was retained.')
    snapshots.mkdir(mode=0o700, exist_ok=True)
    target = snapshots / metadata['createdUtc']
    if target.is_symlink():
        raise RuntimeError('An unexpected symbolic standby snapshot was retained.')
    if target.exists():
        marker = json.loads((target / '_VERIFIED.json').read_text())
        if marker != metadata:
            raise RuntimeError('A different snapshot occupies the same standby timestamp.')
        write_json(NAS_BASE/'current.json', dict(metadata, snapshot=str(target)))
        partial = NAS_BASE/'export.tar.zst.part'
        if partial.is_file() and not partial.is_symlink() and digest(partial) == metadata['sha256']:
            partial.unlink()
        prune_snapshots(snapshots,target)
        log('The fresh source snapshot is already verified on the NAS.'); return
    if shutil.disk_usage(NAS_BASE).free < metadata['archiveBytes'] + metadata['unpackedBytes'] + 2*1024**3:
        raise RuntimeError('The NAS needs more free SSD space for the fresh standby copy.')
    partial = NAS_BASE / 'export.tar.zst.part'
    if partial.is_symlink():
        raise RuntimeError('An unexpected symbolic transfer file was retained.')
    log('Receiving the current source standby snapshot...')
    with tempfile.TemporaryFile() as errors, partial.open('wb') as output:
        process = subprocess.Popen(ssh + ['standby'], stdout=subprocess.PIPE, stderr=errors)
        received = 0; report = 0
        try:
            for block in iter(lambda: process.stdout.read(4*1024**2), b''):
                if shutil.disk_usage(NAS_BASE).free < 1024**3:
                    raise RuntimeError('Transfer stopped before filling the NAS SSD.')
                output.write(block); received += len(block)
                if time.monotonic() >= report:
                    log('Received ' + str(received//1024**2) + ' MiB...'); report=time.monotonic()+30
            if process.wait(timeout=30):
                raise RuntimeError('The private standby transfer did not complete.')
            output.flush(); os.fsync(output.fileno())
        finally:
            process.stdout.close()
            if process.poll() is None:
                process.terminate(); process.wait(timeout=15)
    if partial.stat().st_size != metadata['archiveBytes'] or digest(partial) != metadata['sha256']:
        raw = stage.small_read(ssh + ['standby-ready'])
        latest = json.loads(raw) if raw else None
        if attempt < 2 and latest and valid_metadata(latest) and latest['sha256'] != metadata['sha256']:
            log('The source published a newer snapshot during transfer; retrying its current archive...')
            return receive_nas(attempt+1)
        raise RuntimeError('The standby transfer did not match its SHA256; existing verified snapshots were retained.')
    unpacked = stage.validate_tar(partial)
    if shutil.disk_usage(NAS_BASE).free < unpacked + 1024**3:
        raise RuntimeError('The NAS needs more free space before unpacking the standby data.')
    with tempfile.TemporaryDirectory(prefix='.extract-', dir=NAS_BASE) as temporary:
        work = Path(temporary)
        atomic(work/'.standby-temp-owner', FORMAT)
        run('tar', '--acls', '--xattrs', '--numeric-owner', '-I', 'zstd', '-xpf', str(partial), '-C', str(work), timeout=7200)
        run('sha256sum', '--quiet', '-c', 'SHA256SUMS', cwd=work, timeout=3600)
        manifest = json.loads((work/'manifest.json').read_text())
        if (manifest.get('format') != FORMAT or manifest.get('scope') != 'standby-only'
            or manifest.get('sourceHost') != '192.168.0.29' or manifest.get('createdUtc') != metadata['createdUtc']
            or {row['Name'].lstrip('/') for row in manifest.get('containers', [])} != set(APP_NAMES)):
            raise RuntimeError('The received standby manifest differs from the reviewed source scope.')
        write_json(work/'_VERIFIED.json', metadata)
        (work/'.standby-temp-owner').unlink()
        work.rename(target)
    write_json(NAS_BASE/'current.json', dict(metadata, snapshot=str(target)))
    partial.unlink(missing_ok=True)
    prune_snapshots(snapshots,target)
    log('NAS STANDBY SNAPSHOT VERIFIED: ' + str(target))
    log('Private cutover copy refreshed. Running NAS appdata, Silo, Google credentials, Plex and NPM were not replaced or started.')


def reader_text(original):
    marker='# '+SIGNATURE
    if marker in original:
        return original
    if not original.startswith('#!/bin/sh\n') or 'SSH_ORIGINAL_COMMAND' not in original:
        raise RuntimeError('The existing restricted transfer reader differs; it was retained.')
    return '#!/bin/sh\n'+f'''{marker}
case "${{SSH_ORIGINAL_COMMAND-}}" in
  standby) exec /bin/cat {OUTPUT}/export.tar.zst ;;
  standby-ready) exec /bin/cat {OUTPUT}/ready.json ;;
  standby-status) exec /bin/systemctl show --no-pager nas-migration-standby.service -p ActiveState -p SubState -p Result ;;
esac
'''+original.split('\n',1)[1]


def unit_texts(role):
    source=role=='source'
    dependencies='docker.service nas-migration-standby-resume.service' if source else 'network-online.target'
    main=f'''# {SIGNATURE}
[Unit]
Description=Refresh private migration standby snapshot ({role})
Requires={dependencies}
After=network-online.target {dependencies}
RequiresMountsFor={'/mnt/media /mnt/usenet_scratch' if source else str(SSD)}
[Service]
Type=oneshot
UMask=0077
ExecStart={WORKER} {'snapshot' if source else 'receive'}
{f'ExecStopPost={WORKER} resume-source' if source else ''}
TimeoutStartSec=6h
TimeoutStopSec=8min
Nice=10
IOSchedulingClass=idle
'''
    result={'nas-migration-standby.service':main,'nas-migration-standby.timer':f'''# {SIGNATURE}
[Unit]
Description=Nightly private migration standby refresh ({role})
[Timer]
OnCalendar=*-*-* {'00:30:00' if source else '01:15:00'} Europe/London
Persistent=true
Unit=nas-migration-standby.service
[Install]
WantedBy=timers.target
'''}
    if source:
        result['nas-migration-standby-resume.service']=f'''# {SIGNATURE}
[Unit]
Description=Restore OptiPlex apps interrupted by standby snapshot
Requires=docker.service
After=docker.service network-online.target
StartLimitIntervalSec=0
[Service]
Type=oneshot
RemainAfterExit=yes
UMask=0077
ExecStart={WORKER} resume-source
Restart=on-failure
RestartSec=30s
TimeoutStartSec=8min
[Install]
WantedBy=multi-user.target
'''
    return result


def install(source):
    helper=module(SOURCE_HELPER,SOURCE_SHA,'standby_install_source') if ROLE=='source' else module(NAS_HELPER,NAS_SHA,'standby_install_nas')
    for executable in ('rsync','zstd','tar','sha256sum','ssh'):
        if not shutil.which(executable):
            raise RuntimeError('A required existing standby tool is unavailable: '+executable)
    if ROLE=='source':
        helper.check_authorization()
        data_roots(inspect_source())
        for path in (OUTPUT,):
            if path.is_symlink():
                raise RuntimeError('An unexpected symbolic source output directory was retained.')
            path.mkdir(mode=0o700,exist_ok=True)
        account=pwd.getpwnam('sawdoctor'); os.chown(OUTPUT,account.pw_uid,account.pw_gid); OUTPUT.chmod(0o700)
        text=READER.read_text(); updated=reader_text(text)
        saved=BASE/'reader.before'
        if not saved.exists():atomic(saved,text)
        atomic(READER,updated,READER.stat().st_mode&0o777)
    elif not SSD.is_mount() or not helper.KEY.is_file():
        raise RuntimeError('The existing NAS SSD and transfer key are required.')
    for name,text in unit_texts(ROLE).items():
        path=UNITS/name
        if path.is_symlink() or (path.exists() and SIGNATURE not in path.read_text()):
            raise RuntimeError('An unrelated standby systemd unit was retained.')
        atomic(path,text,0o644)
    run('systemctl','daemon-reload')
    if ROLE=='source':run('systemctl','enable','--now','nas-migration-standby-resume.service')
    run('systemctl','enable','--now','nas-migration-standby.timer')
    run('systemctl','start','--no-block','nas-migration-standby.service')
    log('NIGHTLY STANDBY REFRESH INSTALLED ON '+('OPTIPLEX' if ROLE=='source' else 'NAS')+'.')
    log('Source 00:30; NAS receiver 01:15 UK time. Initial refresh started in systemd; closing SSH is safe.')
    log('Watch: sudo journalctl -u nas-migration-standby.service -n 20 --no-pager -o cat')


def main():
    global ROLE,BASE
    os.umask(0o077)
    if os.geteuid()!=0:raise RuntimeError('Run with sudo on the OptiPlex or NAS.')
    addresses=run('ip','-4','addr','show')
    source='inet 192.168.0.29/' in addresses; nas='inet 192.168.0.220/' in addresses
    if source==nas:raise RuntimeError('The known OptiPlex or NAS LAN address is required.')
    ROLE='source' if source else 'nas'; BASE=SOURCE_BASE if source else NAS_BASE
    if ROLE=='nas' and not SSD.is_mount():raise RuntimeError('The NAS SSD must be mounted.')
    if BASE.is_symlink():raise RuntimeError('An unexpected symbolic standby state directory was retained.')
    BASE.mkdir(parents=True,mode=0o700,exist_ok=True)
    arguments=sys.argv[1:]
    if arguments==['resume-source']:
        if ROLE!='source':raise RuntimeError('Source recovery is OptiPlex-only.')
        source_resume(); return
    if arguments in (['snapshot'],['receive']):
        if arguments!=(['snapshot'] if source else ['receive']):raise RuntimeError('This standby operation belongs on the other host.')
        with (BASE/'.run.lock').open('a') as lock:
            try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:log('The standby operation is already running.');return
            snapshot_source() if source else receive_nas()
        return
    if arguments==['install']:
        install(Path(__file__).read_text());return
    if arguments:raise RuntimeError('Unknown standby operation.')
    if run('systemctl','is-active','nas-migration-standby-install.service',allowed=(0,3,4)).strip() in ('active','activating'):
        log('Standby installation is already running.');return
    code=globals().get('INSTALL_SOURCE')
    if code is None and '__file__' in globals():code=Path(__file__).read_text()
    if not code:raise RuntimeError('Use the complete provided installer command.')
    if WORKER.is_symlink() or (WORKER.exists() and SIGNATURE not in WORKER.read_text()):
        raise RuntimeError('An unrelated standby worker was retained.')
    atomic(WORKER,code,0o700)
    run('systemctl','reset-failed','nas-migration-standby-install.service',allowed=(0,1))
    run('systemd-run','--unit=nas-migration-standby-install','--collect','--description=Install private nightly migration standby refresh',
        '/usr/bin/python3','-u',str(WORKER),'install')
    log('Standby installation started on '+('OptiPlex' if source else 'NAS')+'. Closing SSH will not stop it.')
    log('Check: sudo journalctl -u nas-migration-standby-install.service -n 20 --no-pager -o cat')


if __name__=='__main__':
    try:main()
    except RuntimeError as error:raise SystemExit('STOP: '+str(error))
    except Exception as error:raise SystemExit('STOP: Standby refresh could not finish ('+type(error).__name__+'); private details were withheld.')
