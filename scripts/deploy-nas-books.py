#!/usr/bin/env python3
"""Sawdoctor NAS books deployment v1: restore verified book apps on NAS mounts."""
import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
SCRATCH = Path('/srv/dev-disk-by-uuid-1f12a22e-5cfe-4b02-8d4b-48e9bf5fec6a')
DATA = SSD / 'appdata/books-nas'
STACK = SSD / 'compose/books-nas'
SNAPSHOT = SSD / 'migration/books-optiplex/snapshot'
WORKER = Path('/usr/local/sbin/nas-books-deploy.py')
UNIT = Path('/etc/systemd/system/nas-books.service')
LOCK = Path('/run/lock/sawdoctor-nas-backup.lock')
SIGNATURE = 'Sawdoctor NAS books deployment v1'
PROJECT = 'books-nas'
CORE_SHA = '8ebc4f735c61c5f0ea29c509b1bd6279efc05741675ad4e7370ee3b39c71065e'
APPS = {
    'abr-shelfmark-bridge': (None, 8090, 'Audiobook bridge'),
    'audiobookrequest': (8085, 8000, 'AudioBookRequest'),
    'audiobookshelf-test': (13378, 80, 'Audiobookshelf'),
    'kavita': (5000, 5000, 'Kavita'),
    'sabnzbd-ebooks': (8087, 8080, 'SABnzbd ebooks'),
    'shelfmark-ebooks': (8086, 8084, 'Shelfmark ebooks'),
    'shelfmark-torbox': (8084, 8084, 'Shelfmark audiobooks'),
    'stackarr-ebooks': (8484, 8484, 'Stackarr'),
}
MOUNTS = {
    '/mnt/gdrive-audiobooks': 'gdrive:Soundspan-Audiobooks',
    '/mnt/media/ebooks': 'gdrive:ABS-Ebooks',
    '/mnt/gdrive-torbox-archive': 'gdrive:Shelfmark-TorBox-Archive',
    '/mnt/torbox-audiobooks': 'torbox-audiobooks:',
    '/mnt/nzbdav': 'nzbdav:',
}
MOUNT_UNITS = ['nas-rclone-' + name + '.service' for name in
    ('gdrive-audiobooks', 'gdrive-ebooks', 'gdrive-torbox-archive', 'torbox-audiobooks')]
MOUNT_UNITS.append('nas-infinidysk-rclone.service')
HOST_PORTS = {host: (name, internal) for name, (host, internal, _) in APPS.items() if host}
HOST_PORTS.update({9696: ('prowlarr', 9696), 8082: ('nzbdav', 8080),
    8081: ('infinidysk-nas', 3000), 8989: ('sonarr', 8989), 7878: ('radarr', 7878),
    7879: ('radarr4k', 7878), 1337: ('usenet-ultimate', 1337), 5055: ('overseerr', 5055)})


def log(value):
    print(value, flush=True)


def run(*args, capture=False, **kwargs):
    return subprocess.run(args, check=True, text=True,
        stdout=subprocess.PIPE if capture else None, **kwargs).stdout


def atomic_text(path, text, mode=0o600):
    original = path.stat() if path.exists() else None
    fd, temporary = tempfile.mkstemp(prefix='.nas-books-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(text); stream.flush(); os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        if original:
            os.chown(temporary, original.st_uid, original.st_gid)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_json(path, value):
    atomic_text(path, json.dumps(value, indent=2) + '\n')


def core_helpers():
    path = Path('/usr/local/sbin/nas-core-deploy.py')
    if hashlib.sha256(path.read_bytes()).hexdigest() != CORE_SHA:
        raise RuntimeError('The installed core image-verification helper is not the tested version.')
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('nas_core_images', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def guard():
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show', capture=True):
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220.')
    if not SSD.is_mount() or not SCRATCH.is_mount():
        raise RuntimeError('The NAS application SSD and scratch NVMe must be mounted.')


def check_mounts():
    for target, remote in MOUNTS.items():
        if run('findmnt', '-n', '--mountpoint', target, '-o', 'FSTYPE,SOURCE', capture=True).split() != ['fuse.rclone', remote]:
            raise RuntimeError('The NAS cloud mount is not ready: ' + target)


def source_mapping(source, manifest, data):
    path = Path(source)
    roots = sorted(manifest['dataRoots'].items(), key=lambda item: len(item[1]['source']), reverse=True)
    for label, details in roots:
        root = Path(details['source'])
        if path.is_relative_to(root):
            relative = path.relative_to(root)
            if '..' in relative.parts or '/' in label or label in ('', '.', '..'):
                raise RuntimeError('Unexpected source data mapping.')
            return (SNAPSHOT / details['snapshot'] / relative, data / label / relative)
    for cloud in sorted(MOUNTS, key=len, reverse=True):
        if path == Path(cloud) or Path(cloud) in path.parents:
            return None, path
    raise RuntimeError('An unrecognized book data binding needs review: ' + source)


def rewrite_url(value, browser=False):
    if not isinstance(value, str):
        return value
    # Preserve Plex/Jellyfin production URLs and every secret; rewrite only
    # observed local book/core service endpoints, including embedded JSON URLs.
    pattern = r'(?<![A-Za-z0-9_.])(?P<scheme>https?://)?(?P<host>192\.168\.0\.29|127\.0\.0\.1|localhost|172\.30\.0\.1):(?P<port>[0-9]+)(?![0-9])'
    def replace(match):
        host, port = match['host'], int(match['port'])
        if port == 8090 and host in ('172.30.0.1', '127.0.0.1', 'localhost'):
            name, internal = 'abr-shelfmark-bridge', 8090
        elif port in HOST_PORTS and host != '172.30.0.1':
            name, internal = HOST_PORTS[port]
        else:
            return match[0]
        if browser:
            return (match['scheme'] or '') + '192.168.0.220:' + str(port)
        return 'http://' + name + ':' + str(internal)
    return re.sub(pattern, replace, value)


def rewrite_tree(value, key=''):
    # Kavita stores enum setting keys as SQLite integers. Normalize the key
    # for routing classification without changing stored keys or value types.
    key = '' if key is None else str(key)
    if isinstance(value, dict):
        return {name: rewrite_tree(item, str(name)) for name, item in value.items()}
    if isinstance(value, list):
        return [rewrite_tree(item, key) for item in value]
    if isinstance(value, str):
        # These values appear in browser links rather than server-side requests.
        browser = bool(re.search(r'public|external|applicationurl|app_url|baseurl|base_url', key, re.I))
        if key.lower() == 'abs_base_url':
            browser = False
        if re.search(r'password|secret|token|api.?key', key, re.I):
            return value
        return rewrite_url(value, browser)
    return value


def copy_runtime_data(containers, manifest, work):
    copies = {}
    for name, container in containers.items():
        for mount in container['Mounts']:
            if mount['Type'] != 'bind':
                raise RuntimeError('An unexpected named volume was found for ' + name + '.')
            source, target = source_mapping(mount['Source'], manifest, work)
            if source is not None:
                copies[str(target)] = source
    # Copy parents once. Absolute links are retained without traversing cloud data.
    parents = []
    for target in sorted(map(Path, copies), key=lambda path: len(path.parts)):
        if any(parent in target.parents for parent in parents):
            continue
        source = copies[str(target)]
        if source.is_symlink() or not source.exists():
            raise RuntimeError('A runtime binding is missing or unexpectedly symbolic: ' + str(source.relative_to(SNAPSHOT)))
        if not source.resolve().is_relative_to(SNAPSHOT.resolve()):
            raise RuntimeError('A runtime source escapes the verified snapshot.')
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        run('cp', '-a', '--', str(source), str(target))
        parents.append(target)
    # Make organizational parents traversable for UID 1000 containers; copied
    # application directories/files retain their original owners and modes.
    work.chmod(0o755)
    for label in manifest['dataRoots']:
        path = work / label
        if path.exists() and path not in parents:
            path.chmod(0o755)
    return copies


def qname(name):
    return '"' + name.replace('"', '""') + '"'


def patch_settings_db(path, abr=False):
    connection = sqlite3.connect(path)
    try:
        if connection.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
            raise RuntimeError('A copied configuration database did not pass its integrity check.')
        tables = {row[0].lower(): row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for key in ('config', 'meta', 'settings', 'serversetting', 'user_settings'):
            if key not in tables:
                continue
            table = tables[key]
            columns = [row[1] for row in connection.execute('PRAGMA table_info(' + qname(table) + ')')]
            key_column = next((name for name in columns if name.lower() in ('key', 'name')), None)
            value_columns = [name for name in columns if name.lower() in ('value', 'data', 'settings')]
            for column in value_columns:
                query = 'SELECT rowid,' + (qname(key_column) if key_column else "''") + ',' + qname(column) + ' FROM ' + qname(table)
                for rowid, setting, value in connection.execute(query).fetchall():
                    new = rewrite_tree(value, setting or '')
                    if new != value:
                        connection.execute('UPDATE ' + qname(table) + ' SET ' + qname(column) + '=? WHERE rowid=?', (new, rowid))
        if abr:
            table = tables.get('config')
            if not table:
                raise RuntimeError('The copied AudioBookRequest configuration table is missing.')
            for key, value in (('abs_base_url', 'http://audiobookshelf-test:80'),
                               ('prowlarr_base_url', 'http://prowlarr:9696')):
                connection.execute('UPDATE ' + qname(table) + ' SET value=? WHERE key=? AND value<>?', (value, key, ''))
            connection.execute('INSERT INTO ' + qname(table) + '(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', ('quality_auto_download', '0'))
            table = tables.get('notification')
            if table:
                for rowid, url in connection.execute('SELECT rowid,url FROM ' + qname(table)).fetchall():
                    new = rewrite_url(url)
                    if 'abr-shelfmark-bridge:' in new:
                        connection.execute('UPDATE ' + qname(table) + ' SET url=? WHERE rowid=?', (new, rowid))
                    else:
                        connection.execute('UPDATE ' + qname(table) + ' SET enabled=0 WHERE rowid=?', (rowid,))
        connection.commit()
        if connection.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
            raise RuntimeError('A rewritten book configuration database failed its integrity check.')
    finally:
        connection.close()


def patch_sab(path):
    # ConfigObj uses nested [[server]] sections; edit only the top-level misc
    # host settings rather than reparsing the file with incompatible ConfigParser.
    lines = path.read_text().splitlines()
    result, in_misc, saw_host = [], False, False
    for line in lines:
        stripped = line.strip()
        if re.fullmatch(r'\[[^\[\]]+\]', stripped):
            in_misc = stripped.lower() == '[misc]'
        if in_misc and re.match(r'\s*host\s*=', line):
            line = 'host = 0.0.0.0'; saw_host = True
        if in_misc and re.match(r'\s*host_whitelist\s*=', line):
            prior = line.split('=', 1)[1].strip()
            line = 'host_whitelist = ' + prior + (', ' if prior else '') + 'sabnzbd-ebooks, sabnzbd-ebooks-nas, 192.168.0.220'
        result.append(line)
    if not saw_host:
        raise RuntimeError('The copied SABnzbd misc host setting was not found.')
    atomic_text(path, '\n'.join(result) + '\n', path.stat().st_mode & 0o777)


def patch_runtime(containers, manifest, work):
    config_roots = []
    for name, container in containers.items():
        for mount in container['Mounts']:
            if mount['Destination'] not in ('/config', '/kavita/config', '/data'):
                continue
            _, target = source_mapping(mount['Source'], manifest, work)
            config_roots.append((name, target))
    for name, root in config_roots:
        for path in sorted(root.rglob('*.json')):
            if path.is_symlink() or any(part in ('cache', 'cache-long', 'covers', 'backups') for part in path.relative_to(root).parts):
                continue
            if path.stat().st_size > 8 * 1024**2:
                continue
            try:
                original = json.loads(path.read_text())
            except (ValueError, UnicodeError):
                continue
            updated = rewrite_tree(original)
            if updated != original:
                atomic_text(path, json.dumps(updated, indent=2) + '\n', path.stat().st_mode & 0o777)
        databases = {'audiobookrequest': ['db.sqlite'], 'kavita': ['kavita.db'],
            'stackarr-ebooks': ['stackarr.db'], 'shelfmark-ebooks': ['users.db'], 'shelfmark-torbox': ['users.db']}
        for filename in databases.get(name, []):
            patch_settings_db(root / filename, abr=name == 'audiobookrequest')
        if name == 'sabnzbd-ebooks':
            patch_sab(root / 'sabnzbd.ini')
    # Custom hooks may contain hard-coded URLs. Change only known local endpoints
    # in mounted Python/shell hooks, retaining their permissions and secrets.
    for name, container in containers.items():
        for mount in container['Mounts']:
            if mount['Destination'].startswith(('/custom-scripts', '/app/shelfmark/download/clients/')):
                _, target = source_mapping(mount['Source'], manifest, work)
                files = target.rglob('*') if target.is_dir() else [target]
                for path in files:
                    if path.is_symlink() or not path.is_file() or path.suffix not in ('.py', '.sh'):
                        continue
                    text = path.read_text()
                    updated = rewrite_url(text)
                    if updated != text:
                        atomic_text(path, updated, path.stat().st_mode & 0o777)


def compose_document(containers, manifest, resolved):
    document = {'name': PROJECT, 'x-sawdoctor-managed': SIGNATURE,
        'networks': {'media-core': {'external': True, 'name': 'media-core'}}, 'services': {}}
    for name, source in containers.items():
        config = source['Config']
        environment = dict(item.split('=', 1) for item in config.get('Env', []) if '=' in item)
        environment = rewrite_tree(environment)
        if name == 'abr-shelfmark-bridge':
            environment.update({'SHELFMARK_URL': 'http://shelfmark-torbox:8084', 'ABR_URL': 'http://audiobookrequest:8000'})
        if name == 'stackarr-ebooks':
            environment.update({'SHELFMARK_EBOOK_URL': 'http://shelfmark-ebooks:8084',
                'SHELFMARK_AUDIOBOOK_URL': 'http://shelfmark-torbox:8084',
                'AUDIOBOOK_BRIDGE_URL': 'http://abr-shelfmark-bridge:8090', 'ABS_URL': 'http://audiobookshelf-test:80'})
        if name == 'shelfmark-ebooks':
            environment.update({'PROWLARR_URL': 'http://prowlarr:9696', 'SABNZBD_URL': 'http://sabnzbd-ebooks:8080'})
        volumes = []
        for mount in source['Mounts']:
            _, target = source_mapping(mount['Source'], manifest, DATA)
            volumes.append({'type': 'bind', 'source': str(target), 'target': mount['Destination'],
                'read_only': not mount['RW'], 'bind': {'create_host_path': False}})
        service = {'image': resolved[name], 'container_name': name + '-nas', 'pull_policy': 'never',
            'restart': 'on-failure:5', 'environment': {key: value.replace('$', '$$') for key, value in environment.items()},
            'networks': {'media-core': {'aliases': [name]}}, 'volumes': volumes,
            'logging': {'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '3'}}}
        for source_key, target_key in (('Cmd', 'command'), ('Entrypoint', 'entrypoint')):
            if config.get(source_key) is not None:
                service[target_key] = [rewrite_url(item).replace('$', '$$') for item in config[source_key]]
        if config.get('User'):
            service['user'] = config['User']
        if config.get('WorkingDir'):
            service['working_dir'] = config['WorkingDir']
        host, internal, _ = APPS[name]
        if host:
            service['ports'] = ['192.168.0.220:' + str(host) + ':' + str(internal)]
        document['services'][name] = service
    return document


def check_ports(existing):
    own = {name + '-nas' for name in APPS}
    target_ports = {str(item[0]) for item in APPS.values() if item[0]}
    for container in existing:
        name = container['Name'].lstrip('/')
        if name in own:
            if (container['Config'].get('Labels') or {}).get('com.docker.compose.project') != PROJECT:
                raise RuntimeError('An unrelated container uses a target NAS book name: ' + name)
            continue
        for bindings in (container['HostConfig'].get('PortBindings') or {}).values():
            if any(binding.get('HostPort') in target_ports for binding in bindings or []):
                raise RuntimeError('Another NAS container reserves a book application port: ' + name)
    current = {container['Name'].lstrip('/') for container in existing}
    for name, (host, _, _) in APPS.items():
        if host and name + '-nas' not in current:
            with socket.socket() as listener:
                listener.bind(('192.168.0.220', host))


def unit_text():
    dependencies = ' '.join(['docker.service'] + MOUNT_UNITS)
    return f'''# {SIGNATURE}
[Unit]
Description=NAS book and audiobook applications
Requires={dependencies}
After=network-online.target {dependencies}
PartOf=docker.service
RequiresMountsFor={SSD} {SCRATCH}
[Service]
Type=oneshot
RemainAfterExit=yes
UMask=0077
ExecStart=/usr/bin/python3 -u {WORKER} start
ExecStop=/usr/bin/python3 -u {WORKER} stop
TimeoutStartSec=8min
TimeoutStopSec=5min
[Install]
WantedBy=multi-user.target
'''


def compose_command(*args):
    return run('docker', 'compose', '-f', str(STACK / 'compose.json'), *args)


def operate(mode):
    with open(LOCK, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        document = json.loads((STACK / 'compose.json').read_text())
        if document.get('x-sawdoctor-managed') != SIGNATURE:
            raise RuntimeError('Unexpected NAS book Compose definition.')
        if mode == 'start':
            check_mounts()
            compose_command('up', '-d', '--pull', 'never', '--wait', '--wait-timeout', '300')
        else:
            compose_command('stop', '--timeout', '45')


def check_http():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    pending = {name for name, details in APPS.items() if details[0]}
    deadline = time.monotonic() + 180
    while pending and time.monotonic() < deadline:
        for name in list(pending):
            host, _, label = APPS[name]
            try:
                request = urllib.request.Request('http://192.168.0.220:' + str(host) + '/')
                try:
                    response = opener.open(request, timeout=2)
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    status = response.code
                    if status < 400 or status in (401, 403):
                        pending.remove(name); log(label + ': HTTP responding (' + str(status) + ')')
            except OSError:
                pass
        if pending:
            time.sleep(2)
    if pending:
        raise RuntimeError('NAS book HTTP readiness failed for: ' + ', '.join(sorted(pending)) + '. Configurations were retained for retry.')


def check_internal():
    # UU is already a verified NAS Node application on the same Docker network.
    # Pass only host/port pairs; no configuration secrets enter journal output.
    tests = [{'name': APPS[name][2], 'host': name, 'port': APPS[name][1]} for name in APPS]
    tests.extend([{'name': 'NAS Prowlarr', 'host': 'prowlarr', 'port': 9696},
        {'name': 'NAS InfiniDysk', 'host': 'nzbdav', 'port': 8080}])
    script = r'''const net=require('net'),fs=require('fs');
(async()=>{let bad=false;for(const t of JSON.parse(fs.readFileSync(0,'utf8'))){
const ok=await new Promise(resolve=>{const s=net.connect({host:t.host,port:t.port});let done=false;
function end(value){if(done)return;done=true;s.destroy();resolve(value);}
s.setTimeout(5000);s.on('connect',()=>end(true));s.on('error',()=>end(false));s.on('timeout',()=>end(false));});
console.log(t.name+': Docker connection '+(ok?'verified':'FAILED'));if(!ok)bad=true;}process.exitCode=bad?1:0;})();'''
    result = subprocess.run(['docker', 'exec', '-i', 'usenet-ultimate-nas', 'node', '-e', script],
        input=json.dumps(tests), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=75)
    log(result.stdout.strip())
    if result.returncode:
        raise RuntimeError('A NAS book Docker connection failed; no credential values were printed.')


def addresses():
    for host, _, label in APPS.values():
        if host:
            log(label + ': http://192.168.0.220:' + str(host))


def install():
    marker_path = DATA / 'install.json'
    for path in (DATA, STACK, WORKER, UNIT):
        if path.is_symlink():
            raise RuntimeError('An unexpected symlink occupies a NAS books installation path.')
    if DATA.exists():
        if not marker_path.is_file() or json.loads(marker_path.read_text()).get('format') != SIGNATURE:
            raise RuntimeError('Existing book appdata has no matching installation marker; it was retained.')
        if json.loads(marker_path.read_text()).get('completed'):
            log('The NAS books installation is already complete. Existing NAS settings were retained.')
            addresses(); return
    for path in (WORKER, UNIT):
        if path.exists() and SIGNATURE not in path.read_text():
            raise RuntimeError('An unrelated NAS deployment file already exists: ' + str(path))
    manifest = json.loads((SNAPSHOT / 'manifest.json').read_text())
    if manifest.get('format') != 'sawdoctor-books-export-v1' or manifest.get('sourceHost') != '192.168.0.29':
        raise RuntimeError('The verified OptiPlex book snapshot was not found.')
    containers = {container['Name'].lstrip('/'): container for container in manifest['containers']}
    if not set(APPS).issubset(containers):
        raise RuntimeError('The book snapshot does not contain all eight requested applications.')
    containers = {name: containers[name] for name in APPS}
    cloud = json.loads((SSD / 'appdata/books-cloud/install.json').read_text())
    if cloud.get('format') != 'Sawdoctor NAS books cloud mounts v1' or not cloud.get('completed'):
        raise RuntimeError('The four NAS book cloud mounts must be configured first.')
    check_mounts()
    ids = run('docker', 'ps', '-aq', capture=True).split()
    existing = json.loads(run('docker', 'inspect', *ids, capture=True)) if ids else []
    check_ports(existing)
    core = core_helpers()
    log('Checking the verified book snapshot and exact image archive...')
    run('sha256sum', '--quiet', '-c', 'SHA256SUMS', cwd=SNAPSHOT)
    log('Waiting for the NAS backup lock...')
    with open(LOCK, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not DATA.exists():
            log('Restoring book configurations, libraries, playback overrides and custom hooks...')
            work = Path(tempfile.mkdtemp(prefix='.books-nas-', dir=DATA.parent))
            try:
                copy_runtime_data(containers, manifest, work)
                patch_runtime(containers, manifest, work)
                write_json(work / 'install.json', {'format': SIGNATURE,
                    'sourceCreatedUtc': manifest['createdUtc'], 'coreHelperSha256': CORE_SHA, 'completed': False})
                os.replace(work, DATA)
            finally:
                if work.exists():
                    shutil.rmtree(work)
        STACK.mkdir(mode=0o700, parents=True, exist_ok=True)
        compose = STACK / 'compose.json'
        if compose.exists() and json.loads(compose.read_text()).get('x-sawdoctor-managed') != SIGNATURE:
            raise RuntimeError('An unrelated books Compose file already exists.')
        resolved = core.load_verified_images(SNAPSHOT, manifest, containers, STACK)
        if not compose.exists():
            write_json(compose, compose_document(containers, manifest, resolved))
        else:
            document = json.loads(compose.read_text())
            for name, image in resolved.items():
                document['services'][name]['image'] = image
            write_json(compose, document)
        for service in json.loads(compose.read_text())['services'].values():
            for mount in service['volumes']:
                if not Path(mount['source']).exists():
                    raise RuntimeError('A required runtime binding is not accessible: ' + mount['target'])
        # The custom bridge is a local build. Keep one recoverable exact image in
        # backed-up appdata instead of depending on a future registry download.
        recovery = DATA / 'recovery'
        recovery.mkdir(mode=0o700, exist_ok=True)
        image_backup = recovery / 'abr-shelfmark-bridge-image.tar'
        if not image_backup.exists():
            temporary = recovery / 'bridge-image.tar.incomplete'
            run('docker', 'image', 'save', '--output', str(temporary), resolved['abr-shelfmark-bridge'])
            temporary.chmod(0o600); os.replace(temporary, image_backup)
        source = globals().get('INSTALL_SOURCE') or Path(__file__).read_text()
        atomic_text(WORKER, source, 0o700)
        atomic_text(UNIT, unit_text(), 0o644)
        compose_command('config', '--quiet')
        run('systemctl', 'daemon-reload')
        run('systemctl', 'enable', 'nas-books.service')
    # Mount refresh helpers acquire the same mutex. Start dependencies only after
    # releasing it, so remounts/boot cannot deadlock against this installer.
    log('Starting eight NAS book applications after their cloud mounts...')
    run('systemctl', 'reset-failed', 'nas-books.service', stderr=subprocess.DEVNULL)
    run('systemctl', 'start', 'nas-books.service')
    check_http()
    check_internal()
    with open(LOCK, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        marker = json.loads(marker_path.read_text()); marker['completed'] = True
        write_json(marker_path, marker)
    log('\nNAS BOOK APPS DEPLOYED. Use the existing logins.')
    log('AudioBookRequest automatic searching and copied external notifications are off for initial testing.')
    log('The OptiPlex was not changed. TorBox Media Center and dormant RDTClient remain staged for their later phase.')
    addresses()


if __name__ == '__main__':
    try:
        os.umask(0o077)
        guard()
        if len(sys.argv) == 2 and sys.argv[1] in ('start', 'stop'):
            operate(sys.argv[1])
        else:
            install()
    except KeyboardInterrupt:
        raise SystemExit('Interrupted. NAS book configurations were retained for retry.')
    except Exception as error:
        raise SystemExit('STOP: ' + str(error))
