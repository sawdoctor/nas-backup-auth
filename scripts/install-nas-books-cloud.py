#!/usr/bin/env python3
"""Install the four copied NAS book mounts without changing the backup login."""
import configparser
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import sqlite3
import subprocess
import tempfile
import urllib.parse

SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
SCRATCH = Path('/srv/dev-disk-by-uuid-1f12a22e-5cfe-4b02-8d4b-48e9bf5fec6a')
BINARY = Path('/usr/local/libexec/infinidysk-rclone')
HELPER = Path('/usr/local/sbin/nas-books-cloud-helper')
UNITS = Path('/etc/systemd/system')
LOCK = Path('/run/lock/sawdoctor-nas-backup.lock')
BACKUP_CONFIG = Path('/root/.config/rclone/rclone.conf')
SIGNATURE = 'Sawdoctor NAS books cloud mounts v1'
MOUNTS = {
    'gdrive-audiobooks': {'remote': 'gdrive:Soundspan-Audiobooks', 'target': '/mnt/gdrive-audiobooks', 'readOnly': True},
    'gdrive-ebooks': {'remote': 'gdrive:ABS-Ebooks', 'target': '/mnt/media/ebooks', 'readOnly': False},
    'gdrive-torbox-archive': {'remote': 'gdrive:Shelfmark-TorBox-Archive', 'target': '/mnt/gdrive-torbox-archive', 'readOnly': True},
    'torbox-audiobooks': {'remote': 'torbox-audiobooks:', 'target': '/mnt/torbox-audiobooks', 'readOnly': True},
}

HELPER_SOURCE = r'''#!/usr/bin/env python3
# Sawdoctor NAS books cloud mounts v1
import fcntl
import json
from pathlib import Path
import subprocess
import sys

def run(*args, capture=False):
    return subprocess.run(args, check=True, text=True,
        stdout=subprocess.PIPE if capture else None).stdout

try:
    document = json.loads(Path('__DOCUMENT__').read_text())
    if document.get('format') != 'Sawdoctor NAS books cloud mounts v1':
        raise RuntimeError('Unrecognized NAS cloud mount definition.')
    mode, name = sys.argv[1:3]
    spec = document['mounts'][name]
    target = Path(spec['target'])
    if target.is_symlink() or not target.is_dir():
        raise RuntimeError('The NAS cloud mount path is not a real directory.')
    if mode in ('prepare', 'cleanup'):
        found = subprocess.run(['findmnt', '-n', '--mountpoint', str(target), '-o', 'FSTYPE,SOURCE'],
            text=True, stdout=subprocess.PIPE)
        if found.returncode == 0:
            if found.stdout.split() != ['fuse.rclone', spec['remote']]:
                raise RuntimeError('An unrelated filesystem occupies the cloud mount path.')
            run('__FUSERMOUNT__', '-uz', str(target))
        elif mode == 'prepare' and any(target.iterdir()):
            raise RuntimeError('The unmounted NAS cloud directory contains local files.')
    elif mode == 'refresh':
        with open('__LOCK__', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            ids = run('docker', 'ps', '-q', capture=True).split()
            containers = json.loads(run('docker', 'inspect', *ids, capture=True)) if ids else []
            for container in containers:
                depends = any(Path(m['Source']) == target or target in Path(m['Source']).parents
                    for m in container.get('Mounts', []))
                if depends:
                    current = json.loads(run('docker', 'inspect', container['Id'], capture=True))[0]
                    if current['State']['Running']:
                        run('docker', 'restart', container['Id'])
    else:
        raise RuntimeError('Unknown NAS cloud mount operation.')
except Exception as error:
    raise SystemExit('NAS book mount helper: ' + str(error))
'''


def log(value):
    print(value, flush=True)


def run(*args, capture=False):
    return subprocess.run(args, check=True, text=True,
        stdout=subprocess.PIPE if capture else None).stdout


def atomic_text(path, text, mode=0o600):
    fd, temporary = tempfile.mkstemp(prefix='.books-cloud-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(text);stream.flush();os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def mount_info(target):
    result = subprocess.run(['findmnt', '-n', '--mountpoint', str(target), '-o', 'FSTYPE,SOURCE'],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    return result.stdout.split() if result.returncode == 0 else None


def create_mount_directory(target):
    missing = []
    current = target
    while not current.exists():
        missing.append(current)
        current = current.parent
    for path in reversed(missing):
        path.mkdir(mode=0o755)
        path.chmod(0o755)


def copied_config(snapshot, manifest):
    matches = [item for item in manifest['hostFiles']
        if item['source'] == '/home/sawdoctor/.config/rclone/rclone.conf']
    if len(matches) != 1:
        raise RuntimeError('The copied user media configuration could not be identified.')
    path = snapshot / matches[0]['snapshot']
    if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != matches[0]['sha256']:
        raise RuntimeError('The copied media configuration failed its checksum.')
    source = configparser.ConfigParser(interpolation=None)
    try:
        source.read_string(path.read_text())
    except (configparser.Error, UnicodeError):
        raise RuntimeError('The copied media configuration is not readable INI; no credentials were printed.') from None
    result = configparser.ConfigParser(interpolation=None)
    for remote, kind in (('gdrive', 'drive'), ('torbox-audiobooks', 'webdav')):
        if source.get(remote, 'type', fallback='') != kind:
            raise RuntimeError('Unexpected copied remote type for ' + remote + '.')
        result[remote] = dict(source.items(remote))
    output = io.StringIO();result.write(output)
    return output.getvalue()


def use_nas_drive_auth(media_path):
    """Reuse the authorised NAS client in a separate media config file."""
    media = configparser.ConfigParser(interpolation=None)
    backup = configparser.ConfigParser(interpolation=None)
    try:
        media.read_string(media_path.read_text())
        backup.read_string(BACKUP_CONFIG.read_text())
    except (configparser.Error, UnicodeError):
        raise RuntimeError('Could not read the private NAS Drive configurations; no credentials were printed.') from None
    if backup.get('gdrive', 'type', fallback='') != 'drive':
        raise RuntimeError('The existing NAS backup Drive remote was not found.')
    client_id = backup.get('gdrive', 'client_id', fallback='').strip()
    client_secret = backup.get('gdrive', 'client_secret', fallback='').strip()
    token = backup.get('gdrive', 'token', fallback='').strip()
    try:
        valid_refresh = bool(json.loads(token).get('refresh_token'))
    except (ValueError, AttributeError):
        valid_refresh = False
    if not client_id or not client_secret or not valid_refresh:
        raise RuntimeError('The existing NAS backup configuration lacks its custom Drive client or refresh token.')
    if (media.get('gdrive', 'client_id', fallback='').strip() == client_id
        and media.get('gdrive', 'client_secret', fallback='').strip() == client_secret):
        # Each rclone process can refresh its access token. Do not replace a
        # working media token every time the installer is rerun.
        try:
            if json.loads(media.get('gdrive', 'token', fallback='')).get('refresh_token'):
                return False
        except (ValueError, AttributeError):
            pass
    for key, value in (('client_id', client_id), ('client_secret', client_secret), ('token', token)):
        media.set('gdrive', key, value)
    output = io.StringIO();media.write(output)
    atomic_text(media_path, output.getvalue())
    return True


def mount_command(name, spec, original, config, cache):
    argv = original.get('RuntimeCommand', [])
    if len(argv) < 4 or Path(argv[0]).name != 'rclone' or argv[1:4] != ['mount', spec['remote'], spec['target']]:
        raise RuntimeError('Unexpected copied mount command for ' + name + '.')
    if ('--read-only' in argv[4:]) != spec['readOnly']:
        raise RuntimeError('The copied mount access mode differs for ' + name + '.')
    replaced = {'--config', '--cache-dir', '--log-file', '--uid', '--gid', '--umask'}
    command = [str(BINARY), 'mount', spec['remote'], spec['target']]
    position = 4
    while position < len(argv):
        item = argv[position]
        if item.split('=', 1)[0] in replaced:
            position += 1 if '=' in item else 2
        else:
            command.append(item);position += 1
    command.extend(['--config=' + str(config), '--cache-dir=' + str(cache),
        '--log-file=' + str(cache / 'rclone.log'), '--uid=1000', '--gid=1000', '--umask=002'])
    return command


def environment_file(values):
    lines = []
    for key, value in sorted(values.items()):
        if not re.fullmatch('RCLONE_[A-Z0-9_]+', key) or '\0' in value:
            raise RuntimeError('Unexpected copied rclone environment entry.')
        lines.append(key + '="' + value.replace('\\', '\\\\').replace('"', '\\"') + '"')
    return '\n'.join(lines) + '\n'


def unit_text(name, command, environment):
    command_text = shlex.join(command).replace('%', '%%').replace('$', '$$')
    return f'''# {SIGNATURE}
[Unit]
Description=NAS books cloud mount: {name}
Wants=network-online.target
Requires=docker.service
After=network-online.target docker.service
RequiresMountsFor={SSD} {SCRATCH}
StartLimitIntervalSec=0
[Service]
Type=notify
User=root
UMask=0077
EnvironmentFile={environment}
ExecStartPre={HELPER} prepare {name}
ExecStart={command_text}
ExecStartPost={HELPER} refresh {name}
ExecStopPost={HELPER} cleanup {name}
Restart=on-failure
RestartSec=30
TimeoutStartSec=3min
TimeoutStopSec=45s
[Install]
WantedBy=multi-user.target
'''


def routing_report(snapshot, manifest):
    local_hosts = {'localhost', '127.0.0.1', '192.168.0.29', '192.168.0.220',
        'sonarr', 'radarr', 'radarr4k', 'prowlarr', 'nzbdav', 'usenet-ultimate'}
    local_hosts.update(c['Name'].lstrip('/') for c in manifest['containers'])

    def origins(text):
        found = set()
        for value in re.findall(r'https?://[^\s\"\'<>\\]+', text):
            try:
                url = urllib.parse.urlsplit(value)
                host = url.hostname or ''
                if host in local_hosts or host.endswith('.sawdoctor.uk'):
                    found.add(host + (':' + str(url.port) if url.port else ''))
            except ValueError:
                pass
        return ', '.join(sorted(found))

    log('\nBook application routing inventory (credentials hidden):')
    for container in manifest['containers']:
        name = container['Name'].lstrip('/')
        log(name + ': ' + container['Config']['Image'])
        bindings = container['HostConfig'].get('PortBindings') or {}
        log('  ports: ' + (', '.join(str(item['HostPort']) + ' -> ' + inside
            for inside, items in bindings.items() for item in items or []) or container['HostConfig'].get('NetworkMode', 'none')))
        log('  image ports: ' + ', '.join((container['Config'].get('ExposedPorts') or {}).keys()))
        command = (container['Config'].get('Entrypoint') or []) + (container['Config'].get('Cmd') or [])
        for position, argument in enumerate(command):
            value = command[position + 1] if argument in ('--port', '-p') and position + 1 < len(command) else argument.removeprefix('--port=') if argument.startswith('--port=') else ''
            if value.isdigit():
                log('  command port: ' + value)
        for item in container['Config'].get('Env', []):
            key, _, value = item.partition('=')
            if re.search('pass|secret|token|key|credential', key, re.I) or not re.search('url|host|endpoint|port|server', key, re.I):
                continue
            if '://' in value:
                try:
                    url = urllib.parse.urlsplit(value)
                    origin = (url.hostname or '') + (':' + str(url.port) if url.port else '')
                    log('  ' + key + '=' + origin)
                except ValueError:
                    log('  ' + key + '=<endpoint captured privately>')
            elif re.fullmatch(r'[A-Za-z0-9_.:,/ -]{1,120}', value):
                log('  ' + key + '=' + value)
    log('\nConfiguration file and database schema inventory:')
    for label, spec in manifest['dataRoots'].items():
        if label in ('stable-playback-namespace', 'playback-overrides', 'virtual-audiobooks'):
            continue
        root = snapshot / spec['snapshot']
        reported = 0
        for folder, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [d for d in dirs if d not in ('node_modules', '.git', '__pycache__', 'metadata', 'audiobooks', 'podcasts', 'rclone-cache', 'rclone-archive-cache')]
            for filename in files:
                path = Path(folder) / filename
                if path.is_symlink() or path.suffix.lower() not in ('.json', '.ini', '.conf', '.xml', '.yaml', '.yml', '.db', '.sqlite', '.sqlite3'):
                    continue
                if reported >= 8:
                    continue
                log('  ' + label + '/' + str(path.relative_to(root)))
                reported += 1
                if path.suffix.lower() in ('.json', '.ini', '.conf', '.xml', '.yaml', '.yml') and path.stat().st_size < 2 * 1024**2:
                    destinations = origins(path.read_text(errors='replace'))
                    if destinations:
                        log('    local connection hosts: ' + destinations)
                if path.suffix.lower() in ('.db', '.sqlite', '.sqlite3'):
                    try:
                        with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as connection:
                            tables = [r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")]
                            log('    tables: ' + ', '.join(tables[:20]))
                            for table in tables:
                                if not re.search('config|setting|integration|preference|provider|server|client', table, re.I):
                                    continue
                                quoted = '"' + table.replace('"', '""') + '"'
                                found = set()
                                for row in connection.execute('SELECT * FROM ' + quoted + ' LIMIT 250'):
                                    for value in row:
                                        if isinstance(value, str):
                                            result = origins(value)
                                            if result:
                                                found.add(result)
                                if found:
                                    log('    ' + table + ' connection hosts: ' + ', '.join(sorted(found)))
                    except sqlite3.Error:
                        log('    database schema unavailable; data retained')


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show', capture=True):
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220.')
    if not SSD.is_mount() or not SCRATCH.is_mount():
        raise RuntimeError('The Docker SSD and scratch NVMe must be mounted.')
    snapshot = SSD / 'migration/books-optiplex/snapshot'
    manifest = json.loads((snapshot / 'manifest.json').read_text())
    if manifest.get('format') != 'sawdoctor-books-export-v1' or manifest.get('sourceHost') != '192.168.0.29':
        raise RuntimeError('The verified books snapshot was not found.')
    if not BINARY.is_file() or run(str(BINARY), 'version', capture=True).splitlines()[0] != 'rclone v1.74.3':
        raise RuntimeError('The existing dedicated media rclone v1.74.3 is required.')
    fusermount = shutil.which('fusermount3')
    if not fusermount:
        raise RuntimeError('The existing FUSE3 unmount tool was not found.')
    data = SSD / 'appdata/books-cloud'
    cache_root = SCRATCH / 'scratch/books-cloud'
    marker_path, config = data / 'install.json', data / 'rclone.conf'
    document_path = data / 'mounts.json'
    marker = json.loads(marker_path.read_text()) if marker_path.is_file() else None
    if marker and marker.get('format') != SIGNATURE:
        raise RuntimeError('An unrelated cloud mount installation already exists.')
    if data.exists() and any(data.iterdir()) and not marker:
        raise RuntimeError('Existing book cloud data has no migration marker; it was retained.')
    for path in (data, cache_root, config, marker_path, document_path, BINARY, HELPER):
        if path.is_symlink():
            raise RuntimeError('Unexpected symlink at a NAS book mount installation path.')
    if HELPER.exists() and SIGNATURE not in HELPER.read_text():
        raise RuntimeError('An unrelated mount helper already exists.')
    prepared = copied_config(snapshot, manifest)
    plans = []
    for name, spec in MOUNTS.items():
        target = Path(spec['target'])
        if target.is_symlink() or any(parent.is_symlink() for parent in target.parents):
            raise RuntimeError('Unexpected symlink at a cloud mount path.')
        unit = UNITS / ('nas-rclone-' + name + '.service')
        if unit.is_symlink() or (unit.exists() and SIGNATURE not in unit.read_text()):
            raise RuntimeError('An unrelated cloud mount unit already exists.')
        mounted = mount_info(target)
        if mounted:
            if mounted != ['fuse.rclone', spec['remote']] or not marker or not unit.exists():
                raise RuntimeError('An unrelated filesystem already occupies ' + str(target))
        elif target.exists() and (not target.is_dir() or any(target.iterdir())):
            raise RuntimeError('Local files already occupy ' + str(target) + '; they were retained.')
        original = manifest['hostUnits']['rclone-' + name + '.service']
        cache = cache_root / name
        command = mount_command(name, spec, original, config, cache)
        values = dict(original.get('RcloneEnvironment', {}))
        if name.startswith('gdrive-'):
            for key in ('RCLONE_CONFIG_GDRIVE_CLIENT_ID', 'RCLONE_CONFIG_GDRIVE_CLIENT_SECRET',
                'RCLONE_CONFIG_GDRIVE_TOKEN', 'RCLONE_DRIVE_CLIENT_ID', 'RCLONE_DRIVE_CLIENT_SECRET', 'RCLONE_DRIVE_TOKEN'):
                values.pop(key, None)
        plans.append((name, spec, target, unit, cache, command, values))
    log('Preparing separate NAS media credentials and scratch caches...')
    with open(LOCK, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        data.mkdir(parents=True, mode=0o700, exist_ok=True)
        cache_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        (data / 'environment').mkdir(mode=0o700, exist_ok=True)
        if not marker:
            marker = {'format': SIGNATURE, 'sourceCreatedUtc': manifest['createdUtc'], 'completed': False}
            atomic_text(marker_path, json.dumps(marker, indent=2) + '\n')
        if not config.exists():
            atomic_text(config, prepared)
        auth_changed = use_nas_drive_auth(config)
        log('Book media uses the existing authorised NAS Google client in its separate configuration.')
        atomic_text(document_path, json.dumps({'format': SIGNATURE, 'mounts': MOUNTS}, indent=2) + '\n')
        helper = HELPER_SOURCE.replace('__DOCUMENT__', str(document_path)).replace('__FUSERMOUNT__', fusermount).replace('__LOCK__', str(LOCK))
        atomic_text(HELPER, helper, 0o755)
    # Network calls and the service refresh helpers must not hold the backup lock.
    for name, spec, target, unit, cache, command, values in plans:
        log('Checking cloud directory access: ' + name + '...')
        environment = dict(os.environ, **values)
        result = subprocess.run([str(BINARY), '--config', str(config), '--contimeout', '10s',
            '--timeout', '25s', '--retries', '1', '--low-level-retries', '1', '--tpslimit', '2',
            'lsf', spec['remote'], '--dirs-only', '--max-depth', '1'], env=environment,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
        if result.returncode:
            atomic_text(data / 'preflight-error.log', result.stderr)
            raise RuntimeError('The private cloud access check failed for ' + name + '; details saved privately on the NAS.')
        log(name + ': cloud access verified')
    changes = {}
    with open(LOCK, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        for name, spec, target, unit, cache, command, values in plans:
            create_mount_directory(target)
            cache.mkdir(parents=True, mode=0o700, exist_ok=True)
            environment = data / 'environment' / (name + '.env')
            env_text = environment_file(values)
            environment_changed = not environment.exists() or environment.read_text() != env_text
            atomic_text(environment, env_text)
            text = unit_text(name, command, environment)
            changes[name] = (not unit.exists() or unit.read_text() != text or environment_changed
                or (auth_changed and name.startswith('gdrive-')))
            atomic_text(unit, text, 0o644)
        run('systemctl', 'daemon-reload')
        run('systemctl', 'enable', *(unit.name for _, _, _, unit, _, _, _ in plans))
    for name, spec, target, unit, cache, command, values in plans:
        active = subprocess.run(['systemctl', 'is-active', '--quiet', unit.name]).returncode == 0
        if not active or changes[name]:
            log('Starting NAS cloud mount: ' + name + '...')
            run('systemctl', 'restart' if active else 'start', unit.name)
        if mount_info(target) != ['fuse.rclone', spec['remote']]:
            raise RuntimeError('The cloud mount did not retain its expected identity: ' + name)
        log(str(target) + ': ready (' + ('read-only' if spec['readOnly'] else 'read/write') + ')')
    marker['completed'] = True
    marker['driveClient'] = 'Existing NAS custom client; separate media configuration'
    atomic_text(marker_path, json.dumps(marker, indent=2) + '\n')
    (data / 'preflight-error.log').unlink(missing_ok=True)
    log('\nNAS BOOK CLOUD MOUNTS READY. The NAS backup login and existing media stack were retained.')
    log('Book applications have not been deployed yet. The following inventory is for their NAS connections.')
    routing_report(snapshot, manifest)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit('\nInterrupted. Existing NAS configuration was retained; rerun to continue.')
    except Exception as error:
        raise SystemExit('STOP: ' + str(error))
