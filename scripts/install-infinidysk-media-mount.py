#!/usr/bin/env python3
"""Install Sawdoctor's NAS-only, read-only InfiniDysk media mount."""
import configparser
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time
import urllib.parse

SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
SCRATCH = Path('/srv/dev-disk-by-uuid-1f12a22e-5cfe-4b02-8d4b-48e9bf5fec6a')
MOUNT = Path('/mnt/nzbdav')
SERVICE = 'nas-infinidysk-rclone.service'
SIGNATURE = 'Sawdoctor NAS InfiniDysk media mount v1'
HELPER = Path('/usr/local/sbin/nas-infinidysk-media-helper')
BINARY = Path('/usr/local/libexec/infinidysk-rclone')

HELPER_SOURCE = r'''#!/usr/bin/env python3
# Sawdoctor NAS InfiniDysk media mount v1
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

MOUNT = '/mnt/nzbdav'
STACK = '__STACK__'

def run(*args, capture=False):
    return subprocess.run(args, check=True, text=True,
        stdout=subprocess.PIPE if capture else None).stdout

def cleanup():
    result = subprocess.run(['findmnt', '-n', '--mountpoint', MOUNT,
        '-o', 'FSTYPE,SOURCE'], text=True, stdout=subprocess.PIPE)
    if result.returncode != 0:
        return
    fields = result.stdout.split()
    if fields != ['fuse.rclone', 'nzbdav:']:
        raise RuntimeError('An unrelated filesystem occupies /mnt/nzbdav; leaving it mounted.')
    run('__FUSERMOUNT__', '-uz', MOUNT)

def healthy():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for path in ('http://192.168.0.220:8081/healthz', 'http://192.168.0.220:8082/health'):
        with opener.open(path, timeout=2) as response:
            if response.status != 200:
                return False
    return True

def wait_backend():
    print('Waiting for the NAS InfiniDysk frontend and backend...', flush=True)
    for attempt in range(90):
        try:
            if healthy():
                return
        except OSError:
            pass
        time.sleep(2)
    raise RuntimeError('NAS InfiniDysk is not ready; no stopped container was started.')

def refresh_consumers():
    # Prevent a container restart during the coordinated cold application backup.
    with open('/run/lock/sawdoctor-nas-backup.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        ids = run('docker', 'ps', '-q', capture=True).split()
        containers = json.loads(run('docker', 'inspect', *ids, capture=True)) if ids else []
        names = {c['Name']: c for c in containers}
        if '/infinidysk-nas' not in names:
            raise RuntimeError('NAS InfiniDysk was stopped; leaving it stopped.')
        others = [c['Id'] for c in containers if c['Name'] != '/infinidysk-nas'
            and any(m['Source'] == MOUNT for m in c['Mounts'])]
        print('Rebinding the NAS InfiniDysk container to the live media mount...', flush=True)
        run('docker', 'compose', '-f', STACK, 'up', '-d', '--pull', 'never',
            '--force-recreate', 'infinidysk')
        wait_backend()
        for container_id in others:
            current = json.loads(run('docker', 'inspect', container_id, capture=True))[0]
            if current['State']['Running']:
                run('docker', 'restart', container_id)
        print('NAS media mount and running container bindings are ready.', flush=True)

try:
    mode = sys.argv[1]
    if mode == 'prepare':
        wait_backend()
        cleanup()
    elif mode == 'refresh':
        refresh_consumers()
    elif mode == 'cleanup':
        cleanup()
    else:
        raise RuntimeError('Unknown media helper operation.')
except Exception as error:
    raise SystemExit('NAS media helper: ' + str(error))
'''


def run(*args, capture=False):
    return subprocess.run(args, check=True, text=True,
                          stdout=subprocess.PIPE if capture else None).stdout


def file_hash(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            result.update(block)
    return result.hexdigest()


def atomic_text(path, text, mode=0o600):
    fd, temporary = tempfile.mkstemp(prefix='.nas-media-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def make_remote(source, credentials=None):
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(source)
    if cfg.sections() != ['nzbdav'] or cfg.get('nzbdav', 'type', fallback='') != 'webdav':
        raise RuntimeError('Expected the copied nzbdav WebDAV remote only.')
    original = urllib.parse.urlsplit(cfg.get('nzbdav', 'url'))
    if original.scheme not in ('http', 'https') or original.username or original.password:
        raise RuntimeError('Unexpected original WebDAV URL; leaving it unchanged.')
    cfg.set('nzbdav', 'url', original._replace(scheme='http',
        netloc='192.168.0.220:8082', fragment='').geturl())
    if credentials is not None:
        user, password = credentials
        # A single-remote `config show nzbdav` masks pass as *** ENCRYPTED ***.
        # Configure a separate NAS WebDAV login instead of copying that placeholder.
        # Pass the actual password through stdin, never command arguments or logs.
        result = subprocess.run([str(BINARY), 'obscure', '-'],
            input=password + '\n', text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=30)
        if result.returncode != 0 or not result.stdout.strip():
            raise RuntimeError('Could not prepare the private NAS WebDAV password.')
        cfg.set('nzbdav', 'user', user)
        cfg.set('nzbdav', 'pass', result.stdout.strip())
        # The new NAS login uses Basic authentication rather than a copied token.
        cfg.remove_option('nzbdav', 'bearer_token')
        cfg.remove_option('nzbdav', 'bearer_token_command')
    elif cfg.get('nzbdav', 'pass', fallback='') == '*** ENCRYPTED ***':
        raise RuntimeError('The exported WebDAV password is a display placeholder.')
    output = io.StringIO()
    cfg.write(output)
    return output.getvalue()


def unit_text(config, cache, uid, gid):
    command = [str(BINARY), 'mount', 'nzbdav:', str(MOUNT),
        '--config=' + str(config), '--cache-dir=' + str(cache),
        '--allow-other', '--links', '--use-cookies', '--read-only',
        '--vfs-cache-mode=full', '--vfs-cache-max-size=50G', '--vfs-cache-max-age=24h',
        '--buffer-size=0M', '--vfs-read-ahead=512M', '--dir-cache-time=20s',
        '--uid=' + str(uid), '--gid=' + str(gid)]
    return f'''# {SIGNATURE}
[Unit]
Description=NAS InfiniDysk read-only media mount
Wants=network-online.target
Requires=docker.service
After=network-online.target docker.service
RequiresMountsFor={SSD} {SCRATCH}
StartLimitIntervalSec=0

[Service]
Type=notify
User=root
UMask=0077
ExecStartPre={HELPER} prepare
ExecStart={' '.join(command)}
ExecStartPost={HELPER} refresh
ExecStopPost={HELPER} cleanup
Restart=on-failure
RestartSec=30
TimeoutStartSec=15min
TimeoutStopSec=45s

[Install]
WantedBy=multi-user.target
'''


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show', capture=True):
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220.')
    if not SSD.is_mount() or not SCRATCH.is_mount():
        raise RuntimeError('The Docker SSD and scratch NVMe must both be mounted.')
    fusermount = shutil.which('fusermount3')
    if not fusermount:
        raise RuntimeError('fusermount3 is missing; install the fuse3 package first.')
    snapshot = SSD / 'migration/infinidysk-optiplex/snapshot'
    data = SSD / 'appdata/infinidysk-nas'
    stack = SSD / 'compose/infinidysk-nas/compose.json'
    cache = SCRATCH / 'scratch/infinidysk-nas/rclone-cache'
    config = data / 'media-rclone.conf'
    marker = json.loads((data / 'nas-test-install.json').read_text())
    if marker.get('format') != 'sawdoctor-infinidysk-nas-test-v1':
        raise RuntimeError('The NAS InfiniDysk installation marker is missing.')
    document = json.loads(stack.read_text())
    service = document['services']['infinidysk']
    if service['container_name'] != 'infinidysk-nas':
        raise RuntimeError('Unexpected Compose service; leaving it unchanged.')
    # This phase only mounts metadata. Keep acquisition/repair and all providers disabled.
    providers = json.loads(service['environment']['NZBDAV_CONFIG__USENET__PROVIDERS'].replace('$$', '$'))
    if any(p['Type'] != 0 for p in providers['Providers']):
        raise RuntimeError('NAS providers have been enabled. Review the test setup before proceeding.')
    binary_source = snapshot / 'tools/rclone'
    expected = None
    for line in (snapshot / 'SHA256SUMS').read_text().splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[1].strip().lstrip('*') == './tools/rclone':
            expected = parts[0]
    if not expected or file_hash(binary_source) != expected:
        raise RuntimeError('The copied rclone binary failed its export checksum.')
    for path in (BINARY, HELPER, config, stack, cache, MOUNT):
        if path.is_symlink():
            raise RuntimeError('Unexpected symlink at an installation path: ' + str(path))
    unit = Path('/etc/systemd/system') / SERVICE
    for path in (unit, HELPER):
        if path.exists() and SIGNATURE not in path.read_text():
            raise RuntimeError('An unrelated file already exists: ' + str(path))
    if BINARY.exists() and file_hash(BINARY) != expected:
        raise RuntimeError('The dedicated media rclone binary differs; leaving it unchanged.')
    mounted = subprocess.run(['findmnt', '-n', '--mountpoint', str(MOUNT), '-o', 'FSTYPE,SOURCE'],
                             text=True, stdout=subprocess.PIPE)
    if mounted.returncode == 0:
        if mounted.stdout.split() != ['fuse.rclone', 'nzbdav:'] or not unit.exists():
            raise RuntimeError('An unrelated mount already occupies /mnt/nzbdav.')
    elif MOUNT.exists() and (not MOUNT.is_dir() or any(MOUNT.iterdir())):
        raise RuntimeError('/mnt/nzbdav already contains files; leaving it unchanged.')
    print('Preparing the dedicated media rclone binary and NAS WebDAV configuration...', flush=True)
    with open('/run/lock/sawdoctor-nas-backup.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        BINARY.parent.mkdir(parents=True, exist_ok=True)
        if not BINARY.exists():
            shutil.copy2(binary_source, BINARY)
            BINARY.chmod(0o755)
        version = run(str(BINARY), 'version', capture=True).splitlines()[0]
        if version != 'rclone v1.74.3':
            raise RuntimeError('The exported media binary is not the expected rclone v1.74.3.')
        print('Media mount binary: ' + version, flush=True)
        environment = service['environment']
        password_key = 'NZBDAV_CONFIG__WEBDAV__PASS'
        user_key = 'NZBDAV_CONFIG__WEBDAV__USER'
        password = environment.get(password_key, '').replace('$$', '$')
        user = environment.get(user_key, '').replace('$$', '$')
        if not password or not user:
            login_backup = stack.parent / 'compose.before-media-login.json'
            if not login_backup.exists():
                atomic_text(login_backup, stack.read_text())
            user, password = 'nas-media', secrets.token_urlsafe(32)
            # InfiniDysk's documented headless WebDAV PASS accepts plaintext and
            # hashes it in memory. The persisted clone database is left unchanged.
            environment[user_key] = user
            environment[password_key] = password.replace('$', '$$')
        remote = make_remote(snapshot / 'rclone.conf', (user, password))
        atomic_text(stack, json.dumps(document, indent=2) + '\n')
        atomic_text(config, remote)
        print('Applying the private NAS WebDAV login and waiting for the NAS container...', flush=True)
        run('docker', 'compose', '-f', str(stack), 'config', '--quiet')
        run('docker', 'compose', '-f', str(stack), 'up', '-d', '--pull', 'never',
            '--wait', '--wait-timeout', '180', 'infinidysk')
        print('Checking NAS WebDAV login using a directory listing...', flush=True)
        directories = run(str(BINARY), '--config', str(config), '--contimeout', '10s',
            '--timeout', '30s', '--retries', '2', 'lsf', 'nzbdav:', '--dirs-only', '--max-depth', '1', capture=True)
        if not directories.strip():
            raise RuntimeError('The NAS WebDAV root returned no directories.')
        cache.mkdir(parents=True, exist_ok=True)
        MOUNT.mkdir(mode=0o755, exist_ok=True)
        matches = [m for m in service['volumes'] if m.get('target') == '/mnt/nzbdav']
        if len(matches) != 1 or matches[0]['source'] not in (str(data / 'mount-empty'), str(MOUNT)):
            raise RuntimeError('Unexpected InfiniDysk media mount in Compose.')
        if not (stack.parent / 'compose.before-media-mount.json').exists():
            shutil.copy2(stack, stack.parent / 'compose.before-media-mount.json')
        matches[0]['source'] = str(MOUNT)
        matches[0]['read_only'] = True
        matches[0]['bind'] = {'create_host_path': False}
        atomic_text(stack, json.dumps(document, indent=2) + '\n')
        helper = HELPER_SOURCE.replace('__STACK__', str(stack)).replace('__FUSERMOUNT__', fusermount)
        atomic_text(HELPER, helper, 0o755)
        uid = int(service['environment'].get('PUID', '1000'))
        gid = int(service['environment'].get('PGID', '1000'))
        atomic_text(unit, unit_text(config, cache, uid, gid), 0o644)
        run('docker', 'compose', '-f', str(stack), 'config', '--quiet')
        run('systemctl', 'daemon-reload')
        run('systemctl', 'enable', SERVICE)
    # The service's container-refresh helper takes this same backup lock.
    # Release it before starting the unit to avoid a startup deadlock.
    print('Starting the NAS mount and refreshing its NAS container binding...', flush=True)
    run('systemctl', 'restart', SERVICE)
    run('findmnt', '--mountpoint', str(MOUNT), '-o', 'TARGET,SOURCE,FSTYPE')
    if not MOUNT.is_mount():
        raise RuntimeError('The media mount did not become active.')
    marker['mediaMount'] = {'service': SERVICE, 'path': str(MOUNT), 'readOnly': True,
                            'cache': str(cache), 'rcloneVersion': '1.74.3'}
    marker['state'] = 'NAS media mount configured; providers disabled; downloads and repairs paused'
    atomic_text(data / 'nas-test-install.json', json.dumps(marker, indent=2) + '\n')
    print('\nNAS MEDIA MOUNT READY. Existing library links now point at this NAS WebDAV mount.')
    print('Providers remain disabled. Next: allocate provider connections, then test one file.')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit('\nInterrupted. Rerun to continue; the OptiPlex was not changed.')
    except Exception as error:
        raise SystemExit('STOP: ' + str(error))
