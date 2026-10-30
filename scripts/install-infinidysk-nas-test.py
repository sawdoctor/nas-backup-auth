#!/usr/bin/env python3
"""Create Sawdoctor's LAN-only InfiniDysk test from the verified OptiPlex snapshot."""
import copy
import fcntl
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
SCRATCH = Path('/srv/dev-disk-by-uuid-1f12a22e-5cfe-4b02-8d4b-48e9bf5fec6a')
IMAGE = 'ghcr.io/infinidysk/infinidysk@sha256:8552ebcafb25f9a1e4c8e8f01341f685c45062655db7108e0d2386329b452f76'
MARKER = 'sawdoctor-infinidysk-nas-test-v1'


def run(*args, capture=False):
    return subprocess.run(args, check=True, text=True,
                          stdout=subprocess.PIPE if capture else None).stdout


def original_environment(container):
    return dict(item.split('=', 1) for item in container['Config'].get('Env', []) if '=' in item)


def build_environment(container, settings):
    env = original_environment(container)
    provider_text = env.get('NZBDAV_CONFIG__USENET__PROVIDERS') or settings.get('usenet.providers', '{"Providers":[]}')
    providers = json.loads(provider_text)
    if not isinstance(providers, dict) or not isinstance(providers.get('Providers'), list):
        raise RuntimeError('Unexpected provider configuration; the snapshot was not changed.')
    disabled = copy.deepcopy(providers)
    for provider in disabled['Providers']:
        provider['Type'] = 0
    api_key = (env.get('NZBDAV_CONFIG__API__KEY') or settings.get('api.key')
               or env.get('FRONTEND_BACKEND_API_KEY'))
    if not api_key:
        raise RuntimeError('No existing frontend/backend API key was found.')
    if env.get('DATABASE_PROVIDER', '').lower() not in ('', 'sqlite'):
        raise RuntimeError('This installer expects the existing SQLite installation.')
    for key in list(env):
        if key.startswith('DATABASE_') or key.startswith('POSTGRES_'):
            del env[key]
    env.update({
        'PUID': env.get('PUID', '1000'), 'PGID': env.get('PGID', '1000'),
        'TZ': 'Europe/London', 'CONFIG_PATH': '/config', 'PORT': '3000',
        'BACKEND_URL': 'http://localhost:8080', 'SECURE_COOKIES': 'false',
        'FRONTEND_BACKEND_API_KEY': api_key,
        'NZBDAV_CONFIG__API__KEY': api_key,
        'NZBDAV_CONFIG__QUEUE__PAUSED': 'true',
        'NZBDAV_CONFIG__ARR__INSTANCES': '{"RadarrInstances":[],"SonarrInstances":[],"QueueRules":[]}',
        'NZBDAV_CONFIG__ARR__HEALTH_ENABLED': 'false',
        'NZBDAV_CONFIG__PROWLARR__SYNC_ENABLED': 'false',
        'NZBDAV_CONFIG__REPAIR__ENABLE': 'false',
        'NZBDAV_CONFIG__MAINTENANCE__REMOVE_ORPHANED_SCHEDULE_ENABLED': 'false',
        'NZBDAV_CONFIG__WATCHTOWER__ENABLED': 'false',
        'NZBDAV_CONFIG__PLAY__WATCHDOG_ENABLED': 'false',
        'NZBDAV_CONFIG__BACKUP__SCHEDULE_ENABLED': 'false',
        'NZBDAV_CONFIG__USENET__WARM_CONNECTIONS__ENABLED': 'false',
        'NZBDAV_CONFIG__USENET__PROVIDERS': json.dumps(disabled, separators=(',', ':')),
        'NZBDAV_CONFIG__GENERAL__BASE_URL': 'http://192.168.0.220:8081',
        'NZBDAV_CONFIG__MEDIA__LIBRARY_DIR': '/mnt/media',
        'NZBDAV_CONFIG__RCLONE__MOUNT_DIR': '/mnt/nzbdav',
        'NZBDAV_CONFIG__RCLONE__RC_ENABLED': 'false',
        'TMPDIR': '/scratch/tmp', 'TMP': '/scratch/tmp', 'TEMP': '/scratch/tmp',
    })
    return env, providers['Providers']


def compose_document(env, data, scratch):
    # Compose interpolates dollar signs even in JSON strings; $$ preserves the value.
    env = {key: value.replace('$', '$$') for key, value in env.items()}
    def bind(source, destination, readonly=False):
        return {'type': 'bind', 'source': str(source), 'target': destination,
                'read_only': readonly, 'bind': {'create_host_path': False}}
    return {'name': 'infinidysk-nas', 'services': {'infinidysk': {
        'image': IMAGE, 'container_name': 'infinidysk-nas', 'restart': 'unless-stopped',
        'ports': ['192.168.0.220:8081:3000', '192.168.0.220:8082:8080'],
        'environment': env,
        'volumes': [bind(data / 'config', '/config'),
                    bind(data / 'library', '/mnt/media', True),
                    bind(data / 'mount-empty', '/mnt/nzbdav', True),
                    bind(scratch, '/scratch')],
        'healthcheck': {'test': ['CMD-SHELL', 'curl -fsS http://localhost:3000/healthz >/dev/null && curl -fsS http://localhost:8080/health >/dev/null'],
                        'interval': '15s', 'timeout': '5s', 'retries': 6, 'start_period': '60s'},
        'logging': {'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '3'}},
    }}}


def disable_warden_backup(path):
    if not path.exists():
        return
    connection = sqlite3.connect(path)
    try:
        exists = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='warden_backup'").fetchone()
        if exists:
            connection.execute("UPDATE warden_backup SET v='false' WHERE k='enabled'")
            connection.commit()
    finally:
        connection.close()


def main():
    os.umask(0o077)
    if os.geteuid() != 0:
        raise RuntimeError('Run this with sudo on the NAS.')
    if 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show', capture=True):
        raise RuntimeError('Run this on the NAS at 192.168.0.220.')
    for path in (SSD, SCRATCH):
        if not path.is_mount():
            raise RuntimeError('Required SSD or scratch NVMe is not mounted: ' + str(path))
    snapshot = SSD / 'migration/infinidysk-optiplex/snapshot'
    manifest = json.loads((snapshot / 'manifest.json').read_text())
    if (manifest.get('format') != 'sawdoctor-infinidysk-export-v1'
            or manifest.get('sourceHost') != '192.168.0.29' or manifest.get('image') != IMAGE):
        raise RuntimeError('The snapshot does not match the verified OptiPlex export.')
    source = json.loads((snapshot / 'container.json').read_text())[0]
    mounts = {x['Destination']: x['Source'] for x in source['Mounts']}
    if (mounts.get('/config') != '/home/sawdoctor/docker/nzbdav/nzbdav-config'
            or mounts.get('/mnt/media') != '/mnt/media' or mounts.get('/mnt/nzbdav') != '/mnt/nzbdav'):
        raise RuntimeError('The snapshot has unexpected container mounts.')
    image = json.loads(run('docker', 'image', 'inspect', IMAGE, capture=True))[0]
    if IMAGE not in (image.get('RepoDigests') or []):
        raise RuntimeError('The exact production image is not present on this NAS.')
    run('docker', 'compose', 'version')
    data = SSD / 'appdata/infinidysk-nas'
    stack = SSD / 'compose/infinidysk-nas'
    scratch = SCRATCH / 'scratch/infinidysk-nas'
    for path in (data, stack, scratch):
        if path.is_symlink():
            raise RuntimeError('Refusing to use a symlink as a new installation directory.')
    lock = open('/run/lock/sawdoctor-nas-backup.lock', 'a')
    print('Waiting for the current NAS backup/upload to release its lock...', flush=True)
    deadline = time.monotonic() + 600
    while True:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except BlockingIOError:
            if time.monotonic() > deadline:
                raise RuntimeError('The backup is still busy. Rerun this installer once it finishes.') from None
            time.sleep(2)
    marker = data / 'nas-test-install.json'
    if data.exists():
        if not marker.is_file() or json.loads(marker.read_text()).get('format') != MARKER:
            raise RuntimeError('InfiniDysk appdata already exists without this installer marker; leaving it unchanged.')
        if not (stack / 'compose.json').is_file():
            raise RuntimeError('A previous install needs review; its Compose file is missing.')
    else:
        if stack.exists() and any(stack.iterdir()):
            raise RuntimeError('The stack directory is already in use; leaving it unchanged.')
        ids = run('docker', 'ps', '-aq', capture=True).split()
        containers = json.loads(run('docker', 'inspect', *ids, capture=True)) if ids else []
        for container in containers:
            if container['Name'] == '/infinidysk-nas':
                raise RuntimeError('A container named infinidysk-nas already exists.')
            for bindings in (container['HostConfig'].get('PortBindings') or {}).values():
                if any(binding.get('HostPort') in ('8081', '8082') for binding in bindings or []):
                    raise RuntimeError('Docker already reserves port 8081 or 8082.')
        for port in (8081, 8082):
            with socket.socket() as listener:
                listener.bind(('192.168.0.220', port))
        database = snapshot / 'config/db.sqlite'
        connection = sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)
        try:
            settings = dict(connection.execute('SELECT ConfigName, ConfigValue FROM ConfigItems'))
        finally:
            connection.close()
        env, providers = build_environment(source, settings)
        uid, gid = int(env['PUID']), int(env['PGID'])
        if data.parent.is_symlink() or stack.parent.is_symlink():
            raise RuntimeError('Unexpected appdata or Compose parent path.')
        data.parent.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix='.infinidysk-nas-', dir=data.parent))
        try:
            print('Copying the verified configuration and library links into NAS appdata...', flush=True)
            for name in ('config', 'library'):
                if (snapshot / name).is_symlink():
                    raise RuntimeError('The snapshot contains an unexpected root symlink.')
                run('cp', '-a', '--', str(snapshot / name), str(work / name))
            (work / 'mount-empty').mkdir(mode=0o755)
            disable_warden_backup(work / 'config/warden.db')
            (work / 'nas-test-install.json').write_text(json.dumps({
                'format': MARKER, 'sourceCreatedUtc': manifest['createdUtc'], 'image': IMAGE,
                'state': 'LAN GUI only; providers disabled; queue and repairs paused; rclone mount pending',
            }, indent=2) + '\n')
            scratch.mkdir(parents=True, exist_ok=True)
            (scratch / 'tmp').mkdir(mode=0o755, exist_ok=True)
            scratch.chmod(0o755)
            os.chown(scratch, uid, gid)
            os.chown(scratch / 'tmp', uid, gid)
            stack.mkdir(parents=True, exist_ok=True)
            compose = stack / 'compose.json'
            compose.write_text(json.dumps(compose_document(env, data, scratch), indent=2) + '\n')
            compose.chmod(0o600)
            os.replace(work, data)
            print(f'Copied {len(providers)} provider settings; all NAS providers are initially disabled.', flush=True)
        finally:
            if work.exists():
                shutil.rmtree(work)
    command = ['docker', 'compose', '-f', str(stack / 'compose.json')]
    # Config validation output contains resolved credentials: discard it.
    run(*command, 'config', '--quiet')
    print('Starting InfiniDysk NAS test...', flush=True)
    run(*command, 'up', '-d', '--pull', 'never')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for attempt in range(60):
        state = json.loads(run('docker', 'inspect', 'infinidysk-nas', capture=True))[0]['State']
        if state.get('Status') in ('exited', 'dead'):
            raise RuntimeError('The NAS container exited. Read: sudo docker logs --tail 60 infinidysk-nas')
        try:
            with opener.open('http://192.168.0.220:8081/healthz', timeout=2) as response:
                healthy = response.status == 200
            with opener.open('http://192.168.0.220:8082/health', timeout=2) as response:
                healthy = healthy and response.status == 200
            if healthy:
                print('\nINFINIDYSK NAS TEST READY: http://192.168.0.220:8081')
                print('Use your existing InfiniDysk login. The container should now appear in Dockmon.')
                print('Queue, Arr connections, repairs and NAS provider connections are disabled for initial login.')
                print('Playback awaits the NAS rclone mount and a provider connection budget.')
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(2)
    raise RuntimeError('The container is running but startup has not passed both health checks. Read: sudo docker logs --tail 60 infinidysk-nas')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit('\nInterrupted. Rerun to continue; the OptiPlex was not changed.')
    except Exception as error:
        raise SystemExit('STOP: ' + str(error))
