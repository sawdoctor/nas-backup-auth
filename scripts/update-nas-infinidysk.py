#!/usr/bin/env python3
"""Back up and update only NAS InfiniDysk to the reviewed stable latest image."""
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import urllib.request
import yaml

SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
APP = SSD / 'appdata/infinidysk-nas'
COMPOSE = SSD / 'appdata/dockmon/stacks/infinidysk-nas/compose.yaml'
LEGACY = SSD / 'compose/infinidysk-nas/compose.json'
RECOVERY = SSD / 'compose/infinidysk-nas/recovery/before-latest'
LOCK = Path('/run/lock/sawdoctor-nas-backup.lock')
IMAGE = 'ghcr.io/infinidysk/infinidysk:latest'
VERSION = '1.7.1'
NAME = 'infinidysk-nas'
SIGNATURE = 'Sawdoctor NAS InfiniDysk latest update v1'
BINARY = '/usr/local/libexec/infinidysk-rclone'


def say(message):
    print(message, flush=True)


def run(*args, timeout=90):
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        if RECOVERY.is_dir():
            atomic(RECOVERY / 'command-error.log', (result.stdout + '\n' + result.stderr).encode())
        elif LEGACY.parent.is_dir():
            atomic(LEGACY.parent / 'latest-update-error.log', (result.stdout + '\n' + result.stderr).encode())
        raise RuntimeError('A NAS InfiniDysk update command failed; available recovery files and private diagnostics were retained.')
    return result.stdout


def atomic(path, data):
    if path.is_symlink():
        raise RuntimeError('An unexpected symbolic update file was retained.')
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
            temporary.chmod(0o600); temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def write_json(path, value):
    atomic(path, (json.dumps(value, indent=2) + '\n').encode())


def inspect(name):
    return json.loads(run('docker', 'inspect', name))[0]


def environment(config):
    return dict(item.split('=', 1) for item in config.get('Env', []) if '=' in item)


def version(image):
    return environment(image['Config']).get('NZBDAV_VERSION', '').removeprefix('v')


def updated_document(document):
    result = copy.deepcopy(document)
    if set(result.get('services', {})) != {'infinidysk'}:
        raise RuntimeError('The imported InfiniDysk stack has unexpected services.')
    service = result['services']['infinidysk']
    if service.get('container_name') != NAME:
        raise RuntimeError('The imported InfiniDysk container name differs.')
    env = service.get('environment', {})
    if not isinstance(env, dict) or str(env.get('DATABASE_PROVIDER', 'sqlite')).lower() not in ('', 'sqlite'):
        raise RuntimeError('This update requires the existing NAS SQLite installation.')
    service['image'] = IMAGE
    service['pull_policy'] = 'missing'
    # Copied image-build metadata must be inherited from the replacement
    # image, rather than overriding its real version with the source version.
    for key in ('NZBDAV_VERSION', 'NZBDAV_COMMIT_SHA'):
        env.pop(key, None)
    return result


def compose(*args, timeout=90):
    return run('docker', 'compose', '-p', NAME, '-f', str(COMPOSE), *args, timeout=timeout)


def wait_ready(expected_image, timeout=300):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            current = inspect(NAME)
            if current['Image'] != expected_image:
                raise RuntimeError('The NAS container did not use the selected image.')
            if current['State']['Running']:
                for port, endpoint in ((8081, '/healthz'), (8082, '/health')):
                    with opener.open('http://192.168.0.220:' + str(port) + endpoint, timeout=3) as response:
                        if response.status != 200:
                            raise OSError('Health endpoint was not ready.')
                return current
        except (OSError, RuntimeError):
            pass
        time.sleep(2)
    raise RuntimeError('NAS InfiniDysk did not become ready within five minutes.')


def verify_media():
    fields = run('findmnt', '-n', '--mountpoint', '/mnt/nzbdav', '-o', 'FSTYPE,SOURCE').split()
    if fields != ['fuse.rclone', 'nzbdav:']:
        raise RuntimeError('The existing NAS rclone mount differs from the working configuration.')
    run(BINARY, '--config', str(APP / 'media-rclone.conf'), '--contimeout', '10s',
        '--timeout', '30s', '--retries', '2', 'lsf', 'nzbdav:', '--dirs-only', '--max-depth', '1', timeout=90)
    contract = APP / 'config/db-contract.json'
    if contract.is_file() and json.loads(contract.read_text()).get('provider') != 'sqlite':
        raise RuntimeError('The NAS database provider differs from the preserved SQLite installation.')


def archive_hash(path):
    checksum = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(4 * 1024**2), b''):
            checksum.update(block)
    return checksum.hexdigest()


def rollback(original, image_id, config_saved):
    say('Update verification failed. Restoring the pre-update NAS configuration and image...')
    existing = run('docker', 'ps', '-aq', '--filter', 'name=^/' + NAME + '$').split()
    if existing:
        if inspect(NAME)['State']['Running']:
            run('docker', 'stop', '--timeout', '60', NAME, timeout=90)
        if inspect(NAME)['State']['Running']:
            raise RuntimeError('The new NAS container is still running; the database recovery copy was preserved.')
    if config_saved:
        failed = RECOVERY / 'failed-config'
        if failed.exists():
            raise RuntimeError('An earlier failed configuration was retained; automatic recovery needs review.')
        (APP / 'config').rename(failed)
        run('tar', '--acls', '--xattrs', '--numeric-owner', '-I', 'zstd', '-xpf',
            str(RECOVERY / 'config.tar.zst'), '-C', str(APP), timeout=600)
    atomic(COMPOSE, original)
    compose('up', '-d', '--no-deps', '--pull', 'never', '--force-recreate', 'infinidysk', timeout=180)
    wait_ready(image_id)
    say('The previous NAS InfiniDysk image and configuration are running again. Failed-update data was kept privately.')


def update(original, replacement, current, target):
    original_id = current['Id']; old_image = current['Image']
    atomic(RECOVERY / 'compose.before.yaml', original)
    record = {'format': SIGNATURE, 'phase': 'prepared', 'oldImage': old_image,
              'newImage': target['Id'], 'targetVersion': VERSION}
    write_json(RECOVERY / 'update.json', record)
    stopped = False; changed = False; config_saved = False
    try:
        say('Briefly stopping only NAS InfiniDysk for a complete /config backup, including blobs...')
        stopped = True
        run('docker', 'stop', '--timeout', '60', NAME, timeout=90)
        archive = RECOVERY / 'config.tar.zst'
        run('tar', '--acls', '--xattrs', '--numeric-owner', '--one-file-system',
            '-I', 'zstd -T2 -3', '-cpf', str(archive), '-C', str(APP), 'config', timeout=600)
        run('zstd', '-t', str(archive), timeout=600)
        checksum = archive_hash(archive)
        atomic(RECOVERY / 'SHA256SUMS', (checksum + '  config.tar.zst\n').encode())
        config_saved = True
        atomic(COMPOSE, replacement); changed = True
        record['phase'] = 'updating'; write_json(RECOVERY / 'update.json', record)
        say('Starting NAS InfiniDysk using the reviewed latest image...')
        compose('up', '-d', '--no-deps', '--pull', 'never', 'infinidysk', timeout=180)
        running = wait_ready(target['Id'])
        if environment(running['Config']).get('NZBDAV_VERSION', '').removeprefix('v') != VERSION:
            raise RuntimeError('The running NAS version label differs from the reviewed image.')
        verify_media()
        record['phase'] = 'complete'; record['backupSha256'] = checksum
        write_json(RECOVERY / 'update.json', record)
    except BaseException:
        if changed:
            rollback(original, old_image, config_saved)
            record['phase'] = 'rolled-back'; write_json(RECOVERY / 'update.json', record)
        elif stopped:
            if not inspect(original_id)['State']['Running']:
                run('docker', 'start', original_id, timeout=90)
            wait_ready(old_image)
            record['phase'] = 'backup-interrupted'; write_json(RECOVERY / 'update.json', record)
        raise
    say('NAS INFINIDYSK UPDATED: ' + VERSION + ' using ' + IMAGE)
    say('Frontend/backend health, the existing NAS mount and WebDAV directory access passed.')
    say('SQLite and application settings retained. The editable Dockmon stack now tracks latest; updates stay manual.')
    say('Pre-update /config and Compose recovery copy: ' + str(RECOVERY))
    say('The OptiPlex was not changed. Next: play one existing title in NAS Silo.')


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show') or not SSD.is_mount():
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220 with its application SSD mounted.')
    if COMPOSE.is_symlink() or not COMPOSE.is_file() or not LEGACY.is_symlink() or LEGACY.resolve() != COMPOSE.resolve():
        raise RuntimeError('The editable Dockmon InfiniDysk definition and its compatibility link are required.')
    if (APP / 'config').is_symlink() or not (APP / 'config/db.sqlite').is_file():
        raise RuntimeError('The existing NAS SQLite configuration is required.')
    current = inspect(NAME)
    if not current['State']['Running'] or (current['Config'].get('Labels') or {}).get('com.docker.compose.project') != NAME:
        raise RuntimeError('The running NAS InfiniDysk project must be available.')
    original = COMPOSE.read_bytes(); document = yaml.safe_load(original)
    replacement = yaml.safe_dump(updated_document(document), sort_keys=False, allow_unicode=True).encode()
    old = json.loads(run('docker', 'image', 'inspect', current['Image']))[0]
    if version(old) == VERSION and document['services']['infinidysk'].get('image') == IMAGE and not any(key in document['services']['infinidysk'].get('environment', {}) for key in ('NZBDAV_VERSION', 'NZBDAV_COMMIT_SHA')):
        wait_ready(current['Image']); verify_media()
        say('NAS InfiniDysk already uses the reviewed latest image; health and WebDAV access passed.'); return
    if RECOVERY.exists() or RECOVERY.is_symlink():
        raise RuntimeError('A previous update recovery folder was preserved. Review it before another attempt.')
    say('Pulling the latest image while NAS InfiniDysk continues running...')
    run('docker', 'pull', '--quiet', IMAGE, timeout=600)
    target = json.loads(run('docker', 'image', 'inspect', IMAGE))[0]
    if version(target) != VERSION:
        actual = version(target) or '<version not recorded>'
        raise RuntimeError('The pulled latest image reports ' + repr(actual[:100]) +
                           ', while this update reviewed ' + VERSION + '; the running NAS was retained.')
    say('Reviewed image ready: ' + VERSION + '. Waiting for the NAS backup lock...')
    with LOCK.open('a') as lock:
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB); break
            except BlockingIOError:
                time.sleep(2)
        if COMPOSE.read_bytes() != original or inspect(NAME)['Id'] != current['Id']:
            raise RuntimeError('The NAS stack changed during image preparation; its current state was retained.')
        RECOVERY.mkdir(mode=0o700, parents=True)
        prepared = RECOVERY / 'compose.prepared.yaml'; atomic(prepared, replacement)
        run('docker', 'compose', '-p', NAME, '-f', str(prepared), 'config', '--quiet')
        update(original, replacement, current, target)


if __name__ == '__main__':
    def interrupted(number, _frame):
        raise SystemExit(128 + number)
    for selected in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(selected, interrupted)
    try:
        main()
    except Exception as error:
        raise SystemExit('STOP: ' + (str(error) if isinstance(error, RuntimeError) else
                                   'NAS InfiniDysk update could not finish (' + type(error).__name__ + '); recovery files were retained.'))
