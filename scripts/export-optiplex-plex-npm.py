#!/usr/bin/env python3
"""Consistent, recoverable OptiPlex Plex/NPM snapshot for NAS staging."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import shlex
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request
import xml.etree.ElementTree as ET

SIGNATURE = 'Sawdoctor OptiPlex Plex NPM export v1'
FORMAT = 'sawdoctor-plex-npm-export-v1'
BASE = Path('/var/lib/sawdoctor-nas-plex-npm-export')
OUTPUT = Path('/home/sawdoctor/nas-plex-npm-export')
WORKER = Path('/usr/local/sbin/nas-plex-npm-export')
READER = Path('/usr/local/sbin/nas-migration-export-read')
UNITS = Path('/etc/systemd/system')
STATE = BASE / 'resume.json'
BACKUP_LOCK = Path('/run/lock/plex-daily-backup.lock')
BACKUP_MARKER = Path('/run/plex-daily-backup-active')
BACKUP_TIMER = 'plex-daily-backup.timer'
BACKUP_SERVICE = 'plex-daily-backup.service'
SAFE_START = Path('/usr/local/sbin/plex-safe-start')
BLOB = 'AAAAC3NzaC1lZDI1NTE5AAAAILc56w99kcthdhVVsUuXQxChc1Smtlx6ju+xZPLNIpSE'
IMAGES = {
    'plex': 'sha256:0c2f1122a4275efeea953a9882359f3809b27279d3c3022392e8e610a2eccc67',
    'npm-app-1': 'sha256:4393e642e233e5efd5adeb7f10918d4aaea71c9ed875b94190273fc8e87f9594',
}
ROOTS = {
    'plex-config': '/home/sawdoctor/docker/plex/config',
    'flora-test-library': '/home/sawdoctor/plex2ultimate/flora-test-library',
    'npm-data': '/home/sawdoctor/docker/npm/data',
    'npm-letsencrypt': '/home/sawdoctor/docker/npm/letsencrypt',
}
TARGETS = {
    'plex': {'/config': 'plex-config', '/flora-test-library': 'flora-test-library'},
    'npm-app-1': {'/data': 'npm-data', '/etc/letsencrypt': 'npm-letsencrypt'},
}
PLEX_DB = Path('Library/Application Support/Plex Media Server/Plug-in Support/Databases/com.plexapp.plugins.library.db')


def say(message):
    print(message, flush=True)


def atomic(path, data, mode=0o600, owner=None):
    if path.is_symlink():
        raise RuntimeError('Unexpected symbolic migration output path.')
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


def run(*args, allowed=(0,), timeout=600, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout, **kwargs)
    if result.returncode not in allowed:
        if BASE.is_dir():
            atomic(BASE / 'private-error.log', result.stdout + '\n' + result.stderr)
        raise RuntimeError('An export command failed; diagnostic output was saved privately in the export state directory.')
    return result.stdout


def record(value):
    atomic(STATE, json.dumps(value, indent=2) + '\n')


def file_hash(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(4 * 1024**2), b''):
            result.update(block)
    return result.hexdigest()


def inspect_targets():
    containers = json.loads(run('docker', 'inspect', *IMAGES))
    result = {item['Name'].lstrip('/'): item for item in containers}
    if set(result) != set(IMAGES):
        raise RuntimeError('The inventoried source Plex/NPM containers are required.')
    for name, container in result.items():
        if container['Image'] != IMAGES[name]:
            raise RuntimeError('A source image changed since the inspection: ' + name)
        for target, label in TARGETS[name].items():
            matches = [mount for mount in container['Mounts'] if mount['Destination'] == target
                       and mount['Type'] == 'bind' and mount['Source'] == ROOTS[label]]
            if len(matches) != 1:
                raise RuntimeError('An inventoried persistent source binding differs: ' + name)
        if name != 'plex':
            env = dict(item.split('=', 1) for item in container['Config'].get('Env', []) if '=' in item)
            if env.get('DB_MYSQL_HOST') or env.get('DB_POSTGRES_HOST') or env.get('DB_SQLITE_FILE', '/data/database.sqlite') != '/data/database.sqlite':
                raise RuntimeError('NPM uses database storage that needs a different export.')
    for label, source in ROOTS.items():
        path = Path(source)
        if path.is_symlink() or not path.is_dir() or run('findmnt', '-n', '-T', source, '-o', 'FSTYPE').strip() not in ('ext4', 'xfs', 'btrfs'):
            raise RuntimeError('An inventoried local persistent directory is unavailable: ' + label)
    if not (Path(ROOTS['plex-config']) / PLEX_DB).is_file() or not (Path(ROOTS['npm-data']) / 'database.sqlite').is_file():
        raise RuntimeError('The existing Plex and NPM databases must be present.')
    return result


def check_authorization():
    path = Path('/home/sawdoctor/.ssh/authorized_keys')
    if path.is_symlink() or not path.is_file() or READER.is_symlink() or not READER.is_file():
        raise RuntimeError('The existing restricted NAS transfer setup is required.')
    matches = []
    for line in path.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        fields = shlex.split(line)
        if fields[-3:] == ['ssh-ed25519', BLOB, 'nas-infinidysk-transfer']:
            matches.append(fields[0])
    if len(matches) != 1 or not all(value in matches[0] for value in ('from=192.168.0.220', 'restrict', 'command=' + str(READER))):
        raise RuntimeError('The original restricted NAS key authorization needs review; keys were retained.')


def reader_update(original):
    marker = '# ' + SIGNATURE
    if marker in original:
        return original
    if not original.startswith('#!/bin/sh\n') or 'SSH_ORIGINAL_COMMAND' not in original:
        raise RuntimeError('The existing restricted reader needs review; it was retained.')
    routes = f'''{marker}
case "${{SSH_ORIGINAL_COMMAND-}}" in
  plex-npm) exec /bin/cat {OUTPUT}/export.tar.zst ;;
  plex-npm-sha256) exec /bin/cat {OUTPUT}/export.sha256 ;;
  plex-npm-status) exec /bin/systemctl show nas-plex-npm-export.service -p ActiveState -p SubState -p Result ;;
esac
'''
    return '#!/bin/sh\n' + routes + original.split('\n', 1)[1]


def plex_version():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open('http://127.0.0.1:32400/identity', timeout=5) as response:
        return ET.fromstring(response.read()).attrib['version']


def resume(backup_locked=False):
    if not STATE.exists():
        return
    if not backup_locked:
        with BACKUP_LOCK.open('a') as backup_lock:
            fcntl.flock(backup_lock, fcntl.LOCK_EX)
            return resume(backup_locked=True)
    state = json.loads(STATE.read_text())
    for item in reversed(state.get('containers', [])):
        current = json.loads(run('docker', 'inspect', item['name']))[0]
        if current['Id'] != item['id'] or current['Image'] != IMAGES[item['name']]:
            raise RuntimeError('A paused source container changed; recovery state was retained.')
        if not current['State']['Running']:
            if item['name'] == 'plex':
                run(str(SAFE_START), timeout=330)
            else:
                run('docker', 'start', item['id'])
        if not json.loads(run('docker', 'inspect', item['id']))[0]['State']['Running']:
            raise RuntimeError('Source recovery did not restore: ' + item['name'])
        say('Restored: ' + item['name'])
    if state.get('ownsMarker'):
        BACKUP_MARKER.unlink(missing_ok=True)
    if state.get('restoreBackupTimer'):
        run('systemctl', 'start', BACKUP_TIMER)
    STATE.unlink()


def sync(work, live=False):
    for label, source in ROOTS.items():
        target = work / 'data' / label
        target.mkdir(parents=True, exist_ok=True)
        args = ['rsync', '-aHAX', '--numeric-ids', '--one-file-system', '--no-devices', '--no-specials', '--delete']
        if not live:
            args.append('--checksum')
        run(*args, '--', source + '/', str(target) + '/', allowed=(0, 24) if live else (0,), timeout=3600)


def cold_copy(work, containers):
    # Match the existing daily-backup lock and marker. Pause only the timer's
    # runtime state, restoring it even after failure or reboot recovery.
    with BACKUP_LOCK.open('a') as backup_lock:
        fcntl.flock(backup_lock, fcntl.LOCK_EX)
        timer_active = run('systemctl', 'is-active', BACKUP_TIMER, allowed=(0, 3, 4)).strip() == 'active'
        state = {'format': FORMAT, 'containers': [], 'ownsMarker': False, 'restoreBackupTimer': timer_active}
        record(state)
        try:
            if timer_active:
                run('systemctl', 'stop', BACKUP_TIMER)
            activity = run('systemctl', 'show', BACKUP_SERVICE, '-p', 'ActiveState', '--value').strip()
            if activity not in ('inactive', 'failed') or BACKUP_MARKER.exists():
                raise RuntimeError('Let the existing Plex backup finish, then retry this export.')
            state['ownsMarker'] = True
            record(state)
            BACKUP_MARKER.touch(exist_ok=False)
            current = inspect_targets()
            if any(current[name]['Id'] != containers[name]['Id'] or
                   current[name]['State']['Running'] != containers[name]['State']['Running'] for name in IMAGES):
                raise RuntimeError('A source container or its running state changed during pre-copy; retry the export.')
            state['containers'] = [{'name': name, 'id': current[name]['Id']}
                                   for name in IMAGES if current[name]['State']['Running']]
            record(state)
            say('Pausing Plex and NPM for the final consistent copy...')
            for item in state['containers']:
                run('docker', 'stop', '--timeout', '60', item['id'])
            if any(item['State']['Running'] for item in inspect_targets().values()):
                raise RuntimeError('A source application restarted during the cold snapshot.')
            sync(work)
            if any(item['State']['Running'] for item in inspect_targets().values()):
                raise RuntimeError('A source application restarted during the cold snapshot.')
        finally:
            resume(backup_locked=True)
    say('Plex and NPM restored. Compression and transfer will use the saved snapshot.')


def verify(work):
    database = work / 'data/npm-data/database.sqlite'
    connection = sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)
    try:
        if connection.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
            raise RuntimeError('The copied NPM database did not pass its integrity check.')
    finally:
        connection.close()
    # Run the bundled SQLite utility, never the Plex server, against only the
    # copied data. Its customized engine understands the existing Plex schema.
    result = run('docker', 'run', '--rm', '--network', 'none', '--read-only',
        '--mount', 'type=bind,source=' + str(work / 'data/plex-config') + ',target=/snapshot,readonly',
        '--env', 'LD_LIBRARY_PATH=/usr/lib/plexmediaserver',
        '--entrypoint', '/usr/lib/plexmediaserver/Plex SQLite', IMAGES['plex'],
        '-readonly', '/snapshot/' + str(PLEX_DB), 'PRAGMA quick_check;', timeout=1800)
    if result.strip() != 'ok':
        atomic(BASE / 'plex-database-check.log', result)
        raise RuntimeError('The copied Plex database did not pass its integrity check; private results were retained.')
    preferences = work / 'data/plex-config/Library/Application Support/Plex Media Server/Preferences.xml'
    values = ET.parse(preferences).getroot().attrib
    if not values.get('MachineIdentifier'):
        raise RuntimeError('The copied Plex server identity is unavailable.')
    say('Copied Plex and NPM databases passed their checks; Plex preferences and identity are present.')


def check_sqlite_tool():
    run('docker', 'run', '--rm', '--network', 'none', '--read-only',
        '--env', 'LD_LIBRARY_PATH=/usr/lib/plexmediaserver',
        '--entrypoint', '/usr/lib/plexmediaserver/Plex SQLite', IMAGES['plex'], '-version')


def export():
    resume()
    account = pwd.getpwnam('sawdoctor')
    owner = (account.pw_uid, account.pw_gid)
    archive = OUTPUT / 'export.tar.zst'
    check_authorization()
    if archive.exists():
        atomic(OUTPUT / 'export.sha256', file_hash(archive) + '  export.tar.zst\n', owner=owner)
        say('PLEX/NPM EXPORT READY: ' + str(archive))
        return
    containers = inspect_targets()
    if not all(item['State']['Running'] for item in containers.values()):
        raise RuntimeError('Plex and NPM must be running before the initial source snapshot.')
    version = plex_version()
    check_sqlite_tool()
    images = json.loads(run('docker', 'image', 'inspect', *IMAGES.values()))
    size = sum(int(line.split()[0]) for line in run('du', '-sbx', '--', *ROOTS.values()).splitlines())
    if shutil.disk_usage(BASE).free < 2 * (size + sum(item.get('Size', 0) for item in images)) + 2 * 1024**3:
        raise RuntimeError('The OptiPlex needs more free space for staging and compression.')
    work = BASE / 'snapshot-work'
    if work.exists():
        marker = work / 'manifest.json'
        if work.is_symlink() or not marker.is_file() or json.loads(marker.read_text()).get('format') != FORMAT:
            raise RuntimeError('Unrecognized source staging files were retained.')
    work.mkdir(mode=0o700, exist_ok=True)
    (work / 'compose').mkdir(exist_ok=True)
    manifest = {'format': FORMAT, 'sourceHost': '192.168.0.29',
        'createdUtc': time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()), 'plexVersion': version,
        'containers': list(containers.values()), 'images': images,
        'dataRoots': {label: {'source': source, 'snapshot': 'data/' + label} for label, source in ROOTS.items()},
        'composeFiles': [], 'npmDatabase': 'sqlite'}
    paths = set()
    for container in containers.values():
        labels = container['Config'].get('Labels') or {}
        paths.update(item for item in labels.get('com.docker.compose.project.config_files', '').split(',') if item)
        working = labels.get('com.docker.compose.project.working_dir')
        if working and (Path(working) / '.env').is_file():
            paths.add(str(Path(working) / '.env'))
    for source in sorted(paths):
        path = Path(source)
        if path.is_symlink() or not path.is_file():
            raise RuntimeError('An original private Compose file is unavailable.')
        relative = 'compose/' + hashlib.sha256(source.encode()).hexdigest()[:12] + '-' + path.name
        shutil.copy2(path, work / relative)
        manifest['composeFiles'].append({'source': source, 'snapshot': relative})
    atomic(work / 'manifest.json', json.dumps(manifest, indent=2) + '\n')
    say('Pre-copying Plex configuration, Flora library links and NPM data/certificates while the source apps run...')
    sync(work, live=True)
    cold_copy(work, containers)
    verify(work)
    say('Saving the exact current Plex and NPM images...')
    run('docker', 'image', 'save', '--output', str(work / 'images.tar'), *IMAGES.values(), timeout=1800)
    run('bash', '-o', 'pipefail', '-c',
        'find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS', cwd=work, timeout=1800)
    OUTPUT.mkdir(mode=0o700, exist_ok=True)
    os.chown(OUTPUT, *owner)
    OUTPUT.chmod(0o700)
    partial = OUTPUT / 'export.tar.zst.incomplete'
    say('Compressing and checking the private export; production Plex and NPM are already running...')
    run('tar', '--acls', '--xattrs', '--numeric-owner', '--sparse', '--one-file-system',
        '-I', 'zstd -T2 -3', '-cpf', str(partial), '-C', str(work), '.', timeout=7200)
    run('tar', '-I', 'zstd', '-tf', str(partial), timeout=1800)
    partial.chmod(0o600)
    os.chown(partial, *owner)
    partial.replace(archive)
    atomic(OUTPUT / 'export.sha256', file_hash(archive) + '  export.tar.zst\n', owner=owner)
    shutil.rmtree(work)
    say('PLEX/NPM EXPORT READY: ' + str(archive))
    say('Plex version retained: ' + version + '. NAS deployment and public routing were not changed.')
    say('Temporary source staging removed; one verified private transfer archive is retained.')


def install():
    for tool in ('docker', 'rsync', 'zstd', 'tar', 'findmnt', 'sha256sum'):
        if not shutil.which(tool):
            raise RuntimeError('Required export tool is unavailable: ' + tool)
    if not SAFE_START.is_file() or not os.access(SAFE_START, os.X_OK):
        raise RuntimeError('The existing Plex safe-start helper is required.')
    if run('systemctl', 'is-active', 'nas-plex-npm-export.service', allowed=(0, 3, 4)).strip() in ('active', 'activating'):
        say('The source export is already running. Watch: sudo journalctl -u nas-plex-npm-export.service -f')
        return
    for path in (BASE, OUTPUT, WORKER, STATE, READER):
        if path.is_symlink():
            raise RuntimeError('An unexpected symbolic export installation path was retained.')
    if WORKER.exists() and SIGNATURE not in WORKER.read_text():
        raise RuntimeError('An unrelated export helper was retained.')
    check_authorization()
    inspect_targets()
    source = globals().get('INSTALL_SOURCE')
    if source is None and '__file__' in globals():
        source = Path(__file__).read_text()
    if not source:
        raise RuntimeError('Use the complete provided installer command.')
    BASE.mkdir(mode=0o700, exist_ok=True)
    BASE.chmod(0o700)
    atomic(WORKER, source, 0o700)
    updated = reader_update(READER.read_text())
    with tempfile.NamedTemporaryFile('w', dir=READER.parent, delete=False) as check:
        path = Path(check.name)
        try:
            check.write(updated); check.flush()
            run('sh', '-n', str(path))
        finally:
            path.unlink(missing_ok=True)
    atomic(READER, updated, 0o755)
    for name in ('nas-plex-npm-export.service', 'nas-plex-npm-export-resume.service'):
        path = UNITS / name
        if path.is_symlink() or (path.exists() and SIGNATURE not in path.read_text()):
            raise RuntimeError('An unrelated export service was retained.')
    recovery = f'''# {SIGNATURE}
[Unit]
Description=Restore Plex/NPM after interrupted NAS snapshot
Requires=docker.service
Wants=network-online.target
After=docker.service network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={WORKER} resume
TimeoutStartSec=2h
UMask=0077
[Install]
WantedBy=multi-user.target
'''
    service = f'''# {SIGNATURE}
[Unit]
Description=Consistent OptiPlex Plex/NPM snapshot for NAS migration
Requires=docker.service nas-plex-npm-export-resume.service
After=docker.service nas-plex-npm-export-resume.service
[Service]
Type=oneshot
ExecStart={WORKER} export
ExecStopPost={WORKER} resume
TimeoutStartSec=4h
TimeoutStopSec=10min
Nice=10
IOSchedulingClass=idle
UMask=0077
'''
    atomic(UNITS / 'nas-plex-npm-export-resume.service', recovery, 0o644)
    atomic(UNITS / 'nas-plex-npm-export.service', service, 0o644)
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', 'nas-plex-npm-export-resume.service')
    run('systemctl', 'start', '--no-block', 'nas-plex-npm-export.service')
    say('Plex/NPM export started in the background. Source apps resume before compression and transfer.')
    say('Watch: sudo journalctl -u nas-plex-npm-export.service -f')
    say('Ctrl+C leaves the log viewer; the export continues.')


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or 'inet 192.168.0.29/' not in run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the OptiPlex at 192.168.0.29.')
    mode = sys.argv[1] if len(sys.argv) > 1 else 'install'
    if mode == 'install':
        install()
        return
    BASE.mkdir(mode=0o700, exist_ok=True)
    with (BASE / 'lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if mode == 'resume':
            resume()
        elif mode == 'export':
            def interrupted(signum, frame):
                raise RuntimeError('Export interrupted; source recovery will run.')
            signal.signal(signal.SIGTERM, interrupted)
            export()
        else:
            raise RuntimeError('Unknown export operation.')


if __name__ == '__main__':
    try:
        main()
    except RuntimeError as error:
        raise SystemExit('STOP: ' + str(error))
    except Exception as error:
        raise SystemExit('STOP: Export failed (' + type(error).__name__ + '); available private recovery state was retained.')
