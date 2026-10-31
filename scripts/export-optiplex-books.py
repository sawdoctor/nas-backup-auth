#!/usr/bin/env python3
"""Sawdoctor OptiPlex books export v1: consistent appdata and exact images."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time

SIGNATURE = 'Sawdoctor OptiPlex books export v1'
BASE = Path('/var/lib/sawdoctor-nas-books-export')
OUTPUT = Path('/home/sawdoctor/nas-books-export')
WORKER = Path('/usr/local/sbin/nas-books-export')
READER = Path('/usr/local/sbin/nas-migration-export-read')
UNITS = Path('/etc/systemd/system')
TRANSFER_BLOB = 'AAAAC3NzaC1lZDI1NTE5AAAAILc56w99kcthdhVVsUuXQxChc1Smtlx6ju+xZPLNIpSE'
CONTAINERS = ('abr-shelfmark-bridge', 'audiobookrequest', 'audiobookshelf-test',
    'kavita', 'sabnzbd-ebooks', 'shelfmark-ebooks', 'shelfmark-torbox',
    'stackarr-ebooks', 'torbox-media-center', 'rdtclient-books')
# TorBox's FUSE mount can be used by Plex. Its static patches are copied live.
DO_NOT_PAUSE = {'torbox-media-center'}
ROOTS = {
    'abr-shelfmark-bridge': '/home/sawdoctor/docker/abr-shelfmark-bridge',
    'audiobookrequest': '/home/sawdoctor/docker/audiobookrequest',
    'kavita': '/home/sawdoctor/docker/kavita',
    'sabnzbd': '/home/sawdoctor/docker/sabnzbd',
    'shelfmark-ebooks': '/home/sawdoctor/docker/shelfmark-ebooks',
    'shelfmark-torbox': '/home/sawdoctor/docker/shelfmark-torbox',
    'stackarr-shelfmark': '/home/sawdoctor/docker/stackarr-shelfmark',
    'torbox-media-center': '/home/sawdoctor/docker/torbox-media-center',
    'rdtclient-books': '/home/sawdoctor/docker/rdtclient-books',
    'audiobookshelf-data': '/mnt/usenet_scratch/audiobookshelf-test',
    'stable-playback-namespace': '/home/sawdoctor/torbox-recovery-20261011/stable-playback-namespace',
    'playback-overrides': '/home/sawdoctor/torbox-recovery-20261011/playback-overrides',
    'virtual-audiobooks': '/mnt/media/audiobooks-test',
}
HOST_UNITS = ('rclone-gdrive-audiobooks.service', 'rclone-gdrive-ebooks.service',
    'rclone-gdrive-torbox-archive.service', 'rclone-torbox-audiobooks.service',
    'torbox-audiobook-archive.service', 'torbox-audiobook-archive.timer')
RCLONE_CONFIG = Path('/home/sawdoctor/.config/rclone/rclone.conf')
HOST_FILE_PREFIXES = ('/etc/', '/usr/local/', '/home/sawdoctor/')
READER_SOURCE = '''#!/bin/sh
# Sawdoctor OptiPlex core export v1
# Sawdoctor OptiPlex books export v1
case "${SSH_ORIGINAL_COMMAND-}" in
  ''|infinidysk) exec /bin/cat /home/sawdoctor/nas-infinidysk-export/export.tar.zst ;;
  core) exec /bin/cat /home/sawdoctor/nas-core-export/export.tar.zst ;;
  core-sha256) exec /bin/cat /home/sawdoctor/nas-core-export/export.sha256 ;;
  core-status) exec /bin/systemctl show nas-core-export.service -p ActiveState -p SubState -p Result ;;
  books) exec /bin/cat /home/sawdoctor/nas-books-export/export.tar.zst ;;
  books-sha256) exec /bin/cat /home/sawdoctor/nas-books-export/export.sha256 ;;
  books-status) exec /bin/systemctl show nas-books-export.service -p ActiveState -p SubState -p Result ;;
  *) echo 'Unsupported export request.' >&2; exit 1 ;;
esac
'''


def log(message):
    print(message, flush=True)


def run(*args, capture=False, allowed=(0,), **kwargs):
    result = subprocess.run(args, check=False, text=True,
        stdout=subprocess.PIPE if capture else None, **kwargs)
    if result.returncode not in allowed:
        raise RuntimeError('Command failed: ' + shlex.join(args) + ' (exit ' + str(result.returncode) + ')')
    return result.stdout


def guard():
    if os.geteuid() != 0 or 'inet 192.168.0.29/' not in run('ip', '-4', 'addr', 'show', capture=True):
        raise RuntimeError('Run with sudo on the OptiPlex at 192.168.0.29.')


def atomic_text(path, text, mode=0o600, owner=None):
    fd, temporary = tempfile.mkstemp(prefix='.nas-books-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        if owner:
            os.chown(temporary, *owner)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            digest.update(block)
    return digest.hexdigest()


def ssh_authorization(account, write=False):
    directory = Path(account.pw_dir) / '.ssh'
    path = directory / 'authorized_keys'
    if directory.is_symlink() or path.is_symlink() or not path.is_file():
        raise RuntimeError('The existing NAS transfer authorization was not found safely.')
    lines = path.read_text().splitlines()
    matches = []
    for index, line in enumerate(lines):
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        fields = shlex.split(line)
        if fields[-3:] == ['ssh-ed25519', TRANSFER_BLOB, 'nas-infinidysk-transfer']:
            matches.append(index)
    if len(matches) != 1:
        raise RuntimeError('Expected exactly one verified NAS transfer key; SSH settings were not changed.')
    if write:
        lines[matches[0]] = ('from="192.168.0.220",restrict,command="' + str(READER)
            + '" ssh-ed25519 ' + TRANSFER_BLOB + ' nas-infinidysk-transfer')
        atomic_text(path, '\n'.join(lines) + '\n', owner=(account.pw_uid, account.pw_gid))


def inspect_targets():
    containers = json.loads(run('docker', 'inspect', *CONTAINERS, capture=True))
    by_name = {c['Name'].lstrip('/'): c for c in containers}
    if set(by_name) != set(CONTAINERS):
        raise RuntimeError('The book application containers do not match the inventory.')
    for label, source in ROOTS.items():
        path = Path(source)
        if path.is_symlink() or not path.is_dir():
            raise RuntimeError('Expected a real local data directory: ' + label)
        fs = run('findmnt', '-n', '-o', 'FSTYPE', '-T', source, capture=True).strip()
        if fs not in ('ext4', 'xfs', 'btrfs'):
            raise RuntimeError('Refusing to copy a nonlocal book data root: ' + label)
    for name, container in by_name.items():
        for mount in container.get('Mounts', []):
            source = Path(mount['Source'])
            if any(source == Path(root) or Path(root) in source.parents for root in ROOTS.values()):
                continue
            fs = run('findmnt', '-n', '-o', 'FSTYPE', '-T', str(source), capture=True).strip()
            if fs not in ('fuse.rclone', 'fuse.main.py'):
                raise RuntimeError('Uncaptured local application mount for ' + name + ': ' + mount['Destination'])
    return by_name


def resume():
    state = BASE / 'running-containers.json'
    if not state.exists():
        return
    records = json.loads(state.read_text())
    failed = []
    for item in reversed(records):
        try:
            run('docker', 'start', item['id'], capture=True)
            status = json.loads(run('docker', 'inspect', item['id'], capture=True))[0]
            if not status['State']['Running']:
                raise RuntimeError('not running')
            log('Restored: ' + item['name'])
        except Exception:
            failed.append(item['name'])
    if failed:
        raise RuntimeError('Container recovery needs attention: ' + ', '.join(failed)
            + '. Recovery state has been retained.')
    state.unlink()


def sync_data(work, live=False):
    for name, source in ROOTS.items():
        target = work / 'data' / name
        target.mkdir(parents=True, exist_ok=True)
        args = ['rsync', '-aHAX', '--numeric-ids', '--one-file-system', '--no-devices', '--no-specials', '--delete']
        if not live:
            args.append('--checksum')
        run(*args, '--', source + '/', str(target) + '/', allowed=(0, 24) if live else (0,))


def verify_sqlite(work):
    count = 0
    for directory, dirs, files in os.walk(work / 'data', followlinks=False):
        for name in files:
            path = Path(directory) / name
            if path.is_symlink():
                continue
            with path.open('rb') as stream:
                if stream.read(16) != b'SQLite format 3\x00':
                    continue
            connection = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)
            try:
                if connection.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
                    raise RuntimeError('Copied database integrity check failed: ' + str(path.relative_to(work)))
            finally:
                connection.close()
            count += 1
    log('Copied SQLite databases checked: ' + str(count))


def collect_host_files(work, manifest):
    """Capture private mount definitions and credentials without walking cloud data."""
    host = work / 'host'
    host.mkdir(mode=0o700, exist_ok=True)
    (host / 'files').mkdir(mode=0o700, exist_ok=True)
    if RCLONE_CONFIG.is_symlink() or not RCLONE_CONFIG.is_file():
        raise RuntimeError('The original user rclone configuration was not found safely.')
    paths = {RCLONE_CONFIG, Path(shutil.which('rclone') or '/usr/bin/rclone')}
    unit_data = {}

    def collect_references(text):
        # Only existing local files are copied below; referenced directories and
        # mount contents are never traversed by this collector.
        for value in re.findall(r'(?<![A-Za-z0-9:/])(/[^\s\"\'();]+)', text):
            candidate = Path(value.rstrip(','))
            if candidate.is_file() and not candidate.is_symlink():
                if str(candidate).startswith(HOST_FILE_PREFIXES):
                    paths.add(candidate)

    for unit in HOST_UNITS:
        description = run('systemctl', 'show', unit, '-p', 'LoadState', '-p', 'ActiveState',
            '-p', 'FragmentPath', '-p', 'DropInPaths', '-p', 'MainPID',
            '-p', 'User', '-p', 'Group', '-p', 'WorkingDirectory',
            '-p', 'Environment', '-p', 'EnvironmentFiles', capture=True)
        properties = dict(line.split('=', 1) for line in description.splitlines() if '=' in line)
        if properties.get('LoadState') != 'loaded':
            if unit.startswith('rclone-'):
                raise RuntimeError('Required cloud mount service is missing: ' + unit)
            continue
        text = run('systemctl', 'cat', unit, capture=True)
        atomic_text(host / (unit + '.txt'), text)
        collect_references(text.replace('\\\n', ' '))
        collect_references(properties.get('EnvironmentFiles', ''))
        for key in ('FragmentPath', 'DropInPaths'):
            for value in shlex.split(properties.get(key, '')):
                candidate = Path(value)
                if candidate.is_file() and not candidate.is_symlink():
                    paths.add(candidate)
        pid = int(properties.get('MainPID') or '0')
        if pid:
            proc = Path('/proc') / str(pid)
            try:
                argv = (proc / 'cmdline').read_bytes().decode().rstrip('\0').split('\0')
                environment = dict(item.split('=', 1) for item in
                    (proc / 'environ').read_bytes().decode().split('\0') if '=' in item)
                properties['RuntimeCommand'] = argv
                properties['RcloneEnvironment'] = {key: value for key, value in environment.items()
                    if key.startswith('RCLONE_')}
                collect_references(' '.join(argv))
                for position, value in enumerate(argv):
                    config = value.split('=', 1)[1] if value.startswith('--config=') else (
                        argv[position + 1] if value == '--config' and position + 1 < len(argv) else None)
                    if config:
                        paths.add(Path(config))
                if environment.get('RCLONE_CONFIG'):
                    paths.add(Path(environment['RCLONE_CONFIG']))
            except FileNotFoundError:
                raise RuntimeError('A mount service changed while collecting its runtime: ' + unit)
        unit_data[unit] = properties
    manifest['hostFiles'] = []
    for source in sorted(paths):
        if not source.is_absolute() or source.is_symlink() or not source.is_file():
            raise RuntimeError('A referenced local mount file could not be captured safely.')
        fs = run('findmnt', '-n', '-o', 'FSTYPE', '-T', str(source), capture=True).strip()
        if fs not in ('ext4', 'xfs', 'btrfs'):
            raise RuntimeError('A referenced mount file is not on local storage.')
        target = host / 'files' / (hashlib.sha256(str(source).encode()).hexdigest()[:16] + '-' + source.name)
        shutil.copy2(source, target)
        target.chmod(0o600)
        manifest['hostFiles'].append({'source': str(source), 'snapshot': str(target.relative_to(work)),
            'sourceMode': source.stat().st_mode & 0o777, 'sha256': file_hash(target)})
    manifest['hostUnits'] = unit_data
    manifest['mounts'] = json.loads(run('findmnt', '-J', '-o', 'TARGET,SOURCE,FSTYPE,OPTIONS', capture=True))
    manifest['rcloneVersion'] = run('rclone', 'version', capture=True).splitlines()[0]
    log('Private cloud mount definitions, referenced local helper files and rclone credentials captured.')


def export_books():
    archive = OUTPUT / 'export.tar.zst'
    resume()
    if OUTPUT.is_symlink():
        raise RuntimeError('Unexpected export output symlink.')
    account = pwd.getpwnam('sawdoctor')
    ssh_authorization(account)
    if archive.exists():
        log('A completed books export already exists; leaving it unchanged.')
        checksum = file_hash(archive)
        atomic_text(OUTPUT / 'export.sha256', checksum + '  export.tar.zst\n',
            owner=(account.pw_uid, account.pw_gid))
        ssh_authorization(account, write=True)
        log('BOOKS EXPORT READY: ' + str(archive))
        log('SHA256=' + checksum)
        return
    containers = inspect_targets()
    stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
    work = BASE / ('work-' + stamp + '-' + str(os.getpid()))
    work.mkdir(mode=0o700)
    (work / 'compose').mkdir()
    image_ids = sorted({c['Image'] for c in containers.values()})
    images = json.loads(run('docker', 'image', 'inspect', *image_ids, capture=True))
    size_output = run('du', '-sbx', '--', *ROOTS.values(), capture=True)
    config_size = sum(int(line.split()[0]) for line in size_output.splitlines())
    image_size = sum(item.get('Size', 0) for item in images)
    if shutil.disk_usage(BASE).free < 2 * (config_size + image_size) + 2 * 1024**3:
        raise RuntimeError('Not enough free OptiPlex space for staging and the archive.')
    manifest = {'format': 'sawdoctor-books-export-v1', 'sourceHost': '192.168.0.29',
        'createdUtc': stamp, 'containers': list(containers.values()), 'images': images,
        'dataRoots': {name: {'source': source, 'snapshot': 'data/' + name}
            for name, source in ROOTS.items()}, 'composeFiles': [], 'hostFiles': []}
    compose_paths = set()
    for c in containers.values():
        labels = c['Config'].get('Labels') or {}
        compose_paths.update(x for x in labels.get('com.docker.compose.project.config_files', '').split(',') if x)
        working = labels.get('com.docker.compose.project.working_dir')
        if working and (Path(working) / '.env').is_file():
            compose_paths.add(str(Path(working) / '.env'))
    for source in sorted(compose_paths):
        path = Path(source)
        if not path.is_file() or path.is_symlink():
            raise RuntimeError('An original Compose source is missing or unexpected: ' + source)
        name = hashlib.sha256(source.encode()).hexdigest()[:12] + '-' + path.name
        shutil.copy2(path, work / 'compose' / name)
        manifest['composeFiles'].append({'source': source, 'snapshot': 'compose/' + name})
    inventory = Path('/home/sawdoctor/nas-migration-inventory/optiplex-inventory.json')
    if inventory.is_file() and not inventory.is_symlink():
        shutil.copy2(inventory, work / 'full-optiplex-inventory.json')
    atomic_text(work / 'manifest.json', json.dumps(manifest, indent=2) + '\n')
    log('Pre-copying local book data and custom application files while applications run...')
    sync_data(work, live=True)
    current = inspect_targets()
    if any(current[name]['Id'] != containers[name]['Id'] or current[name]['Image'] != containers[name]['Image'] for name in CONTAINERS):
        raise RuntimeError('A source container changed during the pre-copy. Rerun to capture its current state.')
    running = [{'name': name, 'id': current[name]['Id']} for name in CONTAINERS if current[name]['State']['Running'] and name not in DO_NOT_PAUSE]
    atomic_text(BASE / 'running-containers.json', json.dumps(running) + '\n')
    try:
        log('Briefly pausing the running book applications for a consistent final snapshot...')
        for item in running:
            run('docker', 'stop', '--timeout', '60', item['id'], capture=True)
        if any(c['State']['Running'] for name, c in inspect_targets().items() if name not in DO_NOT_PAUSE):
            raise RuntimeError('A copied application restarted during the snapshot.')
        sync_data(work)
        if any(c['State']['Running'] for name, c in inspect_targets().items() if name not in DO_NOT_PAUSE):
            raise RuntimeError('A copied application restarted during the snapshot.')
    finally:
        resume()
    log('Book applications restored. Plex, InfiniDysk, Arrs, NPM and cloud mounts were not stopped.')
    verify_sqlite(work)
    collect_host_files(work, manifest)
    atomic_text(work / 'manifest.json', json.dumps(manifest, indent=2) + '\n')
    log('Saving exact book application images, including the local bridge build...')
    run('docker', 'image', 'save', '--output', str(work / 'images.tar'), *image_ids)
    run('bash', '-o', 'pipefail', '-c',
        'find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS', cwd=work)
    OUTPUT.mkdir(mode=0o700, exist_ok=True)
    if OUTPUT.is_symlink():
        raise RuntimeError('Unexpected export output symlink.')
    os.chown(OUTPUT, account.pw_uid, account.pw_gid)
    OUTPUT.chmod(0o700)
    temporary = OUTPUT / 'export.tar.zst.incomplete'
    log('Compressing and checking the private export; source apps are already running...')
    run('tar', '--acls', '--xattrs', '--numeric-owner', '--sparse', '--one-file-system',
        '-I', 'zstd -T2 -3', '-cpf', str(temporary), '-C', str(work), '.')
    run('tar', '-I', 'zstd', '-tf', str(temporary), capture=True)
    os.chmod(temporary, 0o600)
    os.chown(temporary, account.pw_uid, account.pw_gid)
    os.replace(temporary, archive)
    checksum = file_hash(archive)
    atomic_text(OUTPUT / 'export.sha256', checksum + '  export.tar.zst\n',
                owner=(account.pw_uid, account.pw_gid))
    ssh_authorization(account, write=True)
    log('BOOKS EXPORT READY: ' + str(archive))
    log('SHA256=' + checksum)
    log('Archive size: ' + str(round(archive.stat().st_size / 1024**3, 2)) + ' GiB')
    log('The existing NAS key can read this books export; earlier InfiniDysk and core transfers remain available.')


def install():
    for tool in ('rsync', 'zstd', 'docker', 'tar', 'findmnt', 'sha256sum', 'rclone'):
        if not shutil.which(tool):
            raise RuntimeError('Required tool is missing: ' + tool)
    if subprocess.run(['systemctl', 'is-active', '--quiet', 'nas-books-export.service']).returncode == 0:
        log('The books export is already running. Watch: sudo journalctl -u nas-books-export.service -f')
        return
    for unit in ('nas-infinidysk-export.service', 'nas-core-export.service', 'torbox-audiobook-archive.service'):
        if subprocess.run(['systemctl', 'is-active', '--quiet', unit]).returncode == 0:
            raise RuntimeError('Let the current source job finish first: ' + unit)
    for path in (BASE, OUTPUT, WORKER, READER, UNITS / 'nas-books-export.service', UNITS / 'nas-books-export-resume.service'):
        if path.is_symlink():
            raise RuntimeError('Unexpected symlink at an export installation path.')
        if path.is_file() and SIGNATURE not in path.read_text() and not (path == READER and 'Sawdoctor OptiPlex core export v1' in path.read_text()):
            raise RuntimeError('An unrelated installation file exists: ' + str(path))
    BASE.mkdir(mode=0o700, exist_ok=True)
    BASE.chmod(0o700)
    ssh_authorization(pwd.getpwnam('sawdoctor'))
    inspect_targets()
    source = globals().get('INSTALL_SOURCE')
    if source is None and '__file__' in globals():
        source = Path(__file__).read_text()
    if not source:
        raise RuntimeError('Use the provided complete installer command.')
    atomic_text(WORKER, source, 0o750)
    atomic_text(READER, READER_SOURCE, 0o755)
    ssh_authorization(pwd.getpwnam('sawdoctor'), write=True)
    recovery = f'''# {SIGNATURE}
[Unit]
Description=Sawdoctor books export container recovery
Requires=docker.service
Wants=network-online.target
After=docker.service network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={WORKER} resume
TimeoutStartSec=5min
UMask=0077
[Install]
WantedBy=multi-user.target
'''
    service = f'''# {SIGNATURE}
[Unit]
Description=Sawdoctor book applications export for NAS migration
Requires=docker.service nas-books-export-resume.service
After=docker.service nas-books-export-resume.service
[Service]
Type=oneshot
ExecStart={WORKER} export
ExecStopPost={WORKER} resume
TimeoutStartSec=4h
TimeoutStopSec=5min
Nice=10
IOSchedulingClass=idle
UMask=0077
'''
    atomic_text(UNITS / 'nas-books-export-resume.service', recovery, 0o644)
    atomic_text(UNITS / 'nas-books-export.service', service, 0o644)
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', 'nas-books-export-resume.service')
    run('systemctl', 'start', '--no-block', 'nas-books-export.service')
    log('Books export started in the background on the OptiPlex.')
    log('It includes application settings, custom patches/images, local audiobook data, library links and private cloud mount configuration.')
    log('Watch: sudo journalctl -u nas-books-export.service -f')
    log('Ctrl+C leaves the log viewer; the export continues.')


def main():
    os.umask(0o077)
    guard()
    mode = sys.argv[1] if len(sys.argv) > 1 else 'install'
    if mode == 'install':
        install()
        return
    BASE.mkdir(mode=0o700, exist_ok=True)
    with open(BASE / 'lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if mode == 'resume':
            resume()
        elif mode == 'export':
            def interrupted(signum, frame):
                raise RuntimeError('Export interrupted; source container recovery will run.')
            signal.signal(signal.SIGTERM, interrupted)
            export_books()
        else:
            raise RuntimeError('Unknown export operation.')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit('\nInterrupted. The recovery service will restore paused containers.')
    except Exception as error:
        raise SystemExit('STOP: ' + str(error))
