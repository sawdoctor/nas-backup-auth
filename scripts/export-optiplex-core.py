#!/usr/bin/env python3
"""Sawdoctor OptiPlex core export v1: consistent appdata and exact images."""
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

SIGNATURE = 'Sawdoctor OptiPlex core export v1'
BASE = Path('/var/lib/sawdoctor-nas-core-export')
OUTPUT = Path('/home/sawdoctor/nas-core-export')
WORKER = Path('/usr/local/sbin/nas-core-export')
READER = Path('/usr/local/sbin/nas-migration-export-read')
UNITS = Path('/etc/systemd/system')
TRANSFER_BLOB = 'AAAAC3NzaC1lZDI1NTE5AAAAILc56w99kcthdhVVsUuXQxChc1Smtlx6ju+xZPLNIpSE'
LAYOUT = {
    'sonarr': ('/home/sawdoctor/docker/media-apps/sonarr/config', '/config'),
    'radarr': ('/home/sawdoctor/docker/media-apps/radarr/config', '/config'),
    'radarr4k': ('/home/sawdoctor/docker/media-apps/radarr4k/config', '/config'),
    'overseerr': ('/home/sawdoctor/docker/media-apps/overseerr/config', '/app/config'),
    'prowlarr': ('/home/sawdoctor/docker/nzbdav/prowlarr_config', '/config'),
    'usenet-ultimate': ('/home/sawdoctor/docker/nzbdav/config', '/app/config'),
}
READER_SOURCE = '''#!/bin/sh
# Sawdoctor OptiPlex core export v1
case "${SSH_ORIGINAL_COMMAND-}" in
  ''|infinidysk) exec /bin/cat /home/sawdoctor/nas-infinidysk-export/export.tar.zst ;;
  core) exec /bin/cat /home/sawdoctor/nas-core-export/export.tar.zst ;;
  core-sha256) exec /bin/cat /home/sawdoctor/nas-core-export/export.sha256 ;;
  core-status) exec /bin/systemctl show nas-core-export.service -p ActiveState -p SubState -p Result ;;
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
    fd, temporary = tempfile.mkstemp(prefix='.nas-core-', dir=path.parent)
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
    containers = json.loads(run('docker', 'inspect', *LAYOUT, capture=True))
    by_name = {c['Name'].lstrip('/'): c for c in containers}
    if set(by_name) != set(LAYOUT):
        raise RuntimeError('The six source containers do not match the inventory.')
    for name, (source, destination) in LAYOUT.items():
        matches = [m for m in by_name[name]['Mounts'] if m['Destination'] == destination]
        if len(matches) != 1 or matches[0]['Source'] != source or matches[0]['Type'] != 'bind':
            raise RuntimeError('The configuration mount changed for ' + name + '.')
        path = Path(source)
        if path.is_symlink() or not path.is_dir():
            raise RuntimeError('Expected a real configuration directory for ' + name + '.')
        fs = run('findmnt', '-n', '-o', 'FSTYPE', '-T', source, capture=True).strip()
        if fs not in ('ext4', 'xfs', 'btrfs'):
            raise RuntimeError('The ' + name + ' configuration is not on a verified local filesystem.')
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


def sync_configs(work, live=False):
    for name, (source, _) in LAYOUT.items():
        target = work / 'configs' / name
        target.mkdir(parents=True, exist_ok=True)
        args = ['rsync', '-aHAX', '--numeric-ids', '--one-file-system', '--delete']
        if not live:
            args.append('--checksum')
        run(*args, '--', source + '/', str(target) + '/', allowed=(0, 24) if live else (0,))


def verify_sqlite(work):
    count = 0
    for directory, dirs, files in os.walk(work / 'configs', followlinks=False):
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


def export_core():
    archive = OUTPUT / 'export.tar.zst'
    resume()
    if OUTPUT.is_symlink():
        raise RuntimeError('Unexpected export output symlink.')
    account = pwd.getpwnam('sawdoctor')
    ssh_authorization(account)
    if archive.exists():
        log('A completed core export already exists; leaving it unchanged.')
        ssh_authorization(account, write=True)
        log('CORE EXPORT READY: ' + str(archive))
        log('SHA256=' + file_hash(archive))
        return
    containers = inspect_targets()
    stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
    work = BASE / ('work-' + stamp + '-' + str(os.getpid()))
    work.mkdir(mode=0o700)
    (work / 'compose').mkdir()
    image_ids = sorted({c['Image'] for c in containers.values()})
    images = json.loads(run('docker', 'image', 'inspect', *image_ids, capture=True))
    size_output = run('du', '-sbx', '--', *(source for source, _ in LAYOUT.values()), capture=True)
    config_size = sum(int(line.split()[0]) for line in size_output.splitlines())
    image_size = sum(item.get('Size', 0) for item in images)
    if shutil.disk_usage(BASE).free < 2 * (config_size + image_size) + 2 * 1024**3:
        raise RuntimeError('Not enough free OptiPlex space for staging and the archive.')
    manifest = {'format': 'sawdoctor-core-export-v1', 'sourceHost': '192.168.0.29',
        'createdUtc': stamp, 'containers': list(containers.values()), 'images': images,
        'configLayout': {name: {'source': paths[0], 'destination': paths[1],
            'snapshot': 'configs/' + name} for name, paths in LAYOUT.items()}, 'composeFiles': []}
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
    log('Pre-copying all six configuration directories while the applications run...')
    sync_configs(work, live=True)
    current = inspect_targets()
    if any(current[name]['Id'] != containers[name]['Id'] or current[name]['Image'] != containers[name]['Image'] for name in LAYOUT):
        raise RuntimeError('A source container changed during the pre-copy. Rerun to capture its current state.')
    running = [{'name': name, 'id': current[name]['Id']} for name in LAYOUT if current[name]['State']['Running']]
    atomic_text(BASE / 'running-containers.json', json.dumps(running) + '\n')
    try:
        log('Briefly pausing the six copied apps for a consistent final snapshot...')
        for item in running:
            run('docker', 'stop', '--timeout', '60', item['id'], capture=True)
        if any(c['State']['Running'] for c in inspect_targets().values()):
            raise RuntimeError('A copied application restarted during the snapshot.')
        sync_configs(work)
        if any(c['State']['Running'] for c in inspect_targets().values()):
            raise RuntimeError('A copied application restarted during the snapshot.')
    finally:
        resume()
    log('Source apps restored. Plex, InfiniDysk and NPM have remained running.')
    verify_sqlite(work)
    log('Saving the exact installed Docker images, including custom Usenet Ultimate...')
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
    log('CORE EXPORT READY: ' + str(archive))
    log('SHA256=' + checksum)
    log('Archive size: ' + str(round(archive.stat().st_size / 1024**3, 2)) + ' GiB')
    log('The existing NAS transfer key now supports the core export; its original InfiniDysk transfer still works.')


def install():
    for tool in ('rsync', 'zstd', 'docker', 'tar', 'findmnt', 'sha256sum'):
        if not shutil.which(tool):
            raise RuntimeError('Required tool is missing: ' + tool)
    if subprocess.run(['systemctl', 'is-active', '--quiet', 'nas-core-export.service']).returncode == 0:
        log('The core export is already running. Watch: sudo journalctl -u nas-core-export.service -f')
        return
    if subprocess.run(['systemctl', 'is-active', '--quiet', 'nas-infinidysk-export.service']).returncode == 0:
        raise RuntimeError('The earlier InfiniDysk export is still running; let it finish first.')
    for path in (BASE, OUTPUT, WORKER, READER, UNITS / 'nas-core-export.service', UNITS / 'nas-core-export-resume.service'):
        if path.is_symlink():
            raise RuntimeError('Unexpected symlink at an export installation path.')
        if path.is_file() and SIGNATURE not in path.read_text():
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
Description=Sawdoctor core export container recovery
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
Description=Sawdoctor core applications export for NAS migration
Requires=docker.service nas-core-export-resume.service
After=docker.service nas-core-export-resume.service
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
    atomic_text(UNITS / 'nas-core-export-resume.service', recovery, 0o644)
    atomic_text(UNITS / 'nas-core-export.service', service, 0o644)
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', 'nas-core-export-resume.service')
    run('systemctl', 'start', '--no-block', 'nas-core-export.service')
    log('Core export started in the background on the OptiPlex.')
    log('It snapshots Sonarr, both Radarrs, Prowlarr, Usenet Ultimate and Seerr together.')
    log('Watch: sudo journalctl -u nas-core-export.service -f')
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
            export_core()
        else:
            raise RuntimeError('Unknown export operation.')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit('\nInterrupted. The recovery service will restore paused containers.')
    except Exception as error:
        raise SystemExit('STOP: ' + str(error))
