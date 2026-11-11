#!/usr/bin/env python3
"""Prepare the NAS Plex import target without copying data or starting Plex.

Only a small private target plan is saved. A disposable, network-isolated
container runs the already installed image's SQLite --version command with no
Plex configuration mounted. It never invokes the Plex server entrypoint.
"""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

FORMAT = 'sawdoctor-nas-plex-handover-target-v1'
APP_UUID = 'e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6'
BACKUP_UUID = '631e3391-6a42-4158-9aa4-f7718ba0e7e9'
SCRATCH_UUID = '1f12a22e-5cfe-4b02-8d4b-48e9bf5fec6a'
APP = Path('/srv/dev-disk-by-uuid-' + APP_UUID)
BACKUP = Path('/srv/dev-disk-by-uuid-' + BACKUP_UUID)
SCRATCH = Path('/srv/dev-disk-by-uuid-' + SCRATCH_UUID)
DATA = APP / 'appdata/plex-nas'
LIBRARY = APP / 'appdata/infinidysk-nas/library'
BASE = APP / 'compose/plex-nas/recovery/production-handover'
INCOMING = APP / 'appdata/.plex-production-incoming'
ROLLBACK = BASE / 'nas-before'
IMAGES = APP / 'compose/plex-nas/image-identities.json'
SOURCE_IMAGE = 'sha256:0c2f1122a4275efeea953a9882359f3809b27279d3c3022392e8e610a2eccc67'
IMAGE_TAG = 'lscr.io/linuxserver/plex:1.43.5.11079-b3b13e506-ls331'
MAX_INCOMING_BYTES = 64 * 1024**3
RESERVE_BYTES = 4 * 1024**3
PREFS = Path('Library/Application Support/Plex Media Server/Preferences.xml')
DATABASE = Path('Library/Application Support/Plex Media Server/Plug-in Support/Databases/com.plexapp.plugins.library.db')
SQLITE = '/usr/lib/plexmediaserver/Plex SQLite'


def safe(path):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise RuntimeError('An unexpected symbolic import-plan/input path was retained.')


def read(path, limit=2 * 1024**2):
    safe(path)
    if not path.is_file() or path.stat().st_size > limit:
        raise RuntimeError('A required bounded NAS input is unavailable: ' + path.name)
    return path.read_bytes()


def run(*args, timeout=30):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('NAS target query/tool check failed: ' + args[0] + ' (exit ' + str(result.returncode) + '); private details withheld.')
    return result.stdout


def mounts():
    for path, uuid in ((APP, APP_UUID), (BACKUP, BACKUP_UUID), (SCRATCH, SCRATCH_UUID)):
        safe(path)
        if (not path.is_mount()
                or run('findmnt', '-rn', '--mountpoint', str(path), '-o', 'UUID,FSTYPE').split() != [uuid, 'ext4']):
            raise RuntimeError('An expected NAS filesystem UUID/type differs; current data retained.')
    # Probe only mount metadata, never read media payloads or trigger a scan.
    if 'fuse.rclone' not in run('findmnt', '-rn', '--mountpoint', '/mnt/nzbdav', '-o', 'FSTYPE').split():
        raise RuntimeError('The NAS nzbDAV FUSE mount is unavailable.')
    if 'fuse.main.py' not in run('findmnt', '-rn', '--mountpoint', '/mnt/torbox-media', '-o', 'FSTYPE').split():
        raise RuntimeError('The NAS TorBox FUSE mount is unavailable.')


def inspect():
    row, = json.loads(run('docker', 'inspect', 'plex-nas'))
    validate_container(row, json.loads(read(IMAGES)))
    return row


def validate_container(row, images):
    if (row['Name'] != '/plex-nas' or row['State']['Running']
            or row['State']['Status'] not in ('exited', 'created')
            or row['Config']['Image'] != IMAGE_TAG
            or row['HostConfig']['RestartPolicy']['Name'] != 'no'
            or row['HostConfig']['NetworkMode'] != 'host'
            or row['HostConfig'].get('Privileged')):
        raise RuntimeError('NAS Plex must remain stopped with its reviewed image/network/restart policy.')
    expected = {'/config': (DATA / 'config', True),
                '/flora-test-library': (DATA / 'flora-test-library', False),
                '/scratch': (SCRATCH, True), '/mnt/media': (LIBRARY, False),
                '/mnt/nzbdav': (Path('/mnt/nzbdav'), False),
                '/torbox-cams': (Path('/mnt/torbox-media/movies'), False)}
    actual = {m['Destination']: (Path(m['Source']), m['RW']) for m in row['Mounts'] if m['Type'] == 'bind'}
    if len(row['Mounts']) != len(expected) or actual != expected:
        raise RuntimeError('A NAS Plex import/media binding or access mode differs; current data retained.')
    if row['HostConfig'].get('Devices') != [
            {'PathOnHost': '/dev/dri', 'PathInContainer': '/dev/dri', 'CgroupPermissions': 'rwm'}]:
        raise RuntimeError('The reviewed Intel graphics binding differs.')
    if images.get('plex', {}).get('source') != SOURCE_IMAGE or images.get('plex', {}).get('nas') != row['Image']:
        raise RuntimeError('The verified source/NAS Plex image mapping differs.')
    env = dict(v.split('=', 1) for v in row['Config'].get('Env', []) if '=' in v)
    if env.get('VERSION') != 'docker' or not all(re.fullmatch(r'\d{1,9}', env.get(k, '')) for k in ('PUID', 'PGID')):
        raise RuntimeError('NAS Plex runtime user/version settings differ; no image update was attempted.')
    return int(env['PUID']), int(env['PGID'])


def identity():
    prefs = ET.fromstring(read(DATA / 'config' / PREFS))
    values = {k: prefs.get(k, '') for k in ('MachineIdentifier', 'ProcessedMachineIdentifier')}
    if not values['MachineIdentifier'] or not re.fullmatch(r'[0-9a-fA-F]{40}', values['ProcessedMachineIdentifier']):
        raise RuntimeError('The existing NAS Plex identity is incomplete; existing data retained.')
    return {k + 'Sha256': hashlib.sha256(v.encode()).hexdigest() for k, v in values.items()}


def sqlite_probe(row, uid, gid):
    # No /config mount or token/environment is passed. Override the image's
    # normal entrypoint so the Plex server cannot start in this tool container.
    version = run('docker', 'run', '--rm', '--pull=never', '--network=none', '--read-only',
                  '--user', f'{uid}:{gid}', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                  '--pids-limit=64', '--memory=512m', '--cpus=1',
                  '--entrypoint', SQLITE, row['Image'], '--version', timeout=45).strip()
    if len(version) > 512 or not re.match(r'^3\.\d+\.\d+(?:\s|$)', version):
        raise RuntimeError('The installed Plex SQLite version response differs; no Plex data was opened.')
    return version.split()[0]


def fingerprint(row):
    return {'containerId': row['Id'], 'imageId': row['Image'], 'status': row['State']['Status'],
            'startedAt': row['State']['StartedAt'], 'finishedAt': row['State']['FinishedAt'],
            'restartPolicy': row['HostConfig']['RestartPolicy'], 'mounts': row['Mounts'],
            'network': row['HostConfig']['NetworkMode'], 'devices': row['HostConfig']['Devices']}


def estimate():
    total = 0
    for leaf in ('config', 'flora-test-library'):
        root = DATA / leaf
        safe(root)
        if not root.is_dir() or root.is_mount():
            raise RuntimeError('An existing NAS Plex data root differs; current data retained.')
        total += int(run('du', '-sbx', '--', str(root), timeout=120).split()[0])
    # Current stopped database existence only. Integrity of the final frozen
    # source and received database must be checked with Plex SQLite later.
    db = DATA / 'config' / DATABASE
    safe(db)
    if not db.is_file() or db.stat().st_size < 4096:
        raise RuntimeError('The existing NAS Plex database is unavailable.')
    if DATA.stat().st_dev != BASE.parent.stat().st_dev:
        raise RuntimeError('The proposed NAS rollback is not on the same filesystem.')
    free = shutil.disk_usage(APP).free
    if free < MAX_INCOMING_BYTES + RESERVE_BYTES:
        raise RuntimeError('The NAS appdata SSD lacks the bounded import budget plus reserve.')
    return {'existingNasPlexBytes': total, 'availableAppBytesAtPreparation': free,
            'incomingPayloadLimitBytes': MAX_INCOMING_BYTES, 'minimumReserveBytes': RESERVE_BYTES,
            'extraFullArchiveBytes': 0, 'extraRollbackCopyBytes': 0,
            'rollbackMethod': 'same-filesystem rename of existing stopped NAS config/Flora roots',
            'spaceMustBeRecheckedBeforeReceive': True}


def atomic(path, value):
    safe(path)
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def save(plan):
    safe(BASE)
    if BASE.exists():
        if json.loads(read(BASE / 'owner.json')) != {'format': FORMAT}:
            raise RuntimeError('An unrecognized NAS handover folder was retained.')
        if {p.name for p in BASE.iterdir()} - {'owner.json', 'target-plan.json'}:
            raise RuntimeError('The NAS handover has additional state; review before replacing its target plan.')
        previous = json.loads(read(BASE / 'target-plan.json'))
        if previous.get('container') != plan['container'] or previous.get('existingNasIdentity') != plan['existingNasIdentity']:
            raise RuntimeError('NAS Plex inputs changed since the saved target plan; existing plan retained.')
    else:
        BASE.mkdir(mode=0o700, parents=True)
        atomic(BASE / 'owner.json', (json.dumps({'format': FORMAT}) + '\n').encode())
    atomic(BASE / 'target-plan.json', (json.dumps(plan, indent=2) + '\n').encode())
    fd = os.open(BASE, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def prepare():
    mounts()
    for path in (INCOMING, ROLLBACK):
        safe(path)
        if path.exists():
            raise RuntimeError('An incoming/rollback path already exists; no data was overwritten.')
    row = inspect()
    before = fingerprint(row)
    uid, gid = validate_container(row, json.loads(read(IMAGES)))
    current_identity = identity()
    budget = estimate()
    version = sqlite_probe(row, uid, gid)
    if fingerprint(inspect()) != before or identity() != current_identity:
        raise RuntimeError('NAS Plex changed during target preparation; no plan published.')
    plan = {'format': FORMAT, 'preparedUtc': dt.datetime.now(dt.timezone.utc).isoformat(),
            'phase': 'target-prepared-no-import', 'container': before,
            'existingNasIdentity': current_identity, 'plexSqliteVersion': version,
            'plexSqliteEntrypoint': SQLITE, 'runtimeUid': uid, 'runtimeGid': gid,
            'existingData': str(DATA), 'incomingRoot': str(INCOMING), 'rollbackRoot': str(ROLLBACK),
            'storageBudget': budget, 'sourceHeldProofRequired': True,
            'nasOnlyMediaAndApplicationDataMustBeRetained': True,
            'copiedPlexBytes': 0, 'plexStarted': False,
            'pending': ['Reviewed persistent source hold activation/release and in-flight helper draining.',
                        'Frozen seed delta, streaming transfer and metadata/checksum/database verification.',
                        'Fresh media/catalogue reconciliation preserving NAS-only content.',
                        'Explicit cutover approval and interruption window.']}
    save(plan)
    gib = lambda n: round(n / 1024**3, 1)
    print('NAS PLEX HANDOVER TARGET PREPARED. Plex remains stopped; restart=no.', flush=True)
    print('Verified: six bindings, source/NAS image mapping, Intel graphics and current FUSE mounts.', flush=True)
    print('Installed-image SQLite tool: ' + version + ' (isolated CLI only; no Plex config mounted).', flush=True)
    print('Existing NAS Plex/Flora: ' + str(gib(budget['existingNasPlexBytes'])) + ' GiB; app SSD free: '
          + str(gib(budget['availableAppBytesAtPreparation'])) + ' GiB.', flush=True)
    print('Import plan: one incoming copy, maximum 64 GiB; 4 GiB reserve; existing NAS roots retained by rename.', flush=True)
    print('No Plex data copied, renamed or started. InfiniDysk, media, Silo, backups and routes retained.', flush=True)
    print('Private target plan: ' + str(BASE / 'target-plan.json'), flush=True)
    print('Hold activation, consistent transfer/import and cutover approval remain pending.', flush=True)


def main():
    os.umask(0o077)
    if sys.argv[1:]:
        raise RuntimeError('This target preparer takes no activation/import arguments.')
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the NAS, SSH port 48223.')
    prepare()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('STOP: ' + (str(error) if isinstance(error, RuntimeError)
                                   else 'NAS target preparation failed (' + type(error).__name__ + '); private details withheld.'))
