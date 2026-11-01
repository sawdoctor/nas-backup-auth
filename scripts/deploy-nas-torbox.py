#!/usr/bin/env python3
"""Sawdoctor NAS TorBox CAM runtime v1.

Install the copied, patched TorBox image without altering the OptiPlex. This
file remains the runtime helper for boot and coordinated backup recovery.
"""
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import traceback

SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
SNAPSHOT = SSD / 'migration/books-optiplex/snapshot'
DATA = SSD / 'appdata/torbox-media-center-nas'
STACK = SSD / 'compose/torbox-media-center-nas'
MOUNT = Path('/mnt/torbox-media')
WORKER = Path('/usr/local/sbin/nas-torbox-media')
UNIT = Path('/etc/systemd/system/nas-torbox-media.service')
BACKUP_WORKER = Path('/usr/local/sbin/nas-backup')
BACKUP_SHA = '2b102359b0cc015034bfd7f32971b76a2355c60dd87fffeddf6075438820c790'
LOCK = Path('/run/lock/sawdoctor-nas-backup.lock')
OWNER = Path('/run/nas-torbox-media/mount-owner.json')
STATE = OWNER.parent / 'backup-resume.json'
WATCH_STATE = OWNER.parent / 'deadlock-count.json'
WATCH_SERVICE = Path('/etc/systemd/system/nas-torbox-watch.service')
WATCH_TIMER = Path('/etc/systemd/system/nas-torbox-watch.timer')
NAME = 'torbox-media-center-nas'
PROJECT = NAME
SIGNATURE = 'Sawdoctor NAS TorBox CAM runtime v1'
CORE_SHA = '8ebc4f735c61c5f0ea29c509b1bd6279efc05741675ad4e7370ee3b39c71065e'
PATCHES = {'/app/functions/fuseFilesystemFunctions.py',
           '/app/functions/torboxFunctions.py', '/app/library/http.py'}


def log(text):
    print(text, flush=True)


def run(*args, check=True, timeout=120):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, timeout=timeout)
    if check and result.returncode:
        if STACK.is_dir():
            atomic(STACK / 'command-error.log', result.stdout + '\n' + result.stderr)
        raise RuntimeError('A NAS command failed; details are saved privately in the TorBox Compose folder.')
    return result


def atomic(path, text, mode=0o600):
    if path.is_symlink():
        raise RuntimeError('An unexpected symbolic configuration path needs review.')
    fd, temporary = tempfile.mkstemp(prefix='.nas-torbox-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(text); stream.flush(); os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_json(path, value):
    atomic(path, json.dumps(value, indent=2) + '\n')


@contextlib.contextmanager
def locked():
    with LOCK.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def guard():
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show').stdout:
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220.')
    if not SSD.is_mount() or not Path('/dev/fuse').exists():
        raise RuntimeError('The NAS application SSD and /dev/fuse must be available.')
    paths = [DATA, STACK, OWNER.parent, WORKER, UNIT, BACKUP_WORKER, WATCH_SERVICE, WATCH_TIMER]
    if not mounts():
        paths.append(MOUNT)
    for path in paths:
        if path.is_symlink():
            raise RuntimeError('An unexpected symbolic TorBox installation path needs review.')


def compose(*args, timeout=120):
    return run('docker', 'compose', '-p', PROJECT, '-f', str(STACK / 'compose.json'),
               *args, timeout=timeout)


def inspect(name):
    result = run('docker', 'inspect', name, check=False)
    if result.returncode:
        return None
    return json.loads(result.stdout)[0]


def owned_container():
    container = inspect(NAME)
    if container and container['Config'].get('Labels', {}).get('com.docker.compose.project') != PROJECT:
        raise RuntimeError('The NAS TorBox container name is already in use by another project.')
    return container


def check_install():
    marker = STACK / 'install.json'
    if not marker.is_file() or marker.is_symlink():
        raise RuntimeError('The NAS TorBox runtime has not been prepared.')
    if json.loads(marker.read_text()).get('format') != SIGNATURE:
        raise RuntimeError('Unexpected NAS TorBox installation metadata.')
    owned_container()


def file_hash(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(8 * 1024**2), b''):
            result.update(block)
    return result.hexdigest()


def source_snapshot():
    manifest = json.loads((SNAPSHOT / 'manifest.json').read_text())
    if manifest.get('format') != 'sawdoctor-books-export-v1' or manifest.get('sourceHost') != '192.168.0.29':
        raise RuntimeError('The verified OptiPlex book snapshot is not available.')
    containers = [c for c in manifest['containers'] if c['Name'].lstrip('/') == 'torbox-media-center']
    if len(containers) != 1:
        raise RuntimeError('The original TorBox container record is missing or ambiguous.')
    container = containers[0]
    environment = dict(item.split('=', 1) for item in container['Config'].get('Env', []) if '=' in item)
    if environment.get('MOUNT_METHOD') != 'fuse' or environment.get('MOUNT_PATH') != '/torbox' or not environment.get('TORBOX_API_KEY'):
        raise RuntimeError('The copied TorBox FUSE settings differ from the checked source.')
    sums = {}
    for line in (SNAPSHOT / 'SHA256SUMS').read_text().splitlines():
        if len(line) >= 67 and line[64:66] in ('  ', ' *'):
            sums[line[66:].removeprefix('./')] = line[:64]
    roots = manifest['dataRoots'].values()
    patches = {}; media_binds = 0
    for mount in container['Mounts']:
        if mount['Destination'] == '/torbox':
            media_binds += 1
            if mount['Source'] != str(MOUNT) or mount.get('Propagation') != 'rshared':
                raise RuntimeError('The copied shared TorBox mount differs from the checked source.')
            continue
        if mount['Destination'] not in PATCHES or mount['Type'] != 'bind' or mount['RW']:
            raise RuntimeError('An unrecognized TorBox binding needs review.')
        source = Path(mount['Source'])
        matching = [root for root in roots if source.is_relative_to(Path(root['source']))]
        if not matching:
            raise RuntimeError('A TorBox patch is not in the copied data roots.')
        root = max(matching, key=lambda item: len(item['source']))
        path = SNAPSHOT / root['snapshot'] / source.relative_to(Path(root['source']))
        if (not path.resolve().is_relative_to(SNAPSHOT.resolve()) or path.is_symlink()
                or not path.is_file() or file_hash(path) != sums.get(path.relative_to(SNAPSHOT).as_posix())):
            raise RuntimeError('A copied TorBox patch failed verification.')
        patches[mount['Destination']] = path
    if set(patches) != PATCHES or media_binds != 1:
        raise RuntimeError('The three custom playback patches are required.')
    if file_hash(SNAPSHOT / 'images.tar') != sums.get('images.tar'):
        raise RuntimeError('The copied image archive failed verification.')
    return manifest, container, patches


def verifier():
    path = Path('/usr/local/sbin/nas-core-deploy.py')
    if file_hash(path) != CORE_SHA:
        raise RuntimeError('The installed cross-format image verifier is not the tested version.')
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('torbox_image_verifier', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def exact_image(manifest, source):
    helper = verifier()
    identities, configs = helper.archive_image_identities(SNAPSHOT / 'images.tar')
    metadata = next((item for item in manifest['images'] if item['Id'] == source['Image']), {})
    candidates = {digest for digest in identities.get(source['Image'], set())
                  if configs[digest].get('os') == metadata.get('Os')
                  and configs[digest].get('architecture') == metadata.get('Architecture')
                  and configs[digest]['rootfs'].get('diff_ids') == metadata.get('RootFS', {}).get('Layers')}
    if len(candidates) != 1:
        raise RuntimeError('The original TorBox image identity is not unique.')
    expected = next(iter(candidates)); config = configs[expected]
    ids = sorted(set(run('docker', 'image', 'ls', '-q', '--no-trunc').stdout.split()))
    local = json.loads(run('docker', 'image', 'inspect', *ids).stdout) if ids else []
    for image in local:
        if (image.get('Os') != config.get('os') or image.get('Architecture') != config.get('architecture')
                or image.get('Variant', '') != config.get('variant', '')
                or image.get('RootFS', {}).get('Layers') != config['rootfs'].get('diff_ids')):
            continue
        proven = image['Id'] == expected
        if not proven:
            with tempfile.TemporaryDirectory(prefix='.torbox-image-', dir=STACK) as temporary:
                saved = Path(temporary) / 'image.tar'
                run('docker', 'image', 'save', '-o', str(saved), image['Id'], timeout=600)
                saved_ids, saved_configs = helper.archive_image_identities(saved)
                selected = {digest for digest in saved_ids.get(image['Id'], set())
                            if saved_configs[digest].get('os') == config.get('os')
                            and saved_configs[digest].get('architecture') == config.get('architecture')}
                proven = selected == {expected}
        if proven:
            write_json(STACK / 'image-identities.json', {'torbox-media-center':
                       {'source': source['Image'], 'nas': image['Id'], 'config': expected}})
            log('Reusing the exact copied TorBox image; configuration and layers verified.')
            return image['Id']
    log('The TorBox image needs loading from the verified local archive; no online update will be pulled.')
    return helper.load_verified_images(SNAPSHOT, manifest, {'torbox-media-center': source}, STACK)['torbox-media-center']


def literal(value):
    if isinstance(value, str):
        return value.replace('$', '$$')
    if isinstance(value, list):
        return [literal(item) for item in value]
    return value


def compose_document(source, image):
    config, host = source['Config'], source['HostConfig']
    if host.get('Privileged') or host.get('NetworkMode') in ('host', 'none'):
        raise RuntimeError('Unexpected TorBox privileges or networking need review.')
    service = {'image': image, 'container_name': NAME, 'restart': 'on-failure:5',
               'labels': {'com.sawdoctor.backup.static-mount': SIGNATURE},
               'environment': {k: literal(v) for k, v in
                               (item.split('=', 1) for item in config.get('Env', []) if '=' in item)},
               'volumes': [], 'cap_add': [item.removeprefix('CAP_') for item in host.get('CapAdd') or []],
               'security_opt': host.get('SecurityOpt') or [],
               'devices': [item['PathOnHost'] + ':' + item['PathInContainer'] + ':' + item['CgroupPermissions']
                           for item in host.get('Devices') or []],
               'stdin_open': bool(config.get('OpenStdin')), 'tty': bool(config.get('Tty'))}
    if '/dev/fuse:/dev/fuse:rwm' not in service['devices'] or 'SYS_ADMIN' not in service['cap_add']:
        raise RuntimeError('The original FUSE device and capability are required.')
    for destination in sorted(PATCHES):
        service['volumes'].append({'type': 'bind', 'source': str(DATA / destination.removeprefix('/app/')),
                                   'target': destination, 'read_only': True,
                                   'bind': {'create_host_path': False}})
    service['volumes'].append({'type': 'bind', 'source': str(MOUNT), 'target': '/torbox',
                               'bind': {'propagation': 'rshared', 'create_host_path': False}})
    for key, target in (('Entrypoint', 'entrypoint'), ('Cmd', 'command'), ('User', 'user'), ('WorkingDir', 'working_dir')):
        if config.get(key) is not None and config.get(key) != '':
            service[target] = literal(config[key])
    if host.get('Init'):
        service['init'] = True
    if host.get('Memory'):
        service['mem_limit'] = host['Memory']
    return {'name': PROJECT, 'services': {'torbox-media-center': service}}


def mounts(target=None):
    target = MOUNT if target is None else Path(target)
    def unescape(value):
        return re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), value)
    result = []
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        left, right = line.split(' - ', 1); fields = left.split(); tail = right.split()
        if unescape(fields[4]) == str(target):
            major, minor = (int(value) for value in fields[2].split(':'))
            result.append({'id': int(fields[0]), 'type': tail[0], 'source': unescape(tail[1]),
                           'device': os.makedev(major, minor),
                           'shared': any(item.startswith('shared:') for item in fields[6:])})
    return result


def is_fuse(record):
    return record['type'] == 'fuse.main.py' or (record['type'] == 'fuse' and 'main.py' in record['source'])


def owner_record():
    if not OWNER.exists():
        return None
    value = json.loads(OWNER.read_text())
    if value.get('format') != SIGNATURE:
        raise RuntimeError('Unexpected TorBox mount ownership record.')
    return value


def remove_stale_fuse():
    owner = owner_record()
    for _ in range(4):
        current = mounts()
        if not current or not is_fuse(current[-1]):
            return
        if not owner or not any(item['id'] == owner['mountId'] for item in current):
            raise RuntimeError('An unowned FUSE mount at the TorBox path needs review.')
        run('umount', '--no-canonicalize', '--lazy', str(MOUNT), timeout=20)
    raise RuntimeError('The TorBox mount could not be detached cleanly.')


def prepare_mount():
    MOUNT.mkdir(mode=0o755, parents=True, exist_ok=True)
    current = mounts(); owner = owner_record()
    if current:
        if len(current) != 1 or not owner or current[0]['id'] != owner['mountId'] or is_fuse(current[0]):
            raise RuntimeError('An existing mount at /mnt/torbox-media is not owned by this runtime.')
    else:
        if any(MOUNT.iterdir()):
            raise RuntimeError('The unmounted TorBox directory contains local files; leaving them untouched.')
        os.chown(MOUNT, 1000, 1000); MOUNT.chmod(0o755)
        run('mount', '--bind', str(MOUNT), str(MOUNT))
        # Give this dedicated bind its own propagation group, without changing
        # the root filesystem or any other media mount.
        run('mount', '--make-private', str(MOUNT))
        current = mounts()
        if len(current) != 1:
            raise RuntimeError('The dedicated TorBox bind mount could not be established.')
        OWNER.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_json(OWNER, {'format': SIGNATURE, 'mountId': current[0]['id']})
    run('mount', '--make-rshared', str(MOUNT))
    if not mounts()[-1]['shared']:
        raise RuntimeError('The TorBox mount is not shared with its container.')


def wait_ready():
    deadline = time.monotonic() + 420
    while time.monotonic() < deadline:
        container = owned_container()
        if container and container['State']['Running'] and mounts() and is_fuse(mounts()[-1]):
            try:
                probe = run('/usr/bin/python3', '-c',
                            'import os; p="/mnt/torbox-media/movies"; s=os.scandir(p); next(s,None); s.close()',
                            check=False, timeout=15)
            except subprocess.TimeoutExpired:
                time.sleep(3)
                continue
            if probe.returncode == 0:
                return
        time.sleep(3)
    raise RuntimeError('The NAS TorBox host mount did not become ready; private logs are retained.')


def start():
    with locked():
        check_install()
        container = owned_container()
        if container and container['State']['Running']:
            if mounts() and is_fuse(mounts()[-1]):
                wait_ready(); return
            compose('stop', '--timeout', '30')
        log('Preparing the dedicated NAS TorBox shared mount...')
        remove_stale_fuse(); prepare_mount()
        log('Starting the patched TorBox container and checking host visibility...')
        compose('up', '-d', '--pull', 'never', '--no-build')
        wait_ready()
        log('NAS TorBox mount ready: /mnt/torbox-media (CAMs: /mnt/torbox-media/movies).')


def stop():
    with locked():
        check_install()
        consumers = mount_consumers()
        if consumers:
            if STATE.exists():
                prior = json.loads(STATE.read_text())
                if prior.get('format') != SIGNATURE:
                    raise RuntimeError('Unexpected pending CAM consumer recovery state.')
                consumers = list(dict.fromkeys(prior['consumers'] + consumers))
            write_json(STATE, {'format': SIGNATURE, 'consumers': consumers})
            run('docker', 'stop', '--timeout', '30', *consumers)
        if owned_container():
            compose('stop', '--timeout', '30')
        remove_stale_fuse()


def mount_consumers():
    ids = run('docker', 'ps', '-q').stdout.split()
    containers = json.loads(run('docker', 'inspect', *ids).stdout) if ids else []
    return [c['Id'] for c in containers if c['Name'].lstrip('/') != NAME
            and any(Path(m.get('Source', '/')).is_relative_to(MOUNT) for m in c.get('Mounts', []))]


def backup_list():
    # Called while the backup coordinator already owns LOCK. The TMC image
    # has no persistent database bind: only three immutable patch files and
    # its Compose settings need archiving. Leave its live FUSE mount online.
    check_install()
    identities = run('docker', 'ps', '-q', '--no-trunc').stdout.split()
    containers = json.loads(run('docker', 'inspect', *identities).stdout) if identities else []
    result = []
    for container in containers:
        if container['Name'].lstrip('/') == NAME:
            labels = container['Config'].get('Labels') or {}
            if (labels.get('com.docker.compose.project') != PROJECT
                    or labels.get('com.sawdoctor.backup.static-mount') != SIGNATURE):
                raise RuntimeError('The live TorBox backup exemption no longer matches its static configuration.')
            continue
        result.append(container['Id'])
    if any(not re.fullmatch(r'[0-9a-f]{64}', identity) for identity in result):
        raise RuntimeError('An invalid container identity was rejected before creating backup recovery state.')
    for identity in result:
        print(identity)


def resume_clients_locked():
    if not STATE.exists():
        return
    state = json.loads(STATE.read_text())
    if state.get('format') != SIGNATURE:
        raise RuntimeError('Unexpected TorBox recovery metadata.')
    wait_ready()
    for identity in state['consumers']:
        if not re.fullmatch(r'[0-9a-f]{64}', identity):
            raise RuntimeError('Invalid TorBox consumer recovery identity.')
        container = inspect(identity)
        if not container:
            raise RuntimeError('A TorBox consumer changed during recovery; its prior state was retained.')
        if not container['State']['Running']:
            run('docker', 'start', identity)
    STATE.unlink()
    log('TorBox recovery complete; prior CAM consumers restored after the mount.')


def resume_clients():
    with locked():
        resume_clients_locked()


def backup_patch(original):
    old = 'docker ps -q --no-trunc > "$STATE"'
    if original.count(old) != 1:
        raise RuntimeError('The NAS backup container selection differs from the checked version.')
    new = ('# ' + SIGNATURE + ': archive static settings without stopping the live FUSE provider.\n'
           + str(WORKER) + ' backup-list > "$STATE"')
    return original.replace(old, new)


def install_backup_filter():
    original = BACKUP_WORKER.read_bytes()
    recovery = STACK / 'recovery'
    saved = recovery / 'nas-backup.before-torbox'
    if hashlib.sha256(original).hexdigest() == BACKUP_SHA:
        recovery.mkdir(mode=0o700, exist_ok=True)
        if saved.exists() and file_hash(saved) != BACKUP_SHA:
            raise RuntimeError('The saved NAS backup recovery copy differs from the original version.')
        atomic(saved, original.decode())
        updated = backup_patch(original.decode())
        with tempfile.NamedTemporaryFile('w', dir=STACK) as syntax:
            syntax.write(updated); syntax.flush()
            run('/bin/bash', '-n', syntax.name)
        atomic(BACKUP_WORKER, updated, BACKUP_WORKER.stat().st_mode & 0o777)
    elif not saved.is_file() or file_hash(saved) != BACKUP_SHA or original.decode() != backup_patch(saved.read_text()):
        raise RuntimeError('The NAS backup worker changed; leaving it untouched for review.')


def plex_fuse_blocked(container):
    output = run('docker', 'top', container['Id'], '-eo', 'pid,stat,comm', timeout=10).stdout
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 2 or not fields[0].isdigit() or not fields[1].startswith('D'):
            continue
        try:
            if 'fuse' in (Path('/proc') / fields[0] / 'stack').read_text().lower():
                return True
        except OSError:
            pass
    return False


def waiting(record):
    path = Path('/sys/fs/fuse/connections') / str(record['device']) / 'waiting'
    try:
        value = path.read_text().strip()
    except OSError:
        return None
    return int(value) if value.isdigit() else None


def watch():
    # Preserve the OptiPlex's conservative three-sample deadlock detection.
    # Do not queue a recovery behind a backup or start deliberately stopped apps.
    with LOCK.open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        check_install()
        active = run('systemctl', 'is-active', '--quiet', UNIT.name, check=False).returncode == 0
        provider = owned_container()
        players = []
        if active and provider and provider['State']['Running'] and not STATE.exists():
            for name in ('plex-nas', 'plex'):
                player = inspect(name)
                if player and player['State']['Running'] and any(
                        Path(item.get('Source', '/')).is_relative_to(MOUNT) for item in player.get('Mounts', [])):
                    players.append(player)
        current, nzb = mounts(), mounts('/mnt/nzbdav')
        if not players or not current or not is_fuse(current[-1]) or not nzb or nzb[-1]['type'] != 'fuse.rclone':
            WATCH_STATE.unlink(missing_ok=True); return
        tor_wait, nzb_wait = waiting(current[-1]), waiting(nzb[-1])
        if tor_wait is None or tor_wait <= 0 or nzb_wait != 0 or not any(plex_fuse_blocked(player) for player in players):
            WATCH_STATE.unlink(missing_ok=True); return
        generation = {'connection': current[-1]['device'], 'players': sorted(player['Id'] for player in players)}
        old = json.loads(WATCH_STATE.read_text()) if WATCH_STATE.is_file() else {}
        count = old.get('count', 0) + 1 if old.get('generation') == generation else 1
        write_json(WATCH_STATE, {'generation': generation, 'count': count})
        log('TorBox deadlock check: blocked Plex FUSE request, sample ' + str(count) + '/3.')
        if count < 3:
            return
        owner = owner_record()
        if not owner or not any(record['id'] == owner['mountId'] for record in current):
            raise RuntimeError('TorBox recovery refused an unowned FUSE connection.')
        # Recheck the generation immediately before touching its abort control.
        latest = mounts()
        if not latest or latest[-1]['device'] != generation['connection'] or not is_fuse(latest[-1]):
            WATCH_STATE.unlink(missing_ok=True); return
        abort = Path('/sys/fs/fuse/connections') / str(generation['connection']) / 'abort'
        if not abort.is_file() or not os.access(abort, os.W_OK):
            raise RuntimeError('The TorBox FUSE abort control is unavailable; no containers were stopped.')
        consumers = mount_consumers()
        write_json(STATE, {'format': SIGNATURE, 'consumers': consumers})
        abort.write_text('1\n')
        log('Confirmed TorBox FUSE deadlock; recovering its mount and prior CAM consumers.')
        if consumers:
            run('docker', 'stop', '--timeout', '30', *consumers)
        compose('stop', '--timeout', '30')
        remove_stale_fuse(); prepare_mount()
        compose('up', '-d', '--pull', 'never', '--no-build')
        wait_ready(); resume_clients_locked()
        WATCH_STATE.unlink(missing_ok=True)


def install_units():
    unit = f'''# {SIGNATURE}
[Unit]
Description=NAS TorBox CAM mount with copied playback patches
Requires=docker.service
Wants=network-online.target nas-backup-resume.service
After=docker.service network-online.target nas-backup-resume.service
PartOf=docker.service
RequiresMountsFor={SSD}

[Service]
Type=oneshot
RemainAfterExit=yes
UMask=0077
ExecStart={WORKER} start
ExecStartPost={WORKER} resume-clients
ExecStop={WORKER} stop
TimeoutStartSec=600
TimeoutStopSec=120

[Install]
WantedBy=multi-user.target
'''
    watch_service = f'''# {SIGNATURE}
[Unit]
Description=Detect proven NAS TorBox FUSE deadlocks affecting Plex
Requires=docker.service
After=docker.service nas-torbox-media.service

[Service]
Type=oneshot
UMask=0077
ExecStart={WORKER} watch
TimeoutStartSec=600
'''
    watch_timer = f'''# {SIGNATURE}
[Unit]
Description=Check NAS TorBox Plex deadlock signature

[Timer]
OnBootSec=2min
OnUnitActiveSec=30s
Unit={WATCH_SERVICE.name}

[Install]
WantedBy=timers.target
'''
    for path, text in ((UNIT, unit), (WATCH_SERVICE, watch_service), (WATCH_TIMER, watch_timer)):
        if path.exists() and SIGNATURE not in path.read_text():
            raise RuntimeError('An existing TorBox systemd file needs review before replacement.')
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        atomic(path, text, 0o644)


def sample_read():
    program = '''import os
count=0
for root,dirs,files in os.walk('/mnt/torbox-media/movies',followlinks=False):
    count+=1
    if count>500:break
    for name in sorted(files):
        if name.lower().endswith(('.mkv','.mp4','.avi','.m4v','.ts')):
            with open(os.path.join(root,name),'rb') as stream:data=stream.read(1048576)
            if not data:raise RuntimeError('Empty sample')
            print('CAM sample read verified: '+str(len(data))+' bytes.');raise SystemExit(0)
print('CAM folder is readable; no movie file is currently available for a sample read.')
'''
    result = run('/usr/bin/python3', '-c', program, check=False, timeout=90)
    if result.returncode:
        atomic(STACK / 'sample-read-error.log', result.stderr)
        raise RuntimeError('The mount is running, but its sample file read failed; details were saved privately.')
    log(result.stdout.strip())


def deploy():
    log('Checking the copied TorBox configuration, custom patches and exact image archive...')
    manifest, source, patches = source_snapshot()
    log('Waiting for the NAS backup lock...')
    with locked():
        if STACK.exists() and any(STACK.iterdir()) and not (STACK / 'install.json').is_file():
            raise RuntimeError('An unrecognized TorBox Compose folder already exists.')
        STACK.mkdir(mode=0o700, parents=True, exist_ok=True)
        marker = STACK / 'install.json'
        prepared = marker.is_file()
        if prepared:
            check_install()
        else:
            if DATA.exists():
                raise RuntimeError('An existing NAS TorBox data folder needs review before copying.')
            write_json(marker, {'format': SIGNATURE, 'complete': False, 'prepared': False})
        state = json.loads(marker.read_text())
        if not state.get('prepared'):
            image = exact_image(manifest, source)
            owner = DATA / '.runtime-owner.json'
            if DATA.exists():
                if not owner.is_file() or owner.is_symlink() or json.loads(owner.read_text()).get('format') != SIGNATURE:
                    raise RuntimeError('An existing NAS TorBox data folder needs review before copying.')
                for destination, original in patches.items():
                    path = DATA / destination.removeprefix('/app/')
                    if path.is_symlink() or not path.is_file() or file_hash(path) != file_hash(original):
                        raise RuntimeError('Previously staged TorBox patches changed; leaving them untouched.')
            else:
                with tempfile.TemporaryDirectory(prefix='.torbox-data-', dir=DATA.parent) as directory:
                    work = Path(directory) / 'data'; work.mkdir(mode=0o700)
                    for destination, original in patches.items():
                        path = work / destination.removeprefix('/app/')
                        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                        run('cp', '-a', '--', str(original), str(path))
                    write_json(work / '.runtime-owner.json', {'format': SIGNATURE})
                    work.rename(DATA)
            document = compose_document(source, image)
            existing = STACK / 'compose.json'
            if existing.exists() and json.loads(existing.read_text()) != document:
                raise RuntimeError('Existing NAS TorBox settings differ; leaving them untouched.')
            write_json(existing, document)
            write_json(marker, {'format': SIGNATURE, 'complete': False, 'prepared': True,
                               'sourceCreatedUtc': manifest.get('createdUtc'), 'image': image,
                               'sourceImage': source['Image'], 'sourceReference': source['Config']['Image'],
                               'sourceRepoDigests': next((item.get('RepoDigests', []) for item in manifest['images']
                                                          if item['Id'] == source['Image']), [])})
        # Compose validation prints no environment or credentials.
        compose('config', '--quiet')
        install_backup_filter()
        install_units()
    # Starting a unit while holding its runtime lock would deadlock.
    run('systemctl', 'daemon-reload')
    log('Starting the NAS TorBox mount service; production OptiPlex services remain in place...')
    run('systemctl', 'enable', '--now', UNIT.name, timeout=660)
    log('Checking a small CAM file read through the NAS host mount...')
    sample_read()
    with locked():
        state = json.loads(marker.read_text()); state['complete'] = True
        write_json(marker, state)
    log('NAS TORBOX CAM MOUNT READY. No web port is required.')
    log('Copied API settings and all three original patches are retained.')
    log('The TorBox deadlock watchdog is installed but its timer stays disabled until the NAS Plex cutover.')
    log('Boot recovery is configured. The existing NAS backup includes its static settings while leaving the CAM mount online.')
    log('The OptiPlex and production Plex were not changed.')


def main():
    os.umask(0o077); guard()
    action = sys.argv[1] if len(sys.argv) > 1 else 'deploy'
    actions = {'deploy': deploy, 'start': start, 'stop': stop, 'backup-list': backup_list,
               'resume-clients': resume_clients, 'watch': watch}
    if action not in actions:
        raise RuntimeError('Unknown NAS TorBox runtime action.')
    actions[action]()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        if STACK.is_dir():
            with contextlib.suppress(Exception):
                atomic(STACK / 'runtime-error.log', traceback.format_exc())
                output = run('docker', 'logs', '--tail', '80', NAME, check=False)
                atomic(STACK / 'container-error.log', output.stdout + '\n' + output.stderr)
        message = 'STOP: ' + (str(error) if isinstance(error, RuntimeError) else
                             'TorBox setup could not finish (' + type(error).__name__ + '); details were saved privately.')
        # backup-list feeds a recovery-state file: stdout must contain IDs only.
        print(message, file=sys.stderr, flush=True)
        raise SystemExit(1)
