#!/usr/bin/env python3
"""Prepare an editable, created-but-stopped NAS Plex stack from the verified copy."""
import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import yaml

SIGNATURE = 'Sawdoctor NAS Plex cutover preparation v1'
SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
SCRATCH = Path('/srv/dev-disk-by-uuid-1f12a22e-5cfe-4b02-8d4b-48e9bf5fec6a')
SNAPSHOT = SSD / 'migration/plex-npm-optiplex/snapshot'
DATA = SSD / 'appdata/plex-nas'
LIBRARY = SSD / 'appdata/infinidysk-nas/library'
STACK = SSD / 'compose/plex-nas'
CANONICAL = SSD / 'appdata/dockmon/stacks/plex-nas/compose.yaml'
WORKER = Path('/usr/local/sbin/nas-plex-prepare')
LOCK = Path('/run/lock/sawdoctor-nas-backup.lock')
CORE = Path('/usr/local/sbin/nas-core-deploy.py')
CORE_SHA = '8ebc4f735c61c5f0ea29c509b1bd6279efc05741675ad4e7370ee3b39c71065e'
STORAGE_SHA = '43519c5e0f5f5c2f3d03d55fc0aa82ee3ac3c3dfdb5d72e3ae44bb8bc17f6f9b'
PROJECT = 'plex-nas'
VERSION = '1.43.5.11079-b3b13e506'
IMAGE = 'lscr.io/linuxserver/plex:1.43.5.11079-b3b13e506-ls331'
SOURCE_ID = 'sha256:0c2f1122a4275efeea953a9882359f3809b27279d3c3022392e8e610a2eccc67'

STORAGE_CODE = r'''
import asyncio, hashlib, json, pathlib, sys
sys.dont_write_bytecode = True
sys.path.insert(0, '/app/backend')
from deployment import stack_storage as storage
packet = json.load(sys.stdin)
if hashlib.sha256(pathlib.Path(storage.__file__).read_bytes()).hexdigest() != packet['sha']:
    raise SystemExit('The installed Dockmon storage implementation differs from the reviewed version.')
if str(storage.STACKS_DIR) != '/app/data/stacks':
    raise SystemExit('The existing Dockmon stack directory differs.')
async def main():
    exists = await storage.stack_exists('plex-nas')
    if exists:
        text, env = await storage.read_stack('plex-nas')
        if packet['mode'] == 'create' and (text != packet['text'] or env):
            raise SystemExit('An existing Plex stack differs; its edits were retained.')
    elif packet['mode'] == 'create':
        await storage.write_stack('plex-nas', packet['text'], env_files={}, create_only=True)
    print(json.dumps({'exists': exists}))
asyncio.run(main())
'''


def say(message):
    print(message, flush=True)


def run(*args, timeout=90, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout, **kwargs)
    if result.returncode:
        if STACK.is_dir():
            atomic(STACK / 'private-error.log', (result.stdout + '\n' + result.stderr).encode())
        raise RuntimeError('A local Plex preparation command failed; diagnostic output was retained privately.')
    return result.stdout


def atomic(path, data, mode=0o600):
    if path.is_symlink():
        raise RuntimeError('An unexpected symbolic preparation path was retained.')
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
            temporary.chmod(mode); temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def storage(mode='inspect', text=''):
    return json.loads(run('docker', 'exec', '-i', 'dockmon', 'python', '-c', STORAGE_CODE,
        input=json.dumps({'sha': STORAGE_SHA, 'mode': mode, 'text': text})))


def containers():
    ids = run('docker', 'ps', '-aq').split()
    return json.loads(run('docker', 'inspect', *ids)) if ids else []


def fingerprint(items):
    return {item['Id']: (item['Image'], item['State']['Status'], item['State']['StartedAt'])
            for item in items if item['Name'] != '/plex-nas'}


def image_module():
    if CORE.is_symlink() or hashlib.sha256(CORE.read_bytes()).hexdigest() != CORE_SHA:
        raise RuntimeError('The existing tested image verifier is required.')
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('plex_image_verifier', CORE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def resolved_images(manifest):
    module = image_module()
    selected = {item['Name'].lstrip('/'): copy.deepcopy(item) for item in manifest['containers']}
    if set(selected) != {'plex', 'npm-app-1'} or selected['plex']['Image'] != SOURCE_ID:
        raise RuntimeError('The copied source image identities differ from this preparation.')
    selected['plex']['Config']['Image'] = IMAGE
    # Cache NPM's exported image for the next import without changing the
    # existing NAS NPM latest tag or its running container.
    selected['npm-app-1']['Config']['Image'] = 'jc21/nginx-proxy-manager:source-20261103'
    cache = STACK / 'image-identities.json'
    if cache.is_file() and not cache.is_symlink():
        records = json.loads(cache.read_text())
        if set(records) == set(selected) and all(records[name]['source'] == item['Image'] for name, item in selected.items()):
            local = json.loads(run('docker', 'image', 'inspect', *(records[name]['nas'] for name in selected)))
            if {item['Id'] for item in local} == {record['nas'] for record in records.values()}:
                return {name: record['nas'] for name, record in records.items()}
    return module.load_verified_images(SNAPSHOT, manifest, selected, STACK)


def check_copied_files(work):
    mappings = {'data/plex-config/': work / 'config',
                'data/flora-test-library/': work / 'flora-test-library'}
    count = 0
    with tempfile.NamedTemporaryFile('w', dir=STACK, delete=False) as checksum:
        path = Path(checksum.name)
        try:
            with (SNAPSHOT / 'SHA256SUMS').open() as source:
                for line in source:
                    offset = 67 if line.startswith('\\') else 66
                    relative = line[offset:].removeprefix('./')
                    for prefix, target in mappings.items():
                        if relative.startswith(prefix):
                            checksum.write(line[:offset] + str(target) + '/' + relative[len(prefix):])
                            count += 1
                            break
            if not count:
                raise RuntimeError('The verified snapshot has no Plex file checksums.')
            checksum.flush()
            run('sha256sum', '--quiet', '-c', str(path), timeout=3600)
        finally:
            path.unlink(missing_ok=True)


def prepare_data(manifest, archive_sha):
    expected = {'format': SIGNATURE, 'sourceArchiveSha256': archive_sha,
                'sourceCreatedUtc': manifest['createdUtc'], 'plexVersion': VERSION}
    if DATA.is_symlink():
        raise RuntimeError('An unexpected symbolic Plex data directory was retained.')
    if DATA.exists():
        marker = DATA / '.prepared.json'
        if not marker.is_file() or json.loads(marker.read_text()) != expected:
            raise RuntimeError('Existing NAS Plex data differs; it was retained.')
        say('Reusing the already prepared NAS Plex data; later settings were retained.')
        return
    roots = {'config': SNAPSHOT / 'data/plex-config',
             'flora-test-library': SNAPSHOT / 'data/flora-test-library'}
    size = sum(int(run('du', '-sbx', '--', str(root)).split()[0]) for root in roots.values())
    if shutil.disk_usage(DATA.parent).free < size + 2 * 1024**3:
        raise RuntimeError('The NAS SSD needs more free space for its Plex application data.')
    with tempfile.TemporaryDirectory(prefix='.plex-prepare-', dir=DATA.parent) as temporary:
        work = Path(temporary) / 'data'; work.mkdir(mode=0o700)
        for label, source in roots.items():
            target = work / label; target.mkdir()
            run('rsync', '-aHAX', '--numeric-ids', '--one-file-system', '--no-devices', '--no-specials',
                '--', str(source) + '/', str(target) + '/', timeout=3600)
        say('Verifying every copied Plex/Flora regular file against the staged checksums...')
        check_copied_files(work)
        atomic(work / '.prepared.json', (json.dumps(expected, indent=2) + '\n').encode())
        work.rename(DATA)


def literal(value):
    if isinstance(value, str):
        return value.replace('$', '$$')
    if isinstance(value, list):
        return [literal(item) for item in value]
    return value


def document(source, metadata):
    original = source['Config']
    environment = dict(item.split('=', 1) for item in original.get('Env', []) if '=' in item)
    baseline = dict(item.split('=', 1) for item in metadata.get('Config', {}).get('Env', []) if '=' in item)
    configured = {key: value for key, value in environment.items() if baseline.get(key) != value}
    for key in ('PUID', 'PGID', 'TZ'):
        if key in environment:
            configured[key] = environment[key]
    configured['VERSION'] = 'docker'
    configured.pop('PLEX_CLAIM', None)
    replacements = {'/config': DATA / 'config', '/flora-test-library': DATA / 'flora-test-library',
                    '/mnt/media': LIBRARY, '/mnt/nzbdav': Path('/mnt/nzbdav'),
                    '/torbox-cams': Path('/mnt/torbox-media/movies'), '/scratch': SCRATCH}
    if {mount['Destination'] for mount in source['Mounts']} != set(replacements):
        raise RuntimeError('The source Plex mount list differs from the reviewed six bindings.')
    volumes = []
    for mount in source['Mounts']:
        if mount['Type'] != 'bind':
            raise RuntimeError('An unexpected Plex source volume requires review.')
        volumes.append({'type': 'bind', 'source': str(replacements[mount['Destination']]),
                        'target': mount['Destination'], 'read_only': not mount['RW'],
                        'bind': {'create_host_path': False}})
    host = source['HostConfig']
    if host.get('NetworkMode') != 'host' or host.get('Privileged'):
        raise RuntimeError('The source Plex network/privilege settings differ from the reviewed installation.')
    devices = [item['PathOnHost'] + ':' + item['PathInContainer'] + ':' + item['CgroupPermissions']
               for item in host.get('Devices') or []]
    if devices != ['/dev/dri:/dev/dri:rwm']:
        raise RuntimeError('The source Intel graphics binding differs from the reviewed installation.')
    service = {'image': IMAGE, 'container_name': PROJECT, 'profiles': ['plex-cutover'],
        'restart': 'no', 'pull_policy': 'never', 'network_mode': 'host',
        'environment': {key: literal(value) for key, value in configured.items()},
        'volumes': volumes, 'devices': devices,
        'labels': {'com.sawdoctor.plex-preparation': SIGNATURE},
        'logging': {'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '3'}}}
    if original.get('Hostname'):
        service['hostname'] = original['Hostname']
    for old, new in (('Entrypoint', 'entrypoint'), ('Cmd', 'command'), ('User', 'user'), ('WorkingDir', 'working_dir')):
        value = original.get(old)
        if value not in (None, '') and value != metadata.get('Config', {}).get(old):
            service[new] = literal(value)
    return {'name': PROJECT, 'x-sawdoctor-managed': SIGNATURE, 'services': {'plex': service}}


def prepare():
    if not SSD.is_mount() or not SCRATCH.is_mount():
        raise RuntimeError('The NAS appdata SSD and scratch NVMe must be mounted.')
    if not Path('/dev/dri').is_dir():
        raise RuntimeError('The NAS Intel graphics device directory is unavailable; no Plex server was started.')
    for path in (LIBRARY / 'movies', LIBRARY / 'movies-4k', LIBRARY / 'tv', Path('/mnt/nzbdav'), Path('/mnt/torbox-media/movies')):
        if not path.is_dir():
            raise RuntimeError('A required NAS media/library directory is unavailable.')
    manifest = json.loads((SNAPSHOT / 'manifest.json').read_text())
    marker = json.loads((SNAPSHOT.parent / 'staged.json').read_text())
    if manifest.get('format') != 'sawdoctor-plex-npm-export-v1' or manifest.get('sourceHost') != '192.168.0.29' or manifest.get('plexVersion') != VERSION:
        raise RuntimeError('The verified Plex/NPM snapshot at the recorded Plex version is required.')
    original = next(item for item in manifest['containers'] if item['Name'] == '/plex')
    metadata = next(item for item in manifest['images'] if item['Id'] == original['Image'])
    if STACK.is_symlink():
        raise RuntimeError('An unexpected symbolic Plex preparation directory was retained.')
    STACK.mkdir(mode=0o700, parents=True, exist_ok=True)
    say('Waiting for the NAS backup lock...')
    with LOCK.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        before = containers()
        for item in before:
            if item['Name'] == '/plex-nas':
                if item['State']['Running'] or (item['Config'].get('Labels') or {}).get('com.sawdoctor.plex-preparation') != SIGNATURE:
                    raise RuntimeError('An existing/running NAS Plex container was retained.')
            elif item['Name'] == '/plex' or 'linuxserver/plex' in item['Config']['Image']:
                raise RuntimeError('Another NAS Plex container already exists; it was retained.')
        storage()
        say('Preparing the verified Plex data and loading the exact exported images...')
        prepare_data(manifest, marker['archiveSha256'])
        resolved = resolved_images(manifest)
        if json.loads(run('docker', 'image', 'inspect', IMAGE))[0]['Id'] != resolved['plex']:
            raise RuntimeError('The prepared Plex tag differs from its verified image.')
        text = yaml.safe_dump(document(original, metadata), sort_keys=False, allow_unicode=True)
        validation = STACK / 'prepared.yaml'; atomic(validation, text.encode())
        run('docker', 'compose', '-p', PROJECT, '--profile', 'plex-cutover', '-f', str(validation), 'config', '--quiet')
        say('Importing the Plex stack into Dockmon and creating its stopped container...')
        storage('create', text)
        if not CANONICAL.is_file() or CANONICAL.is_symlink() or CANONICAL.read_text() != text:
            raise RuntimeError('The editable Dockmon Plex definition could not be verified.')
        run('docker', 'compose', '-p', PROJECT, '--profile', 'plex-cutover', '-f', str(CANONICAL),
            'create', '--pull', 'never', '--no-build', '--no-recreate', 'plex', timeout=180)
        current = json.loads(run('docker', 'inspect', PROJECT))[0]
        if current['State']['Running'] or current['Image'] != resolved['plex']:
            raise RuntimeError('The prepared Plex container did not retain the expected stopped state and image.')
        if fingerprint(before) != fingerprint(containers()):
            raise RuntimeError('Another NAS container changed during preparation; its current state was retained.')
        compatibility = STACK / 'compose.yaml'
        if compatibility.exists() or compatibility.is_symlink():
            if not compatibility.is_symlink() or compatibility.resolve() != CANONICAL.resolve():
                raise RuntimeError('An existing compatibility definition differs; it was retained.')
        else:
            compatibility.symlink_to(CANONICAL)
        validation.unlink(missing_ok=True)
    say('NAS PLEX PREPARED IN DOCKMON: plex-nas (' + VERSION + ').')
    say('Container status: ' + current['State']['Status'] + '. The Plex server was not started.')
    say('Configuration/history, server identity, six media bindings and Intel graphics mapping retained.')
    say('Plex and Kometa remain behind the plex-cutover profile; production remains on the OptiPlex.')


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220.')
    if sys.argv[1:] == ['prepare']:
        prepare()
        return
    if sys.argv[1:]:
        raise RuntimeError('Unknown Plex preparation operation.')
    active = subprocess.run(['systemctl', 'is-active', '--quiet', 'nas-plex-prepare.service']).returncode == 0
    if active:
        say('NAS Plex preparation is already running. Watch: sudo journalctl -u nas-plex-prepare.service -f')
        return
    if WORKER.is_symlink() or (WORKER.exists() and SIGNATURE not in WORKER.read_text()):
        raise RuntimeError('An unrelated Plex preparation helper was retained.')
    source = globals().get('INSTALL_SOURCE')
    if source is None and '__file__' in globals():
        source = Path(__file__).read_text()
    if not source:
        raise RuntimeError('Use the complete provided installer command.')
    atomic(WORKER, source.encode(), 0o700)
    subprocess.run(['systemctl', 'reset-failed', 'nas-plex-prepare.service'], capture_output=True)
    run('systemd-run', '--unit=nas-plex-prepare', '--collect', '--description=Prepare stopped NAS Plex stack in Dockmon',
        '/usr/bin/python3', '-u', str(WORKER), 'prepare')
    say('Plex preparation started in the background. Closing SSH will not stop it.')
    say('Progress: sudo journalctl -u nas-plex-prepare.service -n 20 --no-pager -o cat')


if __name__ == '__main__':
    try:
        main()
    except RuntimeError as error:
        raise SystemExit('STOP: ' + str(error))
    except Exception as error:
        raise SystemExit('STOP: Plex preparation could not finish (' + type(error).__name__ + '); private details were withheld.')
