#!/usr/bin/env python3
"""Prepare the verified NPM restore alongside the existing NAS proxy, offline."""
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import yaml

SIGNATURE = 'Sawdoctor NAS NPM offline restore preparation v1'
SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
SNAPSHOT = SSD / 'migration/plex-npm-optiplex/snapshot'
DATA = SSD / 'appdata/npm-source-copy'
WORK = SSD / 'compose/npm-restore'
LOCK = Path('/run/lock/sawdoctor-nas-backup.lock')
WORKER = Path('/usr/local/sbin/nas-npm-prepare')
CACHE = SSD / 'compose/plex-nas/image-identities.json'
STORAGE_SHA = '43519c5e0f5f5c2f3d03d55fc0aa82ee3ac3c3dfdb5d72e3ae44bb8bc17f6f9b'
SOURCE_IMAGE = 'sha256:4393e642e233e5efd5adeb7f10918d4aaea71c9ed875b94190273fc8e87f9594'
PORTS = {'80/tcp': [{'HostIp': '192.168.0.220', 'HostPort': '10080'}],
         '81/tcp': [{'HostIp': '192.168.0.220', 'HostPort': '10081'}],
         '443/tcp': [{'HostIp': '192.168.0.220', 'HostPort': '10443'}]}
TABLES = ('proxy_host', 'redirection_host', 'dead_host', 'stream', 'certificate', 'access_list', 'user')

STORAGE_CODE = r'''
import asyncio, hashlib, json, pathlib, sys
sys.dont_write_bytecode = True
sys.path.insert(0, '/app/backend')
from deployment import stack_storage as storage
if hashlib.sha256(pathlib.Path(storage.__file__).read_bytes()).hexdigest() != sys.argv[1]:
    raise SystemExit('The Dockmon storage implementation differs from the reviewed version.')
if str(storage.STACKS_DIR) != '/app/data/stacks':
    raise SystemExit('The Dockmon stack directory differs.')
async def main():
    text, env = await storage.read_stack('npm-nas')
    path = storage.find_compose_file(storage.get_stack_path('npm-nas'))
    print(json.dumps({'text': text, 'env': env, 'path': str(path)}))
asyncio.run(main())
'''


def say(message):
    print(message, flush=True)


def atomic(path, data, mode=0o600):
    if path.is_symlink():
        raise RuntimeError('An unexpected symbolic preparation file was retained.')
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
            temporary.chmod(mode); temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def run(*args, timeout=90):
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        if WORK.is_dir():
            atomic(WORK / 'private-error.log', (result.stdout + '\n' + result.stderr).encode())
        raise RuntimeError('A local NPM preparation command failed; diagnostic output was saved privately in compose/npm-restore.')
    return result.stdout


def all_containers():
    ids = run('docker', 'ps', '-aq').split()
    return json.loads(run('docker', 'inspect', *ids)) if ids else []


def fingerprint(items):
    return {item['Id']: (item['Image'], item['State']['Status'], item['State']['StartedAt']) for item in items}


def database_report(path, certificates=None):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('The expected NPM SQLite database is unavailable.')
    db = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=10)
    try:
        db.execute('PRAGMA query_only=ON'); db.execute('BEGIN')
        if db.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
            raise RuntimeError('The copied NPM database did not pass its integrity check.')
        counts = {}
        for table in TABLES:
            fields = {row[1] for row in db.execute('PRAGMA table_info("' + table + '")')}
            if not fields:
                raise RuntimeError('An expected NPM database table is missing.')
            where = ' WHERE is_deleted=0' if 'is_deleted' in fields else ''
            counts[table] = db.execute('SELECT count(*) FROM "' + table + '"' + where).fetchone()[0]
        if certificates is not None:
            referenced = set()
            for table in ('proxy_host', 'redirection_host', 'dead_host', 'stream'):
                fields = {row[1] for row in db.execute('PRAGMA table_info("' + table + '")')}
                if 'certificate_id' in fields:
                    where = 'is_deleted=0' + (' AND enabled=1' if 'enabled' in fields else '')
                    referenced.update(row[0] for row in db.execute('SELECT certificate_id FROM "' + table + '" WHERE ' + where) if row[0])
            for certificate_id in referenced:
                provider = db.execute('SELECT provider FROM certificate WHERE id=? AND is_deleted=0', (certificate_id,)).fetchone()
                if provider is None:
                    raise RuntimeError('A copied proxy host refers to an unavailable certificate record.')
                if provider[0] == 'letsencrypt':
                    root = certificates; folder = root / 'live' / ('npm-' + str(certificate_id))
                elif provider[0] == 'other':
                    root = path.parent; folder = root / 'custom_ssl' / ('npm-' + str(certificate_id))
                else:
                    raise RuntimeError('An unrecognised copied certificate provider needs review.')
                for filename in ('fullchain.pem', 'privkey.pem'):
                    pem = folder / filename
                    if not pem.resolve().is_relative_to(root.resolve()) or not pem.is_file() or not pem.stat().st_size:
                        raise RuntimeError('A certificate/key used by a copied proxy host is missing or outside its copied storage.')
        return counts
    finally:
        db.rollback(); db.close()


def verify_files(work):
    mappings = {'data/npm-data/': work / 'data', 'data/npm-letsencrypt/': work / 'letsencrypt'}
    counts = {prefix: 0 for prefix in mappings}
    with tempfile.NamedTemporaryFile('w', dir=WORK, delete=False) as stream:
        checks = Path(stream.name)
        try:
            for line in (SNAPSHOT / 'SHA256SUMS').read_text().splitlines(keepends=True):
                offset = 67 if line.startswith('\\') else 66
                relative = line[offset:].removeprefix('./')
                for prefix, target in mappings.items():
                    if relative.startswith(prefix):
                        stream.write(line[:offset] + str(target) + '/' + relative[len(prefix):])
                        counts[prefix] += 1
                        break
            if not all(counts.values()):
                raise RuntimeError('The staged snapshot is missing NPM data/certificate checksums.')
            stream.flush()
            run('sha256sum', '--quiet', '-c', str(checks), timeout=300)
        finally:
            checks.unlink(missing_ok=True)


def prepare_data(expected):
    if DATA.is_symlink():
        raise RuntimeError('An unexpected symbolic NPM restore directory was retained.')
    if DATA.exists():
        marker = DATA / '.prepared.json'
        if not marker.is_file() or json.loads(marker.read_text()) != expected:
            raise RuntimeError('An existing NPM restore copy differs; it was retained.')
        verify_files(DATA)
        return
    if shutil.disk_usage(DATA.parent).free < 1024**3:
        raise RuntimeError('At least 1 GiB free SSD space is required for NPM restore preparation.')
    with tempfile.TemporaryDirectory(prefix='.npm-prepare-', dir=DATA.parent) as temporary:
        work = Path(temporary) / 'restore'; work.mkdir(mode=0o700)
        for source, target in (('npm-data', 'data'), ('npm-letsencrypt', 'letsencrypt')):
            destination = work / target; destination.mkdir()
            run('rsync', '-aHAX', '--numeric-ids', '--one-file-system', '--no-devices', '--no-specials',
                '--', str(SNAPSHOT / 'data' / source) + '/', str(destination) + '/', timeout=300)
        verify_files(work)
        database_report(work / 'data/database.sqlite', work / 'letsencrypt')
        atomic(work / '.prepared.json', (json.dumps(expected, indent=2) + '\n').encode())
        work.rename(DATA)


def candidate(model, container, image_id):
    result = copy.deepcopy(model)
    if set(result.get('services', {})) != {'npm'}:
        raise RuntimeError('The current NAS NPM stack has an unexpected service list.')
    service = result['services']['npm']
    if service.get('container_name') != 'npm-nas' or container['HostConfig'].get('PortBindings') != PORTS:
        raise RuntimeError('The existing NAS NPM identity or published ports differ from the reviewed installation.')
    if container['Image'] != image_id or service.get('image') != 'jc21/nginx-proxy-manager:latest':
        raise RuntimeError('The existing NAS NPM image differs from the verified source image.')
    mounts = service.get('volumes', [])
    if {mount.get('target') for mount in mounts} != {'/data', '/etc/letsencrypt'}:
        raise RuntimeError('The existing NAS NPM persistent bindings differ from the reviewed installation.')
    for mount in mounts:
        if mount.get('type') != 'bind' or mount.get('read_only'):
            raise RuntimeError('The existing NAS NPM storage is not the expected writable bind storage.')
        mount['source'] = str(DATA / ('data' if mount['target'] == '/data' else 'letsencrypt'))
        mount.setdefault('bind', {})['create_host_path'] = False
    service['pull_policy'] = 'never'
    result['x-sawdoctor-npm-preparation'] = SIGNATURE
    return result


def prepare():
    if not SSD.is_mount():
        raise RuntimeError('The NAS application SSD must be mounted.')
    if WORK.is_symlink():
        raise RuntimeError('An unexpected symbolic preparation directory was retained.')
    WORK.mkdir(parents=True, exist_ok=True, mode=0o700)
    say('Waiting for the NAS backup lock...')
    with LOCK.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        before = all_containers()
        current = next(item for item in before if item['Name'] == '/npm-nas')
        manifest = json.loads((SNAPSHOT / 'manifest.json').read_text())
        staged = json.loads((SNAPSHOT.parent / 'staged.json').read_text())
        if manifest.get('format') != 'sawdoctor-plex-npm-export-v1' or manifest.get('sourceHost') != '192.168.0.29':
            raise RuntimeError('The verified OptiPlex Plex/NPM snapshot is required.')
        source = next(item for item in manifest['containers'] if item['Name'] == '/npm-app-1')
        image = json.loads(CACHE.read_text())['npm-app-1']
        if source['Image'] != SOURCE_IMAGE or image['source'] != source['Image']:
            raise RuntimeError('The verified Plex preparation image cache is required.')
        if json.loads(run('docker', 'image', 'inspect', 'jc21/nginx-proxy-manager:latest'))[0]['Id'] != image['nas']:
            raise RuntimeError('The local NPM latest tag differs from the verified exported image.')
        stored = json.loads(run('docker', 'exec', 'dockmon', 'python', '-c', STORAGE_CODE, STORAGE_SHA))
        container_path = Path(stored['path'])
        if not container_path.is_relative_to('/app/data/stacks/npm-nas'):
            raise RuntimeError('The existing Dockmon NPM stack path differs.')
        host_path = SSD / 'appdata/dockmon' / container_path.relative_to('/app/data')
        if host_path.is_symlink() or host_path.read_text() != stored['text']:
            raise RuntimeError('The host and Dockmon NPM definitions differ.')
        model = json.loads(run('docker', 'compose', '-p', 'npm-nas', '-f', str(host_path), 'config', '--format', 'json'))
        proposed = candidate(model, current, image['nas'])
        environment = dict(item.split('=', 1) for item in current['Config'].get('Env', []) if '=' in item)
        if environment.get('DB_MYSQL_HOST') or environment.get('DB_POSTGRES_HOST') or environment.get('DB_SQLITE_FILE', '/data/database.sqlite') != '/data/database.sqlite':
            raise RuntimeError('The current NAS NPM database configuration differs.')
        live_mounts = {mount['Destination']: mount for mount in current['Mounts']}
        for mount in model['services']['npm']['volumes']:
            live = live_mounts.get(mount['target'], {})
            if live.get('Type') != 'bind' or live.get('Source') != mount['source'] or not live.get('RW'):
                raise RuntimeError('The running and configured NPM persistent paths differ.')
        live_data = Path(live_mounts['/data']['Source'])
        if not live_data.resolve().is_relative_to((SSD / 'appdata').resolve()):
            raise RuntimeError('The existing NAS NPM data is outside application storage.')
        live_counts = database_report(live_data / 'database.sqlite')
        if any(count for table, count in live_counts.items() if table != 'user'):
            raise RuntimeError('The existing NAS NPM now contains hosts, certificates or access lists; they were retained.')
        say('Copying and verifying the complete NPM database, signing keys, settings and certificates...')
        expected = {'format': SIGNATURE, 'archiveSha256': staged['archiveSha256'], 'createdUtc': manifest['createdUtc']}
        prepare_data(expected)
        counts = database_report(DATA / 'data/database.sqlite', DATA / 'letsencrypt')
        text = yaml.safe_dump(proposed, sort_keys=False, allow_unicode=True)
        prepared = WORK / 'ready.yaml'
        if prepared.exists() and prepared.read_text() != text:
            raise RuntimeError('An edited NPM restore proposal was retained.')
        atomic(prepared, text.encode())
        run('docker', 'compose', '-p', 'npm-nas', '-f', str(prepared), 'config', '--quiet')
        plan = dict(expected, sourceImage=source['Image'], nasImage=image['nas'], counts=counts,
                    existingStackPath=str(host_path), existingStackSha256=hashlib.sha256(stored['text'].encode()).hexdigest(),
                    proposalSha256=hashlib.sha256(text.encode()).hexdigest(), status='prepared-offline')
        atomic(WORK / 'prepared.json', (json.dumps(plan, indent=2) + '\n').encode())
        if fingerprint(before) != fingerprint(all_containers()):
            raise RuntimeError('A NAS container changed during preparation; its current state was retained.')
        if json.loads(run('docker', 'exec', 'dockmon', 'python', '-c', STORAGE_CODE, STORAGE_SHA)) != stored:
            raise RuntimeError('The live NAS NPM stack changed during preparation; its current definition was retained.')
    say('NAS NPM RESTORE PREPARED: ' + json.dumps(counts, sort_keys=True))
    say('Copied database, certificate/key files, accounts and access lists verified. Original destination addresses retained.')
    say('NAS restore data: ' + str(DATA))
    say('NAS cutover definition: ' + str(WORK / 'ready.yaml'))
    say('The existing NAS NPM, Dockmon definition, public routing and OptiPlex were not changed.')
    say('Activation and destination changes remain for the coordinated proxy cutover; no second certificate-renewal process was started.')


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220.')
    if sys.argv[1:] == ['prepare']:
        prepare(); return
    if sys.argv[1:]:
        raise RuntimeError('Unknown NPM preparation operation.')
    if subprocess.run(['systemctl', 'is-active', '--quiet', 'nas-npm-prepare.service']).returncode == 0:
        say('NPM preparation is already running.'); return
    if WORKER.is_symlink() or (WORKER.exists() and SIGNATURE not in WORKER.read_text()):
        raise RuntimeError('An unrelated NPM preparation helper was retained.')
    source = globals().get('INSTALL_SOURCE')
    if source is None and '__file__' in globals():
        source = Path(__file__).read_text()
    if not source:
        raise RuntimeError('Use the complete provided installer command.')
    atomic(WORKER, source.encode(), 0o700)
    subprocess.run(['systemctl', 'reset-failed', 'nas-npm-prepare.service'], capture_output=True)
    run('systemd-run', '--unit=nas-npm-prepare', '--collect', '--description=Prepare verified NPM restore for NAS proxy cutover',
        '/usr/bin/python3', '-u', str(WORKER), 'prepare')
    say('NPM restore preparation started in the background. Closing SSH will not stop it.')
    say('Progress: sudo journalctl -u nas-npm-prepare.service -n 20 --no-pager -o cat')


if __name__ == '__main__':
    try:
        main()
    except RuntimeError as error:
        raise SystemExit('STOP: ' + str(error))
    except Exception as error:
        raise SystemExit('STOP: NPM preparation could not finish (' + type(error).__name__ + '); private details were withheld.')
