#!/usr/bin/env python3
"""Sawdoctor NAS mount-aware media startup and coordinated backup recovery v1."""
import contextlib
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
import yaml

SIGNATURE = 'Sawdoctor NAS mount-aware media recovery v1'
SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
SCRATCH = Path('/srv/dev-disk-by-uuid-1f12a22e-5cfe-4b02-8d4b-48e9bf5fec6a')
LIBRARY = SSD / 'appdata/infinidysk-nas/library'
WORK = SSD / 'compose/media-recovery'
SETTINGS = SSD / 'appdata/host-jobs/media-recovery/settings.json'
WORKER = Path('/usr/local/sbin/nas-media-recovery')
BACKUP = Path('/usr/local/sbin/nas-backup')
STATE = Path('/var/lib/sawdoctor-nas-backup/running-containers')
BOOT_PENDING = Path('/run/nas-media-recovery/boot-pending.json')
LOCK = Path('/run/lock/sawdoctor-nas-backup.lock')
UNITS = Path('/etc/systemd/system')
BACKUP_SHA = '9165318df1599fe615c30b3761c20b96182019ac95d161c408bc0ad8c17a4a46'
STORAGE_SHA = '43519c5e0f5f5c2f3d03d55fc0aa82ee3ac3c3dfdb5d72e3ae44bb8bc17f6f9b'
HELPERS = {
    '/usr/local/sbin/nas-infinidysk-media-helper': 'eed6110122820ab6108823b35702672e310b0d73e65791702a1374f1781a7c01',
    '/usr/local/sbin/nas-torbox-media': '83ea3a55902c143caf579c28244987ad00e024557b53f0dbfec8f4b30dbe70d7',
    '/usr/local/sbin/nas-books-deploy.py': '16889a58d366a86f01e580b8efab8fed5e04cbaee6843e4240ddd87f5c0f9bc9',
}
CLIENTS = {'silo-nas-silo-1': ('silo-nas', 'silo'),
           'sonarr-nas': ('media-core-nas', 'sonarr'),
           'radarr-nas': ('media-core-nas', 'radarr'),
           'radarr4k-nas': ('media-core-nas', 'radarr4k')}
PREREQUISITES = {'/silo-nas-silo-1': ('silo-nas-postgres-1', 'silo-nas-redis-1'),
                 '/tracearr-nas': ('tracearr-db-nas', 'tracearr-redis-nas')}
MOUNTS = {
    '/mnt/nzbdav': ('fuse.rclone', 'nzbdav:'),
    '/mnt/torbox-media': ('fuse.main.py', 'main.py'),
    '/mnt/gdrive-audiobooks': ('fuse.rclone', 'gdrive:Soundspan-Audiobooks'),
    '/mnt/media/ebooks': ('fuse.rclone', 'gdrive:ABS-Ebooks'),
    '/mnt/gdrive-torbox-archive': ('fuse.rclone', 'gdrive:Shelfmark-TorBox-Archive'),
    '/mnt/torbox-audiobooks': ('fuse.rclone', 'torbox-audiobooks:'),
}

STORAGE_CODE = r'''
import asyncio, hashlib, json, pathlib, sys
sys.dont_write_bytecode = True
sys.path.insert(0, '/app/backend')
from deployment import stack_storage as storage
p = json.load(sys.stdin)
if hashlib.sha256(pathlib.Path(storage.__file__).read_bytes()).hexdigest() != p['sha']:
    raise SystemExit('The installed Dockmon storage implementation differs.')
if str(storage.STACKS_DIR) != '/app/data/stacks':
    raise SystemExit('The installed Dockmon stack directory differs.')
async def main():
    result = {}
    for name in p['projects']:
        text, env = await storage.read_stack(name)
        path = storage.find_compose_file(storage.get_stack_path(name))
        if p['mode'] == 'write':
            change = p['projects'][name]
            if text not in (change['before'], change['after']):
                raise SystemExit('An edited NAS stack was retained: ' + name)
            if text != change['after']:
                await storage.write_stack(name, change['after'])
            text, env = await storage.read_stack(name)
        result[name] = {'text': text, 'env': env, 'path': str(path)}
    print(json.dumps(result))
asyncio.run(main())
'''


def log(value):
    print(value, flush=True)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def atomic(path, data, mode=0o600):
    if path.is_symlink():
        raise RuntimeError('An unexpected symbolic recovery file was retained.')
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
            temporary.chmod(mode); temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def write_json(path, value):
    atomic(path, (json.dumps(value, indent=2) + '\n').encode())


def run(*args, timeout=90, input=None):
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout, input=input)
    if result.returncode:
        if WORK.is_dir():
            atomic(WORK / 'private-error.log', (result.stdout + '\n' + result.stderr).encode())
        raise RuntimeError('A NAS recovery command failed; diagnostic output was retained privately in compose/media-recovery.')
    return result.stdout


def containers():
    ids = run('docker', 'ps', '-aq').split()
    return json.loads(run('docker', 'inspect', *ids)) if ids else []


def label_identity(item):
    labels = item['Config'].get('Labels') or {}
    return (labels.get('com.docker.compose.project'), labels.get('com.docker.compose.service'))


def fingerprint(items):
    return {item['Id']: (item['Image'], item['State']['Status'], item['State']['StartedAt']) for item in items}


def unescape(value):
    return re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), value)


def parse_mounts(text):
    result = {}
    for line in text.splitlines():
        fields = line.split(); separator = fields.index('-')
        result[unescape(fields[4])] = {'device': fields[2], 'root': unescape(fields[3]),
            'type': fields[separator + 1], 'source': unescape(fields[separator + 2])}
    return result


def host_mounts():
    return parse_mounts(Path('/proc/self/mountinfo').read_text())


def dependencies(item):
    if item['Name'] in ('/infinidysk-nas', '/torbox-media-center-nas'):
        return set()
    result = set()
    for mount in item.get('Mounts', []):
        if mount.get('Type') != 'bind':
            continue
        source = Path(mount['Source'])
        for target in MOUNTS:
            if source.is_relative_to(target):
                result.add(target)
        if source.is_relative_to(LIBRARY):
            result.add('/mnt/nzbdav')
    return result


def ready(item, mounts):
    return all(target in mounts and (mounts[target]['type'], mounts[target]['source']) == MOUNTS[target]
               for target in dependencies(item))


def stale_bindings(item, mounts):
    if not item['State']['Running'] or not dependencies(item) or not ready(item, mounts):
        return False
    namespace = parse_mounts(Path('/proc/' + str(item['State']['Pid']) + '/mountinfo').read_text())
    for bind in item.get('Mounts', []):
        if bind.get('Type') != 'bind':
            continue
        source = Path(bind['Source'])
        for target in dependencies(item):
            if not source.is_relative_to(target):
                continue
            live = mounts[target]
            relative = source.relative_to(target).as_posix()
            root = live['root'].rstrip('/') + ('/' + relative if relative != '.' else '')
            root = root or '/'
            current = namespace.get(bind['Destination'])
            if current is None or (current['device'], current['root'], current['type']) != (live['device'], root, live['type']):
                return True
    return False


def wait_health(identity, seconds=40):
    deadline = time.monotonic() + seconds
    while True:
        item = json.loads(run('docker', 'inspect', identity))[0]
        status = item['State'].get('Health', {}).get('Status', 'none')
        if item['State']['Running'] and status in ('none', 'healthy'):
            return
        if time.monotonic() >= deadline:
            raise RuntimeError('A NAS database/backend did not become ready; its pending recovery record was retained.')
        time.sleep(2)


def backend_ready(seconds=30):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + seconds
    while True:
        try:
            for url in ('http://192.168.0.220:8081/healthz', 'http://192.168.0.220:8082/health'):
                with opener.open(url, timeout=2) as response:
                    if response.status != 200:
                        raise OSError('Backend is not ready.')
            return
        except OSError:
            if time.monotonic() >= deadline:
                raise RuntimeError('NAS InfiniDysk is not ready; media clients were deferred.')
            time.sleep(2)


def rank(item):
    service = label_identity(item)[1] or ''
    if re.search(r'(^|[-_])(postgres|redis|db|database|mariadb)($|[-_])', service):
        return 0
    return 1 if item['Name'] == '/infinidysk-nas' else 2


def saved_ids():
    if STATE.is_symlink():
        raise RuntimeError('An unexpected symbolic backup recovery file was retained.')
    values = STATE.read_text().splitlines() if STATE.exists() else []
    if any(not re.fullmatch('[0-9a-f]{64}', value) for value in values):
        raise RuntimeError('An invalid saved backup container identity was retained.')
    return list(dict.fromkeys(values))


def save_remaining(values):
    if values:
        atomic(STATE, ('\n'.join(values) + '\n').encode())
    else:
        STATE.unlink(missing_ok=True)


def recover_saved(early=False, strict=False):
    remaining = saved_ids()
    if not remaining:
        return
    current = {item['Id']: item for item in containers()}
    records = sorted((current[value] for value in remaining if value in current), key=rank)
    failures = []
    backend_checked = False
    backend_failed = False
    for item in records:
        deps = dependencies(item)
        if (early and deps) or not ready(item, host_mounts()):
            continue
        if '/mnt/nzbdav' in deps and backend_failed:
            continue
        try:
            if '/mnt/nzbdav' in deps and not backend_checked:
                try:
                    backend_ready(); backend_checked = True
                except RuntimeError:
                    backend_failed = True
                    raise
            for database in PREREQUISITES.get(item['Name'], ()):
                wait_health(database)
            if not item['State']['Running']:
                log('Restoring: ' + item['Name'].lstrip('/'))
                run('docker', 'start', item['Id'])
            if rank(item) == 0:
                wait_health(item['Id'])
            elif item['Name'] == '/infinidysk-nas':
                try:
                    backend_ready(); backend_checked = True
                except RuntimeError:
                    backend_failed = True
                    raise
            remaining.remove(item['Id'])
            # Commit each restored identity before a mount helper can recreate
            # its provider after this lock is released.
            save_remaining(remaining)
        except RuntimeError:
            failures.append(item['Name'].lstrip('/'))
    if remaining:
        log('Pending backup media recovery: ' + str(len(remaining)) + ' container(s).')
    if failures or (strict and remaining):
        raise RuntimeError('Backup recovery is pending; the saved container identities were retained for retry.')


def settings():
    value = json.loads(SETTINGS.read_text())
    if value.get('format') != SIGNATURE or set(value['autostart']) - set(CLIENTS):
        raise RuntimeError('The NAS media startup settings differ from the reviewed installation.')
    return value


def start_configured():
    if not BOOT_PENDING.exists():
        return 0
    pending = json.loads(BOOT_PENDING.read_text())
    if pending.get('format') != SIGNATURE or set(pending['names']) - set(settings()['autostart']):
        raise RuntimeError('The pending NAS startup membership differs from its configuration.')
    configured = pending['names'][:]
    current = {item['Name'].lstrip('/'): item for item in containers()}
    backend_checked = False
    for name in configured:
        item = current.get(name)
        if item is None or label_identity(item) != CLIENTS[name]:
            raise RuntimeError('An enrolled NAS media client changed; its startup was retained for review.')
        if not ready(item, host_mounts()):
            continue
        try:
            if not backend_checked:
                backend_ready(); backend_checked = True
            for database in PREREQUISITES.get(item['Name'], ()):
                wait_health(database)
            if not item['State']['Running']:
                log('Starting after media mounts: ' + name)
                run('docker', 'start', item['Id'])
            pending['names'].remove(name)
            if pending['names']:
                write_json(BOOT_PENDING, pending)
            else:
                BOOT_PENDING.unlink(missing_ok=True)
        except RuntimeError:
            continue
    return len(pending['names'])


def refresh_running():
    mounts = host_mounts()
    for item in containers():
        try:
            stale = stale_bindings(item, mounts)
        except FileNotFoundError:
            continue
        if stale:
            if '/mnt/nzbdav' in dependencies(item):
                backend_ready()
            log('Refreshing an old media mount binding: ' + item['Name'].lstrip('/'))
            run('docker', 'restart', '--timeout', '30', item['Id'], timeout=90)


@contextlib.contextmanager
def locked(nonblocking=False):
    with LOCK.open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0))
        except BlockingIOError:
            yield False
            return
        yield True


def runtime(mode):
    if mode == 'resume-locked':
        # The backup coordinator owns fd 9. Reuse its lock, never wait for
        # a mount service whose ExecStartPost needs that same lock.
        try:
            if os.fstat(9).st_ino != LOCK.stat().st_ino or os.fstat(9).st_dev != LOCK.stat().st_dev:
                raise OSError('Incorrect inherited lock.')
            fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise RuntimeError('The backup coordinator lock must be inherited for this operation.')
        recover_saved(strict=True)
        return
    if mode == 'tick' and subprocess.run(['systemctl', 'is-active', '--quiet', 'docker.service']).returncode:
        return
    with locked(nonblocking=mode == 'tick') as acquired:
        if not acquired:
            return
        if mode == 'check':
            bad = [item['Name'].lstrip('/') for item in containers()
                   if item['State']['Running'] and dependencies(item)
                   and (not ready(item, host_mounts()) or stale_bindings(item, host_mounts()))]
            log('Media clients with unavailable/old mounts: ' + (', '.join(bad) or 'none'))
            log('Pending backup recovery records: ' + str(len(saved_ids())))
        elif mode == 'resume-early':
            recover_saved(early=True)
        elif mode in ('boot', 'tick'):
            if mode == 'boot':
                BOOT_PENDING.parent.mkdir(mode=0o700, exist_ok=True)
                write_json(BOOT_PENDING, {'format': SIGNATURE, 'names': settings()['autostart']})
            failed = False
            try:
                recover_saved()
            except RuntimeError:
                failed = True
            pending = start_configured()
            refresh_running()
            if failed or pending:
                raise RuntimeError('NAS media recovery is pending; its saved startup/backup records will be retried.')
        else:
            raise RuntimeError('Unknown NAS media recovery operation.')


def patch_backup(text):
    if digest(text.encode()) != BACKUP_SHA:
        raise RuntimeError('The installed NAS backup differs from the verified version.')
    start = text.index('resume_containers() {\n')
    end = text.index('\n}\n', start) + 3
    replacement = 'resume_containers() {\n  ' + str(WORKER) + ' resume-locked\n}'
    return text[:start] + replacement + text[end:]


def unit_documents():
    return {
        'nas-backup-resume.service.d/media-recovery.conf': f'''# {SIGNATURE}
[Service]
ExecStart=
ExecStart={WORKER} resume-early
''',
        'nas-backup.service.d/media-recovery.conf': f'''# {SIGNATURE}
[Unit]
Wants=nas-media-boot.service
After=nas-media-boot.service nas-books.service
''',
        'nas-media-boot.service': f'''# {SIGNATURE}
[Unit]
Description=Start NAS media clients after their streaming mounts
Requires=docker.service
Wants=network-online.target nas-backup-resume.service nas-infinidysk-rclone.service nas-torbox-media.service
After=docker.service network-online.target nas-backup-resume.service nas-infinidysk-rclone.service nas-torbox-media.service
PartOf=docker.service
RequiresMountsFor={SSD} {SCRATCH}
StartLimitIntervalSec=0
[Service]
Type=oneshot
RemainAfterExit=yes
UMask=0077
ExecStart={WORKER} boot
Restart=on-failure
RestartSec=1min
TimeoutStartSec=5min
[Install]
WantedBy=multi-user.target
''',
        'nas-media-recovery.service': f'''# {SIGNATURE}
[Unit]
Description=Restore pending NAS backup clients and refresh old media bindings
After=docker.service nas-media-boot.service
RequiresMountsFor={SSD}
[Service]
Type=oneshot
UMask=0077
ExecStart={WORKER} tick
TimeoutStartSec=5min
''',
        'nas-media-recovery.timer': f'''# {SIGNATURE}
[Unit]
Description=Check NAS media bindings and pending backup recovery
[Timer]
OnActiveSec=1min
OnUnitActiveSec=1min
Unit=nas-media-recovery.service
[Install]
WantedBy=timers.target
'''}


def storage(projects, mode='read'):
    return json.loads(run('docker', 'exec', '-i', 'dockmon', 'python', '-c', STORAGE_CODE,
                          input=json.dumps({'sha': STORAGE_SHA, 'mode': mode, 'projects': projects})))


def model(project, path):
    return json.loads(run('docker', 'compose', '-p', project, '-f', str(path), 'config', '--format', 'json'))


def check_order(documents):
    names = ('nas-backup-resume.service', 'nas-backup.service', 'nas-torbox-media.service',
             'nas-infinidysk-rclone.service', 'nas-books.service')
    graph = {name: set(run('systemctl', 'show', '--no-pager', '--full', name,
                          '-p', 'After', '--value').split()) for name in names}
    for name, text in documents.items():
        owner = name.split('.d/', 1)[0]
        graph.setdefault(owner, set())
        for line in text.splitlines():
            if line.startswith('After='):
                graph[owner].update(line[6:].split())
    def visit(name, parents):
        if name in parents:
            raise RuntimeError('The proposed NAS startup dependencies form a cycle; current units were retained.')
        for before in graph.get(name, ()):
            visit(before, parents | {name})
    for name in graph:
        visit(name, set())


def prepare_plan(source):
    current = containers(); selected = {item['Name'].lstrip('/'): item for item in current if item['Name'].lstrip('/') in CLIENTS}
    if set(selected) != set(CLIENTS) or any(not item['State']['Running'] or label_identity(item) != CLIENTS[name]
                                          for name, item in selected.items()):
        raise RuntimeError('The four reviewed NAS media clients must be present and running; existing states were retained.')
    for name, item in selected.items():
        policy = item['HostConfig']['RestartPolicy']
        if policy['Name'] != 'unless-stopped' or not dependencies(item) or not ready(item, host_mounts()) or stale_bindings(item, host_mounts()):
            raise RuntimeError('A current NAS media policy/mount differs from the reported healthy setup; it was retained.')
    if saved_ids():
        raise RuntimeError('A pending NAS backup recovery must finish before installing startup changes.')
    for filename, expected in HELPERS.items():
        path = Path(filename)
        if path.is_symlink() or digest(path.read_bytes()) != expected:
            raise RuntimeError('An installed NAS runtime helper differs from the reported checksum.')
    existing_start = run('systemctl', 'show', '--no-pager', '--full', 'nas-backup-resume.service',
                         '-p', 'ExecStart', '--value')
    if 'path=/usr/local/sbin/nas-backup ;' not in existing_start or 'argv[]=/usr/local/sbin/nas-backup resume ;' not in existing_start:
        raise RuntimeError('The existing backup recovery entry point differs from the reviewed unit.')
    original = BACKUP.read_text(); patched = patch_backup(original)
    backup_test = WORK / 'backup-syntax'; atomic(backup_test, patched.encode())
    run('bash', '-n', str(backup_test)); backup_test.unlink()
    projects = storage({project: {} for project, _service in CLIENTS.values()})
    changes = {}
    for project, document in projects.items():
        path = Path(document['path'])
        if path != Path('/app/data/stacks') / project / 'compose.yaml':
            raise RuntimeError('An adopted NAS Compose location differs from its reviewed canonical path.')
        host = SSD / 'appdata/dockmon' / path.relative_to('/app/data')
        if host.is_symlink() or host.read_text() != document['text']:
            raise RuntimeError('The host and Dockmon definitions differ.')
        before = model(project, host); proposed = yaml.safe_load(document['text'])
        expected = copy.deepcopy(before)
        for name, (group, service) in CLIENTS.items():
            if group != project:
                continue
            if proposed['services'][service].get('restart') != 'unless-stopped':
                raise RuntimeError('An enrolled client Compose policy differs from its running policy.')
            proposed['services'][service]['restart'] = 'on-failure:5'
            expected['services'][service]['restart'] = 'on-failure:5'
        text = yaml.safe_dump(proposed, sort_keys=False, allow_unicode=True)
        candidate = WORK / (project + '.yaml'); atomic(candidate, text.encode())
        if model(project, candidate) != expected:
            raise RuntimeError('A startup-policy proposal changed other Compose settings; values were withheld.')
        candidate.unlink()
        changes[project] = {'before': document['text'], 'after': text, 'env': document['env']}
    documents = unit_documents()
    check_order(documents)
    for name in documents:
        path = UNITS / name
        if path.is_symlink() or path.exists():
            raise RuntimeError('A media recovery systemd file already exists without a matching installation plan.')
    return {'format': SIGNATURE, 'workerSha256': digest(source.encode()), 'backupBefore': original, 'backupAfter': patched,
            'projects': changes, 'units': documents, 'clients': list(CLIENTS), 'fingerprint': fingerprint(current)}


def apply_plan(plan, source):
    if plan.get('format') != SIGNATURE or plan['workerSha256'] != digest(source.encode()):
        raise RuntimeError('An existing recovery plan differs from this installer.')
    # Preflight every touched definition before applying/resuming this plan.
    if BACKUP.is_symlink() or BACKUP.read_text() not in (plan['backupBefore'], plan['backupAfter']):
        raise RuntimeError('An edited NAS backup was retained.')
    current_stacks = storage(plan['projects'])
    for project, change in plan['projects'].items():
        if current_stacks[project]['text'] not in (change['before'], change['after']) or current_stacks[project]['env'] != change['env']:
            raise RuntimeError('An edited NAS Compose/environment definition was retained.')
    for name, text in plan['units'].items():
        path = UNITS / name
        if path.is_symlink() or (path.exists() and path.read_text() != text):
            raise RuntimeError('An edited NAS recovery unit was retained.')
    before = containers(); names = {item['Name'].lstrip('/'): item for item in before}
    for name in plan['clients']:
        item = names.get(name)
        if not item or label_identity(item) != CLIENTS[name] or item['HostConfig']['RestartPolicy'] not in (
                {'Name': 'unless-stopped', 'MaximumRetryCount': 0}, {'Name': 'on-failure', 'MaximumRetryCount': 5}):
            raise RuntimeError('An edited or replaced NAS client policy was retained.')
    configuration = {'format': SIGNATURE, 'autostart': plan['clients']}
    if SETTINGS.is_symlink() or (SETTINGS.exists() and json.loads(SETTINGS.read_text()) != configuration):
        raise RuntimeError('Edited NAS startup membership settings were retained.')
    recovery = WORK / 'recovery'; recovery.mkdir(mode=0o700, exist_ok=True)
    if not (recovery / 'nas-backup').exists():
        atomic(recovery / 'nas-backup', plan['backupBefore'].encode(), BACKUP.stat().st_mode & 0o777)
        write_json(recovery / 'stacks.json', plan['projects'])
    atomic(WORKER, source.encode(), 0o700)
    storage(plan['projects'], mode='write')
    SETTINGS.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    write_json(SETTINGS, configuration)
    atomic(BACKUP, plan['backupAfter'].encode(), BACKUP.stat().st_mode & 0o777)
    for name, text in plan['units'].items():
        path = UNITS / name; path.parent.mkdir(parents=True, exist_ok=True)
        atomic(path, text.encode(), 0o644)
    for name in plan['clients']:
        run('docker', 'update', '--restart', 'on-failure:5', name)
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', 'nas-media-boot.service')
    run('systemctl', 'enable', '--now', 'nas-media-recovery.timer')
    after = containers()
    if fingerprint(before) != fingerprint(after):
        raise RuntimeError('A NAS container changed during installation; its current state was retained.')
    for item in after:
        if item['Name'].lstrip('/') in plan['clients'] and item['HostConfig']['RestartPolicy'] != {'Name':'on-failure', 'MaximumRetryCount':5}:
            raise RuntimeError('An enrolled NAS restart policy could not be verified.')
    write_json(WORK / 'installed.json', {'format': SIGNATURE, 'workerSha256': digest(source.encode()), 'clients': plan['clients']})


def install(source):
    if not SSD.is_mount() or not SCRATCH.is_mount():
        raise RuntimeError('The NAS appdata SSD and scratch NVMe must be mounted.')
    if WORK.is_symlink() or SETTINGS.parent.is_symlink() or WORKER.is_symlink():
        raise RuntimeError('An unexpected symbolic media recovery installation path was retained.')
    if WORKER.exists() and SIGNATURE not in WORKER.read_text():
        raise RuntimeError('An unrelated NAS recovery worker was retained.')
    WORK.mkdir(parents=True, exist_ok=True, mode=0o700)
    log('Waiting for the NAS backup lock...')
    with locked() as acquired:
        path = WORK / 'plan.json'
        if path.exists():
            plan = json.loads(path.read_text())
        else:
            log('Checking the installed backup, live mount bindings and adopted Dockmon definitions...')
            plan = prepare_plan(source); write_json(path, plan)
        log('Installing mount-aware backup recovery and media startup policies...')
        apply_plan(plan, source)
    runtime('check')
    log('NAS MEDIA RECOVERY INSTALLED. Four running media clients now start after their mounts.')
    log('Dockmon Compose and Docker restart policies agree. Current container IDs, images and start times were retained.')
    log('Plex and Kometa remain stopped and outside the startup list. OMV backup schedule and cloud upload settings are retained.')
    log('One recovery copy is kept in compose/media-recovery/recovery. The OptiPlex was not changed.')


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220.')
    arguments = sys.argv[1:]
    if arguments and arguments[0] != 'install':
        if len(arguments) != 1:
            raise RuntimeError('Unknown NAS media recovery arguments.')
        runtime(arguments[0]); return
    source = globals().get('INSTALL_SOURCE')
    if source is None and '__file__' in globals():
        source = Path(__file__).read_text()
    if not source:
        raise RuntimeError('Use the complete provided installer command.')
    if arguments == ['install']:
        install(source); return
    if arguments:
        raise RuntimeError('Unknown NAS recovery installation arguments.')
    if subprocess.run(['systemctl', 'is-active', '--quiet', 'nas-media-recovery-install.service']).returncode == 0:
        log('NAS media recovery installation is already running.'); return
    if WORKER.is_symlink() or (WORKER.exists() and SIGNATURE not in WORKER.read_text()):
        raise RuntimeError('An unrelated NAS recovery worker was retained.')
    atomic(WORKER, source.encode(), 0o700)
    subprocess.run(['systemctl', 'reset-failed', 'nas-media-recovery-install.service'], capture_output=True)
    run('systemd-run', '--unit=nas-media-recovery-install', '--collect',
        '--description=Install NAS mount-aware startup and backup recovery', '/usr/bin/python3', '-u', str(WORKER), 'install')
    log('NAS media recovery installation started in the background. Closing SSH will not stop it.')
    log('Progress: sudo journalctl -u nas-media-recovery-install.service -n 25 --no-pager -o cat')


if __name__ == '__main__':
    try:
        main()
    except RuntimeError as error:
        raise SystemExit('STOP: ' + str(error))
    except Exception as error:
        raise SystemExit('STOP: NAS media recovery could not finish (' + type(error).__name__ + '); private details were withheld.')
