#!/usr/bin/env python3
"""Prepare the copied Audiobookshelf user provisioner with its timer disabled."""
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shlex
import subprocess
import tempfile

SIGNATURE = 'Sawdoctor NAS Audiobookshelf user provisioner v1'
SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
SNAPSHOT = SSD / 'migration/host-jobs-optiplex/snapshot'
BOOKS = SSD / 'migration/books-optiplex/snapshot/manifest.json'
DATA = SSD / 'appdata/host-jobs/abs-user-provisioner'
HELPER = Path('/usr/local/sbin/nas-abs-user-provisioner')
UNIT = Path('/etc/systemd/system/nas-abs-user-provisioner.service')
TIMER = Path('/etc/systemd/system/nas-abs-user-provisioner.timer')
LOCK = Path('/run/lock/sawdoctor-nas-backup.lock')
ORIGINAL = '/usr/local/sbin/abs-user-provisioner.py'
SOURCE_SHA = '47e244009589803da06de531c0bc56baf167f4a878ef12a0c5f5e0810cb10b19'

WORKER = r'''#!/usr/bin/python3
# Sawdoctor NAS Audiobookshelf user provisioner v1
import contextlib
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys

DATA = Path("/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6/appdata/host-jobs/abs-user-provisioner")
SOURCE_SHA = "47e244009589803da06de531c0bc56baf167f4a878ef12a0c5f5e0810cb10b19"

def load_program():
    source = DATA / 'original.py'
    if source.is_symlink() or hashlib.sha256(source.read_bytes()).hexdigest() != SOURCE_SHA:
        raise RuntimeError('The copied provisioner implementation changed.')
    settings = json.loads((DATA / 'settings.json').read_text())
    if settings['ABS_URL'] != 'http://192.168.0.220:13378':
        raise RuntimeError('The provisioner must target NAS Audiobookshelf.')
    root = Path(settings['PODCAST_HOST_ROOT'])
    allowed = DATA.parents[1] / 'books-nas'
    if root.is_symlink() or not root.is_dir() or not root.resolve().is_relative_to(allowed.resolve()):
        raise RuntimeError('The copied NAS podcast directory is unavailable.')
    os.environ.update(settings)
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('copied_abs_provisioner', source)
    program = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(program)
    return program

def plan(program):
    libraries = program.api('GET', '/api/libraries').get('libraries', [])
    users = program.api('GET', '/api/users').get('users', [])
    shared = [library['id'] for library in libraries if library.get('mediaType') != 'podcast']
    if not shared:
        raise RuntimeError('No shared book libraries were returned; permissions were retained.')
    folders, assigned = set(), set()
    result = {'active_members': 0, 'shared_libraries': len(shared),
              'private_libraries_to_create': 0, 'permission_updates': 0}
    for user in users:
        if user.get('type') != 'user' or not user.get('isActive', True) or not user.get('username'):
            continue
        username = user['username']
        folder = program.safe_name(username)
        if folder in folders:
            raise RuntimeError('Two member names map to the same podcast folder; permissions were retained.')
        folders.add(folder)
        host = Path(program.HOST_ROOT) / folder
        if host.is_symlink() or (host.exists() and (not host.is_dir() or not host.resolve().is_relative_to(Path(program.HOST_ROOT).resolve()))):
            raise RuntimeError('An unexpected member podcast directory was retained.')
        path = program.ABS_ROOT + '/' + folder
        matches = [library for library in libraries if library.get('mediaType') == 'podcast'
                   and path in program.library_folder_paths(library)]
        if not matches:
            matches = [library for library in libraries if library.get('mediaType') == 'podcast'
                       and library.get('name') == 'Podcasts - ' + username]
        if len(matches) > 1:
            raise RuntimeError('Duplicate private podcast libraries require review.')
        private_id = None
        if matches:
            library = matches[0]
            if set(program.library_folder_paths(library)) != {path} or library['id'] in assigned:
                raise RuntimeError('An existing private podcast library has unexpected folders or ownership.')
            private_id = library['id']
            assigned.add(private_id)
        else:
            result['private_libraries_to_create'] += 1
        permissions = user.get('permissions') or {}
        current = user.get('librariesAccessible', permissions.get('librariesAccessible')) or []
        if private_id is None or permissions.get('accessAllLibraries', False) or set(current) != set(shared + [private_id]):
            result['permission_updates'] += 1
        result['active_members'] += 1
    return result

def apply_program(program):
    # Keep the copied private program, adapting both API response layouts and
    # the explicit private-library flag. Unrelated permissions are preserved.
    original_api = program.api
    users = {}
    def api(method, path, payload=None):
        if method == 'GET':
            result = original_api(method, path, payload)
            if path == '/api/users':
                result = json.loads(json.dumps(result))
                for user in result.get('users', []):
                    users[program.urllib.parse.quote(user['id'], safe='')] = user
                    permissions = user.setdefault('permissions', {})
                    accessible = user.get('librariesAccessible', permissions.get('librariesAccessible')) or []
                    permissions['librariesAccessible'] = [] if permissions.get('accessAllLibraries', False) else accessible
            return result
        if method == 'PATCH' and path.startswith('/api/users/'):
            user = users.get(path.removeprefix('/api/users/'))
            if not user or user.get('type') != 'user' or not user.get('isActive', True):
                raise RuntimeError('Only active normal members may be provisioned.')
            if set(payload or {}) != {'permissions'} or set(payload['permissions']) != {'librariesAccessible'}:
                raise RuntimeError('An unexpected provisioner user update was retained.')
            accessible = payload['permissions']['librariesAccessible']
            if not accessible:
                raise RuntimeError('An empty library-access list was refused.')
            permissions = {key: value for key, value in user.get('permissions', {}).items() if isinstance(value, bool)}
            permissions['accessAllLibraries'] = False
            return original_api(method, path, {'permissions': permissions, 'librariesAccessible': accessible})
        if method == 'POST' and path == '/api/libraries' and payload.get('mediaType') == 'podcast':
            return original_api(method, path, payload)
        raise RuntimeError('An unexpected provisioner API write was refused.')
    program.api = api
    try:
        program.main()
    finally:
        program.api = original_api
    verified = plan(program)
    if verified['private_libraries_to_create'] or verified['permission_updates']:
        raise RuntimeError('Post-run private-library permissions require review.')

def main():
    if os.geteuid() != 0 or sys.argv[1:] not in (['--plan'], ['--apply']):
        raise RuntimeError('Run with sudo and exactly --plan or --apply.')
    apply = sys.argv[1] == '--apply'
    with open('/run/lock/sawdoctor-nas-backup.lock', 'a') as backup_lock:
        fcntl.flock(backup_lock, fcntl.LOCK_EX)
        with open('/run/lock/sawdoctor-nas-abs-provisioner.lock', 'a') as job_lock:
            fcntl.flock(job_lock, fcntl.LOCK_EX)
            program = load_program()
            result = plan(program)
            if apply:
                private_output = io.StringIO()
                with contextlib.redirect_stdout(private_output), contextlib.redirect_stderr(private_output):
                    apply_program(program)
                output = DATA / 'last-apply.log'
                output.write_text(private_output.getvalue())
                output.chmod(0o600)
            print(('Applied' if apply else 'Read-only plan') + ': ' + json.dumps(result, sort_keys=True))

if __name__ == '__main__':
    os.umask(0o077)
    try:
        main()
    except Exception as error:
        target = DATA / 'private-error.log'
        target.write_text(type(error).__name__ + ': ' + str(error) + '\n')
        target.chmod(0o600)
        raise SystemExit('STOP: Audiobookshelf validation failed; details saved privately in its host-job appdata.')
'''


def say(message):
    print(message, flush=True)


def run(*args, checked=True):
    result = subprocess.run(args, text=True, capture_output=True, timeout=90)
    if checked and result.returncode:
        raise RuntimeError('A local setup or read-only API check failed; available diagnostics remain private.')
    return result


def atomic(path, data, mode=0o600):
    if path.is_symlink():
        raise RuntimeError('An unexpected symbolic installation path was retained.')
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
            temporary.chmod(mode); temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def copied(source):
    manifest = json.loads((SNAPSHOT / 'manifest.json').read_text())
    if manifest.get('format') != 'sawdoctor-host-jobs-export-v1' or manifest.get('sourceHost') != '192.168.0.29':
        raise RuntimeError('The verified OptiPlex host-job snapshot is required.')
    entries = [item for item in manifest['files'] if item['source'] == source]
    if len(entries) != 1:
        raise RuntimeError('A copied provisioner dependency is unavailable.')
    entry = entries[0]
    relative = PurePosixPath(entry['snapshot']); path = SNAPSHOT / relative
    if relative.is_absolute() or '..' in relative.parts or path.is_symlink() or not path.resolve().is_relative_to(SNAPSHOT.resolve()):
        raise RuntimeError('An unexpected copied file path was retained.')
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != entry['sha256']:
        raise RuntimeError('A copied provisioner dependency failed verification.')
    return data


def settings():
    source = {}
    for line in copied('/etc/abs-user-provisioner.env').decode().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.removeprefix('export ').partition('=')
        values = shlex.split(value, comments=False)
        if not separator or len(values) != 1 or key in source:
            raise RuntimeError('The copied private provisioner settings need review.')
        source[key] = values[0]
    if set(source) != {'ABS_URL', 'ABS_API_KEY', 'PODCAST_HOST_ROOT', 'PODCAST_ABS_ROOT'} or not source['ABS_API_KEY']:
        raise RuntimeError('The complete copied provisioner settings are required.')
    books = json.loads(BOOKS.read_text())
    original = next(item for item in books['containers'] if item['Name'] == '/audiobookshelf-test')
    current = json.loads(run('docker', 'inspect', 'audiobookshelf-test-nas').stdout)[0]
    if (current['Config'].get('Labels') or {}).get('com.docker.compose.project') != 'books-nas':
        raise RuntimeError('The installed NAS Audiobookshelf container is required.')
    abs_root = Path(source['PODCAST_ABS_ROOT'])
    if not abs_root.is_absolute() or '..' in abs_root.parts:
        raise RuntimeError('The copied podcast container path is unexpected.')
    mounts = sorted(original['Mounts'], key=lambda item: len(item['Destination']), reverse=True)
    for mount in mounts:
        if mount['Type'] != 'bind' or not abs_root.is_relative_to(mount['Destination']):
            continue
        relative = abs_root.relative_to(mount['Destination'])
        if Path(mount['Source']) / relative != Path(source['PODCAST_HOST_ROOT']):
            raise RuntimeError('The copied podcast host/container paths disagree.')
        match = next((item for item in current['Mounts'] if item['Type'] == 'bind'
                      and item['Destination'] == mount['Destination'] and item['RW']), None)
        if match is None:
            break
        root = Path(match['Source']) / relative
        if root.is_symlink() or not root.is_dir() or not root.resolve().is_relative_to((SSD / 'appdata/books-nas').resolve()):
            raise RuntimeError('The copied NAS podcast directory must be present in book appdata.')
        source['ABS_URL'] = 'http://192.168.0.220:13378'
        source['PODCAST_HOST_ROOT'] = str(root)
        return source
    raise RuntimeError('Could not map the copied podcast path to the current NAS bindings.')


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or not SSD.is_mount() or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show').stdout:
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220 with its application SSD mounted.')
    source = copied(ORIGINAL)
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA:
        raise RuntimeError('The copied provisioner differs from the reviewed implementation.')
    for path in (UNIT, TIMER, HELPER):
        if path.is_symlink() or (path.exists() and SIGNATURE not in path.read_text()):
            raise RuntimeError('An unrelated provisioner installation was retained.')
    for unit in (UNIT.name, TIMER.name):
        if run('systemctl', 'is-active', '--quiet', unit, checked=False).returncode == 0 or run('systemctl', 'is-enabled', '--quiet', unit, checked=False).returncode == 0:
            raise RuntimeError('The provisioner is already active/enabled; its settings were retained.')
    say('Checking the copied provisioner and mapping its podcast directory to NAS Audiobookshelf...')
    with LOCK.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        configuration = settings()
        if DATA.is_symlink():
            raise RuntimeError('An unexpected symbolic provisioner data directory was retained.')
        if DATA.exists():
            if (json.loads((DATA / 'settings.json').read_text()) != configuration
                    or (DATA / 'original.py').read_bytes() != source):
                raise RuntimeError('Existing NAS provisioner settings differ; they were retained.')
        else:
            DATA.mkdir(mode=0o700, parents=True)
            atomic(DATA / 'settings.json', (json.dumps(configuration, indent=2) + '\n').encode())
            atomic(DATA / 'original.py', source)
        atomic(HELPER, WORKER.encode(), 0o700)
    # The worker takes the same backup lock: do not hold it while starting the check.
    say('Checking the NAS API and private-library plan without changing users or libraries...')
    result = run('/usr/bin/python3', str(HELPER), '--plan', checked=False)
    if result.returncode:
        raise RuntimeError('The NAS read-only provisioner check failed; details are in appdata/host-jobs/abs-user-provisioner/private-error.log.')
    say(result.stdout.strip())
    service = f'''# {SIGNATURE}
[Unit]
Description=NAS Audiobookshelf private podcast libraries for members
After=network-online.target docker.service nas-books.service
Wants=network-online.target
RequiresMountsFor={SSD}

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {HELPER} --apply
UMask=0077
TimeoutStartSec=5min
'''
    timer = f'''# {SIGNATURE}
[Unit]
Description=Check NAS Audiobookshelf for new members

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
AccuracySec=10s
Persistent=true

[Install]
WantedBy=timers.target
'''
    atomic(UNIT, service.encode(), 0o644)
    atomic(TIMER, timer.encode(), 0o644)
    run('systemctl', 'daemon-reload')
    say('NAS AUDIOBOOKSHELF USER JOB PREPARED. The original program and private API key are retained.')
    say('Read-only NAS checks passed. No user permissions, libraries or podcast files were changed.')
    say('nas-abs-user-provisioner.timer is installed and disabled until cutover.')


if __name__ == '__main__':
    try:
        main()
    except RuntimeError as error:
        raise SystemExit('STOP: ' + str(error))
    except Exception as error:
        raise SystemExit('STOP: Provisioner preparation failed (' + type(error).__name__ + '); private values were withheld.')
