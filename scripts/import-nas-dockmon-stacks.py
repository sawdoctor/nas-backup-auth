#!/usr/bin/env python3
"""Import existing NAS Compose stacks into Dockmon without redeployment."""
import ast
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

SIGNATURE = 'Sawdoctor Dockmon canonical Compose v1'
SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
COMPOSE = SSD / 'compose'
DATA = SSD / 'appdata/dockmon'
WORK = COMPOSE / 'dockmon-adoption'
LOCK = Path('/run/lock/sawdoctor-nas-backup.lock')
PROJECTS = {'books-nas', 'dockmon', 'infinidysk-nas', 'media-core-nas',
            'silo-nas', 'support-nas', 'torbox-media-center-nas'}
STORAGE_SHA = '43519c5e0f5f5c2f3d03d55fc0aa82ee3ac3c3dfdb5d72e3ae44bb8bc17f6f9b'
HELPERS = {
    '/usr/local/sbin/nas-books-deploy.py':
        ('b642081632182a3a14c8886b051ac99e9e19db3bffc80b93048d3dfd872fd46c',
         {"json.loads((STACK / 'compose.json').read_text())": 1, "json.loads(compose.read_text())": 3}),
    '/usr/local/sbin/nas-torbox-media':
        ('bed0fa738f8d99a247c6c7442b779346a75c7a9ce9b929e36ed7a9fd6249d1ac',
         {'json.loads(existing.read_text())': 1}),
}

STORAGE_CODE = r'''
import asyncio, hashlib, json, pathlib, sys
sys.dont_write_bytecode = True
sys.path.insert(0, '/app/backend')
from deployment import stack_storage as storage
packet = json.load(sys.stdin)
if hashlib.sha256(pathlib.Path(storage.__file__).read_bytes()).hexdigest() != packet['storage_sha']:
    raise SystemExit('The installed Dockmon stack-storage implementation differs from the reviewed version.')
if str(storage.STACKS_DIR) != '/app/data/stacks':
    raise SystemExit('The Dockmon stack directory differs from the reviewed installation.')
async def main():
    if packet['mode'] == 'import':
        for name, text in packet['stacks'].items():
            if await storage.stack_exists(name):
                current, env = await storage.read_stack(name)
                if current != text or env:
                    raise SystemExit('An existing imported stack was retained because its content differs: ' + name)
            else:
                await storage.write_stack(name, text, env_files={}, create_only=True)
    result = {}
    for name in await storage.list_stacks():
        text, env = await storage.read_stack(name)
        result[name] = hashlib.sha256(json.dumps([text, env], sort_keys=True).encode()).hexdigest()
    print(json.dumps(result, sort_keys=True))
asyncio.run(main())
'''


def say(message):
    print(message, flush=True)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(*args, input=None, timeout=90):
    result = subprocess.run(args, input=input, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        if WORK.is_dir():
            atomic(WORK / 'command-error.log', (result.stdout + '\n' + result.stderr).encode())
        raise RuntimeError('A NAS/Dockmon command failed; details were saved privately in compose/dockmon-adoption.')
    return result.stdout


def atomic(path, data, mode=0o600):
    if path.is_symlink():
        raise RuntimeError('An unexpected symbolic migration-state path was retained.')
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
            temporary.chmod(mode); temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def write_json(path, value):
    atomic(path, (json.dumps(value, indent=2) + '\n').encode())


def storage(mode='inspect', stacks=None):
    payload = {'storage_sha': STORAGE_SHA, 'mode': mode, 'stacks': stacks or {}}
    return json.loads(run('docker', 'exec', '-i', 'dockmon', 'python', '-c', STORAGE_CODE,
                          input=json.dumps(payload)))


def literal_tree(value):
    if isinstance(value, str):
        return value.replace('$', '$$')
    if isinstance(value, list):
        return [literal_tree(item) for item in value]
    if isinstance(value, dict):
        return {key: literal_tree(item) for key, item in value.items()}
    return value


def compose_model(project, paths, directory):
    command = ['docker', 'compose', '-p', project, '--project-directory', str(directory), '--profile', '*']
    for path in paths:
        command += ['-f', str(path)]
    result = subprocess.run(command + ['config', '--format', 'json'], text=True, capture_output=True, timeout=90)
    if result.returncode or ('variable' in result.stderr.lower() and 'not set' in result.stderr.lower()):
        atomic(WORK / ('compose-error-' + project + '.log'), (result.stdout + result.stderr).encode())
        raise RuntimeError('The original Compose definition could not be resolved safely: ' + project)
    return json.loads(result.stdout)


def discover(containers):
    groups = {name: [] for name in PROJECTS}
    for container in containers:
        labels = container['Config'].get('Labels') or {}
        project = labels.get('com.docker.compose.project')
        if project in groups:
            groups[project].append(container)
    result = {}
    for project, members in groups.items():
        if not members:
            raise RuntimeError('An expected NAS Compose project was not found: ' + project)
        sequences = [container['Config']['Labels'].get('com.docker.compose.project.config_files', '').split(',') for container in members]
        chosen = max(sequences, key=len)
        if any(sequence != chosen[:len(sequence)] for sequence in sequences):
            raise RuntimeError('Inconsistent Compose-file ordering requires review: ' + project)
        paths = [Path(value) for value in chosen]
        for path in paths:
            if not path.is_absolute() or '..' in path.parts or not path.is_relative_to(COMPOSE) or path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024**2:
                raise RuntimeError('A source Compose path was not the expected regular NAS file: ' + project)
        result[project] = {'paths': paths, 'members': members}
    return result


def validate_live(model, containers):
    services = model.get('services', {})
    for container in containers:
        labels = container['Config']['Labels']; key = labels['com.docker.compose.service']
        if key not in services:
            raise RuntimeError('A running service is absent from its original Compose definition.')
        service = services[key]
        if service.get('image') != container['Config']['Image']:
            raise RuntimeError('An image reference differs between Compose and its existing container: ' + key)
        current_env = dict(item.split('=', 1) for item in container['Config'].get('Env', []) if '=' in item)
        for name, value in service.get('environment', {}).items():
            if value is not None and current_env.get(name) != str(value):
                raise RuntimeError('A configured environment value differs from the existing container: ' + key + '. Its value was not displayed.')
        for mount in service.get('volumes', []):
            if mount.get('type') != 'bind':
                continue
            existing = next((item for item in container['Mounts'] if item['Destination'] == mount['target']), None)
            if existing is None or existing['Type'] != 'bind' or existing['Source'] != mount['source'] or existing['RW'] == bool(mount.get('read_only', False)):
                raise RuntimeError('A bind mount differs from the existing container: ' + key)


def patch_helper(data, expected, expressions):
    if digest(data) != expected:
        raise RuntimeError('A NAS runtime helper differs from its reviewed version; it was retained.')
    text = data.decode()
    if text.count('import json\n') != 1:
        raise RuntimeError('The runtime helper import layout needs review.')
    text = text.replace('import json\n', 'import json\nimport yaml  # ' + SIGNATURE + '\n', 1)
    for expression, count in expressions.items():
        if text.count(expression) != count:
            raise RuntimeError('A runtime Compose reader differs from the reviewed implementation.')
        text = text.replace(expression, expression.replace('json.loads(', 'yaml.safe_load(', 1))
    ast.parse(text)
    return text.encode()


def saved_file(path, index, replacement=None):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('An original migration file changed before it could be preserved.')
    data = path.read_bytes(); stat = path.stat()
    destination = WORK / 'recovery' / (str(index) + '-' + path.name)
    atomic(destination, data)
    result = {'path': str(path), 'saved': str(destination), 'sha256': digest(data),
              'mode': stat.st_mode & 0o777, 'uid': stat.st_uid, 'gid': stat.st_gid}
    if replacement is not None:
        replacement_path = WORK / 'prepared' / (str(index) + '-' + path.name)
        atomic(replacement_path, replacement)
        result.update({'replacement': str(replacement_path), 'replacementSha256': digest(replacement)})
    return result


def prepare(groups, previous, yaml):
    for name in ('recovery', 'prepared', 'compatibility'):
        (WORK / name).mkdir(mode=0o700, exist_ok=True)
    plan = {'format': SIGNATURE, 'completed': False, 'existingStacks': previous,
            'stacks': {}, 'files': [], 'helpers': [], 'containers': {}}
    for project, group in sorted(groups.items()):
        say('Checking original Compose and runtime settings: ' + project)
        paths = group['paths']; directory = paths[0].parent
        before = {str(path): digest(path.read_bytes()) for path in paths}
        model = compose_model(project, paths, directory)
        validate_live(model, group['members'])
        expected = copy.deepcopy(model)
        if project == 'support-nas' and 'kometa' in expected['services']:
            kometa = next((item for item in group['members'] if item['Config']['Labels']['com.docker.compose.service'] == 'kometa'), None)
            if kometa and kometa['State']['Running']:
                raise RuntimeError('Kometa is running; its schedule/profile needs review before adoption.')
            expected['services']['kometa']['profiles'] = ['plex-cutover']
        expected['x-sawdoctor-dockmon-import'] = SIGNATURE
        text = yaml.safe_dump(literal_tree(expected), sort_keys=False, allow_unicode=True)
        prepared = WORK / 'prepared' / (project + '.yaml')
        atomic(prepared, text.encode())
        if compose_model(project, [prepared], directory) != expected:
            raise RuntimeError('The editable Compose export changed settings during validation: ' + project)
        plan['stacks'][project] = text
        canonical = DATA / 'stacks' / project / 'compose.yaml'
        for number, path in enumerate(paths):
            if digest(path.read_bytes()) != before[str(path)]:
                raise RuntimeError('A source Compose file changed during preparation; it was retained.')
            record = saved_file(path, len(plan['files']))
            target = canonical
            if number:
                target = WORK / 'compatibility' / (project + '-' + str(number) + '.json')
                # Older commands may still mention the former override paths.
                # A neutral document keeps the canonical stack authoritative.
                atomic(target, (json.dumps({'services': {}}) + '\n').encode())
            record['target'] = str(target); plan['files'].append(record)
        for container in group['members']:
            plan['containers'][container['Id']] = {'running': container['State']['Running'],
                'startedAt': container['State']['StartedAt'], 'image': container['Image']}
    for filename, (expected, expressions) in HELPERS.items():
        path = Path(filename); replacement = patch_helper(path.read_bytes(), expected, expressions)
        plan['helpers'].append(saved_file(path, len(plan['files']) + len(plan['helpers']), replacement))
    write_json(WORK / 'plan.json', plan)
    return plan


def apply_links(plan):
    for item in plan['helpers']:
        path = Path(item['path']); current = path.read_bytes()
        if path.is_symlink() or digest(current) not in (item['sha256'], item['replacementSha256']):
            raise RuntimeError('An edited runtime helper was preserved for review.')
        replacement = Path(item['replacement']).read_bytes()
        if digest(replacement) != item['replacementSha256']:
            raise RuntimeError('A prepared runtime helper failed verification.')
        atomic(path, replacement, item['mode']); os.chown(path, item['uid'], item['gid'])
    for item in plan['files']:
        path, target = Path(item['path']), Path(item['target'])
        if path.is_symlink():
            if path.resolve() != target.resolve():
                raise RuntimeError('An unexpected existing Compose link was preserved.')
            continue
        if digest(path.read_bytes()) != item['sha256'] or not target.is_file():
            raise RuntimeError('A Compose file changed after preparation; it was retained.')
        temporary = path.parent / ('.dockmon-link-' + path.name)
        if temporary.exists() or temporary.is_symlink():
            raise RuntimeError('An unexpected temporary Compose link was retained.')
        try:
            temporary.symlink_to(target); temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def verify(plan):
    current = storage()
    if not PROJECTS.issubset(current):
        raise RuntimeError('A required editable Dockmon stack is missing.')
    for name, expected in plan['existingStacks'].items():
        if current.get(name) != expected:
            raise RuntimeError('A pre-existing Dockmon stack changed during import: ' + name)
    for item in plan['files']:
        path = Path(item['path'])
        if not path.is_symlink() or path.resolve() != Path(item['target']).resolve():
            raise RuntimeError('An original Compose path is not linked to its editable replacement.')
    existing = json.loads(run('docker', 'inspect', *plan['containers']))
    now = {item['Id']: {'running': item['State']['Running'], 'startedAt': item['State']['StartedAt'], 'image': item['Image']} for item in existing}
    if now != plan['containers']:
        raise RuntimeError('Container state changed during import; review it before any redeployment.')
    return current


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show') or not SSD.is_mount():
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220 with its application SSD mounted.')
    try:
        import yaml
    except ImportError:
        say('Installing the small system YAML library for the existing runtime helpers...')
        run('apt-get', 'install', '-y', 'python3-yaml', timeout=180)
        import yaml
    if WORK.is_symlink() or DATA.is_symlink() or not DATA.is_dir():
        raise RuntimeError('Unexpected Dockmon or adoption directory.')
    dockmon = json.loads(run('docker', 'inspect', 'dockmon'))[0]
    if not any(mount['Type'] == 'bind' and mount['Source'] == str(DATA) and mount['Destination'] == '/app/data' and mount['RW'] for mount in dockmon['Mounts']):
        raise RuntimeError('Dockmon does not use the verified writable NAS appdata binding.')
    with LOCK.open('a') as lock:
        announced = False
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB); break
            except BlockingIOError:
                if not announced:
                    say('Waiting for the NAS backup lock...'); announced = True
                time.sleep(2)
        marker = WORK / 'plan.json'
        if WORK.exists():
            if not marker.is_file() or marker.is_symlink():
                raise RuntimeError('An unrecognized adoption folder was retained.')
            plan = json.loads(marker.read_text())
            if plan.get('format') != SIGNATURE:
                raise RuntimeError('Unrecognized Dockmon adoption metadata was retained.')
            if plan.get('completed'):
                # Keep subsequent user edits; the old import text is not replayed.
                if not PROJECTS.issubset(storage()):
                    raise RuntimeError('A previously imported Dockmon stack is missing; existing edits were retained.')
                say('Dockmon adoption is already complete. Your subsequent edits were retained.'); return
        else:
            WORK.mkdir(mode=0o700)
            plan = {'format': SIGNATURE, 'phase': 'preparing', 'completed': False}
            write_json(marker, plan)
        if plan.get('phase') == 'preparing':
            current = storage()
            if PROJECTS.intersection(current):
                raise RuntimeError('A target stack already exists in Dockmon; it was retained for review.')
            ids = run('docker', 'ps', '-aq').split()
            groups = discover(json.loads(run('docker', 'inspect', *ids)))
            try:
                plan = prepare(groups, current, yaml)
            except Exception:
                # Preserve diagnostics and rollback copies; never make an
                # incomplete preparation look like a resumable import.
                atomic(WORK / 'preparation-failed.txt', b'Preparation stopped before import. Review saved diagnostics before retry.\n')
                raise
        say('Importing seven stacks using the installed Dockmon storage functions...')
        storage('import', plan['stacks'])
        say('Aligning original Compose paths and the book/TorBox YAML readers...')
        apply_links(plan)
        current = verify(plan)
        plan['completed'] = True; plan['importedStackHashes'] = {name: current[name] for name in PROJECTS}
        write_json(marker, plan)
        say('DOCKMON IMPORT COMPLETE: ' + ', '.join(sorted(PROJECTS)))
        say('NPM and Fail2ban retained. All existing container IDs, images and start times are unchanged.')
        say('Original Compose commands now use the Dockmon definitions. Kometa stays behind the plex-cutover profile.')
        say('One private rollback copy is kept in compose/dockmon-adoption/recovery.')
        say('Refresh Dockmon Stacks at https://192.168.0.220:8001. Image-tag changes are the next separate step.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('STOP: ' + (str(error) if isinstance(error, RuntimeError) else
                                   'Dockmon adoption could not finish (' + type(error).__name__ + '); saved files were retained.'))
