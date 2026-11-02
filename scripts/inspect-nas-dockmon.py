#!/usr/bin/env python3
"""Read-only Dockmon stack-adoption and NAS image inventory; no credentials."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
PROBE = r'''
import asyncio, hashlib, inspect, json, os, pathlib, sys
sys.dont_write_bytecode = True
sys.path.insert(0, '/app/backend')
result = {'version_environment': {key: os.environ[key] for key in
    ('APP_VERSION', 'DOCKMON_VERSION', 'VERSION', 'RELEASE_VERSION') if key in os.environ}}
try:
    from deployment import stack_storage as storage
    result['stacks_directory'] = str(storage.STACKS_DIR)
    result['compose_filenames'] = list(storage.COMPOSE_FILENAMES)
    result['existing_stacks'] = asyncio.run(storage.list_stacks())
    result['write_stack_signature'] = str(inspect.signature(storage.write_stack))
    result['read_stack_signature'] = str(inspect.signature(storage.read_stack))
    result['module_sha256'] = hashlib.sha256(pathlib.Path(storage.__file__).read_bytes()).hexdigest()
except Exception as error:
    result['storage_probe_error'] = type(error).__name__
for label, path in (('routes', '/app/backend/deployment/stack_routes.py'),
                    ('executor', '/app/backend/deployment/stack_executor.py')):
    file = pathlib.Path(path)
    if file.is_file():
        result[label + '_sha256'] = hashlib.sha256(file.read_bytes()).hexdigest()
print(json.dumps(result, sort_keys=True))
'''


def run(*args, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, timeout=45, **kwargs)
    if result.returncode:
        raise RuntimeError('The read-only Docker/Dockmon inspection failed; no services were changed.')
    return result.stdout


def main():
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220.')
    ids = run('docker', 'ps', '-aq').split()
    containers = json.loads(run('docker', 'inspect', *ids)) if ids else []
    dockmon = next((entry for entry in containers if entry['Name'].lstrip('/') == 'dockmon'), None)
    if dockmon is None or not dockmon['State']['Running']:
        raise RuntimeError('The existing NAS Dockmon container must be running.')
    image = json.loads(run('docker', 'image', 'inspect', dockmon['Image']))[0]
    labels = image['Config'].get('Labels') or {}
    print('DOCKMON:', json.dumps({'image': dockmon['Config']['Image'],
        'version': labels.get('org.opencontainers.image.version'),
        'revision': labels.get('org.opencontainers.image.revision'),
        'repo_digests': image.get('RepoDigests', []),
        'mounts': [{'source': mount['Source'], 'target': mount['Destination'], 'type': mount['Type']}
                   for mount in dockmon['Mounts'] if mount['Destination'] != '/var/run/docker.sock']}))
    print('DOCKMON STORAGE:', run('docker', 'exec', '-i', 'dockmon', 'python', '-', input=PROBE).strip())
    projects = {}; source_files = set()
    for entry in containers:
        name = entry['Name'].lstrip('/'); labels = entry['Config'].get('Labels') or {}
        project = labels.get('com.docker.compose.project', '(no Compose project)')
        compose = labels.get('com.docker.compose.project.config_files', '')
        for filename in compose.split(','):
            if filename:
                source_files.add(filename)
        projects.setdefault(project, {'files': set(), 'containers': []})
        if compose:
            projects[project]['files'].add(compose)
        projects[project]['containers'].append({'name': name, 'status': entry['State']['Status'],
            'service': labels.get('com.docker.compose.service'), 'image': entry['Config']['Image']})
    for name, project in sorted(projects.items()):
        print('PROJECT:', name)
        for files in sorted(project['files']):
            print('  Compose:', files)
        for container in sorted(project['containers'], key=lambda item: item['name']):
            print('  ' + json.dumps(container, sort_keys=True))
    print('COMPOSE FILE CHECKS:')
    for filename in sorted(source_files):
        path = Path(filename)
        if (path.is_absolute() and path.is_relative_to(SSD / 'compose')
                and path.is_file() and not path.is_symlink() and path.stat().st_size <= 2 * 1024**2):
            print(json.dumps({'path': filename, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}))
        else:
            print(json.dumps({'path': filename, 'status': 'not a readable regular NAS Compose file'}))
    print('Inspection complete. No imports, image pulls, file edits or restarts were performed.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('STOP: ' + (str(error) if isinstance(error, RuntimeError) else
                                   'Dockmon inspection could not finish (' + type(error).__name__ + ').'))
