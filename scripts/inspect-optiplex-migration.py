#!/usr/bin/env python3
"""Inventory OptiPlex migration sources without changing or stopping services."""
import json
import os
from pathlib import Path
import subprocess
import tempfile


def run(*args):
    return subprocess.check_output(args, text=True)


def describe(container):
    name = container['Name'].lstrip('/')
    result = ['\nCONTAINER: ' + name + ' [' + container['State']['Status'] + ']',
              'Image: ' + container['Config']['Image'],
              'Networks: ' + ', '.join(container['NetworkSettings'].get('Networks', {}))]
    if container['HostConfig'].get('NetworkMode') == 'host':
        result.append('Ports: host network')
    else:
        ports = []
        for inside, bindings in (container['HostConfig'].get('PortBindings') or {}).items():
            for binding in bindings or []:
                ports.append((binding.get('HostIp') or '*') + ':' + binding['HostPort'] + ' -> ' + inside)
        result.append('Ports: ' + (', '.join(ports) or 'not published'))
    labels = container['Config'].get('Labels') or {}
    result.append('Compose: ' + labels.get('com.docker.compose.project.config_files', 'not recorded'))
    for mount in container.get('Mounts', []):
        result.append('Mount: ' + mount['Source'] + ' -> ' + mount['Destination']
            + ' [' + mount['Type'] + ', ' + ('rw' if mount.get('RW') else 'ro') + ']')
    return '\n'.join(result)


def atomic_json(path, document):
    fd, temporary = tempfile.mkstemp(prefix='.inventory-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(document, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or 'inet 192.168.0.29/' not in run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the OptiPlex at 192.168.0.29.')
    ids = run('docker', 'ps', '-aq').split()
    containers = json.loads(run('docker', 'inspect', *ids)) if ids else []
    images = sorted({item['Image'] for item in containers})
    image_data = json.loads(run('docker', 'image', 'inspect', *images)) if images else []
    units = run('systemctl', 'list-unit-files', '--type=service', '--no-legend', '--no-pager')
    relevant_units = [line for line in units.splitlines()
        if line.split() and any(word in line.split()[0].lower()
            for word in ('rclone', 'nzbdav', 'torbox', 'plex', 'infinidysk'))]
    destination = Path('/home/sawdoctor/nas-migration-inventory')
    if destination.is_symlink():
        raise RuntimeError('Unexpected symlink at the private inventory directory.')
    destination.mkdir(mode=0o700, exist_ok=True)
    destination.chmod(0o700)
    atomic_json(destination / 'optiplex-inventory.json', {
        'format': 'sawdoctor-optiplex-migration-inventory-v1', 'sourceHost': '192.168.0.29',
        'containers': containers,
        'images': [{'Id': item['Id'], 'RepoDigests': item.get('RepoDigests') or []}
                   for item in image_data],
        'hostServices': relevant_units,
    })
    print('OptiPlex inventory: ' + str(len(containers)) + ' containers. No services were changed or stopped.')
    for container in sorted(containers, key=lambda item: item['Name']):
        print(describe(container))
    print('\nRELEVANT HOST SERVICES:')
    for line in relevant_units:
        print(line)
    print('\nDetailed inventory saved privately; environment values and credentials are not printed.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('STOP: ' + str(error))
