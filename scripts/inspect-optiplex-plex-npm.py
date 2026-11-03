#!/usr/bin/env python3
"""Read-only Plex and NPM source checks before preparing their NAS copies."""
import json
import os
from pathlib import Path
import subprocess
import urllib.request
import xml.etree.ElementTree as ET


def run(*args):
    return subprocess.check_output(args, text=True, timeout=60)


def say(*args):
    print(*args, flush=True)


def main():
    if os.geteuid() != 0 or 'inet 192.168.0.29/' not in run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the OptiPlex at 192.168.0.29.')
    ids = run('docker', 'ps', '-aq').split()
    containers = json.loads(run('docker', 'inspect', *ids)) if ids else []
    selected = [item for item in containers if item['Name'] == '/plex'
                or 'nginx-proxy-manager' in item['Config']['Image'].lower()]
    if not any(item['Name'] == '/plex' for item in selected):
        raise RuntimeError('The production Plex container was not found.')
    for container in selected:
        name = container['Name'].lstrip('/')
        config = container['Config']
        metadata = json.loads(run('docker', 'image', 'inspect', container['Image']))[0]
        labels = metadata.get('Config', {}).get('Labels') or {}
        say('\nCONTAINER:', name)
        say('State:', container['State']['Status'])
        say('Image:', config['Image'])
        say('Exact local image:', container['Image'])
        say('Registry digest:', ', '.join(metadata.get('RepoDigests') or []) or 'none saved')
        say('Image version:', labels.get('org.opencontainers.image.version')
            or labels.get('build_version') or 'not recorded in image labels')
        say('Network mode:', container['HostConfig']['NetworkMode'])
        say('Ports:', json.dumps(container['HostConfig'].get('PortBindings')))
        say('Compose:', (config.get('Labels') or {}).get('com.docker.compose.project.config_files', 'not recorded'))
        if name != 'plex':
            env = dict(item.split('=', 1) for item in config.get('Env', []) if '=' in item)
            say('External DB environment configured:', bool(env.get('DB_MYSQL_HOST') or env.get('DB_POSTGRES_HOST')))
        for mount in container.get('Mounts', []):
            say('Mount:', mount['Source'], '->', mount['Destination'],
                '[' + mount['Type'] + ', ' + ('rw' if mount['RW'] else 'ro') + ']')
            targets = {'/config'} if name == 'plex' else {'/data', '/etc/letsencrypt', '/config'}
            if mount['Destination'] in targets and Path(mount['Source']).is_dir():
                say('Persistent data size:')
                subprocess.run(['du', '-shx', '--', mount['Source']], check=True)
    say('\nPlex running version:')
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open('http://127.0.0.1:32400/identity', timeout=5) as response:
            say(ET.fromstring(response.read()).attrib.get('version', 'not returned'))
    except Exception as error:
        say('Local identity endpoint unavailable (' + type(error).__name__ + '); exact image is recorded above.')
    say('\nSource staging disk space:')
    subprocess.run(['df', '-h', '/var/lib'], check=True)
    say('\nRead-only check complete. No services or settings were changed; no files were created.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('STOP: Source inspection did not finish (' + type(error).__name__ + ').')
