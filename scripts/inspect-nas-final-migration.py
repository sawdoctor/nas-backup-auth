#!/usr/bin/env python3
"""Read-only NAS checks before TorBox CAM and NPM state migration.

Prints selected non-secret settings only. Does not start containers, change
mounts, read credential values into the report, or modify application files.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess

SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
SNAPSHOT = SSD / 'migration/books-optiplex/snapshot'


def command(*args):
    return subprocess.run(args, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, timeout=30)


def print_mounts(mounts):
    for mount in mounts:
        print(' ', mount.get('Source'), '->', mount.get('Destination'),
              '[' + mount.get('Type', 'unknown') + ',',
              'rw' if mount.get('RW') else 'ro',
              'propagation=' + (mount.get('Propagation') or 'default') + ']')


def snapshot_file(source, manifest):
    source = Path(source)
    for root in sorted(manifest['dataRoots'].values(),
                       key=lambda item: len(item['source']), reverse=True):
        original = Path(root['source'])
        if source.is_relative_to(original):
            path = SNAPSHOT / root['snapshot'] / source.relative_to(original)
            if not path.resolve().is_relative_to(SNAPSHOT.resolve()):
                raise RuntimeError('Unexpected snapshot path.')
            return path
    raise RuntimeError('A TorBox patch is outside the copied data roots.')


def torbox_report(manifest):
    found = [c for c in manifest['containers']
             if c['Name'].lstrip('/') == 'torbox-media-center']
    if len(found) != 1:
        raise RuntimeError('The copied TorBox container record is missing or ambiguous.')
    container = found[0]
    config, host = container['Config'], container['HostConfig']
    print('\nTORBOX SOURCE SETTINGS (from the verified NAS snapshot)')
    print('Image:', config['Image'])
    print('Image identity:', container['Image'])
    print('Network mode:', host.get('NetworkMode'))
    print('Privileged:', bool(host.get('Privileged')))
    print('Capabilities:', ', '.join(host.get('CapAdd') or []) or 'none')
    print('Security options:', ', '.join(host.get('SecurityOpt') or []) or 'default')
    for device in host.get('Devices') or []:
        print('Device:', device.get('PathOnHost'), '->',
              device.get('PathInContainer'), device.get('CgroupPermissions'))
    environment = dict(item.split('=', 1) for item in config.get('Env', []) if '=' in item)
    allowed = ('MOUNT_METHOD', 'MOUNT_PATH', 'RAW_MODE', 'ENABLE_METADATA',
               'MOUNT_REFRESH_TIME', 'PUID', 'PGID', 'UID', 'GID', 'TZ')
    for key in allowed:
        if key in environment:
            print(key + '=' + environment[key])
    print('TorBox API key recorded:', bool(environment.get('TORBOX_API_KEY')))
    print('Original binds:')
    print_mounts(container['Mounts'])
    checksums = {}
    for line in (SNAPSHOT / 'SHA256SUMS').read_text().splitlines():
        if len(line) >= 67 and line[64:66] in ('  ', ' *'):
            checksums[line[66:].removeprefix('./')] = line[:64]
    patches = [m for m in container['Mounts']
               if m.get('Destination', '').startswith('/app/')]
    print('Copied playback patches:')
    for mount in patches:
        path = snapshot_file(mount['Source'], manifest)
        expected = checksums.get(path.relative_to(SNAPSHOT).as_posix())
        if not expected or not path.is_file() or path.is_symlink():
            raise RuntimeError('A copied playback patch needs verification.')
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise RuntimeError('A copied playback patch failed verification.')
        print(' ', mount['Destination'], '- verified')
    print('NAS mount status:')
    result = command('findmnt', '-n', '--mountpoint', '/mnt/torbox-media',
                     '-o', 'TARGET,FSTYPE,PROPAGATION')
    print(result.stdout.strip() if result.returncode == 0 else 'Not mounted yet.')
    result = command('docker', 'ps', '-a', '--filter', 'name=torbox-media-center',
                     '--format', '{{.Names}}: {{.Status}}')
    print(result.stdout.strip() or 'No NAS TorBox Media Center container yet.')


def npm_report():
    print('\nEXISTING NAS NPM')
    result = command('docker', 'inspect', 'npm-nas')
    if result.returncode:
        print('npm-nas was not found; no changes made.')
        return
    container = json.loads(result.stdout)[0]
    print('Image:', container['Config']['Image'])
    print('Image identity:', container['Image'])
    print('State:', container['State']['Status'])
    print('Ports:', json.dumps(container['HostConfig'].get('PortBindings')))
    print_mounts(container['Mounts'])
    environment = dict(item.split('=', 1) for item in
                       container['Config'].get('Env', []) if '=' in item)
    external = any(environment.get(key) for key in
                   ('DB_MYSQL_HOST', 'DB_POSTGRES_HOST'))
    print('External database configured:', external)
    for mount in container['Mounts']:
        if mount['Destination'] == '/data':
            print('SQLite database present:',
                  (Path(mount['Source']) / 'database.sqlite').is_file())


def main():
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in command(
            'ip', '-4', 'addr', 'show').stdout:
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220.')
    if not SSD.is_mount():
        raise RuntimeError('The NAS application SSD is not mounted.')
    manifest = json.loads((SNAPSHOT / 'manifest.json').read_text())
    if manifest.get('format') != 'sawdoctor-books-export-v1' or manifest.get('sourceHost') != '192.168.0.29':
        raise RuntimeError('The expected OptiPlex books snapshot was not found.')
    torbox_report(manifest)
    npm_report()
    print('\nBACKUP STATUS')
    result = command('systemctl', 'show', 'nas-backup.service',
                     '-p', 'ActiveState', '-p', 'SubState', '-p', 'Result')
    print(result.stdout.strip() or 'Status not available.')
    result = command('systemctl', 'list-timers', 'nas-backup.timer',
                     '--all', '--no-pager')
    print(result.stdout.strip())
    print('\nRead-only checks complete. No containers, settings or credentials were changed.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Command stderr and raw private manifest contents are never printed.
        if isinstance(error, RuntimeError):
            print('STOP:', error)
        else:
            print('STOP: The check could not finish (' + type(error).__name__ + ').')
        raise SystemExit(1)
