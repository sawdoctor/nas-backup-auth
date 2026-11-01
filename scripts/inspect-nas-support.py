#!/usr/bin/env python3
"""Read-only NAS support snapshot report; credentials and database values stay private."""
import contextlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import tempfile
import urllib.parse

SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
SNAPSHOT = SSD / 'migration/support-optiplex/snapshot'
TABLES = {'monitor', 'notification', 'setting', 'settings', 'config', 'configuration',
    'instance', 'instances', 'server', 'servers', 'media_server', 'media_servers',
    'job', 'jobs', 'schedule', 'schedules', 'scheduled_task', 'scheduled_tasks',
    'arr_instance', 'arr_instances', 'app_settings', 'system_settings', 'preferences'}


def host_summary(value):
    """Report only local URL host/port pairs, never userinfo, paths or query strings."""
    hosts = set()
    for text in re.findall(r'(?:https?|postgres(?:ql)?|redis|rediss)://[^\s\"\'<>]+', value):
        try:
            url = urllib.parse.urlsplit(text)
            host = url.hostname or ''
            port = url.port
        except ValueError:
            continue
        if (host in ('localhost', '127.0.0.1', '192.168.0.29', '192.168.0.220')
            or host.endswith('.sawdoctor.uk') or '.' not in host):
            hosts.add(host + (':' + str(port) if port else ''))
    return sorted(hosts)


def quote(name):
    return '"' + name.replace('"', '""') + '"'


@contextlib.contextmanager
def open_database(path):
    # Work on private temporary copies if a frozen WAL is present. This includes
    # its committed rows without creating or changing WAL/SHM in the snapshot.
    wal = path.with_name(path.name + '-wal')
    with tempfile.TemporaryDirectory(prefix='nas-support-report-') as temporary:
        if wal.is_file() and wal.stat().st_size:
            target = Path(temporary) / path.name
            shutil.copyfile(path, target)
            shutil.copyfile(wal, target.with_name(target.name + '-wal'))
            uri = target.as_uri() + '?mode=ro'
        else:
            uri = path.as_uri() + '?mode=ro&immutable=1'
        connection = sqlite3.connect(uri, uri=True)
        try:
            yield connection
        finally:
            connection.close()


def report(snapshot, manifest):
    print('Support runtime inventory (credential values hidden):')
    for container in manifest['containers']:
        name = container['Name'].lstrip('/')
        config, host = container['Config'], container['HostConfig']
        print('\n' + name + ': ' + config['Image'])
        print('  Network mode:', host.get('NetworkMode', 'default'),
            '| PID mode:', host.get('PidMode') or 'private',
            '| privileged:', bool(host.get('Privileged')),
            '| container user:', config.get('User') or 'image default')
        ports = []
        for inside, bindings in (host.get('PortBindings') or {}).items():
            ports.extend(binding['HostPort'] + ' -> ' + inside for binding in bindings or [])
        print('  Ports:', ', '.join(ports) or 'internal only')
        values = dict(item.split('=', 1) for item in config.get('Env', []) if '=' in item)
        # Names tell us which configuration overrides exist; do not print values.
        names = [key for key in values if key not in ('PATH', 'HOME', 'LANG', 'LANGUAGE', 'LC_ALL')]
        print('  Environment names:', ', '.join(sorted(names)))
        for key, value in sorted(values.items()):
            if re.search(r'password|secret|token|api.?key|credential', key, re.I):
                continue
            hosts = host_summary(value)
            if hosts:
                print('  ' + key + ' connection hosts:', ', '.join(hosts))
        for mount in container.get('Mounts', []):
            print('  Mount target:', mount['Destination'],
                '[' + mount['Type'] + ', ' + ('rw' if mount.get('RW') else 'ro') + ']')

    print('\nConfiguration and SQLite schema inventory (no row values):')
    for label, root in manifest['dataRoots'].items():
        if label in ('tracearr-db', 'tracearr-redis', 'tracearr'):
            continue
        directory = snapshot / root['snapshot']
        # os.walk does not follow links into mounted media or other locations.
        for parent, dirs, files in os.walk(directory, followlinks=False):
            dirs[:] = [name for name in dirs if name.lower() not in
                {'cache', 'logs', 'log', 'node_modules', 'vendor', 'backups', 'images', 'fonts', '.git'}]
            for name in sorted(files):
                path = Path(parent) / name
                if path.is_symlink() or not path.is_file():
                    continue
                relative = str(path.relative_to(snapshot / 'data'))
                if path.suffix.lower() in ('.json', '.yaml', '.yml', '.ini', '.conf', '.toml'):
                    print('  Config:', relative)
                    if path.stat().st_size <= 2 * 1024**2:
                        hosts = host_summary(path.read_text(errors='replace'))
                        if hosts:
                            print('    Local connection hosts:', ', '.join(hosts))
                with path.open('rb') as stream:
                    if stream.read(16) != b'SQLite format 3\0':
                        continue
                print('  SQLite:', relative)
                with open_database(path) as connection:
                    tables = [row[0] for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
                    print('    Tables:', ', '.join(tables[:60]))
                    for table in tables:
                        if table.lower() not in TABLES and not re.search(r'setting|config|schedul|instance|server|notification', table, re.I):
                            continue
                        columns = [str(row[1]) for row in connection.execute('PRAGMA table_info(' + quote(table) + ')')]
                        print('    ' + table + ' columns:', ', '.join(columns))
                        if table.lower() in ('monitor', 'notification') and 'active' in columns:
                            rows = connection.execute('SELECT COUNT(*),COALESCE(SUM(active<>0),0) FROM ' + quote(table)).fetchone()
                            print('      Rows:', rows[0], '| active:', rows[1])
    print('\nTracearr copied PostgreSQL major:', manifest.get('postgresMajor', 'not recorded'))
    print('Read-only report complete. No services or configuration files were changed.')


def main():
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in subprocess.check_output(
            ['ip', '-4', 'addr', 'show'], text=True):
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220.')
    manifest = json.loads((SNAPSHOT / 'manifest.json').read_text())
    if manifest.get('format') != 'sawdoctor-support-export-v1':
        raise RuntimeError('The verified support snapshot was not found.')
    report(SNAPSHOT, manifest)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('STOP: ' + str(error))
