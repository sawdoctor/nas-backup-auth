#!/usr/bin/env python3
"""Compare staged source NPM routes/schema with existing NAS NPM, read-only."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess

SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
SNAPSHOT = SSD / 'migration/plex-npm-optiplex/snapshot'
TABLES = ('proxy_host', 'redirection_host', 'dead_host', 'stream', 'certificate', 'access_list', 'user')
FIELDS = ('id', 'domain_names', 'forward_scheme', 'forward_host', 'forward_port',
          'forwarding_host', 'forwarding_port', 'incoming_port', 'tcp_forwarding',
          'udp_forwarding', 'certificate_id', 'access_list_id', 'enabled')


def say(*values):
    print(*values, flush=True)


def run(*args, required=True):
    result = subprocess.run(args, text=True, capture_output=True, timeout=45)
    if required and result.returncode:
        raise RuntimeError('A local NPM inspection command failed; raw settings were withheld.')
    return result


def database_report(path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('The expected SQLite database is unavailable.')
    database = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=10)
    database.row_factory = sqlite3.Row
    try:
        database.execute('PRAGMA query_only=ON')
        database.execute('BEGIN')
        existing = {row[0] for row in database.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        columns, counts, routes, certificates = {}, {}, [], []
        domains = set()
        for table in TABLES:
            if table not in existing:
                columns[table] = []; counts[table] = None
                continue
            fields = [row[1] for row in database.execute('PRAGMA table_info("' + table + '")')]
            columns[table] = fields
            where = ' WHERE is_deleted=0' if 'is_deleted' in fields else ''
            counts[table] = database.execute('SELECT count(*) FROM "' + table + '"' + where).fetchone()[0]
            allowed = [field for field in FIELDS if field in fields]
            if table not in ('proxy_host', 'redirection_host', 'dead_host', 'stream', 'certificate'):
                continue
            if table == 'certificate':
                allowed = [field for field in ('id', 'provider', 'domain_names') if field in fields]
            selected = ','.join('"' + field + '"' for field in allowed)
            for row in database.execute('SELECT ' + selected + ' FROM "' + table + '"' + where):
                entry = dict(row)
                if 'domain_names' in entry:
                    raw = entry['domain_names']
                    names = json.loads(raw) if isinstance(raw, str) and raw else (raw or [])
                    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
                        raise RuntimeError('A stored domain-name list has an unexpected format.')
                    entry['domain_names'] = names
                    if table != 'certificate':
                        domains.update(name.lower().rstrip('.') for name in names)
                # Forward hosts are expected to be plain DNS names/IPs. Never
                # print a stored URL containing credentials, a query or a path.
                for field in ('forward_host', 'forwarding_host'):
                    if field in entry and any(char in str(entry[field]) for char in ('@', '/', '?', '#', '\n', '\r')):
                        entry[field] = '<nonstandard host hidden>'
                if table == 'certificate':
                    certificates.append(entry)
                else:
                    entry['kind'] = table
                    routes.append(entry)
        migrations = []
        if 'knex_migrations' in existing:
            migration_fields = {row[1] for row in database.execute('PRAGMA table_info(knex_migrations)')}
            if {'id', 'name'} <= migration_fields:
                migrations = [row[0] for row in database.execute('SELECT name FROM knex_migrations ORDER BY id DESC LIMIT 3')]
        return {'counts': counts, 'columns': columns, 'routes': routes,
                'certificates': certificates, 'domains': domains, 'migrations': migrations}
    finally:
        database.rollback()
        database.close()


def main():
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show').stdout or not SSD.is_mount():
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220 with its appdata SSD mounted.')
    manifest = json.loads((SNAPSHOT / 'manifest.json').read_text())
    if manifest.get('format') != 'sawdoctor-plex-npm-export-v1' or manifest.get('sourceHost') != '192.168.0.29':
        raise RuntimeError('The verified Plex/NPM snapshot is required.')
    source = next(item for item in manifest['containers'] if item['Name'] == '/npm-app-1')
    current = json.loads(run('docker', 'inspect', 'npm-nas').stdout)[0]
    environment = dict(item.split('=', 1) for item in current['Config'].get('Env', []) if '=' in item)
    if environment.get('DB_MYSQL_HOST') or environment.get('DB_POSTGRES_HOST') or environment.get('DB_SQLITE_FILE', '/data/database.sqlite') != '/data/database.sqlite':
        raise RuntimeError('The existing NAS NPM uses database storage that needs a separate review.')
    mount = next(item for item in current['Mounts'] if item['Destination'] == '/data' and item['Type'] == 'bind')
    current_root = Path(mount['Source'])
    if not current_root.resolve().is_relative_to((SSD / 'appdata').resolve()):
        raise RuntimeError('The NAS NPM database is outside its expected application storage.')
    source_report = database_report(SNAPSHOT / 'data/npm-data/database.sqlite')
    current_report = database_report(current_root / 'database.sqlite')
    for label, report, image in (('COPIED OPTIPLEX NPM', source_report, source['Image']),
                                 ('EXISTING NAS NPM', current_report, current['Image'])):
        say('\n' + label)
        say('Image identity:', image)
        say('Active record counts:', json.dumps(report['counts'], sort_keys=True))
        say('Latest database migrations:', json.dumps(report['migrations']))
        say('Proxy routes:')
        for entry in report['routes']:
            say(json.dumps(entry, sort_keys=True))
        say('Certificate records:', json.dumps(report['certificates'], sort_keys=True))
    different = {table: {'source': source_report['columns'][table], 'nas': current_report['columns'][table]}
                 for table in TABLES if source_report['columns'][table] != current_report['columns'][table]}
    say('\nSchema column differences:', json.dumps(different, sort_keys=True))
    say('NAS-only domains to preserve:', json.dumps(sorted(current_report['domains'] - source_report['domains'])))
    say('Domains present in both:', json.dumps(sorted(current_report['domains'] & source_report['domains'])))
    say('NAS NPM published ports:', json.dumps(current['HostConfig'].get('PortBindings'), sort_keys=True))
    say('Read-only comparison complete. Passwords, API tokens, private keys and custom configuration contents were not printed.')


if __name__ == '__main__':
    try:
        main()
    except RuntimeError as error:
        raise SystemExit('STOP: ' + str(error))
    except Exception as error:
        raise SystemExit('STOP: NPM comparison could not finish (' + type(error).__name__ + '); private values were withheld.')
