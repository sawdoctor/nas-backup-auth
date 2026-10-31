#!/usr/bin/env python3
"""Deploy Sawdoctor's verified six-app snapshot against NAS media and InfiniDysk."""
import copy
import fcntl
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
SCRATCH = Path('/srv/dev-disk-by-uuid-1f12a22e-5cfe-4b02-8d4b-48e9bf5fec6a')
PROJECT = 'media-core-nas'
MARKER = 'sawdoctor-nas-core-v1'
NETWORK = 'media-core'
APPS = {
    'sonarr': {'target': '/config', 'port': 8989, 'hostPort': 8989, 'db': 'sonarr.db'},
    'radarr': {'target': '/config', 'port': 7878, 'hostPort': 7878, 'db': 'radarr.db'},
    'radarr4k': {'target': '/config', 'port': 7878, 'hostPort': 7879, 'db': 'radarr.db'},
    'prowlarr': {'target': '/config', 'port': 9696, 'hostPort': 9696, 'db': 'prowlarr.db'},
    'usenet-ultimate': {'target': '/app/config', 'port': 1337, 'hostPort': 1337},
    'overseerr': {'target': '/app/config', 'port': 5055, 'hostPort': 5055},
}


def log(message):
    print(message, flush=True)


def run(*args, capture=False, **kwargs):
    return subprocess.run(args, check=True, text=True,
        stdout=subprocess.PIPE if capture else None, **kwargs).stdout


def atomic_text(path, text, mode=None):
    original = path.stat() if path.exists() else None
    fd, temporary = tempfile.mkstemp(prefix='.nas-core-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode if mode is not None else (original.st_mode & 0o777 if original else 0o600))
        if original:
            os.chown(temporary, original.st_uid, original.st_gid)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_json(path, document):
    atomic_text(path, json.dumps(document, indent=2) + '\n')


def environment(container):
    return dict(item.split('=', 1) for item in container['Config'].get('Env', []) if '=' in item)


def qname(name):
    return '"' + name.replace('"', '""') + '"'


def columns(connection, table):
    return {row[1].lower(): row[1] for row in connection.execute('PRAGMA table_info(' + qname(table) + ')')}


def config_value(connection, name, value):
    changed = connection.execute('UPDATE Config SET Value=? WHERE lower(Key)=?', (value, name.lower())).rowcount
    if not changed:
        connection.execute('INSERT INTO Config (Key, Value) VALUES (?,?)', (name.lower(), value))


def rewrite_url(value, ports):
    if not isinstance(value, str) or not value.startswith(('http://', 'https://')):
        return value
    url = urllib.parse.urlsplit(value)
    host = (url.hostname or '').lower()
    alias = None
    aliases = {'seerr': 'overseerr', 'infinidysk': 'nzbdav', 'infinidysk-nas': 'nzbdav'}
    if host in set(APPS) | set(aliases) | {'nzbdav'}:
        alias = aliases.get(host, host)
    elif host == '192.168.0.29':
        exposed = {8989: 'sonarr', 7878: 'radarr', 7879: 'radarr4k', 9696: 'prowlarr',
                   1337: 'usenet-ultimate', 5055: 'overseerr', 8081: 'nzbdav', 8082: 'nzbdav'}
        alias = exposed.get(url.port)
    elif host.endswith('.sawdoctor.uk'):
        prefix = host.split('.')[0]
        if prefix in set(APPS) | set(aliases) | {'nzbdav'}:
            alias = aliases.get(prefix, prefix)
    if alias:
        port = 8080 if alias == 'nzbdav' else ports[alias]
        return url._replace(scheme='http', netloc=alias + ':' + str(port)).geturl()
    return value


def rewrite_values(value, ports):
    if isinstance(value, dict):
        return {key: rewrite_values(item, ports) for key, item in value.items()}
    if isinstance(value, list):
        return [rewrite_values(item, ports) for item in value]
    return rewrite_url(value, ports)


def patch_xml(folder, name):
    path = folder / 'config.xml'
    tree = ET.parse(path)
    root = tree.getroot()
    key = root.findtext('ApiKey')
    if not key:
        raise RuntimeError('No copied API key was found for ' + name + '.')
    def put(tag, text):
        node = root.find(tag)
        if node is None:
            node = ET.SubElement(root, tag)
        node.text = text
    port = int(root.findtext('Port') or APPS[name]['port'])
    if not 1 <= port <= 65535:
        raise RuntimeError('Invalid copied application port for ' + name + '.')
    for tag, value in {'BindAddress': '*', 'Port': str(port), 'UrlBase': '',
                       'EnableSsl': 'False', 'LaunchBrowser': 'False'}.items():
        put(tag, value)
    atomic_text(path, ET.tostring(root, encoding='unicode'))
    return key, port


def row_settings(connection, table):
    if not columns(connection, table):
        return []
    connection.row_factory = sqlite3.Row
    return list(connection.execute('SELECT * FROM ' + qname(table)))


def set_row_settings(connection, table, row, settings, changes=None):
    fields = {'Settings': json.dumps(settings, separators=(',', ':')), **(changes or {})}
    connection.execute('UPDATE ' + qname(table) + ' SET '
        + ', '.join(qname(key) + '=?' for key in fields) + ' WHERE Id=?', [*fields.values(), row['Id']])


def patch_arr_database(path, name, keys, ports, infini_key):
    if not path.is_file():
        raise RuntimeError('The copied database is missing for ' + name + '.')
    connection = sqlite3.connect(path)
    try:
        for required in ('Config', 'DownloadClients', 'Notifications'):
            if not columns(connection, required):
                raise RuntimeError('Unexpected ' + name + ' database schema: ' + required)
        # These are test copies: interactive requests/searches work; scheduled grabs do not.
        if name != 'prowlarr':
            config_value(connection, 'RssSyncInterval', '0')
            config_value(connection, 'AutoRedownloadFailed', 'False')
            config_value(connection, 'AutoRedownloadFailedFromInteractiveSearch', 'False')
        for table in ('ImportLists', 'Notifications'):
            fields = columns(connection, table)
            disable = [actual for lower, actual in fields.items() if
                (table == 'ImportLists' and lower in ('enabled', 'enableauto', 'enableautomaticadd',
                    'enableautomaticsearch', 'searchonadd', 'searchformissingepisodes'))
                or (table == 'Notifications' and (lower.startswith('on') or lower == 'enabled'))]
            if disable:
                connection.execute('UPDATE ' + qname(table) + ' SET ' + ', '.join(qname(field) + '=0' for field in disable))
        if columns(connection, 'PendingReleases'):
            connection.execute('DELETE FROM PendingReleases')
        if 'status' in columns(connection, 'Commands'):
            connection.execute("UPDATE Commands SET Status=5 WHERE typeof(Status)='integer' AND Status IN (0,1)")
            connection.execute("UPDATE Commands SET Status='cancelled' WHERE typeof(Status)='text' AND lower(Status) IN ('queued','started')")
        download_clients = 0
        for row in row_settings(connection, 'DownloadClients'):
            settings = rewrite_values(json.loads(row['Settings']), ports)
            host = str(settings.get('host', '')).lower()
            title = str(row['Name']).lower()
            is_infini = ('nzbdav' in host or 'infinidysk' in host or 'nzbdav' in title or 'infini' in title
                or (host in ('192.168.0.29', '192.168.0.220') and settings.get('port') in (8080, 8082)))
            if 'sabnzbd' in str(row['Implementation']).lower() and is_infini:
                settings.update({'host': 'nzbdav', 'port': 8080, 'useSsl': False, 'urlBase': '', 'apiKey': infini_key})
                set_row_settings(connection, 'DownloadClients', row, settings, {'Enable': 1})
                download_clients += 1
            else:
                set_row_settings(connection, 'DownloadClients', row, settings, {'Enable': 0})
        if name != 'prowlarr' and not download_clients:
            raise RuntimeError('No recognizable InfiniDysk download client was found for ' + name + '.')
        for row in row_settings(connection, 'Indexers'):
            settings = rewrite_values(json.loads(row['Settings']), ports)
            changes = {'EnableRss': 0} if 'enablerss' in columns(connection, 'Indexers') else None
            set_row_settings(connection, 'Indexers', row, settings, changes)
        for row in row_settings(connection, 'Applications'):
            settings = rewrite_values(json.loads(row['Settings']), ports)
            implementation = str(row['Implementation']).lower()
            if implementation == 'sonarr':
                target = 'sonarr'
            elif implementation == 'radarr':
                target = 'radarr4k' if ('4k' in str(row['Name']).lower()
                    or ':7879' in str(settings.get('baseUrl', '')) or 'radarr4k' in str(settings.get('baseUrl', ''))) else 'radarr'
            else:
                set_row_settings(connection, 'Applications', row, settings, {'SyncLevel': 0})
                continue
            settings.update({'baseUrl': 'http://' + target + ':' + str(ports[target]),
                'prowlarrUrl': 'http://prowlarr:' + str(ports['prowlarr']), 'apiKey': keys[target]})
            set_row_settings(connection, 'Applications', row, settings)
        if connection.execute('PRAGMA quick_check').fetchall()[0][0] != 'ok':
            raise RuntimeError('The prepared database failed integrity verification for ' + name + '.')
        connection.commit()
    finally:
        connection.close()
        st = path.stat()
        for suffix in ('-wal', '-shm', '-journal'):
            auxiliary = Path(str(path) + suffix)
            if auxiliary.exists():
                os.chown(auxiliary, st.st_uid, st.st_gid)


def patch_seerr(folder, keys, ports):
    path = folder / 'settings.json'
    settings = json.loads(path.read_text())
    settings.setdefault('main', {})['applicationUrl'] = 'http://192.168.0.220:5055'
    for app in ('radarr', 'sonarr'):
        for server in settings.get(app, []):
            target = 'radarr4k' if app == 'radarr' and server.get('is4k') else app
            server.update({'hostname': target, 'port': ports[target], 'useSsl': False,
                'baseUrl': '', 'apiKey': keys[target], 'preventSearch': False,
                'externalUrl': 'http://192.168.0.220:' + str(APPS[target]['hostPort'])})
    for agent in settings.get('notifications', {}).get('agents', {}).values():
        agent['enabled'] = False
    atomic_text(path, json.dumps(settings, indent=2) + '\n')
    found = False
    for candidate in folder.rglob('*'):
        if not candidate.is_file() or candidate.is_symlink() or candidate.suffix.lower() not in ('.db', '.sqlite', '.sqlite3'):
            continue
        with candidate.open('rb') as stream:
            if stream.read(16) != b'SQLite format 3\x00':
                continue
        connection = sqlite3.connect(candidate)
        try:
            tables = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            for table in tables:
                fields = columns(connection, table)
                flags = [actual for lower, actual in fields.items()
                         if lower.replace('_', '') in ('watchlistsyncmovies', 'watchlistsynctv')]
                if flags:
                    connection.execute('UPDATE ' + qname(table) + ' SET ' + ', '.join(qname(field) + '=0' for field in flags))
                    found = True
            connection.commit()
        finally:
            connection.close()
    if not found:
        raise RuntimeError('The copied Seerr watchlist settings could not be identified before startup.')


def patch_ultimate(folder, ports, keys, infini):
    path = folder / 'config.json'
    settings = rewrite_values(json.loads(path.read_text()), ports)
    settings.update({'prowlarrUrl': 'http://prowlarr:' + str(ports['prowlarr']),
        'prowlarrApiKey': keys['prowlarr'], 'nzbdavUrl': 'http://nzbdav:8080',
        'nzbdavApiKey': infini['apiKey'], 'nzbdavWebdavUrl': 'http://nzbdav:8080',
        'nzbdavWebdavUser': infini['user'], 'nzbdavWebdavPassword': infini['password']})
    # Searches may health-check results, but must not prequeue every result on a test server.
    if isinstance(settings.get('healthChecks'), dict):
        settings['healthChecks']['autoQueueMode'] = 'off'
    atomic_text(path, json.dumps(settings, indent=2) + '\n')


def bind(source, target, readonly=False):
    return {'type': 'bind', 'source': str(source), 'target': target,
            'read_only': readonly, 'bind': {'create_host_path': False}}


def compose_document(containers, data, library, scratch, ports, keys, infini):
    result = {'name': PROJECT, 'x-sawdoctor-managed': MARKER, 'services': {},
              'networks': {NETWORK: {'external': True, 'name': NETWORK}}}
    references = {}
    for source in containers.values():
        references.setdefault(source['Config']['Image'], set()).add(source['Image'])
    for name, source in containers.items():
        env = environment(source)
        for key in list(env):
            if key.endswith(('__SERVER__PORT', '__SERVER__URLBASE', '__SERVER__BINDADDRESS', '__SERVER__ENABLESSL', '__AUTH__APIKEY')):
                del env[key]
        if name == 'usenet-ultimate':
            env.update({'PORT': str(ports[name]), 'NZBDAV_URL': 'http://nzbdav:8080',
                'NZBDAV_API_KEY': infini['apiKey'], 'NZBDAV_WEBDAV_URL': 'http://nzbdav:8080',
                'NZBDAV_WEBDAV_USER': infini['user'], 'NZBDAV_WEBDAV_PASS': infini['password'],
                'PROWLARR_URL': 'http://prowlarr:' + str(ports['prowlarr']),
                'PROWLARR_API_KEY': keys['prowlarr']})
        env = {key: rewrite_url(value, ports).replace('$', '$$') for key, value in env.items()}
        aliases = [name] + (['seerr'] if name == 'overseerr' else [])
        reference = source['Config']['Image']
        if len(references[reference]) > 1 or '@' in reference or reference.startswith('sha256:'):
            reference = source['Image']
        service = {'image': reference,
            'container_name': ('seerr' if name == 'overseerr' else name) + '-nas',
            'restart': 'unless-stopped', 'pull_policy': 'never',
            'environment': env, 'networks': {NETWORK: {'aliases': aliases}},
            'ports': ['192.168.0.220:' + str(APPS[name]['hostPort']) + ':' + str(ports[name])],
            'volumes': [bind(data / name, APPS[name]['target'])],
            'logging': {'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '3'}}}
        if source['Config'].get('User'):
            service['user'] = source['Config']['User']
        if name in ('sonarr', 'radarr', 'radarr4k'):
            service['volumes'].extend([bind(library, '/mnt/media'), bind('/mnt/nzbdav', '/mnt/nzbdav'), bind(scratch, '/scratch')])
        result['services'][name] = service
    return result


def connect_infini(document, keys, ports, db_settings):
    document = copy.deepcopy(document)
    service = document['services']['infinidysk']
    if service.get('container_name') != 'infinidysk-nas':
        raise RuntimeError('Unexpected existing InfiniDysk container name.')
    networks = service.get('networks', ['default'])
    if isinstance(networks, list):
        networks = {name: {} for name in networks}
    networks[NETWORK] = {'aliases': ['nzbdav', 'infinidysk']}
    service['networks'] = networks
    document.setdefault('networks', {}).setdefault('default', {})
    document['networks'][NETWORK] = {'external': True, 'name': NETWORK}
    prior = json.loads(db_settings.get('arr.instances') or '{}')
    arr = {'RadarrInstances': [{'Host': 'http://' + name + ':' + str(ports[name]), 'ApiKey': keys[name]}
                              for name in ('radarr', 'radarr4k')],
           'SonarrInstances': [{'Host': 'http://sonarr:' + str(ports['sonarr']), 'ApiKey': keys['sonarr']}],
           'QueueRules': prior.get('QueueRules', [])}
    env = service['environment']
    env.update({'NZBDAV_CONFIG__ARR__INSTANCES': json.dumps(arr, separators=(',', ':')).replace('$', '$$'),
        'NZBDAV_CONFIG__ARR__HEALTH_ENABLED': 'true',
        'NZBDAV_CONFIG__PROWLARR__URL': 'http://prowlarr:' + str(ports['prowlarr']),
        'NZBDAV_CONFIG__PROWLARR__API_KEY': keys['prowlarr'].replace('$', '$$'),
        'NZBDAV_CONFIG__PROWLARR__SYNC_ENABLED': 'true',
        'NZBDAV_CONFIG__WEBDAV__ENFORCE_READONLY': 'false'})
    for mount in service['volumes']:
        if mount.get('target') in ('/mnt/media', '/mnt/nzbdav'):
            mount['read_only'] = False
    return document


def write_mount_override():
    unit = Path('/etc/systemd/system/nas-infinidysk-rclone.service')
    text = unit.read_text()
    if 'Sawdoctor NAS InfiniDysk media mount v1' not in text:
        raise RuntimeError('The NAS media mount unit is not the expected installation.')
    commands = [line.split('=', 1)[1] for line in text.splitlines() if line.startswith('ExecStart=')]
    if len(commands) != 1:
        raise RuntimeError('The existing NAS mount command could not be identified.')
    command = [item for item in shlex.split(commands[0]) if item != '--read-only']
    if command[:4] != ['/usr/local/libexec/infinidysk-rclone', 'mount', 'nzbdav:', '/mnt/nzbdav']:
        raise RuntimeError('Unexpected NAS mount command.')
    directory = unit.parent / (unit.name + '.d')
    directory.mkdir(mode=0o755, exist_ok=True)
    path = directory / '20-nas-acquisition.conf'
    if path.exists() and MARKER not in path.read_text():
        raise RuntimeError('An unrelated media mount override already exists.')
    atomic_text(path, '# ' + MARKER + '\n[Unit]\nDescription=NAS InfiniDysk media for acquisition and playback\n'
        '[Service]\nExecStart=\nExecStart=' + shlex.join(command) + '\n', 0o644)


def check_ports(existing, names):
    expected = {('seerr' if name == 'overseerr' else name) + '-nas' for name in names}
    own = {c['Name'].lstrip('/'): c for c in existing if c['Name'].lstrip('/') in expected}
    for name, container in own.items():
        labels = container['Config'].get('Labels') or {}
        if labels.get('com.docker.compose.project') != PROJECT:
            raise RuntimeError('A different existing container already uses the name ' + name + '.')
    target_ports = {str(APPS[name]['hostPort']) for name in names}
    for container in existing:
        if container['Name'].lstrip('/') in own:
            continue
        for bindings in (container['HostConfig'].get('PortBindings') or {}).values():
            if any(item.get('HostPort') in target_ports for item in bindings or []):
                raise RuntimeError('Another NAS container already reserves a required core port: ' + container['Name'])
    for name in names:
        if ('seerr' if name == 'overseerr' else name) + '-nas' not in own:
            with socket.socket() as listener:
                listener.bind(('192.168.0.220', APPS[name]['hostPort']))


def wait_http(label, url, api_key=None):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for attempt in range(90):
        try:
            request = urllib.request.Request(url, headers={'X-Api-Key': api_key} if api_key else {})
            with opener.open(request, timeout=3) as response:
                if response.status == 200:
                    log(label + ': responding')
                    return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(2)
    raise RuntimeError(label + ' did not become ready. The NAS configuration was retained for retry.')


def silo_override(containers, library):
    matches = [c for c in containers if c['Name'] == '/silo-nas-silo-1']
    if len(matches) != 1:
        raise RuntimeError('The existing NAS Silo container could not be identified.')
    source = matches[0]
    labels = source['Config'].get('Labels') or {}
    if labels.get('com.docker.compose.project') != 'silo-nas':
        raise RuntimeError('Unexpected Silo Compose project.')
    files = labels.get('com.docker.compose.project.config_files', '').split(',')
    service = labels.get('com.docker.compose.service')
    if not service or not files or not all(Path(path).is_file() for path in files):
        raise RuntimeError('The existing Silo Compose sources were not found.')
    stack = SSD / 'compose/silo-nas'
    path = stack / 'nas-media.override.json'
    if path.exists() and json.loads(path.read_text()).get('x-sawdoctor-managed') != MARKER:
        raise RuntimeError('An unrelated Silo media override already exists.')
    backup = stack / 'silo.before-core.inspect.json'
    if not backup.exists():
        write_json(backup, source)
    document = {'x-sawdoctor-managed': MARKER, 'services': {service: {'volumes': [
        bind(library / name, '/mnt/media/' + name, True) for name in ('movies', 'movies-4k', 'tv')
    ] + [bind('/mnt/nzbdav', '/mnt/nzbdav', True)]}}}
    write_json(path, document)
    files = [file for file in files if file != str(path)] + [str(path)]
    command = ['docker', 'compose', '-p', 'silo-nas', '--project-directory', str(stack)]
    for file in files:
        command.extend(['-f', file])
    return command, service


def check_internal_connections(keys, ports):
    tests = [{'name': 'NAS InfiniDysk', 'url': 'http://nzbdav:8080/health'}]
    for name in ('sonarr', 'radarr', 'radarr4k', 'prowlarr'):
        version = 'v1' if name == 'prowlarr' else 'v3'
        tests.append({'name': name, 'url': 'http://' + name + ':' + str(ports[name])
            + '/api/' + version + '/system/status', 'key': keys[name]})
    tests.append({'name': 'Seerr', 'url': 'http://overseerr:5055/api/v1/status'})
    script = '''const fs = require('fs');
const tests = JSON.parse(fs.readFileSync(0, 'utf8'));
(async () => {
  let failed = false;
  for (const test of tests) {
    try {
      const response = await fetch(test.url, {
        headers: test.key ? {'X-Api-Key': test.key} : {},
        signal: AbortSignal.timeout(10000)
      });
      if (!response.ok) { failed = true; console.log(test.name + ': HTTP ' + response.status); }
      else console.log(test.name + ': NAS network connection verified');
      await response.arrayBuffer();
    } catch (_) { failed = true; console.log(test.name + ': NAS network request failed'); }
  }
  process.exitCode = failed ? 1 : 0;
})();'''
    result = subprocess.run(['docker', 'exec', '-i', 'usenet-ultimate-nas', 'node', '-e', script],
        input=json.dumps(tests), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    if result.stdout.strip():
        log(result.stdout.strip())
    if result.returncode:
        raise RuntimeError('A NAS internal connection check failed; no credential values were printed.')


def check_silo_bindings(library):
    silo = json.loads(run('docker', 'inspect', 'silo-nas-silo-1', capture=True))[0]
    mounts = {mount['Destination']: mount for mount in silo['Mounts']}
    required = {'/mnt/media/' + name: str(library / name) for name in ('movies', 'movies-4k', 'tv')}
    required['/mnt/nzbdav'] = '/mnt/nzbdav'
    if not silo['State']['Running'] or any(target not in mounts or mounts[target]['Source'] != source
        or mounts[target]['RW'] for target, source in required.items()):
        raise RuntimeError('Silo did not retain all four read-only NAS media bindings.')
    log('Silo: NAS library and NAS rclone bindings verified')


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show', capture=True):
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220.')
    if not SSD.is_mount() or not SCRATCH.is_mount():
        raise RuntimeError('The appdata SSD and scratch NVMe must be mounted.')
    snapshot = SSD / 'migration/core-optiplex/snapshot'
    manifest = json.loads((snapshot / 'manifest.json').read_text())
    containers = {c['Name'].lstrip('/'): c for c in manifest['containers']}
    if (manifest.get('format') != 'sawdoctor-core-export-v1' or manifest.get('sourceHost') != '192.168.0.29'
        or set(containers) != set(APPS)):
        raise RuntimeError('The verified six-app snapshot was not found.')
    data = SSD / 'appdata/media-core-nas'
    stack = SSD / 'compose/media-core-nas'
    library = SSD / 'appdata/infinidysk-nas/library'
    scratch = SCRATCH / 'scratch/infinidysk-nas'
    backend = SSD / 'compose/infinidysk-nas/compose.json'
    for path in (data, stack, library, scratch, backend):
        if path.is_symlink():
            raise RuntimeError('Unexpected symlink at a NAS deployment path.')
    for name in ('movies', 'movies-4k', 'tv'):
        if not (library / name).is_dir():
            raise RuntimeError('The copied NAS media library is missing ' + name + '.')
    if run('findmnt', '-n', '--mountpoint', '/mnt/nzbdav', '-o', 'FSTYPE,SOURCE', capture=True).split() != ['fuse.rclone', 'nzbdav:']:
        raise RuntimeError('The NAS media mount is not ready.')
    backend_doc = json.loads(backend.read_text())
    backend_env = backend_doc['services']['infinidysk']['environment']
    infini = {'apiKey': backend_env['FRONTEND_BACKEND_API_KEY'].replace('$$', '$'),
        'user': backend_env['NZBDAV_CONFIG__WEBDAV__USER'].replace('$$', '$'),
        'password': backend_env['NZBDAV_CONFIG__WEBDAV__PASS'].replace('$$', '$')}
    marker_path = data / 'nas-core-install.json'
    if data.exists() and (not marker_path.is_file() or json.loads(marker_path.read_text()).get('format') != MARKER):
        raise RuntimeError('Existing core appdata has no matching migration marker; it was retained.')
    if marker_path.exists() and json.loads(marker_path.read_text()).get('completed'):
        log('The NAS core deployment is already complete. Existing application settings were retained.')
        print_addresses()
        return
    ids = run('docker', 'ps', '-aq', capture=True).split()
    existing = json.loads(run('docker', 'inspect', *ids, capture=True)) if ids else []
    check_ports(existing, containers)
    log('Verifying the staged core files and exact image archive...')
    run('sha256sum', '--quiet', '-c', 'SHA256SUMS', cwd=snapshot)
    log('Waiting for the NAS backup lock...')
    with open('/run/lock/sawdoctor-nas-backup.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        ports = {name: details['port'] for name, details in APPS.items()}
        uu_env = environment(containers['usenet-ultimate'])
        ports['usenet-ultimate'] = int(uu_env.get('PORT', ports['usenet-ultimate']))
        if ports['usenet-ultimate'] != 1337:
            raise RuntimeError('The copied Usenet Ultimate internal port differs from the verified image layout.')
        if not data.exists():
            log('Preparing the six NAS configuration copies and manual test settings...')
            work = Path(tempfile.mkdtemp(prefix='.media-core-nas-', dir=data.parent))
            try:
                for name in APPS:
                    run('cp', '-a', '--', str(snapshot / 'configs' / name), str(work / name))
                keys = {}
                for name in ('sonarr', 'radarr', 'radarr4k', 'prowlarr'):
                    keys[name], ports[name] = patch_xml(work / name, name)
                for name in ('sonarr', 'radarr', 'radarr4k', 'prowlarr'):
                    patch_arr_database(work / name / APPS[name]['db'], name, keys, ports, infini['apiKey'])
                patch_seerr(work / 'overseerr', keys, ports)
                patch_ultimate(work / 'usenet-ultimate', ports, keys, infini)
                write_json(work / 'nas-core-install.json', {'format': MARKER,
                    'sourceCreatedUtc': manifest['createdUtc'], 'ports': ports, 'completed': False})
                os.replace(work, data)
            finally:
                if work.exists():
                    shutil.rmtree(work)
        marker = json.loads(marker_path.read_text())
        ports = marker['ports']
        keys = {name: ET.parse(data / name / 'config.xml').getroot().findtext('ApiKey')
                for name in ('sonarr', 'radarr', 'radarr4k', 'prowlarr')}
        stack.mkdir(parents=True, mode=0o700, exist_ok=True)
        compose = stack / 'compose.json'
        if compose.exists() and json.loads(compose.read_text()).get('x-sawdoctor-managed') != MARKER:
            raise RuntimeError('An unrelated core Compose file already exists.')
        if not compose.exists():
            write_json(compose, compose_document(containers, data, library, scratch, ports, keys, infini))
        tag_ids = {}
        for source in containers.values():
            image = source['Config']['Image']
            tag_ids.setdefault(image, set()).add(source['Image'])
        log('Loading the exact exported Docker images...')
        run('docker', 'image', 'load', '--input', str(snapshot / 'images.tar'))
        for tag, image_ids in tag_ids.items():
            for image_id in image_ids:
                loaded = json.loads(run('docker', 'image', 'inspect', image_id, capture=True))[0]
                if loaded['Id'] != image_id:
                    raise RuntimeError('An exported image did not retain its expected identity.')
            if len(image_ids) == 1 and '@' not in tag and not tag.startswith('sha256:'):
                run('docker', 'image', 'tag', next(iter(image_ids)), tag)
        network = subprocess.run(['docker', 'network', 'inspect', NETWORK], text=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if network.returncode:
            run('docker', 'network', 'create', '--driver', 'bridge', '--label', 'sawdoctor.migration=nas-core', NETWORK)
        elif json.loads(network.stdout)[0].get('Driver') != 'bridge':
            raise RuntimeError('The existing NAS media-core network is not a local bridge.')
        database = SSD / 'appdata/infinidysk-nas/config/db.sqlite'
        connection = sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)
        try:
            db_settings = dict(connection.execute('SELECT ConfigName, ConfigValue FROM ConfigItems'))
        finally:
            connection.close()
        backup = backend.parent / 'compose.before-core.json'
        if not backup.exists():
            atomic_text(backup, backend.read_text(), 0o600)
        write_json(backend, connect_infini(backend_doc, keys, ports, db_settings))
        run('docker', 'compose', '-f', str(backend), 'config', '--quiet')
        run('docker', 'compose', '-f', str(compose), 'config', '--quiet')
        write_mount_override()
        run('systemctl', 'daemon-reload')
    # The mount's existing refresh helper takes the backup lock itself.
    log('Enabling NAS media imports and connecting InfiniDysk to the NAS app network...')
    run('systemctl', 'restart', 'nas-infinidysk-rclone.service')
    log('Starting the six NAS applications...')
    with open('/run/lock/sawdoctor-nas-backup.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        run('docker', 'compose', '-f', str(compose), 'up', '-d', '--pull', 'never', '--wait', '--wait-timeout', '300')
    for name in ('sonarr', 'radarr', 'radarr4k', 'prowlarr'):
        version = 'v1' if name == 'prowlarr' else 'v3'
        wait_http(name, 'http://192.168.0.220:' + str(APPS[name]['hostPort']) + '/api/' + version + '/system/status', keys[name])
    wait_http('Usenet Ultimate', 'http://192.168.0.220:1337/health')
    wait_http('Seerr', 'http://192.168.0.220:5055/api/v1/status')
    check_internal_connections(keys, ports)
    ids = run('docker', 'ps', '-aq', capture=True).split()
    current = json.loads(run('docker', 'inspect', *ids, capture=True))
    with open('/run/lock/sawdoctor-nas-backup.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        command, service = silo_override(current, library)
        run(*command, 'config', '--quiet')
        log('Switching Silo to the NAS library and NAS rclone mount...')
        run(*command, 'up', '-d', '--pull', 'never', '--no-deps', service)
        check_silo_bindings(library)
        marker['completed'] = True
        write_json(marker_path, marker)
    log('\nNAS CORE DEPLOYED. Silo now uses NAS InfiniDysk media.')
    log('RSS grabs, import-list automation, Seerr watchlists and copied notifications are disabled for manual testing.')
    log('Existing library paths, quality profiles, user accounts and API keys are retained.')
    print_addresses()


def print_addresses():
    for name, port in [('Silo', 8090), ('InfiniDysk', 8081), ('Seerr', 5055), ('Sonarr', 8989),
                       ('Radarr', 7878), ('Radarr 4K', 7879), ('Prowlarr', 9696), ('Usenet Ultimate', 1337)]:
        log(name + ': http://192.168.0.220:' + str(port))


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit('\nInterrupted. Prepared NAS configurations were retained; rerun to continue.')
    except Exception as error:
        raise SystemExit('STOP: ' + str(error))
