#!/usr/bin/env python3
"""Endpoint adapters for PRIVATE source-authoritative production restore copies.

Unlike the initial NAS test deployer, these adapters never clear queues, disable
RSS/import lists/watchlists/notifications, change search/repair flags, merge
catalogues, or add missing media. Callers must copy and verify frozen source
roots first, and must pass a separate private working root as the write fence.
This module has no host actions, installer, service control, or activation CLI.
"""
import copy
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import urllib.parse
import xml.etree.ElementTree as ET

SOURCE_IP = '192.168.0.29'
NAS_IP = '192.168.0.220'
PORTS = {'sonarr': 8989, 'radarr': 7878, 'radarr4k': 7878, 'prowlarr': 9696,
         'usenet-ultimate': 1337, 'overseerr': 5055}
NAS_HOST_PORTS = {8989, 7878, 7879, 9696, 1337, 5055, 8080, 8081, 8082, 32400}
INF_CORE_MACHINE = {
    'FRONTEND_BACKEND_API_KEY', 'NZBDAV_CONFIG__API__KEY',
    'NZBDAV_CONFIG__WEBDAV__USER', 'NZBDAV_CONFIG__WEBDAV__PASS',
    'NZBDAV_CONFIG__WEBDAV__ENFORCE_READONLY',
    'NZBDAV_CONFIG__GENERAL__BASE_URL', 'NZBDAV_CONFIG__MEDIA__LIBRARY_DIR',
    'NZBDAV_CONFIG__RCLONE__MOUNT_DIR', 'NZBDAV_CONFIG__RCLONE__RC_ENABLED',
}
MACHINE_ENV = {'PUID', 'PGID', 'TZ', 'PORT', 'CONFIG_PATH', 'TMPDIR', 'TMP', 'TEMP',
               'BACKEND_URL', 'SECURE_COOKIES'}
CONNECTION_TABLES = ('DownloadClients', 'Indexers', 'Applications', 'Notifications', 'ImportLists')


def safe(path):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise RuntimeError('A symbolic production-restore working path was retained.')


def fenced(root, path):
    root, path = Path(root), Path(path)
    safe(root); safe(path)
    if not root.is_absolute() or path == root or not path.is_relative_to(root):
        raise RuntimeError('A restore adapter was given a path outside its private working root.')
    return path


def write(root, path, value):
    path = fenced(root, path)
    original = path.stat()
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(value); stream.flush(); os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), original.st_mode & 0o777)
            if os.geteuid() == 0:
                os.fchown(stream.fileno(), original.st_uid, original.st_gid)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def endpoint(value):
    if not isinstance(value, str) or not value.startswith(('http://', 'https://')):
        return value
    url = urllib.parse.urlsplit(value)
    if url.username or url.password:
        # Embedded credentials need a dedicated adapter, never generic rewriting.
        if url.hostname == SOURCE_IP:
            raise RuntimeError('A source endpoint has embedded credentials; review is required.')
        return value
    if url.hostname == SOURCE_IP and url.port in NAS_HOST_PORTS:
        port = 8082 if url.port == 8080 else url.port
        return url._replace(netloc=NAS_IP + ':' + str(port)).geturl()
    return value


def connections(value):
    if isinstance(value, list):
        return [connections(v) for v in value]
    if not isinstance(value, dict):
        return endpoint(value)
    result = {k: connections(v) for k, v in value.items()}
    fields = {k.lower(): k for k in result}
    host = fields.get('host') or fields.get('hostname')
    port = fields.get('port')
    if host and port and result[host] == SOURCE_IP:
        try:
            number = int(result[port])
        except (TypeError, ValueError):
            return result
        if number in NAS_HOST_PORTS:
            result[host] = NAS_IP
            if number == 8080:
                result[port] = 8082
    return result


def environment(values):
    if isinstance(values, dict):
        return dict(values)
    return dict(v.split('=', 1) for v in values if '=' in v)


def environment_value(value):
    if isinstance(value, str) and value.lstrip().startswith(('{', '[')):
        try:
            parsed = json.loads(value)
        except ValueError:
            return endpoint(value)
        updated = connections(parsed)
        return json.dumps(updated, separators=(',', ':')) if updated != parsed else value
    return endpoint(value)


def runtime_environment(name, source, nas, infini):
    """Restore source behavior and preserve the deliberate NAS runtime adapters."""
    source, nas = environment(source), environment(nas)
    result = {key: environment_value(value) for key, value in source.items()}
    for key in MACHINE_ENV:
        if key in nas:
            result[key] = nas[key]
    if name == 'nzbdav':
        for key in INF_CORE_MACHINE:
            if key in nas:
                result[key] = nas[key]
            else:
                result.pop(key, None)
        # This is the user's notify-only update policy, not a test-mode setting.
        result['NZBDAV_CONFIG__WATCHTOWER__ENABLED'] = 'false'
        trusted = result.get('NZBDAV_CONFIG__API__ADDURL_TRUSTED_HOSTS', '').split(',')
        if SOURCE_IP in trusted and NAS_IP not in trusted:
            result['NZBDAV_CONFIG__API__ADDURL_TRUSTED_HOSTS'] = ','.join(trusted + [NAS_IP])
    elif name == 'usenet-ultimate':
        result.update({'NZBDAV_URL': 'http://nzbdav:8080', 'NZBDAV_API_KEY': infini['apiKey'],
                       'NZBDAV_WEBDAV_URL': 'http://nzbdav:8080',
                       'NZBDAV_WEBDAV_USER': infini['user'],
                       'NZBDAV_WEBDAV_PASS': infini['password']})
    else:
        # Existing NAS listener/host restrictions are machine-specific. Source
        # non-server overrides (including policy settings) remain authoritative.
        for key, value in nas.items():
            if '__SERVER__' in key.upper():
                result[key] = value
    return result


def quote(name):
    return '"' + name.replace('"', '""') + '"'


def open_copy(root, path):
    path = fenced(root, path)
    if not path.is_file():
        raise RuntimeError('A required copied database is unavailable.')
    db = sqlite3.connect(path.as_uri() + '?mode=rw', uri=True, timeout=30)
    db.row_factory = sqlite3.Row
    return db


def check(db):
    if [tuple(row) for row in db.execute('PRAGMA quick_check')] != [('ok',)]:
        raise RuntimeError('A private production restore database failed its integrity check.')


def align_auxiliary(root, path):
    path = fenced(root, path)
    original = path.stat()
    for suffix in ('-wal', '-shm', '-journal'):
        auxiliary = Path(str(path) + suffix)
        if auxiliary.exists() or auxiliary.is_symlink():
            fenced(root, auxiliary)
            if not auxiliary.is_file():
                raise RuntimeError('A private SQLite support file is not a regular file.')
            os.chmod(auxiliary, original.st_mode & 0o777)
            if os.geteuid() == 0:
                os.chown(auxiliary, original.st_uid, original.st_gid)


def patch_arr(root, path, name, keys, ports, infini):
    """Only connection JSON columns change; all policy/queue/history rows survive."""
    db = open_copy(root, path)
    changed = 0
    try:
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {'Config', 'DownloadClients', 'Notifications'} <= tables:
            raise RuntimeError('The copied Arr schema differs from the reviewed application.')
        for table in CONNECTION_TABLES:
            if table not in tables:
                continue
            fields = {r[1].lower() for r in db.execute('PRAGMA table_info(' + quote(table) + ')')}
            if not {'id', 'settings'} <= fields:
                raise RuntimeError('A copied Arr connection table needs schema review.')
            for row in db.execute('SELECT * FROM ' + quote(table)).fetchall():
                original = json.loads(row['Settings'])
                updated = connections(original)
                if table == 'DownloadClients':
                    host = str(original.get('host', '')).lower()
                    title = str(row['Name']).lower()
                    is_infini = (host in ('nzbdav', 'infinidysk', 'infinidysk-nas')
                                 or 'nzbdav' in title or 'infini' in title
                                 or (host in (SOURCE_IP, NAS_IP) and original.get('port') in (8080, 8082)))
                    if 'sabnzbd' in str(row['Implementation']).lower() and is_infini:
                        updated.update(host='nzbdav', port=8080, useSsl=False, urlBase='', apiKey=infini['apiKey'])
                if table == 'Applications':
                    kind = str(row['Implementation']).lower()
                    if kind in ('sonarr', 'radarr'):
                        target = ('radarr4k' if kind == 'radarr' and
                                  ('4k' in str(row['Name']).lower() or ':7879' in str(original.get('baseUrl', ''))
                                   or 'radarr4k' in str(original.get('baseUrl', ''))) else kind)
                        updated.update(baseUrl='http://' + target + ':' + str(ports[target]),
                                       prowlarrUrl='http://prowlarr:' + str(ports['prowlarr']), apiKey=keys[target])
                if updated != original:
                    db.execute('UPDATE ' + quote(table) + ' SET Settings=? WHERE Id=?',
                               (json.dumps(updated, separators=(',', ':')), row['Id']))
                    changed += 1
        check(db); db.commit()
    finally:
        db.close()
        align_auxiliary(root, path)
    return changed


def patch_seerr(root, folder, keys, ports):
    path = fenced(root, folder / 'settings.json')
    original = json.loads(path.read_text())
    value = copy.deepcopy(original)
    value = connections(value)
    for kind in ('radarr', 'sonarr'):
        for server in value.get(kind, []):
            target = 'radarr4k' if kind == 'radarr' and server.get('is4k') else kind
            server.update(hostname=target, port=ports[target], useSsl=False,
                          baseUrl='', apiKey=keys[target])
            if server.get('externalUrl', '').startswith('http://' + SOURCE_IP):
                server['externalUrl'] = endpoint(server['externalUrl'])
    if value != original:
        write(root, path, (json.dumps(value, indent=2) + '\n').encode())
    # Its SQLite files are never opened for writing: watchlists, users, requests,
    # tokens and notification enablement are copied exactly, not reset for tests.
    return value != original


def patch_ultimate(root, folder, keys, ports, infini):
    path = fenced(root, folder / 'config.json')
    value = connections(json.loads(path.read_text()))
    value.update(prowlarrUrl='http://prowlarr:' + str(ports['prowlarr']), prowlarrApiKey=keys['prowlarr'],
                 nzbdavUrl='http://nzbdav:8080', nzbdavApiKey=infini['apiKey'],
                 nzbdavWebdavUrl='http://nzbdav:8080', nzbdavWebdavUser=infini['user'],
                 nzbdavWebdavPassword=infini['password'])
    write(root, path, (json.dumps(value, indent=2) + '\n').encode())


def patch_infinidysk(root, path):
    db = open_copy(root, path)
    changed = []
    try:
        for row in db.execute('SELECT ConfigName,ConfigValue FROM ConfigItems').fetchall():
            key, raw = row['ConfigName'], row['ConfigValue']
            if not isinstance(raw, str):
                continue
            try:
                value = json.loads(raw)
            except (ValueError, TypeError):
                updated = endpoint(raw)
            else:
                result = connections(value)
                updated = json.dumps(result, separators=(',', ':')) if result != value else raw
            if key == 'general.base-url' and raw.startswith('http://' + SOURCE_IP):
                updated = 'http://' + NAS_IP + ':8081'
            if key == 'api.addurl-trusted-hosts':
                hosts = raw.split(',')
                if SOURCE_IP in hosts and NAS_IP not in hosts:
                    updated = ','.join(hosts + [NAS_IP])
            if updated != raw:
                db.execute('UPDATE ConfigItems SET ConfigValue=? WHERE ConfigName=?', (updated, key))
                changed.append(key)
        check(db); db.commit()
    finally:
        db.close()
        align_auxiliary(root, path)
    return changed


def patch_xml(root, folder, nas_path, source_environment=()):
    path = fenced(root, folder / 'config.xml')
    safe(nas_path)
    source = ET.fromstring(path.read_bytes())
    nas = ET.fromstring(nas_path.read_bytes())
    prefix = 'RADARR' if folder.name == 'radarr4k' else folder.name.upper()
    source_env = environment(source_environment)
    key = source_env.get(prefix + '__AUTH__APIKEY') or source.findtext('ApiKey')
    if not key:
        raise RuntimeError('The source application API key is missing.')
    node = source.find('ApiKey')
    if node is None:
        node = ET.SubElement(source, 'ApiKey')
    node.text = key
    for tag in ('BindAddress', 'Port', 'UrlBase', 'EnableSsl', 'LaunchBrowser'):
        incoming = nas.find(tag)
        if incoming is not None:
            outgoing = source.find(tag)
            if outgoing is None:
                outgoing = ET.SubElement(source, tag)
            outgoing.text = incoming.text
    for node in source.findall('AllowedHosts'):
        hosts = [h.strip() for h in re.split('[,;]', node.text or '') if h.strip()]
        if hosts and '*' not in hosts and NAS_IP not in hosts:
            node.text = ','.join(hosts + [NAS_IP])
    port = int(source.findtext('Port') or PORTS[folder.name])
    if not 1 <= port <= 65535:
        raise RuntimeError('The existing NAS application port is invalid.')
    write(root, path, ET.tostring(source, encoding='utf-8'))
    return key, port
