#!/usr/bin/env python3
"""Enable the copied providers and indexers on Sawdoctor's NAS test only."""
import copy
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request

SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
API_URL = 'http://192.168.0.220:8082/api/update-config'


def run(*args, capture=False):
    return subprocess.run(args, check=True, text=True,
        stdout=subprocess.PIPE if capture else None).stdout


def atomic_text(path, text):
    fd, temporary = tempfile.mkstemp(prefix='.nas-test-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_settings(database):
    connection = sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)
    try:
        settings = dict(connection.execute('SELECT ConfigName, ConfigValue FROM ConfigItems'))
        queued = connection.execute('SELECT COUNT(*) FROM QueueItems').fetchone()[0]
        return settings, queued
    finally:
        connection.close()


def prepare(document, settings, original_env, queued):
    result = copy.deepcopy(document)
    service = result['services']['infinidysk']
    if service.get('container_name') != 'infinidysk-nas':
        raise RuntimeError('Unexpected NAS container name.')
    env = service['environment']
    providers = json.loads(original_env.get('NZBDAV_CONFIG__USENET__PROVIDERS')
        or settings.get('usenet.providers', '{"Providers":[]}'))
    if not providers.get('Providers'):
        raise RuntimeError('No copied provider settings were found.')
    for provider in providers['Providers']:
        if provider['Type'] == 0:
            provider['Type'] = 1
    indexers = json.loads(env.get('NZBDAV_CONFIG__INDEXERS__INSTANCES', '').replace('$$', '$')
        or settings.get('indexers.instances', '{"Indexers":[]}'))
    notes = []
    uses_prowlarr_lan = False
    for indexer in indexers.get('Indexers', []):
        indexer['Enabled'] = True
        url = urllib.parse.urlsplit(indexer['Url'])
        # Prowlarr is still on the OptiPlex, with its verified LAN port 9696.
        if url.hostname == 'prowlarr' and url.port in (None, 9696):
            indexer['Url'] = url._replace(netloc='192.168.0.29:9696').geturl()
            uses_prowlarr_lan = True
        elif url.hostname and ('.' not in url.hostname or url.hostname in ('127.0.0.1', '0.0.0.0')):
            notes.append((indexer['Name'], url.hostname, url.port))
    if uses_prowlarr_lan:
        key = 'NZBDAV_CONFIG__API__ADDURL_TRUSTED_HOSTS'
        trusted = env.get(key, '').replace('$$', '$') or settings.get('api.addurl-trusted-hosts', '')
        hosts = [host.strip() for host in trusted.split(',') if host.strip()]
        if '192.168.0.29' not in hosts:
            hosts.append('192.168.0.29')
        env[key] = ','.join(hosts).replace('$', '$$')
    # Release these controls to the web UI; keep the NAS isolation controls.
    for key in ('NZBDAV_CONFIG__USENET__PROVIDERS', 'NZBDAV_CONFIG__INDEXERS__INSTANCES'):
        env.pop(key, None)
    if queued:
        env['NZBDAV_CONFIG__QUEUE__PAUSED'] = 'true'
    else:
        env.pop('NZBDAV_CONFIG__QUEUE__PAUSED', None)
    env.update({
        'NZBDAV_CONFIG__ARR__INSTANCES': '{"RadarrInstances":[],"SonarrInstances":[],"QueueRules":[]}',
        'NZBDAV_CONFIG__ARR__HEALTH_ENABLED': 'false',
        'NZBDAV_CONFIG__PROWLARR__SYNC_ENABLED': 'false',
        'NZBDAV_CONFIG__REPAIR__ENABLE': 'false',
        'NZBDAV_CONFIG__WATCHTOWER__ENABLED': 'false',
        'NZBDAV_CONFIG__PLAY__WATCHDOG_ENABLED': 'false',
        'NZBDAV_CONFIG__MAINTENANCE__REMOVE_ORPHANED_SCHEDULE_ENABLED': 'false',
        'NZBDAV_CONFIG__USENET__WARM_CONNECTIONS__ENABLED': 'false',
    })
    updates = {'usenet.providers': json.dumps(providers, separators=(',', ':')),
               'indexers.instances': json.dumps(indexers, separators=(',', ':'))}
    if not queued:
        updates['queue.paused'] = 'false'
    return result, updates, notes


def apply_settings(updates, api_key):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(API_URL,
        data=urllib.parse.urlencode(updates).encode(),
        headers={'x-api-key': api_key, 'Content-Type': 'application/x-www-form-urlencoded'},
        method='POST')
    try:
        with opener.open(request, timeout=60) as response:
            result = json.load(response)
    except urllib.error.HTTPError as error:
        # Validation errors can contain submitted values. Never print their body.
        raise RuntimeError('NAS settings API returned HTTP ' + str(error.code)
            + '; credentials have not been displayed.') from None
    if result.get('Status', result.get('status')) is not True:
        raise RuntimeError('The NAS settings API did not confirm the update.')


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show', capture=True):
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220.')
    if not SSD.is_mount():
        raise RuntimeError('The NAS appdata SSD must be mounted.')
    data = SSD / 'appdata/infinidysk-nas'
    stack = SSD / 'compose/infinidysk-nas/compose.json'
    snapshot = SSD / 'migration/infinidysk-optiplex/snapshot'
    marker = json.loads((data / 'nas-test-install.json').read_text())
    if marker.get('format') != 'sawdoctor-infinidysk-nas-test-v1':
        raise RuntimeError('Unexpected NAS installation marker.')
    mounted = run('findmnt', '-n', '--mountpoint', '/mnt/nzbdav',
                  '-o', 'FSTYPE,SOURCE', capture=True).split()
    if mounted != ['fuse.rclone', 'nzbdav:']:
        raise RuntimeError('The NAS media mount is not ready.')
    if stack.is_symlink() or (data / 'config/db.sqlite').is_symlink():
        raise RuntimeError('Unexpected symlink in the NAS settings paths.')
    print('Waiting for the NAS backup lock...', flush=True)
    with open('/run/lock/sawdoctor-nas-backup.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        settings, queued = read_settings(data / 'config/db.sqlite')
        source = json.loads((snapshot / 'container.json').read_text())[0]
        original_env = dict(item.split('=', 1) for item in source['Config'].get('Env', []) if '=' in item)
        document = json.loads(stack.read_text())
        document, updates, notes = prepare(document, settings, original_env, queued)
        env = document['services']['infinidysk']['environment']
        api_key = env.get('FRONTEND_BACKEND_API_KEY', '').replace('$$', '$')
        if not api_key:
            raise RuntimeError('The existing NAS API key was not found.')
        backup = stack.parent / 'settings.before-test-enable.json'
        if not backup.exists():
            atomic_text(backup, json.dumps({'compose': json.loads(stack.read_text()),
                'settings': {key: settings.get(key) for key in updates}}, indent=2) + '\n')
        atomic_text(stack, json.dumps(document, indent=2) + '\n')
        print('Unlocking the NAS provider controls and restarting NAS InfiniDysk...', flush=True)
        run('docker', 'compose', '-f', str(stack), 'config', '--quiet')
        run('docker', 'compose', '-f', str(stack), 'up', '-d', '--pull', 'never',
            '--wait', '--wait-timeout', '180', 'infinidysk')
        print('Enabling the copied providers and indexers through the NAS settings API...', flush=True)
        apply_settings(updates, api_key)
        actual, _ = read_settings(data / 'config/db.sqlite')
        for key in ('usenet.providers', 'indexers.instances'):
            if json.loads(actual.get(key, '{}')) != json.loads(updates[key]):
                # Provider identities/generation may be normalized by the application.
                if key == 'usenet.providers':
                    got, want = json.loads(actual.get(key, '{}')), json.loads(updates[key])
                    if len(got.get('Providers', [])) == len(want['Providers']) and all(
                        p['Type'] != 0 for p in got.get('Providers', [])):
                        continue
                raise RuntimeError('The NAS did not retain the requested ' + key + ' settings.')
    providers = json.loads(actual['usenet.providers'])['Providers']
    indexers = json.loads(actual['indexers.instances']).get('Indexers', [])
    print('\nNAS INFINIDYSK TEST ENABLED: http://192.168.0.220:8081')
    print('Providers enabled: ' + str(len(providers)) + ' (copied connection limits and backup roles retained).')
    print('Indexers enabled: ' + str(len(indexers)) + '.')
    print('Provider and indexer settings are now editable in the web interface.')
    if queued:
        print('Queue remains paused: the copied snapshot contains ' + str(queued) + ' existing queued jobs.')
        print('Review those copied jobs before resuming acquisition. Nothing was deleted.')
    else:
        print('Queue is ready for a manual acquisition test.')
    for name, host, port in notes:
        print('Indexer address needs review: ' + name + ' -> ' + host + (':' + str(port) if port else ''))
    print('Arr integration and automatic repairs remain off. The OptiPlex was not changed.')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit('\nInterrupted. Rerun to continue.')
    except Exception as error:
        raise SystemExit('STOP: ' + str(error))
