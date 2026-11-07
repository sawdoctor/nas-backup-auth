#!/usr/bin/env python3
"""Read-only comparison of staged Kometa policy and the verified source standby."""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import urllib.parse

import yaml

APP_UUID = 'e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6'
BACKUP_UUID = '631e3391-6a42-4158-9aa4-f7718ba0e7e9'
APP = Path('/srv/dev-disk-by-uuid-' + APP_UUID)
BACKUP = Path('/srv/dev-disk-by-uuid-' + BACKUP_UUID)
BASE = BACKUP / 'migration/nightly-standby'
LIVE = APP / 'appdata/support-nas/kometa'
LOCK = Path('/run/lock/sawdoctor-nas-backup.lock')
FILES = ('config.yml', 'uk-us-movies.yml', 'uk-us-movies4k.yml', 'uk-us-tv.yml')
FORMAT = 'sawdoctor-migration-standby-v1'
SECRET = re.compile(r'api.?key|token|password|secret|credential|authorization|client.?id', re.I)
FLAGS = {'add_missing', 'add_existing', 'radarr_add_missing', 'sonarr_add_missing',
         'radarr_add_existing', 'sonarr_add_existing', 'radarr_monitor', 'sonarr_monitor',
         'radarr_search', 'sonarr_search', 'search', 'monitor'}
CONNECTIONS = {'plex', 'radarr', 'sonarr', 'tmdb', 'trakt', 'tautulli', 'omdb', 'mdblist'}


def say(value):
    print(value, flush=True)


def no_links(path):
    if any(item.is_symlink() for item in (path, *path.parents)):
        raise RuntimeError('A symbolic report input was rejected.')


def read(path, limit=2 * 1024**2):
    no_links(path)
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise RuntimeError('A report input is unavailable or exceeds its size limit.')
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if len(data) > limit or any(getattr(before, key) != getattr(after, key) for key in fields):
        raise RuntimeError('A report input changed while being read.')
    return data


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise RuntimeError('A read-only host query failed; no service was changed.')
    return result.stdout


def mount(path, uuid):
    no_links(path)
    if not path.is_mount() or run('findmnt', '-rn', '--mountpoint', str(path), '-o', 'UUID,FSTYPE').split() != [uuid, 'ext4']:
        raise RuntimeError('An expected NAS filesystem is unavailable or has a different identity.')


def latest():
    current = json.loads(read(BASE / 'current.json'))
    stamp = current.get('createdUtc', '')
    if not re.fullmatch(r'[0-9]{8}T[0-9]{6}Z', stamp) or current.get('format') != FORMAT:
        raise RuntimeError('The current standby identity differs.')
    snapshot = BASE / 'snapshots' / stamp
    no_links(snapshot)
    if current.get('snapshot') != str(snapshot):
        raise RuntimeError('The current standby locator differs.')
    if json.loads(read(snapshot / '_VERIFIED.json')) != {key: value for key, value in current.items() if key != 'snapshot'}:
        raise RuntimeError('The standby verification marker differs.')
    manifest_data = read(snapshot / 'manifest.json', 8 * 1024**2)
    manifest = json.loads(manifest_data)
    root = manifest.get('dataRoots', {}).get('support.kometa', {})
    if (manifest.get('format') != FORMAT or manifest.get('scope') != 'standby-only'
            or manifest.get('sourceHost') != '192.168.0.29' or manifest.get('createdUtc') != stamp
            or root.get('snapshot') != 'data/support.kometa'):
        raise RuntimeError('The source standby manifest or Kometa location differs.')
    wanted = {'manifest.json': manifest_data}
    wanted.update({'data/support.kometa/' + name: read(snapshot / 'data/support.kometa' / name) for name in FILES})
    verify_selected(snapshot / 'SHA256SUMS', wanted)
    containers = [row for row in manifest.get('containers', []) if row.get('Name') == '/kometa']
    if len(containers) != 1:
        raise RuntimeError('The source Kometa container record is unavailable or duplicated.')
    return stamp, {name: wanted['data/support.kometa/' + name] for name in FILES}, containers[0]


def verify_selected(checks, wanted):
    no_links(checks)
    seen = set()
    with checks.open('rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError('The standby checksum list is unavailable.')
        while True:
            line = stream.readline(65537)
            if not line:
                break
            if len(line) > 65536:
                raise RuntimeError('A standby checksum line exceeds its size limit.')
            match = re.fullmatch(rb'([a-f0-9]{64})  \./([^\r\n]+)\n?', line)
            if not match:
                # Unrelated GNU-escaped filenames do not affect these five
                # fixed ASCII names. Every selected member must still match.
                continue
            name = match[2].decode('utf-8')
            if name not in wanted:
                continue
            if name in seen or hashlib.sha256(wanted[name]).hexdigest() != match[1].decode():
                raise RuntimeError('A selected source file failed its original checksum check.')
            seen.add(name)
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if seen != set(wanted) or any(getattr(before, key) != getattr(after, key) for key in fields):
        raise RuntimeError('Required source checksums are missing or the list changed.')


def parse(data):
    try:
        document = yaml.safe_load(data)
    except yaml.YAMLError:
        raise RuntimeError('A Kometa YAML file could not be parsed; its contents were not displayed.') from None
    if not isinstance(document, dict):
        raise RuntimeError('A Kometa configuration does not contain a YAML mapping.')
    # Bound traversal and reject recursive aliases; neither operation executes YAML.
    walk(document)
    return document


def walk(value):
    rows = []
    active = set()
    def visit(item, path=()):
        if len(rows) >= 10000 or len(path) > 20:
            raise RuntimeError('The Kometa YAML structure exceeds the report limit.')
        rows.append((path, item))
        if isinstance(item, (dict, list)):
            if id(item) in active:
                raise RuntimeError('A recursive Kometa YAML alias was rejected.')
            active.add(id(item))
            if isinstance(item, dict):
                if any(not isinstance(key, str) for key in item):
                    raise RuntimeError('A non-text Kometa mapping key was rejected.')
                for key, child in item.items():
                    visit(child, (*path, key))
            else:
                for index, child in enumerate(item):
                    visit(child, (*path, str(index)))
            active.remove(id(item))
        elif item is not None and not isinstance(item, (str, bool, int, float)):
            raise RuntimeError('A nonstandard Kometa YAML value was rejected.')
    visit(value)
    return rows


def canonical(value, path=()):
    if isinstance(value, dict):
        return {key: ('present' if child not in (None, '') else 'empty') if SECRET.search(key)
                else 'connection-url' if key == 'url' and path and path[-1] in CONNECTIONS
                else canonical(child, (*path, key)) for key, child in value.items()}
    if isinstance(value, list):
        return [canonical(child, (*path, str(index))) for index, child in enumerate(value)]
    return value


def label(path):
    # Mapping names are labels only; never print credential-key descendants.
    return '.'.join(part if re.fullmatch(r'[A-Za-z0-9 _./|()&:+-]{1,100}', part) else '[label]' for part in path)


def safe_filter(value):
    if isinstance(value, str):
        if (len(value) > 160 or '://' in value or re.fullmatch(r'[a-fA-F0-9]{24,}', value)
                or any(ord(char) < 32 for char in value)):
            return '[nonstandard filter value withheld]'
        return value
    if isinstance(value, list) and len(value) <= 30:
        return [safe_filter(item) for item in value]
    if value is None or type(value) in (bool, int, float):
        return value
    return '[structured filter value; inspect child policy fields]'


def policy(document):
    result = []
    for path, value in walk(document):
        if not path or any(SECRET.search(part) for part in path):
            continue
        key = path[-1].lower()
        if key in FLAGS:
            result.append((label(path), value if type(value) is bool else '[not a literal boolean]'))
        elif re.search(r'country|language|region', key):
            result.append((label(path), safe_filter(value)))
        elif key == 'file':
            result.append((label(path), value if isinstance(value, str) and re.fullmatch(r'(?:/config/)?[A-Za-z0-9_.-]+\.ya?ml', value) else '[nonstandard file reference withheld]'))
        elif key == 'url' and len(path) >= 2 and path[-2] in CONNECTIONS:
            try:
                url = urllib.parse.urlsplit(value)
                host = url.hostname or ''
                port = url.port
            except (TypeError, ValueError):
                host, port = '', None
            allowed = {'192.168.0.29', '192.168.0.220', '127.0.0.1', 'localhost', 'plex', 'plex-nas', 'sonarr', 'sonarr-nas', 'radarr', 'radarr-nas', 'radarr4k', 'radarr4k-nas'}
            shown = host + (':' + str(port) if port else '') if host in allowed or host.endswith('.sawdoctor.uk') else '[other host withheld]'
            result.append((label(path), shown))
    return result


def report(source, live):
    for name in FILES:
        old, new = parse(source[name]), parse(live[name])
        same_policy = json.dumps(canonical(old), sort_keys=True) == json.dumps(canonical(new), sort_keys=True)
        status = 'identical bytes' if source[name] == live[name] else 'same policy apart from credentials/connection URLs' if same_policy else 'POLICY DIFFERS: review required'
        say(name + ': ' + status)
        for role, doc in (('SOURCE', old), ('NAS', new)):
            rows = policy(doc)
            if not rows:
                say('  ' + role + ': no explicit country/language, add/search flags or file references found.')
            for key, value in rows:
                say('  ' + role + ' ' + key + ': ' + json.dumps(value, ensure_ascii=True))


def runtime_report(source, live):
    source_config, live_config = source.get('Config', {}), live.get('Config', {})
    say('Container image identity matches captured source: ' + json.dumps(source.get('Image') == live.get('Image') and bool(source.get('Image'))))
    say('Container entrypoint/command match captured source: ' + json.dumps(all(source_config.get(key) == live_config.get(key) for key in ('Entrypoint', 'Cmd'))))
    # Compare environment privately, including any custom run switches. Values
    # and command arguments are never included in the report.
    def environment(config):
        return dict(value.split('=', 1) for value in config.get('Env', []) if '=' in value)
    say('Container environment matches captured source: ' + json.dumps(environment(source_config) == environment(live_config)))


def main():
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the NAS.')
    mount(APP, APP_UUID)
    mount(BACKUP, BACKUP_UUID)
    with contextlib.ExitStack() as stack:
        for path in (LOCK, BASE / '.run.lock'):
            no_links(path)
            handle = stack.enter_context(path.open('rb'))
            try:
                fcntl.flock(handle, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError('NAS backup or standby work is busy; retry this report later.') from None
        row = json.loads(run('docker', 'inspect', 'kometa-nas'))[0]
        binds = [(item['Source'], item['Destination']) for item in row.get('Mounts', [])]
        if (row['State']['Status'] not in ('created', 'exited') or row['State'].get('Running')
                or row['HostConfig']['RestartPolicy']['Name'] != 'no' or binds != [(str(LIVE), '/config')]):
            raise RuntimeError('The stopped, staged Kometa container or configuration binding differs.')
        stamp, source, source_container = latest()
        live = {name: read(LIVE / name) for name in FILES}
        say('Comparing four Kometa YAML files with the verified source standby: ' + stamp)
        runtime_report(source_container, row)
        report(source, live)
        if live != {name: read(LIVE / name) for name in FILES}:
            raise RuntimeError('A live Kometa configuration changed during the report.')
    say('KOMETA POLICY REPORT COMPLETE. No Kometa run, API request, configuration write or service change was made.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        say('STOP: ' + (str(error) if isinstance(error, RuntimeError) else type(error).__name__))
        sys.exit(1)
