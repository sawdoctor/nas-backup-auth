#!/usr/bin/env python3
"""Start only Kometa from the already received common frozen production point.

Retain its existing NAS container, command, image and schedule. Replace its
stopped config root by a verified, privately adapted source copy, retaining
the old root by rename. No Plex scan, --run override, other service restart,
timer, route or core commitment is performed.
"""
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

import yaml

APP = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
BASE = APP / 'compose/production-cutover'
WORK = BASE / 'kometa-handover'
SELF = WORK / 'worker.py'
STATE = WORK / 'state.json'
FORMAT = 'sawdoctor-frozen-kometa-handover-v1'
NATIVE_SHA = 'ae59ce0542f9c72acc84cbc1888c397fb6a5c2bd730f6e101d2e3da4f62669f1'
FINISH_SHA = '068495226906f5a3674d3464e1124b25e472d13ad7419a1d9a98545e7d99d96f'
PLAN_SHA = 'bf4176032a44b7d3e113fbeb212acb5f0bd895f391c81f7543188d3db8779b10'
POLICY_SHA = '3f3a68af9991af39ebaa58e3c6d93d310c44c73543b9c9ed645515f3d14408be'
POLICY_URL = 'https://raw.githubusercontent.com/sawdoctor/nas-backup-auth/1d7b231756ae8a2bb212a3d2f93ea9eec51a2202/scripts/production-support-policy.py'
FILES = ('config.yml', 'uk-us-movies.yml', 'uk-us-movies4k.yml', 'uk-us-tv.yml')
PORTS = {'plex': 32400, 'sonarr': 8989, 'radarr': 7878, 'radarr4k': 7879}
TARGETS = {'sonarr': '/config', 'radarr': '/config', 'radarr4k': '/config'}
LIMIT = 8 * 1024**3


def say(value): print(value, flush=True)
def sha(body): return hashlib.sha256(body).hexdigest()


def load_module(path, expected, name):
    if any(p.is_symlink() for p in (path, *path.parents)) or sha(path.read_bytes()) != expected:
        raise RuntimeError('A reviewed Kometa handover helper differs: ' + path.name)
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def environment(row):
    result = {}
    for value in row['Config'].get('Env') or []:
        key, separator, item = value.partition('=')
        if not separator or key in result:
            raise RuntimeError('Kometa environment contains a malformed or duplicate entry.')
        result[key] = item
    return result


def validate_runtime(source, current):
    # The staged container was created from the original source command/env.
    # An unreviewed override cannot silently defeat the adapted config file.
    if environment(source) != environment(current):
        raise RuntimeError('Kometa source/NAS environment differs; no configuration installed.')
    for key in ('Cmd', 'Entrypoint', 'User', 'WorkingDir'):
        if (source['Config'].get(key) or None) != (current['Config'].get(key) or None):
            raise RuntimeError('Kometa source/NAS command or user differs; no configuration installed.')
    for key, value in environment(current).items():
        if '192.168.0.29' in value or (value and key.upper().removeprefix('KOMETA_').removeprefix('PMM_') in
                {app.upper() + '_' + field for app in PORTS for field in ('URL', 'TOKEN', 'API_KEY')}):
            raise RuntimeError('A Kometa connection environment override requires a dedicated adapter; no root changed.')
    if current['State'].get('Running') or current['HostConfig']['RestartPolicy']['Name'] != 'no':
        raise RuntimeError('Kometa must still be stopped with restart=no before this handover.')
    if current['HostConfig'].get('Privileged') or current['HostConfig'].get('NetworkMode') == 'host':
        raise RuntimeError('The accepted isolated NAS Kometa runtime differs.')


def frozen_manifest(native, state):
    proof = state['proof']; native.validate_proof(proof)
    raw = Path(state['raw'])
    if raw != BASE / proof['cutoverId'] / 'incoming' or Path(state['folder']) != raw.parent:
        raise RuntimeError('The frozen source locator differs.')
    body = native.read(raw / 'manifest.json')
    if sha(body) != proof['manifestSha256']:
        raise RuntimeError('The already received frozen manifest differs.')
    manifest = json.loads(body)
    expected = {'format': native.SOURCE_FORMAT, 'scope': 'production-frozen',
                'sourceHost': '192.168.0.29', 'cutoverId': proof['cutoverId'],
                'createdUtc': proof['frozenUtc'], 'plexConfigIncluded': True,
                'sourceDockerStopped': True, 'identitySha256': proof['identitySha256']}
    if any(manifest.get(key) != value for key, value in expected.items()):
        raise RuntimeError('This is not the current common stopped source capture.')
    root = manifest.get('dataRoots', {}).get('support.kometa', {})
    if root.get('snapshot') != 'data/support.kometa':
        raise RuntimeError('The frozen Kometa root differs.')
    rows = [row for row in manifest['containers'] if row['Name'] == '/kometa']
    if len(rows) != 1:
        raise RuntimeError('The frozen source Kometa record is unavailable or ambiguous.')
    binds = [m for m in rows[0]['Mounts'] if m['Destination'] == '/config' and m['Type'] == 'bind']
    if len(binds) != 1 or binds[0]['Source'] != root.get('source'):
        raise RuntimeError('The source Kometa configuration binding differs from its frozen root.')
    return raw, manifest, rows[0]


def inventory(root):
    if root.is_symlink() or not root.is_dir() or root.is_mount():
        raise RuntimeError('A Kometa configuration root is unavailable or mounted.')
    files = {}; total = 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        for name in (*dirs, *names):
            path = Path(directory) / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise RuntimeError('A Kometa symbolic/special file needs review; live root retained.')
            if stat.S_ISREG(info.st_mode):
                files[str(path.relative_to(root))] = path
                total += info.st_size
            if total > LIMIT or len(files) > 100000:
                raise RuntimeError('Kometa exceeds its private copy budget; live root retained.')
    if not set(FILES) <= set(files):
        raise RuntimeError('The four accepted Kometa configuration/collection files are unavailable.')
    return files, total


def selected_checks(native, core, raw, root):
    files, total = inventory(root)
    prefix = 'data/support.kometa/'
    checks = {}
    with (raw / 'SHA256SUMS').open('r', encoding='utf-8', errors='surrogateescape') as stream:
        for line in stream:
            if len(line) > 65536:
                raise RuntimeError('A frozen checksum entry exceeds its bound.')
            name, digest = core.parse_checksum(line)
            if name.startswith(prefix):
                relative = name[len(prefix):]
                if relative in checks:
                    raise RuntimeError('A frozen Kometa checksum is duplicated.')
                checks[relative] = digest
    if set(checks) != set(files):
        raise RuntimeError('The frozen Kometa checksum inventory differs.')
    for index, (name, path) in enumerate(sorted(files.items()), 1):
        if native.digest(path) != checks[name]:
            raise RuntimeError('A frozen Kometa file failed its original checksum.')
        if index % 1000 == 0: say('Verified frozen Kometa files: ' + str(index))
    return checks, total


def parse_config(body, policy):
    try: document = yaml.safe_load(body)
    except yaml.YAMLError:
        raise RuntimeError('A Kometa YAML file could not be parsed; credentials withheld.') from None
    if not isinstance(document, dict):
        raise RuntimeError('A Kometa configuration is not a YAML mapping.')
    policy.validate_tree(document)
    return document


def connections(document):
    global_config = {name: document.get(name) or {} for name in ('plex', 'radarr', 'sonarr')}
    libraries = document.get('libraries')
    if not isinstance(libraries, dict) or not libraries:
        raise RuntimeError('Kometa has no configured source libraries.')
    rows = []
    for title, settings in libraries.items():
        if not isinstance(settings, dict):
            raise RuntimeError('A Kometa library configuration needs review.')
        for kind in ('plex', 'radarr', 'sonarr'):
            base, override = global_config[kind], settings.get(kind) or {}
            if not isinstance(base, dict) or not isinstance(override, dict):
                raise RuntimeError('A Kometa connection needs review.')
            merged = {**base, **override}
            if not merged and kind != 'plex': continue
            url = merged.get('url')
            parsed = urllib.parse.urlsplit(url if isinstance(url, str) else '')
            port = parsed.port
            app = {32400: 'plex', 8989: 'sonarr', 7878: 'radarr', 7879: 'radarr4k'}.get(port)
            if (parsed.scheme != 'http' or parsed.hostname != '192.168.0.220'
                    or parsed.username is not None or parsed.password is not None
                    or parsed.path not in ('', '/') or parsed.query or parsed.fragment
                    or (kind == 'radarr' and app not in ('radarr', 'radarr4k'))
                    or (kind != 'radarr' and app != kind)):
                raise RuntimeError('A Kometa connection is not the reviewed direct NAS endpoint.')
            token = merged.get('token', merged.get('api_key'))
            if not isinstance(token, str) or not token or any(c.isspace() for c in token):
                raise RuntimeError('A configured Kometa connection token is unavailable.')
            rows.append((title, app, url.rstrip('/'), token))
    return rows


def http_json(url, headers):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(url, headers=headers)
    try:
        with opener.open(request, timeout=12) as response:
            body = response.read(2 * 1024**2 + 1)
            if len(body) > 2 * 1024**2 or response.status != 200:
                raise RuntimeError('A Kometa dependency response differs.')
            return body
    except urllib.error.HTTPError as error:
        raise RuntimeError('Kometa dependency authentication/HTTP check failed: HTTP' + str(error.code)) from None
    except OSError:
        raise RuntimeError('A reviewed NAS Kometa dependency is unreachable; no config installed.') from None


def dependency_check(document):
    checked = {}; titles = set(document['libraries'])
    for title, app, url, token in connections(document):
        identity = (app, url, sha(token.encode()))
        if identity not in checked:
            if app == 'plex':
                data = ET.fromstring(http_json(url + '/library/sections', {'X-Plex-Token': token}))
                checked[identity] = {row.get('title') for row in data.findall('Directory')}
                if not checked[identity]:
                    raise RuntimeError('The authenticated NAS Plex library list is empty.')
            else:
                data = json.loads(http_json(url + '/api/v3/system/status', {'X-Api-Key': token}))
                if not isinstance(data, dict) or not data.get('version'):
                    raise RuntimeError('A NAS Arr API status response differs.')
                checked[identity] = None
            say('Kometa connection verified: ' + app + ' at ' + url)
        if app == 'plex' and title not in checked[identity]:
            raise RuntimeError('An existing Kometa library title is absent from current NAS Plex; no scan or config change.')
    return len(titles)


def plex_identity(native, plan, state):
    finisher = load_module(BASE / 'finish-plex-identity.py', FINISH_SHA, 'kometa_plex_identity')
    evidence = json.loads(native.read(BASE / 'plex-frozen-identity.json'))
    if evidence.get('format') != 'sawdoctor-frozen-plex-identity-v1' or evidence.get('cutoverId') != state['proof']['cutoverId']:
        raise RuntimeError('The accepted frozen Plex identity evidence differs.')
    prefs = native.read(Path(plan['liveRoots']['plex']) / native.PREFS)
    api = http_json('http://192.168.0.220:32400/identity', {})
    finisher.validate_identity(prefs, evidence, state['proof'], api)


def install_root(native, operation):
    live = Path(operation['live']); incoming = WORK / 'incoming'; before = WORK / 'rollback/kometa'
    native.safe(before); before.parent.mkdir(mode=0o700, exist_ok=True)
    phase = operation['phase']
    # Recover either rename-before-journal-write window from exact root states.
    if phase in ('prepared', 'saved') and not live.exists() and before.is_dir() and incoming.is_dir():
        operation['phase'] = 'saved'; native.atomic(STATE, operation); phase = 'saved'
    if phase in ('prepared', 'saved') and live.is_dir() and before.is_dir() and not incoming.exists():
        if native.digest(live / 'config.yml') != operation['configSha256'] or any(
                native.digest(live / name) != value for name, value in operation['collectionSha256'].items()):
            raise RuntimeError('An interrupted installed Kometa root differs; all roots retained.')
        operation['phase'] = 'installed'; native.atomic(STATE, operation); return
    if phase in ('prepared', 'saved'):
        if native.digest(incoming / 'config.yml') != operation['configSha256'] or any(
                native.digest(incoming / name) != value for name, value in operation['collectionSha256'].items()):
            raise RuntimeError('Prepared Kometa files changed before installation; live root retained.')
    if phase == 'prepared':
        if not live.is_dir() or not incoming.is_dir() or before.exists():
            raise RuntimeError('A prepared Kometa rename state differs; roots retained.')
        live.rename(before); native.sync_dir(live.parent); native.sync_dir(WORK)
        operation['phase'] = 'saved'; native.atomic(STATE, operation); phase = 'saved'
    if phase == 'saved':
        if live.exists() or not before.is_dir() or not incoming.is_dir():
            raise RuntimeError('An interrupted Kometa root state needs review; recovery copy retained.')
        incoming.rename(live); native.sync_dir(live.parent)
        operation['phase'] = 'installed'; native.atomic(STATE, operation)


def worker():
    native = load_module(BASE / 'worker.py', NATIVE_SHA, 'kometa_native')
    policy = load_module(WORK / 'support-policy.py', POLICY_SHA, 'kometa_policy')
    plan = native.approved(PLAN_SHA)
    with native.lock(BASE / '.run.lock'), native.lock(native.BACKUP_LOCK):
        state = json.loads(native.read(native.STATE))
        if state.get('phase') not in ('awaiting-acceptance', 'committed-core') or state.get('plexIdentityValidated') is not True:
            raise RuntimeError('The verified live NAS Plex/core import must be complete first.')
        say('Verifying current frozen Kometa files, source hold, Plex identity and exact NAS runtime...')
        raw, manifest, source = frozen_manifest(native, state)
        native.held(state['proof'])
        plex_identity(native, plan, state)
        h = native.helpers(); rows = native.catalog(); current = rows['kometa-nas']
        binds = [m for m in current['Mounts'] if m['Destination'] == '/config' and m['Type'] == 'bind']
        if len(binds) != 1:
            raise RuntimeError('The accepted NAS Kometa configuration binding differs.')
        live = Path(binds[0]['Source']); native.safe(live)
        if live != APP / 'appdata/support-nas/kometa' or len(current['Mounts']) != 1 or live.is_mount():
            raise RuntimeError('The accepted NAS Kometa configuration binding differs.')
        images = {image['Id']: image for image in manifest['images']}
        local = json.loads(native.run('docker', 'image', 'inspect', current['Image']))[0]
        if not h['cache'].same_image(h['core'], images[source['Image']], local):
            raise RuntimeError('The NAS Kometa image differs from current frozen source; an exact-image cache step is required.')
        if STATE.exists():
            operation = json.loads(native.read(STATE))
            if (operation.get('format') != FORMAT or operation.get('cutoverId') != state['proof']['cutoverId']
                    or operation.get('containerId') != current['Id'] or operation.get('live') != str(live)):
                raise RuntimeError('An earlier Kometa handover belongs to a different runtime; retained.')
            if operation['phase'] in ('starting', 'started'):
                if current['State']['Running']:
                    say('KOMETA IS ALREADY RUNNING FROM THIS FROZEN HANDOVER. No copy or restart repeated.')
                else:
                    say('The recorded Kometa start is no longer running. Inspect its private log before another start.')
                return
            if operation['phase'] not in ('prepared', 'saved', 'installed'):
                raise RuntimeError('An earlier private Kometa preparation was interrupted; retained for inspection.')
        else:
            validate_runtime(source, current)
            checks, size = selected_checks(native, h['core'], raw, raw / 'data/support.kometa')
            if shutil.disk_usage(APP).free < size + 4 * 1024**3:
                raise RuntimeError('Kometa private copy/reserve space is insufficient.')
            keys = {}
            for app in TARGETS:
                name = h['core'].NAMES[app]
                if not rows[name]['State']['Running']:
                    raise RuntimeError('An imported NAS Arr dependency is stopped.')
                root = native.config_bind(rows[name], TARGETS[app])
                if str(root) != plan['liveRoots'][app]:
                    raise RuntimeError('An imported NAS Arr configuration binding differs.')
                keys[app] = ET.fromstring(native.read(root / 'config.xml')).findtext('ApiKey')
            original = parse_config(native.read(raw / 'data/support.kometa/config.yml'), policy)
            adapted = policy.kometa(original, keys)
            libraries = dependency_check(adapted)
            operation = {'format': FORMAT, 'cutoverId': state['proof']['cutoverId'], 'phase': 'copying',
                         'live': str(live), 'containerId': current['Id'], 'image': current['Image'],
                         'createdUtc': dt.datetime.now(dt.timezone.utc).isoformat(), 'files': len(checks),
                         'libraries': libraries, 'sourceConfigSha256': sha(native.read(raw / 'data/support.kometa/config.yml'))}
            native.atomic(STATE, operation)
            incoming = WORK / 'incoming'
            if incoming.exists() or (WORK / 'rollback/kometa').exists():
                raise RuntimeError('A prior Kometa private copy/root was retained.')
            say('Copying only the current frozen Kometa configuration/cache/assets privately...')
            native.run('cp', '-a', '--', str(raw / 'data/support.kometa'), str(incoming), timeout=900)
            copied, _ = inventory(incoming)
            if set(copied) != set(checks) or any(native.digest(path) != checks[name] for name, path in copied.items()):
                raise RuntimeError('The private Kometa copy differs from its verified frozen files.')
            # The three custom collection files and all other assets stay byte-identical.
            target = incoming / 'config.yml'
            encoded = yaml.safe_dump(adapted, sort_keys=False, allow_unicode=True).encode()
            if parse_config(encoded, policy) != adapted:
                raise RuntimeError('Adapted Kometa settings did not round-trip exactly.')
            native.atomic(target, encoded, reference=target)
            operation['configSha256'] = sha(encoded)
            operation['collectionSha256'] = {name: checks[name] for name in FILES[1:]}
            operation['phase'] = 'prepared'; native.atomic(STATE, operation)
        validate_runtime(source, current)
        native.held(state['proof'])
        if operation['phase'] in ('prepared', 'saved'): install_root(native, operation)
        if operation['phase'] != 'installed' or not (WORK / 'rollback/kometa').is_dir():
            raise RuntimeError('Kometa configuration installation is not fully journalled.')
        if native.digest(live / 'config.yml') != operation['configSha256'] or any(
                native.digest(live / name) != value for name, value in operation['collectionSha256'].items()):
            raise RuntimeError('Installed Kometa configuration/collection hashes differ; not started.')
        dependency_check(parse_config(native.read(live / 'config.yml'), policy))
        native.held(state['proof'])
        operation['phase'] = 'starting'; native.atomic(STATE, operation)
        say('Starting only the existing Kometa container; original command and schedule retained...')
        native.run('docker', 'start', current['Id'], timeout=90)
        time.sleep(5)
        after = json.loads(native.run('docker', 'inspect', current['Id']))[0]
        if not after['State']['Running']:
            native.atomic(WORK / 'last-start-log.txt', native.run('docker', 'logs', '--tail', '80', current['Id']).encode())
            raise RuntimeError('Kometa exited after startup; private log and both roots retained. No other service changed.')
        operation['phase'] = 'started'; operation['startedUtc'] = dt.datetime.now(dt.timezone.utc).isoformat()
        native.atomic(STATE, operation)
    say('CURRENT SOURCE KOMETA STARTED ON NAS. Plex/HD/4K/TV credentials and library names verified.')
    say('Original acquisition settings, filters, three custom collections, assets and cache retained.')
    say('No forced Plex scan, extra --run, source restart, other container stop, timer, route or certificate change.')
    say('Original NAS Kometa root retained: ' + str(WORK / 'rollback/kometa'))
    say('Restart/boot ownership remains with the pending final migration commitment; restart=no retained for now.')


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or not APP.is_mount() or 'inet 192.168.0.220/' not in subprocess.check_output(
            ['ip', '-4', 'addr', 'show'], text=True, timeout=10):
        raise RuntimeError('Run with sudo on the NAS at192.168.0.220.')
    if len(sys.argv) == 3 and sys.argv[1] == '--worker':
        if sha(SELF.read_bytes()) != sys.argv[2]:
            raise RuntimeError('The pinned Kometa worker differs.')
        worker(); return
    if sys.argv[1:] or globals().get('START_APPROVED_KOMETA') is not True:
        raise RuntimeError('The explicit approved Kometa start flag is required.')
    source = globals().get('INSTALL_SOURCE')
    if not isinstance(source, str):
        raise RuntimeError('The exact installer source is required.')
    native = load_module(BASE / 'worker.py', NATIVE_SHA, 'kometa_installer_native')
    native.approved(PLAN_SHA)
    for path in (WORK, SELF, WORK / 'support-policy.py'): native.safe(path)
    WORK.mkdir(mode=0o700, exist_ok=True)
    owner = WORK / 'owner.json'
    if owner.exists() and json.loads(native.read(owner)) != {'format': FORMAT}:
        raise RuntimeError('An unrelated Kometa work folder was retained.')
    if not owner.exists(): native.atomic(owner, {'format': FORMAT})
    policy = WORK / 'support-policy.py'
    if policy.exists():
        if sha(native.read(policy)) != POLICY_SHA:
            raise RuntimeError('The retained Kometa policy adapter differs.')
    else:
        data = urllib.request.urlopen(POLICY_URL, timeout=30).read(256 * 1024)
        if sha(data) != POLICY_SHA:
            raise RuntimeError('The reviewed support-policy download failed SHA256 verification.')
        native.atomic(policy, data)
    encoded = source.encode()
    if SELF.exists() and native.read(SELF) != encoded:
        raise RuntimeError('An installed Kometa worker differs; retained.')
    if not SELF.exists(): native.atomic(SELF, encoded)
    current = native.unit_state('nas-production-kometa.service')
    if current['ActiveState'] in ('active', 'activating', 'deactivating'):
        raise RuntimeError('The Kometa handover worker is already active.')
    native.run('systemd-run', '--unit=nas-production-kometa', '--collect',
               '--description=Start current frozen production Kometa on NAS',
               '--property=Type=exec', '--property=MemoryMax=2G', '--property=CPUQuota=100%',
               '--property=TimeoutStopSec=30', '/usr/bin/python3', str(SELF), '--worker', sha(encoded))
    say('Kometa handover started in systemd. Closing SSH is safe.')
    say('Progress: sudo journalctl -fu nas-production-kometa.service -n 20 --no-pager -o cat')


if __name__ == '__main__':
    try: main()
    except Exception as exc:
        message = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
        raise SystemExit('STOP: ' + message)
