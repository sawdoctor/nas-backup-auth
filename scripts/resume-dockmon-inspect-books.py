#!/usr/bin/env python3
"""Resume notify-only Dockmon; report exact frozen/current book layout read-only.

No book/Plex data replacement, book start/stop, mount, timer, route or image
pull is performed. Database changes are limited to the previously reviewed
Dockmon automatic-action switches, backed up while Dockmon is stopped.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

APP = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
BASE = APP / 'compose/production-cutover'
WORK = BASE / 'remaining-apps-inspection'
STARTER = BASE / 'kometa-handover/worker.py'
STARTER_SHA = '5a2e0bf3bad87b798efbf82082a155f2cf73f1b835be4560896d527c66405a14'
FORMAT = 'sawdoctor-dockmon-books-resume-inspection-v1'
BOOKS = ('abr-shelfmark-bridge', 'audiobookrequest', 'audiobookshelf-test', 'kavita',
         'sabnzbd-ebooks', 'shelfmark-ebooks', 'shelfmark-torbox', 'stackarr-ebooks')
MOUNTS = ('/mnt/gdrive-audiobooks', '/mnt/media/ebooks', '/mnt/gdrive-torbox-archive',
          '/mnt/torbox-audiobooks', '/mnt/nzbdav')


def say(value): print(value, flush=True)


def starter_module():
    if any(p.is_symlink() for p in (STARTER, *STARTER.parents)) or hashlib.sha256(STARTER.read_bytes()).hexdigest() != STARTER_SHA:
        raise RuntimeError('The verified Kometa/source-proof helper differs.')
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('remaining_apps_source', STARTER)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


def source_locator(manifest, source):
    path = Path(source)
    matches = [(Path(value['source']), value['snapshot'], label)
               for label, value in manifest['dataRoots'].items()
               if path == Path(value['source']) or Path(value['source']) in path.parents]
    if not matches: return {'kind': 'external/mount', 'source': source}
    root, relative, label = max(matches, key=lambda item: len(item[0].parts))
    return {'kind': 'frozen', 'root': label, 'snapshot': str(Path(relative) / path.relative_to(root))}


def private_version(image):
    labels = (image.get('Config') or {}).get('Labels') or {}
    result = {}
    for key in ('org.opencontainers.image.version', 'build_version'):
        value = labels.get(key)
        if isinstance(value, str): result[key] = value[:200]
    return result


def inspect_books(native, starter, manifest, rows):
    h = native.helpers(); images = {image['Id']: image for image in manifest['images']}
    source_rows = {row['Name'].lstrip('/'): row for row in manifest['containers']}
    current_images = json.loads(native.run('docker', 'image', 'inspect', *sorted({rows[name + '-nas']['Image'] for name in BOOKS})))
    current_images = {image['Id']: image for image in current_images}
    result = {'applications': [], 'mounts': {}, 'units': {}}
    for name in BOOKS:
        old = source_rows[name]; current = rows[name + '-nas']
        source_image = images[old['Image']]; current_image = current_images[current['Image']]
        row = {'app': name, 'state': current['State']['Status'],
               'imageMatchesFrozen': h['cache'].same_image(h['core'], source_image, current_image),
               'sourceVersion': private_version(source_image), 'nasVersion': private_version(current_image),
               'sourceHasRegistryDigest': bool(source_image.get('RepoDigests')),
               'bindings': []}
        targets = {mount['Destination']: mount for mount in current['Mounts']}
        for mount in old['Mounts']:
            target = targets.get(mount['Destination'])
            row['bindings'].append({'target': mount['Destination'],
                                    'source': source_locator(manifest, mount['Source']),
                                    'nas': target['Source'] if target else '[missing binding]',
                                    'nasReadOnly': not target.get('RW', True) if target else None})
        labels = current['Config'].get('Labels') or {}
        row['composeProject'] = labels.get('com.docker.compose.project')
        paths = labels.get('com.docker.compose.project.config_files', '').split(',')
        row['composeFiles'] = []
        for filename in paths:
            if not filename: continue
            path = Path(filename)
            if str(path).startswith('/app/data/stacks/'):
                path = APP / 'appdata/dockmon/stacks' / path.relative_to('/app/data/stacks')
            entry = {'file': str(path), 'linkTarget': os.readlink(path) if path.is_symlink() else None}
            if path.is_file():
                body = path.read_bytes()
                entry['sha256'] = hashlib.sha256(body).hexdigest()
                try: json.loads(body); entry['jsonDocument'] = True
                except (ValueError, UnicodeError): entry['jsonDocument'] = False
            row['composeFiles'].append(entry)
        result['applications'].append(row)
        say('BOOK ' + json.dumps(row, separators=(',', ':')))
    for target in MOUNTS:
        query = subprocess.run(['findmnt', '-rn', '--mountpoint', target, '-o', 'FSTYPE,SOURCE'], capture_output=True, text=True, timeout=10)
        result['mounts'][target] = query.stdout.strip() if query.returncode == 0 else '[not mounted]'
    say('BOOK MOUNTS ' + json.dumps(result['mounts'], separators=(',', ':')))
    for name in ('nas-books.service', 'nas-infinidysk-rclone.service'):
        result['units'][name] = native.unit_state(name)
    guard = native.UNITS / 'nas-books.service.d' / native.DROPIN
    result['bookImportGuardInstalled'] = guard.is_file() and native.read(guard) == native.CONDITION.encode()
    worker = Path('/usr/local/sbin/nas-books-deploy.py')
    if worker.is_file():
        body = native.read(worker, 2 * 1024**2)
        result['booksWorkerSha256'] = hashlib.sha256(body).hexdigest()
        result['booksWorkerReadsJsonCompose'] = b"json.loads((STACK / 'compose.json').read_text())" in body
    say('BOOK CONTROL ' + json.dumps({key: value for key, value in result.items() if key not in ('applications', 'mounts')}, separators=(',', ':')))
    return result


def main():
    os.umask(0o077)
    if globals().get('RESUME_NOTIFY_ONLY_DOCKMON') is not True:
        raise RuntimeError('The explicit notify-only Dockmon resume flag is required.')
    if os.geteuid() != 0 or not APP.is_mount() or 'inet 192.168.0.220/' not in subprocess.check_output(['ip', '-4', 'addr', 'show'], text=True, timeout=10):
        raise RuntimeError('Run with sudo on the NAS at192.168.0.220.')
    starter = starter_module()
    native = starter.load_module(BASE / 'worker.py', starter.NATIVE_SHA, 'remaining_apps_native')
    with native.lock(BASE / '.run.lock'), native.lock(native.BACKUP_LOCK):
        plan = native.approved(starter.PLAN_SHA); state = json.loads(native.read(native.STATE))
        if state.get('phase') not in ('awaiting-acceptance', 'committed-core'):
            raise RuntimeError('The live tested NAS core is required before resuming its admin app.')
        raw, manifest, _ = starter.frozen_manifest(native, state)
        native.held(state['proof']); starter.plex_identity(native, plan, state)
        rows = native.catalog()
        # Read Compose/mount/image metadata; no book database or media payload opened.
        details = inspect_books(native, starter, manifest, rows)
        current = rows['dockmon']; expected = plan['containers']['dockmon']
        if current['Id'] != expected['Id'] or current['Image'] != expected['Image']:
            raise RuntimeError('Dockmon runtime changed since the approved hold; book inspection only.')
        database = native.dockmon_database(current)
        if str(database) != plan['dockmonDatabase']:
            raise RuntimeError('The accepted Dockmon data binding differs.')
        native.safe(WORK); WORK.mkdir(mode=0o700, exist_ok=True)
        owner = WORK / 'owner.json'
        identity = {'format': FORMAT, 'cutoverId': state['proof']['cutoverId']}
        if owner.exists() and json.loads(native.read(owner)) != identity:
            raise RuntimeError('An earlier remaining-app inspection belongs to a different cutover.')
        if not owner.exists(): native.atomic(owner, identity)
        native.atomic(WORK / 'books.json', details)
        counts = native.dockmon_notify(database)
        if any(counts.values()):
            if current['State']['Running']:
                native.run('docker', 'stop', '--timeout', '30', current['Id'], timeout=60)
            saved = WORK / 'rollback'; native.safe(saved); saved.mkdir(mode=0o700, exist_ok=True)
            counts = native.dockmon_notify(database, backup=saved / 'dockmon.before.sqlite')
        if any(counts.values()): raise RuntimeError('Dockmon notify-only controls did not verify; not started.')
        say('Dockmon automatic-action enabled counts: ' + json.dumps(counts, sort_keys=True))
        native.held(state['proof'])
        if not json.loads(native.run('docker', 'inspect', current['Id']))[0]['State']['Running']:
            native.run('docker', 'start', current['Id'], timeout=60)
        if not json.loads(native.run('docker', 'inspect', current['Id']))[0]['State']['Running']:
            raise RuntimeError('Dockmon did not remain running; existing data retained.')
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(('192.168.0.220', 8001), timeout=1): break
            except OSError: time.sleep(1)
        else:
            raise RuntimeError('Dockmon is started but its existing admin port8001 is not ready; data retained.')
        native.atomic(WORK / 'dockmon.json', {**identity, 'running': True, 'automaticActionsEnabled': counts})
    say('DOCKMON RESTORED IN NOTIFY-ONLY MODE. Existing accounts, alerts and update notifications retained.')
    say('Book images/layout/mounts reported read-only; book data, services and cloud mounts unchanged.')
    say('Use the existing dedicated SSH admin APK for Dockmon. Final boot/backup ownership remains pending.')


if __name__ == '__main__':
    try: main()
    except Exception as exc:
        raise SystemExit('STOP: ' + (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__))
