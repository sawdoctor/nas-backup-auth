#!/usr/bin/env python3
"""Import the current common frozen book state using the existing NAS layout.

Only eight book applications are paused/recreated. Preserve live cloud mounts,
NAS paths, media-core/Plex/Silo/TorBox CAM and notify-only Dockmon. Old book
roots and Compose are retained. Global import/boot/backup guards stay in place
until final ownership commitment.
"""
import copy
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import time
APP = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
BASE = APP / 'compose/production-cutover'
WORK = BASE / 'books-handover'
SELF = WORK / 'worker.py'
STATE = WORK / 'state.json'
LIVE = APP / 'appdata/books-nas'
COMPOSE = APP / 'appdata/dockmon/stacks/books-nas/compose.yaml'
BOOK_WORKER = Path('/usr/local/sbin/nas-books-deploy.py')
BOOK_SHA = '16889a58d366a86f01e580b8efab8fed5e04cbaee6843e4240ddd87f5c0f9bc9'
STARTER = BASE / 'kometa-handover/worker.py'
STARTER_SHA = '5a2e0bf3bad87b798efbf82082a155f2cf73f1b835be4560896d527c66405a14'
IMAGE_HELPER = BASE / 'kometa-image-refresh/worker.py'
IMAGE_HELPER_SHA = 'e612e1a72edc7a7c57ad0a4f605757a25bfefa70177add57e865cc1f54dd6c31'
FORMAT = 'sawdoctor-current-frozen-books-handover-v1'
ROOTS = ('abr-shelfmark-bridge', 'audiobookrequest', 'kavita', 'sabnzbd',
         'shelfmark-ebooks', 'shelfmark-torbox', 'stackarr-shelfmark',
         'audiobookshelf-data', 'stable-playback-namespace', 'playback-overrides')
MAX_BYTES = 64 * 1024**3


def say(value): print(value, flush=True)
def sha(body): return hashlib.sha256(body).hexdigest()


def load(path, expected, name):
    body = path.read_bytes()
    if any(p.is_symlink() for p in (path, *path.parents)) or sha(body) != expected:
        raise RuntimeError('A reviewed book handover helper differs: ' + path.name)
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    exec(compile(body, str(path), 'exec'), result.__dict__)
    return result


def layout(manifest):
    result = {}
    for label in ROOTS:
        item = manifest['dataRoots'].get('books.' + label, {})
        if item.get('kind') != 'directory' or item.get('snapshot') != 'data/books.' + label:
            raise RuntimeError('A required frozen book root differs: ' + label)
        result[label] = dict(item)
    library = manifest['dataRoots'].get('library', {})
    if library.get('source') != '/mnt/media' or library.get('snapshot') != 'data/library':
        raise RuntimeError('The current frozen virtual book library locator differs.')
    result['virtual-audiobooks'] = {'source': '/mnt/media/audiobooks-test',
                                   'snapshot': 'data/library/audiobooks-test', 'kind': 'directory'}
    return result


def mapping(source, roots, data, mounts):
    path = Path(source)
    if not path.is_absolute() or '..' in path.parts:
        raise RuntimeError('An absolute canonical book binding is required.')
    # The library snapshot intentionally excludes ebooks: preserve its live
    # NAS cloud binding before considering the broader /mnt/media descriptor.
    for target in sorted(mounts, key=len, reverse=True):
        cloud = Path(target)
        if path == cloud or cloud in path.parents: return None, path
    choices = [(label, item) for label, item in roots.items()
               if path == Path(item['source']) or Path(item['source']) in path.parents]
    if not choices: raise RuntimeError('An unreviewed book binding needs a specific adapter.')
    label, item = max(choices, key=lambda pair: len(Path(pair[1]['source']).parts))
    return item, data / label / path.relative_to(item['source'])


def files_and_links(root):
    if root.is_symlink() or not root.is_dir() or root.is_mount():
        raise RuntimeError('An expected private/local book root is unavailable.')
    files, links = {}, {}
    for directory, dirs, names in os.walk(root, followlinks=False):
        for name in (*dirs, *names):
            path = Path(directory) / name; relative = str(path.relative_to(root))
            if path.is_symlink(): links[relative] = os.readlink(path)
            elif path.is_file(): files[relative] = path
            elif not path.is_dir(): raise RuntimeError('A special file was retained in a book root.')
            if len(files) + len(links) > 200000: raise RuntimeError('A book root exceeds its member bound.')
    return files, links


def verify_selected(native, core, raw, roots):
    wanted, inventories, total = {}, {}, 0
    for label, item in roots.items():
        source = raw / item['snapshot']; native.safe(source)
        files, links = files_and_links(source); inventories[label] = (files, links)
        for name, path in files.items():
            relative = item['snapshot'] + '/' + name
            wanted[relative] = path; total += path.stat().st_size
    if total > MAX_BYTES: raise RuntimeError('Selected book state exceeds its private copy limit.')
    matched = set(); checks = {}; next_report = time.monotonic() + 20
    prefixes = tuple(item['snapshot'] + '/' for item in roots.values())
    with (raw / 'SHA256SUMS').open('r', encoding='utf-8', errors='surrogateescape') as stream:
        for line in stream:
            if len(line) > 65536: raise RuntimeError('A frozen book checksum entry exceeds its bound.')
            name, digest = core.parse_checksum(line)
            if not name.startswith(prefixes): continue
            if name not in wanted or name in matched or native.digest(wanted[name]) != digest:
                raise RuntimeError('A current frozen book checksum/inventory differs.')
            matched.add(name); checks[name] = digest
            if time.monotonic() > next_report:
                say('Verified current frozen book files: ' + str(len(matched))); next_report = time.monotonic() + 20
    if matched != set(wanted): raise RuntimeError('Current frozen book checksums are incomplete.')
    return inventories, checks, total


def controls(path):
    with contextlib.closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as db:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        result = {}
        if 'config' in tables:
            result['quality'] = db.execute("SELECT value FROM config WHERE key='quality_auto_download'").fetchall()
        if 'notification' in tables:
            columns = {row[1] for row in db.execute('PRAGMA table_info(notification)')}
            if 'enabled' in columns: result['notifications'] = db.execute('SELECT rowid,enabled FROM notification ORDER BY rowid').fetchall()
        return result


def install_adapters(books, roots, infini_key_pairs):
    original_url = books.rewrite_url; original_tree = books.rewrite_tree; original_db = books.patch_settings_db
    def secrets(value):
        if isinstance(value, dict): return {key: secrets(child) for key, child in value.items()}
        if isinstance(value, list): return [secrets(child) for child in value]
        if isinstance(value, str):
            for old, new in infini_key_pairs:
                if len(old) >= 16 and old != new: value = value.replace(old, new)
        return value
    def url(value, browser=False):
        value = original_url(value, browser)
        if isinstance(value, str):
            value = re.sub(r'https?://(?:192\.168\.0\.29|plex|localhost|127\.0\.0\.1):32400(?![0-9])',
                           'http://192.168.0.220:32400', value)
        return secrets(value)
    def tree(value, key=''): return secrets(original_tree(value, key))
    def db(path, abr=False):
        prior = controls(path) if abr else None
        original_db(path, abr=False)  # Never apply the old ABR test-mode flags.
        if abr:
            with contextlib.closing(sqlite3.connect(path)) as connection:
                for key, value in (('abs_base_url', 'http://audiobookshelf-test:80'),
                                   ('prowlarr_base_url', 'http://prowlarr:9696')):
                    connection.execute('UPDATE config SET value=? WHERE key=? AND value<>?', (value, key, ''))
                tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if 'notification' in tables:
                    for rowid, value in connection.execute('SELECT rowid,url FROM notification').fetchall():
                        updated = url(value)
                        if updated != value: connection.execute('UPDATE notification SET url=? WHERE rowid=?', (updated, rowid))
                connection.commit()
            if controls(path) != prior: raise RuntimeError('ABR source acquisition/notification controls changed; private copy retained.')
    books.rewrite_url = url; books.rewrite_tree = tree; books.patch_settings_db = db
    books.source_mapping = lambda source, manifest, data: mapping(source, roots, data, books.MOUNTS)
    return secrets


def link_target(target, roots, books, containers):
    if not target.startswith('/'): return target
    try: return str(mapping(target, roots, LIVE, books.MOUNTS)[1])
    except RuntimeError:
        # ABS links can use its container namespace, e.g.
        # /mnt/legacy-gdrive-audiobooks, rather than a source-host path.
        path = Path(target)
        for row in containers.values():
            for mount in row['Mounts']:
                destination = Path(mount['Destination'])
                if path == destination or destination in path.parents: return target
        raise RuntimeError('An absolute book playback link has an unreviewed target.') from None


def fix_links_and_databases(native, roots, incoming, books, containers):
    for label in roots:
        root = incoming / label
        _, links = files_and_links(root)
        for relative, target in links.items():
            updated = link_target(target, roots, books, containers)
            if updated != target:
                link = root / relative; link.unlink(); link.symlink_to(updated)
        for database in root.rglob('*'):
            if database.is_symlink() or not database.is_file() or database.suffix.lower() not in ('.db', '.sqlite', '.sqlite3'): continue
            with database.open('rb') as stream:
                if stream.read(16) != b'SQLite format 3\x00': continue
            with contextlib.closing(sqlite3.connect(database)) as db:
                db.execute('PRAGMA temp_store=MEMORY')
                if db.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
                    raise RuntimeError('A private source book SQLite database failed integrity checking.')
                if db.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()[0] != 0:
                    raise RuntimeError('A private book WAL could not be checkpointed.')
            info = database.stat()
            for suffix in ('-wal', '-shm'):
                sidecar = Path(str(database) + suffix)
                if sidecar.exists(): os.chown(sidecar, info.st_uid, info.st_gid)


def root_digest(native, root):
    files, links = files_and_links(root)
    value = {'files': {name: native.digest(path) for name, path in sorted(files.items())}, 'links': links}
    return sha(json.dumps(value, sort_keys=True, ensure_ascii=True).encode())


def swap(native, operation, item):
    live, candidate, old = (Path(item[key]) for key in ('live', 'incoming', 'before'))
    for path in (live, candidate, old): native.safe(path)
    if item['phase'] == 'installed':
        if not live.is_dir() or not old.is_dir() or candidate.exists(): raise RuntimeError('An installed book root journal differs.')
        return
    retained = candidate if candidate.is_dir() else live
    if root_digest(native, retained) != item['sha256']:
        raise RuntimeError('A prepared book root changed before installation; all roots retained.')
    if live.is_dir() and not old.exists() and candidate.is_dir():
        item['phase'] = 'planned'; native.atomic(STATE, operation)
        live.rename(old); native.sync_dir(live.parent); native.sync_dir(old.parent)
    if not live.exists() and old.is_dir() and candidate.is_dir():
        item['phase'] = 'saved'; native.atomic(STATE, operation)
        candidate.rename(live); native.sync_dir(live.parent)
    if live.is_dir() and old.is_dir() and not candidate.exists():
        item['phase'] = 'installed'; native.atomic(STATE, operation); return
    raise RuntimeError('An interrupted book rename state needs review; all roots retained.')


def command(native, path, *args, timeout=300):
    return native.run('docker', 'compose', '-p', 'books-nas', '--project-directory', str(COMPOSE.parent),
                      '-f', str(path), *args, timeout=timeout)


def running_others(rows, names):
    return {name: {'id': row['Id'], 'image': row['Image'], 'started': row['State'].get('StartedAt'),
                   'running': row['State']['Running'], 'config': row['Config']}
            for name, row in rows.items() if name not in names}


def candidate_model(model, books, selected, roots, resolved, rows, starter, secrets):
    proposed = copy.deepcopy(model)
    generated = books.compose_document(selected, {'dataRoots': roots}, resolved)
    for name in books.APPS:
        target = proposed['services'][name]; producer = generated['services'][name]
        for key in ('image', 'environment', 'command', 'entrypoint', 'user', 'working_dir'):
            if key in producer: target[key] = secrets(copy.deepcopy(producer[key]))
            else: target.pop(key, None)
        for key in ('PUID', 'PGID', 'TZ'):
            value = starter.environment(rows[name + '-nas']).get(key)
            if value is not None: target['environment'][key] = value.replace('$', '$$')
        target['restart'] = 'no'; target['pull_policy'] = 'never'
    return proposed


def activate(native, books, main, operation, names, before_others):
    # This unit's ExecStop acquires BACKUP_LOCK; stop it outside that lock.
    native.held(main['proof'])
    operation['phase'] = 'stopping'; native.atomic(STATE, operation)
    native.run('systemctl', 'stop', 'nas-books.service', timeout=330)
    with native.lock(native.BACKUP_LOCK):
        native.held(main['proof']); books.check_mounts()
        say('Pausing only the eight NAS book applications for consistent retained-root replacement...')
        for name in sorted(names):
            native.run('docker', 'update', '--restart=no', name)
            if native.catalog()[name]['State']['Running']: native.run('docker', 'stop', '--timeout', '45', name, timeout=75)
        if running_others(native.catalog(), names) != before_others: raise RuntimeError('An unrelated application changed during book handover.')
        if native.digest(COMPOSE) not in (operation['composeBeforeSha256'], operation['composeAfterSha256']):
            raise RuntimeError('The NAS book Compose file changed concurrently; roots retained.')
        operation['phase'] = 'installing'; native.atomic(STATE, operation)
        for item in operation['roots']: swap(native, operation, item)
        candidate = native.read(WORK / 'compose.candidate.json', 2 * 1024**2)
        if sha(candidate) != operation['composeAfterSha256']: raise RuntimeError('The retained book candidate changed.')
        native.atomic(COMPOSE, candidate, reference=COMPOSE)
        books.check_mounts(); native.held(main['proof'])
        operation['phase'] = 'starting'; native.atomic(STATE, operation)
        say('Starting current frozen book state on the existing NAS mounts...')
        command(native, COMPOSE, 'up', '-d', '--no-deps', '--pull', 'never', '--force-recreate', *sorted(books.APPS), timeout=360)
        books.check_http(); books.check_internal()
        after = native.catalog()
        if not all(after[name]['State']['Running'] for name in names) or running_others(after, names) != before_others:
            raise RuntimeError('Book startup/other-application isolation check failed; retained copies remain.')
        marker = LIVE / 'install.json'; record = json.loads(native.read(marker))
        record.update({'sourceCreatedUtc': main['proof']['frozenUtc'], 'productionCutoverId': main['proof']['cutoverId'], 'productionRefreshComplete': True})
        native.atomic(marker, record, reference=marker)
        operation['phase'] = 'running'; native.atomic(STATE, operation)


def retain_stopped(native, operation, names):
    # A failed activation must not leave only some of the book writers running.
    # Do not roll data backwards after a new app may have written to it.
    operation['failureAtPhase'] = operation['phase']
    stopped = True
    for name in sorted(names):
        try:
            native.run('docker', 'update', '--restart=no', name)
            native.run('docker', 'stop', '--timeout', '45', name, timeout=75)
        except Exception: stopped = False
    operation['bookWritersStoppedAfterFailure'] = stopped
    native.atomic(STATE, operation)
    say('Book activation did not complete. Recovery roots and current book state retained; source remains held.')


def worker():
    starter = load(STARTER, STARTER_SHA, 'books_source_proof')
    image_helper = load(IMAGE_HELPER, IMAGE_HELPER_SHA, 'books_image_tools')
    native = starter.load_module(BASE / 'worker.py', starter.NATIVE_SHA, 'books_cutover_native')
    books = load(BOOK_WORKER, BOOK_SHA, 'verified_nas_books')
    names = {name + '-nas' for name in books.APPS}
    with native.lock(BASE / '.run.lock'):
        with native.lock(native.BACKUP_LOCK):
            plan = native.approved(starter.PLAN_SHA); main = json.loads(native.read(native.STATE))
            if main.get('phase') not in ('awaiting-acceptance', 'committed-core'): raise RuntimeError('The live accepted NAS core is required.')
            raw, manifest, _ = starter.frozen_manifest(native, main)
            native.held(main['proof']); starter.plex_identity(native, plan, main)
            h = native.helpers(); core, cache = h['core'], h['cache']; roots = layout(manifest)
            rows = native.catalog(); before_others = running_others(rows, names)
            source = {row['Name'].lstrip('/'): row for row in manifest['containers']}
            selected = {name: source[name] for name in books.APPS}
            images = {image['Id']: image for image in manifest['images']}
            if any(native.dockmon_notify(Path(plan['dockmonDatabase'])).values()):
                raise RuntimeError('Dockmon automatic actions must remain off during book import.')
            books.check_mounts()
            if native.read(books.UNIT) != books.unit_text().encode(): raise RuntimeError('The existing book service definition differs.')
            if STATE.exists():
                operation = json.loads(native.read(STATE))
                if operation.get('format') != FORMAT or operation.get('cutoverId') != main['proof']['cutoverId']:
                    raise RuntimeError('A different book handover operation was retained.')
                if operation['phase'] == 'running':
                    if not all(rows[name]['State']['Running'] for name in names): raise RuntimeError('A previously imported book app is stopped; inspect before retrying.')
                    say('CURRENT FROZEN BOOK STACK IS ALREADY RUNNING. No copy/recreation repeated.'); return
                if operation['phase'] not in ('prepared', 'stopping', 'installing', 'roots-installed', 'starting'):
                    raise RuntimeError('A previous private book preparation was interrupted; retained for inspection.')
            else:
                native.safe(COMPOSE); current_body = native.read(COMPOSE, 2 * 1024**2)
                model = image_helper.compose_model(current_body)
                if set(model['services']) != set(books.APPS) or model.get('x-sawdoctor-managed') != books.SIGNATURE:
                    raise RuntimeError('The existing eight-service NAS book definition differs.')
                for name, row in selected.items():
                    target = rows[name + '-nas']; mounts = {item['Destination']: item for item in target['Mounts']}
                    if len(mounts) != len(row['Mounts']): raise RuntimeError('A book runtime binding inventory differs.')
                    for mount in row['Mounts']:
                        _, wanted = mapping(mount['Source'], roots, LIVE, books.MOUNTS)
                        actual = mounts.get(mount['Destination'], {})
                        if actual.get('Source') != str(wanted) or actual.get('RW') != mount['RW']:
                            raise RuntimeError('An accepted NAS book path/read-only binding differs: ' + name)
                say('Verifying selected current frozen book databases, assets and link roots...')
                for item in roots.values(): core.no_nested_mounts(raw / item['snapshot'])
                inventories, checks, size = verify_selected(native, core, raw, roots)
                if shutil.disk_usage(APP).free < size + 4 * 1024**3: raise RuntimeError('Book copy/reserve space is insufficient.')
                resolved = {}; local_images = cache.inventory(core)
                tags = cache.tag_bindings(local_images, [selected['sabnzbd-ebooks']['Config']['Image']])
                for name, row in selected.items():
                    expected = images[row['Image']]; old_image = rows[name + '-nas']['Image']
                    if cache.same_image(core, expected, local_images[old_image]): resolved[name] = old_image; continue
                    matches = sorted(key for key, value in local_images.items() if cache.same_image(core, expected, value))
                    if not matches:
                        if name != 'sabnzbd-ebooks' or image_helper.repository(row['Config']['Image']) != 'lscr.io/linuxserver/sabnzbd':
                            raise RuntimeError('An additional book image differs from the verified inspection; no apps stopped.')
                        cache.PULL_REPOSITORIES[name] = 'lscr.io/linuxserver/sabnzbd'
                        reference = cache.saved_digest(name, expected)
                        image_size = expected.get('Size', 0)
                        if expected.get('Os') != 'linux' or expected.get('Architecture') != 'amd64' or expected.get('Variant'):
                            raise RuntimeError('The frozen SABnzbd image requires a different platform.')
                        docker_root = Path(native.run('docker', 'info', '--format', '{{.DockerRootDir}}').strip())
                        if not 0 < image_size < 12 * 1024**3 or shutil.disk_usage(docker_root).free < 2 * image_size + 4 * 1024**3:
                            raise RuntimeError('Exact SABnzbd image expansion/reserve space is insufficient.')
                        cache.pull(core, name, reference, 'linux/amd64', WORK)
                        downloaded = json.loads(native.run('docker', 'image', 'inspect', reference))[0]
                        if not cache.same_image(core, expected, downloaded): raise RuntimeError('Cached SABnzbd image differs from frozen source.')
                        local_images = cache.inventory(core)
                        matches = sorted(key for key, value in local_images.items() if cache.same_image(core, expected, value))
                    if not matches: raise RuntimeError('A verified exact source book image is unavailable.')
                    resolved[name] = matches[0]
                if cache.tag_bindings(local_images, [selected['sabnzbd-ebooks']['Config']['Image']]) != tags:
                    raise RuntimeError('An existing SABnzbd tag changed during exact caching.')
                infini_name = core.NAMES['nzbdav']
                old_env = starter.environment(source['nzbdav']); new_env = starter.environment(rows[infini_name])
                old_key = old_env.get('FRONTEND_BACKEND_API_KEY') or old_env.get('NZBDAV_CONFIG__API__KEY')
                new_key = new_env.get('FRONTEND_BACKEND_API_KEY') or new_env.get('NZBDAV_CONFIG__API__KEY')
                if not old_key or not new_key: raise RuntimeError('Current source/NAS InfiniDysk API adapters are unavailable.')
                secrets = install_adapters(books, roots, [(old_key, new_key)])
                incoming = WORK / 'incoming'; native.safe(incoming)
                if incoming.exists(): raise RuntimeError('An earlier private book copy was retained.')
                incoming.mkdir(mode=0o755)
                operation = {'format': FORMAT, 'cutoverId': main['proof']['cutoverId'], 'phase': 'preparing',
                             'composeBeforeSha256': sha(current_body), 'roots': [], 'files': len(checks), 'bytes': size}
                native.atomic(STATE, operation)
                for label, item in roots.items():
                    say('Copying current frozen book root privately: ' + label)
                    source_root = raw / item['snapshot']; target = incoming / label
                    native.run('cp', '-a', '--', str(source_root), str(target), timeout=1200)
                    copied, links = files_and_links(target); files, expected_links = inventories[label]
                    if set(copied) != set(files) or links != expected_links or any(
                            native.digest(path) != checks[item['snapshot'] + '/' + name] for name, path in copied.items()):
                        raise RuntimeError('A private book copy differs from current frozen source.')
                books.patch_runtime(selected, {'dataRoots': roots}, incoming)
                fix_links_and_databases(native, roots, incoming, books, selected)
                proposed = candidate_model(model, books, selected, roots, resolved, rows, starter, secrets)
                candidate = (json.dumps(proposed, indent=2) + '\n').encode()
                native.atomic(WORK / 'compose.candidate.json', candidate)
                normalized = json.loads(command(native, WORK / 'compose.candidate.json', 'config', '--format', 'json'))
                for name in books.APPS:
                    if normalized['services'][name]['image'] != resolved[name]: raise RuntimeError('A pinned book image did not round-trip.')
                before = WORK / 'rollback'; before.mkdir(mode=0o700)
                native.atomic(before / 'compose.before.yaml', current_body)
                native.atomic(before / 'containers.before.json', {name: rows[name] for name in names})
                operation['composeAfterSha256'] = sha(candidate)
                for label in roots:
                    live = LIVE / label; old = before / label; native.safe(live)
                    if not live.is_dir() or live.is_mount() or live.stat().st_dev != APP.stat().st_dev:
                        raise RuntimeError('A current NAS book rollback root is unavailable: ' + label)
                    core.no_nested_mounts(live)
                    operation['roots'].append({'label': label, 'incoming': str(incoming / label), 'live': str(live),
                                               'before': str(old), 'phase': 'prepared', 'sha256': root_digest(native, incoming / label)})
                operation['phase'] = 'prepared'; native.atomic(STATE, operation)
                say('Fresh book state prepared and databases checked. Original production acquisition/notification settings retained.')
        try:
            activate(native, books, main, operation, names, before_others)
        except BaseException:
            if operation['phase'] in ('stopping', 'installing', 'roots-installed', 'starting'):
                retain_stopped(native, operation, names)
            raise
    say('CURRENT FROZEN BOOK STACK RUNNING ON NAS: eight applications; HTTP and internal connections verified.')
    say('Source databases, users, settings, local assets and playback links imported; prior NAS roots retained.')
    say('Cloud mounts/credentials, Plex, Silo, Kometa, Tracearr, Dockmon and TorBox CAM retained.')
    say('Book restart policies remain held until final boot/job ownership; existing systemd import guards retained.')
    say('Rollback roots: ' + str(WORK / 'rollback'))


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or not APP.is_mount() or 'inet 192.168.0.220/' not in subprocess.check_output(['ip', '-4', 'addr', 'show'], text=True, timeout=10):
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220.')
    if len(sys.argv) == 3 and sys.argv[1] == '--worker':
        if sha(SELF.read_bytes()) != sys.argv[2]: raise RuntimeError('The pinned book worker changed.')
        worker(); return
    if sys.argv[1:] or globals().get('IMPORT_APPROVED_FROZEN_BOOKS') is not True:
        raise RuntimeError('The explicit approved frozen-book import flag is required.')
    source = globals().get('INSTALL_SOURCE')
    if not isinstance(source, str): raise RuntimeError('The exact installer source is required.')
    starter = load(STARTER, STARTER_SHA, 'books_installer_proof')
    native = starter.load_module(BASE / 'worker.py', starter.NATIVE_SHA, 'books_installer_native')
    native.approved(starter.PLAN_SHA); native.safe(WORK); WORK.mkdir(mode=0o700, exist_ok=True)
    owner = WORK / 'owner.json'
    if owner.exists() and json.loads(native.read(owner)) != {'format': FORMAT}: raise RuntimeError('An unrelated book work folder was retained.')
    if not owner.exists(): native.atomic(owner, {'format': FORMAT})
    encoded = source.encode()
    if SELF.exists() and native.read(SELF) != encoded: raise RuntimeError('A different book worker was retained.')
    if not SELF.exists(): native.atomic(SELF, encoded)
    if native.unit_state('nas-production-books.service')['ActiveState'] in ('active', 'activating', 'deactivating'):
        raise RuntimeError('The book production handover is already active.')
    native.run('systemd-run', '--unit=nas-production-books', '--collect', '--description=Import current frozen book state into existing NAS mounts',
               '--property=Type=exec', '--property=Nice=10', '--property=TimeoutStopSec=30',
               '/usr/bin/python3', str(SELF), '--worker', sha(encoded))
    say('Current frozen book import started in systemd. Closing SSH is safe.')
    say('Progress: sudo journalctl -fu nas-production-books.service -n 20 --no-pager -o cat')


if __name__ == '__main__':
    try: main()
    except Exception as exc:
        raise SystemExit('STOP: ' + (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__))
