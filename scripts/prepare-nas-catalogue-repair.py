#!/usr/bin/env python3
"""Sawdoctor NAS additive catalogue preparation v1.

Creates a private, inactive candidate. It never updates live appdata or stops apps.
Only missing catalogue rows are inserted into a disposable NAS database copy.
"""
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid

SIGNATURE = 'Sawdoctor NAS additive catalogue preparation v1'
SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
CONFIG = SSD / 'appdata/infinidysk-nas/config'
LIBRARY = SSD / 'appdata/infinidysk-nas/library'
PLEX = SSD / 'appdata/plex-nas'
STANDBY = SSD / 'migration/nightly-standby'
BASE = SSD / 'compose/infinidysk-nas/recovery/catalogue-additions'
WORKER = Path('/run/nas-catalogue-prepare.py')
LOCK = Path('/run/lock/sawdoctor-nas-backup.lock')
TABLES = ('DavItems', 'HistoryItems', 'NzbNames', 'DavNzbFiles', 'DavRarFiles', 'DavMultipartFiles')
EXTENSIONS = {'.mkv', '.mp4', '.avi', '.m4v', '.ts', '.strm', '.mov'}


def log(message):
    print(message, flush=True)


def run(*args, allowed=(0,)):
    result = subprocess.run(args, text=True, capture_output=True, timeout=30)
    if result.returncode not in allowed:
        raise RuntimeError('A preparation command failed; live applications were not changed.')
    return result.stdout


def atomic(path, value, mode=0o600):
    if path.is_symlink():
        raise RuntimeError('An unexpected symbolic preparation file was retained.')
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(value.encode()); stream.flush(); os.fsync(stream.fileno())
            temporary.chmod(mode); temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def digest(path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('An expected regular preparation file is unavailable.')
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def identifier(value):
    return str(uuid.UUID(value)) if value is not None else None


def read_only(path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('The expected regular catalogue database is unavailable.')
    connection = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute('PRAGMA query_only=ON')
    deadline = time.monotonic() + 120
    connection.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
    return connection


def inventory(root):
    result = {}
    pending = []
    for category in ('movies', 'movies-4k', 'tv'):
        folder = root / category
        if folder.is_symlink() or not folder.is_dir():
            raise RuntimeError('The expected local library categories differ.')
        pending.append(folder)
    while pending:
        with os.scandir(pending.pop()) as entries:
            for entry in entries:
                path = Path(entry.path)
                if entry.is_dir(follow_symlinks=False): pending.append(path)
                elif path.suffix.lower() in EXTENSIONS:
                    result[str(path.relative_to(root))] = os.readlink(path) if entry.is_symlink() else None
    return result


def file_id(relative, target):
    if not isinstance(target, str):
        raise RuntimeError('A missing media item is not a reviewed symbolic link.')
    path = Path(os.path.normpath(os.path.join('/mnt/media', str(Path(relative).parent), target)))
    try:
        parts = path.relative_to('/mnt/nzbdav/.ids').parts
        value = identifier(parts[-1])
        if len(parts) != 6 or ''.join(parts[:5]).lower() != value[:5]:
            raise ValueError()
        return value
    except (ValueError, IndexError):
        raise RuntimeError('A library link uses an unreviewed target layout.') from None


def rows(connection, table, keys=None):
    if table not in TABLES:
        raise RuntimeError('An unreviewed table was requested.')
    exists = connection.execute('SELECT 1 FROM sqlite_master WHERE type=\'table\' AND name=?', (table,)).fetchone()
    if not exists:
        return {}
    if keys is None:
        return {identifier(row['Id']): dict(row) for row in connection.execute('SELECT * FROM "' + table + '"')}
    result = {}
    values = sorted(key.upper() for key in keys)
    for start in range(0, len(values), 200):
        batch = values[start:start + 200]
        for row in connection.execute('SELECT * FROM "' + table + '" WHERE UPPER(Id) IN ('
                                      + ','.join('?' for _ in batch) + ')', batch):
            result[identifier(row['Id'])] = dict(row)
    return result


def build_rows(source, nas, seeds):
    original = rows(source, 'DavItems'); current = rows(nas, 'DavItems')
    original_history = rows(source, 'HistoryItems'); current_history = rows(nas, 'HistoryItems')
    selected = {}; histories = {}; active = set()
    nas_paths = {row['Path']: key for key, row in current.items()}
    structural = ('ParentId', 'Name', 'Type', 'SubType', 'Path')

    def include(key, depth=0):
        if key is None or key in selected:
            return
        if depth > 100 or key in active or key not in original:
            raise RuntimeError('The source catalogue ancestry is incomplete or cyclic.')
        row = original[key]
        if key in current:
            for column in structural:
                left, right = row.get(column), current[key].get(column)
                if column == 'ParentId': left, right = identifier(left), identifier(right)
                if left != right:
                    raise RuntimeError('An existing NAS directory or file has different source metadata; it was retained.')
            return
        if row['Path'] in nas_paths and nas_paths[row['Path']] != key:
            raise RuntimeError('A source catalogue path collides with an existing NAS item; it was retained.')
        active.add(key)
        include(identifier(row.get('ParentId')), depth + 1)
        selected[key] = row; active.remove(key)

    for seed in seeds:
        if seed not in original or original[seed]['Type'] != 2 or not original[seed].get('FileBlobId'):
            raise RuntimeError('A missing video lacks its expected source file metadata.')
        include(seed)
    checked = set()
    while True:
        references = {identifier(row.get('HistoryItemId')) for row in selected.values()} - {None} - checked
        if not references: break
        for key in references:
            checked.add(key)
            if key not in original_history:
                # Completed-job history can be pruned independently of playable
                # catalogue files. Preserve the source pointer; do not fabricate
                # a replacement history row or change the live NAS history.
                continue
            row = original_history[key]
            if key in current_history:
                if (identifier(current_history[key].get('DownloadDirId')) != identifier(row.get('DownloadDirId'))
                        or any(current_history[key].get(field) != row.get(field) for field in
                               ('DownloadStatus', 'Category', 'FileName'))):
                    raise RuntimeError('A referenced NAS history entry differs; it was retained.')
                continue
            if row['DownloadStatus'] != 1:
                raise RuntimeError('A selected source release is not completed.')
            include(identifier(row.get('DownloadDirId')))
            histories[key] = row
    additions = {'DavItems': list(selected.values()), 'HistoryItems': list(histories.values())}
    for table in TABLES[3:]:
        legacy = rows(source, table, selected); present = rows(nas, table, selected)
        additions[table] = [row for key, row in legacy.items() if key in selected and key not in present]
    blobs = set()
    for table in ('DavItems', 'HistoryItems'):
        for row in additions[table]:
            for column in ('FileBlobId', 'NzbBlobId'):
                if row.get(column): blobs.add(identifier(row[column]))
    names = rows(source, 'NzbNames', blobs); nas_names = rows(nas, 'NzbNames', blobs)
    additions['NzbNames'] = [row for key, row in names.items() if key in blobs and key not in nas_names]
    for table, keys in (('BlobCleanupItems', blobs), ('NzbBlobCleanupItems', blobs),
                        ('DavCleanupItems', set(selected)), ('HistoryCleanupItems', set(histories))):
        exists = nas.execute('SELECT 1 FROM sqlite_master WHERE type=\'table\' AND name=?', (table,)).fetchone()
        if exists and any(identifier(row[0]) in keys for row in nas.execute('SELECT Id FROM "' + table + '"')):
            raise RuntimeError('A selected item has a pending NAS cleanup record; it was retained for review.')
    return additions, blobs


def review_test_labels(source, plex_database, links):
    original = rows(source, 'DavItems'); histories = rows(source, 'HistoryItems')
    if plex_database.is_symlink() or not plex_database.is_file():
        raise RuntimeError('The copied Plex database is required for the library review.')
    wanted = ['/mnt/media/' + name for name in links]
    labels = {}
    with contextlib.closing(read_only(plex_database)) as plex:
        for start in range(0, len(wanted), 100):
            batch = wanted[start:start + 100]
            for file, name in plex.execute(
                    'SELECT p.file,s.name FROM media_parts p JOIN media_items m ON m.id=p.media_item_id '
                    'JOIN metadata_items t ON t.id=m.metadata_item_id JOIN library_sections s ON s.id=t.library_section_id '
                    'WHERE p.file COLLATE BINARY IN (' + ','.join('?' for _ in batch) + ')', batch):
                labels.setdefault(file, []).append(name)
    review = []
    for name, target in links.items():
        record = original[file_id(name, target)]
        history = histories.get(identifier(record.get('HistoryItemId')), {})
        sections = sorted(set(labels.get('/mnt/media/' + name, [])))
        values = [record['Path'], str(history.get('Category') or '')] + sections
        possible_test = any(re.search(r'(?i)(?:^|[\W_])(test(?:ing)?|flora|trial|poc|experiment)(?:$|[\W_])', value) for value in values)
        review.append({'path': name, 'sourceDavPath': record['Path'], 'category': history.get('Category'),
                       'plexSections': sections, 'possibleTestLabel': possible_test})
    return review


def insert_additions(connection, additions):
    connection.execute('PRAGMA foreign_keys=ON')
    with connection:
        for table in ('HistoryItems', 'DavItems', 'NzbNames', 'DavNzbFiles', 'DavRarFiles', 'DavMultipartFiles'):
            batch = additions.get(table, [])
            if not batch: continue
            schema = list(connection.execute('PRAGMA table_info("' + table + '")'))
            columns = {row[1]: row for row in schema}
            if not schema or any(key not in columns for key in batch[0]):
                raise RuntimeError('A source catalogue table has columns absent from the NAS schema.')
            omitted = set(columns) - set(batch[0])
            if any(columns[key][3] and columns[key][4] is None and not columns[key][5] for key in omitted):
                raise RuntimeError('A required NAS catalogue column has no reviewed source value.')
            keys = list(batch[0])
            names = ','.join('"' + key.replace('"', '""') + '"' for key in keys)
            connection.executemany('INSERT INTO "' + table + '" (' + names + ') VALUES ('
                                   + ','.join('?' for _ in keys) + ')', [[row[key] for key in keys] for row in batch])
    if list(connection.execute('PRAGMA foreign_key_check')) or connection.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
        raise RuntimeError('The inactive candidate failed database integrity checks.')


def verify_preserved(candidate, base_database, additions):
    candidate.execute('ATTACH DATABASE ? AS baseline', (base_database.as_uri() + '?mode=ro',))
    try:
        tables = [row[0] for row in candidate.execute("SELECT name FROM baseline.sqlite_master WHERE type='table'")]
        if list(candidate.execute('SELECT type,name,tbl_name,sql FROM baseline.sqlite_master ORDER BY type,name')) != list(
                candidate.execute('SELECT type,name,tbl_name,sql FROM main.sqlite_master ORDER BY type,name')):
            raise RuntimeError('The inactive candidate changed the NAS database schema.')
        for table in tables:
            quoted = '"' + table.replace('"', '""') + '"'
            if candidate.execute('SELECT * FROM baseline.' + quoted + ' EXCEPT SELECT * FROM main.' + quoted + ' LIMIT 1').fetchone():
                raise RuntimeError('The inactive candidate changed an existing NAS database row.')
            extra = candidate.execute('SELECT COUNT(*) FROM main.' + quoted).fetchone()[0] - candidate.execute(
                'SELECT COUNT(*) FROM baseline.' + quoted).fetchone()[0]
            if extra != len(additions.get(table, [])):
                raise RuntimeError('The inactive candidate has unplanned database additions.')
    finally:
        candidate.execute('DETACH DATABASE baseline')


def checksum_entries(snapshot):
    result = {}
    for raw in (snapshot / 'SHA256SUMS').read_text().splitlines():
        escaped = raw.startswith('\\')
        value = raw[1:] if escaped else raw
        if len(value) < 67 or not re.fullmatch('[a-f0-9]{64}', value[:64]):
            raise RuntimeError('The source checksum record layout differs.')
        name = value[66:]
        if escaped:
            name = re.sub(r'\\([\\nr])', lambda match: {'\\': '\\', 'n': '\n', 'r': '\r'}[match[1]], name)
        result[name.removeprefix('./')] = value[:64]
    return result


def checked_source_file(snapshot, relative, checksums):
    path = snapshot / relative
    if not path.resolve().is_relative_to(snapshot.resolve()) or checksums.get(relative) != digest(path):
        raise RuntimeError('A selected source metadata file failed its verified checksum.')
    return path


def blob_relative(key):
    compact = key.replace('-', '')
    return Path('blobs') / compact[:2] / compact[2:4] / key


def prepared_source():
    if PLEX.is_symlink(): raise RuntimeError('An unexpected symbolic Plex data path was retained.')
    marker_path = PLEX / '.standby-refreshed.json'
    if marker_path.is_symlink(): raise RuntimeError('An unexpected symbolic Plex marker was retained.')
    marker = json.loads(marker_path.read_text())
    stamp = marker.get('sourceCreatedUtc')
    if marker.get('format') != 'Sawdoctor NAS Plex standby refresh v1' or not isinstance(stamp, str) or not re.fullmatch(r'\d{8}T\d{6}Z', stamp):
        raise RuntimeError('The completed Plex standby refresh is required.')
    snapshot = STANDBY / 'snapshots' / stamp
    if snapshot.is_symlink(): raise RuntimeError('An unexpected symbolic snapshot was retained.')
    verified = json.loads((snapshot / '_VERIFIED.json').read_text())
    if (verified.get('format') != 'sawdoctor-migration-standby-v1' or verified.get('createdUtc') != stamp
            or verified.get('sha256') != marker.get('sourceArchiveSha256')):
        raise RuntimeError('The prepared Plex source verification differs.')
    return snapshot, marker


def validate_runtime():
    state = json.loads(run('docker', 'inspect', 'plex-nas', 'infinidysk-nas'))
    by_name = {row['Name']: row for row in state}
    if by_name['/plex-nas']['State']['Running']:
        raise RuntimeError('Keep NAS Plex stopped during preparation.')
    backend = by_name['/infinidysk-nas']
    if not backend['State']['Running'] or not any(mount['Source'] == str(CONFIG)
            and mount['Destination'] == '/config' for mount in backend['Mounts']):
        raise RuntimeError('The NAS InfiniDysk configuration binding differs.')


def prepare():
    log('Waiting for the NAS backup and standby locks; all applications stay online...')
    with LOCK.open('a') as backup_lock, (STANDBY / '.run.lock').open('a') as standby_lock:
        fcntl.flock(backup_lock, fcntl.LOCK_EX); fcntl.flock(standby_lock, fcntl.LOCK_EX)
        validate_runtime(); snapshot, marker = prepared_source()
        if BASE.is_symlink(): raise RuntimeError('An unexpected symbolic preparation folder was retained.')
        if BASE.exists():
            saved = json.loads((BASE / 'plan.json').read_text())
            if saved.get('format') != SIGNATURE or saved.get('sourceArchiveSha256') != marker['sourceArchiveSha256']:
                raise RuntimeError('A different candidate already exists; it was retained for review.')
            if (digest(BASE / 'candidate.sqlite') != saved['candidateSha256']
                    or digest(BASE / 'baseline.sqlite') != saved['baselineSha256']
                    or any(digest(BASE / blob_relative(key)) != value for key, value in saved['blobSha256'].items())):
                raise RuntimeError('The saved inactive candidate differs; it was retained for review.')
            log('INACTIVE NAS CATALOGUE CANDIDATE ALREADY PREPARED: ' + json.dumps(saved['counts'], sort_keys=True))
            log('No activation occurred. Live NAS settings may have advanced since this preparation.'); return
        BASE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        database_bytes = sum(path.stat().st_size for path in (CONFIG / 'db.sqlite', CONFIG / 'db.sqlite-wal') if path.is_file())
        if shutil.disk_usage(BASE.parent).free < database_bytes * 3 + 1024**3:
            raise RuntimeError('More free NAS SSD space is required for the inactive database copies.')
        checksums = checksum_entries(snapshot)
        original_db = checked_source_file(snapshot, 'data/infinidysk-config/db.sqlite', checksums)
        # The WAL contains database data; SHM is volatile SQLite coordination
        # state and can change during an otherwise read-only catalogue query.
        for suffix in ('-wal',):
            relative = 'data/infinidysk-config/db.sqlite' + suffix
            sidecar = snapshot / relative
            if sidecar.exists() and sidecar.stat().st_size:
                checked_source_file(snapshot, relative, checksums)
        source_paths = inventory(snapshot / 'data/library'); nas_paths = inventory(LIBRARY)
        if any(source_paths[name] != nas_paths[name] for name in source_paths.keys() & nas_paths.keys()):
            raise RuntimeError('An existing library path has different targets; it was retained.')
        links = {name: source_paths[name] for name in sorted(source_paths.keys() - nas_paths.keys())}
        seeds = {file_id(name, target) for name, target in links.items()}
        if not seeds: log('No missing source library links need preparation.'); return
        log('Preparing an isolated NAS database copy for ' + str(len(links)) + ' missing source links...')
        with tempfile.TemporaryDirectory(prefix='.catalogue-prepare-', dir=BASE.parent) as temporary:
            work = Path(temporary)
            base_database = work / 'baseline.sqlite'; candidate_database = work / 'candidate.sqlite'
            with contextlib.closing(read_only(CONFIG / 'db.sqlite')) as live, contextlib.closing(sqlite3.connect(base_database)) as backup:
                deadline = time.monotonic() + 90
                def progress(status, remaining, total):
                    if time.monotonic() > deadline: raise RuntimeError('The online NAS database copy exceeded its preparation deadline.')
                live.backup(backup, pages=512, progress=progress, sleep=0.05)
            shutil.copy2(base_database, candidate_database)
            with contextlib.closing(read_only(original_db)) as source, contextlib.closing(read_only(base_database)) as nas:
                additions, blobs = build_rows(source, nas, seeds)
                review = review_test_labels(source, snapshot / 'data/plex-config/Library/Application Support/Plex Media Server/Plug-in Support/Databases/com.plexapp.plugins.library.db', links)
                source_history_ids = set(rows(source, 'HistoryItems'))
                pruned_history = sum(bool(row.get('HistoryItemId')) and identifier(row['HistoryItemId']) not in source_history_ids
                                     for row in additions['DavItems'])
            blob_bytes = sum((snapshot / 'data/infinidysk-config' / blob_relative(key)).stat().st_size for key in blobs)
            if shutil.disk_usage(work).free < blob_bytes + 512 * 1024**2:
                raise RuntimeError('More free NAS SSD space is required for the selected metadata blobs.')
            for number, key in enumerate(sorted(blobs), 1):
                relative = blob_relative(key)
                source = checked_source_file(snapshot, str(Path('data/infinidysk-config') / relative), checksums)
                existing = CONFIG / relative
                if existing.exists() and digest(existing) != digest(source):
                    raise RuntimeError('A source metadata blob conflicts with an existing NAS blob; it was retained.')
                destination = work / relative; destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                shutil.copy2(source, destination)
                if digest(destination) != checksums[str(Path('data/infinidysk-config') / relative)]:
                    raise RuntimeError('A copied metadata blob failed verification.')
            log('Checking the isolated candidate and proving every original NAS row is retained...')
            with contextlib.closing(sqlite3.connect(candidate_database.as_uri(), uri=True)) as candidate:
                candidate.execute('PRAGMA journal_mode=DELETE')
                insert_additions(candidate, additions)
                verify_preserved(candidate, base_database, additions)
            counts = {table: len(batch) for table, batch in additions.items()}
            counts.update({'sourceLinksToAdd': len(links), 'metadataBlobsPrepared': len(blobs),
                           'nasOnlyPathsPreserved': len(nas_paths.keys() - source_paths.keys()),
                           'possibleTestEntriesForReview': sum(item['possibleTestLabel'] for item in review),
                           'sourceRowsWithPrunedHistory': pruned_history})
            plan = {'format': SIGNATURE, 'preparedUtc': dt.datetime.now(dt.timezone.utc).isoformat(),
                    'sourceCreatedUtc': marker['sourceCreatedUtc'], 'sourceArchiveSha256': marker['sourceArchiveSha256'],
                    'candidateSha256': digest(candidate_database), 'baselineSha256': digest(base_database),
                    'links': links, 'additions': additions, 'testEntryReview': review, 'blobSha256': {key: digest(work / blob_relative(key)) for key in blobs},
                    'counts': counts, 'activationStatus': 'not-activated'}
            atomic(work / 'plan.json', json.dumps(plan, indent=2) + '\n')
            validate_runtime(); work.rename(BASE)
        log('INACTIVE NAS CATALOGUE CANDIDATE READY: ' + json.dumps(counts, sort_keys=True))
        for item in review:
            if item['possibleTestLabel']: log('POSSIBLE TEST ENTRY, REVIEW BEFORE ACTIVATION: ' + json.dumps(item))
        log('Every pre-existing NAS database row and its schema were retained in the candidate. NAS-only links remain untouched.')
        log('Prepared folder: ' + str(BASE))
        log('No live database, library link, credential, container or schedule was changed. Activation is a separate step and must retain changes made after preparation.')


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220.')
    if not SSD.is_mount(): raise RuntimeError('The NAS appdata filesystem must be mounted.')
    if sys.argv[1:] == ['prepare']: prepare(); return
    if sys.argv[1:]: raise RuntimeError('Unknown preparation operation.')
    if run('systemctl', 'is-active', 'nas-catalogue-prepare.service', allowed=(0, 3, 4)).strip() in ('active', 'activating'):
        log('NAS catalogue preparation is already running.'); return
    source = globals().get('INSTALL_SOURCE')
    if not source: raise RuntimeError('Use the complete provided preparation command.')
    if WORKER.exists() and (WORKER.is_symlink() or SIGNATURE not in WORKER.read_text()):
        raise RuntimeError('An unrelated temporary preparation helper was retained.')
    atomic(WORKER, source, 0o700)
    run('systemctl', 'reset-failed', 'nas-catalogue-prepare.service', allowed=(0, 1))
    run('systemd-run', '--unit=nas-catalogue-prepare', '--collect',
        '--description=Prepare inactive additive NAS media catalogue repair', '/usr/bin/python3', '-u', str(WORKER), 'prepare')
    log('Inactive NAS catalogue preparation started. Closing SSH is safe.')
    log('Check: sudo journalctl -u nas-catalogue-prepare.service -n 20 --no-pager -o cat')


if __name__ == '__main__':
    try: main()
    except RuntimeError as error: raise SystemExit('STOP: ' + str(error))
    except Exception as error: raise SystemExit('STOP: Inactive catalogue preparation failed (' + type(error).__name__ + '); live applications were not changed.') from None
