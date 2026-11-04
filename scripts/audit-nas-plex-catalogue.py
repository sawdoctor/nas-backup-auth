#!/usr/bin/env python3
"""Read-only catalogue diagnosis for the prepared NAS Plex media differences."""
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import time
import uuid

SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
DATA = SSD / 'appdata/plex-nas'
LIBRARY = SSD / 'appdata/infinidysk-nas/library'
NAS_CONFIG = SSD / 'appdata/infinidysk-nas/config'
SNAPSHOTS = SSD / 'migration/nightly-standby/snapshots'
EXTENSIONS = {'.mkv', '.mp4', '.avi', '.m4v', '.ts', '.strm', '.mov'}


def local_videos(root, categories=None):
    result = {}
    pending = [root / category for category in categories] if categories is not None else [root]
    while pending:
        folder = pending.pop()
        if folder.is_symlink():
            raise RuntimeError('An unexpected symbolic library category was retained.')
        try:
            with os.scandir(folder) as entries:
                for entry in entries:
                    path = Path(entry.path)
                    if entry.is_dir(follow_symlinks=False):
                        pending.append(path)
                    elif path.suffix.lower() in EXTENSIONS:
                        result[str(path.relative_to(root))] = os.readlink(path) if entry.is_symlink() else None
        except FileNotFoundError:
            continue
    return result


def paths(root):
    return local_videos(root, ('movies', 'movies-4k', 'tv'))


def file_id(relative, target):
    if not isinstance(target, str):
        return None
    path = Path(os.path.normpath(os.path.join('/mnt/media', str(Path(relative).parent), target)))
    try:
        parts = path.relative_to('/mnt/nzbdav/.ids').parts
        if len(parts) != 6:
            return None
        value = str(uuid.UUID(parts[-1]))
        return value if ''.join(parts[:5]).lower() == value[:5] else None
    except ValueError:
        return None


def records(database):
    if database.is_symlink() or not database.is_file():
        raise RuntimeError('The expected regular InfiniDysk database is unavailable.')
    connection = sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=5)
    try:
        connection.execute('PRAGMA query_only=ON')
        deadline = time.monotonic() + 15
        connection.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        columns = {row[1] for row in connection.execute('PRAGMA table_info(DavItems)')}
        if not {'Id', 'Type', 'FileSize', 'FileBlobId'} <= columns:
            raise RuntimeError('The InfiniDysk file-record schema needs review.')
        result = {}
        extras = ',Path,HistoryItemId' if {'Path', 'HistoryItemId'} <= columns else ',NULL,NULL'
        for identifier, kind, size, blob, folder, history in connection.execute('SELECT Id, Type, FileSize, FileBlobId' + extras + ' FROM DavItems'):
            try:
                key = str(uuid.UUID(identifier))
                blob = str(uuid.UUID(blob)) if blob is not None else None
            except (ValueError, TypeError, AttributeError):
                raise RuntimeError('An InfiniDysk file identifier uses an unreviewed encoding.') from None
            result[key] = {'type': kind, 'size': size, 'blob': blob, 'path': folder, 'history': history}
        return result
    finally:
        connection.close()


def episode_key(relative):
    parts = Path(relative).parts
    if len(parts) < 3 or parts[0] != 'tv':
        return None
    matches = list(re.finditer(r'(?i)(?<![a-z0-9])s(\d{1,3})[ ._-]*e(\d{1,3})(?!\d)', parts[-1]))
    if len(matches) != 1:
        return None
    match = matches[0]
    if re.match(r'(?i)[ ._-]*e\d', parts[-1][match.end():]):
        return None
    return parts[1].casefold(), int(match[1]), int(match[2])


def blob_exists(config, record):
    if not record or not record['blob']:
        return False
    identifier = record['blob']
    compact = identifier.replace('-', '')
    return (config / 'blobs' / compact[:2] / compact[2:4] / identifier).is_file()


def diagnose(source, nas, source_records, nas_records, source_config):
    common = {name for name in source.keys() & nas.keys() if source[name] == nas[name]}
    missing = sorted(source.keys() - nas.keys())
    nas_only = sorted(nas.keys() - source.keys())
    alternatives = {}
    for name in nas_only:
        key = episode_key(name)
        if key:
            alternatives.setdefault(key, []).append(name)
    counts = {'missingSourcePaths': len(missing), 'sourceRecordsPresent': 0,
              'sourceRecordsAbsent': 0, 'nasRecordsPresent': 0, 'nasRecordsAbsent': 0,
              'unsupportedTargets': 0, 'sourceFileBlobsPresent': 0,
              'alternateNasEpisodeCandidates': 0, 'nasOnlyPathsRetained': len(nas_only),
              'commonLibraryPaths': len(common), 'commonPathsWithNasRecords': 0}
    for name in common:
        record = nas_records.get(file_id(name, nas[name]))
        if record and record['type'] == 2:
            counts['commonPathsWithNasRecords'] += 1
    findings = []
    for name in missing:
        identifier = file_id(name, source[name])
        if identifier is None:
            counts['unsupportedTargets'] += 1
            findings.append(('unreviewed target', name))
            continue
        original = source_records.get(identifier)
        current = nas_records.get(identifier)
        counts['sourceRecordsPresent' if original else 'sourceRecordsAbsent'] += 1
        counts['nasRecordsPresent' if current else 'nasRecordsAbsent'] += 1
        counts['sourceFileBlobsPresent'] += int(blob_exists(source_config, original))
        candidates = alternatives.get(episode_key(name), [])
        if candidates:
            counts['alternateNasEpisodeCandidates'] += 1
        status = ('source record ' + ('present' if original else 'absent')
                  + '; NAS record ' + ('present' if current else 'absent')
                  + ('; alternate NAS episode candidate' if candidates else ''))
        findings.append((status, name))
    return counts, findings


def reference_id(relative, target, root, source, flora, seen=None):
    if not isinstance(target, str): return None
    path = Path(os.path.normpath(os.path.join(root, str(Path(relative).parent), target)))
    seen = set() if seen is None else seen
    if str(path) in seen or len(seen) > 16: return None
    seen = seen | {str(path)}
    if path.is_relative_to('/mnt/nzbdav/.ids'):
        return file_id('file.mkv', str(path))
    for prefix, mapping in (('/mnt/media', source), ('/flora-test-library', flora),
                            ('/home/sawdoctor/plex2ultimate/flora-test-library', flora)):
        if path.is_relative_to(prefix):
            name = str(path.relative_to(prefix))
            return reference_id(name, mapping.get(name), prefix, source, flora, seen)
    return None


def history_labels(database, records_needed):
    connection = sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=5)
    try:
        connection.execute('PRAGMA query_only=ON')
        deadline = time.monotonic() + 15
        connection.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        wanted = {str(uuid.UUID(item['history'])) for item in records_needed if item.get('history')}
        return {str(uuid.UUID(key)): {'category': category, 'job': job} for key, category, job in
                connection.execute('SELECT Id,Category,JobName FROM HistoryItems') if str(uuid.UUID(key)) in wanted}
    finally:
        connection.close()


def plex_sections(database, wanted):
    connection = sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=5)
    try:
        connection.execute('PRAGMA query_only=ON')
        deadline = time.monotonic() + 15
        connection.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        sections = [{'name': name, 'root': root} for name, root in connection.execute(
            'SELECT s.name,l.root_path FROM library_sections s LEFT JOIN section_locations l ON l.library_section_id=s.id ORDER BY s.id')]
        labels = {}
        for start in range(0, len(wanted), 100):
            batch = wanted[start:start + 100]
            for file, name in connection.execute(
                    'SELECT p.file,s.name FROM media_parts p JOIN media_items m ON m.id=p.media_item_id '
                    'JOIN metadata_items t ON t.id=m.metadata_item_id JOIN library_sections s ON s.id=t.library_section_id '
                    'WHERE p.file COLLATE BINARY IN (' + ','.join('?' for _ in batch) + ')', batch):
                labels.setdefault(file, []).append(name)
        return sections, labels
    finally:
        connection.close()


def provenance_report(snapshot, source, nas, original):
    missing = sorted(source.keys() - nas.keys())
    flora = local_videos(snapshot / 'data/flora-test-library')
    flora_ids = {value for name, target in flora.items()
                 if (value := reference_id(name, target, '/flora-test-library', source, flora)) is not None}
    wanted = {name: file_id(name, source[name]) for name in missing}
    histories = history_labels(snapshot / 'data/infinidysk-config/db.sqlite', [original.get(key, {}) for key in wanted.values()])
    plex_database = snapshot / 'data/plex-config/Library/Application Support/Plex Media Server/Plug-in Support/Databases/com.plexapp.plugins.library.db'
    if plex_database.is_symlink() or not plex_database.is_file():
        raise RuntimeError('The copied Plex database is unavailable for library identification.')
    sections, plex_labels = plex_sections(plex_database, ['/mnt/media/' + name for name in missing])
    print('COPIED PLEX LIBRARY SECTIONS: ' + json.dumps(sections, ensure_ascii=True), flush=True)
    results = []; hints = 0; flora_matches = 0; categories = {}; dav_roots = {}
    for name, key in wanted.items():
        record = original.get(key, {})
        history = histories.get(str(uuid.UUID(record['history'])), {}) if record.get('history') else {}
        sections_for_file = sorted(set(plex_labels.get('/mnt/media/' + name, [])))
        labels = [str(record.get('path') or ''), str(history.get('category') or '')] + sections_for_file
        test_hint = any(re.search(r'(?i)(?:^|[\W_])(test(?:ing)?|flora|trial|poc|experiment)(?:$|[\W_])', label) for label in labels)
        in_flora = key is not None and key in flora_ids
        hints += int(test_hint); flora_matches += int(in_flora)
        category = str(history.get('category') or '(unknown)')
        categories[category] = categories.get(category, 0) + 1
        root = str(Path(*Path(record['path']).parts[:3])) if record.get('path') else '(unknown)'
        dav_roots[root] = dav_roots.get(root, 0) + 1
        results.append({'libraryPath': name, 'sourceDavPath': record.get('path'),
                        'sourceCategory': history.get('category'), 'sourceJob': history.get('job'),
                        'plexSections': sections_for_file, 'referencedByFloraLinks': in_flora,
                        'possibleTestLabel': test_hint})
    print('READ-ONLY PROVENANCE SUMMARY: ' + json.dumps({'missingSourcePaths': len(missing),
        'possibleTestLabels': hints, 'matchingFloraLinkTargets': flora_matches,
        'floraVideoLinksInspected': len(flora), 'sourceCategories': categories, 'sourceDavRoots': dav_roots}, sort_keys=True), flush=True)
    for result in results: print(json.dumps(result, ensure_ascii=True), flush=True)
    print('Test labels and Flora references are clues only. No entries were restored, deleted or excluded.', flush=True)


def main():
    print('Checking local InfiniDysk file records and library provenance; no streaming-mount probes or service changes...', flush=True)
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in subprocess.check_output(
            ['ip', '-4', 'addr', 'show'], text=True, timeout=10):
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220.')
    if not SSD.is_mount():
        raise RuntimeError('The NAS appdata filesystem must be mounted.')
    if DATA.is_symlink() or (DATA / '.standby-refreshed.json').is_symlink():
        raise RuntimeError('An unexpected symbolic Plex preparation path was retained.')
    marker = json.loads((DATA / '.standby-refreshed.json').read_text())
    stamp = marker.get('sourceCreatedUtc')
    if marker.get('format') != 'Sawdoctor NAS Plex standby refresh v1' or not isinstance(stamp, str) or not re.fullmatch(r'\d{8}T\d{6}Z', stamp):
        raise RuntimeError('The completed Plex standby refresh is required.')
    snapshot = SNAPSHOTS / stamp
    if snapshot.is_symlink():
        raise RuntimeError('An unexpected symbolic standby snapshot was retained.')
    verified = json.loads((snapshot / '_VERIFIED.json').read_text())
    if (verified.get('format') != 'sawdoctor-migration-standby-v1'
            or verified.get('createdUtc') != stamp
            or verified.get('sha256') != marker.get('sourceArchiveSha256')):
        raise RuntimeError('The prepared Plex snapshot verification differs.')
    containers = json.loads(subprocess.check_output(
        ['docker', 'inspect', 'plex-nas', 'infinidysk-nas'], text=True, timeout=15))
    by_name = {item['Name']: item for item in containers}
    if by_name['/plex-nas']['State']['Running']:
        raise RuntimeError('Keep NAS Plex stopped during its preparation.')
    if not by_name['/infinidysk-nas']['State']['Running'] or not any(
            mount['Source'] == str(NAS_CONFIG) and mount['Destination'] == '/config'
            for mount in by_name['/infinidysk-nas']['Mounts']):
        raise RuntimeError('The NAS InfiniDysk configuration binding differs.')
    source_config = snapshot / 'data/infinidysk-config'
    original = records(source_config / 'db.sqlite')
    source_paths = paths(snapshot / 'data/library'); nas_paths = paths(LIBRARY)
    if globals().get('REPORT_PROVENANCE'):
        provenance_report(snapshot, source_paths, nas_paths, original)
        return
    current = records(NAS_CONFIG / 'db.sqlite')
    counts, findings = diagnose(source_paths, nas_paths, original, current, source_config)
    print('READ-ONLY CATALOGUE COMPARISON: ' + json.dumps(counts, sort_keys=True), flush=True)
    for status, name in findings:
        print(status + ' | ' + name, flush=True)
    print('Database presence is a catalogue check, not a video-playback test. Alternate episodes are candidates, not automatic replacements.', flush=True)
    print('No links, databases, application settings, containers or schedules were changed.', flush=True)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, sqlite3.Error, ValueError, KeyError, subprocess.SubprocessError):
        raise SystemExit('STOP: The local catalogue comparison could not complete; no application changes were made.') from None
