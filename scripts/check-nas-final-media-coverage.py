#!/usr/bin/env python3
"""Compare the latest received source library with NAS catalogue metadata."""
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import types
import urllib.request

APP_UUID = 'e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6'
BACKUP_UUID = '631e3391-6a42-4158-9aa4-f7718ba0e7e9'
APP = Path('/srv/dev-disk-by-uuid-' + APP_UUID)
BACKUP = Path('/srv/dev-disk-by-uuid-' + BACKUP_UUID)
BASE = BACKUP / 'migration/nightly-standby'
LIBRARY = APP / 'appdata/infinidysk-nas/library'
CONFIG = APP / 'appdata/infinidysk-nas/config'
PIN = '97ffcf7f7a573309cc25d2cb1e3a86d1aac4aa97'
HELPER_SHA = '768304c40c6744f841cf08e5a040dbc2108c5b78201a67d9127b7c9774d28e6d'


def safe(path):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise RuntimeError('An unexpected symbolic input path was retained.')


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise RuntimeError('A read-only NAS query failed; private details were withheld.')
    return result.stdout


def read(path, limit=8 * 1024**2):
    safe(path)
    if not path.is_file() or path.stat().st_size > limit:
        raise RuntimeError('A required source record is unavailable or exceeds its size bound.')
    return path.read_bytes()


def digest(path):
    safe(path)
    if not path.is_file() or path.stat().st_size > 2 * 1024**3:
        raise RuntimeError('A source metadata database exceeds the read-only review bound.')
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(4 * 1024**2), b''): value.update(block)
    return value.hexdigest()


def snapshot():
    record = json.loads(read(BASE / 'current.json'))
    stamp = record.get('createdUtc', '')
    if record.get('format') != 'sawdoctor-migration-standby-v1' or not re.fullmatch(r'\d{8}T\d{6}Z', stamp):
        raise RuntimeError('The current source snapshot identity differs.')
    folder = BASE / 'snapshots' / stamp; safe(folder)
    if record.get('snapshot') != str(folder) or json.loads(read(folder / '_VERIFIED.json')) != {k: v for k, v in record.items() if k != 'snapshot'}:
        raise RuntimeError('The current source locator/verification marker differs.')
    created = dt.datetime.strptime(stamp, '%Y%m%dT%H%M%SZ').replace(tzinfo=dt.timezone.utc)
    if not -dt.timedelta(minutes=5) <= dt.datetime.now(dt.timezone.utc) - created <= dt.timedelta(hours=36):
        raise RuntimeError('The latest received source snapshot is older than 36 hours or future-dated.')
    manifest_bytes = read(folder / 'manifest.json'); manifest = json.loads(manifest_bytes)
    if (manifest.get('sourceHost') != '192.168.0.29' or manifest.get('createdUtc') != stamp
            or manifest.get('format') != record['format'] or manifest.get('scope') != 'standby-only'):
        raise RuntimeError('The selected source snapshot manifest differs.')
    for name in ('library', 'infinidysk-config'):
        if manifest.get('dataRoots', {}).get(name, {}).get('snapshot') != 'data/' + name:
            raise RuntimeError('The required source catalogue/library roots differ.')
    wanted = {'manifest.json': hashlib.sha256(manifest_bytes).hexdigest(),
              'data/infinidysk-config/db.sqlite': digest(folder / 'data/infinidysk-config/db.sqlite')}
    wal = folder / 'data/infinidysk-config/db.sqlite-wal'
    if wal.exists(): wanted['data/infinidysk-config/db.sqlite-wal'] = digest(wal)
    checks = folder / 'SHA256SUMS'; safe(checks); seen = set()
    with checks.open('rb') as stream:
        for line in stream:
            if len(line) > 65536: raise RuntimeError('A source checksum entry exceeds the review bound.')
            match = re.fullmatch(rb'([a-f0-9]{64})  \./([^\r\n]+)\n?', line)
            if match:
                name = match[2].decode('utf-8')
                if name in wanted:
                    if name in seen or match[1].decode() != wanted[name]:
                        raise RuntimeError('A selected source metadata checksum differs.')
                    seen.add(name)
    if seen != set(wanted): raise RuntimeError('Selected source metadata checksums are unavailable.')
    return folder, record


def compare(helper, source_root, library, config):
    for root in (source_root, library):
        safe(root)
        for category in ('movies', 'movies-4k', 'tv'):
            safe(root / category)
            if not (root / category).is_dir(): raise RuntimeError('An expected local media category is unavailable.')
    source = helper.paths(source_root); nas = helper.paths(library)
    if not source or not nas or max(len(source), len(nas)) > 250000:
        raise RuntimeError('The source or NAS library is empty or outside the comparison bound.')
    current = helper.records(config / 'db.sqlite')
    unsupported = sum(helper.file_id(name, target) is None for name, target in source.items())
    ids = {key for name, target in source.items() if (key := helper.file_id(name, target)) is not None}
    missing = {key for key in ids if key not in current or current[key]['type'] != 2}
    no_blob = {key for key in ids - missing if not helper.blob_exists(config, current[key])}
    common = source.keys() & nas.keys()
    return {'sourceVideoPaths': len(source), 'nasVideoPaths': len(nas),
            'matchingLibraryPaths': sum(source[name] == nas[name] for name in common),
            'sourcePathsAbsentOnNas': len(source.keys() - nas.keys()),
            'nasOnlyPathsRetained': len(nas.keys() - source.keys()),
            'commonPathsWithDifferentTargets': sum(source[name] != nas[name] for name in common),
            'unsupportedSourceTargets': unsupported, 'sourceReferencedIds': len(ids),
            'sourceIdsMissingNasFileRecords': len(missing), 'sourceIdsMissingNasMetadataBlobs': len(no_blob)}


def main():
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the NAS, SSH port48223.')
    for path, uuid in ((APP, APP_UUID), (BACKUP, BACKUP_UUID)):
        safe(path)
        if not path.is_mount() or run('findmnt', '-rn', '--mountpoint', str(path), '-o', 'UUID,FSTYPE').split() != [uuid, 'ext4']:
            raise RuntimeError('An expected application/backup SSD identity differs.')
    rows = {r['Name']: r for r in json.loads(run('docker', 'inspect', 'plex-nas', 'infinidysk-nas'))}
    if rows['/plex-nas']['State']['Running']:
        raise RuntimeError('NAS Plex must remain stopped before the coordinated identity handover.')
    backend = rows['/infinidysk-nas']
    if not backend['State']['Running'] or not any(m.get('Source') == str(CONFIG) and m['Destination'] == '/config' for m in backend['Mounts']):
        raise RuntimeError('The current NAS InfiniDysk binding/state differs.')
    url = 'https://raw.githubusercontent.com/sawdoctor/nas-backup-auth/' + PIN + '/scripts/audit-nas-plex-catalogue.py'
    with urllib.request.urlopen(url, timeout=30) as response: data = response.read(128 * 1024 + 1)
    if hashlib.sha256(data).hexdigest() != HELPER_SHA:
        raise RuntimeError('The existing catalogue-comparison dependency failed integrity verification.')
    helper = types.ModuleType('_reviewed_plex_catalogue_audit')
    exec(compile(data, url, 'exec'), helper.__dict__)
    safe(BASE / '.run.lock')
    with (BASE / '.run.lock').open('rb') as lock:
        try: fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError: raise RuntimeError('The standby receiver is busy; retry this read-only comparison later.') from None
        folder, record = snapshot()
        counts = compare(helper, folder / 'data/library', LIBRARY, CONFIG)
        if json.loads(read(BASE / 'current.json')) != record:
            raise RuntimeError('The selected source snapshot changed during comparison.')
    print('LATEST SOURCE SNAPSHOT: ' + record['createdUtc'], flush=True)
    print('NAS MEDIA/CATALOGUE COVERAGE: ' + json.dumps(counts, sort_keys=True), flush=True)
    print('CURRENT NAS PLEX: ' + rows['/plex-nas']['State']['Status'] + '; restart=' + rows['/plex-nas']['HostConfig']['RestartPolicy']['Name'], flush=True)
    print('NAS HELPER SHA256 VALUES:', flush=True)
    for name in ('nas-plex-trial', 'nas-plex-prepare', 'nas-media-recovery', 'nas-backup'):
        path = Path('/usr/local/sbin') / name
        print(digest(path) + '  ' + str(path), flush=True)
    print('READ-ONLY NAS COVERAGE CHECK COMPLETE. No media payload read, link/database change, container stop or mount change.', flush=True)
    print('Coverage refers to the latest received snapshot; the final frozen source must be checked again before activation.', flush=True)


if __name__ == '__main__':
    try: main()
    except Exception as error:
        raise SystemExit('STOP: ' + (str(error) if isinstance(error, RuntimeError)
                                   else 'Read-only coverage check failed (' + type(error).__name__ + '); private details withheld.'))
