import contextlib
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'scripts'
if not SCRIPTS.is_dir(): SCRIPTS = ROOT / 'nas-backup-auth/scripts'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


s = load('final_media_coverage', 'check-nas-final-media-coverage.py')
helper = load('final_media_original_audit', 'audit-nas-plex-catalogue.py')


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source, self.nas, self.config = [self.root / name for name in ('source', 'nas', 'config')]
        for p in (self.source, self.nas):
            for category in ('movies', 'movies-4k', 'tv'): (p / category).mkdir(parents=True)
        self.config.mkdir(); self.ids = [str(uuid.uuid4()) for _ in range(5)]
        self.blobs = [str(uuid.uuid4()) for _ in range(5)]
        with contextlib.closing(sqlite3.connect(self.config / 'db.sqlite')) as db, db:
            db.execute('CREATE TABLE DavItems(Id,Type,FileSize,FileBlobId)')
            for i in (0, 1, 3, 4):
                db.execute('INSERT INTO DavItems VALUES(?,2,100,?)', (self.ids[i], self.blobs[i]))
                if i != 0:
                    blob = self.config / 'blobs' / self.blobs[i].replace('-', '')[:2] / self.blobs[i].replace('-', '')[2:4] / self.blobs[i]
                    blob.parent.mkdir(parents=True, exist_ok=True); blob.write_text('PRIVATE_METADATA')
        for root, relative, i in ((self.source, 'movies/common.mkv', 0), (self.source, 'movies/missing-link.mkv', 1),
                                  (self.source, 'tv/changed.mkv', 2), (self.nas, 'movies/common.mkv', 0),
                                  (self.nas, 'tv/changed.mkv', 3), (self.nas, 'movies/nas-only.mkv', 4)):
            target = '/mnt/nzbdav/.ids/' + '/'.join(self.ids[i][:5]) + '/' + self.ids[i]
            (root / relative).symlink_to(target)

    def test_counts_distinguish_missing_links_changed_targets_missing_records_and_blobs(self):
        database = (self.config / 'db.sqlite').read_bytes()
        original_links = {str(p): os.readlink(p) for root in (self.source, self.nas) for p in root.rglob('*.mkv')}
        result = s.compare(helper, self.source, self.nas, self.config)
        self.assertEqual(result, {'sourceVideoPaths': 3, 'nasVideoPaths': 3, 'matchingLibraryPaths': 1,
            'sourcePathsAbsentOnNas': 1, 'nasOnlyPathsRetained': 1, 'commonPathsWithDifferentTargets': 1,
            'unsupportedSourceTargets': 0, 'sourceReferencedIds': 3, 'sourceIdsMissingNasFileRecords': 1,
            'sourceIdsMissingNasMetadataBlobs': 1})
        self.assertEqual((self.config / 'db.sqlite').read_bytes(), database)
        self.assertEqual({str(p): os.readlink(p) for root in (self.source, self.nas) for p in root.rglob('*.mkv')}, original_links)

    def test_unsupported_target_is_reported_and_missing_categories_are_refused(self):
        (self.source / 'movies/unsupported.strm').symlink_to('/different/location')
        self.assertEqual(s.compare(helper, self.source, self.nas, self.config)['unsupportedSourceTargets'], 1)
        (self.source / 'movies-4k').rmdir()
        with self.assertRaisesRegex(RuntimeError, 'category'):
            s.compare(helper, self.source, self.nas, self.config)

    def make_snapshot(self, created=None):
        base = self.root / 'standby'; base.mkdir()
        stamp = (created or dt.datetime.now(dt.timezone.utc)).strftime('%Y%m%dT%H%M%SZ')
        folder = base / 'snapshots' / stamp; (folder / 'data/infinidysk-config').mkdir(parents=True)
        manifest = {'format': 'sawdoctor-migration-standby-v1', 'sourceHost': '192.168.0.29', 'scope': 'standby-only',
                    'createdUtc': stamp, 'dataRoots': {k: {'snapshot': 'data/' + k} for k in ('library', 'infinidysk-config')}}
        (folder / 'manifest.json').write_text(json.dumps(manifest))
        (folder / 'data/infinidysk-config/db.sqlite').write_bytes(b'PRIVATE_SOURCE_DATABASE')
        record = {'format': manifest['format'], 'createdUtc': stamp, 'sha256': '1' * 64, 'snapshot': str(folder)}
        (base / 'current.json').write_text(json.dumps(record))
        (folder / '_VERIFIED.json').write_text(json.dumps({k: v for k, v in record.items() if k != 'snapshot'}))
        with (folder / 'SHA256SUMS').open('w') as out:
            for name in ('manifest.json', 'data/infinidysk-config/db.sqlite'):
                out.write(hashlib.sha256((folder / name).read_bytes()).hexdigest() + '  ./' + name + '\n')
        return base, folder, record

    def test_latest_locator_and_selected_database_checksums_are_required(self):
        base, folder, record = self.make_snapshot()
        with patch.object(s, 'BASE', base):
            self.assertEqual(s.snapshot(), (folder, record))
            (folder / 'data/infinidysk-config/db.sqlite').write_bytes(b'CHANGED')
            with self.assertRaisesRegex(RuntimeError, 'checksum differs'):
                s.snapshot()

    def test_stale_snapshot_is_not_accepted_as_current_cutover_input(self):
        base, folder, record = self.make_snapshot(dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=4))
        with patch.object(s, 'BASE', base):
            with self.assertRaisesRegex(RuntimeError, 'older than 36 hours'):
                s.snapshot()


if __name__ == '__main__': unittest.main()
