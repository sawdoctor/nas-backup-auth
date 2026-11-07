import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/test-nas-backup-restore.py'
if not SCRIPT.is_file():
    SCRIPT = ROOT / 'nas-backup-auth/scripts/test-nas-backup-restore.py'
spec = importlib.util.spec_from_file_location('nas_restore_test', SCRIPT)
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


class RestoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ssd = self.root / 'ssd'
        self.sets = self.ssd / 'backups/sets'
        self.sets.mkdir(parents=True)
        self.data = self.root / 'source'
        self.data.mkdir()
        self.target = self.root / 'restored'
        self.target.mkdir()
        self.patches = contextlib.ExitStack()
        self.addCleanup(self.patches.close)
        self.patches.enter_context(patch.object(s, 'SSD', self.ssd))
        self.patches.enter_context(patch.object(s, 'SETS', self.sets))
        self.patches.enter_context(patch.object(s, 'WORK', self.ssd / 'backups/restore-check'))
        self.patches.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.db = self.data / s.DB
        self.db.parent.mkdir(parents=True)
        with contextlib.closing(sqlite3.connect(self.db)) as connection:
            connection.executescript('CREATE TABLE DavItems (id TEXT); INSERT INTO DavItems VALUES ("retained"); CREATE TABLE NzbNames (id TEXT);')
            connection.commit()
        self.config = self.data / sorted(s.CONFIGS)[-1]
        self.config.parent.mkdir(parents=True)
        self.config.write_text('services:\n  infinidysk:\n    image: example/exact:tag\n    container_name: infinidysk-nas\n')
        self.link = self.data / 'appdata/infinidysk-nas/library/movies/sample.mkv'
        self.link.parent.mkdir(parents=True)
        self.link.symlink_to('/mnt/nzbdav/.ids/never-read-video')
        self.backup = self.sets / 'nas-20261106T020010Z'
        self.backup.mkdir()
        self.archive = self.backup / 'applications.tar.zst'
        self.pack()

    def pack(self, extra=None):
        raw = self.root / 'fixture.tar'
        with tarfile.open(raw, 'w', dereference=False) as archive:
            archive.add(self.data / 'appdata', arcname='appdata')
            if extra is not None:
                archive.addfile(extra[0], io.BytesIO(extra[1]))
        subprocess.run(['zstd', '-q', '-f', str(raw), '-o', str(self.archive)], check=True)
        (self.backup / 'RESTORE.txt').write_bytes(b'recovery directions\n')
        (self.backup / 'backup-script').write_bytes(b'backup worker\n')
        lines = [hashlib.sha256((self.backup / name).read_bytes()).hexdigest() + '  ./' + name
                 for name in ('applications.tar.zst', 'RESTORE.txt', 'backup-script')]
        (self.backup / 'SHA256SUMS').write_text('\n'.join(lines) + '\n')
        (self.backup / '_COMPLETE').write_bytes(s.MARKER)
        (self.backup / '_UPLOADED').touch()

    def test_real_archive_restores_database_config_and_literal_link(self):
        before = self.db.read_bytes()
        config, wal = s.restore_samples(self.archive, self.target)
        self.assertFalse(wal)
        self.assertIn(config, s.CONFIGS)
        self.assertEqual(s.check_database(self.target / 'db.sqlite'), 1)
        s.check_compose(self.target / 'compose-sample')
        self.assertEqual((self.target / 'db.sqlite').read_bytes(), before)
        self.assertEqual((self.target / 'library-link').readlink(), self.link.readlink())
        self.assertEqual(self.db.read_bytes(), before)

    def test_wal_committed_rows_restored_and_stale_shm_not_copied(self):
        with contextlib.closing(sqlite3.connect(self.db)) as connection:
            connection.execute('PRAGMA journal_mode=WAL')
            connection.execute('INSERT INTO DavItems VALUES ("committed-only-in-wal")')
            connection.commit()
            self.assertTrue(Path(str(self.db) + '-wal').exists())
            self.pack()
            _config, wal = s.restore_samples(self.archive, self.target)
            self.assertTrue(wal)
            self.assertFalse((self.target / 'db.sqlite-shm').exists())
            self.assertEqual(s.check_database(self.target / 'db.sqlite'), 2)

    def test_gnu_tar_format_used_by_real_backup(self):
        subprocess.run(['tar', '--acls', '--xattrs', '--numeric-owner', '--sparse',
                        '--one-file-system', '-I', 'zstd -T2 -3', '-cpf', str(self.archive),
                        '-C', str(self.data), '--', 'appdata'], check=True)
        s.restore_samples(self.archive, self.target)
        self.assertEqual(s.check_database(self.target / 'db.sqlite'), 1)
        s.check_compose(self.target / 'compose-sample')

    def test_database_symlink_rejected(self):
        self.db.unlink()
        self.db.symlink_to('/outside/live/database')
        self.pack()
        with self.assertRaises(s.RestoreError):
            s.restore_samples(self.archive, self.target)
        self.assertFalse((self.target / 'db.sqlite').exists())

    def test_config_hardlink_rejected(self):
        self.config.unlink()
        header = tarfile.TarInfo(str(self.config.relative_to(self.data)))
        header.type = tarfile.LNKTYPE
        header.linkname = s.DB
        self.pack((header, b''))
        with self.assertRaises(s.RestoreError):
            s.restore_samples(self.archive, self.target)

    def test_oversized_database_stops_before_copy(self):
        with patch.object(s, 'MAX_DB', 1):
            with self.assertRaises(s.RestoreError):
                s.restore_samples(self.archive, self.target)
        self.assertFalse((self.target / 'db.sqlite').exists())

    def test_parent_traversal_and_duplicate_member_rejected(self):
        for name in ('../outside', s.DB):
            with self.subTest(name=name), tempfile.TemporaryDirectory(dir=self.root) as output:
                header = tarfile.TarInfo(name)
                header.size = 1
                self.pack((header, b'x'))
                with self.assertRaises(s.RestoreError):
                    s.restore_samples(self.archive, Path(output))
        self.assertFalse((self.root / 'outside').exists())

    def test_missing_catalogue_tables_and_corrupt_database_rejected(self):
        broken = self.root / 'broken.sqlite'
        broken.write_bytes(b'not a database')
        with self.assertRaises(sqlite3.DatabaseError):
            s.check_database(broken)
        broken.unlink()
        with contextlib.closing(sqlite3.connect(broken)) as connection:
            connection.execute('CREATE TABLE unrelated (id TEXT)')
            connection.commit()
        with self.assertRaises(s.RestoreError):
            s.check_database(broken)

    def test_compose_requires_nas_container_identity(self):
        path = self.root / 'bad-compose'
        path.write_text('services:\n  source:\n    image: original\n    container_name: nzbdav\n')
        with self.assertRaises(s.RestoreError):
            s.check_compose(path)

    def test_newest_requires_complete_uploaded_markers(self):
        newer = self.sets / 'nas-20261107T020010Z'
        newer.mkdir()
        (newer / '_COMPLETE').write_bytes(s.MARKER)
        self.assertEqual(s.newest_set(), self.backup)
        (newer / '_UPLOADED').touch()
        self.assertEqual(s.newest_set(), newer)

    def test_symlinked_backup_file_and_bad_marker_rejected(self):
        self.archive.unlink()
        self.archive.symlink_to(self.db)
        with self.assertRaises(s.RestoreError):
            s.regular(self.archive)
        (self.backup / '_COMPLETE').write_bytes(b'other job\n')
        with self.assertRaises(s.RestoreError):
            s.newest_set()

    def test_checksum_manifest_required_paths_and_duplicates(self):
        original = (self.backup / 'SHA256SUMS').read_bytes()
        self.assertIn('applications.tar.zst', s.sums(original))
        for invalid in (original + original.splitlines(keepends=True)[0],
                        original.replace(b'./applications.tar.zst', b'./../outside'),
                        original.replace(b'./applications.tar.zst', b'./missing')):
            with self.subTest(invalid=invalid), self.assertRaises(s.RestoreError):
                s.sums(invalid)

    def test_cloud_read_bounded_and_mismatches_fail(self):
        expected = b'expected bytes'
        with patch.object(s.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, expected, b'')) as run:
            s.cloud_read(self.backup, 'RESTORE.txt', expected)
            command = run.call_args.args[0]
            self.assertEqual(command[-2:], ['--head', str(len(expected) + 1)])
            self.assertEqual(command[command.index('cat') + 1], s.CLOUD + '/' + self.backup.name + '/RESTORE.txt')
        for result in (subprocess.CompletedProcess([], 0, b'different', b''),
                       subprocess.CompletedProcess([], 1, expected, b'error')):
            with patch.object(s.subprocess, 'run', return_value=result), self.assertRaises(s.RestoreError):
                s.cloud_read(self.backup, 'RESTORE.txt', expected)

    def test_complete_check_cleans_temporary_copies_and_preserves_backup(self):
        before = {path.name: path.read_bytes() for path in self.backup.iterdir()}
        with patch.object(s, 'cloud_read') as cloud:
            s.test_locked()
            self.assertEqual(cloud.call_count, 4)
        record = json.loads((s.WORK / 'result.json').read_text())
        self.assertEqual(record['phase'], 'complete')
        self.assertEqual(record['databaseRows'], 1)
        self.assertTrue(record['temporaryCopiesRemoved'])
        self.assertFalse(record['applicationsStarted'])
        self.assertFalse(list(self.sets.parent.glob('.nas-sample-restore-*')))
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.backup.iterdir()})

    def test_bad_archive_checksum_stops_before_cloud_or_restore(self):
        with self.archive.open('ab') as output:
            output.write(b'corrupted')
        with patch.object(s, 'cloud_read') as cloud, patch.object(s, 'restore_samples') as restore:
            with self.assertRaises(s.RestoreError):
                s.test_locked()
            cloud.assert_not_called()
            restore.assert_not_called()

    def test_failed_database_check_still_cleans_temporary_copy(self):
        with patch.object(s, 'cloud_read'), patch.object(s, 'check_database', side_effect=s.RestoreError('bad copied DB')):
            with self.assertRaises(s.RestoreError):
                s.test_locked()
        self.assertFalse(list(self.sets.parent.glob('.nas-sample-restore-*')))

    def test_guard_requires_mounted_backup_volume_and_known_nas(self):
        with patch.object(s.os, 'geteuid', return_value=0), \
                patch.object(s.subprocess, 'check_output', return_value='inet 192.168.0.220/24'), \
                patch.object(Path, 'is_mount', return_value=False), self.assertRaisesRegex(s.RestoreError, 'mounted FIKWOT'):
            s.guard()
        self.assertFalse(s.WORK.exists())

    def test_guard_rejects_other_uuid_or_filesystem_before_restore(self):
        for identity in ('other-uuid ext4', s.BACKUP_UUID + ' xfs'):
            with self.subTest(identity=identity), patch.object(s.os, 'geteuid', return_value=0), \
                    patch.object(Path, 'is_mount', return_value=True), \
                    patch.object(s.subprocess, 'check_output', side_effect=['inet 192.168.0.220/24', identity]), \
                    self.assertRaisesRegex(s.RestoreError, 'identity differs'):
                s.guard()
        self.assertFalse(s.WORK.exists())

    def test_guard_accepts_exact_mounted_fikwot_ext4_volume(self):
        with patch.object(s.os, 'geteuid', return_value=0), patch.object(Path, 'is_mount', return_value=True), \
                patch.object(s.shutil, 'which', return_value='/usr/bin/existing-program'), \
                patch.object(s.subprocess, 'check_output', side_effect=[
                    'inet 192.168.0.220/24', s.BACKUP_UUID + ' ext4\n']):
            s.guard()


if __name__ == '__main__':
    unittest.main()
