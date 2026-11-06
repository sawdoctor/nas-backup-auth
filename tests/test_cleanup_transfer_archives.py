import contextlib
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/cleanup-nas-transfer-archives.py'
if not SCRIPT.is_file():
    SCRIPT = ROOT / 'nas-backup-auth/scripts/cleanup-nas-transfer-archives.py'
spec = importlib.util.spec_from_file_location('cleanup_transfers', SCRIPT)
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ssd = self.root / 'ssd'
        self.ssd.mkdir()
        self.patches = contextlib.ExitStack()
        self.addCleanup(self.patches.close)
        self.patches.enter_context(patch.object(s, 'SSD', self.ssd))
        self.patches.enter_context(contextlib.redirect_stdout(io.StringIO()))
        for name, format_name in s.BUNDLES.items():
            self.bundle(name, format_name)
        for name in ('appdata/plex-nas/live.db', 'backups/sets/current/archive.tar',
                     'compose/plex-nas/recovery/trial/receipt',
                     'migration/nightly-standby/snapshot/data',
                     'migration/infinidysk-optiplex/export.tar.zst'):
            path = self.ssd / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'keep this independent data')

    def bundle(self, name, format_name):
        stage = self.ssd / 'migration' / name
        stage.mkdir(parents=True)
        source = self.root / name
        source.mkdir()
        (source / 'manifest.json').write_text(json.dumps({
            'format': format_name, 'sourceHost': '192.168.0.29', 'createdUtc': '20261103T000000Z'}))
        (source / 'config').mkdir()
        (source / 'config/custom-script.py').write_bytes(b'custom code must survive\n')
        (source / 'config/db.sqlite').write_bytes(b'fixture database\n')
        (source / 'images.tar').write_bytes(b'exact images fixture\n')
        (source / 'media-link.mkv').symlink_to('/mnt/nzbdav/.ids/do-not-dereference')
        if name == 'books-optiplex':
            for relative in s.BOOKS_SHM_TIMESTAMPS:
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'unchanged shared-memory bytes\n')
        sums = []
        for path in sorted(source.rglob('*')):
            if path.is_file() and not path.is_symlink():
                sums.append(hashlib.sha256(path.read_bytes()).hexdigest() + '  ./' + str(path.relative_to(source)))
        (source / 'SHA256SUMS').write_text('\n'.join(sums) + '\n')
        archive = stage / 'export.tar.zst'
        subprocess.run(['tar', '--acls', '--xattrs', '--numeric-owner', '--sparse',
                        '-I', 'zstd', '-cpf', str(archive), '-C', str(source), '.'], check=True)
        snapshot = stage / 'snapshot'
        snapshot.mkdir()
        subprocess.run(['tar', '--acls', '--xattrs', '--numeric-owner', '-I', 'zstd',
                        '-xpf', str(archive), '-C', str(snapshot)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (stage / 'staged.json').write_text(json.dumps({
            'archiveSha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
            'createdUtc': '20261103T000000Z'}))

    def state(self):
        return {str(p.relative_to(self.ssd)): ('link', p.readlink()) if p.is_symlink()
                else ('file', hashlib.sha256(p.read_bytes()).hexdigest())
                for p in self.ssd.rglob('*') if p.is_symlink() or p.is_file()}

    def assert_all_archives_retained(self):
        for name in s.BUNDLES:
            self.assertTrue((self.ssd / 'migration' / name / 'export.tar.zst').is_file())

    def test_real_cleanup_removes_only_four_archives_and_keeps_contents_links_and_images(self):
        before = self.state()
        archives = {'migration/' + name + '/export.tar.zst' for name in s.BUNDLES}
        s.cleanup_locked()
        after = self.state()
        self.assertEqual(set(before) - set(after), archives)
        self.assertTrue(all(after[name] == value for name, value in before.items() if name not in archives))
        record = json.loads((self.ssd / 'migration/transfer-archive-cleanup/record.json').read_text())
        self.assertEqual(record['phase'], 'complete')
        self.assertEqual(len(record['items']), 4)
        self.assertTrue(all(item['status'] == 'removed' for item in record['items']))

    def test_changed_last_snapshot_aborts_before_deleting_any_earlier_archive(self):
        (self.ssd / 'migration/plex-npm-optiplex/snapshot/config/db.sqlite').write_text('changed')
        with self.assertRaisesRegex(RuntimeError, 'comparison failed'):
            s.cleanup_locked()
        self.assert_all_archives_retained()

    def test_changed_symlink_target_aborts_even_though_regular_checksums_match(self):
        link = self.ssd / 'migration/books-optiplex/snapshot/media-link.mkv'
        link.unlink()
        link.symlink_to('/mnt/nzbdav/.ids/different')
        with self.assertRaisesRegex(RuntimeError, 'comparison failed'):
            s.cleanup_locked()
        self.assert_all_archives_retained()

    def test_corrupt_archive_is_retained(self):
        archive = self.ssd / 'migration/core-optiplex/export.tar.zst'
        archive.write_bytes(archive.read_bytes() + b'damage')
        with self.assertRaisesRegex(RuntimeError, 'checksum differs'):
            s.cleanup_locked()
        self.assert_all_archives_retained()

    def test_file_replaced_with_external_symlink_is_rejected_without_reading_target(self):
        path = self.ssd / 'migration/core-optiplex/snapshot/config/db.sqlite'
        path.unlink()
        path.symlink_to('/dev/zero')
        with self.assertRaisesRegex(RuntimeError, 'symbolic'):
            s.cleanup_locked()
        self.assert_all_archives_retained()

    def test_changed_metadata_is_not_discarded(self):
        path = self.ssd / 'migration/support-optiplex/snapshot/config/custom-script.py'
        path.chmod(0o700)
        with self.assertRaisesRegex(RuntimeError, 'comparison failed'):
            s.cleanup_locked()
        self.assert_all_archives_retained()

    def test_wrong_saved_identity_is_retained(self):
        path = self.ssd / 'migration/core-optiplex/staged.json'
        value = json.loads(path.read_text())
        value['createdUtc'] = 'unrelated'
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(RuntimeError, 'identity differs'):
            s.cleanup_locked()
        self.assert_all_archives_retained()

    def test_unsafe_checksum_path_is_rejected(self):
        path = self.ssd / 'migration/core-optiplex/snapshot/SHA256SUMS'
        path.write_text('0' * 64 + '  ../../outside\n')
        with self.assertRaisesRegex(RuntimeError, 'unsafe checksum'):
            s.cleanup_locked()
        self.assert_all_archives_retained()

    def test_busy_transfer_prevents_deletion(self):
        lock = self.ssd / 'migration/support-optiplex/.copy.lock'
        with lock.open('a') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(RuntimeError, 'active'):
                s.cleanup_locked()
        self.assert_all_archives_retained()

    def test_archive_replaced_after_verification_is_retained(self):
        original = s.verify_bundle
        def changed(stage, expected_format, error_path):
            result = original(stage, expected_format, error_path)
            if stage.name == 'plex-npm-optiplex':
                target = self.ssd / 'migration/core-optiplex/export.tar.zst'
                target.write_bytes(target.read_bytes() + b'changed after validation')
            return result
        with patch.object(s, 'verify_bundle', side_effect=changed):
            with self.assertRaisesRegex(RuntimeError, 'changed before cleanup'):
                s.cleanup_locked()
        self.assert_all_archives_retained()

    def test_wrong_host_guard_cannot_start_cleanup(self):
        with patch.object(s.os, 'geteuid', return_value=0), patch.object(
                s.subprocess, 'check_output', return_value='inet 192.168.0.29/24'):
            with self.assertRaisesRegex(RuntimeError, 'only on the NAS'):
                s.guard()
        self.assert_all_archives_retained()

    def test_repeating_completed_cleanup_keeps_the_original_record_and_all_remaining_data(self):
        s.cleanup_locked()
        before = self.state()
        s.cleanup_locked()
        self.assertEqual(self.state(), before)

    def change_mtime(self, path):
        value = path.stat()
        os.utime(path, ns=(value.st_atime_ns, value.st_mtime_ns + 5_000_000_000))

    def test_exact_seven_shm_timestamp_differences_allow_cleanup_without_changing_any_saved_file(self):
        for relative in s.BOOKS_SHM_TIMESTAMPS:
            self.change_mtime(self.ssd / 'migration/books-optiplex/snapshot' / relative)
        before = self.state()
        s.cleanup_locked()
        after = self.state()
        for name, value in before.items():
            if not name.endswith('/export.tar.zst') or 'infinidysk-optiplex' in name:
                self.assertEqual(after[name], value)
        record = json.loads((self.ssd / 'migration/transfer-archive-cleanup/record.json').read_text())
        books = next(item for item in record['items'] if item['archive'].endswith('books-optiplex/export.tar.zst'))
        self.assertEqual(set(books['acceptedShmTimestampPaths']), s.BOOKS_SHM_TIMESTAMPS)

    def test_reviewed_shm_timestamp_difference_does_not_hide_content_changes(self):
        path = self.ssd / 'migration/books-optiplex/snapshot' / sorted(s.BOOKS_SHM_TIMESTAMPS)[0]
        path.write_bytes(b'different shared-memory bytes')
        self.change_mtime(path)
        with self.assertRaisesRegex(RuntimeError, 'comparison failed'):
            s.cleanup_locked()
        self.assert_all_archives_retained()

    def test_reviewed_shm_timestamp_difference_does_not_hide_mode_changes(self):
        path = self.ssd / 'migration/books-optiplex/snapshot' / sorted(s.BOOKS_SHM_TIMESTAMPS)[0]
        self.change_mtime(path)
        path.chmod(0o700)
        with self.assertRaisesRegex(RuntimeError, 'comparison failed'):
            s.cleanup_locked()
        self.assert_all_archives_retained()

    def test_timestamp_exception_does_not_cover_database_file_mtime(self):
        shm = self.ssd / 'migration/books-optiplex/snapshot' / sorted(s.BOOKS_SHM_TIMESTAMPS)[0]
        self.change_mtime(shm)
        self.change_mtime(self.ssd / 'migration/books-optiplex/snapshot/config/db.sqlite')
        with self.assertRaisesRegex(RuntimeError, 'comparison failed'):
            s.cleanup_locked()
        self.assert_all_archives_retained()

    def test_matching_diagnostic_with_tar_error_status_two_is_rejected(self):
        audit = self.ssd / 'error.log'
        relative = sorted(s.BOOKS_SHM_TIMESTAMPS)[0]
        def failed(command, **kwargs):
            kwargs['stdout'].write(('./' + relative + ': Mod time differs\n').encode())
            return subprocess.CompletedProcess(command, 2)
        with patch.object(s.subprocess, 'run', side_effect=failed):
            with self.assertRaisesRegex(RuntimeError, 'comparison failed'):
                s.checked(['tar', '--compare'], self.ssd, audit, {relative})

    def test_timestamp_exception_is_not_used_for_files_missing_from_checksum_manifest(self):
        path = self.ssd / 'migration/books-optiplex/snapshot' / sorted(s.BOOKS_SHM_TIMESTAMPS)[0]
        self.change_mtime(path)
        original = s.verify_checksums_paths
        def uncovered(snapshot, checksums):
            return original(snapshot, checksums) - s.BOOKS_SHM_TIMESTAMPS
        with patch.object(s, 'verify_checksums_paths', side_effect=uncovered):
            with self.assertRaisesRegex(RuntimeError, 'comparison failed'):
                s.cleanup_locked()
        self.assert_all_archives_retained()


if __name__ == '__main__':
    unittest.main()
