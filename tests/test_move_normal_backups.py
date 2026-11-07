import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/move-nas-backups-to-ssd.py'
if not SCRIPT.is_file():
    SCRIPT = ROOT / 'nas-backup-auth/scripts/move-nas-backups-to-ssd.py'
spec = importlib.util.spec_from_file_location('normal_backup_move', SCRIPT)
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


class TransferTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.old = self.root / 'old'
        self.new = self.root / 'new'
        self.source = self.old / 'backups'
        self.target = self.new / 'backups'
        self.source.mkdir(parents=True)
        self.target.mkdir(parents=True)
        self.work = self.root / 'state'
        self.stage = self.new / '.staging'
        self.retry = self.root / 'retry'
        self.backup = self.root / 'backup'
        self.backup.write_bytes(b'unchanged normal backup worker')
        self.patches = contextlib.ExitStack()
        self.addCleanup(self.patches.close)
        self.patches.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.patches.enter_context(patch.multiple(s, OLD_VOLUME=self.old, NEW_VOLUME=self.new,
                                                SOURCE=self.source, TARGET=self.target, STAGING=self.stage,
                                                WORK=self.work, RETRY=self.retry, BACKUP=self.backup,
                                                BACKUP_SHA=s.sha(self.backup.read_bytes())))
        self.set = self.source / 'sets/nas-20261106T020010Z'
        (self.set / 'omv').mkdir(parents=True)
        (self.source / 'omvbackup').mkdir()
        for name, content in [('applications.tar.zst', b'archive payload'),
                              ('RESTORE.txt', b'recovery instructions'), ('backup-script', b'worker')]:
            (self.set / name).write_bytes(content)
        os.setxattr(self.set / 'RESTORE.txt', 'user.backup-test', b'preserved')
        os_file = self.source / 'omvbackup/backup-omv-test.fsa'
        os_file.write_bytes(b'OS image archive')
        os.link(os_file, self.set / 'omv/backup-omv-test.fsa')
        (self.source / 'literal-link').symlink_to('/mnt/nzbdav/.ids/never-read-video')
        (self.set / '_COMPLETE').write_bytes(s.MARKER)
        (self.set / '_UPLOADED').touch()
        self.sums()

    def sums(self):
        names = sorted(str(path.relative_to(self.set)) for path in self.set.rglob('*')
                       if path.is_file() and path.name not in {'SHA256SUMS', '_COMPLETE', '_UPLOADED'})
        (self.set / 'SHA256SUMS').write_text(''.join(
            s.sha((self.set / name).read_bytes()) + '  ./' + name + '\n' for name in names))

    def fixture_preflight(self):
        path = self.work / 'result.json'
        return (json.loads(path.read_text()) if path.is_file() else None), None

    def transfer(self):
        usage = shutil.disk_usage(self.new)
        usage = type(usage)(total=1024**4, used=0, free=1024**4)
        with patch.object(s, 'preflight', side_effect=self.fixture_preflight), \
                patch.object(s, 'destination'), patch.object(s.os, 'chown'), \
                patch.object(s.shutil, 'disk_usage', return_value=usage):
            s.transfer_locked()

    def test_real_copy_verifies_hardlinks_xattrs_and_literal_links_before_freeing_old_data(self):
        before = s.tree(self.source)
        root_mode = stat.S_IMODE(self.target.stat().st_mode)
        self.transfer()
        self.assertEqual(list(self.source.iterdir()), [])
        self.assertTrue(self.source.is_dir())
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), root_mode)
        after = s.tree(self.target)
        s.verify_copy(before, after)
        self.assertEqual((self.target / 'literal-link').readlink(), Path('/mnt/nzbdav/.ids/never-read-video'))
        self.assertEqual((self.target / 'omvbackup/backup-omv-test.fsa').stat().st_ino,
                         (self.target / 'sets/nas-20261106T020010Z/omv/backup-omv-test.fsa').stat().st_ino)
        self.assertEqual(os.getxattr(self.target / 'sets/nas-20261106T020010Z/RESTORE.txt', 'user.backup-test'), b'preserved')
        result = json.loads((self.work / 'result.json').read_text())
        self.assertEqual(result['phase'], 'complete')
        self.assertFalse(result['applicationServicesChanged'])
        self.assertFalse(result['standbySnapshotsMoved'])
        self.assertFalse(result['cloudSettingsChanged'])
        self.assertFalse(self.stage.exists())

    def test_retry_after_completion_keeps_destination_and_does_no_second_copy(self):
        self.transfer()
        with patch.object(s, 'copy_payload', side_effect=AssertionError('no extra copy')):
            self.transfer()
        self.assertTrue((self.target / 'sets/nas-20261106T020010Z/applications.tar.zst').is_file())

    def test_plugin_created_empty_directories_are_allowed_and_preserved(self):
        (self.target / 'omvbackup/empty').mkdir(parents=True)
        self.transfer()
        self.assertTrue((self.target / 'omvbackup/backup-omv-test.fsa').is_file())
        self.assertTrue((self.target / 'omvbackup/empty').is_dir())

    def test_failed_destination_flush_retains_original_payload(self):
        original_run = s.run
        def fail_sync(*args, **kwargs):
            if args[:2] == ('sync', '-f'):
                raise RuntimeError('simulated flush failure')
            return original_run(*args, **kwargs)
        with patch.object(s, 'run', side_effect=fail_sync), self.assertRaisesRegex(RuntimeError, 'flush failure'):
            self.transfer()
        self.assertTrue((self.set / 'applications.tar.zst').is_file())
        self.assertTrue((self.target / 'sets/nas-20261106T020010Z/applications.tar.zst').is_file())

    def test_retry_recovers_interruption_immediately_after_merge(self):
        original_record = s.record
        def interrupted(phase, **extra):
            if phase == 'merged':
                raise RuntimeError('simulated interruption after merge')
            original_record(phase, **extra)
        with patch.object(s, 'record', side_effect=interrupted), self.assertRaisesRegex(RuntimeError, 'simulated interruption'):
            self.transfer()
        self.assertTrue((self.set / 'applications.tar.zst').exists())
        self.assertEqual(json.loads((self.work / 'result.json').read_text())['phase'], 'merging')
        with patch.object(s, 'copy_payload', side_effect=AssertionError('activated data must not be copied again')):
            self.transfer()
        self.assertEqual(list(self.source.iterdir()), [])
        self.assertFalse(self.stage.exists())

    def test_retry_recovers_interrupted_old_payload_removal(self):
        original_remove = shutil.rmtree
        stopped = False
        def interrupted(path, *args, **kwargs):
            nonlocal stopped
            result = original_remove(path, *args, **kwargs)
            if Path(path).is_relative_to(self.source) and not stopped:
                stopped = True
                raise RuntimeError('simulated cleanup interruption')
            return result
        with patch.object(s.shutil, 'rmtree', side_effect=interrupted), self.assertRaisesRegex(RuntimeError, 'cleanup interruption'):
            self.transfer()
        self.assertEqual(json.loads((self.work / 'result.json').read_text())['phase'], 'removing-old-payload')
        with patch.object(s, 'copy_payload', side_effect=AssertionError('no extra copy')):
            self.transfer()
        self.assertEqual(list(self.source.iterdir()), [])

    def test_real_copy_preserves_posix_acl(self):
        path = self.set / 'RESTORE.txt'
        entries = [(1, 6, 0xffffffff), (2, 4, os.getuid()),
                   (4, 0, 0xffffffff), (16, 4, 0xffffffff), (32, 0, 0xffffffff)]
        acl = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *row) for row in entries)
        try:
            os.setxattr(path, 'system.posix_acl_access', acl)
        except OSError as error:
            if error.errno in (95, 45):
                self.skipTest('The local test filesystem does not support POSIX ACLs.')
            raise
        self.transfer()
        copied = self.target / 'sets/nas-20261106T020010Z/RESTORE.txt'
        self.assertEqual(os.getxattr(copied, 'system.posix_acl_access'), acl)

    def test_copy_corruption_retains_every_original_file(self):
        original_copy = s.copy_payload
        before = s.tree(self.source)
        def corrupt():
            payload = original_copy()
            (payload / 'sets/nas-20261106T020010Z/applications.tar.zst').write_bytes(b'corrupt')
            return payload
        with patch.object(s, 'copy_payload', side_effect=corrupt), self.assertRaisesRegex(RuntimeError, 'differ'):
            self.transfer()
        self.assertEqual(s.comparable(before), s.comparable(s.tree(self.source)))
        self.assertEqual(list(self.target.iterdir()), [])

    def test_source_mutation_during_copy_retains_the_changed_source(self):
        original_copy = s.copy_payload
        def mutate():
            payload = original_copy()
            (self.source / 'new-unexpected-file').write_bytes(b'keep this')
            return payload
        with patch.object(s, 'copy_payload', side_effect=mutate), self.assertRaisesRegex(RuntimeError, 'changed during'):
            self.transfer()
        self.assertTrue((self.source / 'new-unexpected-file').is_file())
        self.assertTrue((self.set / 'applications.tar.zst').is_file())

    def test_destination_collision_after_copy_retains_both_originals(self):
        original_copy = s.copy_payload
        def collide():
            payload = original_copy()
            (self.target / 'keep-existing').write_text('different destination data')
            return payload
        with patch.object(s, 'copy_payload', side_effect=collide), self.assertRaisesRegex(RuntimeError, 'destination changed'):
            self.transfer()
        self.assertEqual((self.target / 'keep-existing').read_text(), 'different destination data')
        self.assertTrue((self.set / 'applications.tar.zst').is_file())

    def target_fixture(self):
        folder = self.target / 'sets/nas-20261107T020009Z'
        (folder / 'omv').mkdir(parents=True)
        (self.target / 'omvbackup').mkdir(exist_ok=True)
        for name, value in [('applications.tar.zst', b'new application archive'),
                            ('RESTORE.txt', b'new restore notes'), ('backup-script', b'current worker')]:
            (folder / name).write_bytes(value)
        os_file = self.target / 'omvbackup/backup-omv-new.fsa'
        os_file.write_bytes(b'new OS image')
        os.link(os_file, folder / 'omv/backup-omv-new.fsa')
        for name in ('RESTORE-README.txt', 'omv-restore-helper'):
            (self.source / 'omvbackup' / name).write_bytes(b'old ' + name.encode())
            (self.set / 'omv' / name).write_bytes(b'old ' + name.encode())
            (self.target / 'omvbackup' / name).write_bytes(b'new ' + name.encode())
            (folder / 'omv' / name).write_bytes(b'new ' + name.encode())
        self.sums()
        names = sorted(str(path.relative_to(folder)) for path in folder.rglob('*') if path.is_file())
        (folder / 'SHA256SUMS').write_text(''.join(
            s.sha((folder / name).read_bytes()) + '  ./' + name + '\n' for name in names))
        (folder / '_COMPLETE').write_bytes(s.MARKER)
        (folder / '_UPLOADED').touch()
        return folder

    def test_nonempty_destination_preserves_new_set_guides_metadata_and_both_hardlink_groups(self):
        newest = self.target_fixture()
        original, existing = s.tree(self.source), s.tree(self.target)
        expected = s.merge_plan(original, existing)
        self.transfer()
        merged = s.tree(self.target)
        s.verify_merged(original, existing, expected, merged)
        self.assertEqual(s.verify_backup_sets(self.target, merged), 2)
        self.assertEqual(list(self.source.iterdir()), [])
        self.assertEqual((self.target / 'omvbackup/RESTORE-README.txt').read_bytes(), b'new RESTORE-README.txt')
        self.assertEqual((newest / 'applications.tar.zst').read_bytes(), b'new application archive')
        self.assertEqual((self.target / 'omvbackup/backup-omv-new.fsa').stat().st_ino,
                         (newest / 'omv/backup-omv-new.fsa').stat().st_ino)
        self.assertEqual((self.target / 'omvbackup/backup-omv-test.fsa').stat().st_ino,
                         (self.target / 'sets' / self.set.name / 'omv/backup-omv-test.fsa').stat().st_ino)
        self.assertFalse(self.stage.exists())

    def test_existing_filename_collision_stops_before_copy(self):
        self.target_fixture()
        (self.target / 'literal-link').write_bytes(b'keep destination data')
        with patch.object(s, 'copy_payload') as copy, self.assertRaisesRegex(RuntimeError, 'filename collision'):
            self.transfer()
        copy.assert_not_called()
        self.assertEqual((self.target / 'literal-link').read_bytes(), b'keep destination data')
        self.assertTrue((self.set / 'applications.tar.zst').is_file())
        self.assertFalse(self.work.exists())

    def test_old_guide_without_retained_checksummed_version_is_not_discarded(self):
        self.target_fixture()
        (self.source / 'omvbackup/RESTORE-README.txt').write_bytes(b'unarchived old notes')
        with self.assertRaisesRegex(RuntimeError, 'filename collision'):
            self.transfer()
        self.assertFalse(self.work.exists())

    def test_new_guide_without_matching_new_set_is_preserved_and_stops_merge(self):
        self.target_fixture()
        (self.target / 'omvbackup/RESTORE-README.txt').write_bytes(b'unarchived new notes')
        with self.assertRaisesRegex(RuntimeError, 'filename collision'):
            self.transfer()
        self.assertEqual((self.target / 'omvbackup/RESTORE-README.txt').read_bytes(), b'unarchived new notes')

    def test_existing_backup_corruption_stops_before_copy(self):
        newest = self.target_fixture()
        (newest / 'applications.tar.zst').write_bytes(b'corrupted destination archive')
        with patch.object(s, 'copy_payload') as copy, self.assertRaisesRegex(RuntimeError, 'original SHA256'):
            self.transfer()
        copy.assert_not_called()
        self.assertTrue((self.set / 'applications.tar.zst').is_file())

    def test_existing_destination_mutation_during_copy_is_retained(self):
        newest = self.target_fixture()
        original_copy = s.copy_payload
        def mutate():
            payload = original_copy()
            (newest / 'RESTORE.txt').write_bytes(b'changed destination notes')
            return payload
        with patch.object(s, 'copy_payload', side_effect=mutate), self.assertRaisesRegex(RuntimeError, 'destination changed'):
            self.transfer()
        self.assertEqual((newest / 'RESTORE.txt').read_bytes(), b'changed destination notes')
        self.assertTrue((self.set / 'applications.tar.zst').is_file())

    def test_exclusive_link_never_overwrites_concurrent_destination_file(self):
        original_link = os.link
        def collide(src, dst, **kwargs):
            if str(dst).endswith('applications.tar.zst'):
                Path(dst).write_bytes(b'concurrent file')
            return original_link(src, dst, **kwargs)
        with patch.object(s.os, 'link', side_effect=collide), self.assertRaises(FileExistsError):
            self.transfer()
        self.assertEqual((self.target / 'sets' / self.set.name / 'applications.tar.zst').read_bytes(), b'concurrent file')
        self.assertTrue((self.set / 'applications.tar.zst').is_file())

    def test_resume_after_exclusive_link_before_staging_unlink(self):
        self.target_fixture()
        original_link = os.link
        interrupted = False
        def interrupt(src, dst, **kwargs):
            nonlocal interrupted
            result = original_link(src, dst, **kwargs)
            if not interrupted:
                interrupted = True
                raise RuntimeError('interrupted after exclusive link')
            return result
        with patch.object(s.os, 'link', side_effect=interrupt), self.assertRaisesRegex(RuntimeError, 'after exclusive link'):
            self.transfer()
        self.assertEqual(json.loads((self.work / 'result.json').read_text())['phase'], 'merging')
        self.transfer()
        self.assertEqual(list(self.source.iterdir()), [])
        self.assertEqual(s.verify_backup_sets(self.target, s.tree(self.target)), 2)

    def test_merged_data_changed_before_resume_retains_old_source(self):
        original_record = s.record
        def interrupt(phase, **extra):
            if phase == 'merged':
                raise RuntimeError('interrupted merge')
            original_record(phase, **extra)
        with patch.object(s, 'record', side_effect=interrupt), self.assertRaisesRegex(RuntimeError, 'interrupted merge'):
            self.transfer()
        (self.target / 'sets' / self.set.name / 'applications.tar.zst').write_bytes(b'changed merged file')
        with self.assertRaisesRegex(RuntimeError, 'Merged original'):
            self.transfer()
        self.assertTrue((self.set / 'applications.tar.zst').is_file())

    def test_unlisted_file_inside_completed_set_is_rejected(self):
        (self.set / 'unlisted').write_bytes(b'not covered by checksums')
        with self.assertRaisesRegex(RuntimeError, 'outside its original checksum'):
            self.transfer()

    def test_full_metadata_check_detects_broken_hardlinks(self):
        expected = s.tree(self.source)
        copied = json.loads(json.dumps(expected))
        key = 'sets/nas-20261106T020010Z/omv/backup-omv-test.fsa'
        copied[key]['group'] = key
        with self.assertRaisesRegex(RuntimeError, 'hard-link'):
            s.verify_copy(expected, copied)

    def test_acl_xattr_difference_is_rejected(self):
        expected = s.tree(self.source)
        copied = json.loads(json.dumps(expected))
        expected['sets/nas-20261106T020010Z/RESTORE.txt']['xattrs']['system.posix_acl_access'] = '02000000'
        with self.assertRaisesRegex(RuntimeError, 'metadata'):
            s.verify_copy(expected, copied)

    def test_original_checksum_mismatch_is_rejected_before_copy(self):
        (self.set / 'applications.tar.zst').write_bytes(b'changed after original backup')
        with patch.object(s, 'copy_payload') as copy, self.assertRaisesRegex(RuntimeError, 'original SHA256'):
            self.transfer()
        copy.assert_not_called()
        self.assertFalse(self.work.exists())

    def test_external_marker_link_is_rejected_without_reading_its_target(self):
        path = self.set / '_COMPLETE'
        path.unlink()
        path.symlink_to('/must-never-be-opened')
        with self.assertRaisesRegex(RuntimeError, 'completion record'):
            s.verify_backup_sets(self.source, s.tree(self.source))

    def test_unsafe_checksum_member_is_rejected(self):
        (self.set / 'SHA256SUMS').write_text('0' * 64 + '  ./../escape\n')
        with self.assertRaisesRegex(RuntimeError, 'unsafe'):
            s.verify_backup_sets(self.source, s.tree(self.source))

    def test_special_files_are_rejected_without_copying(self):
        os.mkfifo(self.source / 'fifo')
        with self.assertRaisesRegex(RuntimeError, 'special'):
            s.tree(self.source)

    def test_remaining_cleanup_allows_own_partial_removal_but_rejects_new_or_changed_files(self):
        original = s.tree(self.source)
        (self.set / 'omv/backup-omv-test.fsa').unlink()
        s.verify_remaining_source(original, s.tree(self.source))
        (self.source / 'new').write_bytes(b'new')
        with self.assertRaisesRegex(RuntimeError, 'New files'):
            s.verify_remaining_source(original, s.tree(self.source))
        (self.source / 'new').unlink()
        (self.set / 'RESTORE.txt').write_bytes(b'new content')
        with self.assertRaisesRegex(RuntimeError, 'changed before cleanup'):
            s.verify_remaining_source(original, s.tree(self.source))

    def test_exact_upload_helper_patch_and_retry_are_preserved(self):
        data = b'#!/bin/bash\n' + s.RETRY_ANCHOR + b'unchanged upload settings\n'
        changed = data.replace(s.RETRY_ANCHOR, s.RETRY_NEW)
        with patch.multiple(s, RETRY_BEFORE_SHA=s.sha(data), RETRY_AFTER_SHA=s.sha(changed)):
            self.assertEqual(s.retry_patch(data), changed)
            self.assertEqual(s.retry_patch(changed), changed)
            with self.assertRaises(RuntimeError):
                s.retry_patch(data + b'unreviewed mutation')

    def test_new_upload_helper_gets_one_small_original_copy(self):
        self.work.mkdir()
        old = b'old reviewed retry helper'
        new = b'new reviewed retry helper'
        self.retry.write_bytes(old)
        self.retry.chmod(0o700)
        with patch.multiple(s, RETRY_BEFORE_SHA=s.sha(old), RETRY_AFTER_SHA=s.sha(new)), patch.object(s.os, 'chown'):
            s.install_retry(new)
            s.install_retry(new)
        self.assertEqual((self.work / 'upload-retry.before').read_bytes(), old)
        self.assertEqual(self.retry.read_bytes(), new)
        self.assertEqual(stat.S_IMODE(self.retry.stat().st_mode), 0o700)

    def test_unknown_destination_is_rejected_before_any_copy(self):
        with patch.object(s, 'run', return_value='/wrong\0/wrong\0fsarchiver'), self.assertRaisesRegex(RuntimeError, 'unavailable'):
            s.destination()

    def test_omv_paths_accept_trailing_separators_and_still_require_exact_destination(self):
        value = str(self.target) + '/\0' + str(self.new) + '/\0fsarchiver'
        with patch.object(s, 'run', return_value=value):
            s.destination()

    def test_preflight_allows_nonempty_target_but_rejects_modified_worker_without_writes(self):
        original_stat = Path.stat
        def separate_ssd(path, *args, **kwargs):
            info = original_stat(path, *args, **kwargs)
            if path == self.new or path == self.target:
                values = list(info)
                values[2] += 1  # st_dev; model separate mounted SSDs in this temp fixture.
                return os.stat_result(values)
            return info
        with patch.object(s, 'mount_check'), patch.object(s, 'destination'), patch.object(Path, 'stat', separate_ssd):
            self.assertEqual(s.preflight(), (None, None))
            (self.target / 'keep').write_text('existing data')
            self.assertEqual(s.preflight(), (None, None))
            (self.target / 'keep').unlink()
            self.backup.write_bytes(b'unreviewed backup change')
            with self.assertRaisesRegex(RuntimeError, 'backup worker differs'):
                s.preflight()
        self.assertFalse(self.work.exists())
        self.assertFalse(self.stage.exists())

    def test_filesystem_or_serial_mismatch_is_rejected(self):
        with patch.object(Path, 'is_mount', return_value=True), patch.object(s, 'run', return_value='wrong ext4 /dev/sdb1'), \
                self.assertRaisesRegex(RuntimeError, 'filesystem identity'):
            s.mount_check(self.new, s.NEW_UUID, 'serial')
        with patch.object(Path, 'is_mount', return_value=True), \
                patch.object(s, 'run', side_effect=[s.NEW_UUID + ' ext4 /dev/sdb1', 'sdb', 'wrong']), \
                self.assertRaisesRegex(RuntimeError, 'serial'):
            s.mount_check(self.new, s.NEW_UUID, 'serial')

    def test_nested_mount_is_rejected(self):
        line = '1 0 8:1 / ' + str(self.source / 'nested') + ' rw - ext4 /dev/sdb1 rw\n'
        with patch.object(Path, 'read_text', return_value=line), self.assertRaisesRegex(RuntimeError, 'nested'):
            s.no_nested_mounts(self.source)

    def test_literal_symlink_in_operation_path_is_rejected(self):
        self.retry.symlink_to(self.backup)
        with self.assertRaisesRegex(RuntimeError, 'symbolic'):
            s.no_links(self.retry)

    def test_collected_transient_service_is_accepted_by_launcher(self):
        result = subprocess.CompletedProcess([], 1, 'LoadState=not-found\nActiveState=inactive\n', '')
        with patch.object(s, 'guard'), patch.object(s.sys, 'argv', ['installer']), \
                patch.object(s.subprocess, 'run', return_value=result), patch.object(s, 'run') as run, \
                patch.object(s.tempfile, 'mkdtemp', return_value=str(self.root / 'worker')):
            (self.root / 'worker').mkdir()
            s.INSTALL_SOURCE = 'reviewed worker source'
            self.addCleanup(lambda: s.__dict__.pop('INSTALL_SOURCE', None))
            s.main()
        self.assertEqual(run.call_args.args[0], 'systemd-run')
        self.assertIn('--collect', run.call_args.args)


if __name__ == '__main__':
    unittest.main()
