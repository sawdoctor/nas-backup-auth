import contextlib
import fcntl
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'scripts'
if not SCRIPTS.is_dir():
    SCRIPTS = ROOT / 'nas-backup-auth/scripts'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


s = load('repair_torbox_boot', 'repair-nas-torbox-boot.py')
adopt = load('adopt_fixture_for_torbox_boot', 'import-nas-dockmon-stacks.py')
original = (SCRIPTS / 'deploy-nas-torbox.py').read_bytes()
expected, expressions = adopt.HELPERS['/usr/local/sbin/nas-torbox-media']
before = adopt.patch_helper(original, expected, expressions)
after = s.patched(before)
runtime = {'__name__': 'repaired_runtime_for_tests'}
exec(compile(after, 'repaired-runtime', 'exec'), runtime)


class BootRepairTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.mount = self.root / 'mount'
        self.mount.mkdir()
        self.worker = self.root / 'nas-torbox-media'
        self.worker.write_bytes(before)
        self.worker.chmod(0o700)
        self.lock = self.root / 'lock'
        self.recovery = self.root / 'recovery'
        self.patches = contextlib.ExitStack()
        self.addCleanup(self.patches.close)
        self.patches.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.patches.enter_context(patch.multiple(s, WORKER=self.worker, LOCK=self.lock,
                                                RECOVERY=self.recovery, PENDING=self.root / 'pending'))

    def prepare(self, records=None):
        events = []
        count = 0

        def mounts(target=None):
            nonlocal count
            if target is not None:
                return [] if records is None else records
            count += 1
            if count == 1:
                return []
            return [{'id': 99, 'type': 'ext4', 'shared': True}]

        def run(*args, **kwargs):
            events.append(args)
            return subprocess.CompletedProcess(args, 0, '', '')

        with patch.dict(runtime, {'MOUNT': self.mount, 'OWNER': self.root / 'owner',
                                 'owner_record': lambda: None, 'mounts': mounts,
                                 'run': run}):
            runtime['prepare_mount']()
        return events

    def test_only_expected_guard_changes_and_yaml_adaptation_survives(self):
        self.assertEqual(s.sha(before), s.BEFORE_SHA)
        self.assertEqual(s.sha(after), s.AFTER_SHA)
        self.assertEqual(after.replace(s.NEW.encode(), s.OLD.encode(), 1), before)
        self.assertIn(b'yaml.safe_load(existing.read_text())', after)
        self.assertEqual(s.patched(after), after)
        with self.assertRaises(RuntimeError):
            s.patched(before + b'\n# unrelated modification\n')

    def test_empty_standard_directories_are_kept_and_mounted(self):
        for name in ('movies', 'series'):
            (self.mount / name).mkdir()
        identities = {path.name: path.stat().st_ino for path in self.mount.iterdir()}
        commands = self.prepare()
        self.assertEqual(identities, {path.name: path.stat().st_ino for path in self.mount.iterdir()})
        self.assertEqual(commands[0], ('mount', '--bind', str(self.mount), str(self.mount)))
        self.assertEqual(commands[-1], ('mount', '--make-rshared', str(self.mount)))

    def test_empty_root_still_works(self):
        self.assertTrue(self.prepare())

    def test_file_inside_expected_folder_stops_before_mount(self):
        (self.mount / 'movies').mkdir()
        data = self.mount / 'movies/keep.mkv'
        data.write_bytes(b'keep actual local file')
        with self.assertRaisesRegex(RuntimeError, 'local files'):
            self.prepare()
        self.assertEqual(data.read_bytes(), b'keep actual local file')
        self.assertFalse((self.root / 'owner').exists())

    def test_unexpected_directory_and_hidden_file_are_preserved(self):
        for name, directory in (('other', True), ('.hidden', False)):
            path = self.mount / name
            path.mkdir() if directory else path.write_bytes(b'keep')
            with self.assertRaises(RuntimeError):
                self.prepare()
            self.assertTrue(path.exists())
            path.rmdir() if directory else path.unlink()

    def test_symlink_named_movies_is_not_followed(self):
        outside = self.root / 'outside'
        outside.mkdir()
        (self.mount / 'movies').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(RuntimeError):
            self.prepare()
        self.assertTrue((self.mount / 'movies').is_symlink())
        self.assertFalse(list(outside.iterdir()))

    def test_empty_nested_mount_is_rejected(self):
        (self.mount / 'series').mkdir()
        with self.assertRaises(RuntimeError):
            self.prepare(records=[{'id': 77, 'type': 'ext4'}])

    def test_successful_patch_preserves_mode_and_original_recovery_copy(self):
        with patch.object(s, 'plex_stopped'), patch.object(s, 'run', return_value='failed\n'):
            s.patch_locked()
            s.patch_locked()
        self.assertEqual(self.worker.read_bytes(), after)
        self.assertEqual(self.worker.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.recovery / 'nas-torbox-media.before').read_bytes(), before)
        self.assertEqual(json.loads((self.recovery / 'result.json').read_text())['phase'], 'patched')

    def test_unknown_worker_is_retained_without_recovery_write(self):
        self.worker.write_bytes(b'user edited helper')
        with patch.object(s, 'plex_stopped'), patch.object(s, 'run', return_value='failed\n'):
            with self.assertRaises(RuntimeError):
                s.patch_locked()
        self.assertEqual(self.worker.read_bytes(), b'user edited helper')
        self.assertFalse(self.recovery.exists())

    def test_edited_recovery_copy_is_not_overwritten(self):
        self.recovery.mkdir()
        saved = self.recovery / 'nas-torbox-media.before'
        saved.write_bytes(b'other recovery data')
        with patch.object(s, 'plex_stopped'), patch.object(s, 'run', return_value='failed\n'):
            with self.assertRaises(RuntimeError):
                s.patch_locked()
        self.assertEqual(saved.read_bytes(), b'other recovery data')
        self.assertEqual(self.worker.read_bytes(), before)

    def test_running_nas_plex_is_rejected(self):
        with patch.object(s, 'run', return_value=json.dumps({'Running': True, 'Paused': False})):
            with self.assertRaisesRegex(RuntimeError, 'Plex is running'):
                s.plex_stopped()

    def test_pending_consumers_are_not_started(self):
        s.PENDING.write_text(json.dumps({'format': 'Sawdoctor NAS TorBox CAM runtime v1', 'consumers': ['plex-id']}))
        with patch.object(s, 'plex_stopped'), patch.object(s, 'run', return_value='failed\n'):
            with self.assertRaisesRegex(RuntimeError, 'Pending CAM'):
                s.patch_locked()
        self.assertEqual(self.worker.read_bytes(), before)

    def test_service_starts_only_after_backup_lock_is_released(self):
        calls = []

        def run(*args, **kwargs):
            calls.append(args)
            if args[:2] == ('systemctl', 'start'):
                with self.lock.open('a') as stream:
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return 'active\n'

        with patch.object(s, 'patch_locked', side_effect=lambda: self.recovery.mkdir()), \
                patch.object(s, 'run', side_effect=run), patch.object(s, 'fuse_ready', return_value=True), \
                patch.object(s, 'plex_stopped'):
            s.repair()
        self.assertEqual(calls[0], ('systemctl', 'start', s.SERVICE))
        self.assertEqual(json.loads((self.recovery / 'result.json').read_text())['phase'], 'complete')
        self.assertFalse(any('restart' in call or 'docker' in call for call in calls))

    def test_collected_transient_service_allows_new_background_job(self):
        def command(*args, **kwargs):
            if args[0][0] == 'systemctl':
                return subprocess.CompletedProcess(args, 1, 'LoadState=not-found\nActiveState=inactive\n', '')
            raise AssertionError(args)

        with patch.object(s, 'guard'), patch.object(s.sys, 'argv', ['repair']), \
                patch.object(s.subprocess, 'run', side_effect=command), \
                patch.object(s.tempfile, 'mkdtemp', return_value=str(self.root / 'background')), \
                patch.object(s, 'run') as run, patch.dict(s.__dict__, {'INSTALL_SOURCE': '# reviewed worker\n'}):
            (self.root / 'background').mkdir()
            s.main()
        self.assertEqual(run.call_args.args[0], 'systemd-run')
        self.assertNotIn('restart', run.call_args.args)


if __name__ == '__main__':
    unittest.main()
