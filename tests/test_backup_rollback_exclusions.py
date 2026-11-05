import contextlib
import hashlib
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/exclude-nas-backup-rollback-copies.py'
if not SCRIPT.is_file():
    SCRIPT = ROOT / 'nas-backup-auth/scripts/exclude-nas-backup-rollback-copies.py'
spec = importlib.util.spec_from_file_location('backup_rollback_exclusions', SCRIPT)
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)

FIXTURE = (b'#!/bin/bash\nset -eu\nKEEP=3\n'
           b'resume_containers() { /usr/local/sbin/nas-media-recovery resume-locked; }\n'
           b'tar --one-file-system \\\n'
           b"  --exclude='appdata/silo/transcode/*' \\\n"
           b"  --exclude='appdata/silo/download-artifacts/*' \\\n"
           b'  -cf output.tar -- appdata compose\n')


class BackupScopeTests(unittest.TestCase):
    def patch_fixture(self):
        return patch.object(s, 'BEFORE_SHA', hashlib.sha256(FIXTURE).hexdigest())

    def test_unknown_worker_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'differs'):
            s.patch(FIXTURE)

    def test_only_two_exact_exclusions_change_and_reapplication_is_idempotent(self):
        with self.patch_fixture():
            changed = s.patch(FIXTURE)
            self.assertEqual(s.patch(changed), changed)
            for path in s.EXCLUSIONS:
                changed = changed.replace(("  --exclude='" + path + "' \\\n").encode(), b'')
            self.assertEqual(changed, FIXTURE)

    def test_a_further_edit_after_patching_is_rejected(self):
        with self.patch_fixture():
            changed = s.patch(FIXTURE)
            with self.assertRaisesRegex(RuntimeError, 'beyond'):
                s.patch(changed.replace(b'KEEP=3', b'KEEP=1'))

    def test_exclusions_inserted_outside_the_tar_command_are_rejected(self):
        addition = ''.join("  --exclude='" + path + "' \\\n" for path in s.EXCLUSIONS).encode()
        with self.patch_fixture(), self.assertRaisesRegex(RuntimeError, 'beyond'):
            s.patch(FIXTURE + addition)

    def test_real_tar_excludes_old_copies_but_keeps_live_data_custom_code_and_trial(self):
        with tempfile.TemporaryDirectory() as directory, self.patch_fixture():
            root = Path(directory)
            files = [
                'appdata/plex-nas/config/Library/Application Support/Plex Media Server/Preferences.xml',
                'appdata/infinidysk-nas/config/db.sqlite',
                'appdata/books-nas/custom-hook.py',
                'compose/plex-nas/recovery/trial/state.json',
                'compose/plex-nas/compose.yaml',
                s.EXCLUSIONS[0] + '/config/old.sqlite',
                s.EXCLUSIONS[1] + '/config.tar.zst',
            ]
            for name in files:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('fixture')
            link = root / 'appdata/library/movie.mkv'
            link.parent.mkdir(parents=True)
            link.symlink_to('/mnt/nzbdav/.ids/fixture')
            subprocess.run(['/bin/bash'], input=s.patch(FIXTURE), cwd=root, check=True)
            names = subprocess.check_output(['tar', '-tf', 'output.tar'], cwd=root, text=True).splitlines()
            for name in files[:-2]:
                self.assertIn(name, names)
            for prefix in s.EXCLUSIONS:
                self.assertFalse(any(name.rstrip('/') == prefix or name.startswith(prefix + '/') for name in names))
            self.assertIn('appdata/library/movie.mkv', names)

    def install_fixture(self, root):
        worker = root / 'nas-backup'
        worker.write_bytes(FIXTURE)
        worker.chmod(0o700)
        work = root / 'backup-scope'
        stack = contextlib.ExitStack()
        stack.enter_context(self.patch_fixture())
        stack.enter_context(patch.multiple(s, WORKER=worker, WORK=work))
        stack.enter_context(patch.object(s.subprocess, 'run', side_effect=lambda args, **kw:
            types.SimpleNamespace(stdout='inactive\n', returncode=0) if args[0] == 'systemctl'
            else subprocess_run(args, **kw)))
        stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        return stack, worker, work

    def test_install_preserves_original_script_mode_and_is_repeatable(self):
        with tempfile.TemporaryDirectory() as directory:
            stack, worker, work = self.install_fixture(Path(directory))
            with stack:
                s.install_locked()
                expected = s.patch(FIXTURE)
                self.assertEqual(worker.read_bytes(), expected)
                self.assertEqual(worker.stat().st_mode & 0o777, 0o700)
                self.assertEqual((work / 'recovery/nas-backup.before').read_bytes(), FIXTURE)
                s.install_locked()
                self.assertEqual(worker.read_bytes(), expected)

    def test_unrelated_recovery_folder_prevents_worker_change(self):
        with tempfile.TemporaryDirectory() as directory:
            stack, worker, work = self.install_fixture(Path(directory))
            work.mkdir()
            with stack, self.assertRaisesRegex(RuntimeError, 'unrelated'):
                s.install_locked()
            self.assertEqual(worker.read_bytes(), FIXTURE)

    def test_busy_backup_is_rejected_before_creating_recovery_files(self):
        with tempfile.TemporaryDirectory() as directory:
            stack, worker, work = self.install_fixture(Path(directory))
            with stack, patch.object(s.subprocess, 'run', return_value=
                    types.SimpleNamespace(stdout='active\n', returncode=0)):
                with self.assertRaisesRegex(RuntimeError, 'active'):
                    s.install_locked()
            self.assertEqual(worker.read_bytes(), FIXTURE)
            self.assertFalse(work.exists())

    def test_symbolic_recovery_path_prevents_worker_change(self):
        with tempfile.TemporaryDirectory() as directory:
            stack, worker, work = self.install_fixture(Path(directory))
            foreign = Path(directory) / 'foreign'
            foreign.mkdir()
            work.symlink_to(foreign, target_is_directory=True)
            with stack, self.assertRaisesRegex(RuntimeError, 'symbolic'):
                s.install_locked()
            self.assertEqual(worker.read_bytes(), FIXTURE)


subprocess_run = subprocess.run
if __name__ == '__main__':
    unittest.main()
