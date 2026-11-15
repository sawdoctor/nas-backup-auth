"""Backup release boundaries, retained-tree selection and lock ordering."""
import contextlib
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('backup_ownership', ROOT / 'scripts/resume-nas-production-backups.py')
b = importlib.util.module_from_spec(spec); spec.loader.exec_module(b)
FIXTURE = b'''#!/bin/bash
NEEDED=$(du -sbx "$SSD/appdata" "$SSD/compose" "${VOLUMES[@]/#/$SSD/}" | awk '{n+=$1} END {printf "%.0f", n}')
tar --one-file-system \\
  --exclude='appdata/silo/transcode/*' \\
  --exclude='appdata/silo/download-artifacts/*' \\
  --exclude='compose/plex-nas/recovery/before-standby-refresh' \\
  --exclude='compose/infinidysk-nas/recovery/before-latest' \\
  -cf "$ARCHIVE" -C "$SSD" -- appdata compose
'''


class BackupScope(unittest.TestCase):
    def proposed(self):
        with patch.object(b, 'LEGACY_SHA', hashlib.sha256(FIXTURE).hexdigest()):
            return b.patch_backup(FIXTURE)

    def test_unknown_installed_worker_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'differs'):
            b.patch_backup(FIXTURE)

    def test_real_tar_and_space_estimate_exclude_only_retained_payloads(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); archive = root / 'backup.tar'
            kept = ('appdata/plex-nas/config/library.db', 'appdata/dockmon/stacks/core/compose.yaml',
                    'compose/production-cutover/state.json', 'compose/production-cutover/backup-handover/state.json')
            excluded = ('compose/production-cutover/freeze-1/incoming/old.db',
                        'compose/production-cutover/books-handover/rollback/old.db',
                        'compose/production-cutover/kometa-handover/rollback/old.db',
                        'compose/production-cutover/freeze-1/prepared/old.db',
                        'compose/plex-nas/recovery/before-standby-refresh/old.db',
                        'compose/infinidysk-nas/recovery/before-latest/old.db')
            for relative in kept + excluded:
                path = root / relative; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'live' if relative in kept else b'x' * 1048576)
            env = 'SSD=' + repr(str(root)) + '\nARCHIVE=' + repr(str(archive)) + '\nVOLUMES=()\n'
            result = subprocess.run(['bash'], input=env.encode() + self.proposed() + b'printf "%s" "$NEEDED"\n', capture_output=True, check=True)
            self.assertLess(int(result.stdout), 256 * 1024)
            members = subprocess.check_output(['tar', '-tf', str(archive)], text=True).splitlines()
            for relative in kept: self.assertIn(relative, members)
            for relative in excluded: self.assertNotIn(relative, members)


class ReleaseTransaction(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.work = self.root / 'handover'; self.work.mkdir()
        self.worker = self.root / 'nas-backup'; self.worker.write_bytes(FIXTURE)
        self.units = self.root / 'units'; self.units.mkdir()
        self.condition = '# migration\n[Unit]\nConditionPathExists=!/import-active\n'
        for name in (*b.RELEASE_UNITS, 'cron.service', 'nas-books.service'):
            path = self.units / (name + '.d/96-hold.conf'); path.parent.mkdir(); path.write_text(self.condition)
        for name, value in {'WORK': self.work, 'RECORD': self.work / 'state.json',
                            'BACKUP_WORKER': self.worker, 'LEGACY_SHA': b.sha(FIXTURE)}.items():
            p = patch.object(b, name, value); p.start(); self.addCleanup(p.stop)
        self.commands = []
        def run(*args, **kwargs):
            self.commands.append(args)
            if args[0] == 'bash': subprocess.run(['bash', '-n'], input=kwargs['input'], text=True, check=True)
            return ''
        def atomic(path, value, **kwargs):
            path.write_bytes(value if isinstance(value, bytes) else (json.dumps(value) + '\n').encode())
        self.native = types.SimpleNamespace(read=lambda path: path.read_bytes(), atomic=atomic,
                    UNITS=self.units, DROPIN='96-hold.conf', CONDITION=self.condition,
                    sync_dir=lambda path: None, run=run)
        rows = {'plex-nas': {'Id': 'current-id', 'Image': 'manually-upgraded-image', 'State': {'Running': True}}}
        p = patch.object(b, 'preflight', return_value=({'proof': {'cutoverId': 'frozen'}}, rows)); p.start(); self.addCleanup(p.stop)
        p = patch.object(b, 'unit', return_value={'ExecMainStartTimestampMonotonic': '123'}); p.start(); self.addCleanup(p.stop)

    def test_release_changes_only_three_backup_guards_and_no_containers(self):
        record = b.configure_locked(self.native)
        self.assertEqual(record['releasedUnits'], list(b.RELEASE_UNITS))
        self.assertEqual(record['runningBefore'][0]['image'], 'manually-upgraded-image')
        for name in b.RELEASE_UNITS: self.assertFalse((self.units / (name + '.d/96-hold.conf')).exists())
        for name in ('cron.service', 'nas-books.service'):
            self.assertEqual((self.units / (name + '.d/96-hold.conf')).read_text(), self.condition)
        self.assertEqual((self.work / 'nas-backup.before').read_bytes(), FIXTURE)
        self.assertFalse(any(args[0] == 'docker' for args in self.commands))

    def test_partial_release_can_resume_without_replacing_saved_original(self):
        original_run = self.native.run
        def fail_reload(*args, **kwargs):
            if args == ('systemctl', 'daemon-reload'): raise RuntimeError('simulated reload failure')
            return original_run(*args, **kwargs)
        self.native.run = fail_reload
        with self.assertRaisesRegex(RuntimeError, 'reload failure'): b.configure_locked(self.native)
        self.native.run = original_run
        record = b.configure_locked(self.native)
        self.assertEqual(record['phase'], 'released')
        self.assertEqual((self.work / 'nas-backup.before').read_bytes(), FIXTURE)

    def test_modified_guard_stops_before_worker_or_other_guard_changes(self):
        changed = self.units / (b.RELEASE_UNITS[-1] + '.d/96-hold.conf'); changed.write_text('operator override')
        with self.assertRaisesRegex(RuntimeError, 'edited'): b.configure_locked(self.native)
        self.assertEqual(self.worker.read_bytes(), FIXTURE)
        self.assertFalse(b.RECORD.exists())
        self.assertTrue((self.units / (b.RELEASE_UNITS[0] + '.d/96-hold.conf')).exists())

    def test_missing_guard_without_journal_is_not_assumed_released(self):
        (self.units / (b.RELEASE_UNITS[0] + '.d/96-hold.conf')).unlink()
        with self.assertRaisesRegex(RuntimeError, 'missing'): b.configure_locked(self.native)
        self.assertEqual(self.worker.read_bytes(), FIXTURE)


class LockOrdering(unittest.TestCase):
    def test_persistent_timer_start_occurs_after_backup_lock_is_released(self):
        held = set()
        @contextlib.contextmanager
        def lock(path):
            held.add(path)
            try: yield
            finally: held.remove(path)
        native = types.SimpleNamespace(lock=lock, BACKUP_LOCK=Path('/backup-lock'))
        def arm(*args):
            self.assertNotIn(native.BACKUP_LOCK, held)
            self.assertIn(b.BASE / '.run.lock', held)
        with patch.object(b, 'guard'), patch.object(b, 'load', return_value=native), \
             patch.object(b, 'configure_locked', return_value={}), patch.object(b, 'arm_and_verify', side_effect=arm) as verify, \
             patch.object(b.sys, 'argv', ['worker', '--worker']):
            b.main()
        verify.assert_called_once()


if __name__ == '__main__': unittest.main()
