"""Exercise staging fences and failure labels without accessing either host."""
import contextlib
import fcntl
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('precopy', ROOT / 'scripts/refresh-optiplex-handover-precopy.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


class WorkingTrees(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root / 'refresh'
        self.seed = self.root / 'plex-seed'
        self.apps = self.root / 'applications'
        self.work = self.apps / 'snapshot-work'
        self.seed.mkdir(); self.work.mkdir(parents=True)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for name, value in {'BASE': self.base, 'SEED': self.seed, 'APPS': self.apps,
                            'BACKUP_LOCK': self.root / 'backup.lock', 'PENDING': ()}.items():
            self.stack.enter_context(patch.object(s, name, value))
        self.stack.enter_context(patch.object(s.shutil, 'disk_usage', return_value=SimpleNamespace(free=200 * 1024**3)))
        self.roots = {}
        for leaf in ('plex-config', 'flora-test-library'):
            source = self.root / ('source-' + leaf)
            source.mkdir(); (source / 'data').write_bytes(b'current source data')
            self.roots[leaf] = source
            destination = self.seed / 'payload' / leaf
            destination.mkdir(parents=True); (destination / 'data').write_bytes(b'old staged data')
        self.before = {'Id': 'same-container', 'Image': 'same-image', 'startedAt': 'after-daily-backup'}
        self.previous = {'format': 'sawdoctor-plex-handover-precopy-v1',
                         'phase': 'seeded-running-not-frozen', 'consistentSnapshot': False,
                         'sourceStopPerformed': False, 'container': {**self.before, 'startedAt': 'old-start'},
                         'sourceRoots': {k: str(v) for k, v in self.roots.items()}}
        (self.seed / 'state.json').write_text(json.dumps(self.previous))
        (self.seed / 'owner.json').write_text(json.dumps({'format': self.previous['format']}))
        (self.seed / 'worker.py').write_text('existing retained worker')
        (self.work / '.standby-owner').write_text('nightly-format')
        (self.work / 'manifest.json').write_bytes(b'original manifest')
        (self.work / 'SHA256SUMS').write_bytes(b'original checksum list')
        self.source_app = self.root / 'live-app'
        self.source_app.mkdir(); (self.source_app / 'db.sqlite').write_bytes(b'fresh application data')
        self.app_roots = {'core.sonarr': {'source': str(self.source_app), 'snapshot': 'data/core.sonarr', 'kind': 'directory'}}
        self.copied = []

        def copy_plex(source, target):
            self.copied.append(('plex', source, target))
            self.assertFalse((self.work / 'manifest.json').exists())
            self.assertFalse((self.work / 'SHA256SUMS').exists())
            shutil.copyfile(source / 'data', target / 'data')

        def copy_apps(work, roots, live):
            self.assertTrue(live)
            for entry in roots.values():
                target = work / entry['snapshot']
                target.mkdir(parents=True, exist_ok=True)
                self.copied.append(('app', Path(entry['source']), target))
                shutil.copyfile(Path(entry['source']) / 'db.sqlite', target / 'db.sqlite')

        self.seed_module = SimpleNamespace(
            EXPECTED={}, source_checks=lambda: None, container=lambda: self.before,
            FORMAT=self.previous['format'], ROOTS=self.roots, atomic=s.atomic,
            size=lambda path: 1024, copy_root=copy_plex)
        self.nightly_module = SimpleNamespace(
            inspect_source=lambda: {'sonarr': {'Id': 'arr-id', 'Image': 'arr-image'}},
            validate_source_networks=lambda catalog: None,
            data_roots=lambda catalog: self.app_roots, FORMAT='nightly-format',
            run=lambda *args: '1024\n', copy_roots=copy_apps)
        self.stack.enter_context(patch.object(s, 'load', side_effect=lambda p, h, n:
                                 self.seed_module if p == self.seed / 'worker.py' else self.nightly_module))

    def test_backup_restart_allows_refresh_without_claiming_frozen_copy(self):
        record = s.seed_record(self.previous, self.before, self.previous['sourceRoots'])
        self.assertEqual(record['container']['startedAt'], 'after-daily-backup')
        self.assertEqual(record['phase'], 'seeding')
        self.assertFalse(record['consistentSnapshot'])

    def test_finalized_or_changed_identity_is_never_reused(self):
        for field, value in [('phase', 'frozen'), ('consistentSnapshot', True), ('sourceStopPerformed', True)]:
            changed = {**self.previous, field: value}
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                s.seed_record(changed, self.before, self.previous['sourceRoots'])
        with self.assertRaises(RuntimeError):
            s.seed_record(self.previous, {**self.before, 'Id': 'replacement'}, self.previous['sourceRoots'])

    def test_working_destination_cannot_escape_through_symlink(self):
        outside = self.root / 'outside'; outside.mkdir()
        (self.work / 'data').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(RuntimeError):
            s.validate_work(self.work, self.app_roots, 'nightly-format')
        self.assertEqual(list(outside.iterdir()), [])

    def test_unowned_or_traversing_working_tree_is_rejected(self):
        (self.work / '.standby-owner').write_text('some other job')
        with self.assertRaises(RuntimeError):
            s.validate_work(self.work, self.app_roots, 'nightly-format')
        (self.work / '.standby-owner').write_text('nightly-format')
        bad = {'core.sonarr': {**self.app_roots['core.sonarr'], 'snapshot': '../production'}}
        with self.assertRaises(RuntimeError):
            s.validate_work(self.work, bad, 'nightly-format')

    def test_nested_mount_cannot_receive_rsync_writes(self):
        mount = str(self.work / 'data/core.sonarr/prod bind').replace(' ', '\\040')
        with self.assertRaises(RuntimeError):
            s.reject_nested_mounts((self.work,), '123 1 0:1 / ' + mount + ' rw - ext4 /dev/test rw')
        s.reject_nested_mounts((self.work,), '123 1 0:1 / /unrelated rw - ext4 /dev/test rw')

    def test_success_refreshes_both_seeds_but_preserves_archives_and_source(self):
        archive = self.apps / 'export.tar.zst'; archive.write_bytes(b'retained verified archive')
        with contextlib.redirect_stdout(io.StringIO()):
            s.refresh()
        result = json.loads((self.base / 'state.json').read_text())
        self.assertEqual(result['phase'], 'live-precopy-ready-NOT-FROZEN')
        self.assertFalse(result['consistentSnapshot']); self.assertFalse(result['sourceStopPerformed'])
        self.assertEqual(archive.read_bytes(), b'retained verified archive')
        self.assertEqual((self.work / 'data/core.sonarr/db.sqlite').read_bytes(), b'fresh application data')
        self.assertEqual((self.source_app / 'db.sqlite').read_bytes(), b'fresh application data')
        self.assertEqual((self.seed / 'payload/plex-config/data').read_bytes(), b'current source data')
        self.assertEqual((self.base / 'metadata-before-first-refresh/manifest.json').read_bytes(), b'original manifest')
        self.assertEqual((self.base / 'metadata-before-first-refresh/SHA256SUMS').read_bytes(), b'original checksum list')
        self.assertEqual(len(self.copied), 3)

    def test_interruption_cannot_leave_stale_verified_labels_on_live_seed(self):
        self.nightly_module.copy_roots = lambda *a, **k: (_ for _ in ()).throw(RuntimeError('interrupted'))
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(RuntimeError):
            s.refresh()
        self.assertFalse((self.work / 'manifest.json').exists())
        self.assertFalse((self.work / 'SHA256SUMS').exists())
        record = json.loads((self.seed / 'state.json').read_text())
        self.assertFalse(record['consistentSnapshot'])
        self.assertEqual(record['phase'], 'seeding')
        self.assertEqual(json.loads((self.base / 'state.json').read_text())['phase'], 'refreshing')

    def test_busy_snapshot_lock_prevents_copy(self):
        with (self.apps / '.run.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(RuntimeError):
                s.refresh()
        self.assertEqual(self.copied, [])
        self.assertEqual((self.work / 'manifest.json').read_bytes(), b'original manifest')

    def test_unknown_later_plex_recovery_files_prevent_copy(self):
        (self.seed / 'final-transfer.json').write_text('retain')
        with self.assertRaises(RuntimeError):
            s.refresh()
        self.assertEqual(self.copied, [])
        self.assertTrue((self.seed / 'final-transfer.json').exists())

    def test_new_nightly_manifest_is_not_silently_discarded_on_repeat(self):
        s.owner(); s.retire_work_checksums(self.work)
        (self.work / 'manifest.json').write_bytes(b'later completed nightly manifest')
        with self.assertRaises(RuntimeError):
            s.retire_work_checksums(self.work)
        self.assertEqual((self.work / 'manifest.json').read_bytes(), b'later completed nightly manifest')


if __name__ == '__main__':
    unittest.main()
