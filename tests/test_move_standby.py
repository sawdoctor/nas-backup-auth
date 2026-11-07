import ast
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT if (ROOT / 'scripts').is_dir() else ROOT / 'nas-backup-auth'
spec = importlib.util.spec_from_file_location('standby_move', REPO / 'scripts/move-nas-standby-to-ssd.py')
s = importlib.util.module_from_spec(spec); spec.loader.exec_module(s)
ENGINE = (REPO / 'scripts/move-nas-backups-to-ssd.py').read_bytes()
RECEIVER = (REPO / 'scripts/install-migration-standby-sync.py').read_bytes()
TRIAL = (REPO / 'scripts/plex-migration-trial.py').read_bytes()


class StandbyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.old, self.new = self.root / 'old', self.root / 'new'
        self.source = self.old / 'migration/nightly-standby'
        self.target = self.new / 'migration/nightly-standby'
        self.source.mkdir(parents=True); self.new.mkdir()
        self.work, self.stage = self.root / 'operation', self.new / '.staging'
        self.receiver, self.trial, self.unit = [self.root / name for name in ('receiver', 'trial', 'standby.service')]
        self.stack = contextlib.ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.stack.enter_context(patch.multiple(s, OLD_VOLUME=self.old, NEW_VOLUME=self.new,
            SOURCE=self.source, TARGET=self.target, WORK=self.work, STAGING=self.stage,
            RECEIVER=self.receiver, TRIAL=self.trial, SERVICE=self.unit, RECEIVER_SHA=s.sha(RECEIVER)))
        self.receiver.write_bytes(RECEIVER); self.trial.write_bytes(TRIAL)
        self.unit.write_text('# Sawdoctor nightly migration standby snapshots v1\n[Unit]\n'
            'Description=Refresh private migration standby snapshot (nas)\nRequires=network-online.target\n'
            'After=network-online.target network-online.target\nRequiresMountsFor=' + str(self.old) + '\n'
            '[Service]\nType=oneshot\nUMask=0077\nExecStart=' + str(self.receiver) + ' receive\n\n'
            'TimeoutStartSec=6h\nTimeoutStopSec=8min\nNice=10\nIOSchedulingClass=idle\n')
        self.original_controls = {path: path.read_bytes() for path in (self.receiver, self.trial, self.unit)}
        self.engine = s.load_engine(ENGINE)
        self.stack.enter_context(patch.object(self.engine, 'mount_check'))
        self.stack.enter_context(patch.object(s.os, 'chown'))
        original_stat = Path.stat
        def owned(path, *args, **kwargs):
            value = original_stat(path, *args, **kwargs)
            if path in self.original_controls:
                result = list(value); result[4] = 0
                return os.stat_result(result)
            return value
        self.stack.enter_context(patch.object(Path, 'stat', owned))
        for stamp, full in (('20261104T003744Z', True), ('20261107T003613Z', False)):
            folder = self.source / 'snapshots' / stamp
            (folder / 'data/library').mkdir(parents=True)
            (folder / 'data/library/video.mkv').symlink_to('/mnt/nzbdav/.ids/never-open-video')
            (folder / 'data/config.db').write_bytes(b'consistent source configuration ' + stamp.encode())
            os.setxattr(folder / 'data/config.db', 'user.copy-test', b'preserve this')
            if full:
                (folder / 'data/plex-config').mkdir()
                (folder / 'data/plex-config/Preferences.xml').write_bytes(b'private Plex fixture')
                os.link(folder / 'data/plex-config/Preferences.xml', folder / 'data/plex-config/hard-link')
            source = {'format': s.SNAPSHOT_FORMAT, 'scope': 'standby-only',
                      'createdUtc': stamp, 'sourceHost': '192.168.0.29'}
            (folder / 'manifest.json').write_text(json.dumps(source))
            metadata = {'format': s.SNAPSHOT_FORMAT, 'createdUtc': stamp, 'sha256': 'a' * 64,
                        'archiveBytes': 100, 'unpackedBytes': 200}
            if not full: metadata['profile'] = 'apps-with-external-plex-v1'
            self.checksums(folder)
            (folder / '_VERIFIED.json').write_text(json.dumps(metadata))
            if not full:
                self.engine.write_json(self.source / 'current.json', dict(metadata, snapshot=str(folder)))
        (self.source / '.run.lock').touch()
        (self.source / 'scope-change').mkdir()
        (self.source / 'scope-change/applied.json').write_text('{"oldScopeReceipt":true}')

    def checksums(self, folder):
        names = sorted(str(path.relative_to(folder)) for path in folder.rglob('*')
                       if path.is_file() and not path.is_symlink() and path.name not in {'SHA256SUMS', '_VERIFIED.json'})
        (folder / 'SHA256SUMS').write_text(''.join(s.sha((folder / name).read_bytes()) + '  ./' + name + '\n' for name in names))

    def fixture_preflight(self, engine):
        record = self.work / 'result.json'
        return json.loads(record.read_text()) if record.exists() else None

    def fixture_status(self, engine, unit, allow_missing=False):
        return {'LoadState': 'loaded', 'ActiveState': 'inactive', 'FragmentPath': str(self.unit),
                'DropInPaths': '', 'RequiresMountsFor': str(self.old) + ' ' + str(self.new)}

    def transfer(self):
        original_run = self.engine.run
        def run(*args, **kwargs):
            if args == ('systemctl', 'daemon-reload'): return ''
            return original_run(*args, **kwargs)
        usage = shutil.disk_usage(self.new)
        enough = type(usage)(total=1024**4, used=0, free=1024**4)
        with patch.object(s, 'preflight', side_effect=self.fixture_preflight), \
                patch.object(s, 'status', side_effect=self.fixture_status), \
                patch.object(self.engine, 'run', side_effect=run), \
                patch.object(s.shutil, 'disk_usage', return_value=enough), contextlib.ExitStack() as stack:
            s.transfer_locked(self.engine, stack)

    def test_real_copy_rebases_only_current_index_and_retains_both_snapshots(self):
        original = self.engine.tree(self.source)
        self.transfer()
        self.assertEqual({p.name for p in self.source.iterdir()}, {'.run.lock'})
        actual = self.engine.tree(self.target)
        for name in original:
            if name not in ('.', 'current.json'):
                self.assertEqual(self.engine.comparable({name: original[name]}), self.engine.comparable({name: actual[name]}))
        summary = s.verify_snapshots(self.engine, self.target, actual)
        self.assertEqual(summary['snapshots'], ['20261104T003744Z', '20261107T003613Z'])
        self.assertEqual(summary['fullPlexSnapshots'], ['20261104T003744Z'])
        self.assertTrue(summary['current']['snapshot'].startswith(str(self.target)))
        self.assertFalse(self.stage.exists())
        self.assertEqual(json.loads((self.work / 'result.json').read_text())['phase'], 'complete')
        for path, original_control in self.original_controls.items():
            self.assertEqual((self.work / (path.name + '.before')).read_bytes(), original_control)
            self.assertNotEqual(path.read_bytes(), original_control)
        self.assertIn(str(self.new).encode(), self.unit.read_bytes())
        self.assertEqual((self.target / 'snapshots/20261104T003744Z/data/plex-config/Preferences.xml').stat().st_ino,
                         (self.target / 'snapshots/20261104T003744Z/data/plex-config/hard-link').stat().st_ino)

    def test_copy_corruption_retains_original_and_original_readers(self):
        original = self.engine.copy_payload
        def corrupt():
            payload = original()
            (payload / 'snapshots/20261107T003613Z/data/config.db').write_bytes(b'bad copy')
            return payload
        with patch.object(self.engine, 'copy_payload', side_effect=corrupt), self.assertRaisesRegex(RuntimeError, 'differ'):
            self.transfer()
        self.assertTrue((self.source / 'current.json').is_file())
        self.assertFalse(self.target.exists())
        self.assertEqual(self.receiver.read_bytes(), self.original_controls[self.receiver])

    def test_corrupt_original_checksum_stops_before_copy_or_state_creation(self):
        (self.source / 'snapshots/20261107T003613Z/data/config.db').write_bytes(b'bad original')
        with patch.object(self.engine, 'copy_payload') as copy, self.assertRaisesRegex(RuntimeError, 'original checksum'):
            self.transfer()
        copy.assert_not_called(); self.assertFalse(self.work.exists())

    def test_full_plex_rollback_is_required_before_copy(self):
        shutil.rmtree(self.source / 'snapshots/20261104T003744Z')
        with self.assertRaisesRegex(RuntimeError, 'full Plex rollback'):
            self.transfer()
        self.assertFalse(self.work.exists())

    def test_unexpected_destination_is_not_overwritten(self):
        self.target.mkdir(parents=True); (self.target / 'keep').write_bytes(b'existing data')
        with self.assertRaisesRegex(RuntimeError, 'destination acquired files'):
            self.transfer()
        self.assertEqual((self.target / 'keep').read_bytes(), b'existing data')
        self.assertTrue((self.source / 'current.json').exists())

    def test_failed_destination_flush_keeps_old_payload_and_all_config_is_retryable(self):
        original_run = self.engine.run
        def fail(*args, **kwargs):
            if args[:2] == ('sync', '-f'): raise RuntimeError('flush failure')
            return original_run(*args, **kwargs)
        with patch.object(self.engine, 'run', side_effect=fail), self.assertRaisesRegex(RuntimeError, 'flush failure'):
            self.transfer()
        self.assertTrue((self.source / 'current.json').exists())
        self.assertTrue((self.target / 'current.json').exists())
        self.transfer()
        self.assertEqual({p.name for p in self.source.iterdir()}, {'.run.lock'})

    def test_retry_after_atomic_activation_without_second_payload_copy(self):
        original_record = s.record
        def interrupt(engine, phase, **extra):
            if phase == 'activated': raise RuntimeError('activation interruption')
            original_record(engine, phase, **extra)
        with patch.object(s, 'record', side_effect=interrupt), self.assertRaisesRegex(RuntimeError, 'activation interruption'):
            self.transfer()
        self.assertTrue(self.target.is_dir())
        with patch.object(self.engine, 'copy_payload', side_effect=AssertionError('no second payload copy')):
            self.transfer()

    def test_retry_after_partial_reader_update(self):
        original_replace = s.replace_control
        def interrupt(engine, path, original, proposed):
            original_replace(engine, path, original, proposed)
            if path == self.receiver: raise RuntimeError('reader update interruption')
        with patch.object(s, 'replace_control', side_effect=interrupt), self.assertRaisesRegex(RuntimeError, 'reader update interruption'):
            self.transfer()
        self.assertTrue((self.source / 'current.json').exists())
        self.transfer()
        self.assertEqual(json.loads((self.work / 'result.json').read_text())['phase'], 'complete')

    def test_retry_after_partial_source_cleanup(self):
        original_remove = shutil.rmtree
        stopped = False
        def interrupt(path, *args, **kwargs):
            nonlocal stopped
            result = original_remove(path, *args, **kwargs)
            if Path(path).is_relative_to(self.source) and not stopped:
                stopped = True; raise RuntimeError('cleanup interruption')
            return result
        with patch.object(s.shutil, 'rmtree', side_effect=interrupt), self.assertRaisesRegex(RuntimeError, 'cleanup interruption'):
            self.transfer()
        self.transfer()
        self.assertEqual({p.name for p in self.source.iterdir()}, {'.run.lock'})

    def test_original_mutation_during_copy_stops_before_reader_changes(self):
        original_copy = self.engine.copy_payload
        def mutate():
            payload = original_copy(); (self.source / 'unexpected').write_bytes(b'keep this'); return payload
        with patch.object(self.engine, 'copy_payload', side_effect=mutate), self.assertRaisesRegex(RuntimeError, 'changed during copying'):
            self.transfer()
        self.assertTrue((self.source / 'unexpected').exists())
        self.assertEqual(self.receiver.read_bytes(), self.original_controls[self.receiver])

    def test_completed_retry_is_harmless(self):
        self.transfer()
        with patch.object(self.engine, 'copy_payload', side_effect=AssertionError('no new copy')):
            self.transfer()

    def test_extra_postverification_file_is_preserved_and_hashed_by_transfer(self):
        path = self.source / 'snapshots/20261107T003613Z/diagnostic-after-verification.txt'
        path.write_text('retain this note too')
        self.transfer()
        self.assertEqual((self.target / path.relative_to(self.source)).read_text(), 'retain this note too')

    def test_pinned_engine_and_unknown_helpers_fail_closed(self):
        with self.assertRaisesRegex(RuntimeError, 'integrity'):
            s.load_engine(ENGINE + b'changed')
        with self.assertRaisesRegex(RuntimeError, 'receiver differs'):
            s.receiver_patch(RECEIVER + b'changed')
        with self.assertRaisesRegex(RuntimeError, 'trial helper differs'):
            s.trial_patch(TRIAL + b'changed')

    def test_only_nas_main_and_base_change_in_receiver(self):
        changed = s.receiver_patch(RECEIVER)
        def functions(data):
            return {node.name: ast.dump(node, include_attributes=False) for node in ast.parse(data).body if isinstance(node, ast.FunctionDef)}
        before, after = functions(RECEIVER), functions(changed)
        self.assertEqual({key for key in before if before[key] != after[key]}, {'main'})
        self.assertIn(str(self.target).encode(), changed)
        self.assertIn(b'keep.add(max(full))', changed)

    def test_trial_changes_only_its_nas_validation(self):
        changed = s.trial_patch(TRIAL)
        before = {node.name: ast.dump(node, include_attributes=False) for node in ast.parse(TRIAL).body if isinstance(node, ast.FunctionDef)}
        after = {node.name: ast.dump(node, include_attributes=False) for node in ast.parse(changed).body if isinstance(node, ast.FunctionDef)}
        self.assertEqual({key for key in before if before[key] != after[key]}, {'validate_nas'})

    def test_missing_backup_drive_stops_patched_receiver_before_directory_creation(self):
        module = types.ModuleType('patched_receiver')
        exec(compile(s.receiver_patch(RECEIVER), 'receiver', 'exec'), module.__dict__)
        def mounted(path): return path == module.SSD
        module.run = lambda *args, **kwargs: 'inet 192.168.0.220/24' if args[0] == 'ip' else ''
        with patch.object(module.os, 'geteuid', return_value=0), patch.object(Path, 'is_mount', mounted), \
                patch.object(module.sys, 'argv', ['worker', 'receive']), self.assertRaisesRegex(RuntimeError, 'FIKWOT standby SSD'):
            module.main()
        self.assertFalse(self.target.exists())

    def test_wrong_uuid_stops_patched_receiver_before_directory_creation(self):
        module = types.ModuleType('patched_receiver')
        exec(compile(s.receiver_patch(RECEIVER), 'receiver', 'exec'), module.__dict__)
        module.run = lambda *args, **kwargs: 'inet 192.168.0.220/24' if args[0] == 'ip' else 'wrong ext4'
        with patch.object(module.os, 'geteuid', return_value=0), patch.object(Path, 'is_mount', return_value=True), \
                patch.object(module.sys, 'argv', ['worker', 'receive']), self.assertRaisesRegex(RuntimeError, 'FIKWOT standby SSD'):
            module.main()
        self.assertFalse(self.target.exists())

    def test_unit_adds_only_backup_mount_requirement_and_rejects_unknown_settings(self):
        original = self.original_controls[self.unit]
        changed = s.service_patch(original)
        self.assertEqual(changed.replace((' ' + str(self.new) + '\n').encode(), b'\n', 1), original)
        with self.assertRaisesRegex(RuntimeError, 'unit differs'):
            s.service_patch(original + b'Restart=always\n')

    def test_current_index_outside_snapshot_root_is_rejected(self):
        path = self.source / 'current.json'; value = json.loads(path.read_text()); value['snapshot'] = '/outside'
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(RuntimeError, 'outside'):
            s.verify_snapshots(self.engine, self.source, self.engine.tree(self.source))

    def test_symlinked_snapshot_checksum_and_unsafe_checksum_path_rejected(self):
        path = self.source / 'snapshots/20261107T003613Z/SHA256SUMS'
        path.unlink(); path.symlink_to('/never-read-outside')
        with self.assertRaisesRegex(RuntimeError, 'symbolic'):
            s.verify_snapshots(self.engine, self.source, self.engine.tree(self.source))
        path.unlink(); path.write_text('a' * 64 + '  ./../outside\n')
        with self.assertRaisesRegex(RuntimeError, 'unsafe'):
            s.verify_snapshots(self.engine, self.source, self.engine.tree(self.source))

    def test_busy_job_and_collected_transient_status_handling(self):
        absent = subprocess.CompletedProcess([], 1, 'LoadState=not-found\nActiveState=inactive\n', '')
        with patch.object(s.subprocess, 'run', return_value=absent):
            s.status(self.engine, 'transient.service', allow_missing=True)
            with self.assertRaisesRegex(RuntimeError, 'busy or unavailable'):
                s.status(self.engine, 'main.service')
        active = subprocess.CompletedProcess([], 0, 'LoadState=loaded\nActiveState=active\n', '')
        with patch.object(s.subprocess, 'run', return_value=active), self.assertRaisesRegex(RuntimeError, 'busy or unavailable'):
            s.status(self.engine, 'main.service')

    def test_failed_loaded_mount_dependency_verification_keeps_original_snapshots(self):
        original_status = self.fixture_status
        def bad_status(*args, **kwargs):
            value = original_status(*args, **kwargs)
            value['RequiresMountsFor'] = str(self.old)
            return value
        with patch.object(self, 'fixture_status', side_effect=bad_status), self.assertRaisesRegex(RuntimeError, 'mount dependencies'):
            self.transfer()
        self.assertTrue((self.source / 'snapshots/20261104T003744Z').is_dir())
        self.assertTrue((self.source / 'snapshots/20261107T003613Z').is_dir())
        self.transfer()

    def test_existing_lock_is_respected_without_worker_calls(self):
        lock = self.root / 'existing.lock'
        import fcntl
        with lock.open('a') as original, contextlib.ExitStack() as stack:
            fcntl.flock(original, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(RuntimeError, 'required lock'):
                s.acquire(self.engine, stack, lock)

    def test_control_file_modes_and_xattrs_survive_atomic_updates(self):
        self.receiver.chmod(0o750); self.trial.chmod(0o700); self.unit.chmod(0o644)
        for path in self.original_controls:
            os.setxattr(path, 'user.control-test', b'preserved control metadata')
        modes = {path: path.stat().st_mode for path in self.original_controls}
        self.transfer()
        for path in self.original_controls:
            self.assertEqual(path.stat().st_mode, modes[path])
            self.assertEqual(os.getxattr(path, 'user.control-test'), b'preserved control metadata')

    def test_preflight_rejects_an_additional_installed_snapshot_reader(self):
        original_stat = Path.stat
        def different_device(path, *args, **kwargs):
            value = original_stat(path, *args, **kwargs)
            if path == self.new:
                fields = list(value); fields[2] += 1
                return os.stat_result(fields)
            return value
        original_rglob = Path.rglob
        extra = self.root / 'new-unreviewed-reader'
        extra.write_text('uses nightly-standby too')
        readers = [self.receiver, self.trial]
        def files(path, pattern):
            if str(path) == '/usr/local/sbin': return iter(readers)
            if str(path) in ('/usr/local/bin', '/etc/systemd/system'): return iter(())
            return original_rglob(path, pattern)
        with patch.object(Path, 'stat', different_device), patch.object(Path, 'rglob', files), \
                patch.object(s, 'status', side_effect=self.fixture_status), \
                patch.object(self.engine, 'run', return_value='[{"State":{"Running":false}}]'):
            self.assertIsNone(s.preflight(self.engine))
            readers.append(extra)
            with self.assertRaisesRegex(RuntimeError, 'inventory changed'):
                s.preflight(self.engine)
        self.assertFalse(self.work.exists())

    def test_destination_detached_after_long_source_check_cannot_remove_old_payload(self):
        seen = 0
        def detached(volume, *args):
            nonlocal seen
            if volume == self.new:
                seen += 1
                if seen == 2: raise RuntimeError('destination detached')
        with patch.object(self.engine, 'mount_check', side_effect=detached), self.assertRaisesRegex(RuntimeError, 'destination detached'):
            self.transfer()
        self.assertTrue((self.source / 'snapshots/20261104T003744Z').is_dir())
        self.assertTrue((self.source / 'snapshots/20261107T003613Z').is_dir())


if __name__ == '__main__': unittest.main()
