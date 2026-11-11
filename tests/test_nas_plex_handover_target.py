import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('target', ROOT / 'scripts/prepare-nas-plex-handover-target.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


def container():
    paths = {'/config': (s.DATA / 'config', True),
             '/flora-test-library': (s.DATA / 'flora-test-library', False),
             '/scratch': (s.SCRATCH, True), '/mnt/media': (s.LIBRARY, False),
             '/mnt/nzbdav': (Path('/mnt/nzbdav'), False),
             '/torbox-cams': (Path('/mnt/torbox-media/movies'), False)}
    return {'Name': '/plex-nas', 'Id': 'existing-nas-container', 'Image': 'sha256:verified-local-image',
            'State': {'Running': False, 'Status': 'exited', 'StartedAt': 'old', 'FinishedAt': 'old'},
            'Config': {'Image': s.IMAGE_TAG, 'Env': ['PUID=1000', 'PGID=1000', 'VERSION=docker', 'OTHER=retained']},
            'HostConfig': {'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0}, 'NetworkMode': 'host',
                           'Privileged': False, 'Devices': [{'PathOnHost': '/dev/dri', 'PathInContainer': '/dev/dri',
                                                            'CgroupPermissions': 'rwm'}]},
            'Mounts': [{'Destination': k, 'Type': 'bind', 'Source': str(v[0]), 'RW': v[1]} for k, v in paths.items()]}


class TargetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.row = container()
        self.images = {'plex': {'source': s.SOURCE_IMAGE, 'nas': self.row['Image']}}

    def test_accepts_existing_stopped_trial_container(self):
        self.assertEqual(s.validate_container(self.row, self.images), (1000, 1000))

    def test_running_plex_or_enabled_restart_is_rejected(self):
        for key, value in [('running', True), ('restart', 'on-failure')]:
            row = copy.deepcopy(self.row)
            if key == 'running':
                row['State']['Running'] = value
            else:
                row['HostConfig']['RestartPolicy']['Name'] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                s.validate_container(row, self.images)

    def test_old_source_media_binding_or_writable_media_is_rejected(self):
        for field, value in [('Source', '/mnt/old-source'), ('RW', True)]:
            row = copy.deepcopy(self.row)
            mount = next(m for m in row['Mounts'] if m['Destination'] == '/mnt/media')
            mount[field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                s.validate_container(row, self.images)

    def test_unverified_image_mapping_is_rejected(self):
        self.images['plex']['nas'] = 'sha256:different-image'
        with self.assertRaises(RuntimeError):
            s.validate_container(self.row, self.images)

    def test_sqlite_probe_cannot_invoke_plex_entrypoint_or_mount_config(self):
        with patch.object(s, 'run', return_value='3.46.1 local-tool-build\n') as command:
            self.assertEqual(s.sqlite_probe(self.row, 1000, 1000), '3.46.1')
        args = command.call_args.args
        self.assertEqual(args[:3], ('docker', 'run', '--rm'))
        self.assertIn('--pull=never', args)
        self.assertIn('--network=none', args)
        self.assertIn('--read-only', args)
        self.assertEqual(args[args.index('--entrypoint') + 1], s.SQLITE)
        self.assertEqual(args[-2:], (self.row['Image'], '--version'))
        self.assertFalse(any(a in args for a in ('-v', '--volume', '--mount', '--env', '--restart')))

    def test_incomplete_existing_identity_fails_without_changes(self):
        data = self.root / 'data'
        path = data / 'config' / s.PREFS
        path.parent.mkdir(parents=True)
        path.write_text('<Preferences MachineIdentifier="existing" PlexOnlineToken="private" />')
        original = path.read_bytes()
        with patch.object(s, 'DATA', data), self.assertRaises(RuntimeError):
            s.identity()
        self.assertEqual(path.read_bytes(), original)

    def test_saved_target_plan_is_small_and_other_files_are_retained(self):
        base = self.root / 'handover'
        sentinel = self.root / 'existing-plex-data'
        sentinel.write_text('retained')
        plan = {'container': s.fingerprint(self.row), 'existingNasIdentity': {'id': 'hash'}, 'format': s.FORMAT}
        with patch.object(s, 'BASE', base):
            s.save(plan)
            s.save(plan)
        self.assertEqual(sentinel.read_text(), 'retained')
        self.assertEqual({p.name for p in base.iterdir()}, {'owner.json', 'target-plan.json'})
        self.assertEqual(base.stat().st_mode & 0o777, 0o700)
        self.assertEqual((base / 'target-plan.json').stat().st_mode & 0o777, 0o600)

    def test_unknown_rollback_or_operation_files_are_not_overwritten(self):
        base = self.root / 'handover'
        base.mkdir()
        (base / 'owner.json').write_text(json.dumps({'format': s.FORMAT}))
        extra = base / 'rollback-progress'
        extra.write_text('retained')
        with patch.object(s, 'BASE', base), self.assertRaises(RuntimeError):
            s.save({'container': {}, 'existingNasIdentity': {}})
        self.assertEqual(extra.read_text(), 'retained')

    def test_prepare_changes_only_small_plan_and_leaves_nas_stopped(self):
        base = self.root / 'handover'
        data = self.root / 'plex-config'
        data.write_bytes(b'existing Plex data')
        budget = {'existingNasPlexBytes': 14 * 1024**3, 'availableAppBytesAtPreparation': 374 * 1024**3}
        with contextlib.ExitStack() as stack:
            for name, value in [('BASE', base), ('INCOMING', self.root / 'incoming'), ('ROLLBACK', self.root / 'rollback')]:
                stack.enter_context(patch.object(s, name, value))
            stack.enter_context(patch.object(s, 'mounts'))
            stack.enter_context(patch.object(s, 'inspect', return_value=self.row))
            stack.enter_context(patch.object(s, 'read', return_value=json.dumps(self.images).encode()))
            stack.enter_context(patch.object(s, 'identity', return_value={'MachineIdentifierSha256': 'hash'}))
            stack.enter_context(patch.object(s, 'estimate', return_value=budget))
            stack.enter_context(patch.object(s, 'sqlite_probe', return_value='3.46.1'))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            s.prepare()
        self.assertEqual(data.read_bytes(), b'existing Plex data')
        self.assertFalse((self.root / 'incoming').exists())
        self.assertFalse((self.root / 'rollback').exists())
        plan = json.loads((base / 'target-plan.json').read_text())
        self.assertEqual(plan['copiedPlexBytes'], 0)
        self.assertFalse(plan['plexStarted'])
        self.assertTrue(plan['sourceHeldProofRequired'])

    def test_unsafe_input_symlink_is_rejected(self):
        target = self.root / 'target'
        target.write_text('data')
        alias = self.root / 'alias'
        alias.symlink_to(target)
        with self.assertRaises(RuntimeError):
            s.read(alias)

    def test_insufficient_peak_space_blocks_plan_before_any_copy(self):
        data = self.root / 'data'
        for leaf in ('config', 'flora-test-library'):
            (data / leaf).mkdir(parents=True)
        db = data / 'config' / s.DATABASE
        db.parent.mkdir(parents=True)
        db.write_bytes(b'0' * 4096)
        base = self.root / 'recovery' / 'operation'
        base.parent.mkdir()
        with patch.object(s, 'DATA', data), patch.object(s, 'BASE', base), \
                patch.object(s, 'run', return_value='15032385536  directory\n'), \
                patch.object(s.shutil, 'disk_usage', return_value=SimpleNamespace(free=10 * 1024**3)), \
                self.assertRaises(RuntimeError):
            s.estimate()
        self.assertFalse(base.exists())

    def test_unexpected_tool_output_fails_without_opening_database(self):
        with patch.object(s, 'run', return_value='not a SQLite CLI response'), self.assertRaises(RuntimeError):
            s.sqlite_probe(self.row, 1000, 1000)


if __name__ == '__main__':
    unittest.main()
