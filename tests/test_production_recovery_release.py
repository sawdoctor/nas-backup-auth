"""Constrain recovery release and accept only proven post-archive updates."""
import contextlib
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('recovery_release', ROOT / 'scripts/resume-nas-production-recovery.py')
r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)


def container(name='speedtest-tracker-nas', identity='new', image='new-image'):
    return {'Name': '/' + name, 'Id': identity, 'Image': image, 'Created': '2026-11-15T09:42:04.587390248Z',
            'State': {'Running': True, 'StartedAt': 'now', 'Pid': 1234},
            'Config': {'Image': 'original/repository:latest', 'Env': ['SECRET=private'],
                       'Labels': {'com.docker.compose.project': 'support-nas', 'com.docker.compose.service': 'speedtest'}},
            'HostConfig': {'NetworkMode': 'media-core', 'PortBindings': {'80/tcp': [{'HostIp': '192.168.0.220', 'HostPort': '8765'}]}},
            'Mounts': [{'Type': 'bind', 'Source': '/appdata/current', 'Destination': '/config', 'RW': True},
                       {'Type': 'bind', 'Source': '/etc/localtime', 'Destination': '/etc/localtime', 'RW': False}]}


class ManualUpdates(unittest.TestCase):
    archive = 1794735300  # 2026-11-15 09:35 UTC

    def test_only_both_known_updated_applications_are_accepted(self):
        for name in sorted(r.MANUAL_UPDATES):
            new = container(name); old = copy.deepcopy(new); old.update(Id='old', Image='old-image')
            result = r.approved_manual_update(old, new, self.archive)
            self.assertEqual(result['beforeImageId'], 'old-image')
            self.assertEqual(result['afterImageId'], 'new-image')
            self.assertNotIn('SECRET', json.dumps(result))
            self.assertEqual(old['Id'], 'old')

    def test_other_application_identity_changes_are_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'separate review'):
            r.approved_manual_update(container('plex-nas'), container('plex-nas'), self.archive)

    def test_recreation_during_archive_is_not_accepted(self):
        new = container(); new['Created'] = '2026-11-15T09:20:00Z'
        with self.assertRaisesRegex(RuntimeError, 'before the application archive'):
            r.approved_manual_update(container(), new, self.archive)

    def test_data_network_and_ownership_changes_are_rejected(self):
        mutations = [lambda row: row['Mounts'][0].update(Source='/different-data'),
                     lambda row: row['HostConfig'].update(NetworkMode='host'),
                     lambda row: row['Config']['Labels'].update({'com.docker.compose.project': 'different'})]
        for mutate in mutations:
            old, new = container(), container(); mutate(new)
            with self.assertRaises(RuntimeError): r.approved_manual_update(old, new, self.archive)

    def test_mount_order_changes_do_not_change_mount_identity(self):
        old, new = container(), container(); new['Mounts'].reverse()
        r.approved_manual_update(old, new, self.archive)

    def test_restart_changes_only_lifecycle_fields_in_runtime_signature(self):
        before = {'test': container()}; after = copy.deepcopy(before)
        after['test']['State'].update(Pid=5678, StartedAt='later')
        self.assertEqual(r.runtime_signature(before), r.runtime_signature(after))
        after['test']['Image'] = 'unexpected-version'
        self.assertNotEqual(r.runtime_signature(before), r.runtime_signature(after))


class RecoveryConditions(unittest.TestCase):
    def test_only_two_existing_media_recovery_conditions_are_released(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); unitdir = root / 'units'; unitdir.mkdir(); record = root / 'record.json'
            condition = '# expected import condition\n'; dropin = '96-hold.conf'
            documents = {name: '# installed ' + name + '\n' for name in r.RELEASE}
            for name in (*r.RELEASE, 'cron.service', 'nas-books.service'):
                parent = unitdir / (name + '.d'); parent.mkdir(); (parent / dropin).write_text(condition)
                if name in documents: (unitdir / name).write_text(documents[name])
            commands = []
            def atomic(path, value): path.write_text(json.dumps(value))
            native = types.SimpleNamespace(UNITS=unitdir, DROPIN=dropin, CONDITION=condition,
                read=lambda path: path.read_bytes(), atomic=atomic, sync_dir=lambda path: None,
                run=lambda *args: commands.append(args))
            recovery = types.SimpleNamespace(unit_documents=lambda: documents)
            with patch.object(r, 'RECORD', record), patch.object(r, 'current_guard',
                    return_value=({'proof': {'cutoverId': 'same-source-hold'}}, {'test': container()}, recovery)):
                result = r.release_locked(native, object())
            self.assertEqual(result['releasedUnits'], list(r.RELEASE))
            for name in r.RELEASE: self.assertFalse((unitdir / (name + '.d') / dropin).exists())
            for name in ('cron.service', 'nas-books.service'):
                self.assertEqual((unitdir / (name + '.d') / dropin).read_text(), condition)
            self.assertEqual(commands, [('systemctl', 'daemon-reload')])

    def test_recovery_service_start_is_outside_shared_backup_lock(self):
        held = set()
        @contextlib.contextmanager
        def lock(path):
            held.add(path)
            try: yield
            finally: held.remove(path)
        backup_lock = Path('/backup-lock')
        native = types.SimpleNamespace(lock=lock, BACKUP_LOCK=backup_lock)
        backup = types.SimpleNamespace(guard=lambda: None, NATIVE_SHA='accepted', load=lambda *args: native)
        def complete(*args):
            self.assertNotIn(backup_lock, held)
            self.assertIn(r.BASE / '.run.lock', held)
        with patch.object(r, 'backup_module', return_value=backup), \
             patch.object(r, 'release_locked', return_value={}), \
             patch.object(r, 'complete', side_effect=complete) as final, \
             patch.object(r.sys, 'argv', ['worker', '--worker']):
            r.main()
        final.assert_called_once()


if __name__ == '__main__': unittest.main()
