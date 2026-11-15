"""Constrain recovery release and accept only proven post-archive updates."""
import contextlib
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
import io
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


class SiloVolumeReview(unittest.TestCase):
    def silo_pair(self, app):
        old, current = container('silo-nas-silo-1'), container('silo-nas-silo-1')
        old.update(Id='old', Image='old-image')
        for row, name in zip((old, current), r.SILO_CONFIG_VOLUMES):
            root = app / 'docker/volumes' / name / '_data'
            (root / 'silo/plugins').mkdir(parents=True)
            row['Mounts'][0] = {'Type': 'volume', 'Name': name, 'Source': str(root),
                               'Destination': '/config', 'Driver': 'local', 'RW': True}
        docs = [{'Name': name, 'Driver': 'local', 'Options': None,
                 'Mountpoint': row['Mounts'][0]['Source']}
                for row, name in zip((old, current), r.SILO_CONFIG_VOLUMES)]
        commands = []
        def run(*args):
            commands.append(args)
            if args != ('docker', 'volume', 'inspect', *r.SILO_CONFIG_VOLUMES):
                raise AssertionError('unexpected command')
            return json.dumps(docs)
        native = types.SimpleNamespace(run=run, safe=lambda path: None)
        return old, current, docs, native, commands

    def test_both_reported_directory_only_volumes_allow_the_scoped_exception(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(r, 'APP', Path(folder)):
            old, current, _docs, native, commands = self.silo_pair(Path(folder))
            before = copy.deepcopy((old, current))
            result = r.approved_manual_update(old, current, ManualUpdates.archive, native)
            evidence = result['reviewedStorageException']
            self.assertFalse(evidence['storageWritten'])
            self.assertEqual([item['nonDirectoryCount'] for item in evidence['volumes']], [0, 0])
            self.assertEqual((old, current), before)
            self.assertEqual(len(commands), 1)

    def test_a_file_link_or_special_entry_in_either_volume_prevents_acceptance(self):
        for index in (0, 1):
            for kind in ('file', 'link', 'fifo'):
                with self.subTest(index=index, kind=kind), tempfile.TemporaryDirectory() as folder, \
                     patch.object(r, 'APP', Path(folder)), contextlib.redirect_stdout(io.StringIO()) as out:
                    old, current, _docs, native, _commands = self.silo_pair(Path(folder))
                    target = Path((old, current)[index]['Mounts'][0]['Source']) / 'silo/state'
                    if kind == 'file': target.write_text('SECRET-NOT-TO-BE-PRINTED')
                    elif kind == 'link': target.symlink_to('/etc/shadow')
                    else: r.os.mkfifo(target)
                    with self.assertRaisesRegex(RuntimeError, 'not an empty directory scaffold'):
                        r.approved_manual_update(old, current, ManualUpdates.archive, native)
                    self.assertNotIn('SECRET-NOT-TO-BE-PRINTED', out.getvalue())
                    self.assertTrue(target.exists() or target.is_symlink())

    def test_unknown_volume_id_other_mount_or_volume_mode_changes_are_rejected(self):
        mutations = [lambda row: row['Mounts'][0].update(Name='different'),
                     lambda row: row['Mounts'][1].update(Source='/different-persistent-data'),
                     lambda row: row['Mounts'][0].update(RW=False)]
        for mutate in mutations:
            with tempfile.TemporaryDirectory() as folder, patch.object(r, 'APP', Path(folder)):
                old, current, _docs, native, commands = self.silo_pair(Path(folder)); mutate(current)
                with self.assertRaises(RuntimeError): r.approved_manual_update(old, current, ManualUpdates.archive, native)
                self.assertFalse(commands)

    def test_external_driver_path_or_options_are_not_accepted(self):
        mutations = [lambda row: row.update(Driver='nfs'), lambda row: row.update(Options={'device': 'remote'}),
                     lambda row: row.update(Mountpoint='/somewhere-else')]
        for mutate in mutations:
            with tempfile.TemporaryDirectory() as folder, patch.object(r, 'APP', Path(folder)):
                old, current, docs, native, _commands = self.silo_pair(Path(folder)); mutate(docs[0])
                with self.assertRaisesRegex(RuntimeError, 'unreviewed storage'):
                    r.approved_manual_update(old, current, ManualUpdates.archive, native)

    def test_directory_replacement_or_content_change_between_passes_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(r, 'APP', Path(folder)):
            old, current, _docs, native, _commands = self.silo_pair(Path(folder))
            original = r.directory_report; calls = 0
            def changing(path):
                nonlocal calls
                calls += 1
                if calls == 3: (path / 'silo/new-state').write_text('new')
                return original(path)
            with patch.object(r, 'directory_report', side_effect=changing), \
                 self.assertRaisesRegex(RuntimeError, 'changed between inspection'):
                r.approved_manual_update(old, current, ManualUpdates.archive, native)

    def test_root_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); (root / 'real/silo').mkdir(parents=True); (root / 'alias').symlink_to(root / 'real')
            with self.assertRaises(OSError): r.directory_report(root / 'alias')


class ReviewedWebPorts(unittest.TestCase):
    def test_silo_main_web_is_selected_when_both_web_and_jellyfin_ports_are_published(self):
        row = container('silo-nas-silo-1')
        row['HostConfig']['PortBindings'] = {
            '8080/tcp': [{'HostIp': '192.168.0.220', 'HostPort': '8090'}],
            '8096/tcp': [{'HostIp': '192.168.0.220', 'HostPort': '8096'}]}
        self.assertEqual(r.reviewed_web_port(row), '8090')
        self.assertEqual(r.reviewed_web_port(container()), '8765')

    def test_an_unknown_app_or_changed_web_port_is_rejected(self):
        for row in (container('unreviewed'), container()):
            row['HostConfig']['PortBindings']['80/tcp'][0]['HostPort'] = '9999'
            with self.assertRaisesRegex(RuntimeError, 'reviewed web endpoint'): r.reviewed_web_port(row)


class ControllerUpgrade(unittest.TestCase):
    def setup_native(self, root):
        units = root / 'units'; units.mkdir(); old = b'known prior worker'
        for name in r.RELEASE:
            parent = units / (name + '.d'); parent.mkdir(); (parent / 'hold.conf').write_text('known condition')
        writes = []
        def atomic(path, body): path.write_bytes(body); writes.append(path)
        native = types.SimpleNamespace(UNITS=units, DROPIN='hold.conf', CONDITION='known condition',
            read=lambda path: path.read_bytes(), atomic=atomic)
        worker = root / 'worker.py'; worker.write_bytes(old)
        return native, worker, old, writes

    def test_known_preflight_only_worker_is_retained_and_replaced(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); native, worker, old, _writes = self.setup_native(root)
            with patch.object(r, 'WORK', root), patch.object(r, 'SELF', worker), \
                 patch.object(r, 'RECORD', root / 'absent.json'), patch.object(r, 'PRIOR_WORKER_SHA', r.sha(old)):
                r.install_controller(native, 'reviewed new worker')
            self.assertEqual(worker.read_text(), 'reviewed new worker')
            self.assertEqual((root / ('worker.before-' + r.sha(old) + '.py')).read_bytes(), old)

    def test_unknown_worker_existing_release_record_or_changed_condition_is_retained(self):
        for cause in ('unknown-worker', 'record', 'condition'):
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder); native, worker, old, writes = self.setup_native(root); record = root / 'record.json'
                digest = r.sha(old) if cause != 'unknown-worker' else 'unknown'
                if cause == 'record': record.write_text('{}')
                if cause == 'condition': (native.UNITS / (r.RELEASE[0] + '.d') / native.DROPIN).write_text('edited')
                with patch.object(r, 'WORK', root), patch.object(r, 'SELF', worker), \
                     patch.object(r, 'RECORD', record), patch.object(r, 'PRIOR_WORKER_SHA', digest):
                    with self.assertRaises(RuntimeError): r.install_controller(native, 'new')
                self.assertEqual(worker.read_bytes(), old); self.assertFalse(writes)


if __name__ == '__main__': unittest.main()
