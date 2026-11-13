"""A reordered Mounts array is harmless; changed records and duplicates are not."""
import copy
import importlib.util
import io
import contextlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('mount_order_runner', Path(__file__).resolve().parents[1] / 'scripts/run-production-cutover-stable-mounts.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class MountOrder(unittest.TestCase):
    def setUp(self):
        self.mounts = [{'Type': 'bind', 'Source': '/real/config', 'Destination': '/config', 'RW': True, 'Propagation': 'rprivate'},
                       {'Type': 'bind', 'Source': '/mnt/media', 'Destination': '/mnt/media', 'RW': False, 'Propagation': 'rprivate'}]

    def test_only_record_order_changes_and_other_config_is_retained(self):
        saved = {'plex': {'Mounts': self.mounts}}
        row = {'Mounts': list(reversed(self.mounts)), 'Image': 'image', 'Config': {'Env': ['secret=private']}}
        with contextlib.redirect_stdout(io.StringIO()) as output: result = m.normalize({'plex': row}, saved)
        self.assertEqual(result['plex']['Mounts'], self.mounts)
        self.assertEqual(result['plex']['Config'], row['Config'])
        self.assertNotIn('private', output.getvalue())

    def test_every_binding_field_still_matters(self):
        changes = [('Source', '/wrong'), ('Destination', '/wrong'), ('RW', False), ('Propagation', 'rshared'), ('Type', 'volume')]
        for key, value in changes:
            current = copy.deepcopy(self.mounts); current[0][key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError): m.normalize({'plex': {'Mounts': current}}, {'plex': {'Mounts': self.mounts}})

    def test_missing_added_or_duplicate_records_are_rejected(self):
        for mounts in (self.mounts[:1], self.mounts + [self.mounts[0]], []):
            with self.assertRaises(RuntimeError): m.normalize({'plex': {'Mounts': mounts}}, {'plex': {'Mounts': self.mounts}})

    def test_dictionary_key_order_is_not_a_record_change(self):
        changed = [dict(reversed(list(item.items()))) for item in self.mounts]
        self.assertEqual(m.canonical(changed), m.canonical(self.mounts))

    def test_unknown_record_fields_and_value_types_are_not_discarded(self):
        for changes in ({'AdditionalField': 'new'}, {'RW': 1}):
            current = copy.deepcopy(self.mounts); current[0].update(changes)
            with self.assertRaises(RuntimeError): m.normalize({'plex': {'Mounts': current}}, {'plex': {'Mounts': self.mounts}})

    def test_native_launch_and_future_plex_boot_use_the_pinned_runner(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); runner = root / 'stable.py'; runner.write_bytes(b'runner')
            worker = root / 'worker.py'; calls = []
            module = SimpleNamespace(WORKER=worker, catalog=lambda: {}, run=lambda *args, **kwargs: calls.append(args),
                plex_boot_text=lambda: 'ExecStart=/usr/bin/python3 ' + str(worker) + ' --boot-plex\n')
            m.install_overrides(module, {'containers': {}}, runner, 'nas')
            module.run('systemd-run', '--unit=nas-production-activate', '/usr/bin/python3', str(worker), '--activate-worker', 'plan')
            self.assertIn(str(runner), calls[0]); self.assertNotIn(str(worker), calls[0])
            self.assertEqual(calls[0][-2:], ('--runner-sha', m.sha(b'runner')))
            self.assertIn('--boot-plex --runner-sha ' + m.sha(b'runner'), module.plex_boot_text())
            with self.assertRaises(RuntimeError): module.run('systemd-run', '/usr/bin/python3', str(worker), '--unreviewed')

    def test_nas_import_failure_retains_native_stopped_writer_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            active = Path(directory) / 'active'; active.touch(); recovered = []
            def fail(): raise RuntimeError('native failure')
            module = SimpleNamespace(WORKER=Path(directory) / 'worker.py', main=fail,
                                     ACTIVE=active, recover=lambda: recovered.append('stopped writers'))
            with patch.object(m.sys, 'argv', ['test']), self.assertRaisesRegex(RuntimeError, 'native failure'):
                m.invoke_native(module, 'nas', ['--activate-worker', 'plan'])
            self.assertEqual(recovered, ['stopped writers'])

    def test_source_failure_keeps_native_source_recovery_ownership(self):
        recovered = []
        def fail(): raise RuntimeError('native source failure')
        module = SimpleNamespace(WORKER=Path('/native/worker.py'), main=fail,
                                 recover=lambda: recovered.append('must not run'))
        with patch.object(m.sys, 'argv', ['test']), self.assertRaisesRegex(RuntimeError, 'native source failure'):
            m.invoke_native(module, 'source', ['--hold-worker', 'plan'])
        self.assertFalse(recovered)


if __name__ == '__main__': unittest.main()
