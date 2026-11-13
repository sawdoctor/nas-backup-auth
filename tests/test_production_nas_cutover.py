"""NAS frozen provenance, crash boundaries and paired rollback protocol."""
import base64
import contextlib
import copy
import hashlib
import importlib.util
import json
import io
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from unittest.mock import MagicMock
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


n = load('nas_cutover_test', 'nas-production-cutover.py')
s = load('source_cutover_test', 'source-production-cutover.py')
a = load('source_approval_test', 'approve-source-production-cutover.py')
c = load('core_checksum_test', 'prepare-nas-production-core.py')


class NASCutover(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.base = self.root / 'controls'; self.base.mkdir()
        for key, value in {'BASE': self.base, 'STATE': self.base / 'state.json'}.items():
            p = patch.object(n, key, value); p.start(); self.addCleanup(p.stop)
        self.proof = {'format': n.SOURCE_FORMAT, 'held': True, 'cutoverId': '20261113T190000Z-' + 'a' * 16,
                      'receiptKey': 'b' * 64, 'identitySha256': n.sha(b'current-server'),
                      'archiveSha256': 'c' * 64, 'manifestSha256': 'd' * 64,
                      'archiveBytes': 100, 'payloadLimitBytes': n.MAX_BYTES, 'frozenUtc': '20261113T191000Z'}

    def test_only_complete_published_source_proof_authorizes_import(self):
        n.validate_proof(self.proof)
        for key, value in [('held', False), ('receiptKey', ''), ('archiveBytes', n.MAX_BYTES + 1),
                           ('cutoverId', '../../source'), ('payloadLimitBytes', 1), ('archiveBytes', True)]:
            with self.subTest(key=key), self.assertRaises(RuntimeError): n.validate_proof({**self.proof, key: value})

    def test_start_permission_is_bound_to_same_exact_operation(self):
        with patch.object(n, 'source_status', return_value=self.proof): n.held(self.proof)
        for changes in ({'held': False}, {'archiveSha256': 'a' * 64}, {'receiptKey': 'c' * 64}):
            with patch.object(n, 'source_status', return_value={**self.proof, **changes}), self.assertRaises(RuntimeError): n.held(self.proof)

    def test_signed_nas_stopped_receipt_is_accepted_by_existing_source_controller(self):
        state = {'cutoverId': self.proof['cutoverId'], 'receiptKey': self.proof['receiptKey']}
        token = n.receipt(self.proof, now=1000)
        s.validate_receipt(token, state, now=1050)
        with self.assertRaises(RuntimeError): s.validate_receipt(token, state, now=1601)
        with self.assertRaises(RuntimeError): s.validate_receipt(token + 'changed', state, now=1050)

    def test_private_record_rejects_a_symbolic_parent(self):
        outside = self.root / 'outside'; outside.mkdir(); (outside / 'record').write_text('private')
        link = self.root / 'link'; link.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(RuntimeError): n.read(link / 'record')

    def test_journalled_root_swap_retains_old_data_and_new_data(self):
        live = self.root / 'live'; live.mkdir(); (live / 'old').write_text('NAS original')
        incoming = self.root / 'incoming'; incoming.mkdir(); (incoming / 'new').write_text('fresh source')
        before = self.root / 'rollback'; state = {'roots': []}
        n.swap_root(state, incoming, live, before)
        self.assertEqual((live / 'new').read_text(), 'fresh source')
        self.assertEqual((before / 'old').read_text(), 'NAS original')
        self.assertEqual(json.loads(n.STATE.read_bytes())['roots'][0]['phase'], 'installed')

    def test_existing_rollback_root_blocks_any_rename(self):
        live = self.root / 'live'; live.mkdir()
        incoming = self.root / 'incoming'; incoming.mkdir()
        before = self.root / 'old'; before.mkdir()
        with self.assertRaises(RuntimeError): n.swap_root({'roots': []}, incoming, live, before)
        self.assertTrue(live.exists()); self.assertTrue(incoming.exists())

    def manifest(self):
        config = self.root / 'data/plex-config'; (config / n.PREFS).parent.mkdir(parents=True)
        (config / n.PREFS).write_bytes(b'<Preferences MachineIdentifier="current-server"/>')
        db = config / n.DB; db.parent.mkdir(parents=True); db.write_bytes(b'current watch history')
        manifest = {'format': n.SOURCE_FORMAT, 'scope': 'production-frozen', 'sourceHost': '192.168.0.29',
                    'createdUtc': self.proof['frozenUtc'], 'cutoverId': self.proof['cutoverId'],
                    'plexConfigIncluded': True, 'sourceDockerStopped': True,
                    'identitySha256': self.proof['identitySha256'], 'livePlexDatabaseSha256': {'main': n.digest(db)},
                    'containers': [{'Name': '/plex', 'Image': 'exact-source-image'}]}
        n.atomic(self.root / 'manifest.json', manifest)
        self.proof['manifestSha256'] = n.digest(self.root / 'manifest.json')
        return config, manifest, {'sourceImages': {'plex': 'exact-source-image'}}

    def test_old_plex_database_cannot_pass_current_stopped_source_provenance(self):
        config, _, plan = self.manifest()
        n.verify_manifest(self.root, self.proof, plan)
        (config / n.DB).write_bytes(b'three-day-old Plex backup')
        with self.assertRaisesRegex(RuntimeError, 'stopped live source'): n.verify_manifest(self.root, self.proof, plan)

    def test_stale_wal_is_rejected_even_with_correct_main_database(self):
        config, _, plan = self.manifest(); Path(str(config / n.DB) + '-wal').write_bytes(b'old WAL')
        with self.assertRaisesRegex(RuntimeError, 'obsolete Plex WAL'): n.verify_manifest(self.root, self.proof, plan)

    def test_regular_nightly_snapshot_is_not_an_acceptable_plex_handover(self):
        _, manifest, plan = self.manifest(); manifest.update({'scope': 'standby-only', 'plexConfigIncluded': False})
        n.atomic(self.root / 'manifest.json', manifest); self.proof['manifestSha256'] = n.digest(self.root / 'manifest.json')
        with self.assertRaises(RuntimeError): n.verify_manifest(self.root, self.proof, plan)

    def test_incomplete_checksum_inventory_cannot_be_accepted(self):
        (self.root / 'current').write_bytes(b'current'); (self.root / 'unlisted').write_bytes(b'not in list')
        (self.root / 'SHA256SUMS').write_text(n.sha(b'current') + '  ./current\n')
        with self.assertRaisesRegex(RuntimeError, 'incomplete'): n.verify_files(self.root, c)
        (self.root / 'unlisted').unlink(); self.assertEqual(n.verify_files(self.root, c), 1)

    def test_dockmon_writes_only_reviewed_automation_fields(self):
        path = self.root / 'dockmon.db'
        with sqlite3.connect(path) as db:
            db.executescript('CREATE TABLE global_settings(default_auto_restart,auto_update_enabled_default,prune_images_enabled,enable_notifications);'
                'INSERT INTO global_settings VALUES(1,1,1,1);CREATE TABLE auto_restart_configs(enabled);INSERT INTO auto_restart_configs VALUES(1);'
                'CREATE TABLE container_updates(auto_update_enabled);INSERT INTO container_updates VALUES(1);'
                'CREATE TABLE container_http_health_checks(auto_restart_on_failure);INSERT INTO container_http_health_checks VALUES(1);')
        before = n.digest(path)
        self.assertTrue(any(n.dockmon_notify(path).values())); self.assertEqual(before, n.digest(path))
        self.assertFalse(any(n.dockmon_notify(path, self.root / 'saved.db').values()))
        with sqlite3.connect(path) as db: self.assertEqual(db.execute('SELECT enable_notifications FROM global_settings').fetchone(), (1,))
        with sqlite3.connect(self.root / 'saved.db') as db:
            self.assertEqual(db.execute('SELECT * FROM global_settings').fetchone(), (1, 1, 1, 1))

    def test_unknown_dockmon_schema_is_never_modified(self):
        path = self.root / 'dockmon.db'
        with sqlite3.connect(path) as db: db.execute('CREATE TABLE unrelated(value)')
        before = n.digest(path)
        with self.assertRaises(RuntimeError): n.dockmon_notify(path, self.root / 'saved.db')
        self.assertEqual(before, n.digest(path)); self.assertFalse((self.root / 'saved.db').exists())

    def test_plex_integrity_check_mounts_disposable_database_only(self):
        config, _, _ = self.manifest(); folder = self.root / 'operation'; folder.mkdir()
        calls = []
        def run(*args, **kwargs): calls.append(args); return 'ok\n'
        with patch.object(n, 'run', side_effect=run): n.plex_check(config, 'pinned-image', folder)
        args = calls[0]
        self.assertIn('--network=none', args); self.assertIn('--pull=never', args)
        self.assertTrue(any(a.startswith('--name=nas-plex-db-check-') for a in args))
        mount = next(a for a in args if a.startswith('--mount='))
        self.assertNotIn(str(config), mount); self.assertIn('plex-database-check', mount)
        self.assertIn('PRAGMA query_only=ON; PRAGMA temp_store=MEMORY; PRAGMA quick_check;', args)
        self.assertNotIn('--version', args)

    def test_failed_plex_native_integrity_check_never_opens_live_data(self):
        config, _, _ = self.manifest(); folder = self.root / 'operation'; folder.mkdir()
        with patch.object(n, 'run', return_value='database disk image is malformed'), self.assertRaises(RuntimeError): n.plex_check(config, 'pinned', folder)
        self.assertTrue((folder / 'plex-database-check').is_dir())
        self.assertEqual((config / n.DB).read_bytes(), b'current watch history')

    def test_source_approval_rejects_changed_source_images_before_any_stop(self):
        source = {'catalog': {name: {'Image': name + '-source-image'} for name in a.NAMES},
                  'format': n.SOURCE_FORMAT, 'workerSha256': a.WORKER_SHA}
        data = json.dumps(source).encode()
        ready = {'format': n.FORMAT, 'nasPlanSha256': 'f' * 64, 'sourcePlanSha256': n.sha(data),
                 'sourceImages': {name: item['Image'] for name, item in source['catalog'].items()}}
        token = lambda: base64.urlsafe_b64encode(json.dumps(ready).encode()).decode()
        with patch.object(a, 'WORKER_SHA', n.sha(b'worker')):
            source['workerSha256'] = n.sha(b'worker'); data = json.dumps(source).encode(); ready['sourcePlanSha256'] = n.sha(data)
            self.assertEqual(a.validate(token(), data, b'worker'), n.sha(data))
            ready['sourceImages']['plex'] = 'different-source-image'
            with self.assertRaisesRegex(RuntimeError, 'source image changed'): a.validate(token(), data, b'worker')

    def test_rollback_reconciles_both_rename_crash_windows_without_source_restart(self):
        for crash in ('before-first-rename', 'after-first-rename', 'after-second-rename'):
            with self.subTest(crash=crash), tempfile.TemporaryDirectory(dir=self.root) as directory:
                folder = Path(directory); live, incoming, before = (folder / name for name in ('live', 'incoming', 'before'))
                live.mkdir(); (live / 'old').write_text('original NAS')
                incoming.mkdir(); (incoming / 'new').write_text('frozen production')
                if crash != 'before-first-rename': live.rename(before)
                if crash == 'after-second-rename': incoming.rename(live)
                state = {'format': n.FORMAT, 'phase': 'importing', 'nasPlanSha256': 'approved', 'proof': self.proof,
                         'composes': [], 'units': {}, 'roots': [{'incoming': str(incoming), 'live': str(live), 'before': str(before), 'phase': 'planned'}]}
                n.atomic(n.STATE, state); active = folder / 'active'; active.touch(); output = io.StringIO()
                socket = MagicMock(); socket.__enter__.return_value.connect_ex.return_value = 111
                with patch.object(n, 'ACTIVE', active), patch.object(n, 'approved', return_value={'affected': ['plex-nas']}), \
                        patch.object(n, 'lock', return_value=contextlib.nullcontext()), patch.object(n, 'stop_affected') as stop, \
                        patch.object(n, 'catalog', return_value={'plex-nas': {'State': {'Running': False}}}), \
                        patch.object(n.socket, 'socket', return_value=socket), patch.object(n, 'run') as run, contextlib.redirect_stdout(output): n.rollback()
                self.assertEqual((live / 'old').read_text(), 'original NAS')
                stop.assert_called_once()
                self.assertTrue(all(call.args[:2] != ('docker', 'start') for call in run.call_args_list))
                token = output.getvalue().strip().split()[-1]
                s.validate_receipt(token, self.proof)
                self.assertEqual(json.loads(n.STATE.read_bytes())['phase'], 'rolled-back-stopped')

    def test_running_nas_writer_blocks_source_return_receipt(self):
        active = self.root / 'active'; active.touch()
        n.atomic(n.STATE, {'phase': 'importing', 'nasPlanSha256': 'approved', 'proof': self.proof, 'roots': [], 'composes': []})
        output = io.StringIO()
        with patch.object(n, 'ACTIVE', active), patch.object(n, 'approved', return_value={'affected': ['plex-nas']}), \
                patch.object(n, 'lock', return_value=contextlib.nullcontext()), patch.object(n, 'stop_affected'), patch.object(n, 'run'), \
                patch.object(n, 'catalog', return_value={'plex-nas': {'State': {'Running': True}}}), \
                contextlib.redirect_stdout(output), self.assertRaisesRegex(RuntimeError, 'writer remains running'): n.rollback()
        self.assertNotIn('--resume', output.getvalue())

    def test_active_published_plex_port_blocks_source_return_receipt(self):
        active = self.root / 'active'; active.touch()
        n.atomic(n.STATE, {'phase': 'importing', 'nasPlanSha256': 'approved', 'proof': self.proof, 'roots': [], 'composes': []})
        socket = MagicMock(); socket.__enter__.return_value.connect_ex.return_value = 0
        with patch.object(n, 'ACTIVE', active), patch.object(n, 'approved', return_value={'affected': []}), \
                patch.object(n, 'lock', return_value=contextlib.nullcontext()), patch.object(n, 'stop_affected'), patch.object(n, 'run'), \
                patch.object(n, 'catalog', return_value={}), patch.object(n.socket, 'socket', return_value=socket), \
                self.assertRaisesRegex(RuntimeError, 'still responds'): n.rollback()

    def test_backup_scope_excludes_large_incoming_and_rollback_but_keeps_live_data(self):
        original = b"#!/bin/bash\ntar -cpf archive \\\n+  --exclude='appdata/silo/download-artifacts/*' \\\n+  appdata compose\n"
        with patch.object(n, 'BACKUP_SHA', n.sha(original)):
            result = n.backup_scope(original)
        self.assertIn(b"--exclude='compose/production-cutover/*/incoming'", result)
        self.assertIn(b"--exclude='compose/production-cutover/*/rollback'", result)
        self.assertIn(b'  appdata compose\n', result)
        with self.assertRaises(RuntimeError): n.backup_scope(b'unreviewed backup')

    def test_idle_backup_resume_service_does_not_block_guard_install(self):
        active = self.root / 'active'; units = self.root / 'units'; units.mkdir(); boot = units / 'guard.service'
        state = {'units': {}, 'proof': self.proof}
        with patch.object(n, 'ACTIVE', active), patch.object(n, 'UNITS', units), patch.object(n, 'BOOT', boot), \
                patch.object(n, 'guard_units', return_value=['nas-backup-resume.service']), \
                patch.object(n, 'unit_state', return_value={'ActiveState': 'active', 'SubState': 'exited', 'MainPID': '0'}), patch.object(n, 'run'):
            n.guard_install(state)
        self.assertTrue(active.exists())

    def test_running_backup_resume_service_blocks_guard_install(self):
        active = self.root / 'active'
        with patch.object(n, 'ACTIVE', active), patch.object(n, 'guard_units', return_value=['nas-backup-resume.service']), \
                patch.object(n, 'unit_state', return_value={'ActiveState': 'active', 'SubState': 'running', 'MainPID': '123'}), \
                self.assertRaisesRegex(RuntimeError, 'service is active'): n.guard_install({'units': {}, 'proof': self.proof})
        self.assertFalse(active.exists())


if __name__ == '__main__': unittest.main()
