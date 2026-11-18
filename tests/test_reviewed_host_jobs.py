import contextlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

PATH = Path(__file__).resolve().parents[1] / 'scripts/restore-nas-reviewed-host-jobs.py'
spec = importlib.util.spec_from_file_location('host_jobs', PATH)
jobs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jobs)


def archive_plan(**changes):
    result = {'mode': 'plan', 'already_protected': [], 'pending_protection': [],
              'unmatched_links': [], 'errors': [], 'vault_links_need_review': []}
    result.update(changes)
    return result


class ReviewedHostJobTests(unittest.TestCase):
    def test_pending_protection_is_valid_planned_work(self):
        result = jobs.archive_plan_summary(1, archive_plan(pending_protection=['book']))
        self.assertEqual(result['pending_protection'], 1)

    def test_unknown_plan_error_link_or_apply_mode_refused(self):
        for data in (archive_plan(errors=['API denied']), archive_plan(unmatched_links=['book']),
                     archive_plan(vault_links_need_review=['book']), archive_plan(mode='apply'),
                     archive_plan(pending_protection='invalid')):
            with self.assertRaises(RuntimeError):
                jobs.archive_plan_summary(1, data)

    def test_backup_lock_only_wraps_original_archive_command(self):
        text = jobs.archive_drop().decode()
        self.assertIn('ExecStart=\nExecStart=/usr/bin/flock --nonblock --conflict-exit-code 75 ', text)
        self.assertIn(str(jobs.ARCHIVE_PROGRAM) + ' --apply', text)
        self.assertIn('SuccessExitStatus=75', text)
        self.assertNotIn('Environment=', text)
        self.assertNotIn('rm ', text)

    def test_failed_read_only_plan_prevents_all_releases(self):
        with tempfile.TemporaryDirectory() as root:
            state = Path(root) / 'state.json'
            native = Mock()
            native.lock.return_value = contextlib.nullcontext()
            native.read.return_value = b'{"phase":"complete"}'
            boot = Mock()
            boot.boot_lock.return_value = contextlib.nullcontext()
            backup = Mock()
            backup.preflight.return_value = ({'proof': {'cutoverId': 'current'}}, {})
            with patch.object(jobs, 'STATE', state), patch.object(jobs, 'validate_review'), \
                 patch.object(jobs, 'plans', side_effect=RuntimeError('API plan unavailable')), \
                 patch.object(jobs, 'restore_cron') as cron, patch.object(jobs, 'restore_job') as job:
                with self.assertRaisesRegex(RuntimeError, 'API plan unavailable'):
                    jobs.worker(boot, backup, native)
                cron.assert_not_called()
                job.assert_not_called()
                native.run.assert_not_called()

    def test_hba_handover_disables_bridge_before_cron_start(self):
        calls = []
        native = Mock()
        native.run.side_effect = lambda *args, **kwargs: calls.append(args)
        record = {'completed': []}
        statuses = lambda native, name: {'ActiveState': 'active' if name == 'cron.service' else 'inactive'}
        with patch.object(jobs, 'status', side_effect=statuses), patch.object(jobs, 'release_hold'), \
             patch.object(jobs, 'cache_snapshot', side_effect=[{'inode': 1}, {'inode': 2, 'mtime': 100, 'temperatureC': 60}]), \
             patch.object(jobs.time, 'time_ns', return_value=100):
            jobs.restore_cron(native, record)
        disable = calls.index(('systemctl', 'disable', '--now', jobs.BRIDGE + '.timer'))
        start = calls.index(('systemctl', 'start', 'cron.service'))
        self.assertLess(disable, start)
        self.assertEqual(record['completed'], ['cron'])

    def test_failed_cron_hba_check_recovers_bridge_and_original_hold(self):
        calls = []
        with tempfile.TemporaryDirectory() as root:
            work = Path(root)
            (work / 'retained').mkdir()
            (work / 'retained/cron.service.d.conf').write_bytes(b'original')
            native = Mock()
            native.run.side_effect = lambda *args, **kwargs: calls.append(args)
            native.read.return_value = b'original'
            with patch.object(jobs, 'WORK', work), patch.object(jobs, 'status', return_value={'ActiveState': 'inactive'}), \
                 patch.object(jobs, 'release_hold'), patch.object(jobs, 'cache_snapshot', return_value=None), \
                 patch.object(jobs.time, 'monotonic', side_effect=[0, 0, 101]):
                with self.assertRaisesRegex(RuntimeError, 'No fresh'):
                    jobs.restore_cron(native, {'completed': []})
            self.assertIn(('systemctl', 'stop', 'cron.service'), calls)
            self.assertIn(('systemctl', 'enable', '--now', jobs.BRIDGE + '.timer'), calls)
            native.atomic.assert_called_once_with(jobs.hold_path('cron.service'), b'original', mode=0o644)

    def test_archiver_scheduler_does_not_wait_for_or_claim_cloud_transfer(self):
        calls = []
        native = Mock()
        native.run.side_effect = lambda *args, **kwargs: calls.append(args)
        record = {'completed': []}
        with patch.object(jobs, 'release_hold'), patch.object(jobs, 'status', return_value={
                'ActiveState': 'active', 'UnitFileState': 'enabled'}):
            jobs.restore_job(native, 'nas-torbox-audiobook-archive', record)
        self.assertNotIn(('systemctl', 'start', 'nas-torbox-audiobook-archive.service'), calls)
        self.assertIn(('systemctl', 'enable', '--now', 'nas-torbox-audiobook-archive.timer'), calls)
        self.assertNotIn('archiveTransfersVerified', record)

    def test_unknown_unit_state_refused(self):
        with patch.object(jobs.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'ActiveState=unknown\n', '')):
            with self.assertRaises(RuntimeError):
                jobs.status(None, 'cron.service')

    def test_renewal_context_counts_only_enabled_live_hosts(self):
        db = sqlite3.connect(':memory:')
        try:
            db.executescript('CREATE TABLE certificate(id INTEGER, provider TEXT, expires_on TEXT);'
                             'CREATE TABLE proxy_host(id INTEGER, certificate_id INTEGER, enabled INTEGER, is_deleted INTEGER);'
                             "INSERT INTO certificate VALUES(1,'letsencrypt','expired'),(2,'letsencrypt','current');"
                             'INSERT INTO proxy_host VALUES(1,1,0,0),(2,1,1,1),(3,2,1,0);')
            result = jobs.certificate_usage(db)
            self.assertEqual([r['id'] for r in result], [2])
            self.assertEqual(result[0]['activeUses'], [{'table': 'proxy_host', 'id': 3}])
        finally:
            db.close()

    def test_plans_and_scheduler_starts_run_outside_backup_lock(self):
        held = {'value': False}
        @contextlib.contextmanager
        def backup_lock(native):
            held['value'] = True
            try:
                yield
            finally:
                held['value'] = False
        def outside(*args):
            self.assertFalse(held['value'], 'a lock-owning worker was called under BACKUP_LOCK')
            return {}
        with tempfile.TemporaryDirectory() as root:
            work = Path(root)
            native = Mock()
            native.lock.return_value = contextlib.nullcontext()
            native.read.return_value = b'{"phase":"complete"}'
            native.catalog.return_value = {}
            native.ACTIVE.exists.return_value = True
            boot = Mock()
            boot.boot_lock = backup_lock
            backup = Mock()
            backup.preflight.return_value = ({'proof': {'cutoverId': 'current'}}, {})
            with patch.object(jobs, 'STATE', work / 'state.json'), patch.object(jobs, 'WORK', work), \
                 patch.object(jobs, 'ARCHIVE_DROP', work / 'archive.d/lock.conf'), \
                 patch.object(jobs, 'validate_review'), patch.object(jobs, 'plans', side_effect=outside), \
                 patch.object(jobs, 'restore_cron', side_effect=outside), \
                 patch.object(jobs, 'restore_job', side_effect=outside), \
                 patch.object(jobs, 'status', return_value={}), patch.object(jobs, 'renewal_context'):
                jobs.worker(boot, backup, native)


if __name__ == '__main__':
    unittest.main()
