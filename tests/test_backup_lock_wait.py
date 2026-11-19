import fcntl
import importlib.util
import math
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

spec = importlib.util.spec_from_file_location('backup_lock_repair', Path(__file__).resolve().parents[1] / 'scripts/repair-nas-backup-lock-wait.py')
repair = importlib.util.module_from_spec(spec); spec.loader.exec_module(repair)


class BackupLockWaitTests(unittest.TestCase):
    def test_only_exact_lock_statement_changes(self):
        source = b'#!/bin/bash\nset -euo pipefail\nexec 9>/tmp/unused\n' + repair.OLD + b'echo original-work\n'
        expected = source.replace(repair.OLD, repair.NEW)
        self.assertEqual(repair.patch_lines(source), expected)
        self.assertEqual(subprocess.run(['bash', '-n'], input=expected, capture_output=True).returncode, 0)

    def test_unknown_or_duplicate_lock_lines_refused(self):
        for source in (b'flock -n 8\n', repair.OLD + repair.OLD):
            with self.assertRaises(RuntimeError): repair.patch_lines(source)

    def test_failure_proof_is_exact_not_a_guess(self):
        self.assertTrue(repair.collision_confirmed('unit starting\n' + repair.FAILURE + '\n'))
        self.assertFalse(repair.collision_confirmed('Permission denied\n'))
        self.assertFalse(repair.collision_confirmed('A quoted possible error: ' + repair.FAILURE))

    def test_existing_unit_timeout_is_interpreted(self):
        self.assertEqual(repair.timeout_seconds('infinity'), math.inf)
        self.assertEqual(repair.timeout_seconds('2h 30min'), 9000)
        self.assertEqual(repair.timeout_seconds('1min 30s'), 90)
        with self.assertRaises(RuntimeError): repair.timeout_seconds('unexpected')

    def test_missing_timestamp_does_not_claim_a_new_backup(self):
        record = {'backupStartBefore': 'old'}
        self.assertFalse(repair.new_run({'ExecMainStartTimestamp': ''}, record))
        self.assertFalse(repair.new_run({'ExecMainStartTimestamp': 'old'}, record))
        self.assertTrue(repair.new_run({'ExecMainStartTimestamp': 'new'}, record))

    def test_journal_is_limited_to_the_actual_failed_invocation(self):
        self.assertEqual(repair.journal_selection({'InvocationID': 'a' * 32}), ['_SYSTEMD_INVOCATION_ID=' + 'a' * 32])
        selected = repair.journal_selection({'ExecMainStartTimestamp': 'Thu 2026-11-19 02:00:04 GMT',
                                            'ExecMainExitTimestamp': 'Thu 2026-11-19 02:00:04 GMT'})
        self.assertEqual(selected[0], '--since')
        self.assertEqual(int(selected[3][1:]) - int(selected[1][1:]), 2)
        with self.assertRaises(RuntimeError): repair.journal_selection({'InvocationID': ''})

    def test_real_waiting_flock_acquires_after_current_owner_finishes(self):
        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / 'lock'
            with lock_path.open('w') as owner:
                fcntl.flock(owner, fcntl.LOCK_EX)
                process = subprocess.Popen(['bash', '-c', 'set -e; exec 9>"$1"; flock -w 3 9; echo acquired', 'test', str(lock_path)],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                time.sleep(.15)
                self.assertIsNone(process.poll())
                fcntl.flock(owner, fcntl.LOCK_UN)
                stdout, stderr = process.communicate(timeout=4)
                self.assertEqual(process.returncode, 0, stderr)
                self.assertEqual(stdout.strip(), b'acquired')

    def test_real_wait_has_a_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / 'lock'
            with lock_path.open('w') as owner:
                fcntl.flock(owner, fcntl.LOCK_EX)
                response = subprocess.run(['bash', '-c', 'exec 9>"$1"; flock -w .1 9', 'test', str(lock_path)],
                                          capture_output=True, timeout=2)
                self.assertEqual(response.returncode, 1)


if __name__ == '__main__': unittest.main()
