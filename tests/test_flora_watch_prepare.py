import contextlib
import datetime as dt
import fcntl
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'scripts'
if not SCRIPTS.is_dir():
    SCRIPTS = ROOT / 'nas-backup-auth/scripts'
spec = importlib.util.spec_from_file_location('flora_watch_prepare', SCRIPTS / 'prepare-nas-flora-watch.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
REAL_SOURCE_FILE = s.source_file

ORIGINAL = b'''#!/usr/bin/env bash
set -u
DB="/home/sawdoctor/docker/nzbdav/nzbdav-config/db.sqlite"
KUMA_URL="http://192.168.0.29:3001/api/push/PRIVATE_FIXTURE_KEY"
THRESHOLD_MINUTES=60
STOP_NZBDAV=0
LOG="/home/sawdoctor/logs/flora-nzbdav-watch.log"
# Fixture control flow is retained while the three path/URL assignments change.
if [ "$STOP_NZBDAV" -eq 1 ]; then docker stop nzbdav; fi
'''
CODE = b'#!/usr/bin/env python3\n# public fixture helper\n'


class FloraTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = self.root / 'app'
        self.backup = self.root / 'backup'
        self.base = self.backup / 'migration/nightly-standby'
        self.base.mkdir(parents=True)
        (self.base / '.run.lock').touch()
        self.data = self.app / 'appdata/host-jobs/flora-queue-watch'
        self.helper = self.root / 'bin/nas-flora-queue-watch'
        self.unit = self.root / 'units/nas-flora-queue-watch.service'
        self.timer = self.unit.with_suffix('.timer')
        self.lock = self.root / 'backup.lock'
        self.lock.touch()
        self.database = self.app / 'appdata/infinidysk-nas/config/db.sqlite'
        self.kuma = self.app / 'appdata/support-nas/uptime-kuma/kuma.db'
        self.database.parent.mkdir(parents=True)
        self.kuma.parent.mkdir(parents=True)
        with contextlib.closing(sqlite3.connect(self.database)) as db, db:
            db.execute('CREATE TABLE QueueItems(JobName TEXT, CreatedAt TEXT)')
        with contextlib.closing(sqlite3.connect(self.kuma)) as db, db:
            db.execute('CREATE TABLE monitor(type TEXT,push_token TEXT,active INTEGER)')
            db.execute('INSERT INTO monitor VALUES(?,?,0)', ('push', 'PRIVATE_FIXTURE_KEY'))
        self.calls = []
        self.reloaded = False
        self.enabled = False
        self.running = True
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.output = self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.stack.enter_context(patch.multiple(s, APP=self.app, BACKUP=self.backup, BASE=self.base, DATA=self.data,
                                              HELPER=self.helper, UNIT=self.unit, TIMER=self.timer, LOCK=self.lock,
                                              SOURCE_SHA=hashlib.sha256(ORIGINAL).hexdigest()))
        self.stack.enter_context(patch.object(s, 'run', side_effect=self.query))
        self.stack.enter_context(patch.object(s, 'mount'))
        self.stack.enter_context(patch.object(s, 'source_file', return_value=(ORIGINAL, '20261107T003613Z')))

    def query(self, *args, **kwargs):
        self.calls.append(args)
        if args[0] == 'ip':
            return 'inet 192.168.0.220/24'
        if args[:2] == ('docker', 'inspect'):
            return json.dumps([{'Name': '/' + name, 'State': {'Running': self.running}, 'Mounts': [
                {'Type': 'bind', 'Destination': target, 'Source': str(path)}]}
                for name, target, path in [('infinidysk-nas', '/config', self.database.parent), ('uptime-kuma-nas', '/app/data', self.kuma.parent)]])
        if args[:2] == ('systemctl', 'show'):
            return ('LoadState=' + ('loaded' if self.reloaded else 'not-found') + '\nActiveState=inactive\nUnitFileState='
                    + ('enabled' if self.enabled else 'disabled' if args[2].endswith('.timer') else 'static') + '\n')
        if args == ('systemctl', 'daemon-reload'):
            self.reloaded = True
            return ''
        if args[:2] == ('/usr/bin/bash', '-n'):
            result = subprocess.run(args, input=kwargs['input'], text=True, capture_output=True)
            if result.returncode:
                raise RuntimeError('Invalid shell syntax')
            return ''
        if args[0] == '/usr/bin/which':
            return '/usr/bin/' + args[1] + '\n'
        raise AssertionError(args)

    def test_scoped_adaptation_preserves_all_other_source_lines(self):
        runtime, token = s.adapt(ORIGINAL, self.database)
        self.assertEqual(token, 'PRIVATE_FIXTURE_KEY')
        before, after = ORIGINAL.decode().splitlines(), runtime.decode().splitlines()
        changed = [(old.split('=', 1)[0], new) for old, new in zip(before, after, strict=True) if old != new]
        self.assertEqual([key for key, value in changed], ['DB', 'KUMA_URL', 'LOG'])
        self.assertIn(b'THRESHOLD_MINUTES=60\nSTOP_NZBDAV=0\n', runtime)
        self.assertIn(b'http://192.168.0.220:3001/api/push/PRIVATE_FIXTURE_KEY', runtime)

    def test_changed_source_or_stop_policy_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'identity'):
            s.adapt(ORIGINAL + b'\n', self.database)
        changed = ORIGINAL.replace(b'STOP_NZBDAV=0', b'STOP_NZBDAV=1')
        with patch.object(s, 'SOURCE_SHA', s.digest(changed)), self.assertRaisesRegex(RuntimeError, 'policy'):
            s.adapt(changed, self.database)

    def test_invalid_endpoint_and_shell_path_are_rejected(self):
        for target in (b'192.168.0.99', b'192.168.0.29:3001@attacker.invalid'):
            changed = ORIGINAL.replace(b'192.168.0.29', target)
            with self.subTest(target=target), patch.object(s, 'SOURCE_SHA', s.digest(changed)), self.assertRaises(RuntimeError):
                s.adapt(changed, self.database)
        with self.assertRaisesRegex(RuntimeError, 'unsafe'):
            s.adapt(ORIGINAL, Path('/tmp/$(bad)/db.sqlite'))

    def test_prepares_disabled_timer_and_read_only_plan_without_database_changes(self):
        before = (self.database.read_bytes(), self.kuma.read_bytes())
        s.prepare(CODE)
        self.assertEqual(self.helper.read_bytes(), CODE)
        self.assertEqual((self.data / 'original.sh').read_bytes(), ORIGINAL)
        self.assertEqual(before, (self.database.read_bytes(), self.kuma.read_bytes()))
        self.assertIn('OnCalendar=*-*-* *:0/15:00 Europe/London', self.timer.read_text())
        self.assertIn('SuccessExitStatus=2', self.unit.read_text())
        self.assertFalse(any('start' in call or 'enable' in call or 'stop' in call or 'restart' in call or call[0] in ('curl', 'rclone') for call in self.calls))
        self.assertNotIn('PRIVATE_FIXTURE_KEY', self.output.getvalue())
        self.assertIn('"pushRequestSent": false', self.output.getvalue())
        self.assertIn('timer disabled', self.output.getvalue())

    def test_preparation_retry_preserves_existing_payload_inodes(self):
        s.prepare(CODE)
        paths = [self.helper, self.unit, self.timer, *(self.data / name for name in ('original.sh', 'runtime.sh', 'prepared.json'))]
        before = {path: (path.read_bytes(), path.stat().st_ino) for path in paths}
        s.prepare(CODE)
        self.assertEqual(before, {path: (path.read_bytes(), path.stat().st_ino) for path in paths})

    def test_missing_kuma_monitor_stops_before_install(self):
        with contextlib.closing(sqlite3.connect(self.kuma)) as db, db:
            db.execute('DELETE FROM monitor')
        with self.assertRaisesRegex(RuntimeError, 'Kuma push monitor'):
            s.prepare(CODE)
        self.assertFalse(self.helper.exists())
        self.assertFalse(self.data.exists())

    def test_missing_executable_is_named_before_any_install(self):
        original = self.query
        def query(*args, **kwargs):
            if args == ('/usr/bin/which', 'sqlite3'):
                raise RuntimeError('not found')
            return original(*args, **kwargs)
        with patch.object(s, 'run', side_effect=query), self.assertRaisesRegex(RuntimeError, 'needs the sqlite3 command'):
            s.prepare(CODE)
        self.assertFalse(self.helper.exists())
        self.assertFalse(self.data.exists())

    def test_running_dependencies_and_paused_units_are_required(self):
        self.running = False
        with self.assertRaisesRegex(RuntimeError, 'dependencies'):
            s.prepare(CODE)
        self.running = True
        self.enabled = True
        with self.assertRaisesRegex(RuntimeError, 'active, enabled'):
            s.prepare(CODE)
        self.assertFalse(self.data.exists())

    def test_foreign_files_and_modified_runtime_are_retained(self):
        self.data.mkdir(parents=True)
        foreign = self.data / 'keep-me'
        foreign.write_text('retain')
        with self.assertRaisesRegex(RuntimeError, 'Unrecognized'):
            s.prepare(CODE)
        self.assertEqual(foreign.read_text(), 'retain')
        foreign.unlink()
        s.prepare(CODE)
        (self.data / 'runtime.sh').write_text('retain changed runtime')
        with self.assertRaisesRegex(RuntimeError, 'differs'):
            s.staged()
        with self.assertRaisesRegex(RuntimeError, 'differs'):
            s.prepare(CODE)

    def test_read_only_plan_reports_stuck_queue_without_titles_or_key(self):
        created = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=61)).strftime('%Y-%m-%d %H:%M:%S')
        with contextlib.closing(sqlite3.connect(self.database)) as db, db:
            db.execute('INSERT INTO QueueItems VALUES(?,?)', ('PRIVATE_JOB_TITLE', created))
        s.prepare(CODE)
        with patch.object(s.os, 'geteuid', return_value=0), patch.object(s.sys, 'argv', ['helper', '--plan']):
            s.main()
        self.assertIn('"stuckByOriginalRule": true', self.output.getvalue())
        self.assertNotIn('PRIVATE_JOB_TITLE', self.output.getvalue())
        self.assertNotIn('PRIVATE_FIXTURE_KEY', self.output.getvalue())

    def test_malformed_queue_timestamp_fails_before_install(self):
        with contextlib.closing(sqlite3.connect(self.database)) as db, db:
            db.execute('INSERT INTO QueueItems VALUES(?,?)', ('Title', 'bad-date'))
        with self.assertRaisesRegex(RuntimeError, 'timestamp'):
            s.prepare(CODE)
        self.assertFalse(self.data.exists())

    def test_run_revalidates_runtime_but_leaves_missing_database_handling_to_original(self):
        s.prepare(CODE)
        self.database.unlink()
        with patch.object(s.os, 'geteuid', return_value=0), patch.object(s.sys, 'argv', ['helper', '--run']), \
                patch.object(s, 'inspect_databases') as check, patch.object(s.subprocess, 'run', return_value=subprocess.CompletedProcess([], 2)) as command, \
                self.assertRaises(SystemExit) as error:
            s.main()
        self.assertEqual(error.exception.code, 2)
        check.assert_not_called()
        self.assertEqual(command.call_args.args[0], ['/usr/bin/bash', str(self.data / 'runtime.sh')])

    def test_symlink_and_staged_path_escape_are_rejected(self):
        s.prepare(CODE)
        path = self.data / 'prepared.json'
        record = json.loads(path.read_text())
        record['database'] = '/another/database/db.sqlite'
        path.write_text(json.dumps(record))
        with self.assertRaisesRegex(RuntimeError, 'outside'):
            s.staged()
        path.unlink()
        path.symlink_to(self.helper)
        with self.assertRaisesRegex(RuntimeError, 'symbolic'):
            s.staged()

    def test_source_snapshot_identity_is_checked(self):
        folder = self.base / 'snapshots/20261107T003613Z'
        (folder / 'data/host.scripts').mkdir(parents=True)
        meta = {'format': s.FORMAT, 'createdUtc': folder.name, 'sha256': 'a' * 64}
        (self.base / 'current.json').write_text(json.dumps({**meta, 'snapshot': str(folder)}))
        (folder / '_VERIFIED.json').write_text(json.dumps(meta))
        (folder / 'manifest.json').write_text(json.dumps({**meta, 'scope': 'standby-only', 'sourceHost': '192.168.0.29',
            'dataRoots': {'host.scripts': {'snapshot': 'data/host.scripts'}}}))
        (folder / 'data/host.scripts/flora-nzbdav-watch.sh').write_bytes(ORIGINAL)
        self.assertEqual(REAL_SOURCE_FILE(), (ORIGINAL, folder.name))
        (folder / '_VERIFIED.json').write_text('{}')
        with self.assertRaisesRegex(RuntimeError, 'verification'):
            REAL_SOURCE_FILE()

    def test_held_backup_lock_stops_before_staging(self):
        with self.lock.open('rb') as lock, patch.object(s.os, 'geteuid', return_value=0), patch.object(s.sys, 'argv', ['helper']):
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(RuntimeError, 'busy'):
                s.main()
        self.assertFalse(self.data.exists())

    def test_log_symlink_is_retained_and_never_followed(self):
        self.data.mkdir(parents=True)
        target = self.root / 'outside-log'
        target.write_text('retain outside')
        (self.data / 'flora-nzbdav-watch.log').symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, 'symbolic'):
            s.prepare(CODE)
        self.assertEqual(target.read_text(), 'retain outside')
        self.assertFalse(self.helper.exists())

    def test_prepared_unit_and_calendar_pass_systemd_syntax_checks(self):
        s.prepare(CODE)
        result = subprocess.run(['systemd-analyze', 'verify', '--man=no', str(self.unit), str(self.timer)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run(['systemd-analyze', 'calendar', '--iterations=1', '*-*-* *:0/15:00 Europe/London'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
