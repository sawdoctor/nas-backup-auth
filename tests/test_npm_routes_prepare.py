import contextlib
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'scripts'
if not SCRIPTS.is_dir():
    SCRIPTS = ROOT / 'nas-backup-auth/scripts'
spec = importlib.util.spec_from_file_location('npm_routes_prepare', SCRIPTS / 'prepare-nas-npm-routes.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


def database(path, populated):
    path.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.closing(sqlite3.connect(path)) as db, db:
        db.execute('CREATE TABLE proxy_host(id INTEGER PRIMARY KEY,is_deleted INTEGER,enabled INTEGER,domain_names TEXT,forward_scheme TEXT,forward_host TEXT,forward_port INTEGER,advanced_config TEXT,certificate_id INTEGER,access_list_id INTEGER)')
        for table in ('certificate', 'access_list', 'dead_host', 'redirection_host', 'stream'):
            db.execute('CREATE TABLE ' + table + '(id INTEGER PRIMARY KEY,is_deleted INTEGER,private_value TEXT)')
        db.execute('CREATE TABLE user(id INTEGER PRIMARY KEY,email TEXT,password TEXT)')
        db.execute("INSERT INTO user VALUES(1,'PRIVATE_EMAIL','PRIVATE_PASSWORD')")
        if populated:
            seq = 0
            for domain, (_, port) in s.TARGETS.items():
                seq += 1
                host = 'usenet-ultimate' if domain == 'usenet' else '192.168.0.29'
                db.execute('INSERT INTO proxy_host VALUES(?,0,1,?,?,?,?,?,6,5)',
                           (seq, json.dumps([domain + s.SUFFIX]), 'http', host, port, 'PRIVATE_CUSTOM_CONFIG'))
            for domain, (scheme, port) in s.EXISTING_NAS.items():
                seq += 1
                db.execute('INSERT INTO proxy_host VALUES(?,0,1,?,?,?,?,?,6,5)',
                           (seq, json.dumps([domain + s.SUFFIX]), scheme, '192.168.0.220', port, 'PRIVATE_CUSTOM_CONFIG'))
            for domain, port in s.KEEP_SOURCE.items():
                seq += 1
                db.execute('INSERT INTO proxy_host VALUES(?,0,1,?,?,?,?,?,6,5)',
                           (seq, json.dumps([domain + s.SUFFIX]), 'http', '192.168.0.29', port, 'PRIVATE_CUSTOM_CONFIG'))
            db.execute("INSERT INTO proxy_host VALUES(99,1,0,'[\"deleted.invalid\"]','http','192.168.0.29',999,'PRIVATE_DELETED_CONFIG',0,0)")
            db.execute("INSERT INTO certificate VALUES(6,0,'PRIVATE_CERT_METADATA')")
            db.execute("INSERT INTO access_list VALUES(5,0,'PRIVATE_ACL_PASSWORD_HASH')")


class RoutePlanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app, self.backup = self.root / 'app', self.root / 'backup'
        self.base = self.backup / 'migration/nightly-standby'
        self.stamp = '20261107T003613Z'
        self.snapshot = self.base / 'snapshots' / self.stamp
        self.snapshot.mkdir(parents=True)
        self.path = self.snapshot / 'data/npm-data/database.sqlite'
        database(self.path, True)
        self.live = self.app / 'appdata/npm/data/database.sqlite'
        database(self.live, False)
        metadata = {'format': s.FORMAT, 'createdUtc': self.stamp, 'sha256': 'a' * 64}
        (self.snapshot / '_VERIFIED.json').write_text(json.dumps(metadata))
        (self.base / 'current.json').write_text(json.dumps({**metadata, 'snapshot': str(self.snapshot)}))
        self.manifest = self.snapshot / 'manifest.json'
        self.manifest.write_text(json.dumps({'format': s.FORMAT, 'sourceHost': '192.168.0.29',
            'scope': 'standby-only', 'createdUtc': self.stamp,
            'dataRoots': {'npm-data': {'snapshot': 'data/npm-data'}},
            'containers': [{'Name': '/npm-app-1', 'Image': s.SOURCE_IMAGE}]}))
        self.checksums()
        self.lock = self.root / 'backup.lock'
        self.lock.touch()
        (self.base / '.run.lock').touch()
        self.work = self.app / 'compose/npm-restore/route-plan'
        self.calls = []
        self.bad_port = False
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.output = self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.stack.enter_context(patch.multiple(s, APP=self.app, BACKUP=self.backup, BASE=self.base,
                                              WORK=self.work, LOCK=self.lock))
        self.stack.enter_context(patch.object(s.os, 'geteuid', return_value=0))
        self.stack.enter_context(patch.object(Path, 'is_mount', return_value=True))
        self.stack.enter_context(patch.object(s, 'run', side_effect=self.query))

    def checksums(self):
        (self.snapshot / 'SHA256SUMS').write_text(''.join(
            hashlib.sha256(path.read_bytes()).hexdigest() + '  ./' + str(path.relative_to(self.snapshot)) + '\n'
            for path in (self.manifest, self.path)))

    def query(self, *args, **kw):
        self.calls.append(args)
        if args[0] == 'ip':
            return 'inet 192.168.0.220/24'
        if args[0] == 'findmnt':
            return (s.APP_UUID if args[3] == str(self.app) else s.BACKUP_UUID) + ' ext4\n'
        if args[:2] == ('docker', 'inspect'):
            records = []
            for name in args[2:]:
                ports = {str(port) + '/tcp': [{'HostIp': '192.168.0.220', 'HostPort': str(port)}]
                         for container, port in s.TARGETS.values() if container == name}
                if self.bad_port and name == 'radarr4k-nas':
                    ports = {}
                records.append({'Name': '/' + name, 'Id': 'ID-' + name,
                    'State': {'Status': 'running'}, 'HostConfig': {'NetworkMode': 'host' if name == 'fail2ban-ui' else 'bridge', 'PortBindings': ports},
                    'Mounts': [{'Destination': '/data', 'Type': 'bind', 'Source': str(self.live.parent)}] if name == 'npm-nas' else []})
            return json.dumps(records)
        if args[0] == 'ss':
            return 'LISTEN 0 4096 192.168.0.220:3091 0.0.0.0:*\n'
        raise AssertionError('Unexpected host mutation/query: ' + repr(args))

    def test_real_sqlite_proposal_changes_only_21_hosts_and_preserves_private_state(self):
        original, live = self.path.read_bytes(), self.live.read_bytes()
        s.stage()
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(self.live.read_bytes(), live)
        plan = json.loads((self.work / 'plan.json').read_text())
        self.assertEqual(len(plan['changes']), 21)
        self.assertEqual(len(plan['alreadyNas']), 3)
        self.assertEqual(len(plan['retainedOptiplex']), 6)
        self.assertEqual(plan['sourceSnapshot'], self.stamp)
        self.assertFalse(plan['certificateAndSigningKeyFilesIncluded'])
        self.assertEqual((self.work / 'database.sqlite').stat().st_mode & 0o777, 0o600)
        with contextlib.closing(sqlite3.connect(self.work / 'database.sqlite')) as candidate:
            self.assertEqual(candidate.execute('SELECT password FROM user').fetchone()[0], 'PRIVATE_PASSWORD')
            self.assertEqual(candidate.execute('SELECT forward_host FROM proxy_host WHERE id=99').fetchone()[0], '192.168.0.29')
            self.assertEqual(candidate.execute("SELECT forward_host FROM proxy_host WHERE domain_names='[\"dockhand.sawdoctor.uk\"]'").fetchone()[0], '192.168.0.29')
        self.assertNotIn('PRIVATE_', self.output.getvalue())
        self.assertNotIn('PRIVATE_', (self.work / 'plan.json').read_text())
        self.assertFalse(any(c[0] not in {'ip', 'findmnt', 'docker', 'ss'} for c in self.calls))

    def test_modified_source_checksum_stops_before_writes(self):
        with contextlib.closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE user SET password='CHANGED'")
        with self.assertRaisesRegex(RuntimeError, 'checksum differs'):
            s.stage()
        self.assertFalse(self.work.exists())

    def test_changed_source_route_set_requires_review(self):
        with contextlib.closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE proxy_host SET domain_names='[\"different.sawdoctor.uk\"]' WHERE id=1")
        self.checksums()
        with self.assertRaisesRegex(RuntimeError, 'route set changed'):
            s.stage()
        self.assertFalse(self.work.exists())

    def test_wrong_target_port_stops_before_writes(self):
        self.bad_port = True
        with self.assertRaisesRegex(RuntimeError, 'published port differs'):
            s.stage()
        self.assertFalse(self.work.exists())

    def test_live_nas_routes_require_merge_review(self):
        with contextlib.closing(sqlite3.connect(self.live)) as db, db:
            db.execute("INSERT INTO proxy_host VALUES(1,0,1,'[\"nas-only.sawdoctor.uk\"]','http','127.0.0.1',1,'PRIVATE',0,0)")
        with self.assertRaisesRegex(RuntimeError, 'records to preserve'):
            s.stage()
        self.assertFalse(self.work.exists())

    def test_unexpected_values_in_other_tables_are_detected(self):
        original_compare = s.compare_all
        def corrupt(original, candidate, changes):
            candidate.execute("UPDATE user SET password='CORRUPTED'")
            original_compare(original, candidate, changes)
        with patch.object(s, 'compare_all', side_effect=corrupt):
            with self.assertRaisesRegex(RuntimeError, 'outside its 21'):
                s.stage()
        self.assertFalse(self.work.exists())

    def test_repeat_keeps_only_one_proposal_and_rejects_manual_edits(self):
        s.stage()
        first = (self.work / 'database.sqlite').read_bytes()
        s.stage()
        self.assertEqual((self.work / 'database.sqlite').read_bytes(), first)
        self.assertEqual({p.name for p in self.work.iterdir()}, {'database.sqlite', 'plan.json'})
        (self.work / 'database.sqlite').write_bytes(b'edited')
        with self.assertRaisesRegex(RuntimeError, 'was edited'):
            s.stage()
        self.assertEqual((self.work / 'database.sqlite').read_bytes(), b'edited')

    def test_symbolic_or_foreign_plan_is_preserved(self):
        self.work.mkdir(parents=True)
        (self.work / 'unrelated').write_text('retained')
        with self.assertRaisesRegex(RuntimeError, 'unexpected files'):
            s.stage()
        self.assertEqual((self.work / 'unrelated').read_text(), 'retained')
        protected = self.root / 'protected'
        protected.mkdir()
        linked = self.root / 'link'
        linked.symlink_to(protected)
        with patch.object(s, 'WORK', linked):
            with self.assertRaisesRegex(RuntimeError, 'symbolic'):
                s.stage()
        self.assertFalse(list(protected.iterdir()))

    def test_active_backup_lock_stops_preparation(self):
        with self.lock.open('rb') as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(RuntimeError, 'busy'):
                s.stage()
        self.assertFalse(self.work.exists())


if __name__ == '__main__':
    unittest.main()
