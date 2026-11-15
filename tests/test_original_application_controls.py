"""Original control provenance, WAL visibility and credential suppression."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/inspect-nas-original-application-controls.py'
spec = importlib.util.spec_from_file_location('original_application_controls', SCRIPT)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


def connection():
    db = sqlite3.connect(':memory:'); db.row_factory = sqlite3.Row
    return db


class OriginalControlsTests(unittest.TestCase):
    def test_original_modes_and_manual_instance_enable_are_distinct(self):
        with connection() as old, connection() as live:
            for db in (old, live):
                db.execute('CREATE TABLE instances(id INTEGER,url TEXT,enabled INTEGER,missing_enabled INTEGER,cutoff_enabled INTEGER,upgrade_enabled INTEGER)')
            old.execute('INSERT INTO instances VALUES(1,?,0,1,0,1)', ('http://192.168.0.29:7879',))
            live.execute('INSERT INTO instances VALUES(1,?,1,0,0,0)', ('http://radarr4k:7878',))
            value = m.houndarr(old, live)
            self.assertTrue(value['preserveCurrentInstanceEnables'])
            self.assertTrue(value['instances'][0]['sameInstance'])
            self.assertEqual(value['instances'][0]['source'], dict(enabled=False, missing_enabled=True, cutoff_enabled=False, upgrade_enabled=True))
            self.assertTrue(value['instances'][0]['current']['enabled'])
            live.execute('UPDATE instances SET url="http://sonarr:8989"')
            self.assertFalse(m.houndarr(old, live)['instances'][0]['sameInstance'])

    def test_kuma_preserves_original_pauses_links_and_hides_credentials(self):
        with connection() as old, connection() as live:
            for db in (old, live):
                db.executescript('''CREATE TABLE monitor(id INTEGER,name TEXT,type TEXT,active INTEGER,url TEXT,hostname TEXT,port INTEGER);
                    CREATE TABLE notification(id INTEGER,active INTEGER,is_default INTEGER,name TEXT,config TEXT);
                    CREATE TABLE monitor_notification(monitor_id INTEGER,notification_id INTEGER);''')
                db.execute('INSERT INTO notification VALUES(1,0,0,"Telegram",?)', ('SECRET-TOKEN',))
            old.executemany('INSERT INTO monitor VALUES(?,?,?,?,?,?,?)', [(1,'Arr','http',1,'http://192.168.0.29:7878',None,None), (2,'Paused','http',0,'https://example.com',None,None)])
            live.executemany('INSERT INTO monitor VALUES(?,?,?,?,?,?,?)', [(1,'Arr','http',0,'http://192.168.0.220:7878',None,None), (2,'Paused','http',0,'https://example.com',None,None)])
            old.execute('UPDATE notification SET active=1,is_default=1')
            old.execute('INSERT INTO monitor_notification VALUES(1,1)')
            value = m.kuma(old, live)
            self.assertEqual(value['sourceActiveMonitorIds'], [1])
            self.assertEqual(value['currentActiveMonitorIds'], [])
            self.assertEqual(value['sourceLinks'], [(1,1)])
            self.assertEqual(value['currentLinks'], [])
            self.assertEqual(value['monitorIdentityMismatchIds'], [])
            self.assertNotIn('SECRET-TOKEN', json.dumps(value))
            live.execute('UPDATE notification SET config="changed secret"')
            self.assertEqual(m.kuma(old, live)['notificationIdentityMismatchIds'], [1])

    def test_read_only_wal_snapshot_includes_committed_rows_and_refuses_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'houndarr.db'
            with sqlite3.connect(path) as writer:
                writer.execute('PRAGMA journal_mode=WAL'); writer.execute('PRAGMA wal_autocheckpoint=0')
                writer.execute('CREATE TABLE sample(value INTEGER)'); writer.commit()
                writer.execute('INSERT INTO sample VALUES(17)'); writer.commit()
                before = (path.read_bytes(), Path(str(path) + '-wal').read_bytes())
                with m.database(path) as reader:
                    self.assertEqual(reader.execute('SELECT value FROM sample').fetchone()[0], 17)
                    with self.assertRaises(sqlite3.OperationalError): reader.execute('INSERT INTO sample VALUES(18)')
                self.assertEqual(before, (path.read_bytes(), Path(str(path) + '-wal').read_bytes()))

    def test_original_archive_fallback_checks_members_and_each_frozen_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); raw = root / 'raw'; raw.mkdir()
            folder = root / 'private'; folder.mkdir()
            archive = root / 'migration/production-handover/frozen/cutover/export.tar.zst'
            archive.parent.mkdir(parents=True); archive.write_bytes(b'original-zstd')
            bodies = {'data/support.' + name + '/' + relative: ('original-' + name).encode()
                      for name, relative in m.DATABASES.items()}
            bodies['data/support.houndarr/houndarr.db-wal'] = b'original-WAL'
            checks = {name: hashlib.sha256(body).hexdigest() for name, body in bodies.items()}
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode='w') as tar:
                for name, body in bodies.items():
                    info = tarfile.TarInfo('./' + name); info.size = len(body)
                    tar.addfile(info, io.BytesIO(body))
            class Process:
                def __init__(self, *args, **kwargs): self.stdout = io.BytesIO(buffer.getvalue())
                def poll(self): return 0
            native = SimpleNamespace(BACKUP=root, safe=lambda path: None, digest=lambda path: hashlib.sha256(path.read_bytes()).hexdigest())
            proof = dict(cutoverId='cutover', archiveBytes=len(b'original-zstd'))
            with patch.object(m.subprocess, 'Popen', Process):
                selected = m.frozen_databases(native, raw, proof, checks, folder)
            self.assertEqual(selected['houndarr'].read_bytes(), b'original-houndarr')
            self.assertEqual(Path(str(selected['houndarr']) + '-wal').read_bytes(), b'original-WAL')
            with self.assertRaises(RuntimeError):
                m.copy_member(io.BytesIO(b'bad'), folder / 'bad.db', 3, hashlib.sha256(b'good').hexdigest())

    def test_no_unreviewed_schedule_or_arr_credentials_are_disclosed(self):
        row = {'Config': {'Env': ['SPEEDTEST_SCHEDULE=0 */4 * * *', 'PASSWORD=SECRET-TOKEN']}}
        self.assertEqual(m.environment(row, True), {'SPEEDTEST_SCHEDULE': '0 */4 * * *'})
        row['Config']['Env'] = ['SPEEDTEST_SCHEDULE=SECRET-TOKEN']
        self.assertNotIn('SECRET-TOKEN', json.dumps(m.environment(row, True)))
        with self.assertRaises(RuntimeError): m.arr_identity('http://radarr:7878/?apiKey=SECRET-TOKEN')
        with self.assertRaises(RuntimeError): m.flag('false')


if __name__ == '__main__': unittest.main()
