"""Read-only staging audit: preserve WAL state and exclude credentials."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('current_holds', ROOT / 'scripts/inspect-nas-production-holds.py')
a = importlib.util.module_from_spec(spec); spec.loader.exec_module(a)


class CurrentHolds(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.config = self.root / 'appdata/houndarr'; self.config.mkdir(parents=True)
        self.db = self.config / 'houndarr.db'
        self.row = {'Mounts': [{'Type': 'bind', 'Source': str(self.config), 'Destination': '/data'}]}
        p = patch.object(a, 'APP', self.root); p.start(); self.addCleanup(p.stop)

    def create(self, db):
        db.executescript('CREATE TABLE instances(id INTEGER,url TEXT,enabled INTEGER,missing_enabled INTEGER,cutoff_enabled INTEGER,upgrade_enabled INTEGER);'
            "INSERT INTO instances VALUES(1,'http://username:private-password@192.168.0.220:7878/api?apikey=secret',1,0,0,0);")

    def test_instance_enabled_is_distinct_from_all_three_search_modes(self):
        with sqlite3.connect(self.db) as db: self.create(db)
        before = hashlib.sha256(self.db.read_bytes()).hexdigest()
        rows = a.houndarr(self.row)
        self.assertTrue(rows[0]['enabled'])
        for mode in a.FLAGS[1:]: self.assertFalse(rows[0][mode])
        self.assertEqual(rows[0]['endpoint'], 'http://192.168.0.220:7878')
        self.assertNotIn('secret', json.dumps(rows)); self.assertNotIn('private-password', json.dumps(rows))
        self.assertEqual(before, hashlib.sha256(self.db.read_bytes()).hexdigest())

    def test_live_wal_changes_are_visible_without_checkpointing_or_writes(self):
        db = sqlite3.connect(self.db)
        try:
            db.execute('PRAGMA journal_mode=WAL'); db.execute('PRAGMA wal_autocheckpoint=0'); self.create(db); db.commit()
            db.execute('UPDATE instances SET missing_enabled=1'); db.commit()
            wal = Path(str(self.db) + '-wal'); before = wal.read_bytes()
            self.assertTrue(a.houndarr(self.row)[0]['missing_enabled'])
            self.assertEqual(before, wal.read_bytes())
        finally: db.close()

    def test_read_only_connection_refuses_writes(self):
        with sqlite3.connect(self.db) as db: self.create(db)
        with a.database(self.row, ('houndarr.db',)) as db:
            with self.assertRaises(sqlite3.OperationalError): db.execute('UPDATE instances SET enabled=0')

    def test_ambiguous_current_database_binding_is_rejected(self):
        with sqlite3.connect(self.db) as db: self.create(db)
        other = self.root / 'appdata/other'; other.mkdir(); (other / 'houndarr.db').write_bytes(self.db.read_bytes())
        self.row['Mounts'].append({'Type': 'bind', 'Source': str(other), 'Destination': '/other'})
        with self.assertRaises(RuntimeError): a.houndarr(self.row)

    def test_environment_report_prints_only_requested_flags_and_hides_unknown_values(self):
        row = {'Config': {'Env': ['API_TOKEN=private-value', 'FLASK_SKIP_SCHEDULER=true',
                                 'WIZARR_DISABLE_SCHEDULER=unexpected-secret', 'SPEEDTEST_SCHEDULE=']}}
        result = a.environment_flags(row, ('FLASK_SKIP_SCHEDULER', 'WIZARR_DISABLE_SCHEDULER', 'SPEEDTEST_SCHEDULE'))
        self.assertEqual(result['FLASK_SKIP_SCHEDULER'], 'true')
        self.assertEqual(result['SPEEDTEST_SCHEDULE'], 'blank/disabled')
        self.assertNotIn('private-value', json.dumps(result)); self.assertNotIn('unexpected-secret', json.dumps(result))


if __name__ == '__main__': unittest.main()
