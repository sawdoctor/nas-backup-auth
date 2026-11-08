import contextlib
import importlib.util
import json
import os
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
spec = importlib.util.spec_from_file_location('npm_live_refresh', SCRIPTS / 'export-optiplex-npm-refresh.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_online_sqlite_backup_includes_wal_without_stopping_writer(self):
        source = self.root / 'live.sqlite'
        with contextlib.closing(sqlite3.connect(source)) as live:
            live.execute('PRAGMA journal_mode=WAL')
            live.execute('CREATE TABLE settings(id INTEGER PRIMARY KEY,value)')
            live.execute('INSERT INTO settings VALUES(1,?)', ('PRIVATE_CREDENTIAL',)); live.commit()
            self.assertTrue(Path(str(source)+'-wal').exists())
            first = self.root/'first.sqlite'
            fingerprint = s.snapshot_database(source, first)
            self.assertEqual(s.snapshot_database(source, self.root/'second.sqlite'), fingerprint)
            with contextlib.closing(sqlite3.connect(first)) as copied:
                self.assertEqual(copied.execute('SELECT value FROM settings').fetchone(), ('PRIVATE_CREDENTIAL',))
            live.execute('UPDATE settings SET value=?', ('NEW_SECRET',)); live.commit()
            self.assertNotEqual(s.snapshot_database(source, self.root/'third.sqlite'), fingerprint)
        self.assertFalse(Path(str(first)+'-wal').exists())
        self.assertFalse(Path(str(first)+'-journal').exists())

    def test_fixed_read_requests_preserve_old_routes_and_cannot_execute_arguments(self):
        original = '#!/bin/sh\ncase "${SSH_ORIGINAL_COMMAND-}" in\n old) printf OLD ;;\n *) printf DENIED; exit 1 ;;\nesac\n'
        with patch.object(s, 'OUTPUT', self.root):
            reader = s.reader_text(original)
            self.assertEqual(s.reader_text(reader), reader)
        (self.root/'ready.json').write_text('PRIVATE_METADATA')
        subprocess.run(['sh','-n'], input=reader.encode(), check=True, capture_output=True)
        def request(value):
            return subprocess.run(['sh'], input=reader.encode(), capture_output=True,
                                  env={**os.environ,'SSH_ORIGINAL_COMMAND':value})
        self.assertEqual(request('old').stdout,b'OLD')
        self.assertEqual(request('npm-refresh-ready').stdout,b'PRIVATE_METADATA')
        malicious = 'npm-refresh-ready; touch ' + str(self.root/'should-not-exist')
        self.assertEqual(request(malicious).returncode,1)
        self.assertFalse((self.root/'should-not-exist').exists())
        self.assertIn(original.split('\n',1)[1],reader)
        with patch.object(s,'OUTPUT',self.root/'changed'):
            with self.assertRaisesRegex(RuntimeError,'routes differ'):
                s.reader_text(reader)

    def test_preflight_skips_only_live_db_and_logs_but_bounds_custom_files(self):
        data=self.root/'data'; data.mkdir(); (data/'logs').mkdir()
        with (data/'logs/large.log').open('wb') as stream: stream.truncate(s.LIMIT*2)
        with (data/'database.sqlite').open('wb') as stream: stream.truncate(s.LIMIT*2)
        (data/'keys.json').write_text('PRIVATE_KEYS')
        (data/'nginx').mkdir(); (data/'nginx/custom').mkdir()
        (data/'nginx/custom/private.conf').write_text('PRIVATE_CUSTOM')
        self.assertEqual(s.source_size(data,True),len('PRIVATE_KEYSPRIVATE_CUSTOM'))
        with (data/'custom-large').open('wb') as stream: stream.truncate(s.LIMIT+1)
        with self.assertRaisesRegex(RuntimeError,'copy bound'):
            s.source_size(data,True)

    def test_archive_preserves_metadata_safe_links_and_private_xattrs(self):
        payload=self.root/'payload'; payload.mkdir(); (payload/'data').mkdir()
        file=payload/'data/private'; file.write_text('PRIVATE');file.chmod(0o640)
        os.setxattr(file,'user.npm-test',b'PRIVATE_ATTRIBUTE')
        os.utime(file,ns=(1700000000123456789,1700000000123456789))
        (payload/'data/relative').symlink_to('private')
        expected=s.inventory(payload)
        archive=self.root/'archive.tar.gz'
        subprocess.run(['tar','--acls','--xattrs','--numeric-owner','-czpf',str(archive),'-C',str(self.root),'payload'],check=True,capture_output=True)
        restored=self.root/'restored';restored.mkdir()
        subprocess.run(['tar','--acls','--xattrs','--numeric-owner','-xzpf',str(archive),'-C',str(restored)],check=True,capture_output=True)
        self.assertEqual(s.inventory(restored/'payload'),expected)
        (payload/'data/escape').symlink_to(self.root/'outside')
        with self.assertRaisesRegex(RuntimeError,'escapes'):
            s.inventory(payload)


class PolicyAndCertificateTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name); self.payload=self.root/'payload';self.payload.mkdir()
        data=self.payload/'data'; data.mkdir();self.database=data/'database.sqlite'
        self.certdir=self.payload/'letsencrypt/live/npm-99';self.certdir.mkdir(parents=True)
        with contextlib.closing(sqlite3.connect(self.database)) as db, db:
            db.execute('CREATE TABLE proxy_host(id,domain_names,certificate_id,enabled,is_deleted)')
            db.execute('CREATE TABLE certificate(id,provider,is_deleted)')
            for table in ('access_list','user','redirection_host','dead_host','stream'):
                db.execute('CREATE TABLE '+table+'(id,is_deleted)')
            db.execute('INSERT INTO certificate VALUES(99,"letsencrypt",0)')
            db.execute('INSERT INTO proxy_host VALUES(32,?,99,1,0)', ('["shelfmark-audio.sawdoctor.uk"]',))
        self.make_certificate('shelfmark-audio.sawdoctor.uk')
        self.ca=patch.object(s,'CA_FILE',str(self.certdir/'fullchain.pem'));self.ca.start();self.addCleanup(self.ca.stop)

    def make_certificate(self,name):
        subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1',
                        '-nodes','-days','1','-subj','/CN='+name,'-addext','subjectAltName=DNS:'+name,
                        '-keyout',str(self.certdir/'privkey.pem'),'-out',str(self.certdir/'fullchain.pem')],
                       check=True,capture_output=True)

    def test_corrected_shelfmark_hostname_and_matching_key_pass(self):
        counts,shelfmark,number=s.validate_policy(self.database,self.payload)
        self.assertEqual(counts['proxy_host'],1)
        self.assertEqual(shelfmark,{'proxyId':32,'certificateId':99,'enabled':1})
        self.assertEqual(number,1)

    def test_old_shelfmark_hostname_is_rejected_even_if_valid_and_trusted(self):
        self.make_certificate('shelfmark.sawdoctor.uk')
        with self.assertRaisesRegex(RuntimeError,'does not validate for shelfmark-audio'):
            s.validate_policy(self.database,self.payload)

    def test_wrong_private_key_is_rejected(self):
        subprocess.run(['openssl','genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:prime256v1',
                        '-out',str(self.certdir/'privkey.pem')],check=True,capture_output=True)
        with self.assertRaisesRegex(RuntimeError,'private key differ'):
            s.validate_policy(self.database,self.payload)

    def test_retired_routes_cannot_be_reintroduced(self):
        for domain in ('chaptarr.sawdoctor.uk','soundspan.sawdoctor.uk'):
            with contextlib.closing(sqlite3.connect(self.database)) as db, db:
                db.execute('DELETE FROM proxy_host WHERE id=27')
                db.execute('INSERT INTO proxy_host VALUES(27,?,99,1,0)',(json.dumps([domain]),))
            with self.assertRaisesRegex(RuntimeError,'retired Soundspan/Chaptarr'):
                s.validate_policy(self.database,self.payload)
        with contextlib.closing(sqlite3.connect(self.database)) as db, db:
            db.execute('UPDATE proxy_host SET is_deleted=1 WHERE id=27')
        self.assertEqual(s.validate_policy(self.database,self.payload)[0]['proxy_host'],1)


if __name__=='__main__':
    unittest.main()
