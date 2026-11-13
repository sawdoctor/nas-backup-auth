"""Production policy preservation and path fences using realistic SQLite fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('policy', ROOT / 'scripts/production-core-policy.py')
s = importlib.util.module_from_spec(spec); spec.loader.exec_module(s)


class ProductionPolicy(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'private'
        self.root.mkdir()
        self.keys = {n: n + '-source-key' for n in ('sonarr', 'radarr', 'radarr4k', 'prowlarr')}
        self.infini = {'apiKey': 'nas-api-key', 'user': 'nas-media', 'password': 'nas-webdav-password'}

    def database(self):
        path = self.root / 'arr.db'
        with sqlite3.connect(path) as db:
            db.execute('CREATE TABLE Config (Key TEXT, Value TEXT)')
            db.execute("INSERT INTO Config VALUES ('RssSyncInterval','15')")
            for table in s.CONNECTION_TABLES:
                db.execute('CREATE TABLE ' + table + ' (Id INTEGER PRIMARY KEY, Name TEXT, Implementation TEXT, Settings TEXT, Enable INTEGER, EnableRss INTEGER, SearchOnAdd INTEGER, SyncLevel INTEGER, OnGrab INTEGER)')
                db.execute('INSERT INTO ' + table + ' VALUES (1,?,?,?,?,1,1,2,1)',
                           ('NZBDAV' if table == 'DownloadClients' else 'Primary',
                            'Sabnzbd' if table == 'DownloadClients' else 'Radarr',
                            json.dumps({'host': 'nzbdav', 'port': 8080, 'apiKey': 'old'}), 1))
            db.execute("INSERT INTO DownloadClients VALUES (2,'Other client','Sabnzbd','{}',1,1,1,2,1)")
            for table in ('PendingReleases', 'Commands', 'History', 'QualityProfiles'):
                db.execute('CREATE TABLE ' + table + ' (Id INTEGER PRIMARY KEY, Status INTEGER, Value TEXT)')
                db.execute('INSERT INTO ' + table + " VALUES (7,0,'retain production state')")
        return path

    def test_arr_keeps_automation_queues_quality_and_other_download_clients(self):
        path = self.database()
        s.patch_arr(self.root, path, 'sonarr', self.keys, s.PORTS, self.infini)
        with sqlite3.connect(path) as db:
            self.assertEqual(db.execute('SELECT * FROM Config').fetchall(), [('RssSyncInterval', '15')])
            for table in ('PendingReleases', 'Commands', 'History', 'QualityProfiles'):
                self.assertEqual(db.execute('SELECT * FROM ' + table).fetchall(), [(7, 0, 'retain production state')])
            for table in s.CONNECTION_TABLES:
                self.assertEqual(db.execute('SELECT Enable,EnableRss,SearchOnAdd,SyncLevel,OnGrab FROM ' + table + ' WHERE Id=1').fetchone(), (1, 1, 1, 2, 1))
            self.assertEqual(db.execute('SELECT Enable FROM DownloadClients WHERE Id=2').fetchone(), (1,))
            settings = json.loads(db.execute('SELECT Settings FROM DownloadClients WHERE Id=1').fetchone()[0])
            self.assertEqual(settings['apiKey'], self.infini['apiKey'])
            app = json.loads(db.execute('SELECT Settings FROM Applications WHERE Id=1').fetchone()[0])
            self.assertEqual(app['baseUrl'], 'http://radarr:7878')

    def test_source_disabled_download_client_remains_disabled(self):
        path = self.database()
        with sqlite3.connect(path) as db:
            db.execute('UPDATE DownloadClients SET Enable=0 WHERE Id=1')
        s.patch_arr(self.root, path, 'radarr', self.keys, s.PORTS, self.infini)
        with sqlite3.connect(path) as db:
            self.assertEqual(db.execute('SELECT Enable FROM DownloadClients WHERE Id=1').fetchone()[0], 0)

    def test_seerr_keeps_watchlists_notifications_and_search_policy(self):
        folder = self.root / 'overseerr'; folder.mkdir()
        value = {'main': {'applicationUrl': 'https://request.sawdoctor.uk'},
                 'plex': {'hostname': s.SOURCE_IP, 'port': 32400, 'machineId': 'same-identity'},
                 'radarr': [{'hostname': s.SOURCE_IP, 'port': 7879, 'is4k': True, 'preventSearch': True}],
                 'notifications': {'agents': {'telegram': {'enabled': True, 'botToken': 'private-test-token'}}}}
        (folder / 'settings.json').write_text(json.dumps(value))
        db_path = folder / 'db.sqlite'
        with sqlite3.connect(db_path) as db:
            db.execute('CREATE TABLE users (watchlistSyncMovies INTEGER, watchlistSyncTv INTEGER)')
            db.execute('INSERT INTO users VALUES (1,1)')
        before = hashlib.sha256(db_path.read_bytes()).hexdigest()
        s.patch_seerr(self.root, folder, self.keys, s.PORTS)
        actual = json.loads((folder / 'settings.json').read_text())
        self.assertTrue(actual['notifications']['agents']['telegram']['enabled'])
        self.assertTrue(actual['radarr'][0]['preventSearch'])
        self.assertEqual(actual['radarr'][0]['hostname'], 'radarr4k')
        self.assertEqual(actual['main'], value['main'])
        self.assertEqual(actual['plex']['hostname'], s.NAS_IP)
        self.assertEqual(actual['plex']['machineId'], 'same-identity')
        self.assertEqual(hashlib.sha256(db_path.read_bytes()).hexdigest(), before)

    def test_ultimate_keeps_health_autoqueue_and_reputation_settings(self):
        folder = self.root / 'ultimate'; folder.mkdir()
        value = {'healthChecks': {'autoQueueMode': 'all', 'enabled': True}, 'reputation': {'minimum': 90}}
        (folder / 'config.json').write_text(json.dumps(value))
        s.patch_ultimate(self.root, folder, self.keys, s.PORTS, self.infini)
        actual = json.loads((folder / 'config.json').read_text())
        self.assertEqual(actual['healthChecks'], value['healthChecks'])
        self.assertEqual(actual['reputation'], value['reputation'])
        self.assertEqual(actual['nzbdavWebdavUser'], 'nas-media')

    def test_infini_preserves_repairs_provider_roles_limits_and_file_ids(self):
        path = self.root / 'infini.db'
        settings = {'queue.paused': 'false', 'repair.enable': 'true',
                    'usenet.providers': json.dumps({'Providers': [{'Type': 2, 'MaxConnections': 16}]}),
                    'arr.instances': json.dumps({'SonarrInstances': [{'Host': 'http://192.168.0.29:8989', 'ApiKey': 'retain'}], 'QueueRules': [{'name': 'retain'}]}),
                    'api.addurl-trusted-hosts': '192.168.0.29,prowlarr'}
        with sqlite3.connect(path) as db:
            db.execute('CREATE TABLE ConfigItems (ConfigName TEXT, ConfigValue TEXT)')
            db.executemany('INSERT INTO ConfigItems VALUES (?,?)', settings.items())
            db.execute('CREATE TABLE DavItems (Id TEXT, FileBlobId TEXT, RepairGeneration INTEGER)')
            db.execute("INSERT INTO DavItems VALUES ('current-id','repaired-blob',9)")
        s.patch_infinidysk(self.root, path)
        with sqlite3.connect(path) as db:
            actual = dict(db.execute('SELECT * FROM ConfigItems'))
            self.assertEqual(db.execute('SELECT * FROM DavItems').fetchall(), [('current-id', 'repaired-blob', 9)])
        for name in ('queue.paused', 'repair.enable', 'usenet.providers'):
            self.assertEqual(actual[name], settings[name])
        arr = json.loads(actual['arr.instances'])
        self.assertEqual(arr['QueueRules'], [{'name': 'retain'}])
        self.assertEqual(arr['SonarrInstances'][0]['Host'], 'http://192.168.0.220:8989')
        self.assertIn(s.NAS_IP, actual['api.addurl-trusted-hosts'])

    def test_runtime_removes_test_overrides_but_preserves_nas_webdav_login(self):
        source = {'NZBDAV_CONFIG__ARR__HEALTH_ENABLED': 'true',
                  'NZBDAV_CONFIG__USENET__PROVIDERS': '{"Providers":[{"Type":2,"MaxConnections":16}]}',
                  'NZBDAV_CONFIG__WEBDAV__USER': 'source-user', 'PUID': '1000'}
        nas = {'NZBDAV_CONFIG__ARR__HEALTH_ENABLED': 'false', 'NZBDAV_CONFIG__REPAIR__ENABLE': 'false',
               'NZBDAV_CONFIG__WEBDAV__USER': 'nas-media', 'NZBDAV_CONFIG__WEBDAV__PASS': 'nas-private-pass',
               'FRONTEND_BACKEND_API_KEY': 'nas-private-key', 'PUID': '1001', 'TMPDIR': '/scratch/tmp'}
        actual = s.runtime_environment('nzbdav', source, nas, self.infini)
        self.assertEqual(actual['NZBDAV_CONFIG__ARR__HEALTH_ENABLED'], 'true')
        self.assertNotIn('NZBDAV_CONFIG__REPAIR__ENABLE', actual)
        self.assertEqual(actual['NZBDAV_CONFIG__USENET__PROVIDERS'], source['NZBDAV_CONFIG__USENET__PROVIDERS'])
        self.assertEqual(actual['NZBDAV_CONFIG__WEBDAV__USER'], 'nas-media')
        self.assertEqual(actual['FRONTEND_BACKEND_API_KEY'], 'nas-private-key')
        self.assertEqual(actual['PUID'], '1001')
        self.assertEqual(actual['TMPDIR'], '/scratch/tmp')

    def test_xml_preserves_source_key_and_nas_listener(self):
        folder = self.root / 'radarr4k'; folder.mkdir()
        (folder / 'config.xml').write_text('<Config><ApiKey>source-key</ApiKey><Port>7879</Port><AuthenticationMethod>Forms</AuthenticationMethod><AllowedHosts>old</AllowedHosts></Config>')
        nas = self.root / 'nas.xml'
        nas.write_text('<Config><ApiKey>old-nas-key</ApiKey><Port>7878</Port><BindAddress>*</BindAddress></Config>')
        key, port = s.patch_xml(self.root, folder, nas, ['RADARR__AUTH__APIKEY=effective-source-key'])
        actual = ET.parse(folder / 'config.xml').getroot()
        self.assertEqual((key, port), ('effective-source-key', 7878))
        self.assertEqual(actual.findtext('ApiKey'), 'effective-source-key')
        self.assertEqual(actual.findtext('AuthenticationMethod'), 'Forms')
        self.assertIn(s.NAS_IP, actual.findtext('AllowedHosts'))

    def test_endpoint_adapter_is_narrow_and_does_not_expose_embedded_secrets(self):
        self.assertEqual(s.endpoint('https://request.sawdoctor.uk'), 'https://request.sawdoctor.uk')
        self.assertEqual(s.endpoint('http://192.168.0.29:12345/other'), 'http://192.168.0.29:12345/other')
        self.assertEqual(s.endpoint('http://192.168.0.29:8082/api?q=1'), 'http://192.168.0.220:8082/api?q=1')
        with self.assertRaises(RuntimeError) as caught:
            s.endpoint('http://user:secret@192.168.0.29:8082')
        self.assertNotIn('secret', str(caught.exception))

    def test_write_fences_reject_live_or_symlinked_paths(self):
        outside = self.root.parent / 'live-config'; outside.write_bytes(b'retain')
        alias = self.root / 'alias'; alias.symlink_to(outside)
        for path in (outside, alias):
            with self.subTest(path=path), self.assertRaises(RuntimeError):
                s.write(self.root, path, b'bad')
        self.assertEqual(outside.read_bytes(), b'retain')


if __name__ == '__main__':
    unittest.main()
