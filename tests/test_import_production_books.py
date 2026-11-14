"""Production policy, frozen checksums and crash-safe book root replacement."""
import contextlib
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import types
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    value = importlib.util.module_from_spec(spec)
    exec(compile((SCRIPTS / filename).read_bytes(), str(SCRIPTS / filename), 'exec'), value.__dict__)
    return value


m = module('production_books', 'import-nas-production-books.py')
core = module('book_checks', 'prepare-nas-production-core.py')


class ProductionBooks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.native = types.SimpleNamespace(
            digest=lambda p: hashlib.sha256(p.read_bytes()).hexdigest(),
            safe=lambda p: None, sync_dir=lambda p: None,
            atomic=lambda p, value: p.write_text(json.dumps(value)))
        self.books = module('books_fixture', 'deploy-nas-books.py')
        self.roots = {'sample': {'source': '/home/sawdoctor/books', 'snapshot': 'data/books.sample'}}

    def adapter(self):
        return m.install_adapters(self.books, self.roots, [('source-infini-key-123456', 'nas-infini-key-987654')])

    def test_cloud_ebooks_precedes_broad_library_descriptor(self):
        roots = {**self.roots, 'library': {'source': '/mnt/media'}}
        _, target = m.mapping('/mnt/media/ebooks/A/book.epub', roots, self.root, self.books.MOUNTS)
        self.assertEqual(str(target), '/mnt/media/ebooks/A/book.epub')

    def test_longest_local_root_matches_and_cloud_is_not_read(self):
        roots = {**self.roots, 'nested': {'source': '/home/sawdoctor/books/nested'}}
        self.assertEqual(m.mapping('/home/sawdoctor/books/nested/config/db', roots, self.root, {})[1],
                         self.root / 'nested/config/db')
        with self.assertRaises(RuntimeError): m.mapping('/unreviewed/config', roots, self.root, {})
        with self.assertRaises(RuntimeError): m.mapping('/home/sawdoctor/books/../../other', roots, self.root, {})

    def test_relative_and_container_namespace_playback_links_preserved(self):
        containers = {'abs': {'Mounts': [{'Destination': '/mnt/legacy-gdrive-audiobooks'}]}}
        self.assertEqual(m.link_target('../unchanged.flac', self.roots, self.books, containers), '../unchanged.flac')
        value = '/mnt/legacy-gdrive-audiobooks/Author/title.flac'
        self.assertEqual(m.link_target(value, self.roots, self.books, containers), value)
        with self.assertRaises(RuntimeError): m.link_target('/home/other/unknown', self.roots, self.books, containers)

    def test_local_playback_link_moves_to_nas_without_changing_file_id(self):
        target = '/home/sawdoctor/books/.ids/abcd1234'
        expected = str(m.LIVE / 'sample/.ids/abcd1234')
        self.assertEqual(m.link_target(target, self.roots, self.books, {}), expected)

    def test_production_settings_do_not_inherit_old_trial_controls(self):
        self.adapter(); database = self.root / 'abr.sqlite'
        with contextlib.closing(sqlite3.connect(database)) as db:
            db.executescript('CREATE TABLE config(key TEXT PRIMARY KEY,value TEXT); CREATE TABLE notification(url TEXT,enabled INTEGER);')
            db.executemany('INSERT INTO config VALUES (?,?)', [
                ('quality_auto_download', '1'), ('abs_base_url', 'http://192.168.0.29:13378'),
                ('prowlarr_base_url', 'http://192.168.0.29:9696'), ('password', 'production-password'),
                ('api_key', 'source-infini-key-123456')])
            db.executemany('INSERT INTO notification VALUES (?,?)', [
                ('https://notify.example/keep', 1), ('http://127.0.0.1:8090/hook', 1), ('https://off.example', 0)])
            db.commit()
        self.books.patch_settings_db(database, abr=True)
        with contextlib.closing(sqlite3.connect(database)) as db:
            settings = dict(db.execute('SELECT key,value FROM config'))
            alerts = db.execute('SELECT url,enabled FROM notification ORDER BY rowid').fetchall()
        self.assertEqual(settings['quality_auto_download'], '1')
        self.assertEqual(settings['password'], 'production-password')
        self.assertEqual(settings['api_key'], 'nas-infini-key-987654')
        self.assertEqual(settings['abs_base_url'], 'http://audiobookshelf-test:80')
        self.assertEqual(settings['prowlarr_base_url'], 'http://prowlarr:9696')
        self.assertEqual(alerts, [('https://notify.example/keep', 1),
                                 ('http://abr-shelfmark-bridge:8090/hook', 1), ('https://off.example', 0)])

    def test_nested_source_credentials_and_public_domains_retained(self):
        self.adapter()
        value = {'password': 'keep-exact', 'providers': [{'api_key': 'source-prowlarr-key'}],
                 'plex_url': 'http://192.168.0.29:32400', 'public_url': 'https://abr.sawdoctor.uk'}
        updated = self.books.rewrite_tree(value)
        self.assertEqual(updated['password'], value['password'])
        self.assertEqual(updated['providers'], value['providers'])
        self.assertEqual(updated['plex_url'], 'http://192.168.0.220:32400')
        self.assertEqual(updated['public_url'], value['public_url'])

    def test_compose_keeps_nas_bindings_ports_security_and_literal_secrets(self):
        secrets = self.adapter()
        with patch.object(self.books, 'APPS', {'kavita': (5000, 5000, 'Kavita')}):
            model = {'services': {'kavita': {
                'volumes': [{'source': '/nas/current/config', 'target': '/kavita/config', 'read_only': False}],
                'networks': {'media-core': {'aliases': ['kavita']}}, 'ports': ['192.168.0.220:5000:5000'],
                'security_opt': ['no-new-privileges:true'], 'environment': {'TRIAL': 'true'}}}}
            selected = {'kavita': {'Config': {'Env': ['PASSWORD=literal$VALUE', 'PUID=999'],
                                             'Cmd': ['serve', '$LITERAL'], 'Entrypoint': None}, 'Mounts': []}}
            rows = {'kavita-nas': {'Config': {'Env': ['PUID=1000', 'TZ=Europe/London']}}}
            starter = types.SimpleNamespace(environment=lambda row: dict(v.split('=', 1) for v in row['Config']['Env']))
            result = m.candidate_model(model, self.books, selected, self.roots,
                                       {'kavita': 'sha256:exact'}, rows, starter, secrets)['services']['kavita']
        for key in ('volumes', 'networks', 'ports', 'security_opt'):
            self.assertEqual(result[key], model['services']['kavita'][key])
        self.assertEqual(result['environment'], {'PASSWORD': 'literal$$VALUE', 'PUID': '1000', 'TZ': 'Europe/London'})
        self.assertEqual(result['command'], ['serve', '$$LITERAL'])
        self.assertEqual(result['image'], 'sha256:exact'); self.assertEqual(result['restart'], 'no')

    def frozen(self):
        raw = self.root / 'raw'; root = raw / 'data/books.sample'; root.mkdir(parents=True)
        (root / 'db').write_bytes(b'consistent-source-file')
        (root / 'link').symlink_to('/mnt/nzbdav/.ids/abc')
        (raw / 'SHA256SUMS').write_text(self.native.digest(root / 'db') + '  ./data/books.sample/db\n')
        return raw, root

    def test_original_frozen_file_checksums_and_link_inventory(self):
        raw, root = self.frozen()
        inventories, checks, size = m.verify_selected(self.native, core, raw, self.roots)
        self.assertEqual(set(checks), {'data/books.sample/db'})
        self.assertEqual(inventories['sample'][1], {'link': '/mnt/nzbdav/.ids/abc'})
        self.assertEqual(size, len(b'consistent-source-file'))

    def test_corruption_or_added_file_is_rejected_before_activation(self):
        raw, root = self.frozen(); (root / 'db').write_bytes(b'corrupt')
        with self.assertRaisesRegex(RuntimeError, 'checksum/inventory'):
            m.verify_selected(self.native, core, raw, self.roots)
        (root / 'db').write_bytes(b'consistent-source-file'); (root / 'extra').write_bytes(b'unlisted')
        with self.assertRaisesRegex(RuntimeError, 'incomplete'):
            m.verify_selected(self.native, core, raw, self.roots)

    def prepared(self):
        live = self.root / 'live'; candidate = self.root / 'incoming'; old = self.root / 'before'
        live.mkdir(); candidate.mkdir()
        (live / 'db').write_bytes(b'old-nas'); (candidate / 'db').write_bytes(b'current-frozen')
        item = {'live': str(live), 'incoming': str(candidate), 'before': str(old), 'phase': 'prepared',
                'sha256': m.root_digest(self.native, candidate)}
        return live, candidate, old, item

    def test_swap_keeps_old_root_and_resume_after_both_rename_windows(self):
        for window in (0, 1, 2):
            with self.subTest(window=window), tempfile.TemporaryDirectory() as task:
                original = self.root; self.root = Path(task)
                try:
                    live, incoming, old, item = self.prepared()
                    if window > 0: live.rename(old)
                    if window > 1: incoming.rename(live)
                    with patch.object(m, 'STATE', self.root / 'state.json'):
                        m.swap(self.native, {'roots': [item]}, item)
                    self.assertEqual(item['phase'], 'installed')
                    self.assertEqual((live / 'db').read_bytes(), b'current-frozen')
                    self.assertEqual((old / 'db').read_bytes(), b'old-nas')
                finally: self.root = original

    def test_changed_prepared_root_never_replaces_live(self):
        live, incoming, old, item = self.prepared(); (incoming / 'db').write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError, 'changed before installation'):
            m.swap(self.native, {}, item)
        self.assertEqual((live / 'db').read_bytes(), b'old-nas'); self.assertFalse(old.exists())

    def test_private_sqlite_checks_close_databases_before_replacement(self):
        folder = self.root / 'sample'; folder.mkdir(); database = folder / 'data.db'
        with contextlib.closing(sqlite3.connect(database)) as db:
            db.execute('PRAGMA journal_mode=WAL'); db.execute('CREATE TABLE test(value)')
            db.execute("INSERT INTO test VALUES ('retained')"); db.commit()
        m.fix_links_and_databases(self.native, self.roots, self.root, self.books, {})
        with contextlib.closing(sqlite3.connect(database, timeout=0)) as db:
            db.execute('BEGIN EXCLUSIVE'); self.assertEqual(db.execute('SELECT value FROM test').fetchone(), ('retained',))
        self.assertFalse(Path(str(database) + '-wal').exists())

    def test_failure_stops_only_selected_book_writers_and_keeps_phase(self):
        calls = []; native = types.SimpleNamespace(run=lambda *args, **kwargs: calls.append(args), atomic=lambda *args: None)
        op = {'phase': 'starting'}
        m.retain_stopped(native, op, {'kavita-nas', 'sabnzbd-ebooks-nas'})
        self.assertTrue(op['bookWritersStoppedAfterFailure']); self.assertEqual(op['phase'], 'starting')
        self.assertEqual({call[-1] for call in calls}, {'kavita-nas', 'sabnzbd-ebooks-nas'})


if __name__ == '__main__': unittest.main()
