import contextlib
import copy
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'scripts'
if not SCRIPTS.is_dir():
    SCRIPTS = ROOT / 'nas-backup-auth/scripts'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


module = load('complete_npm', SCRIPTS / 'prepare-nas-npm-cutover.py')
fixture = load('npm_route_fixtures', Path(__file__).with_name('test_npm_routes_prepare.py'))


def expired_certificate(key_file, output):
    key = serialization.load_pem_private_key(key_file.read_bytes(), password=None)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'soundspan.sawdoctor.uk')])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(68)
            .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2020, 2, 1, tzinfo=timezone.utc))
            .sign(key, hashes.SHA256()))
    output.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


class CompleteNpmTests(unittest.TestCase):
    def setUp(self):
        self.case = fixture.RoutePlanTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.r = fixture.s
        self.n = load('restore_copy', SCRIPTS / 'prepare-nas-npm.py')
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.root = self.case.app / 'compose/npm-restore/cutover'
        manifest = json.loads(self.case.manifest.read_text())
        manifest['dataRoots']['npm-letsencrypt'] = {'snapshot': 'data/npm-letsencrypt'}
        self.case.manifest.write_text(json.dumps(manifest))
        self.data = self.case.path.parent
        (self.data / 'keys.json').write_text(json.dumps({'key': 'PRIVATE_SIGNING_FIXTURE', 'pub': 'public'}))
        (self.data / 'custom.txt').write_text('PRIVATE_CUSTOM_FILE')
        os.setxattr(self.data / 'custom.txt', 'user.npm-test', b'kept')
        self.certs = self.case.snapshot / 'data/npm-letsencrypt'
        archive = self.certs / 'archive/npm-6'
        archive.mkdir(parents=True)
        self.key = archive / 'privkey1.pem'
        self.certificate = archive / 'fullchain1.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
                        '-nodes', '-subj', '/CN=test.invalid', '-days', '1', '-keyout', str(self.key),
                        '-out', str(self.certificate)], check=True, capture_output=True)
        live = self.certs / 'live/npm-6'
        live.mkdir(parents=True)
        (live / 'privkey.pem').symlink_to('../../archive/npm-6/privkey1.pem')
        (live / 'fullchain.pem').symlink_to('../../archive/npm-6/fullchain1.pem')
        with contextlib.closing(sqlite3.connect(self.case.path)) as db, db:
            db.execute("ALTER TABLE certificate ADD COLUMN provider TEXT DEFAULT 'letsencrypt'")
            db.execute("ALTER TABLE certificate ADD COLUMN domain_names TEXT")
            db.execute("INSERT INTO certificate(id,is_deleted,private_value,provider,domain_names) VALUES(68,0,'PRIVATE_RETIRED_CERT','letsencrypt',?)",
                       (json.dumps(['soundspan.sawdoctor.uk']),))
            db.execute('UPDATE proxy_host SET certificate_id=68 WHERE id=27')
        retired_archive = self.certs / 'archive/npm-68'
        retired_live = self.certs / 'live/npm-68'
        retired_archive.mkdir()
        retired_live.mkdir()
        (retired_archive / 'privkey1.pem').write_bytes(self.key.read_bytes())
        expired_certificate(self.key, retired_archive / 'fullchain1.pem')
        for kind in ('fullchain', 'privkey'):
            (retired_live / (kind + '.pem')).symlink_to('../../archive/npm-68/' + kind + '1.pem')
        (self.certs / 'renewal').mkdir()
        (self.certs / 'renewal/npm-68.conf').write_text('PRIVATE_RETIRED_RENEWAL')
        generated = self.data / 'nginx/proxy_host'
        generated.mkdir(parents=True)
        (generated / '27.conf').write_text('server_name soundspan.sawdoctor.uk;')
        (generated / '1.conf').write_text('PRIVATE_OTHER_ROUTE')
        self.checksums()
        self.r.stage()
        self.cache = self.case.root / 'image-identities.json'
        self.cache.write_text(json.dumps({'npm-app-1': {'source': self.n.SOURCE_IMAGE, 'nas': 'verified-image'}}))
        self.model = {'name': 'npm-nas', 'services': {'npm': {
            'image': 'jc21/nginx-proxy-manager:latest', 'container_name': 'npm-nas', 'restart': 'unless-stopped',
            'environment': {'DISABLE_IPV6': 'true', 'CUSTOM': 'PRIVATE_$literal_$$value'},
            'ports': [{'target': port, 'published': str(host), 'host_ip': '192.168.0.220'}
                      for port, host in ((80, 10080), (81, 10081), (443, 10443))],
            'volumes': [{'type': 'bind', 'source': str(self.case.live.parent), 'target': '/data'},
                        {'type': 'bind', 'source': str(self.case.app / 'appdata/npm/letsencrypt'), 'target': '/etc/letsencrypt'}],
            'networks': {'default': None}}}, 'networks': {'default': {'name': 'npm-nas_default'}}}
        self.host = self.case.app / 'appdata/dockmon/stacks/npm-nas/docker-compose.yml'
        self.host.parent.mkdir(parents=True)
        self.host.write_text(yaml.safe_dump(self.model))
        self.stored = {'path': '/app/data/stacks/npm-nas/docker-compose.yml', 'text': self.host.read_text(), 'env': ''}
        self.calls = []
        self.changed_roundtrip = False
        self.stack.enter_context(patch.multiple(self.n, CACHE=self.cache))
        self.stack.enter_context(patch.object(self.n, 'run', side_effect=self.restore_command))
        self.stack.enter_context(patch.object(self.n, 'all_containers', return_value=[]))
        self.stack.enter_context(patch.object(module.shutil, 'which', return_value='/test/tool'))
        self.stack.enter_context(patch.object(self.r, 'run', side_effect=self.route_command))

    def checksums(self):
        paths = [self.case.manifest] + [p for p in (self.case.snapshot / 'data').rglob('*') if p.is_file() and not p.is_symlink()]
        (self.case.snapshot / 'SHA256SUMS').write_text(''.join(
            self.r.sha(p.read_bytes()) + '  ./' + str(p.relative_to(self.case.snapshot)) + '\n' for p in paths))

    def route_command(self, *args, **kw):
        raw = self.case.query(*args, **kw)
        if args[:2] == ('docker', 'inspect'):
            records = json.loads(raw)
            for item in records:
                item['Image'] = 'verified-image'
                item['State']['StartedAt'] = 'original-time'
                if item['Name'] == '/npm-nas':
                    item['HostConfig']['PortBindings'] = self.n.PORTS
            return json.dumps(records)
        return raw

    def restore_command(self, *args, **kw):
        self.calls.append(args)
        if args[:3] == ('docker', 'image', 'inspect'):
            return json.dumps([{'Id': 'verified-image'}])
        if args[:3] == ('docker', 'exec', 'dockmon'):
            return json.dumps(self.stored)
        if args[:2] == ('docker', 'compose'):
            self.assertNotIn('up', args)
            self.assertNotIn('create', args)
            self.assertNotIn('down', args)
            path = Path(args[args.index('-f') + 1])
            if path == self.host:
                return json.dumps(self.model)
            value = yaml.safe_load(path.read_text())
            def expand(v):
                if isinstance(v, str):
                    return v.replace('$$', '$')
                if isinstance(v, list):
                    return [expand(i) for i in v]
                if isinstance(v, dict):
                    return {k: expand(i) for k, i in v.items()}
                return v
            value = expand(value)
            if self.changed_roundtrip:
                value['services']['npm']['environment']['CUSTOM'] = 'CHANGED'
            return json.dumps(value)
        if args[0] == 'rsync':
            # Run the real GNU archive copier locally: the existing pinned NAS
            # restore helper runs rsync -aHAX there. No copy data is mocked.
            subprocess.run(['cp', '-a', args[-2] + '.', args[-1]], check=True, capture_output=True)
            return ''
        result = subprocess.run(args, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError('Local restore command failed')
        return result.stdout

    def test_real_copy_keeps_keys_links_xattrs_and_only_changes_route_database(self):
        live_before, source_before, stack_before = self.case.live.read_bytes(), self.case.path.read_bytes(), self.host.read_bytes()
        module.prepare(self.r, self.n)
        self.assertEqual(self.case.live.read_bytes(), live_before)
        self.assertEqual(self.case.path.read_bytes(), source_before)
        self.assertEqual(self.host.read_bytes(), stack_before)
        data = self.root / 'payload/data'
        self.assertEqual((data / 'keys.json').read_bytes(), (self.data / 'keys.json').read_bytes())
        self.assertEqual(os.getxattr(data / 'custom.txt', 'user.npm-test'), b'kept')
        self.assertTrue((self.root / 'payload/letsencrypt/live/npm-6/privkey.pem').is_symlink())
        record = json.loads((self.root / 'prepared.json').read_text())
        self.assertEqual(record['changedUpstreams'], 21)
        self.assertEqual(record['checkedCertificateKeyPairs'], 1)
        self.assertEqual(record['status'], 'complete-offline-not-activated')
        self.assertEqual(record['retiredService'], module.RETIRED)
        self.assertEqual(record['counts']['proxy_host'], 29)
        with contextlib.closing(sqlite3.connect(data / 'database.sqlite')) as db:
            self.assertEqual(db.execute('SELECT is_deleted,enabled FROM proxy_host WHERE id=27').fetchone(), (1, 0))
            self.assertEqual(db.execute('SELECT is_deleted FROM certificate WHERE id=68').fetchone(), (1,))
        self.assertFalse((data / 'nginx/proxy_host/27.conf').exists())
        self.assertEqual((data / 'nginx/proxy_host/1.conf').read_text(), 'PRIVATE_OTHER_ROUTE')
        for suffix in ('live/npm-68', 'archive/npm-68', 'renewal/npm-68.conf'):
            self.assertFalse((self.root / 'payload/letsencrypt' / suffix).exists())
            self.assertTrue((self.certs / suffix).exists())
        self.assertNotIn('PRIVATE_', self.case.output.getvalue())
        for call in self.calls:
            self.assertNotIn('stop', call)
            self.assertNotIn('restart', call)
            self.assertNotIn('pull', call)

    def test_retry_has_no_extra_copy_and_rejects_modified_private_payload(self):
        module.prepare(self.r, self.n)
        count = sum(c[0] == 'rsync' for c in self.calls)
        module.prepare(self.r, self.n)
        self.assertEqual(sum(c[0] == 'rsync' for c in self.calls), count)
        (self.root / 'payload/data/keys.json').write_text('edited private key file')
        with self.assertRaisesRegex(RuntimeError, 'differs'):
            module.prepare(self.r, self.n)
        self.assertEqual((self.root / 'payload/data/keys.json').read_text(), 'edited private key file')

    def test_mismatched_tls_key_fails_before_publication(self):
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
                        '-out', str(self.key)], check=True, capture_output=True)
        self.checksums()
        with self.assertRaisesRegex(RuntimeError, 'certificate and private key do not match'):
            module.prepare(self.r, self.n)
        self.assertFalse(self.root.exists())

    def test_another_expired_certificate_still_blocks_preparation(self):
        expired_certificate(self.key, self.certificate)
        self.checksums()
        with self.assertRaisesRegex(RuntimeError, 'record 6 failed expiry/read validation'):
            module.prepare(self.r, self.n)
        self.assertFalse(self.root.exists())

    def test_shared_soundspan_certificate_is_not_removed(self):
        with contextlib.closing(sqlite3.connect(self.case.path)) as db, db:
            db.execute('UPDATE proxy_host SET certificate_id=68,enabled=0 WHERE id=28')
        # Preserve the accepted upstream fixture, then exercise the exact
        # retirement guard directly: disabled routes still count as consumers.
        with contextlib.closing(sqlite3.connect(self.case.path)) as db:
            with self.assertRaisesRegex(RuntimeError, 'certificate 68 is shared'):
                module.retire_soundspan(db)
            self.assertEqual(db.execute('SELECT is_deleted FROM certificate WHERE id=68').fetchone(), (0,))
            self.assertEqual(db.execute('SELECT is_deleted FROM proxy_host WHERE id=27').fetchone(), (0,))

    def test_changed_soundspan_identity_is_not_retired(self):
        with contextlib.closing(sqlite3.connect(self.case.path)) as db, db:
            db.execute('UPDATE certificate SET domain_names=? WHERE id=68', ('["other.invalid"]',))
        with contextlib.closing(sqlite3.connect(self.case.path)) as db:
            with self.assertRaisesRegex(RuntimeError, 'Soundspan certificate differs'):
                module.retire_soundspan(db)
            self.assertEqual(db.execute('SELECT is_deleted FROM proxy_host WHERE id=27').fetchone(), (0,))

    def test_compose_value_change_fails_before_publication(self):
        self.changed_roundtrip = True
        with self.assertRaisesRegex(RuntimeError, 'round trip changed'):
            module.prepare(self.r, self.n)
        self.assertFalse(self.root.exists())

    def test_payload_copy_corruption_is_detected(self):
        original = self.n.prepare_data
        def copy_corrupt(expected):
            original(expected)
            (self.n.DATA / 'data/keys.json').write_text('CORRUPTED')
        with patch.object(self.n, 'prepare_data', side_effect=copy_corrupt):
            with self.assertRaisesRegex(RuntimeError, 'differs from the verified source'):
                module.prepare(self.r, self.n)
        self.assertFalse(self.root.exists())

    def test_proposal_or_symbolic_tree_changes_are_rejected(self):
        (self.r.WORK / 'database.sqlite').write_bytes(b'changed proposal')
        with self.assertRaisesRegex(RuntimeError, 'route proposal or current source database changed'):
            module.prepare(self.r, self.n)
        self.assertFalse(self.root.exists())
        target = self.case.root / 'outside'
        target.write_text('protected')
        (self.data / 'unsafe').symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, 'escapes'):
            module.inventory(self.data)
        self.assertEqual(target.read_text(), 'protected')

    def test_corrupt_inventory_record_is_rejected_on_retry(self):
        module.prepare(self.r, self.n)
        (self.root / 'payload-inventory.json').write_text('{}')
        with self.assertRaisesRegex(RuntimeError, 'differs'):
            module.prepare(self.r, self.n)

    def test_missing_dependency_stops_without_copy(self):
        with patch.object(module.shutil, 'which', return_value=None):
            with self.assertRaisesRegex(RuntimeError, 'rsync command'):
                module.prepare(self.r, self.n)
        self.assertFalse(self.root.exists())


if __name__ == '__main__':
    unittest.main()
