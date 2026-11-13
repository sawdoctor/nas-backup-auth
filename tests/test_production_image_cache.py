"""Image-cache safety and exact-source matching without Docker/network access."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value
s = module('cache', 'cache-nas-production-core-images.py')
h = module('core', 'prepare-nas-production-core.py')

def image(number, repository, layer=None):
    return {'Id': 'sha256:' + str(number) * 64, 'Os': 'linux', 'Architecture': 'amd64',
            'RootFS': {'Layers': ['layer-' + str(layer or number)]}, 'Size': 100,
            'RepoDigests': [repository + '@sha256:' + str(number) * 64],
            'RepoTags': [repository + ':latest'],
            'Config': {'Env': ['BUILD=original'], 'Entrypoint': ['/init'], 'Labels': {'build_version': str(number)}}}

class ImageCache(unittest.TestCase):
    def test_saved_digest_never_uses_latest_or_an_unreviewed_registry(self):
        value = image(1, 'lscr.io/linuxserver/sonarr')
        self.assertEqual(s.saved_digest('sonarr', value), value['RepoDigests'][0])
        for digests in ([], ['lscr.io/linuxserver/sonarr:latest'],
                        ['unexpected.example/sonarr@sha256:'+'1'*64],
                        value['RepoDigests'] + ['lscr.io/linuxserver/sonarr@sha256:'+'2'*64]):
            with self.subTest(digests=digests), self.assertRaises(RuntimeError):
                s.saved_digest('sonarr', {**value, 'RepoDigests': digests})
        with self.assertRaises(RuntimeError):
            s.saved_digest('additional-app', value)

    def test_image_config_must_match_as_well_as_layers_and_platform(self):
        source = image(1, 'lscr.io/linuxserver/sonarr')
        cached = copy.deepcopy(source); cached['Id'] = 'different-Docker-storage-id'
        self.assertTrue(s.same_image(h, source, cached))
        for field, changed in (('Env', ['BUILD=changed']), ('Entrypoint', ['/different-init']),
                               ('Labels', {'build_version': 'different'})):
            altered = copy.deepcopy(cached); altered['Config'][field] = changed
            self.assertFalse(s.same_image(h, source, altered))
        self.assertFalse(s.same_image(h, source, {**cached, 'Architecture': 'arm64'}))

    def fixture(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        root = Path(temp.name); standby = root/'standby'; standby.mkdir()
        stamp = '20261113T003457Z'; candidate = root/stamp; candidate.mkdir()
        record = {'createdUtc': stamp, 'sha256': 'source-archive'}
        plan = candidate/'plan.json'
        plan.write_text(json.dumps({'candidateOnly': True, 'sourceArchiveSha256': record['sha256'], 'sourceCreatedUtc': stamp}))
        expected = {'sonarr': image(1, 'lscr.io/linuxserver/sonarr'),
                    'radarr': image(2, 'lscr.io/linuxserver/radarr'),
                    'prowlarr': image(3, 'ghcr.io/hotio/prowlarr')}
        expected['radarr4k'] = expected['radarr']
        old = image(4, 'lscr.io/linuxserver/sonarr')
        initial = {old['Id']: old}
        downloaded = {}
        for name in ('sonarr', 'radarr', 'prowlarr'):
            row = copy.deepcopy(expected[name]); row['RepoTags'] = []
            downloaded[row['Id']] = row
        final = {**initial, **downloaded}
        catalog = {row['Id']: row for row in expected.values()}
        manifest = {'containers': [{'Name': '/'+name, 'Image': row['Id'],
                    'Config': {'Image': row['RepoDigests'][0].split('@')[0]+':latest'}} for name,row in expected.items()],
                    'images': list(catalog.values())}
        def run(*args):
            if args[:2] == ('docker', 'info'):return json.dumps(str(root))
            if args[:3] == ('docker', 'image', 'inspect'):
                return json.dumps([row for row in downloaded.values() if args[3] in row['RepoDigests']])
            raise AssertionError('Unexpected command: '+str(args))
        core = SimpleNamespace(STANDBY=standby, NAMES={n:n+'-nas' for n in expected},
                    safe=h.safe, read=lambda p:p.read_bytes(), atomic=h.atomic, digest=h.digest,
                    snapshot=lambda:(root,record,manifest), run=run, say=lambda _:None,
                    image_content_matches=h.image_content_matches)
        return root, candidate, core, initial, final

    def test_three_digest_downloads_cover_four_apps_without_retag_or_redeploy(self):
        root, candidate, core, initial, final = self.fixture()
        before = {'sonarr-nas': {'id': 'original', 'startedAt': 'original'}}
        with patch.object(s, 'BASE', root), patch.object(s, 'BACKUP_LOCK', root/'backup.lock'), \
                patch.object(s, 'inventory', side_effect=[initial, final]), \
                patch.object(s, 'containers', return_value=before), \
                patch.object(s, 'pull') as download, \
                patch.object(s.shutil, 'disk_usage', return_value=SimpleNamespace(free=10**12)):
            s.stage(core)
        self.assertEqual(download.call_count, 3)
        self.assertTrue(all('@sha256:' in call.args[2] and ':latest' not in call.args[2] for call in download.call_args_list))
        result = json.loads((candidate/'image-cache/result.json').read_bytes())
        self.assertEqual(result['images']['radarr']['nasImage'], result['images']['radarr4k']['nasImage'])
        self.assertEqual(result['downloadedUniqueImages'], 3)
        self.assertFalse(result['activationImplemented'])
        self.assertEqual(s.tag_bindings(initial, ['lscr.io/linuxserver/sonarr:latest']),
                         s.tag_bindings(final, ['lscr.io/linuxserver/sonarr:latest']))

    def test_cache_retry_reuses_already_verified_images(self):
        root, candidate, core, initial, final = self.fixture()
        with patch.object(s, 'BASE', root), patch.object(s, 'BACKUP_LOCK', root/'backup.lock'), \
                patch.object(s, 'inventory', return_value=final), patch.object(s, 'containers', return_value={}), \
                patch.object(s, 'pull') as download, \
                patch.object(s.shutil, 'disk_usage', return_value=SimpleNamespace(free=10**12)):
            s.stage(core)
        download.assert_not_called()

    def test_unexpected_container_change_keeps_cache_but_never_marks_complete(self):
        root, candidate, core, initial, final = self.fixture()
        with patch.object(s, 'BASE', root), patch.object(s, 'BACKUP_LOCK', root/'backup.lock'), \
                patch.object(s, 'inventory', return_value=final), patch.object(s, 'containers', side_effect=[{}, {'changed': True}]), \
                patch.object(s, 'pull'), \
                patch.object(s.shutil, 'disk_usage', return_value=SimpleNamespace(free=10**12)), self.assertRaises(RuntimeError):
            s.stage(core)
        self.assertFalse((candidate/'image-cache/result.json').exists())

    def test_changed_latest_tag_does_not_receive_a_completion_record(self):
        root, candidate, core, initial, final = self.fixture()
        changed = copy.deepcopy(final)
        changed['sha256:'+'4'*64]['RepoTags'] = []
        changed['sha256:'+'1'*64]['RepoTags'] = ['lscr.io/linuxserver/sonarr:latest']
        with patch.object(s, 'BASE', root), patch.object(s, 'BACKUP_LOCK', root/'backup.lock'), \
                patch.object(s, 'inventory', side_effect=[final, changed]), patch.object(s, 'containers', return_value={}), \
                patch.object(s, 'pull'), \
                patch.object(s.shutil, 'disk_usage', return_value=SimpleNamespace(free=10**12)), self.assertRaises(RuntimeError):
            s.stage(core)
        self.assertFalse((candidate/'image-cache/result.json').exists())

    def test_runtime_docker_mutations_are_limited_to_digest_pull(self):
        import ast
        tree = ast.parse((ROOT/'scripts/cache-nas-production-core-images.py').read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.List) or not node.elts or not isinstance(node.elts[0], ast.Constant) or node.elts[0].value != 'docker':continue
            strings = [v.value for v in node.elts if isinstance(v, ast.Constant)]
            self.assertEqual(strings[:4], ['docker', 'image', 'pull', '--platform'])

if __name__ == '__main__':
    unittest.main()
