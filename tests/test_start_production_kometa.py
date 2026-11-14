"""Frozen provenance, unchanged acquisition policy and interrupted root recovery."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


m = module('start_kometa', 'start-nas-production-kometa.py')
p = module('kometa_adapter', 'production-support-policy.py')
c = module('checksum_core', 'prepare-nas-production-core.py')


class KometaHandover(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.work = self.root / 'work'; self.work.mkdir()
        self.patch = patch.multiple(m, WORK=self.work, STATE=self.work / 'state.json', BASE=self.root)
        self.patch.start(); self.addCleanup(self.patch.stop)
        self.native = types.SimpleNamespace(
            digest=lambda path: hashlib.sha256(path.read_bytes()).hexdigest(),
            sync_dir=lambda path: None,
            atomic=lambda path, obj: path.write_text(json.dumps(obj)),
            safe=lambda path: None,
            read=lambda path: path.read_bytes(), validate_proof=lambda proof: None,
            SOURCE_FORMAT='sawdoctor-production-cutover-v1')

    def write_files(self, root, content):
        root.mkdir()
        for name in m.FILES: (root / name).write_text(content + name)

    def prepared(self):
        (self.work / 'rollback').mkdir()
        live = self.root / 'live'; incoming = self.work / 'incoming'
        self.write_files(live, 'old-'); self.write_files(incoming, 'frozen-')
        operation = {'phase': 'prepared', 'live': str(live),
                     'configSha256': self.native.digest(incoming / 'config.yml'),
                     'collectionSha256': {n: self.native.digest(incoming / n) for n in m.FILES[1:]}}
        return live, incoming, operation

    def test_install_retains_complete_old_root(self):
        live, incoming, op = self.prepared()
        (live / 'old-cache.db').write_bytes(b'old-cache')
        m.install_root(self.native, op)
        self.assertEqual(op['phase'], 'installed')
        self.assertEqual((self.work / 'rollback/kometa/old-cache.db').read_bytes(), b'old-cache')
        self.assertEqual((live / 'config.yml').read_text(), 'frozen-config.yml')
        self.assertFalse(incoming.exists())

    def test_resume_first_rename_before_journal_write(self):
        live, incoming, op = self.prepared()
        live.rename(self.work / 'rollback/kometa')
        m.install_root(self.native, op)
        self.assertEqual(op['phase'], 'installed')
        self.assertEqual((live / 'config.yml').read_text(), 'frozen-config.yml')

    def test_resume_second_rename_before_journal_write(self):
        live, incoming, op = self.prepared()
        live.rename(self.work / 'rollback/kometa'); incoming.rename(live)
        op['phase'] = 'saved'
        m.install_root(self.native, op)
        self.assertEqual(op['phase'], 'installed')

    def test_changed_candidate_does_not_replace_live(self):
        live, incoming, op = self.prepared()
        (incoming / m.FILES[2]).write_text('changed')
        with self.assertRaisesRegex(RuntimeError, 'changed before installation'):
            m.install_root(self.native, op)
        self.assertEqual((live / 'config.yml').read_text(), 'old-config.yml')
        self.assertFalse((self.work / 'rollback/kometa').exists())

    def test_changed_interrupted_root_is_retained_not_restarted(self):
        live, incoming, op = self.prepared()
        live.rename(self.work / 'rollback/kometa'); incoming.rename(live)
        (live / 'config.yml').write_text('unexpected edit')
        with self.assertRaisesRegex(RuntimeError, 'interrupted installed'):
            m.install_root(self.native, op)
        self.assertTrue((self.work / 'rollback/kometa').is_dir())

    def checksum_tree(self):
        raw = self.root / 'incoming'; raw.mkdir(); (raw / 'data').mkdir()
        root = raw / 'data/support.kometa'; self.write_files(root, 'source-')
        checks = {name: self.native.digest(root / name) for name in m.FILES}
        (raw / 'SHA256SUMS').write_text(''.join(digest + '  ./data/support.kometa/' + name + '\n' for name, digest in checks.items()))
        return raw, root, checks

    def test_selected_frozen_checks_pass(self):
        raw, root, expected = self.checksum_tree()
        checks, size = m.selected_checks(self.native, c, raw, root)
        self.assertEqual(checks, expected); self.assertGreater(size, 0)

    def test_corrupt_frozen_file_is_rejected(self):
        raw, root, _ = self.checksum_tree(); (root / m.FILES[0]).write_text('corruption')
        with self.assertRaisesRegex(RuntimeError, 'failed its original checksum'):
            m.selected_checks(self.native, c, raw, root)

    def test_unlisted_file_is_rejected(self):
        raw, root, _ = self.checksum_tree(); (root / 'surprise.yml').write_text('x')
        with self.assertRaisesRegex(RuntimeError, 'inventory differs'):
            m.selected_checks(self.native, c, raw, root)

    def test_symlink_cannot_escape_frozen_config_root(self):
        raw, root, _ = self.checksum_tree(); (root / 'secret').symlink_to('/etc/passwd')
        with self.assertRaisesRegex(RuntimeError, 'symbolic/special'):
            m.selected_checks(self.native, c, raw, root)

    def runtime(self):
        return {'Config': {'Env': ['TZ=Europe/London'], 'Cmd': ['--times', '05:00'], 'Entrypoint': ['/entrypoint']},
                'State': {'Running': False}, 'HostConfig': {'RestartPolicy': {'Name': 'no'}, 'NetworkMode': 'media-core'}}

    def test_original_schedule_is_preserved(self):
        a = self.runtime(); b = copy.deepcopy(a)
        m.validate_runtime(a, b)
        self.assertEqual(b['Config']['Cmd'], ['--times', '05:00'])
        self.assertNotIn('--run', b['Config']['Cmd'])

    def test_unreviewed_environment_and_command_changes_are_rejected(self):
        a = self.runtime(); b = copy.deepcopy(a); b['Config']['Cmd'] = ['--run']
        with self.assertRaisesRegex(RuntimeError, 'command or user'): m.validate_runtime(a, b)
        b = copy.deepcopy(a); b['Config']['Env'].append('KOMETA_PLEX_URL=http://192.168.0.29:32400')
        with self.assertRaisesRegex(RuntimeError, 'environment differs'): m.validate_runtime(a, b)

    def test_matching_old_endpoint_env_cannot_defeat_adapted_config(self):
        a = self.runtime(); a['Config']['Env'].append('PLEX_URL=http://192.168.0.29:32400')
        with self.assertRaisesRegex(RuntimeError, 'override'): m.validate_runtime(a, copy.deepcopy(a))

    def source_config(self):
        return {'plex': {'url': 'http://192.168.0.29:32400', 'token': 'source-plex'},
                'radarr': {'url': 'http://radarr:7878', 'token': 'source-hd', 'add_missing': True, 'search': True},
                'sonarr': {'url': 'http://sonarr:8989', 'token': 'source-tv', 'add_missing': True, 'search': False, 'monitor': 'all'},
                'libraries': {'Movies': {'collection_files': [{'file': 'config/uk-us-movies.yml'}]},
                              'Movies 4K': {'radarr': {'url': 'http://radarr4k:7878'}, 'collection_files': [{'file': 'config/uk-us-movies4k.yml'}]},
                              'TV': {'collection_files': [{'file': 'config/uk-us-tv.yml'}]}}}

    def test_effective_partial_4k_override_uses_imported_key(self):
        adapted = p.kometa(self.source_config(), {'sonarr': 'nas-tv', 'radarr': 'nas-hd', 'radarr4k': 'nas-4k'})
        rows = m.connections(adapted)
        self.assertIn(('Movies 4K', 'radarr4k', 'http://192.168.0.220:7879', 'nas-4k'), rows)
        self.assertTrue(adapted['radarr']['add_missing']); self.assertTrue(adapted['radarr']['search'])
        self.assertTrue(adapted['sonarr']['add_missing']); self.assertFalse(adapted['sonarr']['search'])
        self.assertEqual(adapted['sonarr']['monitor'], 'all')

    def test_unknown_public_or_old_source_connections_cannot_be_started(self):
        for url in ('http://192.168.0.29:32400', 'https://plex.sawdoctor.uk', 'http://127.0.0.1:32400'):
            config = self.source_config(); config['plex']['url'] = url
            with self.assertRaisesRegex(RuntimeError, 'reviewed direct NAS endpoint'): m.connections(config)

    def test_missing_plex_library_stops_before_configuration_install(self):
        adapted = p.kometa(self.source_config(), {'sonarr': 'nas-tv', 'radarr': 'nas-hd', 'radarr4k': 'nas-4k'})
        with patch.object(m, 'http_json', return_value=b'<MediaContainer><Directory title="Other"/></MediaContainer>'):
            with self.assertRaisesRegex(RuntimeError, 'library title is absent'): m.dependency_check(adapted)
        self.assertFalse(m.STATE.exists())

    def test_authenticated_dependency_requests_keep_secrets_in_headers(self):
        config = {'plex': {'url': 'http://192.168.0.220:32400', 'token': 'private-token'}, 'libraries': {'TV': {}}}
        with patch.object(m, 'http_json', return_value=b'<MediaContainer><Directory title="TV"/></MediaContainer>') as request:
            self.assertEqual(m.dependency_check(config), 1)
        request.assert_called_once_with('http://192.168.0.220:32400/library/sections', {'X-Plex-Token': 'private-token'})

    def frozen(self):
        cutover = '20261113T180000Z-aabbccddeeff0011'
        raw = self.root / cutover / 'incoming'; raw.mkdir(parents=True)
        proof = {'cutoverId': cutover, 'frozenUtc': '20261113T180000Z', 'identitySha256': 'a' * 64}
        manifest = {'format': self.native.SOURCE_FORMAT, 'scope': 'production-frozen',
                    'sourceHost': '192.168.0.29', 'cutoverId': cutover,
                    'createdUtc': proof['frozenUtc'], 'plexConfigIncluded': True,
                    'sourceDockerStopped': True, 'identitySha256': proof['identitySha256'],
                    'dataRoots': {'support.kometa': {'snapshot': 'data/support.kometa', 'source': '/source/kometa'}},
                    'containers': [{'Name': '/kometa', 'Mounts': [{'Source': '/source/kometa', 'Destination': '/config', 'Type': 'bind'}]}]}
        state = {'proof': proof, 'raw': str(raw), 'folder': str(raw.parent)}
        return raw, manifest, state

    def write_manifest(self, raw, manifest, state):
        (raw / 'manifest.json').write_text(json.dumps(manifest))
        state['proof']['manifestSha256'] = self.native.digest(raw / 'manifest.json')

    def test_frozen_header_can_be_verified_after_core_roots_were_moved(self):
        raw, manifest, state = self.frozen(); self.write_manifest(raw, manifest, state)
        selected, result, source = m.frozen_manifest(self.native, state)
        self.assertEqual(selected, raw); self.assertEqual(source['Name'], '/kometa')
        self.assertFalse((raw / 'data/plex-config').exists())

    def test_old_snapshot_cannot_replace_current_frozen_configuration(self):
        raw, manifest, state = self.frozen(); manifest['scope'] = 'standby-only'
        self.write_manifest(raw, manifest, state)
        with self.assertRaisesRegex(RuntimeError, 'current common stopped source capture'):
            m.frozen_manifest(self.native, state)

    def test_manifest_digest_is_bound_to_accepted_source_proof(self):
        raw, manifest, state = self.frozen(); self.write_manifest(raw, manifest, state)
        manifest['createdUtc'] = '20261110T003500Z'; (raw / 'manifest.json').write_text(json.dumps(manifest))
        with self.assertRaisesRegex(RuntimeError, 'frozen manifest differs'):
            m.frozen_manifest(self.native, state)

    def test_frozen_bind_must_match_captured_root(self):
        raw, manifest, state = self.frozen(); manifest['dataRoots']['support.kometa']['source'] = '/unrelated'
        self.write_manifest(raw, manifest, state)
        with self.assertRaisesRegex(RuntimeError, 'binding differs'):
            m.frozen_manifest(self.native, state)


if __name__ == '__main__': unittest.main()
