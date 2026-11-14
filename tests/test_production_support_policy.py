"""Source acquisition/notification policies survive endpoint and key changes."""
import copy
import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[1] / 'scripts/production-support-policy.py'
spec = importlib.util.spec_from_file_location('support_policy', path)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class SupportPolicy(unittest.TestCase):
    def setUp(self):
        self.keys = {'sonarr': 'nas-tv-key', 'radarr': 'nas-hd-key', 'radarr4k': 'nas-4k-key'}
        self.source = {
            'plex': {'url': 'http://192.168.0.29:32400', 'token': 'frozen-plex-token'},
            'radarr': {'url': 'http://192.168.0.29:7878', 'token': 'old-hd-key', 'add_missing': True, 'search': True},
            'sonarr': {'url': 'http://sonarr:8989', 'token': 'old-tv-key', 'add_missing': True, 'search': False, 'monitor': 'all'},
            'libraries': {
                'Movies': {'collection_files': [{'file': 'config/uk-us-movies.yml', 'template_variables': {'radarr_add_missing': True, 'radarr_search': True}}]},
                'Movies 4K': {'radarr': {'url': 'http://192.168.0.29:7879', 'token': 'old-4k-key'}, 'collection_files': [{'file': 'config/uk-us-movies4k.yml'}]},
                'TV': {'collection_files': [{'file': 'config/uk-us-tv.yml', 'template_variables': {'sonarr_add_missing': True, 'sonarr_search': False}}]},
            },
            'filters': {'origin_country': ['gb', 'us'], 'original_language': ['en']},
            'tautulli': {'url': 'http://192.168.0.29:8181', 'apikey': 'old-optional-key'},
        }

    def test_only_reviewed_connections_and_keys_change(self):
        original = copy.deepcopy(self.source)
        result = m.kometa(self.source, self.keys)
        expected = copy.deepcopy(original)
        expected['plex']['url'] = 'http://192.168.0.220:32400'
        expected['radarr'].update(url='http://192.168.0.220:7878', token='nas-hd-key')
        expected['sonarr'].update(url='http://192.168.0.220:8989', token='nas-tv-key')
        expected['libraries']['Movies 4K']['radarr'].update(url='http://192.168.0.220:7879', token='nas-4k-key')
        self.assertEqual(result, expected)
        self.assertEqual(self.source, original)

    def test_partial_4k_override_cannot_inherit_hd_key(self):
        self.source['libraries']['Movies 4K']['radarr'].pop('token')
        result = m.kometa(self.source, self.keys)
        self.assertEqual(result['libraries']['Movies 4K']['radarr']['token'], 'nas-4k-key')

    def test_docker_4k_internal_port_is_mapped_to_nas_host_port(self):
        self.source['libraries']['Movies 4K']['radarr']['url'] = 'http://radarr4k:7878'
        result = m.kometa(self.source, self.keys)
        self.assertEqual(result['libraries']['Movies 4K']['radarr']['url'], 'http://192.168.0.220:7879')

    def test_missing_imported_key_fails_without_modifying_source(self):
        original = copy.deepcopy(self.source)
        with self.assertRaises(ValueError):
            m.kometa(self.source, {'sonarr': 'x', 'radarr': 'y'})
        self.assertEqual(self.source, original)

    def test_wrong_application_port_is_rejected(self):
        self.source['radarr']['url'] = 'http://192.168.0.29:8989'
        with self.assertRaises(ValueError):
            m.kometa(self.source, self.keys)

    def test_unknown_lan_port_is_not_silently_accepted(self):
        self.source['radarr']['url'] = 'http://192.168.0.29:12345'
        with self.assertRaises(ValueError):
            m.kometa(self.source, self.keys)

    def test_existing_external_connections_and_public_monitor_urls_stay(self):
        self.source['radarr']['url'] = 'https://radarr.sawdoctor.uk/'
        result = m.kometa(self.source, self.keys)
        self.assertEqual(result['radarr'], self.source['radarr'])
        public = {'url': 'https://request.sawdoctor.uk/', 'active': 1}
        self.assertEqual(m.kuma_monitor(public), public)

    def test_monitor_pauses_and_notification_ids_are_preserved(self):
        for active in (0, 1):
            row = {'id': 27, 'url': 'http://192.168.0.29:5055/api', 'active': active, 'notification_ids': [2, 8], 'retryInterval': 60}
            expected = dict(row, url='http://192.168.0.220:5055/api')
            self.assertEqual(m.kuma_monitor(row), expected)
            self.assertEqual(row['url'], 'http://192.168.0.29:5055/api')

    def test_unsupported_jellyfin_and_admin_targets_are_not_bulk_rewritten(self):
        for value in ('http://192.168.0.29:8096/', 'http://192.168.0.29:3180/', 'https://dockmon.sawdoctor.uk/'):
            self.assertEqual(m.endpoint(value), value)

    def test_api_port_translation_and_url_suffix_preserved(self):
        self.assertEqual(m.endpoint('http://192.168.0.29:8080/api?a=b#part'), 'http://192.168.0.220:8082/api?a=b#part')

    def test_embedded_credentials_are_not_rewritten(self):
        with self.assertRaises(ValueError):
            m.endpoint('http://private:secret@192.168.0.29:5055/')

    def test_recursive_yaml_alias_is_rejected(self):
        source = {}; source['loop'] = source
        with self.assertRaisesRegex(ValueError, 'Recursive'):
            m.kometa(source, self.keys)
        with self.assertRaisesRegex(ValueError, 'Recursive'):
            m.connections(source)


if __name__ == '__main__':
    unittest.main()
