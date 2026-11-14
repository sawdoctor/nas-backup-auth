"""Immutable image selection and isolation of a stopped Kometa recreation."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


m = load('refresh_kometa', 'refresh-nas-kometa-source-image.py')
s = load('start_kometa_image_test', 'start-nas-production-kometa.py')


class RefreshKometa(unittest.TestCase):
    def setUp(self):
        self.source = {'Config': {'Image': 'kometateam/kometa:latest', 'Env': ['TZ=Europe/London', 'EXAMPLE=literal$value'],
                                  'Cmd': ['--times', '05:00'], 'Entrypoint': ['/entrypoint'], 'User': '1000:1000', 'WorkingDir': '/app'}}
        self.old = {'Id': 'old-id', 'Image': 'sha256:' + 'b' * 64,
                    'Config': {'Image': 'sha256:' + 'b' * 64, 'Env': ['TZ=Europe/London'], 'Cmd': ['old-command'],
                               'Entrypoint': ['/old'], 'User': '', 'WorkingDir': ''},
                    'HostConfig': {'RestartPolicy': {'Name': 'no'}, 'NetworkMode': 'media-core'},
                    'Mounts': [{'Source': '/nas/kometa', 'Destination': '/config'}],
                    'State': {'Running': False, 'Status': 'created', 'StartedAt': '0', 'FinishedAt': '0'}}
        self.image = {'Os': 'linux', 'Architecture': 'amd64', 'RepoDigests': ['kometateam/kometa@sha256:' + 'a' * 64]}
        self.model = {'name': 'support-nas', 'services': {
            'kometa': {'container_name': 'kometa-nas', 'image': self.old['Image'], 'restart': 'no',
                       'profiles': ['plex-cutover'], 'environment': {'TZ': 'Europe/London'},
                       'command': ['old-command'], 'volumes': ['/nas/kometa:/config'], 'networks': ['media-core']},
            'homepage': {'image': 'untouched-homepage', 'environment': {'PRIVATE': 'keep$$secret'}, 'ports': ['3002:3000']},
            'tracearr': {'image': 'untouched-tracearr', 'depends_on': ['tracearr-db'], 'restart': 'unless-stopped'}}}

    def test_pull_uses_exact_recorded_digest_instead_of_latest(self):
        result = m.immutable_reference(self.source, self.image)
        self.assertEqual(result, 'kometateam/kometa@sha256:' + 'a' * 64)
        self.assertNotIn(':latest', result)

    def test_equivalent_docker_hub_repository_names_are_recognized(self):
        self.source['Config']['Image'] = 'docker.io/kometateam/kometa:latest'
        self.assertEqual(m.immutable_reference(self.source, self.image), self.image['RepoDigests'][0])

    def test_missing_digest_has_no_mutable_tag_fallback(self):
        self.image['RepoDigests'] = []
        with self.assertRaisesRegex(RuntimeError, 'unique immutable digest'):
            m.immutable_reference(self.source, self.image)

    def test_other_repository_or_multiple_digests_are_rejected(self):
        self.image['RepoDigests'] = ['other/project@sha256:' + 'a' * 64]
        with self.assertRaises(RuntimeError): m.immutable_reference(self.source, self.image)
        self.image['RepoDigests'] = ['kometateam/kometa@sha256:' + char * 64 for char in ('a', 'b')]
        with self.assertRaises(RuntimeError): m.immutable_reference(self.source, self.image)

    def test_unsupported_platform_is_rejected(self):
        self.image['Architecture'] = 'arm64'
        with self.assertRaisesRegex(RuntimeError, 'unreviewed image platform'):
            m.immutable_reference(self.source, self.image)

    def test_candidate_changes_only_kometa_and_preserves_nas_bindings(self):
        before = copy.deepcopy(self.model)
        result = m.candidate_model(self.model, self.source, 'sha256:' + 'c' * 64, s, self.old)
        self.assertEqual(self.model, before)
        self.assertEqual(result['services']['homepage'], before['services']['homepage'])
        self.assertEqual(result['services']['tracearr'], before['services']['tracearr'])
        self.assertEqual(result['services']['kometa']['volumes'], before['services']['kometa']['volumes'])
        self.assertEqual(result['services']['kometa']['networks'], before['services']['kometa']['networks'])
        self.assertEqual(result['services']['kometa']['profiles'], ['plex-cutover'])
        self.assertEqual(result['services']['kometa']['restart'], 'no')
        self.assertEqual(result['services']['kometa']['pull_policy'], 'never')

    def test_new_image_uses_frozen_defaults_and_original_schedule(self):
        result = m.candidate_model(self.model, self.source, 'sha256:' + 'c' * 64, s, self.old)['services']['kometa']
        self.assertEqual(result['command'], ['--times', '05:00'])
        self.assertEqual(result['entrypoint'], ['/entrypoint'])
        self.assertEqual(result['user'], '1000:1000'); self.assertEqual(result['working_dir'], '/app')
        self.assertEqual(result['environment']['EXAMPLE'], 'literal$$value')
        self.assertNotIn('--run', result['command'])

    def test_image_refresh_rejects_connection_overrides_before_deployment(self):
        self.source['Config']['Env'].append('PLEX_URL=http://192.168.0.29:32400')
        before = copy.deepcopy(self.model)
        with self.assertRaisesRegex(RuntimeError, 'override'):
            m.candidate_model(self.model, self.source, 'sha256:' + 'c' * 64, s, self.old)
        self.assertEqual(self.model, before)

    def test_dependencies_or_restartable_service_cannot_be_recreated(self):
        self.model['services']['kometa']['depends_on'] = ['plex']
        with self.assertRaisesRegex(RuntimeError, 'isolated existing service'):
            m.candidate_model(self.model, self.source, 'sha256:' + 'c' * 64, s, self.old)
        self.model['services']['kometa'].pop('depends_on')
        self.model['services']['kometa']['restart'] = 'always'
        with self.assertRaisesRegex(RuntimeError, 'restart policy'):
            m.candidate_model(self.model, self.source, 'sha256:' + 'c' * 64, s, self.old)

    def test_health_and_mount_order_changes_are_not_mistaken_for_restart(self):
        before = copy.deepcopy(self.old)
        before['Mounts'].append({'Source': '/other', 'Destination': '/other'})
        after = copy.deepcopy(before); after['Mounts'].reverse(); after['State']['Health'] = {'Status': 'healthy'}
        self.assertEqual(m.preserve_others({'plex-nas': before}), m.preserve_others({'plex-nas': after}))

    def test_an_actual_other_container_restart_is_detected(self):
        after = copy.deepcopy(self.old); after['State']['StartedAt'] = 'later'
        self.assertNotEqual(m.preserve_others({'plex-nas': self.old}), m.preserve_others({'plex-nas': after}))

    def test_expected_kometa_identity_change_is_excluded_from_other_container_guard(self):
        after = copy.deepcopy(self.old); after['Id'] = 'new-id'
        self.assertEqual(m.preserve_others({'kometa-nas': self.old}), m.preserve_others({'kometa-nas': after}))

    def test_known_dockmon_compatibility_link_is_resolved_to_actual_compose(self):
        with tempfile.TemporaryDirectory() as folder:
            app = Path(folder); canonical = app / 'appdata/dockmon/stacks/support-nas/compose.yaml'
            canonical.parent.mkdir(parents=True); canonical.write_text('services: {}')
            legacy = app / 'compose/support-nas/compose.json'; legacy.parent.mkdir(parents=True); legacy.symlink_to(canonical)
            row = {'Config': {'Labels': {'com.docker.compose.project': 'support-nas', 'com.docker.compose.service': 'kometa',
                                        'com.docker.compose.project.config_files': str(legacy)}}}
            native = type('Native', (), {'safe': staticmethod(lambda path: None)})()
            with patch.object(m, 'APP', app): self.assertEqual(m.compose_path(native, row), canonical)

    def test_compose_yaml12_no_and_on_remain_strings(self):
        parsed = m.compose_model('services:\n  kometa:\n    restart: no\n    environment:\n      MODE: off\n      TOKEN: ON\n')
        self.assertEqual(parsed['services']['kometa']['restart'], 'no')
        self.assertEqual(parsed['services']['kometa']['environment'], {'MODE': 'off', 'TOKEN': 'ON'})

    def test_compose_boolean_controls_and_date_strings_preserved(self):
        parsed = m.compose_model('services:\n  kometa:\n    init: true\n    environment:\n      DATE: 2026-11-14\n')
        self.assertIs(parsed['services']['kometa']['init'], True)
        self.assertEqual(parsed['services']['kometa']['environment']['DATE'], '2026-11-14')


if __name__ == '__main__': unittest.main()
