"""Review real policy differences without exposing secrets or enabling jobs."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


m = load('kuma_hba_review', 'scripts/inspect-nas-kuma-hba-handover.py')
review = load('kuma_hba_original', 'scripts/inspect-nas-original-application-controls.py')


class KumaHbaReviewTests(unittest.TestCase):
    def fixture(self):
        ids = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 18, 21, 22, 23, 24, 25, 26, 27, 28]
        source = {'monitor': [{'id': identity, 'name': 'monitor-'+str(identity), 'type': 'http', 'active': int(identity in m.SOURCE_ACTIVE),
            'url': 'https://service.sawdoctor.uk/private-path?secret=private-query', 'hostname': None, 'port': None,
            'method': 'GET', 'accepted_statuscodes': '["200-299"]', 'ignore_tls': 0, 'basic_auth_pass': 'private-password'} for identity in ids],
            'notification': [{'id': 1, 'name': 'private-name', 'active': 1, 'is_default': 0, 'config': 'private-token'}],
            'monitor_notification': [{'monitor_id': 2, 'notification_id': 1}]}
        by_id = {row['id']: row for row in source['monitor']}
        by_id[6]['url'] = 'http://192.168.0.29:81/'
        by_id[10]['url'] = 'http://192.168.0.29:32400/web/'
        by_id[3].update(type='port', hostname='192.168.0.29', port=8081)
        current = copy.deepcopy(source)
        for row in current['monitor']: row['active'] = 0
        current['notification'][0]['active'] = 0; current['monitor_notification'] = []
        return source, current

    def test_plan_preserves_original_policy_except_absent_replacements_and_retargets_only_known_lan_ports(self):
        source, current = self.fixture(); before = copy.deepcopy((source, current))
        result = m.summarize_kuma(source, current, review)
        self.assertEqual(result['proposedActiveIds'], sorted(m.SOURCE_ACTIVE-{22,24}))
        by_id = {row['id']: row for row in result['monitors']}
        self.assertEqual(by_id[6]['proposedOrigin'], 'http://192.168.0.220:10081')
        self.assertEqual(by_id[10]['proposedOrigin'], 'http://192.168.0.220:32400')
        self.assertEqual(by_id[3]['endpointChanges'], ['hostname'])
        self.assertEqual(by_id[2]['proposedOrigin'], 'https://service.sawdoctor.uk')
        self.assertFalse(by_id[5]['proposedActive']); self.assertFalse(by_id[25]['proposedActive'])
        self.assertFalse(result['notifications'][0]['sourceDefault'])
        self.assertEqual(result['sourceNotificationLinks'], [[2,1]])
        self.assertEqual((source, current), before)

    def test_private_values_are_not_in_report_and_real_settings_differences_are_named(self):
        source, current = self.fixture(); current['monitor'][1]['basic_auth_pass'] = 'different-private-password'
        result = m.summarize_kuma(source, current, review)
        self.assertEqual(result['monitors'][1]['otherSourceCurrentDifferentFieldNames'], ['basic_auth_pass'])
        self.assertNotIn('private-', json.dumps(result))
        current['notification'][0]['config'] = 'different-private-token'
        self.assertFalse(m.summarize_kuma(source, current, review)['notifications'][0]['sameNameAndConfiguration'])

    def test_foreign_monitor_identity_or_source_policy_is_retained_for_review(self):
        for field, value in [('name', 'replacement'), ('type', 'port')]:
            source, current = self.fixture(); current['monitor'][0][field] = value
            with self.assertRaisesRegex(RuntimeError, 'identity changed'): m.summarize_kuma(source, current, review)
        source, current = self.fixture(); source['monitor'][0]['active'] = 1
        with self.assertRaisesRegex(RuntimeError, 'active-monitor choices'): m.summarize_kuma(source, current, review)

    def test_unreviewed_npm_origin_and_symlinked_collector_are_not_followed(self):
        source, current = self.fixture(); source['monitor'][5]['url'] = 'http://foreign.invalid:81/'
        with self.assertRaisesRegex(RuntimeError, 'private endpoint'): m.summarize_kuma(source, current, review)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); script = root/'collector'; script.write_text('private collector source')
            symbolic = root/'symbolic'; symbolic.symlink_to(script)
            self.assertIsNone(m.bounded(symbolic))
            self.assertEqual(m.bounded(script), b'private collector source')


if __name__ == '__main__': unittest.main()
