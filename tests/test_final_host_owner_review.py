import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


PATH = Path(__file__).resolve().parents[1] / 'scripts/inspect-nas-final-host-owners.py'
spec = importlib.util.spec_from_file_location('owners', PATH)
owners = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owners)


class FinalOwnersReviewTests(unittest.TestCase):
    def test_system_cron_withholds_arguments_and_tokens(self):
        result = owners.cron_summary('/etc/cron.d/test',
            '*/15 * * * * root /usr/local/sbin/example --token SECRET https://host/api/SECRET\n')
        self.assertEqual(result[0]['schedule'], '*/15 * * * *')
        self.assertEqual(result[0]['scripts'], ['/usr/local/sbin/example'])
        self.assertNotIn('SECRET', json.dumps(result))

    def test_user_cron_and_boot_schedule(self):
        result = owners.cron_summary('spool', '@reboot /home/sawdoctor/scripts/watch.sh --private SECRET', 'sawdoctor')
        self.assertEqual(result[0]['user'], 'sawdoctor')
        self.assertEqual(result[0]['schedule'], '@reboot')
        self.assertNotIn('SECRET', json.dumps(result))

    def test_comments_assignments_and_unparsed_lines(self):
        result = owners.cron_summary('test', '# ignored\nTOKEN=SECRET\ninvalid\n')
        self.assertEqual(result, [{'file': 'test', 'line': 3, 'unparsed': True}])

    def test_abs_settings_do_not_expose_api_key(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'settings.json'
            path.write_text(json.dumps({'ABS_URL': 'http://192.168.0.220:13378', 'ABS_API_KEY': 'SECRET'}))
            result = owners.setting_summary(path)
            self.assertEqual(result['ABS_URL'], 'http://192.168.0.220:13378')
            self.assertNotIn('SECRET', json.dumps(result))

    def test_unexpected_abs_url_credentials_withheld(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'settings.json'
            path.write_text(json.dumps({'ABS_URL': 'http://name:SECRET@other/'}))
            self.assertEqual(owners.setting_summary(path)['ABS_URL'], 'unexpected/withheld')

    def test_npm_summary_omits_environment_and_unrelated_labels(self):
        result = owners.npm_summary({'Config': {'Env': ['TOKEN=SECRET'], 'Labels': {'private': 'SECRET'}},
                                    'State': {'Running': True}, 'Mounts': []})
        self.assertTrue(result['running'])
        self.assertNotIn('SECRET', json.dumps(result))

    def test_archive_summary_withholds_remote_names(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'archive-state.json'
            path.write_text(json.dumps({'version': 1, 'origins': {'SECRET': {}}, 'backups': {'SECRET': {}}}))
            result = owners.archive_summary(path)
            self.assertEqual(result, {'version': 1, 'originsCount': 1, 'backupsCount': 1})
            self.assertNotIn('SECRET', json.dumps(result))

    def test_symlink_and_oversized_inputs_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'file'
            path.write_text('abc')
            link = Path(root) / 'link'
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                owners.read(link)
            with self.assertRaises(RuntimeError):
                owners.read(path, limit=2)


if __name__ == '__main__':
    unittest.main()
