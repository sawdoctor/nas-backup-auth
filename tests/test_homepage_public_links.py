"""Only clickable LAN hrefs change; exact API/template/comment bytes survive."""
import importlib.util
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import yaml

path = Path(__file__).resolve().parents[1] / 'scripts/fix-nas-homepage-public-links.py'
spec = importlib.util.spec_from_file_location('home_links', path)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class HomepageLinks(unittest.TestCase):
    def test_only_href_changes_not_widget_or_private_credential_bytes(self):
        source = '''# Keep this comment and spacing
- Media:
    - Radarr:
        href: http://192.168.0.220:7878/ # clicked by phone
        icon: custom-infinidysk-icon.png
        widget:
          type: radarr
          url: http://192.168.0.220:7878/
          key: "private-api-key"
'''
        result, changes, _ = m.repair(source, {7878: {'radarr.sawdoctor.uk'}})
        expected = source.replace('href: http://192.168.0.220:7878/', 'href: "https://radarr.sawdoctor.uk/"')
        self.assertEqual(result, expected)
        self.assertEqual(changes, [{'tile': 'Radarr', 'oldEndpoint': '192.168.0.220:7878', 'publicHost': 'radarr.sawdoctor.uk'}])

    def test_unquoted_homepage_environment_template_is_not_evaluated_or_changed(self):
        source = '''- Media:
  - Radarr:
      href: http://192.168.0.220:7878
      widget:
        url: http://192.168.0.220:7878
        key: {{HOMEPAGE_VAR_RADARR_KEY}}
'''
        result, changes, _ = m.repair(source, {7878: {'radarr.sawdoctor.uk'}})
        self.assertEqual(result, source.replace('href: http://192.168.0.220:7878', 'href: "https://radarr.sawdoctor.uk"'))
        self.assertEqual(len(changes), 1)

    def test_existing_public_and_external_links_stay_identical(self):
        source = '- Links:\n  - Cloudflare:\n      href: https://dash.cloudflare.com/\n  - Fail2ban:\n      href: https://fail2ban.sawdoctor.uk/\n'
        self.assertEqual(m.repair(source, {3091: {'fail2ban.sawdoctor.uk'}})[0], source)

    def test_path_query_and_fragment_are_retained_and_hostname_not_guessed(self):
        source = '- Apps:\n  - Reader:\n      href: http://192.168.0.29:5000/login?skipAutoLogin=false#part\n'
        result, _, _ = m.repair(source, {5000: {'kavita.sawdoctor.uk'}})
        self.assertIn('"https://kavita.sawdoctor.uk/login?skipAutoLogin=false#part"', result)
        self.assertNotIn('www.', result)

    def test_private_admin_links_are_not_restored_to_public_hostnames(self):
        source = '- Admin:\n  - Dockmon:\n      href: https://192.168.0.220:8001/\n  - OMV:\n      href: http://192.168.0.220/\n'
        result, changes, _ = m.repair(source, {8001: {'dockmon.sawdoctor.uk'}, 80: {'omv.sawdoctor.uk'}})
        self.assertEqual(result, source)
        self.assertEqual(changes, [])

    def test_unknown_ambiguous_and_unrelated_lan_targets_are_not_guessed(self):
        source = '- Apps:\n  - A:\n      href: http://192.168.0.220:7878\n  - B:\n      href: http://192.168.0.220:9999\n  - C:\n      href: http://192.168.0.50:7878\n'
        result, changes, _ = m.repair(source, {7878: {'radarr.sawdoctor.uk', 'another.sawdoctor.uk'}})
        self.assertEqual(result, source)
        self.assertEqual(changes, [])

    def test_widget_href_and_shared_widget_alias_do_not_change(self):
        source = '- Apps:\n  - A:\n      widget: &widget\n        href: http://192.168.0.220:7878\n        url: http://192.168.0.220:7878\n  - B:\n      widget: *widget\n'
        self.assertEqual(m.repair(source, {7878: {'radarr.sawdoctor.uk'}})[0], source)

    def test_anchored_scalar_is_not_replaced_in_a_way_that_breaks_aliases(self):
        source = '- Apps:\n  - A:\n      href: &link http://192.168.0.220:7878\n  - B:\n      href: *link\n'
        self.assertEqual(m.repair(source, {7878: {'radarr.sawdoctor.uk'}})[0], source)

    def test_recursive_yaml_is_rejected_before_writing(self):
        with self.assertRaisesRegex(RuntimeError, 'Recursive'):
            m.repair('a: &a {b: *a}', {})

    def test_unicode_offsets_preserve_comments_and_icons(self):
        source = '- 🎬 Media:\n  - Radarr:\n      icon: 🎥\n      href: http://192.168.0.220:7878 # 🎞\n'
        result, _, _ = m.repair(source, {7878: {'radarr.sawdoctor.uk'}})
        self.assertEqual(result, source.replace('href: http://192.168.0.220:7878', 'href: "https://radarr.sawdoctor.uk"'))

    def test_npm_routes_are_read_only_and_filter_deleted_disabled_or_source_targets(self):
        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder) / 'database.sqlite'
            db = sqlite3.connect(database)
            db.execute('CREATE TABLE proxy_host(domain_names TEXT,forward_host TEXT,forward_port INTEGER,enabled INTEGER,is_deleted INTEGER,certificate_id INTEGER)')
            db.executemany('INSERT INTO proxy_host VALUES (?,?,?,?,?,?)', [
                ('["radarr.sawdoctor.uk"]', '192.168.0.220', 7878, 1, 0, 1),
                ('["old.sawdoctor.uk"]', '192.168.0.29', 9990, 1, 0, 1),
                ('["disabled.sawdoctor.uk"]', '192.168.0.220', 9991, 0, 0, 1),
                ('["deleted.sawdoctor.uk"]', '192.168.0.220', 9992, 1, 1, 1),
                ('["dockmon.sawdoctor.uk"]', '192.168.0.220', 8001, 1, 0, 1),
            ]); db.commit(); db.close()
            before = database.read_bytes()
            self.assertEqual(m.routes(database), {7878: {'radarr.sawdoctor.uk'}})
            self.assertEqual(database.read_bytes(), before)

    def test_apply_flag_required_before_host_queries(self):
        with patch.object(m.subprocess, 'check_output') as query, self.assertRaisesRegex(RuntimeError, 'apply flag'):
            m.main()
        query.assert_not_called()


if __name__ == '__main__': unittest.main()
