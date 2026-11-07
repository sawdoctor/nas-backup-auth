import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'scripts'
if not SCRIPTS.is_dir():
    SCRIPTS = ROOT / 'nas-backup-auth/scripts'
spec = importlib.util.spec_from_file_location('kometa_policy_report', SCRIPTS / 'check-nas-kometa-policy.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)

OLD = b'''plex:
  url: http://user:PRIVATE_URL_PASSWORD@192.168.0.29:32400/private?token=PRIVATE_QUERY
  token: PRIVATE_PLEX_TOKEN
radarr:
  url: http://192.168.0.29:7878
  api_key: PRIVATE_RADARR_KEY
  add_missing: false
libraries:
  Movies:
    collection_files:
      - file: /config/uk-us-movies.yml
collections:
  UK US:
    tmdb_discover:
      with_origin_country: GB|US
      with_original_language: en
    radarr_add_missing: false
'''


class PolicyTests(unittest.TestCase):
    def output(self, before=OLD, after=None):
        source = {name: before for name in s.FILES}
        live = {name: before if after is None else after for name in s.FILES}
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            s.report(source, live)
        return out.getvalue()

    def test_reports_flags_filters_references_hosts_without_credentials(self):
        output = self.output()
        self.assertIn('GB|US', output)
        self.assertIn('with_original_language: "en"', output)
        self.assertIn('add_missing: false', output)
        self.assertIn('/config/uk-us-movies.yml', output)
        self.assertIn('192.168.0.29:32400', output)
        self.assertNotIn('PRIVATE', output)
        self.assertNotIn('token', output)

    def test_endpoint_and_credential_only_differences_are_distinguished(self):
        after = OLD.replace(b'192.168.0.29', b'192.168.0.220').replace(b'PRIVATE_PLEX_TOKEN', b'NEW_SECRET')
        output = self.output(after=after)
        self.assertIn('same policy apart from credentials/connection URLs', output)
        self.assertIn('192.168.0.220:32400', output)
        self.assertNotIn('NEW_SECRET', output)

    def test_changed_add_missing_or_filter_is_a_policy_difference(self):
        for after in (OLD.replace(b'add_missing: false', b'add_missing: true'), OLD.replace(b'GB|US', b'US')):
            with self.subTest(after=after):
                self.assertIn('POLICY DIFFERS', self.output(after=after))

    def test_missing_boolean_is_not_reported_as_disabled(self):
        output = self.output(b'collections: {Example: {sort_title: A}}\n')
        self.assertIn('no explicit', output)
        self.assertNotIn('add_missing: false', output)

    def test_non_boolean_settings_are_flagged_and_types_not_conflated(self):
        output = self.output(after=OLD.replace(b'add_missing: false', b'add_missing: 0'))
        self.assertIn('[not a literal boolean]', output)
        self.assertIn('POLICY DIFFERS', output)

    def test_nested_secret_fields_and_untrusted_urls_are_hidden(self):
        data = b'''api_key:
  with_original_language: PRIVATE_LANGUAGE
webhooks:
  error: https://example.invalid/PRIVATE_WEBHOOK
plex:
  url: https://PRIVATE_USER:PRIVATE_PASS@example.invalid/PRIVATE_PATH?api_key=PRIVATE_QUERY
collections:
  Item:
    with_original_language: https://example.invalid/PRIVATE_FILTER
    file: https://example.invalid/PRIVATE_FILE
'''
        output = self.output(data)
        self.assertNotIn('PRIVATE', output)
        self.assertNotIn('example.invalid', output)
        self.assertIn('[other host withheld]', output)

    def test_yaml_errors_do_not_echo_private_input(self):
        with self.assertRaises(RuntimeError) as error:
            s.parse(b'token: [PRIVATE_BAD_TOKEN\n')
        self.assertNotIn('PRIVATE', str(error.exception))

    def test_recursive_and_excessive_aliases_are_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'recursive'):
            s.parse(b'loop: &loop {next: *loop}\n')
        with self.assertRaisesRegex(RuntimeError, 'limit'):
            s.parse(('items: [' + ','.join('a' for _ in range(10001)) + ']\n').encode())

    def test_unsafe_yaml_constructors_are_not_executed(self):
        with patch.object(os, 'system') as command, self.assertRaises(RuntimeError):
            s.parse(b'!!python/object/apply:os.system [echo unsafe]\n')
        command.assert_not_called()


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root / 'standby'
        self.snapshot = self.base / 'snapshots/20261107T003613Z'
        (self.snapshot / 'data/support.kometa').mkdir(parents=True)
        self.current = {'format': s.FORMAT, 'createdUtc': self.snapshot.name, 'sha256': 'a' * 64}
        (self.base / 'current.json').write_text(json.dumps({**self.current, 'snapshot': str(self.snapshot)}))
        (self.snapshot / '_VERIFIED.json').write_text(json.dumps(self.current))
        manifest = {'format': s.FORMAT, 'scope': 'standby-only', 'sourceHost': '192.168.0.29',
                    'createdUtc': self.snapshot.name, 'dataRoots': {'support.kometa': {'snapshot': 'data/support.kometa'}},
                    'containers': [{'Name': '/kometa', 'Image': 'sha256:fixture',
                                    'Config': {'Env': ['KOMETA_TOKEN=PRIVATE_RUNTIME_TOKEN'], 'Cmd': ['--config', '/config/config.yml']}}]}
        (self.snapshot / 'manifest.json').write_text(json.dumps(manifest))
        for name in s.FILES:
            (self.snapshot / 'data/support.kometa' / name).write_bytes(OLD)
        self.checks = self.snapshot / 'SHA256SUMS'
        self.checks.write_text(''.join(hashlib.sha256(path.read_bytes()).hexdigest() + '  ./' + str(path.relative_to(self.snapshot)) + '\n'
                                      for path in [self.snapshot / 'manifest.json', *(self.snapshot / 'data/support.kometa' / name for name in s.FILES)]))
        self.patches = contextlib.ExitStack()
        self.addCleanup(self.patches.close)
        self.patches.enter_context(patch.object(s, 'BASE', self.base))

    def test_checks_only_the_selected_files_and_retains_inputs(self):
        before = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in self.snapshot.rglob('*') if path.is_file()}
        stamp, files, container = s.latest()
        self.assertEqual(stamp, self.snapshot.name)
        self.assertEqual(files, {name: OLD for name in s.FILES})
        self.assertEqual(container['Name'], '/kometa')
        self.assertEqual(before, {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in before})

    def test_checksum_mismatch_missing_and_duplicate_entries_fail(self):
        original = self.checks.read_text()
        variants = [original.replace(original[:64], '0' * 64, 1), '\n'.join(original.splitlines()[:-1]) + '\n', original + original.splitlines()[0] + '\n']
        for text in variants:
            self.checks.write_text(text)
            with self.subTest(text=text[:70]), self.assertRaises(RuntimeError):
                s.latest()

    def test_changed_locator_marker_manifest_and_symbolic_inputs_fail(self):
        original = (self.base / 'current.json').read_text()
        (self.base / 'current.json').write_text(original.replace(str(self.snapshot), '/another/snapshot'))
        with self.assertRaisesRegex(RuntimeError, 'locator'):
            s.latest()
        (self.base / 'current.json').write_text(original)
        (self.snapshot / '_VERIFIED.json').write_text('{}')
        with self.assertRaisesRegex(RuntimeError, 'marker'):
            s.latest()
        (self.snapshot / '_VERIFIED.json').write_text(json.dumps(self.current))
        target = self.snapshot / 'data/support.kometa/config.yml'
        target.unlink()
        target.symlink_to(self.snapshot / 'data/support.kometa/uk-us-tv.yml')
        with self.assertRaisesRegex(RuntimeError, 'symbolic'):
            s.latest()

    def test_unrelated_escaped_checksum_names_do_not_require_bulk_reads(self):
        with self.checks.open('ab') as stream:
            stream.write(b'\\' + b'f' * 64 + b'  ./unrelated\\nfilename\n')
        with patch.object(Path, 'read_text', side_effect=AssertionError('no bulk text read')), patch.object(Path, 'read_bytes', side_effect=AssertionError('no bulk bytes read')):
            self.assertEqual(s.latest()[0], self.snapshot.name)

    def test_file_and_checksum_line_limits(self):
        with self.assertRaisesRegex(RuntimeError, 'size limit'):
            s.read(self.snapshot / 'manifest.json', 1)
        self.checks.write_bytes(b'x' * 65537)
        with self.assertRaisesRegex(RuntimeError, 'size limit'):
            s.latest()

    def test_mount_query_requires_exact_uuid_and_filesystem(self):
        with patch.object(Path, 'is_mount', return_value=True):
            for answer in ('wrong-uuid ext4', s.APP_UUID + ' xfs', ''):
                with patch.object(s, 'run', return_value=answer), self.assertRaises(RuntimeError):
                    s.mount(self.root, s.APP_UUID)

    def test_full_read_only_report_does_not_change_files_or_execute_container(self):
        live = self.root / 'live'
        live.mkdir()
        for name in s.FILES:
            (live / name).write_bytes(OLD)
        backup_lock = self.root / 'backup.lock'
        backup_lock.touch()
        (self.base / '.run.lock').touch()
        row = {'Name': '/kometa-nas', 'Image': 'sha256:fixture',
               'Config': {'Env': ['KOMETA_TOKEN=PRIVATE_RUNTIME_TOKEN'], 'Cmd': ['--config', '/config/config.yml']},
               'State': {'Status': 'created', 'Running': False},
               'HostConfig': {'RestartPolicy': {'Name': 'no'}},
               'Mounts': [{'Source': str(live), 'Destination': '/config'}]}
        calls = []
        def query(*args):
            calls.append(args)
            if args[0] == 'ip':
                return 'inet 192.168.0.220/24'
            if args == ('docker', 'inspect', 'kometa-nas'):
                return json.dumps([row])
            raise AssertionError(args)
        before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.rglob('*') if p.is_file()}
        out = io.StringIO()
        with patch.object(s, 'LIVE', live), patch.object(s, 'LOCK', backup_lock), patch.object(s.os, 'geteuid', return_value=0), \
                patch.object(s, 'mount'), patch.object(s, 'run', side_effect=query), contextlib.redirect_stdout(out):
            s.main()
        self.assertIn('REPORT COMPLETE', out.getvalue())
        self.assertIn('image identity matches captured source: true', out.getvalue())
        self.assertNotIn('PRIVATE', out.getvalue())
        self.assertEqual(calls, [('ip', '-4', 'addr', 'show'), ('docker', 'inspect', 'kometa-nas')])
        self.assertEqual(before, {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.rglob('*') if p.is_file()})

    def test_runtime_differences_never_print_environment_or_arguments(self):
        source = {'Image': 'sha256:a', 'Config': {'Cmd': ['PRIVATE_OLD_ARGUMENT'], 'Env': ['TOKEN=PRIVATE_OLD_TOKEN']}}
        live = {'Image': 'sha256:b', 'Config': {'Cmd': ['PRIVATE_NEW_ARGUMENT'], 'Env': ['TOKEN=PRIVATE_NEW_TOKEN']}}
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            s.runtime_report(source, live)
        self.assertEqual(out.getvalue().count('false'), 3)
        self.assertNotIn('PRIVATE', out.getvalue())


if __name__ == '__main__':
    unittest.main()
