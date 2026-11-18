"""Protect live history/connections while restoring narrowly reviewed switches."""
import contextlib
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('restore_tracearr', ROOT / 'scripts/restore-nas-tracearr-setting-identities.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def fixture():
    original = {'schema': {t: {} for t in (*m.TABLES, 'servers')},
                'settings': [{'name': 'mobileEnabled', 'value': True}, {'name': 'backupScheduleType', 'value': 'daily'},
                             {'name': 'externalUrl', 'value': 'https://tracearr.sawdoctor.uk'}],
                'automations': [{'id': str(i), 'name': 'original rule', 'is_active': True,
                                 'actions': {'keep': "private ' quote $tracearr_controls$"}} for i in range(5)],
                'destinations': [{'id': str(i), 'enabled': True, 'config': 'private unchanged destination'} for i in range(2)],
                'notification_preferences': [{'id': str(i), 'mobile_session_id': 'paired-' + str(i), 'push_enabled': True,
                                              **{k: True for k in m.PUSH_FIELDS}, 'quiet_hours_enabled': False} for i in range(2)],
                'request_services': [], 'newsletters': [],
                'servers': [{'id': 'plex', 'type': 'plex', 'url': 'http://192.168.0.29:32400', 'token': 'original token'}]}
    for row in original['notification_preferences']:
        for key in m.DEVICE_CHOICES:
            row[key] = True
    live = copy.deepcopy(original)
    for row in live['settings']:
        row['value'] = {'mobileEnabled': False, 'backupScheduleType': 'disabled', 'externalUrl': 'http://192.168.0.220:7330'}[row['name']]
    live['settings'] += [{'name': k, 'value': False} for k in sorted(m.DEFAULTS)]
    for table, field in (('automations', 'is_active'), ('destinations', 'enabled'), ('notification_preferences', 'push_enabled')):
        for row in live[table]:
            row[field] = False
    for row in live['notification_preferences']:
        for key in m.DEVICE_CHOICES:
            row[key] = False
    live['request_services'] = [{'id': 'current-request', 'enabled': True, 'config': 'current request token', 'last_sync_at': 'progress'}]
    live['servers'][0].update(url='http://192.168.0.220:32400', token='fixed current token', version='current')
    live['schema']['servers'] = {'new_runtime_metadata': 'text'}
    for dataset in (original, live):
        for index, row in enumerate(dataset['settings'], start=1):
            row['id'] = index
    return original, live


class TracearrControlTests(unittest.TestCase):
    def setUp(self):
        self.output = patch.object(m, 'say')
        self.output.start()
        self.addCleanup(self.output.stop)

    def test_preserves_current_preferences_and_connections_with_original_controls(self):
        source, live = fixture()
        untouched = copy.deepcopy((source, live))
        before, after = m.plan(source, live, copy.deepcopy(live))
        self.assertEqual((source, live), untouched)
        self.assertEqual(set(after['settings']), {'mobileEnabled', 'backupScheduleType', 'externalUrl'})
        self.assertTrue(all(r['is_active'] for r in after['automations'].values()))
        self.assertTrue(all(r['enabled'] for r in after['destinations'].values()))
        self.assertTrue(all(r['push_enabled'] and all(r[k] for k in m.DEVICE_CHOICES)
                            for r in after['notification_preferences'].values()))
        self.assertNotIn('request_services', after)
        self.assertEqual(after['automations']['0']['actions'], before['automations']['0']['actions'])

    def test_edited_rule_refused(self):
        source, live = fixture()
        live['automations'][0]['actions'] = {'changed': True}
        with self.assertRaisesRegex(RuntimeError, 'beyond'):
            m.plan(source, live, live)

    def test_device_mutes_refused_before_enabling_shared_senders(self):
        source, live = fixture()
        live['notification_preferences'][0]['on_new_device'] = False
        with self.assertRaisesRegex(RuntimeError, 'mutes'):
            m.plan(source, live, live)

    def test_original_three_choices_must_match_native_true_false_evidence(self):
        for changed in ('source', 'current'):
            source, live = fixture()
            target = source if changed == 'source' else live
            target['notification_preferences'][0]['on_stream_started'] = changed == 'current'
            with self.subTest(changed=changed), self.assertRaisesRegex(RuntimeError, 'native evidence'):
                m.plan(source, live, live)

    def test_unrelated_notification_preference_cannot_be_written(self):
        source, live = fixture()
        before, after = m.plan(source, live, live)
        after['notification_preferences']['0']['quiet_hours_enabled'] = True
        with self.assertRaisesRegex(RuntimeError, 'unrelated'):
            m.changes_sql(before, after)

    def test_new_device_and_explicit_default_edit_are_retained(self):
        for variant in ('device', 'setting'):
            source, live = fixture()
            if variant == 'device':
                live['notification_preferences'][0]['mobile_session_id'] = 'new pairing'
            else:
                next(r for r in live['settings'] if r['name'] == 'pollerEnabled')['value'] = True
            with self.subTest(variant=variant), self.assertRaises(RuntimeError):
                m.plan(source, live, live)

    def test_runtime_must_prove_version_defaults_and_noop_device_migration(self):
        good = {'version': '3.1.7', 'defaults': dict.fromkeys(m.DEFAULTS, True),
                'sourceDefaultFallback': True, 'allTrueDeviceGuard': True}
        m.check_runtime(good)
        for key, value in (('version', '3.2.0'), ('sourceDefaultFallback', False), ('allTrueDeviceGuard', False)):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                m.check_runtime(dict(good, **{key: value}))

    def test_installed_runtime_reader_executes_with_real_node(self):
        settings = 'const PUBLIC_DEFAULTS = {\n' + ''.join(k + ': true,\n' for k in sorted(m.DEFAULTS)) + '};\nALL_DEFAULTS[key];'
        files = {'/app/.build-info.json': json.dumps({'version': '3.1.7', 'commit': 'published'}),
                 '/app/apps/server/dist/services/settings.js': settings,
                 '/app/apps/server/dist/services/pushDelivery.js': 'rows.every((row) => PUSH_PREFERENCES.every((key) => row[key]))'}
        prefix = 'const files=' + json.dumps(files) + '; const fs={readFileSync:(path)=>files[path]};'
        script = m.RUNTIME_JS.replace("const fs=require('fs');", prefix)
        result = subprocess.run(['node', '-e', script], check=True, text=True, capture_output=True)
        m.check_runtime(json.loads(result.stdout))

    def test_sql_cannot_modify_unrelated_fields_or_delete_rule(self):
        source, live = fixture()
        before, after = m.plan(source, live, live)
        for mutation in ('action', 'identity', 'setting'):
            bad = copy.deepcopy(after)
            if mutation == 'action': bad['automations']['0']['actions'] = 'changed'
            elif mutation == 'identity': del bad['destinations']['0']
            else: bad['settings']['unrelated'] = {'name': 'unrelated', 'value': 'no'}
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                m.changes_sql(before, bad)

    def test_sql_uses_guarded_transaction_scope_and_collision_safe_quotes(self):
        source, live = fixture()
        before, after = m.plan(source, live, live)
        sql = m.changes_sql(before, after)
        self.assertIn('IS DISTINCT FROM', sql)
        self.assertIn("private '' quote $tracearr_controls$", sql)
        self.assertTrue(sql.startswith('DO $trace_'))
        self.assertNotIn('UPDATE public."request_services"', sql)
        self.assertNotIn('UPDATE public."servers"', sql)
        self.assertNotIn('DELETE FROM public."sessions"', sql)
        with self.assertRaises(RuntimeError): m.changes_sql(before, after, 'untrusted')

    def test_postgres_regressions_write_only_session_temporary_tables(self):
        source, live = fixture()
        before, after = m.plan(source, live, live)
        captured = []
        def execute(sql, native):
            captured.append(sql)
            return 'TEMPORARY TRACEARR CONTROL TESTS PASSED'
        with patch.object(m, 'execute', side_effect=execute):
            m.database_tests(before, after, object())
        sql = captured[0]
        self.assertIn('CREATE TEMP TABLE', sql)
        self.assertIn('UPDATE pg_temp.', sql)
        self.assertNotIn('UPDATE public.', sql)
        self.assertNotIn('INSERT INTO public.', sql)
        self.assertNotIn('DELETE FROM public.', sql)
        self.assertIn("RAISE EXCEPTION 'intentional test rollback'", sql)
        self.assertIn('ROLLBACK;', sql)

    def test_progress_fields_ignored_but_working_tokens_are_protected(self):
        _, live = fixture()
        changed = copy.deepcopy(live)
        changed['servers'][0]['version'] = 'next'
        changed['request_services'][0]['last_sync_at'] = 'new progress'
        self.assertEqual(m.protected(live), m.protected(changed))
        changed['servers'][0]['token'] = 'new secret'
        self.assertNotEqual(m.protected(live), m.protected(changed))

    def test_existing_setting_ids_are_retained_and_updated_without_sequence_use(self):
        source, live = fixture()
        before, after = m.plan(source, live, live)
        for key in after['settings']:
            self.assertEqual(after['settings'][key]['id'], before['settings'][key]['id'])
        sql = m.changes_sql(before, after)
        self.assertIn('UPDATE public.settings SET value=', sql)
        self.assertNotIn('INSERT INTO public.settings', sql)

    def test_rollback_restores_original_generated_ids_with_system_override(self):
        source, live = fixture()
        before, after = m.plan(source, live, live)
        sql = m.changes_sql(after, before)
        for key in m.DEFAULTS:
            start = 'INSERT INTO public.settings(id,name,value) OVERRIDING SYSTEM VALUE VALUES (' + str(before['settings'][key]['id'])
            self.assertIn(start, sql)
        self.assertNotIn('setval', sql)

    def test_existing_identity_edits_and_unknown_setting_columns_are_refused(self):
        for mutation in ('id', 'extra', 'bool-id'):
            source, live = fixture()
            before, after = m.plan(source, live, live)
            row = after['settings']['mobileEnabled']
            if mutation == 'id': row['id'] += 100
            elif mutation == 'extra': row['unreviewed'] = 'retain'
            else: row['id'] = True
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                m.changes_sql(before, after)

    def test_postgres_fixture_accepts_real_generated_always_identity_column(self):
        source, live = fixture()
        before, after = m.plan(source, live, live)
        captured = []
        with patch.object(m, 'execute', side_effect=lambda sql, native: captured.append(sql) or 'TEMPORARY TRACEARR CONTROL TESTS PASSED'):
            m.database_tests(before, after, object())
        sql = captured[0]
        self.assertIn('INSERT INTO pg_temp."settings" OVERRIDING SYSTEM VALUE SELECT *', sql)
        self.assertNotIn('INSERT INTO pg_temp."automations" OVERRIDING', sql)

    def worker_fixture(self, folder):
        original, live = fixture()
        work = folder / 'handover'; work.mkdir()
        review = folder / 'review'; review.mkdir()
        record = {'format': 'reviewed', 'phase': 'reviewed', 'cutoverId': 'this-cutover', 'temporaryPostgresRemoved': True,
                  'originalSha256': m.sha(m.encoded(original)), 'currentSha256': m.sha(m.encoded(live)),
                  'currentImages': {m.APP: 'image', 'tracearr-db-nas': 'db-image'}}
        for name, data in (('report.json', record), ('original-controls.json', original), ('current-controls.json', live)):
            (review / name).write_bytes(m.encoded(data))
        rows = {m.APP: {'Id': 'app-id', 'Image': 'image', 'Config': {'keep': True}, 'HostConfig': {}, 'Mounts': [],
                       'State': {'Running': True, 'StartedAt': '2026-11-18T12:00:00Z'}},
                'tracearr-db-nas': {'Id': 'db-id', 'Image': 'db-image', 'State': {'Running': True}}}
        commands = []; applications = []; current = [copy.deepcopy(live)]
        def run(*args, **kwargs):
            commands.append(args)
            return ''
        def atomic(path, value, **kwargs):
            path.write_bytes(value if isinstance(value, bytes) else m.encoded(value))
        native = SimpleNamespace(read=lambda p: p.read_bytes(), atomic=atomic, run=run, catalog=lambda: copy.deepcopy(rows))
        boot = SimpleNamespace(boot_lock=lambda native: contextlib.nullcontext())
        backup = SimpleNamespace(preflight=lambda native: ({'proof': {'cutoverId': 'this-cutover'}}, copy.deepcopy(rows)),
                                 unit=lambda native, unit: {'ActiveState': 'inactive'})
        accepted = SimpleNamespace(snapshot=lambda boot, old, selected: copy.deepcopy(selected))
        old = SimpleNamespace(mounts=lambda r: r.get('Mounts', []), networks=lambda r: {},
                              wait_http=lambda *args: copy.deepcopy(rows[m.APP]))
        reviewer = SimpleNamespace(WORK=review, FORMAT='reviewed', UNIT='review.service',
                                   read_controls=lambda callback: copy.deepcopy(current[0]))
        def apply(before, after, native):
            self.assertEqual(m.controls(current[0]), before)
            applications.append(copy.deepcopy(after))
            for table in m.TABLES: current[0][table] = list(copy.deepcopy(after[table]).values())
        args = reviewer, None, None, accepted, None, old, None, boot, backup, native, None
        return work, args, commands, applications, current, apply

    def test_success_restarts_only_same_app_and_repeat_never_rewrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            work, args, commands, changes, current, apply = self.worker_fixture(Path(tmp))
            with patch.object(m, 'WORK', work), patch.object(m, 'STATE', work / 'state.json'), \
                    patch.object(m, 'runtime_evidence', return_value={'version': '3.1.7'}), \
                    patch.object(m, 'database_tests'), patch.object(m, 'apply', side_effect=apply), \
                    patch.object(m, 'startup_proof', return_value={'poller': True, 'dailyBackup': True}):
                m.worker(*args)
                first = copy.deepcopy(current[0])
                m.worker(*args)
            self.assertEqual(current[0], first)
            self.assertEqual(commands, [('docker', 'stop', '--time', '30', 'app-id'), ('docker', 'start', 'app-id')])
            self.assertEqual(len(changes), 1)
            self.assertEqual(json.loads((work / 'state.json').read_text())['phase'], 'complete')
            self.assertEqual(current[0]['servers'][0]['token'], 'fixed current token')
            self.assertTrue(current[0]['request_services'][0]['enabled'])

    def test_failed_readiness_rolls_back_controls_without_replacing_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            work, args, commands, changes, current, apply = self.worker_fixture(Path(tmp))
            baseline = copy.deepcopy(current[0])
            args[5].wait_http = lambda *a: (_ for _ in ()).throw(RuntimeError('not ready'))
            with patch.object(m, 'WORK', work), patch.object(m, 'STATE', work / 'state.json'), \
                    patch.object(m, 'runtime_evidence', return_value={'version': '3.1.7'}), \
                    patch.object(m, 'database_tests'), patch.object(m, 'apply', side_effect=apply), self.assertRaisesRegex(RuntimeError, 'not ready'):
                m.worker(*args)
            self.assertEqual(m.controls(current[0]), m.controls(baseline))
            self.assertEqual(m.protected(current[0]), m.protected(baseline))
            self.assertEqual(len(changes), 2)
            self.assertEqual(commands[-2:], [('docker', 'stop', '--time', '30', 'app-id'), ('docker', 'start', 'app-id')])
            self.assertEqual(json.loads((work / 'state.json').read_text())['phase'], 'needs-review')

    def test_failed_temporary_database_test_cannot_stop_production(self):
        with tempfile.TemporaryDirectory() as tmp:
            work, args, commands, changes, current, apply = self.worker_fixture(Path(tmp))
            with patch.object(m, 'WORK', work), patch.object(m, 'STATE', work / 'state.json'), \
                    patch.object(m, 'runtime_evidence', return_value={'version': '3.1.7'}), \
                    patch.object(m, 'database_tests', side_effect=RuntimeError('temporary test failed')), self.assertRaises(RuntimeError):
                m.worker(*args)
            self.assertEqual(commands, [])
            self.assertEqual(changes, [])
            self.assertFalse((work / 'state.json').exists())


if __name__ == '__main__':
    unittest.main()
