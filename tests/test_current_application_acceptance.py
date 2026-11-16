"""Finish only journal acceptance after the observed unchanged PS1 escaping."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


m = load('current_acceptance', 'scripts/accept-nas-reviewed-application-controls.py')
fixture = load('current_acceptance_fixture', 'tests/test_application_controls_resume.py')


class CurrentApplicationAcceptanceTests(unittest.TestCase):
    def speedtest(self):
        before = fixture.runtime(m.SPEEDTEST, values={'SPEEDTEST_SCHEDULE': '', 'PS1': 'private\\u@\\h: \\$ ', 'APP_KEY': 'private-key'})
        after = copy.deepcopy(before); after['Id'] = 'e'*64; after['Config']['Hostname'] = 'e'*12
        after['Config']['Env'] = ['SPEEDTEST_SCHEDULE=' + m.SCHEDULE, 'PS1=private\\u@\\h: \\$ ', 'APP_KEY=private-key']
        definition = {'environment': {'SPEEDTEST_SCHEDULE': m.SCHEDULE, 'PS1': 'private\\u@\\h: \\$$ ', 'APP_KEY': 'private-key'}}
        return before, after, definition, {'Config': {'Env': []}}

    def test_only_proven_ps1_rendering_is_normalized_in_a_comparison_copy(self):
        before, after, definition, image = self.speedtest(); snapshot = copy.deepcopy((before, after, definition, image))
        owner = {key: after['Config']['Labels'].get(key) for key in fixture.m.OWNER_KEYS}
        m.validate_speedtest(fixture.m, fixture.old, before, after, definition, image, owner)
        self.assertEqual((before, after, definition, image), snapshot)

    def test_actual_ps1_secret_schedule_dns_image_or_storage_changes_are_rejected(self):
        before, after, definition, image = self.speedtest()
        def env_change(row, key, value):
            values = fixture.old.env(row); values[key] = value; row['Config']['Env'] = [k+'='+v for k,v in values.items()]
        changes = [lambda row: env_change(row, 'PS1', 'changed-private'), lambda row: env_change(row, 'APP_KEY', 'changed-private'),
            lambda row: env_change(row, 'SPEEDTEST_SCHEDULE', ''), lambda row: env_change(row, 'EXTRA', 'changed-private'),
            lambda row: row['HostConfig'].update(Dns=['1.1.1.1']), lambda row: row.update(Image='sha256:other'),
            lambda row: row['Mounts'][0].update(RW=False), lambda row: row.update(Name='/other-nas')]
        for change in changes:
            with self.subTest(change=change):
                actual = copy.deepcopy(after); change(actual)
                with self.assertRaises(RuntimeError): m.validate_speedtest(fixture.m, fixture.old, before, actual, definition, image, {})

    def test_dollar_escape_in_another_variable_is_not_waived(self):
        before, after, definition, image = self.speedtest()
        definition['environment']['APP_KEY'] = 'private$$key'
        with self.assertRaisesRegex(RuntimeError, 'exact reviewed PS1'):
            m.validate_speedtest(fixture.m, fixture.old, before, after, definition, image, {})

    def setup_worker(self, folder):
        work, db, original, current, calls, args = fixture.ApplicationControlsResumeTests().fixture(folder)
        old, review, boot, backup, native, startup = args
        backup.unit = lambda native, unit: {'ActiveState': 'inactive'}
        before, after, definition, image = self.speedtest()
        before['Config']['Labels'] = copy.deepcopy(current[m.SPEEDTEST]['Config']['Labels'])
        after['Config']['Labels'] = copy.deepcopy(before['Config']['Labels'])
        current[m.SPEEDTEST] = after
        baseline = work / 'resume-speedtest-before.json'; baseline.write_text(json.dumps(before))
        progress = work / 'resume-state.json'; progress.write_text(json.dumps({'format': fixture.m.FORMAT, 'cutoverId': 'current',
            'phase': 'needs-review', 'oldWorkerSha256': fixture.m.PREVIOUS_SHA,
            'speedtestBeforeSha256': hashlib.sha256(baseline.read_bytes()).hexdigest()}))
        original_model = startup.compose_model
        def compose_model(native, context):
            model = original_model(native, context); model['services'][m.SPEEDTEST]['environment'] = copy.deepcopy(definition['environment']); return model
        startup.compose_model = compose_model
        return work, db, original, current, calls, (fixture.m, *args)

    def test_complete_acceptance_and_repeat_change_only_completion_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            work, db, original, current, calls, args = self.setup_worker(Path(temporary))
            original_runtime = copy.deepcopy(current)
            protected = {p: p.read_bytes() for p in work.iterdir() if p.is_file() and p not in (original, work/'resume-state.json')}
            with patch.object(m, 'WORK', work), patch.object(m, 'STATE', work/'current-acceptance.json'), \
                    patch.object(fixture.m, 'WORK', work), patch.object(fixture.m, 'STATE', work/'resume-state.json'), patch.object(m.subprocess, 'run') as system:
                m.worker(*args); m.worker(*args)
            self.assertEqual(current, original_runtime)
            self.assertEqual({p: p.read_bytes() for p in protected}, protected)
            self.assertEqual(json.loads(original.read_bytes())['completed'], ['houndarr-nas', 'wizarr-nas', m.SPEEDTEST])
            self.assertEqual(json.loads((work/'resume-state.json').read_bytes())['phase'], 'complete')
            self.assertTrue(json.loads((work/'current-acceptance.json').read_bytes())['noApplicationRestartOrRecreation'])
            self.assertTrue(all(call[:3] == ('docker', 'image', 'inspect') for call in calls))
            self.assertTrue(all(call.args[0][:2] == ['systemctl', 'reset-failed'] for call in system.call_args_list))

    def test_real_environment_change_keeps_all_journals_and_apps(self):
        with tempfile.TemporaryDirectory() as temporary:
            work, db, original, current, calls, args = self.setup_worker(Path(temporary))
            current[m.SPEEDTEST]['Config']['Env'].append('EXTRA=private-change')
            protected = {p: p.read_bytes() for p in work.iterdir() if p.is_file()}
            with patch.object(m, 'WORK', work), patch.object(m, 'STATE', work/'current-acceptance.json'), \
                    patch.object(fixture.m, 'WORK', work), patch.object(fixture.m, 'STATE', work/'resume-state.json'), self.assertRaisesRegex(RuntimeError, 'beyond its original schedule'):
                m.worker(*args)
            self.assertEqual({p: p.read_bytes() for p in work.iterdir() if p.is_file()}, protected)
            self.assertTrue(all(call[:3] == ('docker', 'image', 'inspect') for call in calls))

    def test_changed_prepared_file_or_baseline_is_not_accepted(self):
        for changed in ('prepared.yaml', 'resume-speedtest-before.json'):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                work, db, original, current, calls, args = self.setup_worker(Path(temporary))
                (work/changed).write_text('unexpected edit')
                before = original.read_bytes()
                with patch.object(m, 'WORK', work), patch.object(m, 'STATE', work/'current-acceptance.json'), \
                        patch.object(fixture.m, 'WORK', work), patch.object(fixture.m, 'STATE', work/'resume-state.json'), self.assertRaises(RuntimeError):
                    m.worker(*args)
                self.assertEqual(original.read_bytes(), before)
                self.assertFalse((work/'current-acceptance.json').exists())


if __name__ == '__main__': unittest.main()
