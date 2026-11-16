"""A diagnostic must expose the comparison while retaining private values."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('speedtest_diff', ROOT / 'scripts/inspect-nas-speedtest-environment-diff.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class SpeedtestEnvironmentDiffTests(unittest.TestCase):
    def test_literal_dollar_rendering_is_reported_without_waiving_it(self):
        before = {'SECRET': 'private$value', 'SPEEDTEST_SCHEDULE': ''}
        actual = dict(before, SPEEDTEST_SCHEDULE=m.SCHEDULE)
        expected = dict(actual, SECRET='private$$value')
        snapshot = copy.deepcopy((actual, expected, before))
        result = m.environment_report(actual, expected, before)
        self.assertTrue(result['onlyOriginalScheduleChanged'])
        self.assertEqual(result['currentVsRenderedCompose']['differentNames'], ['SECRET'])
        self.assertEqual(result['mismatches'], [{'name': 'SECRET', 'presentInCurrent': True,
            'presentInRenderedCompose': True, 'sameAsSavedBefore': True, 'renderedDollarEscapesOnly': True}])
        self.assertNotIn('private', json.dumps(result))
        self.assertEqual((actual, expected, before), snapshot)

    def test_actual_secret_change_and_added_or_missing_fields_stay_visible(self):
        result = m.environment_report({'SECRET': 'new-private', 'EXTRA': 'new-extra'},
            {'SECRET': 'expected-private', 'MISSING': 'private-missing'}, {'SECRET': 'old-private', 'REMOVED': 'removed-private'})
        self.assertFalse(result['onlyOriginalScheduleChanged'])
        self.assertEqual(result['currentVsRenderedCompose'],
            {'missingNames': ['MISSING'], 'additionalNames': ['EXTRA'], 'differentNames': ['SECRET']})
        self.assertEqual(result['currentVsSavedBeforePlusOriginalSchedule']['missingNames'], ['REMOVED', 'SPEEDTEST_SCHEDULE'])
        self.assertTrue(all(not row['renderedDollarEscapesOnly'] for row in result['mismatches']))
        self.assertNotIn('private', json.dumps(result))

    def test_no_difference_is_an_empty_names_report(self):
        current = {'APP_KEY': 'private', 'SPEEDTEST_SCHEDULE': m.SCHEDULE}
        result = m.environment_report(current, dict(current), dict(current, SPEEDTEST_SCHEDULE=''))
        self.assertTrue(result['onlyOriginalScheduleChanged'])
        self.assertEqual(result['mismatches'], [])

    def test_complete_inspection_retains_runtime_and_journals(self):
        fixture_spec = importlib.util.spec_from_file_location('resume_test_fixture', ROOT / 'tests/test_application_controls_resume.py')
        fixture = importlib.util.module_from_spec(fixture_spec); fixture_spec.loader.exec_module(fixture)
        with tempfile.TemporaryDirectory() as temporary:
            work, _db, _original, current, calls, args = fixture.ApplicationControlsResumeTests().fixture(Path(temporary))
            old, _review, _boot, _backup, native, startup = args
            before = copy.deepcopy(current[m.NAME]); before['Config']['Env'].append('SECRET=private-retained')
            baseline = work / 'resume-speedtest-before.json'; baseline.write_text(json.dumps(before))
            state = work / 'resume-state.json'
            state.write_text(json.dumps({'format': fixture.m.FORMAT, 'cutoverId': 'current', 'phase': 'needs-review',
                'speedtestBeforeSha256': hashlib.sha256(baseline.read_bytes()).hexdigest()}))
            current[m.NAME]['Id'] = 'd'*64; current[m.NAME]['Config']['Hostname'] = 'd'*12
            current[m.NAME]['Config']['Env'] = ['SECRET=private-retained', 'SPEEDTEST_SCHEDULE=' + m.SCHEDULE]
            saved_runtime = copy.deepcopy(current)
            saved_files = {path: path.read_bytes() for path in work.iterdir() if path.is_file()}
            with patch.object(fixture.m, 'WORK', work), patch.object(fixture.m, 'STATE', state), patch.object(m, 'http_status', return_value=302):
                summary, report = m.inspect(fixture.m, old, native, startup)
            self.assertFalse(summary['sameContainerAsSavedBefore'])
            self.assertTrue(summary['sameImageAsSavedBefore'])
            self.assertTrue(summary['currentOwnerMatchesRecordedDefinition'])
            self.assertEqual(summary['currentSchedule'], m.SCHEDULE)
            self.assertTrue(report['onlyOriginalScheduleChanged'])
            self.assertEqual(report['currentVsRenderedCompose']['additionalNames'], ['SECRET'])
            self.assertNotIn('private-retained', json.dumps((summary, report)))
            self.assertEqual(current, saved_runtime)
            self.assertEqual({path: path.read_bytes() for path in work.iterdir() if path.is_file()}, saved_files)
            self.assertTrue(all(call[:3] == ('docker', 'image', 'inspect') for call in calls))


if __name__ == '__main__': unittest.main()
