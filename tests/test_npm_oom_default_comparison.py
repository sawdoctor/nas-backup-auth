import copy
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


previous = load('original_npm_regressions', ROOT / 'tests/test_npm_renewal_handover.py')
resume = load('npm_oom_resume', ROOT / 'scripts/resume-nas-npm-oom-default-comparison.py')
resume.configure(previous.npm)


class ResumedNpmTests(previous.NpmRenewalHandoverTests):
    def test_unset_and_false_oom_default_are_equivalent(self):
        for before_value, after_value in ((None, False), (False, None), (False, False)):
            before, after = previous.runtime(), previous.runtime('probe', '2' * 64, created=True)
            before['HostConfig']['OomKillDisable'] = before_value
            after['HostConfig']['OomKillDisable'] = after_value
            previous.npm.verify_runtime(before, after, unstarted=True)

    def test_explicit_true_policy_cannot_be_changed(self):
        for old, new in ((True, None), (True, False), (False, True)):
            before, after = previous.runtime(), previous.runtime(identity='2' * 64)
            before['HostConfig']['OomKillDisable'] = old
            after['HostConfig']['OomKillDisable'] = new
            with self.assertRaises(RuntimeError):
                previous.npm.verify_runtime(before, after)

    def test_numeric_or_string_values_are_not_silently_coerced(self):
        for value in (0, 1, 'false', 'true', [], {}):
            row = previous.runtime()
            row['HostConfig']['OomKillDisable'] = value
            with self.assertRaises(RuntimeError):
                previous.npm.runtime_signature(row)

    def test_input_policy_is_never_edited(self):
        row = previous.runtime()
        row['HostConfig']['OomKillDisable'] = None
        before = copy.deepcopy(row)
        result = previous.npm.runtime_signature(row)
        self.assertEqual(row, before)
        self.assertIs(result['host']['OomKillDisable'], False)

    def test_other_memory_limits_still_must_match(self):
        before, after = previous.runtime(), previous.runtime(identity='2' * 64)
        before['HostConfig'].update(OomKillDisable=None, Memory=64 * 1024**2)
        after['HostConfig'].update(OomKillDisable=False, Memory=128 * 1024**2)
        with self.assertRaises(RuntimeError):
            previous.npm.verify_runtime(before, after)
