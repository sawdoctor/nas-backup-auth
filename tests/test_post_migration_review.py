import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('current_review', Path(__file__).resolve().parents[1] / 'scripts/review-nas-after-migration.py')
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)


class CurrentReviewTests(unittest.TestCase):
    def setUp(self):
        self.timer = {'ActiveState': 'active', 'UnitFileState': 'enabled'}
        self.service = {'ActiveState': 'inactive', 'Result': 'success', 'ExecMainStatus': '0',
                        'ExecMainExitTimestamp': 'Wed 2026-11-18 20:00:00 GMT'}

    def test_successful_inactive_oneshot_is_healthy(self):
        self.assertEqual(review.job_state(self.service, self.timer), 'last_run_success')

    def test_enabled_timer_without_execution_is_not_success(self):
        self.service.pop('ExecMainExitTimestamp')
        self.assertEqual(review.job_state(self.service, self.timer), 'no_completed_run_recorded')

    def test_backup_lock_skip_is_not_claimed_as_job_completion(self):
        self.service['ExecMainStatus'] = '75'
        self.assertEqual(review.job_state(self.service, self.timer), 'last_attempt_skipped_backup_lock')

    def test_disabled_timer_needs_review_even_after_success(self):
        self.timer['ActiveState'] = 'inactive'
        self.assertEqual(review.job_state(self.service, self.timer), 'timer_needs_review')

    def test_nonzero_execution_is_not_success(self):
        self.service['ExecMainStatus'] = '1'
        self.assertEqual(review.job_state(self.service, self.timer), 'last_run_needs_review')

    def test_busy_job_is_in_progress(self):
        self.service['ActiveState'] = 'activating'
        self.assertEqual(review.job_state(self.service, self.timer), 'running_now')

    def test_cloud_layout_ignores_only_local_upload_receipt(self):
        local = {'applications.tar.zst': 900, 'SHA256SUMS': 150, '_COMPLETE': 24, '_UPLOADED': 24}
        remote = [{'Path': name, 'Size': value} for name, value in local.items() if name != '_UPLOADED']
        self.assertEqual(review.compare_metadata(local, remote), [])
        remote[0]['Size'] = 899
        self.assertEqual(review.compare_metadata(local, remote), ['applications.tar.zst'])

    def test_missing_system_backup_file_is_detected(self):
        self.assertEqual(review.compare_metadata({'os/omv.fsa': 100}, []), ['os/omv.fsa'])


if __name__ == '__main__':
    unittest.main()
