"""Exercise the live worker's isolated Kuma SQL checks without NAS access."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load_script(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReviewedKumaControlTests(unittest.TestCase):
    def test_atomic_controls_retention_rollback_and_recent_hba_proof(self):
        worker = load_script('kuma_restoration', 'restore-nas-reviewed-kuma-controls.py')
        inspected = load_script('kuma_review', 'inspect-nas-kuma-hba-handover.py')
        original = load_script('original_controls', 'inspect-nas-original-application-controls.py')
        self.assertEqual(worker.regressions(inspected, original), 10)


if __name__ == '__main__':
    unittest.main()
