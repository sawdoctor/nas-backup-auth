"""Native/CI regressions for the exact HBA freshness correction."""
import hashlib
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('freshness_repair', ROOT / 'scripts/repair-nas-hba-cache-freshness.py')
repair = importlib.util.module_from_spec(spec); spec.loader.exec_module(repair)


class HbaCacheFreshnessTests(unittest.TestCase):
    def test_only_the_exact_known_block_changed(self):
        source = (ROOT / 'scripts/restore-nas-hba-temperature-bridge.py').read_text()
        self.assertEqual(hashlib.sha256(source.encode()).hexdigest(), repair.NEW_SHA)
        self.assertEqual(source.count(repair.AFTER), 1)
        restored = source.replace(repair.AFTER, repair.BEFORE)
        self.assertEqual(hashlib.sha256(restored.encode()).hexdigest(), repair.OLD_SHA)

    def test_eight_isolated_collector_regressions(self):
        source = (ROOT / 'scripts/restore-nas-hba-temperature-bridge.py').read_text()
        self.assertEqual(repair.regression_tests(source), 8)


if __name__ == '__main__': unittest.main()
