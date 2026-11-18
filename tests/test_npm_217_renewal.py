import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


previous = load('npm_217_existing_tests', ROOT / 'tests/test_npm_oom_default_comparison.py')
current = load('npm_217_resume', ROOT / 'scripts/finish-nas-npm-217-renewal.py')


class Npm217Regressions(previous.ResumedNpmTests):
    def test_reviewed_optional_third_argument_accepted_by_exact_hash(self):
        source = b'renew: async (access, data, options = {}) => {};'
        with patch.object(current, 'STOCK_SHA', hashlib.sha256(source).hexdigest()):
            current.verify_stock(source)
            with self.assertRaises(RuntimeError):
                current.verify_stock(source + b'changed')

    def test_configuration_keeps_the_original_worker_and_oom_guard(self):
        module = SimpleNamespace(IMAGE='same-image', runtime_signature=lambda row: copy.deepcopy(row), say=lambda _:None)
        oom = SimpleNamespace(configure=lambda m: setattr(m, 'oomStillChecked', True))
        current.configure(module, oom, {'image': 'same-image'})
        self.assertTrue(module.oomStillChecked)
        self.assertIs(module.verify_stock, current.verify_stock)
        self.assertEqual(module.SELF, current.SELF)
        self.assertEqual(module.UNIT, current.UNIT)

    def test_different_review_image_refused(self):
        with self.assertRaises(RuntimeError):
            current.configure(SimpleNamespace(IMAGE='current'), None, {'image': 'other'})

    def test_tls_names_include_only_live_routes_for_original_expired_certificates(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / 'database.sqlite'
            connection = sqlite3.connect(database)
            connection.execute('CREATE TABLE proxy_host (certificate_id INTEGER, domain_names TEXT, is_deleted INTEGER, enabled INTEGER)')
            connection.executemany('INSERT INTO proxy_host VALUES (?,?,?,?)', [
                (71, json.dumps(['old.example.test', '*.example.test']), 0, 1),
                (71, json.dumps(['paused.example.test']), 0, 0),
                (71, json.dumps(['deleted.example.test']), 1, 1),
                (72, json.dumps(['other.example.test']), 0, 1),
            ])
            connection.commit()
            connection.close()
            self.assertEqual(current.names_for_certificates(database, {71}), {71: ['old.example.test']})


if __name__ == '__main__':
    unittest.main()
