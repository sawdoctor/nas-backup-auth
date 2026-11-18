import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

PATH = Path(__file__).resolve().parents[1] / 'scripts/inspect-nas-current-npm-certificate-module.py'
spec = importlib.util.spec_from_file_location('stock_review', PATH)
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)


class CurrentStockReviewTests(unittest.TestCase):
    def test_exact_commonjs_and_esm_bytes_are_retained_without_assumed_patterns(self):
        for source in (b'module.exports={renew: function(){}};', b'export default {renew:async()=>{}};'):
            result = review.document(source, b'{"name":"npm","version":"2.13.7","type":"commonjs","irrelevant":"omit"}', 'same-image')
            self.assertEqual(result['moduleSource'].encode(), source)
            self.assertEqual(result['moduleSha256'], hashlib.sha256(source).hexdigest())
            self.assertNotIn('irrelevant', result['package'])

    def test_nonobject_package_and_oversized_module_refused(self):
        for source, package in ((b'code', b'[]'), (b'x' * (1024**2 + 1), b'{}')):
            with self.assertRaises(RuntimeError):
                review.document(source, package, 'same-image')

    def test_review_intercepts_stock_check_before_application_and_unwinds_cleanup(self):
        native = Mock()
        name = 'npm-renewal-probe-' + 'a' * 12
        native.read.return_value = b'probe-definition'
        module = SimpleNamespace(controllers=lambda: ('host', 'boot', 'backup', native),
            yaml=SimpleNamespace(safe_load=lambda _: {'services': {'npm': {'container_name': name}}}),
            IMAGE='same-image', stock_file=Mock(return_value=b'{"name":"npm","version":"2.13.7"}'),
            run=Mock(return_value=json.dumps([{'State': {'Status': 'created', 'Running': False},
                'Image': 'same-image', 'Config': {'Labels': {'com.docker.compose.project': name}}}]).encode()), say=Mock(),
            require=lambda v, m: None if v else (_ for _ in ()).throw(RuntimeError(m)))
        review.configure(module, SimpleNamespace(configure=lambda m: m))
        module.controllers()
        cleanup = Mock()
        apply = Mock()
        with self.assertRaises(review.ReviewComplete):
            try:
                module.verify_stock(b'exact current source')
                apply()
            finally:
                cleanup()
        apply.assert_not_called()
        cleanup.assert_called_once()
        self.assertEqual(native.run.call_args.args[0], 'rclone')


if __name__ == '__main__':
    unittest.main()
