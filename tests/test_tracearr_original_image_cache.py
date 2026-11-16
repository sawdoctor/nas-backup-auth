"""Reject incorrect source PostgreSQL image identities before a cache request."""
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]


def load(name,filename):
    spec=importlib.util.spec_from_file_location(name,ROOT/'scripts'/filename)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class OriginalTracearrImageTests(unittest.TestCase):
    def test_digest_identity_runtime_layers_and_platform(self):
        reviewer=load('tracearr_with_image','inspect-nas-original-tracearr-controls-with-image.py')
        core=load('source_core','prepare-nas-production-core.py')
        cache=load('source_cache','cache-nas-production-core-images.py')
        self.assertEqual(reviewer.image_regressions(core,cache),7)


if __name__=='__main__':
    unittest.main()
