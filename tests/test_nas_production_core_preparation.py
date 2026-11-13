"""Private copying/provenance checks; no host or production-service access."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('prepare', ROOT / 'scripts/prepare-nas-production-core.py')
s = importlib.util.module_from_spec(spec); spec.loader.exec_module(s)


class PrivatePreparation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_checksum_formats_preserve_spaces_and_escaped_names(self):
        h = 'a' * 64
        self.assertEqual(s.parse_checksum(h + '  ./data/core.sonarr/a b\n'), ('data/core.sonarr/a b', h))
        self.assertEqual(s.parse_checksum('\\' + h + '  ./data/library/has\\nnewline\\\\slash\n'),
                         ('data/library/has\nnewline\\slash', h))
        for line in (h + '  ../../live\n', h + '  /live\n', 'invalid'):
            with self.subTest(line=line), self.assertRaises(RuntimeError):
                s.parse_checksum(line)

    def test_copied_database_and_wal_are_checked_and_only_private_shm_is_removed(self):
        source = self.root / 'source'; source.mkdir()
        data = self.root / 'private'; copied = data / 'sonarr'; copied.mkdir(parents=True)
        original = source / 'data/core.sonarr'; original.mkdir(parents=True)
        lines = []
        for filename, content in [('sonarr.db', b'SQLite format 3\x00copied db'), ('sonarr.db-wal', b'copied wal'), ('sonarr.db-shm', b'volatile')]:
            (original / filename).write_bytes(content)
            (copied / filename).write_bytes(content)
            lines.append(hashlib.sha256(content).hexdigest() + '  ./data/core.sonarr/' + filename + '\n')
        (source / 'SHA256SUMS').write_text(''.join(lines))
        count = s.verify_copied_files(source, data, {'sonarr': 'data/core.sonarr'})
        self.assertEqual(count, 2)
        self.assertTrue((original / 'sonarr.db-shm').exists())
        self.assertFalse((copied / 'sonarr.db-shm').exists())
        (copied / 'sonarr.db-wal').write_bytes(b'damaged')
        with self.assertRaises(RuntimeError):
            s.verify_copied_files(source, data, {'sonarr': 'data/core.sonarr'})

    def test_unchecked_regular_files_are_not_accepted(self):
        source = self.root / 'source'; source.mkdir(); (source / 'SHA256SUMS').write_text('')
        data = self.root / 'private'; (data / 'sonarr').mkdir(parents=True)
        (data / 'sonarr/unexpected').write_text('unverified')
        with self.assertRaises(RuntimeError):
            s.verify_copied_files(source, data, {'sonarr': 'data/core.sonarr'})

    def coverage_fixture(self):
        data = self.root / 'private'; (data / 'nzbdav').mkdir(parents=True)
        for name in ('movies', 'movies-4k', 'tv'):
            (data / 'library' / name).mkdir(parents=True)
        identity = str(uuid.uuid4()); blob = str(uuid.uuid4()); compact = blob.replace('-', '')
        blob_path = data / 'nzbdav/blobs' / compact[:2] / compact[2:4] / blob
        blob_path.parent.mkdir(parents=True); blob_path.write_bytes(b'repaired metadata')
        with sqlite3.connect(data / 'nzbdav/db.sqlite') as db:
            db.execute('CREATE TABLE DavItems (Id TEXT, Type INTEGER, FileBlobId TEXT, NzbBlobId TEXT)')
            db.execute('INSERT INTO DavItems VALUES (?,2,?,NULL)', (identity, blob))
        link = data / 'library/movies/example.mkv'
        link.symlink_to('/mnt/nzbdav/.ids/' + '/'.join(identity[:5]) + '/' + identity)
        return data, identity, blob_path, link

    def test_link_namespace_and_repaired_blob_are_checked_without_reading_video(self):
        data, identity, blob, link = self.coverage_fixture()
        self.assertFalse(link.exists())  # no remote FUSE mount or media payload is needed
        result = s.library_coverage(data)
        self.assertEqual(result, {'videoLinks': 1, 'physicalVideoFilesRetained': 0, 'referencedFileIds': 1, 'referencedMetadataBlobs': 1})
        self.assertTrue(blob.exists())
        with sqlite3.connect(data / 'nzbdav/db.sqlite') as db:
            self.assertEqual(db.execute('SELECT Id FROM DavItems').fetchone()[0], identity)

    def test_missing_repair_blob_blocks_preparation(self):
        data, identity, blob, link = self.coverage_fixture(); blob.unlink()
        with self.assertRaises(RuntimeError):
            s.library_coverage(data)

    def test_unknown_id_or_non_id_target_is_rejected(self):
        data, identity, blob, link = self.coverage_fixture()
        with sqlite3.connect(data / 'nzbdav/db.sqlite') as db:
            db.execute('DELETE FROM DavItems')
        with self.assertRaises(RuntimeError):
            s.library_coverage(data)
        link.unlink(); link.symlink_to('/mnt/unknown/video.mkv')
        with self.assertRaises(RuntimeError):
            s.library_coverage(data)

    def test_physical_source_video_is_retained_and_not_treated_as_missing_id(self):
        data, identity, blob, link = self.coverage_fixture()
        (data / 'library/tv/local.mp4').write_bytes(b'local source payload preserved')
        self.assertEqual(s.library_coverage(data)['physicalVideoFilesRetained'], 1)

    def test_dollar_escaping_preserves_literals_through_compose_interpolation(self):
        document = {'environment': {'KEY': 'literal$VALUE and ${secret} and $$'}, 'command': ['echo', '$VALUE']}
        escaped = s.escape_dollars(document)
        decoded = json.loads(json.dumps(escaped).replace('$$', '$'))
        self.assertEqual(decoded, document)

    def test_image_mapping_compares_layers_and_platform_instead_of_storage_ids(self):
        source = {'Id': 'source-manifest', 'RootFS': {'Layers': ['sha256:layer']}, 'Os': 'linux', 'Architecture': 'amd64'}
        nas = {**source, 'Id': 'loaded-config'}
        self.assertTrue(s.image_content_matches(source, nas))
        self.assertFalse(s.image_content_matches(source, {**nas, 'Architecture': 'arm64'}))
        self.assertFalse(s.image_content_matches({}, {}))

    def test_compose_replay_escapes_runtime_env_once_and_preserves_existing_command(self):
        live_file = self.root / 'compose.json'; live_file.write_text('original live Compose retained')
        candidate = self.root / 'private'; candidate.mkdir()
        model = {'name': 'media-core-nas', 'services': {'sonarr': {'container_name': 'sonarr-nas',
                 'environment': {'ORIGINAL': 'old'}, 'command': ['echo', '$$KEEP'],
                 'volumes': [{'type': 'bind', 'source': '/live', 'target': '/config'}]}}, 'networks': {}}
        labels = {'com.docker.compose.project': 'media-core-nas', 'com.docker.compose.service': 'sonarr',
                  'com.docker.compose.project.config_files': str(live_file)}
        runtime = {'sonarr-nas': {'Config': {'Labels': labels, 'Env': []}}}
        source = {'sonarr': {'Config': {'Env': []}}}
        policy = SimpleNamespace(runtime_environment=lambda *args: {'KEY': '$actual'})
        def run(*args, **kwargs):
            filename = Path(args[args.index('-f') + 1])
            return json.dumps(model) if filename == live_file else filename.read_text()
        with patch.object(s, 'NAMES', {'sonarr': 'sonarr-nas'}), patch.object(s, 'run', side_effect=run):
            result = s.prepare_composes(candidate, runtime, source, policy, {})
        actual = json.loads(Path(result[0]['candidate']).read_text())
        self.assertEqual(actual['services']['sonarr']['environment'], {'KEY': '$$actual'})
        self.assertEqual(actual['services']['sonarr']['command'], ['echo', '$$KEEP'])
        self.assertEqual(live_file.read_text(), 'original live Compose retained')

    def test_no_activation_or_mutating_docker_command_exists(self):
        import ast
        tree = ast.parse((ROOT / 'scripts/prepare-nas-production-core.py').read_text())
        prohibited = {'up', 'start', 'stop', 'restart', 'update', 'rm', 'scan', 'pull'}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            args = [a.value for a in node.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
            if args and args[0] == 'docker':
                self.assertFalse(prohibited & set(args))
        self.assertNotIn('activate', {n.name for n in tree.body if isinstance(n, ast.FunctionDef)})


if __name__ == '__main__':
    unittest.main()
