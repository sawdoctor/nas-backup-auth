import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'scripts'
if not SCRIPTS.is_dir(): SCRIPTS = ROOT / 'nas-backup-auth/scripts'
spec = importlib.util.spec_from_file_location('plex_precopy', SCRIPTS / 'prepare-optiplex-plex-handover.py')
s = importlib.util.module_from_spec(spec); spec.loader.exec_module(s)


class PrecopyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.base = self.root / 'private-handover'
        self.sources = {'plex-config': self.root / 'production-plex', 'flora-test-library': self.root / 'production-flora'}
        for p in self.sources.values(): p.mkdir()
        database = self.sources['plex-config'] / 'Library/Application Support/Plex Media Server/Plug-in Support/Databases/com.plexapp.plugins.library.db'
        database.parent.mkdir(parents=True); database.write_bytes(b'PRIVATE_DB' + b'\0' * 8192)
        self.custom = self.sources['plex-config'] / 'PRIVATE_CUSTOM'; self.custom.write_bytes(b'PRIVATE_SETTING')
        self.custom.chmod(0o640); os.setxattr(self.custom, 'user.keep', b'PRIVATE_XATTR')
        (self.sources['flora-test-library'] / 'movie.mkv').symlink_to('/mnt/nzbdav/.ids/PRIVATE_ID')
        self.helper = self.root / 'reviewed-helper'; self.helper.write_bytes(b'#!/bin/sh\nexit 0\n')
        self.row = {'Name': '/plex', 'Id': 'original-plex', 'Image': s.SOURCE_IMAGE,
                    'State': {'Status': 'running', 'StartedAt': 'original-time'},
                    'HostConfig': {'NetworkMode': 'host', 'RestartPolicy': {'Name': 'on-failure', 'MaximumRetryCount': 5}},
                    'Mounts': [{'Destination': target, 'Source': str(self.sources[name]), 'Type': 'bind'}
                               for target, name in (('/config', 'plex-config'), ('/flora-test-library', 'flora-test-library'))]}
        self.calls = []; self.copy_calls = []; self.after_copy = None
        self.real_run = subprocess.run; self.real_popen = subprocess.Popen
        self.resources = contextlib.ExitStack(); self.addCleanup(self.resources.close)
        self.resources.enter_context(patch.multiple(s, BASE=self.base, WORKER=self.base / 'worker.py', ROOTS=self.sources,
            LOCKS=(self.root / 'backup.lock', self.root / 'standby.lock'), EXPECTED={str(self.helper): hashlib.sha256(self.helper.read_bytes()).hexdigest()},
            PENDING=(self.root / 'pending-recovery',)))
        self.resources.enter_context(patch.object(s, 'run', side_effect=self.query))
        self.resources.enter_context(patch.object(s.subprocess, 'Popen', side_effect=self.popen))
        self.messages = self.resources.enter_context(contextlib.redirect_stdout(io.StringIO()))

    def query(self, *args, **kwargs):
        self.calls.append(args)
        if args[:2] == ('docker', 'inspect'):
            return json.dumps([self.row]).encode()
        if args[0] == 'findmnt': return b'ext4\n'
        if args[0] == 'du':
            # subprocess.run uses Popen internally, so call the saved Popen directly.
            with self.real_popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as p:
                out, err = p.communicate(timeout=15)
                if p.returncode: raise AssertionError(err)
                return out
        raise AssertionError('Unexpected production mutation/query: ' + repr(args))

    def popen(self, args, **kwargs):
        self.assertEqual(args[0], 'rsync'); self.assertIn('--delete', args)
        source, target = Path(args[-2]), Path(args[-1])
        self.assertIn(source, self.sources.values())
        self.assertEqual(target.parent, self.base / 'payload')
        self.copy_calls.append(tuple(args))
        # Exercise real GNU metadata-preserving copying for the reviewed rsync
        # call; the production host already provides rsync, absent locally.
        result = self.real_popen(['cp', '-a', str(source) + '/.', str(target) + '/'], **kwargs)
        if self.after_copy:
            self.after_copy()
        return result

    def test_precopy_preserves_live_data_xattrs_and_leaf_links_and_is_not_marked_consistent(self):
        original = self.custom.read_bytes(); before = copy.deepcopy(self.row)
        s.prepare()
        record = json.loads((self.base / 'state.json').read_text())
        self.assertEqual(record['phase'], 'seeded-running-not-frozen')
        self.assertFalse(record['consistentSnapshot']); self.assertFalse(record['sourceStopPerformed'])
        self.assertEqual(self.row, before); self.assertEqual(self.custom.read_bytes(), original)
        copied = self.base / 'payload/plex-config/PRIVATE_CUSTOM'
        self.assertEqual(copied.read_bytes(), original)
        self.assertEqual(copied.stat().st_mode & 0o777, 0o640)
        self.assertEqual(os.getxattr(copied, 'user.keep'), b'PRIVATE_XATTR')
        self.assertEqual(os.readlink(self.base / 'payload/flora-test-library/movie.mkv'), '/mnt/nzbdav/.ids/PRIVATE_ID')
        self.assertEqual(len(self.copy_calls), 2)
        s.prepare(); self.assertEqual(len(self.copy_calls), 2)
        self.assertNotIn('PRIVATE_', self.messages.getvalue())
        self.assertTrue(all(c[0] in ('docker', 'findmnt', 'du') for c in self.calls))

    def test_unknown_staging_directory_or_unrecorded_copy_is_retained(self):
        self.base.mkdir(); (self.base / 'user-file').write_text('KEEP')
        with self.assertRaisesRegex(RuntimeError, 'unrecognized'):
            s.prepare()
        self.assertEqual((self.base / 'user-file').read_text(), 'KEEP')
        self.assertFalse(self.copy_calls)

    def test_pending_recovery_and_changed_helper_refuse_copy(self):
        pending = self.root / 'pending-recovery'; pending.touch()
        with self.assertRaisesRegex(RuntimeError, 'pending'):
            s.prepare()
        pending.unlink(); self.helper.write_text('CHANGED')
        with self.assertRaisesRegex(RuntimeError, 'helper changed'):
            s.prepare()
        self.assertFalse(self.copy_calls)

    def test_production_and_symbolic_destinations_are_never_rsync_targets(self):
        s.owner()
        with self.assertRaisesRegex(RuntimeError, 'destination differs'):
            s.copy_root(self.sources['plex-config'], self.sources['plex-config'])
        (self.base / 'payload').mkdir()
        (self.base / 'payload/plex-config').symlink_to(self.sources['plex-config'], target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, 'symbolic'):
            s.copy_root(self.sources['plex-config'], self.base / 'payload/plex-config')
        self.assertFalse(self.copy_calls)

    def test_source_restart_during_copy_prevents_ready_record(self):
        def changed(): self.row['State']['StartedAt'] = 'later-time'
        self.after_copy = changed
        with self.assertRaisesRegex(RuntimeError, 'restarted or changed'):
            s.prepare()
        self.assertEqual(json.loads((self.base / 'state.json').read_text())['phase'], 'seeding')
        self.assertEqual(self.custom.read_bytes(), b'PRIVATE_SETTING')

    def test_existing_later_handover_state_blocks_a_repeat_precopy(self):
        s.prepare()
        record = json.loads((self.base / 'state.json').read_text()); record['phase'] = 'source-held'
        (self.base / 'state.json').write_text(json.dumps(record))
        with self.assertRaisesRegex(RuntimeError, 'progressed beyond precopy'):
            s.prepare()
        self.assertEqual(len(self.copy_calls), 2)


if __name__ == '__main__': unittest.main()
