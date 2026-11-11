"""Test private proposal writes and real Bash control flow using reviewed helpers.

Production helper texts remain private. Set PLEX_HOLD_REVIEW_FIXTURES to a JSON
object mapping reviewed source paths to script text for the Bash tests. The
preparer itself always checks the pinned live SHA256 values before staging.
"""
import contextlib
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
spec = importlib.util.spec_from_file_location('hold', ROOT / 'scripts/prepare-optiplex-plex-hold.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


class PrivateStaging(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.base = self.root / 'proposal'
        self.edit = patch.object(s, 'BASE', self.base)
        self.edit.start()
        self.addCleanup(self.edit.stop)
        self.plan = {'format': s.FORMAT, 'preparedUtc': 'now', 'source': 'unchanged'}
        self.payload = {'small.before': b'original\n', 'small.proposed': b'proposal\n',
                        'plan.json': json.dumps(self.plan).encode()}

    def test_staging_writes_private_proposal_only_and_repeats(self):
        outside = self.root / 'production-config'
        outside.write_bytes(b'production data retained')
        s.stage(self.plan, self.payload.copy())
        s.stage(self.plan, self.payload.copy())
        self.assertEqual(outside.read_bytes(), b'production data retained')
        self.assertEqual(self.base.stat().st_mode & 0o777, 0o700)
        for item in self.base.iterdir():
            self.assertEqual(item.stat().st_mode & 0o777, 0o600)
        self.assertFalse(s.HOLD.exists())

    def test_modified_proposal_and_unowned_directory_are_retained(self):
        self.base.mkdir()
        retained = self.base / 'other'
        retained.write_text('retain')
        with self.assertRaises(RuntimeError):
            s.stage(self.plan, self.payload.copy())
        self.assertEqual(retained.read_text(), 'retain')

    def test_symlinked_plan_is_rejected(self):
        self.base.mkdir()
        (self.base / 'owner.json').write_text(json.dumps({'format': s.FORMAT}) + '\n')
        outside = self.root / 'outside'
        outside.write_text('retain')
        (self.base / 'plan.json').symlink_to(outside)
        with self.assertRaises(RuntimeError):
            s.stage(self.plan, self.payload.copy())
        self.assertEqual(outside.read_text(), 'retain')

    def test_changed_source_plan_is_not_overwritten(self):
        s.stage(self.plan, self.payload.copy())
        before = (self.base / 'plan.json').read_bytes()
        changed = {**self.plan, 'source': 'changed'}
        with self.assertRaises(RuntimeError):
            s.stage(changed, self.payload.copy())
        self.assertEqual((self.base / 'plan.json').read_bytes(), before)

    def test_unchanged_read_of_symbolic_input_fails_closed(self):
        target = self.root / 'real'
        target.write_text('data')
        alias = self.root / 'alias'
        alias.symlink_to(target)
        with self.assertRaises(RuntimeError):
            s.read(alias)

    def seed(self):
        seed = self.root / 'seed'
        seed.mkdir()
        for leaf in ('plex-config', 'flora-test-library'):
            (seed / 'payload' / leaf).mkdir(parents=True)
        state = {'format': 'sawdoctor-plex-handover-precopy-v1',
                 'phase': 'seeded-running-not-frozen', 'consistentSnapshot': False,
                 'sourceStopPerformed': False,
                 'sourceRoots': {'plex-config': str(s.CONFIG), 'flora-test-library': str(s.FLORA)},
                 'container': {'Id': 'same-id', 'Image': s.IMAGE, 'startedAt': 'before-reboot'}}
        (seed / 'owner.json').write_text(json.dumps({'format': state['format']}))
        (seed / 'state.json').write_text(json.dumps(state))
        worker = ROOT / 'scripts/prepare-optiplex-plex-handover.py'
        (seed / 'worker.py').write_bytes(worker.read_bytes())
        return seed, state

    def test_seed_survives_legitimate_restart_but_is_still_not_consistent(self):
        seed, state = self.seed()
        row = {'id': 'same-id', 'imageId': s.IMAGE, 'startedAt': 'after-backup-restart'}
        with patch.object(s, 'SEED', seed):
            info = s.seed_check(row)
        self.assertIs(info['consistentSnapshot'], False)
        self.assertIs(info['sourceStopPerformed'], False)

    def test_changed_seed_identity_is_rejected(self):
        seed, state = self.seed()
        row = {'id': 'different-id', 'imageId': s.IMAGE, 'startedAt': 'after-restart'}
        with patch.object(s, 'SEED', seed), self.assertRaises(RuntimeError):
            s.seed_check(row)


class ReviewedBash(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = os.environ.get('PLEX_HOLD_REVIEW_FIXTURES')
        if not fixture:
            raise unittest.SkipTest('Private reviewed source fixtures were not supplied.')
        cls.originals = {k: v.encode() for k, v in json.loads(Path(fixture).read_text()).items()}

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.marker = self.root / 'persistent-hold.json'
        self.log = self.root / 'docker.log'
        self.state = self.root / 'watch'
        self.state.mkdir()

    def patched(self, leaf):
        name = next(n for n in self.originals if Path(n).name == leaf)
        self.assertEqual(s.sha(self.originals[name]), s.EXPECTED[name])
        return s.patch_helper(name, self.originals[name]).decode()

    def sandbox(self, text):
        return (text.replace(str(s.HOLD), str(self.marker))
                .replace('/usr/bin/docker', 'docker')
                .replace('/usr/local/sbin/media-mounts-ready', 'mounts_ready')
                .replace('/usr/local/sbin/media-mount-watch.sh sync', 'true')
                .replace('/run/media-mount-recover.lock', str(self.root / 'mount.lock'))
                .replace('/run/media-mount-watch', str(self.state)))

    def execute(self, text, *, running=True):
        # Real Bash runs the complete shared recovery/watch script against
        # isolated paths and command doubles. No real Docker/systemd/FUSE is used.
        preamble = '''
docker() {
    printf '%s\\n' "$*" >> "$LOG"
    case "$1" in
        info) return 0 ;;
        ps) printf 'plex\\njellyfin\\nsonarr\\n'; return 0 ;;
        inspect)
            case "$*" in
                *State.Running*)
                    case "${@: -1}" in
                        nzbdav|torbox-media-center) echo true ;;
                        *) echo "$MOCK_RUNNING" ;;
                    esac ;;
                *) echo '2026-11-11T00:00:00Z' ;;
            esac ;;
        exec)
            echo 'Filesystem Type 1K-blocks Used Available Use% Mounted on'
            if [ "$2" = sonarr ] && ! grep -q '^restart sonarr$' "$LOG"; then
                echo '/dev/example ext4 100 1 99 1% /mnt/nzbdav'
            else
                echo 'nzbdav: fuse.rclone 100 1 99 1% /mnt/nzbdav'
            fi ;;
    esac
    return 0
}
mounts_ready() { return 0; }
findmnt() {
    case "$*" in
        *FSTYPE*) case "$*" in *torbox*) echo fuse.main.py ;; *) echo fuse.rclone ;; esac ;;
        *) echo 42 ;;
    esac
}
timeout() { shift; "$@"; }
find() { echo /fixture/cam.mkv; }
stat() { return 0; }
dd() { return 0; }
flock() { return 0; }
logger() { return 0; }
sleep() { return 0; }
systemctl() { printf 'systemctl %s\\n' "$*" >> "$LOG"; }
'''
        env = {**os.environ, 'LOG': str(self.log), 'MOCK_RUNNING': str(running).lower()}
        self.log.touch()
        script = self.root / 'script.sh'
        script.write_text(self.sandbox(text))
        result = subprocess.run(['bash', '-c', preamble + '\nsource "$1" "${@:2}"',
                                 'fixture', str(script), *getattr(self, 'arguments', [])],
                                env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        return self.log.read_text().splitlines()

    def test_all_eight_full_helpers_are_syntax_valid(self):
        for leaf in (*s.EXCLUSIVE, 'media-mount-watch.sh', 'media-mount-recover.sh', 'docker-postboot-fix'):
            with self.subTest(leaf=leaf):
                self.patched(leaf)

    def test_exclusive_scripts_do_nothing_while_held(self):
        self.marker.write_text('{}')
        for leaf in s.EXCLUSIVE:
            with self.subTest(leaf=leaf):
                self.log.write_text('')
                self.assertEqual(self.execute(self.patched(leaf)), [])

    def test_safe_start_retains_original_behavior_when_not_held(self):
        calls = self.execute(self.patched('plex-safe-start'))
        self.assertIn('start plex', calls)

    def test_dangling_hold_marker_also_blocks_safe_start(self):
        self.marker.symlink_to(self.root / 'missing')
        self.assertEqual(self.execute(self.patched('plex-safe-start')), [])

    def test_recovery_boot_restores_other_consumers_and_skips_held_plex(self):
        self.marker.write_text('{}')
        self.arguments = ['boot']
        calls = self.execute(self.patched('media-mount-recover.sh'), running=False)
        for name in ('sonarr', 'radarr', 'radarr4k', 'jellyfin'):
            self.assertIn('start ' + name, calls)
        self.assertNotIn('start plex', calls)
        self.assertIn('systemctl start nzbdav-rclone.service', calls)

    def test_recovery_can_start_plex_when_not_held(self):
        self.arguments = ['boot']
        self.assertIn('start plex', self.execute(self.patched('media-mount-recover.sh'), running=False))

    def test_postboot_keeps_plex_disabled_and_original_other_policies(self):
        self.marker.write_text('{}')
        text = self.patched('docker-postboot-fix').split('# Repair containers')[0]
        calls = self.execute(text)
        self.assertIn('update --restart=no plex', calls)
        self.assertIn('update --restart=on-failure:5 jellyfin', calls)
        self.assertIn('update --restart=unless-stopped sonarr', calls)
        self.assertNotIn('update --restart=on-failure:5 plex', calls)

    def test_postboot_original_plex_policy_without_hold(self):
        text = self.patched('docker-postboot-fix').split('# Repair containers')[0]
        self.assertIn('update --restart=on-failure:5 plex', self.execute(text))

    def test_stale_fuse_repair_runs_for_arrs_while_plex_held(self):
        self.marker.write_text('{}')
        for name in ('nzbdav.id', 'torbox.id'):
            (self.state / name).write_text('42\n')
        (self.state / 'torbox.started').write_text('2026-11-11T00:00:00Z\n')
        calls = self.execute(self.patched('media-mount-watch.sh'))
        self.assertIn('restart sonarr', calls)
        self.assertFalse(any(c in ('start plex', 'restart plex') for c in calls))
        self.assertFalse((self.state / 'sonarr.stale-nzb-restart').exists())

    def test_pending_mount_restore_cannot_start_held_plex(self):
        self.marker.write_text('{}')
        (self.state / 'nzbdav.restore').write_text('plex\nradarr\n')
        calls = self.execute(self.patched('media-mount-watch.sh'), running=False)
        self.assertIn('start radarr', calls)
        self.assertFalse(any(c in ('start plex', 'restart plex') for c in calls))

    def test_watchdog_repair_code_is_retained_byte_for_byte(self):
        current = self.originals['/usr/local/sbin/media-mount-watch.sh'].decode()
        tail = current[current.index('# Verify actual FUSE visibility'):]
        self.assertTrue(self.patched('media-mount-watch.sh').endswith(tail))

    def test_changed_patch_anchor_is_rejected(self):
        with self.assertRaises(RuntimeError):
            s.patch_helper('/usr/local/sbin/docker-postboot-fix', b'#!/bin/bash\nexit 0\n')

    def test_preparation_creates_only_a_small_inactive_private_proposal(self):
        records = {n: {'sha256': value, 'mode': 0o755, 'uid': 0, 'gid': 0, 'xattrs': {}}
                   for n, value in s.EXPECTED.items()}
        row = {'id': 'unchanged', 'imageId': s.IMAGE, 'startedAt': 'unchanged'}
        seed = {'phase': 'seeded-running-not-frozen', 'consistentSnapshot': False}
        base = self.root / 'proposal'
        source = self.root / 'production-data'
        source.write_bytes(b'original Plex data')
        locks = []
        for i in range(3):
            lock = self.root / f'lock-{i}'
            lock.touch()
            locks.append(lock)
        real_run = subprocess.run
        with patch.object(s, 'BASE', base), patch.object(s, 'LOCKS', locks), \
                patch.object(s, 'PENDING', (self.marker,)), \
                patch.object(s, 'inputs', return_value=(self.originals, records)), \
                patch.object(s, 'source_container', return_value=row), \
                patch.object(s, 'seed_check', return_value=seed), \
                patch.object(s.subprocess, 'run', wraps=real_run) as commands, \
                contextlib.redirect_stdout(io.StringIO()):
            s.prepare()
        self.assertEqual(source.read_bytes(), b'original Plex data')
        self.assertFalse(self.marker.exists())
        plan = json.loads((base / 'plan.json').read_text())
        self.assertEqual(len(plan['patches']), 8)
        self.assertEqual(len(plan['sourceHelpers']), 14)
        self.assertEqual(len(plan['proposedServiceConditions']), 3)
        self.assertFalse(plan['activationImplemented'])
        self.assertFalse(plan['sourceStopPerformed'])
        self.assertFalse(plan['plexDataCopied'])
        self.assertTrue(all(c.args[0] == ('bash', '-n') for c in commands.call_args_list))
        self.assertLess(sum(p.stat().st_size for p in base.iterdir()), 1024**2)


if __name__ == '__main__':
    unittest.main()
