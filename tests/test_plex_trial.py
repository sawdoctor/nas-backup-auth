import contextlib
import copy
import datetime as dt
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('plex_trial', Path(__file__).resolve().parents[1] / 'scripts/plex-migration-trial.py')
m = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(m)


class FixedDate(dt.datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2026, 11, 4, 21, 30, tzinfo=dt.timezone.utc).astimezone(tz)


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.state = {'trialId': 'a' * 32, 'receiptKey': 'b' * 64, 'containerId': 'c' * 64}

    def test_valid_and_renewable_stopped_receipt(self):
        token = m.make_receipt(self.state, now=1000)
        m.verify_receipt(token, self.state, now=1200)
        m.verify_receipt(m.make_receipt(self.state, now=5000), self.state, now=5000)

    def test_receipt_tampering_expiry_and_other_trial_fail_closed(self):
        token = m.make_receipt(self.state, now=1000)
        for candidate, state, now in [(token[:-1] + ('0' if token[-1] != '0' else '1'), self.state, 1001),
                                      (token, self.state, 1601), (token, self.state, 900),
                                      (token, dict(self.state, trialId='d' * 32), 1001),
                                      ('bad.input', self.state, 1001), ('a.b.c', self.state, 1001)]:
            with self.subTest(candidate=candidate, now=now), self.assertRaises(RuntimeError):
                m.verify_receipt(candidate, state, now=now)


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.source = self.root / 'source'; self.source.mkdir()
        self.units = self.root / 'units'; self.units.mkdir()
        self.sudo = self.root / 'sudoers/read'; self.sudo.parent.mkdir()
        self.helper = self.root / 'safe-start'; self.original = b'#!/bin/bash\necho original\n'; self.helper.write_bytes(self.original); self.helper.chmod(0o755)
        self.reader = self.root / 'reader'; self.original_reader = b'#!/bin/sh\ncase "${SSH_ORIGINAL_COMMAND-}" in\nstandby) echo preserved ;;\nesac\n'
        self.reader.write_bytes(self.original_reader); self.reader.chmod(0o755)
        self.row = {'Id': 'f' * 64, 'Image': m.SOURCE_IMAGE, 'Name': '/plex',
                    'State': {'Running': True, 'Status': 'running'},
                    'HostConfig': {'NetworkMode': 'host', 'RestartPolicy': {'Name': 'on-failure', 'MaximumRetryCount': 5}},
                    'Mounts': [{'Destination': '/config', 'Source': str(m.SOURCE_CONFIG)}]}
        self.actions = []; self.fail_stop = False; self.fail_timer_once = False
        self.states = {name: {'Id': name, 'LoadState': 'loaded', 'MainPID': '0', 'ControlPID': '0',
                             'ActiveState': 'active' if name in m.TIMERS and name != 'plex-api-watch.timer' else 'inactive',
                             'SubState': 'waiting' if name in m.TIMERS else 'dead', 'UnitFileState': 'enabled'}
                       for name in m.SERVICES + m.TIMERS}
        mapping = {'SOURCE': self.source, 'HOLD': self.source / 'hold.json', 'READER': self.reader,
                   'SUDOERS': self.sudo, 'UNITS': self.units, 'BOOT': self.units / 'nas-plex-trial-recovery.service',
                   'FILES': {str(self.helper): m.file_sha(self.helper)},
                   'GUARD': m.GUARD.replace(str(m.HOLD), str(self.source / 'hold.json')),
                   'DROPIN': m.DROPIN.replace(str(m.HOLD), str(self.source / 'hold.json'))}
        for name, value in mapping.items():
            p = patch.object(m, name, value); p.start(); self.addCleanup(p.stop)
        for name, value in [('run', self.command), ('unit_state', lambda name: copy.deepcopy(self.states.get(name, {'LoadState': 'not-found', 'ActiveState': 'inactive'}))),
                            ('check_cron', lambda: None), ('locks', lambda paths: contextlib.nullcontext()),
                            ('session_count', lambda config: 1), ('identity', lambda config: 'e' * 64),
                            ('wait_api', lambda config, expected: None),
                            ('port_open', lambda host: self.row['State']['Running'] if host == '127.0.0.1' else False),
                            ('say', lambda text: self.actions.append(('log', text)))]:
            p = patch.object(m, name, value); p.start(); self.addCleanup(p.stop)
        p = patch.object(m.dt, 'datetime', FixedDate); p.start(); self.addCleanup(p.stop)

    def command(self, *args, **kwargs):
        self.actions.append(args)
        if args[:2] == ('docker', 'inspect'): return json.dumps([self.row])
        if args[:2] == ('docker', 'update'):
            value = args[2].split('=', 1)[1]
            name, _, maximum = value.partition(':')
            self.row['HostConfig']['RestartPolicy'] = {'Name': name, 'MaximumRetryCount': int(maximum or 0)}
        if args[:2] == ('docker', 'stop'):
            self.row['State'] = {'Running': False, 'Status': 'exited'}
            if self.fail_stop: raise RuntimeError('simulated interrupted stop')
        if args[0] == '/usr/local/sbin/plex-safe-start': self.row['State'] = {'Running': True, 'Status': 'running'}
        if args[:2] == ('systemctl', 'stop'):
            for name in args[2:]: self.states[name]['ActiveState'] = 'inactive'
        if args[:2] == ('systemctl', 'start'):
            if self.fail_timer_once:
                self.fail_timer_once = False
                raise RuntimeError('simulated timer restore interruption')
            self.states[args[2]]['ActiveState'] = 'active'
        return ''

    def test_hold_only_stops_plex_and_preserves_helpers_then_exact_restoration(self):
        m.hold_source(daytime=True)
        self.assertFalse(self.row['State']['Running'])
        self.assertEqual(self.row['HostConfig']['RestartPolicy']['Name'], 'no')
        self.assertTrue(m.source_status()['held'])
        self.assertIn(b'Plex NAS trial hold', self.helper.read_bytes())
        self.assertIn(b'standby) echo preserved', self.reader.read_bytes())
        self.assertEqual([a for a in self.actions if a[:2] == ('docker', 'stop')], [('docker', 'stop', '--time', '40', 'f' * 64)])
        state = m.read_json(m.HOLD)
        m.resume_source(m.make_receipt(dict(state, containerId='c' * 64)))
        self.assertTrue(self.row['State']['Running'])
        self.assertEqual(self.row['HostConfig']['RestartPolicy'], {'Name': 'on-failure', 'MaximumRetryCount': 5})
        self.assertEqual(self.helper.read_bytes(), self.original)
        self.assertEqual(self.reader.read_bytes(), self.original_reader)
        self.assertFalse(m.HOLD.exists()); self.assertFalse(m.SUDOERS.exists()); self.assertFalse(m.BOOT.exists())
        self.assertEqual(self.states['plex-api-watch.timer']['ActiveState'], 'inactive')
        self.assertEqual(self.states['plex-daily-backup.timer']['ActiveState'], 'active')

    def test_unknown_helper_or_additional_viewer_cannot_stop_plex(self):
        self.helper.write_bytes(b'changed')
        with self.assertRaises(RuntimeError): m.hold_source(daytime=True)
        self.assertTrue(self.row['State']['Running']); self.assertFalse(m.HOLD.exists())
        self.helper.write_bytes(self.original)
        with patch.object(m, 'session_count', return_value=2), self.assertRaises(RuntimeError): m.hold_source(daytime=True)
        self.assertTrue(self.row['State']['Running']); self.assertFalse(m.HOLD.exists())

    def test_before_published_hold_failure_restores_source_even_if_stop_happened(self):
        self.fail_stop = True
        with self.assertRaises(RuntimeError): m.hold_source(daytime=True)
        self.assertTrue(self.row['State']['Running'])
        self.assertEqual(self.helper.read_bytes(), self.original)
        self.assertFalse(m.HOLD.exists())

    def test_published_hold_failure_never_automatically_starts_source(self):
        with patch.object(m, 'source_status', return_value={'held': False}), self.assertRaises(RuntimeError):
            m.hold_source(daytime=True)
        self.assertEqual(m.read_json(m.HOLD)['phase'], 'held')
        self.assertFalse(self.row['State']['Running'])
        m.recover_source()
        self.assertFalse(self.row['State']['Running'])

    def test_return_cannot_resume_without_fresh_nas_receipt_or_with_live_nas(self):
        m.hold_source(daytime=True); state = m.read_json(m.HOLD)
        with self.assertRaises(RuntimeError): m.resume_source('not-a-receipt')
        self.assertFalse(self.row['State']['Running'])
        with patch.object(m, 'port_open', return_value=True), self.assertRaises(RuntimeError):
            m.resume_source(m.make_receipt(dict(state, containerId='c' * 64)))
        self.assertFalse(self.row['State']['Running'])

    def test_interrupted_authorized_restore_is_recoverable(self):
        m.hold_source(daytime=True); state = m.read_json(m.HOLD)
        self.fail_timer_once = True
        with self.assertRaises(RuntimeError): m.resume_source(m.make_receipt(dict(state, containerId='c' * 64)))
        self.assertEqual(m.read_json(m.HOLD)['phase'], 'restoring')
        self.assertTrue(m.BOOT.exists())
        m.recover_source()
        self.assertTrue(self.row['State']['Running']); self.assertFalse(m.HOLD.exists())

    def test_changed_guard_cannot_attest_or_overwrite_user_edit(self):
        m.hold_source(daytime=True)
        self.helper.write_bytes(b'operator edit')
        self.assertFalse(m.source_status()['held'])
        state = m.read_json(m.HOLD)
        with self.assertRaises(RuntimeError): m.resume_source(m.make_receipt(dict(state, containerId='c' * 64)))
        self.assertEqual(self.helper.read_bytes(), b'operator edit')
        self.assertFalse(self.row['State']['Running'])

    def test_busy_recovery_prevents_new_hold(self):
        self.states['media-mount-watch.service']['MainPID'] = '123'
        with self.assertRaises(RuntimeError): m.hold_source(daytime=True)
        self.assertTrue(self.row['State']['Running']); self.assertFalse(m.HOLD.exists())

    def test_new_guarded_helpers_remain_valid_shell_and_skip_while_held(self):
        m.hold_source(daytime=True)
        subprocess.run(['bash', '-n', str(self.helper)], check=True, capture_output=True)
        result = subprocess.run(['bash', str(self.helper)], check=True, capture_output=True, text=True)
        self.assertNotIn('original', result.stdout)


class NasStopTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.row = {'Id': 'c' * 64, 'State': {'Running': True}, 'HostConfig': {'RestartPolicy': {'Name': 'no'}}}
        self.state = {'format': m.SIGNATURE, 'phase': 'active', 'trialId': 'a' * 32, 'receiptKey': 'b' * 64, 'containerId': 'c' * 64}
        (self.root / 'state.json').write_text(json.dumps(self.state))
        self.messages = []; self.stops = 0
        for name, value in [('NAS', self.root), ('NAS_STATE', self.root / 'state.json'),
                            ('locks', lambda paths: contextlib.nullcontext()),
                            ('inspect', lambda name: copy.deepcopy(self.row)), ('run', self.command),
                            ('port_open', lambda host: False), ('say', self.messages.append)]:
            p = patch.object(m, name, value); p.start(); self.addCleanup(p.stop)

    def command(self, *args, **kwargs):
        if args[:2] == ('docker', 'stop'):
            self.stops += 1; self.row['State']['Running'] = False
        return ''

    def test_receipt_only_after_confirmed_stop_and_reissue_without_restart(self):
        m.stop_nas()
        token = next(t for t in self.messages if t.startswith('sudo ')).split()[-1]
        m.verify_receipt(token, self.state)
        self.assertEqual(self.stops, 1)
        self.assertEqual(m.read_json(m.NAS_STATE)['phase'], 'stopped')
        m.stop_nas(); self.assertEqual(self.stops, 1)

    def test_no_receipt_for_live_port_or_changed_container(self):
        with patch.object(m, 'port_open', return_value=True), self.assertRaises(RuntimeError): m.stop_nas()
        self.assertFalse(any(t.startswith('sudo ') for t in self.messages))
        self.row['Id'] = 'd' * 64
        with self.assertRaises(RuntimeError): m.stop_nas()
        self.assertFalse(any(t.startswith('sudo ') for t in self.messages))

    def test_safe_return_even_when_nas_preflight_failed_before_creating_record(self):
        m.NAS_STATE.unlink()
        self.row['State']['Running'] = False
        self.row['Config'] = {'Image': m.IMAGE}
        held = dict(self.state, held=True, identitySha256='e' * 64)
        with patch.object(m, 'source_remote', return_value=held), patch.object(m, 'identity', return_value='e' * 64):
            m.stop_nas()
        token = next(t for t in self.messages if t.startswith('sudo ')).split()[-1]
        m.verify_receipt(token, self.state)
        self.assertEqual(self.stops, 0)


class PathsAndIdentityTests(unittest.TestCase):
    def test_library_walker_does_not_follow_broken_streaming_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ('movies', 'movies-4k', 'tv'): (root / name).mkdir()
            (root / 'tv/example.mkv').symlink_to('/unavailable-streaming-path')
            (root / 'tv/not-a-directory').symlink_to('/unavailable-folder', target_is_directory=True)
            self.assertEqual(m.media_paths(root), {'tv/example.mkv': '/unavailable-streaming-path'})

    def test_bind_check_detects_stale_fuse_device_and_wrong_subfolder(self):
        host = {'/mnt/nzbdav': {'device': '0:101', 'root': '/'}, '/mnt/torbox-media': {'device': '0:102', 'root': '/'}}
        valid = {'/mnt/nzbdav': {'device': '0:101', 'root': '/'}, '/torbox-cams': {'device': '0:102', 'root': '/movies'}}
        row = {'State': {'Pid': 123}}
        with patch.object(m, 'mount_table', return_value=valid): m.bind_check(row, host)
        for bad in ({'/mnt/nzbdav': {'device': '0:99', 'root': '/'}, '/torbox-cams': valid['/torbox-cams']},
                    {'/mnt/nzbdav': valid['/mnt/nzbdav'], '/torbox-cams': {'device': '0:102', 'root': '/old'}}):
            with patch.object(m, 'mount_table', return_value=bad), self.assertRaises(RuntimeError): m.bind_check(row, host)

    def test_wait_api_rejects_other_machine_identity(self):
        import xml.etree.ElementTree as ET
        with patch.object(m, 'api', return_value=ET.fromstring('<MediaContainer machineIdentifier="wrong" version="1.43.5.11079"/>')):
            with self.assertRaises(RuntimeError): m.wait_api(Path('/unused'), 'e' * 64)

    def test_receiver_reader_adds_only_fixed_read_route_and_preserves_original(self):
        original = b'#!/bin/sh\n# existing\ncase "${SSH_ORIGINAL_COMMAND-}" in\nold) echo old ;;\nesac\n'
        new = m.reader_text(original)
        self.assertTrue(new.endswith(original.split(b'\n', 1)[1]))
        self.assertIn(b'plex-trial-status)', new)
        self.assertNotIn(b'source-resume', new)
        self.assertNotIn(b'source-hold', new)


class NasStartTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.ssd = self.root / 'ssd'; self.nas = self.ssd / 'compose/plex-nas/recovery/trial'
        self.nas.mkdir(parents=True); self.data = self.ssd / 'appdata/plex-nas'
        self.library = self.ssd / 'appdata/infinidysk-nas/library'; self.scratch = self.root / 'scratch'
        self.prefs = self.data / 'config' / m.PREFS; self.prefs.parent.mkdir(parents=True)
        self.prefs.write_text('<Preferences MachineIdentifier="original-machine" PlexOnlineToken="synthetic-token" autoEmptyTrash="1" OtherSetting="preserved"/>')
        self.before = self.prefs.read_bytes()
        self.held = {'format': m.SIGNATURE, 'held': True, 'trialId': 'a' * 32, 'receiptKey': 'b' * 64,
                     'identitySha256': m.sha(b'original-machine')}
        self.mounts = {'/mnt/nzbdav': {'type': 'fuse.rclone', 'device': '0:101', 'root': '/'},
                       '/mnt/torbox-media': {'type': 'fuse.main.py', 'device': '0:102', 'root': '/'}}
        self.row = {'Id': 'c' * 64, 'Image': 'nas-image', 'Name': '/plex-nas',
                    'Config': {'Image': m.IMAGE},
                    'State': {'Running': False, 'Status': 'created', 'StartedAt': '0001-01-01T00:00:00Z', 'Pid': 123},
                    'HostConfig': {'NetworkMode': 'host', 'RestartPolicy': {'Name': 'no'},
                                   'Devices': [{'PathOnHost': '/dev/dri', 'PathInContainer': '/dev/dri', 'CgroupPermissions': 'rwm'}]},
                    'Mounts': [{'Destination': target, 'Source': str(source), 'Type': 'bind'} for target, source in {
                        '/config': self.data / 'config', '/flora-test-library': self.data / 'flora-test-library',
                        '/scratch': self.scratch, '/mnt/media': self.library, '/mnt/nzbdav': Path('/mnt/nzbdav'),
                        '/torbox-cams': Path('/mnt/torbox-media/movies')}.items()]}
        (self.ssd / 'compose/plex-nas/image-identities.json').write_text(json.dumps({'plex': {'source': m.SOURCE_IMAGE, 'nas': 'nas-image'}}))
        stamp = '20261104T003744Z'
        (self.data / '.standby-refreshed.json').write_text(json.dumps({'format': 'Sawdoctor NAS Plex standby refresh v1',
               'sourceCreatedUtc': stamp, 'sourceArchiveSha256': 'archive-sha'}))
        snapshot = self.ssd / 'migration/nightly-standby/snapshots' / stamp; snapshot.mkdir(parents=True)
        (snapshot / '_VERIFIED.json').write_text(json.dumps({'sha256': 'archive-sha'}))
        for root in (snapshot / 'data/library', self.library):
            for category in ('movies', 'movies-4k', 'tv'): (root / category).mkdir(parents=True)
            (root / 'tv/title.mkv').symlink_to('/mnt/nzbdav/.ids/synthetic')
        self.actions = []
        for name, value in [('SSD', self.ssd), ('SCRATCH', self.scratch), ('NAS', self.nas),
                            ('NAS_STATE', self.nas / 'state.json'), ('DATA', self.data), ('LIBRARY', self.library),
                            ('source_remote', lambda: copy.deepcopy(self.held)), ('run', self.command),
                            ('inspect', lambda name: copy.deepcopy(self.row)), ('port_open', lambda host: False),
                            ('locks', lambda paths: contextlib.nullcontext()), ('mount_table', lambda *args: self.mounts),
                            ('bind_check', lambda row, mounts: None), ('wait_api', lambda config, expected: None),
                            ('media_recovery_check_locked', lambda: self.actions.append(('recovery-check-under-parent-lock',))),
                            ('say', lambda message: self.actions.append(('log', message)))]:
            p = patch.object(m, name, value); p.start(); self.addCleanup(p.stop)
        for target, value in [('is_mount', lambda self: True)]:
            p = patch.object(Path, target, value); p.start(); self.addCleanup(p.stop)
        p = patch.object(m.os, 'access', return_value=True); p.start(); self.addCleanup(p.stop)
        p = patch.object(m.dt, 'datetime', FixedDate); p.start(); self.addCleanup(p.stop)

    def command(self, *args, **kwargs):
        self.actions.append(args)
        if args[0] == '/usr/local/sbin/nas-media-recovery':
            return 'Media clients with unavailable/old mounts: none\nPending backup recovery records: 0\n'
        if args[:2] == ('docker', 'start'): self.row['State'].update(Running=True, Status='running')
        if args[:2] == ('docker', 'stop'): self.row['State'].update(Running=False, Status='exited')
        return ''

    def test_verified_nas_start_changes_only_scan_safety_preferences_and_same_container(self):
        m.start_nas()
        self.assertTrue(self.row['State']['Running'])
        self.assertEqual(m.read_json(m.NAS_STATE)['phase'], 'active')
        self.assertEqual((self.nas / 'Preferences.before.xml').read_bytes(), self.before)
        self.assertEqual(m.preferences(self.data / 'config').get('OtherSetting'), 'preserved')
        for key, value in m.SAFE_PREFS.items(): self.assertEqual(m.preferences(self.data / 'config').get(key), value)
        self.assertIn(('docker', 'start', 'c' * 64), self.actions)
        self.assertFalse(any(a[:2] == ('docker', 'stop') for a in self.actions))
        self.assertIn(('recovery-check-under-parent-lock',), self.actions)
        self.assertFalse(any(a and a[0] == '/usr/local/sbin/nas-media-recovery' for a in self.actions))

    def test_nas_cannot_start_without_source_attestation_or_missing_source_link(self):
        with patch.object(m, 'source_remote', side_effect=RuntimeError('source not held')), self.assertRaises(RuntimeError):
            m.start_nas()
        self.assertFalse(self.row['State']['Running']); self.assertFalse(m.NAS_STATE.exists())
        (self.library / 'tv/title.mkv').unlink()
        with self.assertRaises(RuntimeError): m.start_nas()
        self.assertFalse(self.row['State']['Running']); self.assertFalse(m.NAS_STATE.exists())

    def test_failed_api_or_lost_hold_stops_nas_and_never_starts_source(self):
        with patch.object(m, 'wait_api', side_effect=RuntimeError('API failed')), self.assertRaises(RuntimeError):
            m.start_nas()
        self.assertFalse(self.row['State']['Running'])
        self.assertEqual(m.read_json(m.NAS_STATE)['phase'], 'stopped')
        self.assertFalse(any('source-resume' in a for a in self.actions))

    def test_start_refuses_wrong_identity_or_already_started_container(self):
        self.held['identitySha256'] = 'e' * 64
        with self.assertRaises(RuntimeError): m.start_nas()
        self.assertFalse(self.row['State']['Running'])
        self.held['identitySha256'] = m.sha(b'original-machine')
        self.row['State']['StartedAt'] = '2026-11-04T20:00:00Z'
        with self.assertRaises(RuntimeError): m.start_nas()
        self.assertFalse(self.row['State']['Running'])


class RecoveryLockRegressionTests(unittest.TestCase):
    def test_reviewed_read_only_queries_work_while_parent_lock_is_held(self):
        # Use the actual installed recovery implementation, including its real
        # lock helper, rather than a CLI mock that conceals nested lock waits.
        path = Path(__file__).resolve().parents[1] / 'scripts/install-nas-media-recovery.py'
        spec = importlib.util.spec_from_file_location('trial_recovery_regression', path)
        recovery = importlib.util.module_from_spec(spec); spec.loader.exec_module(recovery)
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / 'backup.lock'
            with patch.object(recovery, 'LOCK', lock), patch.object(recovery, 'containers', return_value=[]), \
                 patch.object(recovery, 'host_mounts', return_value={}), patch.object(recovery, 'saved_ids', return_value=[]), \
                 patch.object(m, 'recovery_helper', return_value=recovery), patch.object(m, 'say'):
                with m.locks([lock]):
                    with recovery.locked(nonblocking=True) as acquired:
                        self.assertFalse(acquired)
                    m.media_recovery_check_locked()

    def test_stale_mount_and_pending_backup_records_still_block_start(self):
        item = {'Name': '/media-client', 'State': {'Running': True}}
        recovery = types.SimpleNamespace(host_mounts=lambda: {}, containers=lambda: [item],
                dependencies=lambda item: {'mount'}, ready=lambda *args: False,
                stale_bindings=lambda *args: True, saved_ids=lambda: [])
        with patch.object(m, 'recovery_helper', return_value=recovery), patch.object(m, 'say'), self.assertRaises(RuntimeError):
            m.media_recovery_check_locked()
        recovery.containers = lambda: []
        recovery.saved_ids = lambda: ['pending']
        with patch.object(m, 'recovery_helper', return_value=recovery), patch.object(m, 'say'), self.assertRaises(RuntimeError):
            m.media_recovery_check_locked()

    def test_timeout_errors_name_the_operation_without_command_output_or_secrets(self):
        with patch.object(m.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['ssh', 'private'], 20, output='secret')):
            with self.assertRaisesRegex(RuntimeError, '^OptiPlex hold verification timed out after 20 seconds.$'):
                m.run('ssh', 'private', timeout=20)


class NasRetryInstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.worker = self.root / 'worker'; self.nas = self.root / 'nas'; self.nas.mkdir()
        self.old = ('# ' + m.SIGNATURE + '\nold reviewed helper\n').encode(); self.worker.write_bytes(self.old)
        self.new = ('# ' + m.SIGNATURE + '\ncorrected helper\n').encode()
        self.actions = []
        self.row = {'State': {'Running': False, 'Status': 'created', 'StartedAt': '0001-01-01'},
                    'Config': {'Image': m.IMAGE}, 'HostConfig': {'RestartPolicy': {'Name': 'no'}}}
        for name, value in [('NAS', self.nas), ('NAS_STATE', self.nas / 'state.json'), ('WORKER', self.worker),
                            ('NAS_UPDATE_FROM', m.sha(self.old)), ('SOURCE', self.root / 'source'),
                            ('unit_state', lambda name: {'ActiveState': 'inactive'}),
                            ('inspect', lambda name: self.row), ('locks', lambda paths: contextlib.nullcontext()),
                            ('run', lambda *args, **kwargs: self.actions.append(args) or ''), ('say', lambda text: None)]:
            p = patch.object(m, name, value); p.start(); self.addCleanup(p.stop)

    def test_only_reviewed_nas_preflight_can_be_updated_and_retried(self):
        m.install(self.new, 'nas')
        self.assertEqual(self.worker.read_bytes(), self.new)
        self.assertFalse(m.SOURCE.exists())
        self.assertTrue(any(a[0] == 'systemd-run' and 'nas-start' in a for a in self.actions))

    def test_source_unknown_helper_or_progressed_nas_cannot_be_overwritten(self):
        with self.assertRaises(RuntimeError): m.install(self.new, 'source')
        self.assertEqual(self.worker.read_bytes(), self.old)
        with patch.object(m, 'NAS_UPDATE_FROM', 'unreviewed'), self.assertRaises(RuntimeError): m.install(self.new, 'nas')
        self.assertEqual(self.worker.read_bytes(), self.old)
        m.NAS_STATE.write_text('{}')
        with self.assertRaises(RuntimeError): m.install(self.new, 'nas')
        self.assertEqual(self.worker.read_bytes(), self.old)
        self.assertFalse(any(a[0] == 'systemd-run' for a in self.actions))

    def test_an_active_trial_operation_is_retained_without_replacing_its_helper(self):
        with patch.object(m, 'unit_state', return_value={'ActiveState': 'activating'}): m.install(self.new, 'nas')
        self.assertEqual(self.worker.read_bytes(), self.old)
        self.assertFalse(self.actions)


if __name__ == '__main__': unittest.main()
