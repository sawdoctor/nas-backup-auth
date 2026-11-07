import ast
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'scripts'
if not SCRIPTS.is_dir():
    SCRIPTS = ROOT / 'nas-backup-auth/scripts'
spec = importlib.util.spec_from_file_location('npm_auth_setup', SCRIPTS / 'prepare-nas-npm-auth.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
# Set FAIL2BAN_TEST_SOURCE to an extracted official Fail2ban 1.1.0 source tree.
VENDOR = Path(os.environ.get('FAIL2BAN_TEST_SOURCE', str(ROOT / 'tmp/npm-auth-vendor/fail2ban-1.1.0')))


@unittest.skipUnless((VENDOR / 'config').is_dir(), 'Official Fail2ban 1.1.0 source is required for native-parser tests')
class RealFail2banTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.conf = self.root / 'config'
        shutil.copytree(VENDOR / 'config', self.conf)
        (self.conf / 'jail.d').mkdir(exist_ok=True)
        self.logs = self.root / 'logs'
        self.logs.mkdir()
        (self.logs / 'proxy-host-1_error.log').touch()
        self.env = {**os.environ, 'PYTHONPATH': str(VENDOR), 'LC_ALL': 'C'}

    def tool(self, name, *args):
        return subprocess.run([sys.executable, str(VENDOR / 'bin' / name), '-c', str(self.conf), *args],
                              env=self.env, capture_output=True, text=True, timeout=15)

    def test_real_filter_positive_and_negative_samples(self):
        def native(*args, **kwargs):
            self.assertEqual(args[0], 'fail2ban-regex')
            result = self.tool(args[0], *args[1:])
            self.assertEqual(result.returncode, 0, result.stderr)
            return result
        with patch.object(s, 'run', side_effect=native):
            s.filter_test()

    def test_real_jail_and_action_expansion_scopes_all_rules(self):
        with patch.object(s, 'LOGS', self.logs):
            config = s.configuration(s.CF)
        (self.conf / 'action.d/sawdoctor-npm-docker.conf').write_text(s.ACTION_TEXT)
        (self.conf / 'jail.d/sawdoctor-npm-auth.local').write_bytes(config)
        result = self.tool('fail2ban-client', '-d')
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = [ast.literal_eval(line) for line in result.stdout.splitlines() if line.startswith('[')]
        adds = [c for c in commands if c[:2] == ['add', s.JAIL]]
        self.assertEqual(len(adds), 1)
        actions = [c for c in commands if c[:3] == ['multi-set', s.JAIL, 'action']]
        self.assertEqual(len(actions), 2)
        for c in actions:
            values = dict(c[4])
            name = c[3]
            port = '10080:10081' if name == 'saw-npm-web' else '10443'
            for key in ('actionstart', 'actionstop', 'actioncheck'):
                self.assertIn('--ctorigdst 192.168.0.220 --ctorigdstport ' + port, values[key])
                self.assertIn('DOCKER-USER', values[key])
                self.assertNotIn('INPUT', values[key])
            self.assertEqual(values['blocktype'], 'DROP')
            self.assertIn('-s <ip> -j <blocktype>', values['actionban'])
            self.assertIn('-s <ip> -j <blocktype>', values['actionunban'])
        ignores = [c[3:] for c in commands if c[:3] == ['set', s.JAIL, 'addignoreip']]
        joined = str(ignores)
        for net in ('192.168.0.0/24', '127.0.0.0/8', '::/0', *s.CF):
            self.assertIn(net, joined)
        self.assertFalse(any(c[0] == 'set' and c[1] == 'sshd' for c in commands))
        self.assertIn(str(self.logs / 'proxy-host-1_error.log'), str(commands))
        self.assertIn('tail', str(commands))


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.lock = self.root / 'backup.lock'
        self.lock.touch()
        self.action = self.root / 'action.conf'
        self.config = self.root / 'jail.local'
        self.work = self.root / 'work'
        self.payload = {self.action: s.ACTION_TEXT.encode(), self.config: s.configuration(s.CF)}
        self.active = False
        self.calls = []
        self.before = {'ignoreip': '192.168.0.0/24', 'actions': 'existing-ssh-action'}
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.out = self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.stack.enter_context(patch.multiple(s, LOCK=self.lock, ACTION=self.action, CONFIG=self.config, WORK=self.work))
        self.stack.enter_context(patch.object(s, 'preflight', side_effect=lambda: (self.payload, self.before, self.active)))
        self.stack.enter_context(patch.object(s, 'ssh_state', return_value=self.before))
        self.stack.enter_context(patch.object(s, 'run', side_effect=self.query))
        self.stack.enter_context(patch.object(s, 'client', side_effect=self.client))
        self.bantest = self.stack.enter_context(patch.object(s, 'ban_test'))

    def query(self, *args, **kwargs):
        self.calls.append(args)
        return subprocess.CompletedProcess(args, 0, '', '')

    def client(self, *args, **kwargs):
        self.calls.append(('fail2ban-client', *args))
        if args == ('status',):
            return 'Jail list: sshd, ' + s.JAIL
        return 'OK'

    def test_installs_checks_only_new_jail_and_records_small_result(self):
        s.install()
        self.assertEqual(self.action.read_bytes(), self.payload[self.action])
        self.assertEqual(self.config.read_bytes(), self.payload[self.config])
        record = json.loads((self.work / 'result.json').read_text())
        self.assertTrue(record['reservedIpBanUnbanPassed'])
        self.assertTrue(record['sshSettingsRetained'])
        self.assertEqual(record['scope'], 'direct-ipv4-http-basic-auth-only')
        self.assertIn(('fail2ban-client', 'reload', '--if-exists', s.JAIL), self.calls)
        self.assertNotIn(('fail2ban-client', 'reload'), self.calls)
        self.bantest.assert_called_once()

    def test_config_failure_rolls_back_new_files_without_reloading_ssh(self):
        with patch.object(s, 'run', side_effect=RuntimeError('config failed')):
            with self.assertRaisesRegex(RuntimeError, 'config failed'):
                s.install()
        self.assertFalse(self.action.exists())
        self.assertFalse(self.config.exists())
        self.assertIn(('fail2ban-client', 'stop', s.JAIL), self.calls)
        self.assertFalse(self.work.exists())

    def test_active_matching_retry_retains_files_and_jail_if_test_fails(self):
        self.active = True
        for path, data in self.payload.items():
            path.write_bytes(data)
        before = self.action.stat().st_ino
        self.bantest.side_effect = RuntimeError('test failed')
        with self.assertRaisesRegex(RuntimeError, 'test failed'):
            s.install()
        self.assertEqual(self.action.stat().st_ino, before)
        self.assertTrue(self.config.exists())
        self.assertNotIn(('fail2ban-client', 'stop', s.JAIL), self.calls)

    def test_symlink_file_is_rejected_before_replacing_target(self):
        target = self.root / 'protected'
        target.write_text('unchanged')
        self.action.symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, 'symbolic'):
            s.install()
        self.assertEqual(target.read_text(), 'unchanged')

    def test_live_ssh_settings_change_stops_new_jail(self):
        with patch.object(s, 'ssh_state', return_value={'ignoreip': 'CHANGED'}):
            with self.assertRaisesRegex(RuntimeError, 'SSH jail settings changed'):
                s.install()
        self.bantest.assert_not_called()
        self.assertFalse(self.action.exists())

    def test_held_backup_lock_prevents_writes(self):
        import fcntl
        with self.lock.open('rb') as other:
            fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(RuntimeError, 'busy'):
                s.install()
        self.assertFalse(self.action.exists())
        self.assertFalse(self.calls)

    def test_cloudflare_ranges_must_match_review(self):
        with patch.object(s.urllib.request, 'urlopen', return_value=io.BytesIO(('\n'.join(s.CF)).encode())):
            self.assertEqual(s.cf_ranges(), s.CF)
        for bad in ('0.0.0.0/0', '\n'.join((*s.CF, s.CF[0])), 'not a range'):
            with self.subTest(bad=bad), patch.object(s.urllib.request, 'urlopen', return_value=io.BytesIO(bad.encode())):
                with self.assertRaises((RuntimeError, ValueError)):
                    s.cf_ranges()

    def test_changed_existing_config_is_rejected_by_preflight(self):
        self.config.write_text('foreign configuration')
        with self.assertRaisesRegex(RuntimeError, 'differs'):
            s.install()
        self.assertEqual(self.config.read_text(), 'foreign configuration')


class BanTests(unittest.TestCase):
    def test_ban_unban_checks_both_scopes_and_leaves_no_test_rule(self):
        active = set()
        calls = []
        def client(*args, **kw):
            calls.append(args)
            if args[2] == 'banip':
                active.update(name for name, _ in s.CHAINS)
            elif args[2] == 'unbanip':
                active.clear()
            return '1'
        def command(*args, **kw):
            calls.append(args)
            if args[3] == '-C' and args[4] == 'DOCKER-USER':
                self.assertIn('--ctorigdst', args)
                self.assertIn('--ctorigdstport', args)
                return subprocess.CompletedProcess(args, 0, '', '')
            name = args[4].removeprefix('f2b-')
            return subprocess.CompletedProcess(args, 0 if name in active else 1, '', '')
        with patch.object(s, 'client', side_effect=client), patch.object(s, 'run', side_effect=command):
            s.ban_test()
        self.assertFalse(active)
        self.assertEqual(calls[0], ('set', s.JAIL, 'banip', s.TEST_IP))
        self.assertIn(('set', s.JAIL, 'unbanip', s.TEST_IP), calls)
        self.assertFalse(any('-F' in c or '-X' in c for c in calls))

    def test_failed_ban_still_requests_reserved_ip_cleanup(self):
        calls = []
        def client(*args, **kw):
            calls.append(args)
            if args[2] == 'banip':
                raise RuntimeError('ban failed')
            return '0'
        with patch.object(s, 'client', side_effect=client), patch.object(s, 'run', return_value=subprocess.CompletedProcess([], 1, '', '')):
            with self.assertRaisesRegex(RuntimeError, 'ban failed'):
                s.ban_test()
        self.assertIn(('set', s.JAIL, 'unbanip', s.TEST_IP), calls)


if __name__ == '__main__':
    unittest.main()
