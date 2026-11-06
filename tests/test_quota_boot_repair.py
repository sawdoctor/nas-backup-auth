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
SCRIPTS = ROOT / 'scripts'
if not SCRIPTS.is_dir():
    SCRIPTS = ROOT / 'nas-backup-auth/scripts'
spec = importlib.util.spec_from_file_location('quota_boot_repair', SCRIPTS / 'repair-nas-quota-boot.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)

TEMPLATE = '''[Unit]
DefaultDependencies=no
BindsTo=%i.mount
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/quotaon -ug %f
'''


def completed(stdout='', code=0, stderr=''):
    return subprocess.CompletedProcess([], code, stdout, stderr)


class CheckerTests(unittest.TestCase):
    def setUp(self):
        self.ns = s.checker_namespace()
        self.path = s.TARGETS[0]

    def results(self, user='on', group='on'):
        uuid = self.path.removeprefix('/srv/dev-disk-by-uuid-')
        text = f'group quota on {self.path} (/dev/sda1) is {group}\nuser quota on {self.path} (/dev/sda1) is {user}\n'
        return [completed(uuid + ' ext4\n'), completed(text)]

    def call(self, results, main=False):
        with patch.object(Path, 'is_mount', return_value=True), patch.object(Path, 'is_symlink', return_value=False), \
                patch.object(s.os, 'geteuid', return_value=0), patch.object(s.sys, 'argv', ['checker', self.path]), \
                patch.object(s.subprocess, 'run', side_effect=results) as run, contextlib.redirect_stdout(io.StringIO()):
            value = self.ns['main']() if main else self.ns['quota_state'](self.path)
            return value, [call.args[0] for call in run.call_args_list]

    def test_already_on_skips_activation_with_read_only_calls(self):
        code, calls = self.call(self.results(), main=True)
        self.assertEqual(code, 1)
        self.assertEqual(calls[-1], ['/usr/sbin/quotaon', '-p', '-u', '-g', self.path])
        self.assertFalse(any('quotaoff' in ' '.join(call) for call in calls))

    def test_off_state_keeps_packaged_activation(self):
        for user, group in (('off', 'off'), ('on', 'off'), ('off', 'on')):
            with self.subTest(user=user, group=group):
                self.assertEqual(self.call(self.results(user, group), main=True)[0], 0)

    def test_wrong_filesystem_identity_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'identity'):
            self.call([completed('different-uuid ext4\n')])

    def test_unmounted_and_unknown_paths_rejected_without_quota_command(self):
        with patch.object(Path, 'is_mount', return_value=False), patch.object(s.subprocess, 'run') as run:
            with self.assertRaises(RuntimeError):
                self.ns['quota_state'](self.path)
            run.assert_not_called()
        with patch.object(s.subprocess, 'run') as run:
            with self.assertRaises(RuntimeError):
                self.ns['quota_state']('/another/filesystem')
            run.assert_not_called()

    def test_missing_duplicate_wrong_target_and_error_states_rejected(self):
        good = self.results()[1].stdout
        bad = [completed(good, 1), completed(good, stderr='query error'),
               completed(good.splitlines()[0] + '\n'), completed(good + good),
               completed(good.replace(self.path, '/another/path')),
               completed(good.replace('is on', 'is unknown'))]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                self.call([self.results()[0], value])

    def test_exception_wrapper_returns_255_instead_of_skipping_on_error(self):
        namespace = {'__name__': '__main__'}
        with patch.object(s.os, 'geteuid', return_value=0), patch.object(s.sys, 'argv', ['checker', self.path]), \
                patch.object(Path, 'is_mount', return_value=True), patch.object(Path, 'is_symlink', return_value=False), \
                patch.object(s.subprocess, 'run', side_effect=subprocess.TimeoutExpired('query', 15)), \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            exec(compile(s.CHECKER_CODE, 'checker-wrapper-test', 'exec'), namespace)
        self.assertEqual(error.exception.code, 255)


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root / 'quotaon@.service'
        self.base.write_text(TEMPLATE)
        self.system = self.root / 'system'
        self.system.mkdir()
        self.checker = self.root / 'libexec/checker'
        self.work = self.root / 'record'
        self.started = set()
        self.calls = []
        self.patches = contextlib.ExitStack()
        self.addCleanup(self.patches.close)
        self.patches.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.patches.enter_context(patch.multiple(s, BASE=self.base, SYSTEM=self.system, CHECKER=self.checker,
                                                WORK=self.work, LOCK=self.root / 'lock'))
        self.patches.enter_context(patch.object(s, 'checker_namespace', return_value={
            'quota_state': lambda path: {'user': 'on', 'group': 'on'}}))
        self.patches.enter_context(patch.object(s, 'run', side_effect=self.command))

    def command(self, *args, **kwargs):
        self.calls.append(args)
        if args[0] == 'tune2fs':
            return 'Filesystem features: has_journal quota metadata_csum\nUser quota inode: 3\nGroup quota inode: 4\n'
        if args[0] == 'systemd-escape':
            return subprocess.check_output(args, text=True)
        if args[:2] == ('systemctl', 'show'):
            unit = args[3]
            dest = self.system / (unit + '.d') / s.DROPIN
            return ('FragmentPath=' + str(self.base) + '\nDropInPaths=' + (str(dest) if dest.exists() else '')
                    + '\nActiveState=' + ('inactive' if unit in self.started else 'failed') + '\n')
        if args[:2] == ('systemctl', 'start'):
            self.started.add(args[2])
            return ''
        if args == ('systemctl', 'daemon-reload'):
            return ''
        raise AssertionError(args)

    def test_installs_only_two_conditions_and_keeps_vendor_command(self):
        before = self.base.read_bytes()
        s.repair()
        self.assertEqual(self.base.read_bytes(), before)
        self.assertEqual(self.checker.read_text(), s.CHECKER_CODE)
        self.assertEqual(self.checker.stat().st_mode & 0o777, 0o700)
        files = list(self.system.glob('*.service.d/*.conf'))
        self.assertEqual(len(files), 2)
        for path in files:
            self.assertEqual(path.read_bytes(), s.dropin())
            self.assertNotIn('ExecStart=', path.read_text())
            self.assertNotIn('SuccessExitStatus=', path.read_text())
        record = json.loads((self.work / 'result.json').read_text())
        self.assertEqual(record['phase'], 'complete')
        self.assertFalse(record['quotaLimitsChanged'])
        self.assertTrue(all(call[0] != 'quotaon' for call in self.calls))
        self.assertFalse(any('stop' in call or 'restart' in call or 'quotaoff' in call for call in self.calls))

    def test_changed_vendor_command_is_retained_without_writes(self):
        self.base.write_text(TEMPLATE.replace('-ug %f', '-a'))
        with self.assertRaises(RuntimeError):
            s.repair()
        self.assertFalse(self.checker.exists())
        self.assertFalse(list(self.system.rglob('*.conf')))

    def test_retry_keeps_the_existing_helper_and_two_dropins(self):
        s.repair()
        paths = [self.checker, *self.system.glob('*.service.d/*.conf')]
        before = {str(path): (path.read_bytes(), path.stat().st_ino) for path in paths}
        original_stat = Path.stat
        def root_owned_helper(path, *args, **kwargs):
            info = original_stat(path, *args, **kwargs)
            if path == self.checker:
                values = list(info)
                values[4] = 0  # The real installer runs with sudo; this test runner may not.
                return os.stat_result(values)
            return info
        with patch.object(Path, 'stat', root_owned_helper):
            s.repair()
        self.assertEqual(before, {str(path): (path.read_bytes(), path.stat().st_ino) for path in paths})
        self.assertEqual(len(list(self.system.glob('*.service.d/*.conf'))), 2)

    def test_initial_off_quota_state_stops_before_install(self):
        with patch.object(s, 'checker_namespace', return_value={
                'quota_state': lambda path: {'user': 'off', 'group': 'on'}}):
            with self.assertRaises(RuntimeError):
                s.repair()
        self.assertFalse(self.checker.exists())
        self.assertFalse(list(self.system.rglob('*.conf')))

    def test_edited_existing_helper_is_retained(self):
        self.checker.parent.mkdir()
        self.checker.write_text('keep existing helper')
        with self.assertRaises(RuntimeError):
            s.repair()
        self.assertEqual(self.checker.read_text(), 'keep existing helper')
        self.assertFalse(list(self.system.rglob('*.conf')))

    def test_preflight_both_filesystems_before_first_write(self):
        count = 0
        def feature(path):
            nonlocal count
            count += 1
            if count == 2:
                raise RuntimeError('second filesystem differs')
        with patch.object(s, 'filesystem_check', side_effect=feature), self.assertRaises(RuntimeError):
            s.repair()
        self.assertFalse(self.checker.exists())
        self.assertFalse(list(self.system.rglob('*.conf')))

    def test_unrelated_override_is_not_overwritten(self):
        unit = subprocess.check_output(['systemd-escape', '--path', '--template=quotaon@.service', s.TARGETS[0]], text=True).strip()
        folder = self.system / (unit + '.d')
        folder.mkdir()
        existing = folder / 'other.conf'
        existing.write_text('keep this override')
        with self.assertRaises(RuntimeError):
            s.repair()
        self.assertEqual(existing.read_text(), 'keep this override')
        self.assertFalse(self.checker.exists())

    def test_failure_after_install_is_recorded(self):
        original = self.command
        def fail(*args, **kwargs):
            if args[:2] == ('systemctl', 'start'):
                raise RuntimeError('quota precheck failed')
            return original(*args, **kwargs)
        with patch.object(s, 'run', side_effect=fail), self.assertRaises(RuntimeError):
            s.repair()
        self.assertEqual(json.loads((self.work / 'result.json').read_text())['phase'], 'verification-needs-review')
        self.assertEqual(self.base.read_text(), TEMPLATE)

    def test_generated_condition_passes_systemd_syntax_check(self):
        self.checker.parent.mkdir()
        self.checker.write_text(s.CHECKER_CODE)
        self.checker.chmod(0o700)
        unit = subprocess.check_output(['systemd-escape', '--path', '--template=quotaon@.service', s.TARGETS[0]], text=True).strip()
        service = self.system / unit
        service.write_text(TEMPLATE.replace('BindsTo=%i.mount\n', '').replace('/usr/sbin/quotaon -ug %f', '/usr/bin/true'))
        folder = self.system / (unit + '.d')
        folder.mkdir()
        (folder / s.DROPIN).write_bytes(s.dropin())
        result = subprocess.run(['systemd-analyze', 'verify', '--man=no', str(service)],
                                capture_output=True, text=True, env={**os.environ, 'SYSTEMD_LOG_LEVEL': 'err'})
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
