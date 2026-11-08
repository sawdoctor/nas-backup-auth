import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'scripts'
if not SCRIPTS.is_dir():
    SCRIPTS = ROOT / 'nas-backup-auth/scripts'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


s = load('npm_lan_activation', SCRIPTS / 'activate-nas-npm-lan.py')
f = load('npm_lan_fixture', Path(__file__).with_name('test_npm_current_prepare.py'))


class ActivationTests(unittest.TestCase):
    def setUp(self):
        self.case = f.CandidateTests(); self.case.setUp(); self.addCleanup(self.case.doCleanups)
        self.restore, self.app, self.live_db, self.stackfile, self.old = self.case.prepare_environment()
        f.s.prepare(f.source, f.complete, f.private, f.routes, self.restore)
        self.candidate = self.app / 'compose/npm-restore/cutover-current'
        self.record = json.loads((self.candidate / 'prepared.json').read_text())
        self.live = self.app / 'appdata/npm'
        (self.live / 'letsencrypt').mkdir()
        (self.live / 'letsencrypt/original').write_text('ORIGINAL_NAS_CERTIFICATE_STATE')
        (self.live / 'data/logs').mkdir()
        (self.live / 'data/logs/proxy-host-1_error.log').touch()
        self.original_db = self.live_db.read_bytes()
        self.original_stack = self.stackfile.read_bytes()
        self.stackfile.chmod(0o640); os.setxattr(self.stackfile, 'user.keep', b'ORIGINAL_STACK_XATTR')
        self.original_inode = self.live_db.stat().st_ino
        self.work = self.app / 'compose/npm-restore/lan-activation'; self.work.mkdir()
        self.tokens = []
        self.calls = []
        self.fail_start = False
        self.fail_render = False
        self.baseline = copy.deepcopy(self.case.current)
        self.baseline['NetworkSettings'] = {'Networks': {'npm-nas_default': {}}}
        self.baseline['Mounts'] = [{'Destination': target, 'Type': 'bind', 'Source': str(self.live / name), 'RW': True}
                                   for name, target in (('data', '/data'), ('letsencrypt', '/etc/letsencrypt'))]
        self.container = copy.deepcopy(self.baseline)
        self.case.current.update(self.baseline)
        self.held_source = ('const logger={info:()=>{}}; const internalCertificate={\n' + f.private.TIMER + '\n'
                            '\tcreate: async (access, data) => {\n },\n'
                            '\trenew: async (access, data) => {\n }\n};').encode()
        self.resources = contextlib.ExitStack(); self.addCleanup(self.resources.close)
        self.resources.enter_context(patch.multiple(s, APP=self.app, LIVE=self.live, WORK=self.work, STACK=self.stackfile))
        self.resources.enter_context(patch.object(f.private, 'CERT_SHA', f.private.sha(self.held_source)))
        self.resources.enter_context(patch.object(f.private, 'load_current_helpers', return_value=(f.complete, f.routes, self.restore, (f.s, f.source))))
        self.resources.enter_context(patch.object(s, 'command', side_effect=self.command))
        self.resources.enter_context(patch.object(s, 'inspect', side_effect=lambda: copy.deepcopy(self.container)))
        self.resources.enter_context(patch.object(s, 'security', return_value={'ssh': 'UNCHANGED', 'jailConfig': 'UNCHANGED'}))
        self.reload = self.resources.enter_context(patch.object(s, 'jail_reload'))
        self.ready = self.resources.enter_context(patch.object(s, 'ready'))
        self.resources.enter_context(patch.object(self.restore, 'run', side_effect=self.dockmon_read))
        self.write_test()

    def write_test(self, **updates):
        report = {'format': 'sawdoctor-npm-private-proxy-test-v1', 'status': 'route-responses-checked',
                  'candidatePath': str(self.candidate), 'sourceSnapshot': self.record['sourceSnapshot'],
                  **{k: True for k in ('automaticRenewalHeld', 'certificateCreateAndRenewHeld', 'temporaryContainerRemoved',
                     'temporaryPayloadRemoved', 'existingNasProxyUnchanged', 'candidateUnchanged',
                     'currentCandidate', 'newNginxWorkerGenerationReady')},
                  'routes': [{**r, 'needsAttention': False, 'curlExit': 0, 'responseReceivedWithTrustedTls': True}
                             for r in f.private.routes_in(self.candidate / 'payload/data/database.sqlite', current=True)]}
        report.update(updates)
        folder = self.app / 'compose/npm-restore/proxy-test-current'; folder.mkdir(exist_ok=True)
        (folder / 'result.json').write_text(json.dumps(report))

    def dockmon_read(self, *args, **kwargs):
        self.assertEqual(args[:3], ('docker', 'exec', 'dockmon'))
        return json.dumps({'text': self.stackfile.read_text(), 'env': '', 'path': '/app/data/stacks/npm-nas/docker-compose.yml'})

    def command(self, *args, stdin=None, **kwargs):
        self.calls.append(args)
        if args[:3] == ('fail2ban-client', 'get', s.JAIL):
            return str(self.live / 'data/logs/proxy-host-1_error.log').encode()
        if args[:4] == ('docker', 'exec', 'npm-nas', 'cat'):
            return self.held_source
        if args[:5] == ('docker', 'exec', '-i', 'npm-nas', 'node'):
            return subprocess.run(['node', '--input-type=module', '--check'], input=stdin, capture_output=True, check=True).stdout
        if args[0] == 'rsync':
            subprocess.run(['cp', '-a', args[-2] + '.', args[-1]], check=True, capture_output=True)
            return b''
        if args[0] == 'cp':
            return subprocess.run(args, check=True, capture_output=True).stdout
        if args[:2] == ('docker', 'compose'):
            if 'config' in args:
                binary = os.environ['NPM_COMPOSE_BINARY']
                return subprocess.run([binary, *args[2:]], check=True, capture_output=True).stdout
            self.assertIn('up', args)
            self.assertIn('--no-deps', args); self.assertIn('--no-build', args)
            self.assertEqual(args[args.index('--pull')+1], 'never')
            self.assertEqual(args[-1], 'npm')
            model = yaml.safe_load(self.stackfile.read_text()); service = model['services']['npm']
            if s.LABEL in service.get('labels', {}):
                self.container = copy.deepcopy(self.baseline)
                self.container['Id'] = 'new-owned-npm'
                self.container['Config']['Labels'][s.LABEL] = service['labels'][s.LABEL]
                self.container['Mounts'].append({'Destination': '/app/internal/certificate.js',
                                               'Source': str(self.work / 'certificate-held.js'), 'RW': False, 'Type': 'bind'})
                if self.fail_start:
                    self.fail_start = False
                    raise RuntimeError('SIMULATED_COMPOSE_FAILURE')
            else:
                self.container = copy.deepcopy(self.baseline); self.container['Id'] = 'restored-npm'
            return b''
        if args[:2] == ('docker', 'stop'):
            self.assertEqual(args[-1], self.container['Id'])
            self.container['State']['Status'] = 'exited'; return b''
        if args[:2] == ('docker', 'rm'):
            self.assertEqual(args[-1], self.container['Id']); self.container = None; return b''
        if args[:6] == ('docker', 'exec', '-i', '--workdir', '/app', 'npm-nas'):
            self.assertEqual(stdin, f.private.render_code(current=True).encode())
            if self.fail_render:
                raise RuntimeError('SIMULATED_RENDER_FAILURE')
            return b'NPM_PRIVATE_ROUTES_RENDERED=28\nNPM_PRIVATE_NEW_WORKERS_READY\n'
        raise AssertionError('Unexpected command/production mutation: ' + repr(args))

    def activate(self):
        s.activate(f.private)

    def assert_original_restored(self):
        self.assertEqual(self.live_db.read_bytes(), self.original_db)
        self.assertEqual(self.live_db.stat().st_ino, self.original_inode)
        self.assertEqual(self.stackfile.read_bytes(), self.original_stack)
        self.assertEqual(self.stackfile.stat().st_mode & 0o777, 0o640)
        self.assertEqual(os.getxattr(self.stackfile, 'user.keep'), b'ORIGINAL_STACK_XATTR')
        self.assertEqual(s.state()['status'], 'rolled-back')

    def test_full_activation_keeps_candidate_and_source_secrets_and_dockmon_stack_metadata(self):
        before = f.complete.inventory(self.candidate / 'payload')
        self.activate()
        record = s.state()
        self.assertEqual(record['status'], 'nas-lan-active-renewal-held')
        self.assertTrue(record['certificateOperationsHeld']); self.assertFalse(record['publicHandover'])
        self.assertEqual((self.work / 'recovery/data/database.sqlite').read_bytes(), self.original_db)
        self.assertEqual((self.work / 'recovery/data/database.sqlite').stat().st_ino, self.original_inode)
        self.assertEqual(f.complete.inventory(self.candidate / 'payload'), before)
        self.assertEqual((self.live / 'data/keys.json').read_bytes(), (self.candidate / 'payload/data/keys.json').read_bytes())
        self.assertEqual(os.getxattr(self.live / 'data/custom', 'user.keep'), b'PRIVATE_XATTR')
        self.assertEqual(os.readlink(self.live / 'letsencrypt/live/npm-86/privkey.pem'), '../../archive/npm-6/privkey1.pem')
        model = yaml.safe_load(self.stackfile.read_text())
        self.assertEqual(model['services']['npm']['image'], 'jc21/nginx-proxy-manager:latest')
        self.assertEqual(model['services']['npm']['environment']['PRIVATE'], 'SECRET_$$value')
        self.assertEqual(self.stackfile.stat().st_mode & 0o777, 0o640)
        self.assertEqual(os.getxattr(self.stackfile, 'user.keep'), b'ORIGINAL_STACK_XATTR')
        self.ready.assert_called_once_with(held=True); self.reload.assert_called_once()
        count = len(self.calls)
        self.activate()
        self.assertEqual(len(self.calls), count)
        self.assertEqual((self.old / 'earlier').read_text(), 'PRESERVE_EARLIER_CANDIDATE')

    def test_missing_successful_current_test_stops_before_any_container_mutation(self):
        self.write_test(newNginxWorkerGenerationReady=False)
        with self.assertRaisesRegex(RuntimeError, 'successful current 28-route'):
            self.activate()
        self.assertFalse(any(c[:2] in (('docker', 'stop'), ('docker', 'compose')) for c in self.calls))
        self.assertEqual(self.live_db.read_bytes(), self.original_db)

    def test_changed_candidate_is_refused_before_data_or_proxy_changes(self):
        (self.candidate / 'payload/data/keys.json').write_text('CHANGED')
        with self.assertRaisesRegex(RuntimeError, 'candidate changed'):
            self.activate()
        self.assertEqual(self.live_db.read_bytes(), self.original_db)
        self.assertEqual(self.stackfile.read_bytes(), self.original_stack)
        self.assertFalse(self.calls)

    def test_start_failure_restores_original_and_retains_imported_copy(self):
        self.fail_start = True
        with self.assertRaisesRegex(RuntimeError, 'SIMULATED_COMPOSE_FAILURE'):
            self.activate()
        self.assert_original_restored()
        self.assertTrue((self.work / 'retained-activated-data/data/keys.json').is_file())
        self.ready.assert_called_once_with()

    def test_render_failure_rolls_back_instead_of_accepting_old_nginx_routes(self):
        self.fail_render = True
        with self.assertRaisesRegex(RuntimeError, 'SIMULATED_RENDER_FAILURE'):
            self.activate()
        self.assert_original_restored()
        self.assertEqual(self.container['Id'], 'restored-npm')

    def test_interrupted_second_swap_restores_both_original_trees(self):
        original = Path.rename
        failed = [False]
        def rename(path, target):
            if path == self.work / 'payload/letsencrypt' and not failed[0]:
                failed[0] = True
                raise RuntimeError('SIMULATED_PARTIAL_SWAP')
            return original(path, target)
        with patch.object(Path, 'rename', rename):
            with self.assertRaisesRegex(RuntimeError, 'SIMULATED_PARTIAL_SWAP'):
                self.activate()
        self.assert_original_restored()
        self.assertEqual((self.live / 'letsencrypt/original').read_text(), 'ORIGINAL_NAS_CERTIFICATE_STATE')

    def test_explicit_rollback_preserves_later_login_edits_in_retained_working_copy(self):
        self.activate()
        (self.live / 'data/later-login-change').write_text('KEEP_USER_CHANGE')
        s.rollback(s.state())
        self.assert_original_restored()
        self.assertEqual((self.work / 'retained-activated-data/data/later-login-change').read_text(), 'KEEP_USER_CHANGE')

    def test_rollback_refuses_foreign_proxy_without_stopping_it(self):
        self.activate()
        self.container['Id'] = 'foreign'; self.container['Config']['Labels'][s.LABEL] = 'foreign'
        before = len(self.calls)
        with self.assertRaisesRegex(RuntimeError, 'unrelated proxy'):
            s.rollback(s.state())
        self.assertEqual(len(self.calls), before)

    def test_rollback_refuses_later_compose_edits_and_completed_public_handover(self):
        self.activate()
        active = self.stackfile.read_bytes()
        self.stackfile.write_bytes(active + b'\n# LATER_USER_EDIT\n')
        before = len(self.calls)
        with self.assertRaisesRegex(RuntimeError, 'stack changed'):
            s.rollback(s.state())
        self.assertEqual(len(self.calls), before)
        self.stackfile.write_bytes(active)
        with self.assertRaisesRegex(RuntimeError, 'No matching active'):
            s.rollback({**s.state(), 'status': 'production-handover-complete'})
        self.assertEqual(len(self.calls), before)

    def test_log_watch_reopens_only_npm_jail_without_unbanning_or_restarting_ssh(self):
        calls = []
        log = self.live / 'data/logs/proxy-host-1_error.log'
        def command(*args):
            calls.append(args)
            return str(log).encode() if 'get' in args else b'OK'
        # Invoke the original helper rather than the orchestration fixture's mock.
        real = load('npm_lan_reload_check', SCRIPTS / 'activate-nas-npm-lan.py')
        with patch.object(real, 'LIVE', self.live), patch.object(real, 'command', side_effect=command):
            real.jail_reload()
        self.assertEqual(calls, [('fail2ban-client', 'reload', '--restart', s.JAIL),
                                 ('fail2ban-client', 'get', s.JAIL, 'logpath')])


if __name__ == '__main__':
    unittest.main()
