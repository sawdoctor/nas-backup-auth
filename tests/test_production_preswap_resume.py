"""Interrupted pre-swap activation may reuse its verified adapted roots safely."""
import copy
import contextlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT/'scripts'/filename)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value

r = module('resume_test', 'resume-nas-production-import.py')
n = module('native_resume_test', 'nas-production-cutover.py')


class PreSwapResume(unittest.TestCase):
    def setUp(self):
        self.row = {'Name': '/plex-nas', 'Id': 'original-id', 'Image': 'original-image', 'Mounts': [],
                    'Config': {'Env': ['private=retained']},
                    'HostConfig': {'RestartPolicy': {'Name': 'on-failure', 'MaximumRetryCount': 5}, 'NetworkMode': 'host'},
                    'State': {'Running': False}}
        self.plan = {'affected': ['plex-nas'], 'containers': {'plex-nas': copy.deepcopy(self.row)},
                     'fingerprints': {'plex-nas': n.fingerprint(self.row)}}
        self.row['HostConfig']['RestartPolicy'] = {'Name': 'no', 'MaximumRetryCount': 0}

    def test_only_controlled_restart_policy_change_is_accepted(self):
        comparison = r.comparable_stopped_row(n, self.plan, 'plex-nas', self.row)
        self.assertEqual(n.fingerprint(comparison), self.plan['fingerprints']['plex-nas'])
        self.assertEqual(self.row['HostConfig']['RestartPolicy']['Name'], 'no')

    def test_other_runtime_changes_and_running_writers_are_rejected(self):
        for field in ('Id', 'Image', 'Mounts', 'Config', 'HostConfig', 'Running'):
            row = copy.deepcopy(self.row)
            if field in ('Id', 'Image'): row[field] = 'changed'
            elif field == 'Mounts': row[field] = [{'Source': '/changed'}]
            elif field == 'Config': row[field]['Env'] = ['private=changed']
            elif field == 'HostConfig': row[field]['NetworkMode'] = 'bridge'
            else: row['State']['Running'] = True
            with self.subTest(field=field), self.assertRaises(RuntimeError): r.comparable_stopped_row(n, self.plan, 'plex-nas', row)

    def test_any_recorded_swap_prevents_the_special_preswap_resume(self):
        native = SimpleNamespace(FORMAT=n.FORMAT)
        state = {'format':n.FORMAT, 'phase':'importing', 'nasPlanSha256':r.PLAN_SHA, 'roots':[{'phase':'planned'}]}
        with self.assertRaisesRegex(RuntimeError, 'pre-swap'): r.validate_recovery(native, {}, state)

    def test_only_stopped_services_with_no_main_pid_are_idle(self):
        for active, pid, expected in [('inactive','0',True),('failed','0',True),('deactivating','0',False),('active','12',False),('inactive','12',False)]:
            native = SimpleNamespace(unit_state=lambda _: {'ActiveState':active,'MainPID':pid})
            with self.subTest(active=active,pid=pid): self.assertEqual(r.service_idle(native,'mount.service'),expected)

    def test_dependent_stop_runs_outside_backup_lock_and_native_resume_reuses_adapted_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); statefile = root/'state.json'; backup = root/'backup.lock'; locks = []; calls = []
            state = {'phase':'importing','roots':[],'proof':{'held':True}}
            statefile.write_text(json.dumps(state))
            @contextlib.contextmanager
            def lock(path):
                locks.append(path)
                try: yield
                finally: locks.remove(path)
            def run(*args,**kwargs):
                calls.append(args)
                if args[:2]==('systemctl','stop'): self.assertNotIn(backup, locks)
                return ''
            native = SimpleNamespace(lock=lock, STATE=statefile, BACKUP_LOCK=backup, RCLONE='nas-infinidysk-rclone.service',
                SCRATCH=root, safe=lambda _:None, read=lambda p,*a,**k:p.read_bytes(), held=lambda _:None,
                catalog=lambda:{'plex-nas':copy.deepcopy(self.row)}, fingerprint=n.fingerprint, run=run,
                unit_state=lambda _:{'ActiveState':'inactive','MainPID':'0'})
            plan=copy.deepcopy(self.plan);plan['containers']['plex-nas']['Config']['Env']=['PUID=1000','PGID=1000']
            def activate(digest):
                self.assertEqual(digest,r.PLAN_SHA)
                self.assertEqual(json.loads(native.read(statefile))['phase'],'adapted')
                self.assertEqual(json.loads(native.read(statefile))['phase'],'importing')
                with native.lock(backup):
                    self.assertEqual(native.fingerprint(self.row),self.plan['fingerprints']['plex-nas'])
                    native.run('systemctl','stop',native.RCLONE,timeout=90)
            native.activate=activate
            with patch.object(r,'BASE',root),patch.object(r,'validate_recovery'),patch.object(r,'comparable_stopped_row'), \
                    contextlib.redirect_stdout(__import__('io').StringIO()): r.resume(native,plan)
            self.assertEqual([c for c in calls if c[:2]==('systemctl','stop')],
                             [('systemctl','stop',r.BOOKS,native.RCLONE)])
            self.assertEqual(json.loads(statefile.read_bytes())['phase'],'importing')


if __name__ == '__main__': unittest.main()
