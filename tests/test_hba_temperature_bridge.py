"""Keep OMV/cron ownership intact and verify real scheduled cache refresh."""
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import mock_open, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('hba_bridge', ROOT/'scripts/restore-nas-hba-temperature-bridge.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class HbaTemperatureBridgeTests(unittest.TestCase):
    def test_active_cron_skips_existing_collector(self):
        with patch.object(m, 'verified') as verify, patch.object(m, 'cron_state', return_value='active'), patch.object(m.subprocess, 'run') as run:
            self.assertIsNone(m.collect())
        verify.assert_not_called(); run.assert_not_called()

    def test_inactive_cron_runs_only_the_unchanged_existing_collector(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary) / 'cache'
            cache.write_text('58\n')
            def collect_once(*args, **kwargs):
                replacement = cache.with_suffix('.tmp')
                replacement.write_text('59\n')
                replacement.replace(cache)
            with patch.object(m, 'CACHE', cache), patch.object(m, 'verified'), \
                    patch.object(m, 'cron_state', return_value='inactive'), \
                    patch('builtins.open', mock_open()), patch.object(m.fcntl, 'flock'), \
                    patch.object(m.subprocess, 'run', side_effect=collect_once) as run:
                self.assertEqual(m.collect(), 59)
            run.assert_called_once_with([str(m.COLLECTOR)], capture_output=True, timeout=20, check=True)

    def test_boot_collection_does_not_load_migration_or_source_controllers(self):
        with patch.object(m.sys, 'argv', ['worker.py', '--collect']), patch.object(m, 'collect') as collect, \
                patch.object(m, 'controllers', side_effect=AssertionError('source/migration dependency at boot')):
            m.main()
        collect.assert_called_once_with()

    def test_verified_source_and_fresh_numeric_cache_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            p=Path(temporary)/'collector';p.write_bytes(b'reviewed source')
            m.verified(p, hashlib.sha256(p.read_bytes()).hexdigest())
            p.write_bytes(b'changed source')
            with self.assertRaises(RuntimeError):m.verified(p, '0'*64)
            symbolic=Path(temporary)/'symbolic';symbolic.symlink_to(p)
            with self.assertRaises(RuntimeError):m.verified(symbolic, hashlib.sha256(p.read_bytes()).hexdigest())
            cache=Path(temporary)/'cache';cache.write_text('59\n')
            with patch.object(m, 'CACHE', cache):
                self.assertEqual(m.cached_temperature(0),59)
                with self.assertRaises(RuntimeError):m.cached_temperature(cache.stat().st_mtime_ns+1)
                cache.write_text('not a temperature')
                with self.assertRaises(RuntimeError):m.cached_temperature(0)

    def fixture(self, folder):
        work=folder/'handover';work.mkdir(); active=folder/'import-active';active.write_text('remaining jobs held')
        source=folder/'collector';source.write_text('retained collector source')
        job=folder/'omv-job';job.write_text('retained generated OMV job')
        cache=folder/'cache';report=folder/'hba-review.json'
        collector_sha=hashlib.sha256(source.read_bytes()).hexdigest();job_sha=hashlib.sha256(job.read_bytes()).hexdigest()
        report.write_text(json.dumps({'collectorSha256':collector_sha,'relatedUnits':{}}))
        acceptance=folder/'application-acceptance.json';acceptance.write_text(json.dumps({'format':'accepted','phase':'complete','cutoverId':'current'}))
        calls=[];held=[False]
        @contextlib.contextmanager
        def lock(native):
            held[0]=True
            try:yield
            finally:held[0]=False
        def run(*args,**kwargs):
            self.assertFalse(held[0]);calls.append(args)
            if args[:2]==('systemctl','start'):cache.write_text('59\n')
            return ''
        def atomic(path, value, **kwargs):path.write_bytes(value if isinstance(value,bytes) else json.dumps(value).encode())
        native=SimpleNamespace(ACTIVE=active,read=lambda p:p.read_bytes(),safe=lambda p:None,atomic=atomic,run=run)
        rows={'plex-nas':{'unchanged':True}}
        accepted=SimpleNamespace(STATE=acceptance,FORMAT='accepted',snapshot=lambda boot,old,current:current.copy())
        boot=SimpleNamespace(boot_lock=lock)
        backup=SimpleNamespace(preflight=lambda native:({'proof':{'cutoverId':'current'}},rows.copy()),unit=lambda native,name:{'ActiveState':'active'})
        inspected=SimpleNamespace(WORK=folder)
        args=(inspected,accepted,None,None,None,boot,backup,native,None)
        patches={'WORK':work,'STATE':work/'state.json','SELF':work/'worker.py','COLLECTOR':source,'COLLECTOR_SHA':collector_sha,
            'OMV_JOB':job,'OMV_JOB_SHA':job_sha,'CACHE':cache,'SERVICE':folder/'bridge.service','TIMER':folder/'bridge.timer'}
        return args,patches,calls,source,job,cache,active

    def test_full_handover_keeps_cron_apps_and_sources_and_starts_timer_outside_backup_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            args,values,calls,source,job,cache,active=self.fixture(Path(temporary));original={p:p.read_bytes() for p in (source,job,active)}
            def scheduled(_seconds):
                stamp=cache.stat().st_mtime_ns+1_000_000;cache.write_text('60\n');os.utime(cache,ns=(stamp,stamp))
            with contextlib.ExitStack() as stack:
                for key,value in values.items():stack.enter_context(patch.object(m,key,value))
                stack.enter_context(patch.object(m,'cron_state',return_value='inactive'))
                stack.enter_context(patch.object(m.time,'sleep',side_effect=scheduled))
                m.worker(*args)
            self.assertEqual({p:p.read_bytes() for p in original},original)
            self.assertEqual(calls,[('systemctl','daemon-reload'),('systemctl','enable','--now','bridge.timer'),('systemctl','start','bridge.service')])
            state=json.loads(values['STATE'].read_bytes());self.assertEqual(state['phase'],'complete');self.assertTrue(state['twoFreshReadingsVerified'])
            self.assertEqual(state['temperatureC'],60)

    def test_foreign_unit_is_retained_before_any_unit_activation(self):
        with tempfile.TemporaryDirectory() as temporary:
            args,values,calls,source,job,cache,active=self.fixture(Path(temporary));values['SERVICE'].write_text('foreign unit')
            with contextlib.ExitStack() as stack:
                for key,value in values.items():stack.enter_context(patch.object(m,key,value))
                stack.enter_context(patch.object(m,'cron_state',return_value='inactive'))
                with self.assertRaisesRegex(RuntimeError,'different existing'):m.worker(*args)
            self.assertEqual(values['SERVICE'].read_text(),'foreign unit');self.assertEqual(calls,[])


if __name__=='__main__':unittest.main()
