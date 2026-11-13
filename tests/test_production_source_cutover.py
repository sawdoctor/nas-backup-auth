"""Source hold/rollback publication boundaries with no host or Docker access."""
import base64
import contextlib
import copy
import datetime as dt
import hashlib
import hmac
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('cutover', ROOT/'scripts/source-production-cutover.py')
s = importlib.util.module_from_spec(spec); spec.loader.exec_module(s)

def receipt(state, now=1000, **changes):
    payload = {'cutoverId': state['cutoverId'], 'stoppedAt': now,
               'action': 'nas-production-stopped', 'allImportedWritersStopped': True, **changes}
    raw = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')+'.'+hmac.new(bytes.fromhex(state['receiptKey']),raw,hashlib.sha256).hexdigest()

class SourceCutover(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name); self.base = self.root/'controls'; self.base.mkdir()
        self.units = self.root/'units'; self.units.mkdir()
        self.output = self.root/'export'
        self.hold = self.base/'hold.json'; self.plan = self.base/'plan.json'
        for name,value in {'BASE':self.base,'UNITS':self.units,'OUTPUT':self.output,'HOLD':self.hold,
                           'PLAN':self.plan,'WORKER':self.base/'worker.py',
                           'BOOT':self.units/'nas-production-cutover-recover.service'}.items():
            p=patch.object(s,name,value); p.start(); self.addCleanup(p.stop)
        self.state = {'format':s.FORMAT,'cutoverId':'20261113T140000Z-'+'a'*16,'receiptKey':'b'*64,
                      'identitySha256':'identity','units':['docker.service','docker.socket','cron.service'],
                      'roots':{'plex-config':{'source':str(self.root/'live-plex')}}}

    def guards(self):
        for name in self.state['units']:
            path=self.units/(name+'.d')/s.DROPIN; path.parent.mkdir(exist_ok=True)
            path.write_text(s.CONDITION)

    def test_receipt_requires_current_operation_all_writers_stopped_and_freshness(self):
        s.validate_receipt(receipt(self.state),self.state,now=1100)
        for token in (receipt(self.state,cutoverId='another'), receipt(self.state,allImportedWritersStopped=False),
                      receipt(self.state,action='plex-only-stopped'), receipt(self.state)+'changed'):
            with self.subTest(token=token[-20:]),self.assertRaises(RuntimeError):s.validate_receipt(token,self.state,now=1100)
        with self.assertRaises(RuntimeError):s.validate_receipt(receipt(self.state),self.state,now=1601)

    def test_published_source_cannot_resume_without_stopped_nas_proof(self):
        state={**self.state,'published':True,'phase':'published'}
        with patch.object(s,'helpers',return_value=(None,None)),patch.object(s,'run') as run,self.assertRaises(RuntimeError):
            s.restore(state)
        run.assert_not_called()

    def test_private_start_permission_requires_guarded_inactive_docker_socket_and_cron(self):
        self.guards(); archive=s.archive_for(self.state); archive.parent.mkdir(parents=True); archive.write_bytes(b'final')
        state={**self.state,'published':True,'phase':'published','ready':{'archiveBytes':5,'archiveSha256':'digest'}}
        s.atomic(self.hold,state)
        trial=SimpleNamespace(unit_state=lambda _: {'ActiveState':'inactive','MainPID':'0'},
                              port_open=lambda _:False, identity=lambda _:'identity')
        with patch.object(s,'helpers',return_value=(None,trial)):
            self.assertTrue(s.status_private()['held'])
            trial.unit_state=lambda name:{'ActiveState':'active' if name=='docker.socket' else 'inactive','MainPID':'0'}
            self.assertFalse(s.status_private()['held'])
            trial.unit_state=lambda _:{'ActiveState':'inactive','MainPID':'0'}
            (self.units/'cron.service.d'/s.DROPIN).unlink()
            self.assertFalse(s.status_private()['held'])

    def test_unpublished_capture_never_exposes_a_start_permission_or_secret(self):
        state={**self.state,'phase':'holding','published':False}
        s.atomic(self.hold,state)
        trial=SimpleNamespace(unit_state=lambda _: {'ActiveState':'inactive','MainPID':'0'})
        with patch.object(s,'helpers',return_value=(None,trial)):
            self.assertEqual(s.status_private(),{'format':s.FORMAT,'held':False})

    def test_reader_grants_only_two_fixed_read_operations_and_retains_old_routes(self):
        old=b'#!/bin/sh\ncase "$SSH_ORIGINAL_COMMAND" in\n existing) exit 0;;\nesac\n'
        new=s.reader_text(old)
        self.assertIn(old.split(b'\n',1)[1],new)
        self.assertEqual(s.reader_text(new),new)
        permission=s.reader_permission()
        self.assertIn('--status-private',permission);self.assertIn('--archive',permission)
        for action in ('--hold','--resume','--abort','--recover'):
            self.assertNotIn(action,permission)

    def test_previous_final_archives_are_separate_and_paths_are_fenced(self):
        first=s.archive_for(self.state)
        second=s.archive_for({**self.state,'cutoverId':'20261114T140000Z-'+'c'*16})
        self.assertNotEqual(first,second)
        with self.assertRaises(RuntimeError):s.archive_for({**self.state,'cutoverId':'../../production'})

    def test_wrong_approved_plan_hash_cannot_run_a_stop_command(self):
        self.plan.write_text('{}')
        with patch.object(s,'helpers',return_value=(None,None)),patch.object(s,'locks',return_value=contextlib.nullcontext()), \
                patch.object(s,'run') as run,self.assertRaises(RuntimeError):s.hold('a'*64)
        run.assert_not_called()

    def test_interrupted_unpublished_guard_install_can_restore_without_nested_backup_lock(self):
        path=self.units/'docker.service.d'/s.DROPIN;path.parent.mkdir();path.write_text(s.CONDITION)
        state={**self.state,'published':False,'phase':'holding',
               'containers':{'plex':{'Id':'plex-id','State':{'Running':True}}},
               'catalog':{'plex':{'Id':'plex-id','State':{'Running':True}}},
               'unitStates':{'cron.service':{'ActiveState':'active'}}}
        s.atomic(self.hold,state)
        engine=SimpleNamespace()
        engine.record=lambda value:s.atomic(engine.STATE,value)
        resumed=[]
        def resume(e,catalog,backup_locked=False):
            self.assertTrue(backup_locked)
            self.assertEqual(json.loads(e.STATE.read_bytes())['format'],'nightly-format')
            resumed.append('plex');e.STATE.unlink()
        nightly=SimpleNamespace(FORMAT='nightly-format',LIVE_STATIC=set(),
                                source_engine=lambda *args:engine,resume_source_clients=resume)
        trial=SimpleNamespace(wait_api=lambda *args:None)
        with patch.object(s,'helpers',return_value=(nightly,trial)),patch.object(s,'run') as run,contextlib.redirect_stdout(io.StringIO()):
            s.restore(state)
        self.assertEqual(resumed,['plex'])
        self.assertFalse(self.hold.exists());self.assertFalse(path.exists())
        self.assertTrue((self.base/('returned-'+state['cutoverId']+'.json')).exists())
        self.assertIn(('systemctl','start','cron.service'),[call.args for call in run.call_args_list])

    def test_final_copy_uses_current_stopped_plex_and_includes_source_image_metadata(self):
        work=self.root/'nightly-work';work.mkdir();(work/'.standby-owner').write_text('nightly-format')
        seed=self.root/'old-private-plex';seed.mkdir();(seed/'stale-history').write_text('old')
        live=self.root/'live-plex'; db=live/'Library/Application Support/Plex Media Server/Plug-in Support/Databases/com.plexapp.plugins.library.db'
        db.parent.mkdir(parents=True);db.write_bytes(b'current watch history and library')
        roots={'plex-config':{'source':str(live),'snapshot':'data/plex-config','kind':'directory'}}
        def row(name):return {'Name':'/'+name,'Id':name+'-id','Image':name+'-image','Mounts':[],
                             'Config':{'Image':name+':original'},'HostConfig':{'RestartPolicy':{'Name':'unless-stopped'}},'State':{'Running':True}}
        rows={n:row(n) for n in ('plex','npm-app-1')}
        worker=self.base/'worker.py';worker.write_bytes(b'controller')
        reader=self.base/'reader';reader.write_bytes(b'fixed reader')
        images=[{'Id':'plex-image','RootFS':{'Layers':['verified-layer']}}]
        plan={**self.state,'preparedUtc':dt.datetime.now(dt.timezone.utc).isoformat(),'roots':roots,
              'workerSha256':s.sha(worker.read_bytes()),'readerSha256':s.sha(reader.read_bytes()),'helperHashes':{},
              'fingerprints':{n:s.fingerprint(r) for n,r in rows.items()},'sourceImages':images}
        s.atomic(self.plan,plan)
        native={'running':set(rows),'docker':True}
        def run(*args,**kwargs):
            if args[:2]==('systemctl','stop') and 'docker.service' in args:native['docker']=False
            if args[:2]==('docker','stop'):native['running'].discard(args[-1].removesuffix('-id'))
            if args==('docker','ps','-q'):return '\n'.join(native['running'])
            if args[0]=='rsync':shutil.copytree(live,Path(args[-1].rstrip('/')),dirs_exist_ok=True)
            if args[0]=='bash':(work/'SHA256SUMS').write_text('checksummed frozen files')
            if args[0]=='tar':Path(args[args.index('-cpf')+1]).write_bytes(b'final-archive:'+db.read_bytes())
            return ''
        def unit_state(name):return {'ActiveState':'active' if native['docker'] and name in ('docker.service','docker.socket') else 'inactive','MainPID':'0'}
        trial=SimpleNamespace(check_cron=lambda:None,assert_idle=lambda:None,session_count=lambda _:0,
                              port_open=lambda _:False,unit_state=unit_state,identity=lambda _:'identity')
        nightly=SimpleNamespace(APP_NAMES=tuple(rows),FORMAT='nightly-format',copy_roots=lambda *a,**kw:None,
                                digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest())
        out=io.StringIO()
        with patch.object(s,'helpers',return_value=(nightly,trial)),patch.object(s,'locks',return_value=contextlib.nullcontext()), \
                patch.object(s,'WORK',work),patch.object(s,'SEED',seed),patch.object(s,'READER',reader), \
                patch.object(s,'all_containers',return_value=copy.deepcopy(rows)), \
                patch.object(s,'controlled_units',return_value=self.state['units']),patch.object(s,'run',side_effect=run), \
                contextlib.redirect_stdout(out):s.hold(s.sha(self.plan.read_bytes()))
        manifest=json.loads((work/'manifest.json').read_bytes())
        state=json.loads(self.hold.read_bytes())
        self.assertTrue(state['published']);self.assertEqual(state['phase'],'published')
        self.assertTrue(manifest['plexConfigIncluded']);self.assertEqual(manifest['images'],images)
        self.assertEqual(manifest['livePlexDatabaseSha256']['main'],hashlib.sha256(db.read_bytes()).hexdigest())
        self.assertNotIn(state['receiptKey'],out.getvalue())
        self.assertFalse(native['docker'])
        self.assertTrue((seed/'stale-history').exists())
        self.assertTrue(s.archive_for(state).is_file())

if __name__=='__main__':unittest.main()
