"""Resume only pending Speedtest; never weaken real DNS/storage/version checks."""
import contextlib
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path); value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
m=load('resume_controls','scripts/resume-nas-reviewed-application-controls.py')
old=load('restore_controls','scripts/restore-nas-reviewed-application-controls.py')
review=load('compare_controls','scripts/inspect-nas-original-application-controls.py')
boot=load('boot_controls','scripts/restore-nas-production-boot-ownership.py')

def runtime(name,identity='a'*64,values=None):
    return {'Name':'/'+name,'Id':identity,'Image':'sha256:'+'1'*64,'State':{'Running':True,'StartedAt':'retained','Health':{'Status':'healthy'}},
        'Config':{'Image':'current:latest','Env':[key+'='+value for key,value in (values or {}).items()], 'Hostname':identity[:12],
          'Labels':{'com.docker.compose.project':'support','com.docker.compose.service':name},'User':'1000','Cmd':['app']},
        'HostConfig':{'NetworkMode':'media-core','RestartPolicy':{'Name':'unless-stopped','MaximumRetryCount':0},'Dns':None,'DnsOptions':None,'DnsSearch':None,'Privileged':False},
        'Mounts':[{'Type':'bind','Source':'/current/data','Destination':'/data','RW':True,'Propagation':'rprivate'}],
        'NetworkSettings':{'Networks':{'media-core':{'NetworkID':'net-current','Aliases':[name]}}}}

class ApplicationControlsResumeTests(unittest.TestCase):
    def pair(self):
        before=runtime('wizarr-nas',values={'FLASK_SKIP_SCHEDULER':'true','WIZARR_DISABLE_SCHEDULER':'true','SECRET':'retained'})
        after=copy.deepcopy(before);after['Id']='b'*64;after['Config']['Hostname']='b'*12;after['Config']['Env']=['SECRET=retained']
        for field in m.DNS:after['HostConfig'][field]=[]
        return before,after,{'image':'current:latest','environment':{'SECRET':'retained'}},{'Config':{'Env':[]}}

    def test_only_empty_dns_and_generated_hostname_are_normalized(self):
        before,after,definition,image=self.pair(); snapshot=copy.deepcopy(before)
        self.assertEqual(m.validate_runtime(old,before,after,definition,image),list(m.DNS))
        self.assertEqual(before,snapshot)
        for field in m.DNS:
            a,b=copy.deepcopy(before),copy.deepcopy(after);a['HostConfig'][field]=['custom'];b['HostConfig'][field]=['custom']
            m.validate_runtime(old,a,b,definition,image)

    def test_real_dns_and_other_runtime_drift_are_not_waived(self):
        before,after,definition,image=self.pair()
        changes=[lambda row:row['HostConfig'].update(Dns=['1.1.1.1']),lambda row:row['HostConfig'].update(DnsOptions=['timeout:2']),
                 lambda row:row['HostConfig'].update(DnsSearch=['example.org']),lambda row:row['HostConfig'].update(Privileged=True),
                 lambda row:row.update(Image='sha256:other'),lambda row:row['Mounts'][0].update(RW=False),
                 lambda row:row['Config'].update(Env=['SECRET=changed']),lambda row:row['Config'].update(Hostname='custom-unreviewed')]
        for change in changes:
            with self.subTest(change=change):
                row=copy.deepcopy(after);change(row)
                with self.assertRaises(RuntimeError):m.validate_runtime(old,before,row,definition,image)

    def fixture(self,folder,custom_dns=False):
        work=folder/'app/compose/production-cutover/application-control-handover';work.mkdir(parents=True)
        before,wizarr,definition,image=self.pair()
        if custom_dns:wizarr['HostConfig']['Dns']=['1.1.1.1']
        current={'wizarr-nas':wizarr,'houndarr-nas':runtime('houndarr-nas'),'speedtest-tracker-nas':runtime('speedtest-tracker-nas',values={'SPEEDTEST_SCHEDULE':''}),
                 'plex-nas':runtime('plex-nas')}
        live=work/'prepared.yaml';live.write_bytes(b'current reviewed scheduler definition')
        prior=work/'before.yaml';prior.write_bytes(b'previous scheduler definition')
        candidate=work/'candidate.yaml';candidate.write_bytes(live.read_bytes())
        for name in ('wizarr-nas','speedtest-tracker-nas'):
            current[name]['Config']['Labels'].update({'com.docker.compose.project.config_files':str(live),'com.docker.compose.project.working_dir':str(work)})
        before['Config']['Labels'].update({'com.docker.compose.project':'legacy-support','com.docker.compose.service':'wizarr',
            'com.docker.compose.project.config_files':'/legacy/compose.json','com.docker.compose.project.working_dir':'/legacy'})
        database=work/'houndarr.db'
        with sqlite3.connect(database) as db:
            db.execute('CREATE TABLE instances(id INTEGER,url TEXT,enabled INTEGER,missing_enabled INTEGER,cutoff_enabled INTEGER,upgrade_enabled INTEGER,encrypted_api_key TEXT)')
            db.executemany('INSERT INTO instances VALUES(?,?,1,1,0,0,?)',[(1,'http://radarr:7878','CIPHER1'),(2,'http://radarr4k:7878','CIPHER2'),(3,'http://sonarr:8989','CIPHER3')])
        baseline=folder/'backup/backups/sets'/m.BASELINE_SET/'containers.json';baseline.parent.mkdir(parents=True);baseline.write_text(json.dumps([before]))
        original=work/'state.json'; original.write_text(json.dumps({'format':old.FORMAT,'cutoverId':'current','phase':'needs-review',
            'completed':['houndarr-nas'],'files':[{'path':str(live),'before':str(prior),'prepared':str(candidate),
                'beforeSha256':hashlib.sha256(prior.read_bytes()).hexdigest(),'afterSha256':hashlib.sha256(live.read_bytes()).hexdigest()}],
            'images':{name:current[name]['Image'] for name in old.NAMES}}))
        active=work/'import-active';active.write_text('remaining jobs held')
        calls=[]
        def run(*args,**kwargs):
            calls.append(args)
            if args[:3]==('docker','image','inspect'):return json.dumps([image])
            if args[:2]==('docker','compose'):
                row=copy.deepcopy(current['speedtest-tracker-nas']);row['Id']='c'*64;row['Config']['Hostname']='c'*12;row['Config']['Env']=['SPEEDTEST_SCHEDULE=30 4 * * *']
                for field in m.DNS:row['HostConfig'][field]=[]
                current['speedtest-tracker-nas']=row;return ''
            return 'ActiveState=inactive\nResult=success\nConditionResult=yes\n'
        def atomic(path,value,**kwargs):path.write_bytes(value if isinstance(value,bytes) else json.dumps(value).encode())
        native=SimpleNamespace(APP=folder/'app',BACKUP=folder/'backup',ACTIVE=active,catalog=lambda:copy.deepcopy(current),run=run,
            read=lambda path,*args:path.read_bytes(),digest=lambda path:hashlib.sha256(path.read_bytes()).hexdigest(),atomic=atomic)
        fake_old=SimpleNamespace(**{key:getattr(old,key) for key in ('FORMAT','ENV','env','mounts','networks','expected_environment','houndarr_rows','check_houndarr')},
            STATE=original,UNIT='old.service',reviewed_report=lambda native,main:{'results':{}},wait_http=lambda native,name,port:copy.deepcopy(current[name]))
        fake_review=SimpleNamespace(database=review.database,arr_identity=review.arr_identity,flag=review.flag,current_database=lambda row,relative,native:database)
        fake_boot=SimpleNamespace(boot_lock=lambda native:contextlib.nullcontext(),runtime_signature=boot.runtime_signature)
        backup=SimpleNamespace(BACKUP=folder/'backup',preflight=lambda native:({'proof':{'cutoverId':'current'}},copy.deepcopy(current)))
        definition['container_name']='wizarr-nas'
        model={'services':{'wizarr-nas':definition,'speedtest-tracker-nas':{'container_name':'speedtest-tracker-nas','image':'current:latest','environment':{'SPEEDTEST_SCHEDULE':'30 4 * * *'}}}}
        startup=SimpleNamespace(compose_context=lambda row:{'project':'support','directory':work,'files':(work/'prepared.yaml',)},
            compose_model=lambda native,context:copy.deepcopy(model),service_for=lambda model,row:row['Name'].lstrip('/'),local_image=lambda reference:before['Image'])
        return work,database,original,current,calls,(fake_old,fake_review,fake_boot,backup,native,startup)

    def test_full_resume_keeps_completed_apps_and_recreates_speedtest_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            work,db,original,current,calls,args=self.fixture(Path(temporary)); before=copy.deepcopy(current); database_bytes=db.read_bytes()
            with patch.object(m,'WORK',work),patch.object(m,'STATE',work/'resume-state.json'),patch.object(m,'kuma_inventory',return_value=[]),patch.object(m.subprocess,'run'):
                m.worker(*args);m.worker(*args)
            compose=[call for call in calls if call[:2]==('docker','compose')]
            self.assertEqual(len(compose),1);self.assertEqual(compose[0][-1],'speedtest-tracker-nas')
            for field in ('--no-deps','never','--no-build'):self.assertIn(field,compose[0])
            self.assertEqual(db.read_bytes(),database_bytes)
            for name in ('houndarr-nas','wizarr-nas','plex-nas'):self.assertEqual(current[name],before[name])
            self.assertEqual(json.loads(original.read_bytes())['phase'],'complete')
            self.assertEqual(json.loads((work/'resume-state.json').read_bytes())['phase'],'complete')
            self.assertFalse(any(call[:2] in (('docker','start'),('docker','stop'),('docker','restart')) for call in calls))

    def test_active_ownership_is_checked_against_the_recorded_current_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            work,db,original,current,calls,args=self.fixture(Path(temporary))
            fake_old,fake_review,fake_boot,backup,native,startup=args
            record=json.loads(original.read_bytes())
            task=m.task_for(native,startup,current,'wizarr-nas',current['wizarr-nas']['Image'])
            owner=m.verified_current_owner(native,task,record)
            saved=json.loads((backup.BACKUP/'backups/sets'/m.BASELINE_SET/'containers.json').read_bytes())[0]
            with self.assertRaisesRegex(RuntimeError,'Compose owner'):
                m.validate_runtime(fake_old,saved,current['wizarr-nas'],task['definition'],task['imageInfo'])
            m.validate_runtime(fake_old,saved,current['wizarr-nas'],task['definition'],task['imageInfo'],owner)
            unknown=copy.deepcopy(task);unknown['context']['files']=(work/'unrecorded.yaml',)
            with self.assertRaisesRegex(RuntimeError,'outside the recorded'):
                m.verified_current_owner(native,unknown,record)
            wrong=copy.deepcopy(current['wizarr-nas']);wrong['Config']['Labels']['com.docker.compose.service']='unrelated'
            with self.assertRaisesRegex(RuntimeError,'com.docker.compose.service'):
                m.validate_runtime(fake_old,saved,wrong,task['definition'],task['imageInfo'],owner)
            duplicate=copy.deepcopy(task);duplicate['model']['services']['duplicate']=duplicate['definition']
            with self.assertRaisesRegex(RuntimeError,'uniquely own'):
                m.verified_current_owner(native,duplicate,record)

    def test_installer_replaces_only_the_unprogressed_exact_previous_worker(self):
        with tempfile.TemporaryDirectory() as temporary:
            work=Path(temporary);path=work/'resume.py';state=work/'resume-state.json';previous=b'pinned previous resume';path.write_bytes(previous)
            native=SimpleNamespace(read=lambda path:path.read_bytes(),atomic=lambda path,value,**kwargs:path.write_bytes(value))
            with patch.object(m,'WORK',work),patch.object(m,'SELF',path),patch.object(m,'STATE',state),patch.object(m,'PREVIOUS_RESUME_SHA',hashlib.sha256(previous).hexdigest()):
                m.install_resume(native,'new reviewed resume')
                self.assertEqual(path.read_bytes(),b'new reviewed resume');self.assertEqual((work/'resume-before-owner-fix.py').read_bytes(),previous)
                path.write_bytes(b'unrecognized worker')
                with self.assertRaisesRegex(RuntimeError,'different or already-progressed'):m.install_resume(native,'new reviewed resume')
                self.assertEqual(path.read_bytes(),b'unrecognized worker')
                path.write_bytes(previous);state.write_bytes(b'progress retained')
                with self.assertRaisesRegex(RuntimeError,'different or already-progressed'):m.install_resume(native,'new reviewed resume')
                self.assertEqual(path.read_bytes(),previous)

    def test_custom_dns_stops_before_any_pending_recreation(self):
        with tempfile.TemporaryDirectory() as temporary:
            work,db,original,current,calls,args=self.fixture(Path(temporary),True); before=original.read_bytes()
            with patch.object(m,'WORK',work),patch.object(m,'STATE',work/'resume-state.json'),self.assertRaisesRegex(RuntimeError,'Dns'):
                m.worker(*args)
            self.assertFalse(any(call[:2]==('docker','compose') for call in calls))
            self.assertEqual(original.read_bytes(),before);self.assertFalse((work/'resume-state.json').exists())

    def test_changed_live_prepared_definition_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);before=root/'before';prepared=root/'prepared';live=root/'live'
            before.write_bytes(b'before');prepared.write_bytes(b'prepared');live.write_bytes(b'user edit')
            native=SimpleNamespace(APP=root,digest=lambda path:hashlib.sha256(path.read_bytes()).hexdigest())
            record={'files':[{'before':str(before),'prepared':str(prepared),'path':str(live),
                'beforeSha256':hashlib.sha256(b'before').hexdigest(),'afterSha256':hashlib.sha256(b'prepared').hexdigest()}]}
            with self.assertRaises(RuntimeError):m.verify_prepared_files(native,record)
            self.assertEqual(live.read_bytes(),b'user edit')

    def test_full_kuma_inventory_exposes_old_host_and_docker_targets_without_url_secrets(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'kuma.db'
            with sqlite3.connect(path) as db:
                db.execute('CREATE TABLE monitor(id INTEGER,name TEXT,type TEXT,active INTEGER,url TEXT,hostname TEXT,port INTEGER,docker_container TEXT,docker_host INTEGER)')
                db.executemany('INSERT INTO monitor VALUES(?,?,?,?,?,?,?,?,?)',[
                    (2,'Usenet','http',0,'https://user:SECRET@usenet.example/private/SECRET?key=SECRET',None,None,None,None),
                    (10,'Old host ping','ping',0,None,'192.168.0.29',None,None,None),
                    (27,'Old Docker target','docker',0,None,None,None,'plex',1)])
            before=path.read_bytes()
            queries=SimpleNamespace(current_database=lambda *args:path,database=review.database,rows=review.rows,flag=review.flag)
            result=m.kuma_inventory(queries,None,{'uptime-kuma-nas':{}},{'results':{'uptime-kuma':{'sourceActiveMonitorIds':[2,27]}}})
            self.assertEqual(len(result),3);self.assertEqual(result[1]['hostname'],'192.168.0.29')
            self.assertEqual(result[2]['dockerContainer'],'plex');self.assertEqual(result[2]['dockerHostId'],1)
            self.assertNotIn('SECRET',json.dumps(result));self.assertEqual(result[0]['urlOrigin'],'https://usenet.example')
            self.assertEqual(path.read_bytes(),before)

if __name__=='__main__':unittest.main()
