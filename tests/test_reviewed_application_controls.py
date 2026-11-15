"""Scoped current-version schedule restoration and database failure recovery."""
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
import yaml

ROOT = Path(__file__).resolve().parents[1]
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
m = module('reviewed_controls', 'scripts/restore-nas-reviewed-application-controls.py')
r = module('original_controls', 'scripts/inspect-nas-original-application-controls.py')
s = module('startup_controls', 'scripts/reconcile-nas-production-startup-images.py')


def runtime(name='wizarr-nas', image='sha256:current', identity='a'*64, values=None):
    return {'Name':'/'+name, 'Id':identity, 'Image':image, 'State':{'Running':True},
        'Config':{'Image':'ghcr.io/wizarrrr/wizarr:latest', 'Env':[key+'='+value for key,value in (values or {}).items()],
                  'Hostname':identity[:12], 'Labels':{}, 'User':'1000', 'Cmd':['app']},
        'HostConfig':{'RestartPolicy':{'Name':'unless-stopped','MaximumRetryCount':0},'NetworkMode':'media-core'},
        'Mounts':[{'Type':'bind','Source':'/current/data','Destination':'/data','RW':True,'Propagation':'rprivate'}],
        'NetworkSettings':{'Networks':{'media-core':{'NetworkID':'net-current','Aliases':[name, name.removesuffix('-nas')]}}}}


class ReviewedControlsTests(unittest.TestCase):
    def test_environment_spans_preserve_other_fields_unicode_dollars_and_alias_refusal(self):
        for body in (b'''services:\n  wizarr:\n    image: current\n    environment:\n      FLASK_SKIP_SCHEDULER: 'true'\n      WIZARR_DISABLE_SCHEDULER: 'true'\n      SECRET: 'literal$$value'\n    volumes: ['/current:/data']\n''',
            b'''services: {wizarr: {image: current, environment: [FLASK_SKIP_SCHEDULER=true, WIZARR_DISABLE_SCHEDULER=true, SECRET=literal$$value], volumes: ['/current:/data']}}\n'''):
            result=m.patch_environment(body,'wizarr',m.ENV['wizarr-nas'],s)
            old=yaml.safe_load(body); new=yaml.safe_load(result)
            self.assertEqual(new['services']['wizarr']['image'],old['services']['wizarr']['image'])
            self.assertEqual(new['services']['wizarr']['volumes'],old['services']['wizarr']['volumes'])
            self.assertIn('literal$$value',result.decode())
            self.assertNotIn('FLASK_SKIP_SCHEDULER',result.decode())
        with self.assertRaises(RuntimeError):
            m.patch_environment(b'base: &env {FLAG: yes}\nservices: {wizarr: {environment: *env}}','wizarr',m.ENV['wizarr-nas'],s)

    def houndarr_fixture(self, folder, failing=False):
        path=folder/'houndarr.db'
        with sqlite3.connect(path) as db:
            db.executescript('''CREATE TABLE instances(id INTEGER PRIMARY KEY,url TEXT,enabled INTEGER,missing_enabled INTEGER,cutoff_enabled INTEGER,upgrade_enabled INTEGER,encrypted_api_key TEXT);
                CREATE TABLE history(id INTEGER, value TEXT); INSERT INTO history VALUES(1,'retain current history');''')
            db.executemany('INSERT INTO instances VALUES(?,?,1,0,0,0,?)',[(1,'http://radarr:7878','CIPHER1'),(2,'http://radarr4k:7878','CIPHER2'),(3,'http://sonarr:8989','CIPHER3')])
            if failing: db.execute("CREATE TRIGGER refuse_second BEFORE UPDATE ON instances WHEN old.id=2 BEGIN SELECT RAISE(ABORT,'refused'); END")
        return path

    def test_houndarr_missing_only_write_keeps_credentials_history_and_current_container(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder=Path(temporary); path=self.houndarr_fixture(folder); before=runtime('houndarr-nas'); commands=[]
            native=SimpleNamespace(run=lambda *args,**kwargs: commands.append(args))
            with patch.object(m,'WORK',folder),patch.object(m,'wait_http',return_value=copy.deepcopy(before)):
                m.restore_houndarr(r,native,before,path)
            with sqlite3.connect(path) as db:
                self.assertEqual(db.execute('SELECT enabled,missing_enabled,cutoff_enabled,upgrade_enabled FROM instances').fetchall(),[(1,1,0,0)]*3)
                self.assertEqual(db.execute('SELECT encrypted_api_key FROM instances').fetchall(),[('CIPHER1',),('CIPHER2',),('CIPHER3',)])
                self.assertEqual(db.execute('SELECT * FROM history').fetchall(),[(1,'retain current history')])
            self.assertEqual(commands,[('docker','stop','--time','30',before['Id']),('docker','start',before['Id'])])
            with sqlite3.connect(folder/'houndarr-before.sqlite') as db:
                self.assertEqual(db.execute('SELECT missing_enabled FROM instances').fetchall(),[(0,)]*3)

    def test_houndarr_sql_failure_rolls_back_and_starts_same_container(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder=Path(temporary); path=self.houndarr_fixture(folder,True); before=runtime('houndarr-nas'); commands=[]
            native=SimpleNamespace(run=lambda *args,**kwargs: commands.append(args))
            with patch.object(m,'WORK',folder), self.assertRaises(sqlite3.IntegrityError):
                m.restore_houndarr(r,native,before,path)
            self.assertEqual(commands[-1],('docker','start',before['Id']))
            with sqlite3.connect(path) as db: self.assertEqual(db.execute('SELECT missing_enabled FROM instances').fetchall(),[(0,)]*3)

    def test_prepare_retains_current_images_and_changes_only_two_selected_envs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); work=root/'work';work.mkdir(); path=root/'compose.yaml'
            doc={'services':{'wizarr':{'container_name':'wizarr-nas','image':'sha256:old-wizarr','environment':{'FLASK_SKIP_SCHEDULER':'true','WIZARR_DISABLE_SCHEDULER':'true','SECRET':'current-secret'},'volumes':['/current:/data']},
                'speedtest':{'container_name':'speedtest-tracker-nas','image':'sha256:old-speed','environment':{'SPEEDTEST_SCHEDULE':'','APP_KEY':'current-key'},'volumes':['/current-speed:/config']},
                'plex':{'image':'retain-plex','environment':{'UNCHANGED':'yes'}}}}
            path.write_text(yaml.safe_dump(doc)); context={'project':'support','files':(path,),'directory':root}
            current={'wizarr-nas':runtime(values={'FLASK_SKIP_SCHEDULER':'true','WIZARR_DISABLE_SCHEDULER':'true'}), 'speedtest-tracker-nas':runtime('speedtest-tracker-nas',values={'SPEEDTEST_SCHEDULE':''})}
            for name in m.ENV:
                current[name]['Config']['Env']=['FLASK_SKIP_SCHEDULER=true','WIZARR_DISABLE_SCHEDULER=true'] if name=='wizarr-nas' else ['SPEEDTEST_SCHEDULE=']
            def model(native,ctx,replacements=None): return yaml.safe_load((replacements or {}).get(path,path).read_text())
            startup=SimpleNamespace(compose_context=lambda row: context,compose_model=model,service_for=s.service_for,mapping_value=s.mapping_value,patch_images=s.patch_images)
            native=SimpleNamespace(read=lambda p,*args: p.read_bytes(),atomic=lambda p,value,**kwargs:p.write_bytes(value))
            refs={'wizarr-nas':'ghcr.io/wizarrrr/wizarr:latest','speedtest-tracker-nas':'lscr.io/linuxserver/speedtest-tracker:latest'}
            with patch.object(m,'WORK',work),patch.object(m,'image_reference',side_effect=lambda native,startup,row,original:(refs[row['Name'].lstrip('/')],{'Config':{'Env':[]}})):
                files,tasks=m.prepare(native,startup,current,{name.removesuffix('-nas'):{} for name in m.ENV})
            self.assertEqual(path.read_text(),yaml.safe_dump(doc))
            result=yaml.safe_load(Path(files[0]['prepared']).read_bytes())
            self.assertEqual(result['services']['plex'],doc['services']['plex'])
            self.assertEqual(result['services']['wizarr']['environment'],{'SECRET':'current-secret'})
            self.assertEqual(result['services']['speedtest']['environment'],{'SPEEDTEST_SCHEDULE':'30 4 * * *','APP_KEY':'current-key'})
            self.assertEqual(result['services']['wizarr']['image'],refs['wizarr-nas'])
            self.assertEqual(len(tasks),2)

    def test_recreate_is_current_image_no_pull_no_dependencies_and_retains_bindings(self):
        before=runtime(values={'FLASK_SKIP_SCHEDULER':'true','WIZARR_DISABLE_SCHEDULER':'true','SECRET':'current'})
        before['Config']['Hostname']='c'*12  # Auto hostname retained by an earlier manager recreation.
        after=copy.deepcopy(before);after['Id']='b'*64;after['Config']['Hostname']='b'*12;after['Config']['Env']=['SECRET=current']
        commands=[]; native=SimpleNamespace(run=lambda *args,**kwargs:commands.append(args))
        startup=SimpleNamespace(local_image=lambda reference: before['Image'])
        task={'name':'wizarr-nas','before':before,'context':{'project':'support','directory':Path('/current/project'),'files':(Path('/current/compose.yaml'),)},
              'service':'wizarr','definition':{'image':before['Config']['Image'],'environment':{'SECRET':'current'}},'imageInfo':{'Config':{'Env':[]}}}
        with patch.object(m,'wait_http',return_value=after): m.recreate(native,startup,task)
        self.assertEqual(commands[0][-1],'wizarr')
        for flag in ('--no-deps','never','--no-build'): self.assertIn(flag,commands[0])
        after['Image']='sha256:unexpected'
        with patch.object(m,'wait_http',return_value=after),self.assertRaises(RuntimeError):m.recreate(native,startup,task)

    def test_review_gate_rejects_blanket_upgrade_enables_and_unknown_schedule(self):
        report={'format':'sawdoctor-original-application-controls-v1','cutoverId':'current','results':{
            'houndarr':{'instances':[{'id':key,'application':app,'sameInstance':True,'source':dict(zip(m.FLAGS,(True,True,False,False)))} for key,app in ((1,'radarr'),(2,'radarr4k'),(3,'sonarr'))]},
            'wizarr':{'sourceEnvironment':{'FLASK_SKIP_SCHEDULER':'not set','WIZARR_DISABLE_SCHEDULER':'not set'},'currentEnvironment':{'FLASK_SKIP_SCHEDULER':'true','WIZARR_DISABLE_SCHEDULER':'true'},'sourceEnabledLdapIds':[],'currentEnabledLdapIds':[]},
            'speedtest-tracker':{'source':{'SPEEDTEST_SCHEDULE':'30 4 * * *'}}}}
        native=SimpleNamespace(read=lambda path:json.dumps(report).encode());main={'proof':{'cutoverId':'current'}}
        m.reviewed_report(native,main)
        report['results']['houndarr']['instances'][0]['source']['upgrade_enabled']=True
        with self.assertRaises(RuntimeError):m.reviewed_report(native,main)


if __name__ == '__main__': unittest.main()
