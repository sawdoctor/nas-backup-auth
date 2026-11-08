import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import yaml

ROOT=Path(__file__).resolve().parents[1]
SCRIPTS=ROOT/'scripts'
if not SCRIPTS.is_dir(): SCRIPTS=ROOT/'nas-backup-auth/scripts'


def load(name,filename):
    spec=importlib.util.spec_from_file_location(name,SCRIPTS/filename)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result)
    return result


s=load('current_npm_prepare','prepare-nas-current-npm.py')
source=load('current_npm_source','export-optiplex-npm-refresh.py')
routes=load('current_npm_routes','prepare-nas-npm-routes.py')
private=load('current_npm_private','test-nas-npm-proxy.py')
complete=load('current_npm_complete','prepare-nas-npm-cutover.py')


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.export=self.root/'export';self.export.mkdir()
        self.payload=self.export/'payload';self.payload.mkdir();self.data=self.payload/'data';self.data.mkdir()
        self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(routes,'KEEP_SOURCE',{k:v for k,v in routes.KEEP_SOURCE.items() if k not in ('soundspan','chaptarr')}))
        self.database=self.data/'database.sqlite'
        with contextlib.closing(sqlite3.connect(self.database)) as db,db:
            db.execute('CREATE TABLE proxy_host(id INTEGER PRIMARY KEY,domain_names,forward_scheme,forward_host,forward_port,enabled,is_deleted,certificate_id,access_list_id,advanced_config)')
            db.execute('CREATE TABLE certificate(id INTEGER PRIMARY KEY,is_deleted,provider,private_secret)')
            for table in ('access_list','user','redirection_host','dead_host','stream'):
                db.execute('CREATE TABLE '+table+'(id INTEGER PRIMARY KEY,is_deleted,private_secret)')
            identity=0
            for name,(_,port) in routes.TARGETS.items():
                identity+=1
                db.execute('INSERT INTO proxy_host VALUES(?,?,?,?,?,1,0,?,5,?)',
                    (identity,json.dumps([name+'.sawdoctor.uk']),'http','usenet-ultimate' if name=='usenet' else '192.168.0.29',port,
                     86 if name=='shelfmark-audio' else 6,'PRIVATE_CUSTOM'))
            for name,(scheme,port) in routes.EXISTING_NAS.items():
                identity+=1
                db.execute('INSERT INTO proxy_host VALUES(?,?,?,?,?,1,0,6,5,?)',
                           (identity,json.dumps([name+'.sawdoctor.uk']),scheme,'192.168.0.220',port,'PRIVATE_CUSTOM'))
            for name,port in routes.KEEP_SOURCE.items():
                identity+=1
                db.execute('INSERT INTO proxy_host VALUES(?,?,?,?,?,1,0,6,5,?)',
                           (identity,json.dumps([name+'.sawdoctor.uk']),'http','192.168.0.29',port,'PRIVATE_CUSTOM'))
            for identity,name in ((50,'soundspan'),(51,'chaptarr')):
                db.execute('INSERT INTO proxy_host VALUES(?,?,?,?,?,0,1,6,5,?)',
                           (identity,json.dumps([name+'.sawdoctor.uk']),'http','192.168.0.29',1,'PRIVATE_DELETED'))
            db.executemany('INSERT INTO certificate VALUES(?,0,"letsencrypt",?)',[(6,'PRIVATE_CERT'),(86,'PRIVATE_NEW_CERT')])
            db.execute('INSERT INTO access_list VALUES(5,0,?)',('PRIVATE_ACL_HASH',))
            db.execute('INSERT INTO user VALUES(1,0,?)',('PRIVATE_LOGIN_HASH',))
        (self.data/'keys.json').write_text('{"private":"PRIVATE_SIGNING_KEY"}')
        custom=self.data/'custom';custom.write_text('PRIVATE_CUSTOM_FILE');custom.chmod(0o640)
        os.setxattr(custom,'user.keep',b'PRIVATE_XATTR')
        (self.data/'custom-link').symlink_to('custom')
        self.certificates=self.payload/'letsencrypt'
        archive=self.certificates/'archive/npm-6';archive.mkdir(parents=True)
        cert,key=archive/'fullchain1.pem',archive/'privkey1.pem'
        subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-days','1',
                        '-subj','/CN=*.sawdoctor.uk','-addext','subjectAltName=DNS:*.sawdoctor.uk','-out',str(cert),'-keyout',str(key)],
                        check=True,capture_output=True)
        for identity in (6,86):
            live=self.certificates/('live/npm-'+str(identity));live.mkdir(parents=True)
            for filename in ('fullchain','privkey'):
                (live/(filename+'.pem')).symlink_to('../../archive/npm-6/'+filename+'1.pem')
        self.stack.enter_context(patch.object(source,'CA_FILE',str(cert)))
        counts,shelfmark,checked=source.validate_policy(self.database,self.payload)
        self.manifest={'format':s.EXPORT_FORMAT,'createdUtc':time.strftime('%Y%m%dT%H%M%SZ',time.gmtime()),
            'sourceHost':'192.168.0.29','sourceStopped':False,'container':{'Image':source.SOURCE_IMAGE},
            'retiredDomains':s.RETIRED,'shelfmarkAudio':shelfmark,'counts':counts,'checkedCertificateKeyPairs':checked,
            'databaseSha256':source.sha(self.database)}
        self.expected=source.inventory(self.payload)
        (self.export/'manifest.json').write_text(json.dumps(self.manifest))
        (self.export/'payload-inventory.json').write_text(json.dumps(self.expected))
        self.archive=self.root/'export.tar.gz'
        subprocess.run(['tar','--acls','--xattrs','--numeric-owner','-czpf',str(self.archive),'-C',str(self.export),
                        'manifest.json','payload-inventory.json','payload'],check=True,capture_output=True)
        self.ready={'format':s.EXPORT_FORMAT,'createdUtc':self.manifest['createdUtc'],
            'archiveBytes':self.archive.stat().st_size,'payloadBytes':self.expected['bytes'],
            'archiveSha256':source.sha(self.archive),'manifestSha256':source.sha(self.export/'manifest.json'),
            'inventorySha256':source.sha(self.export/'payload-inventory.json')}

    def extract(self):
        s.validate_archive(self.archive)
        destination=self.root/'extracted';destination.mkdir()
        subprocess.run(['tar','--acls','--xattrs','--xattrs-include=*','--numeric-owner','--delay-directory-restore',
                        '-xzpf',str(self.archive),'-C',str(destination)],check=True,capture_output=True)
        return destination

    def test_real_export_extraction_validates_all_source_metadata_and_certificates(self):
        extracted=self.extract()
        # Trust the extracted copy of the same test CA to avoid fixture path coupling.
        with patch.object(source,'CA_FILE',str(extracted/'payload/letsencrypt/archive/npm-6/fullchain1.pem')):
            self.assertEqual(s.validate_export(extracted,self.ready,source),self.manifest)
        self.assertEqual(os.getxattr(extracted/'payload/data/custom','user.keep'),b'PRIVATE_XATTR')
        self.assertEqual(os.readlink(extracted/'payload/data/custom-link'),'custom')

    def test_only_21_upstream_fields_change_and_source_private_state_stays_exact(self):
        before=self.database.read_bytes();extracted=self.extract()
        changes=s.edit_upstreams(extracted,routes)
        self.assertEqual(len(changes),21)
        self.assertEqual(self.database.read_bytes(),before)
        self.assertEqual((extracted/'source-database.sqlite').read_bytes(),before)
        with contextlib.closing(sqlite3.connect(extracted/'payload/data/database.sqlite')) as db:
            self.assertEqual(db.execute('SELECT private_secret FROM user').fetchone()[0],'PRIVATE_LOGIN_HASH')
            self.assertEqual(db.execute('SELECT count(*) FROM proxy_host WHERE is_deleted=0').fetchone()[0],28)
            self.assertEqual(db.execute('SELECT count(*) FROM proxy_host WHERE is_deleted=0 AND forward_host="192.168.0.220"').fetchone()[0],24)
            self.assertEqual(db.execute('SELECT count(*) FROM proxy_host WHERE is_deleted=1').fetchone()[0],2)
        self.assertEqual((extracted/'payload/data/keys.json').read_bytes(),(self.data/'keys.json').read_bytes())
        self.assertEqual((extracted/'payload/data/custom').read_bytes(),(self.data/'custom').read_bytes())

    def test_changed_private_file_and_wrong_shelfmark_report_stop_before_edits(self):
        extracted=self.extract();(extracted/'payload/data/custom').write_text('TAMPERED')
        with self.assertRaisesRegex(RuntimeError,'source inventory'):
            s.validate_export(extracted,self.ready,source)
        self.manifest['shelfmarkAudio']['certificateId']=73
        (self.export/'manifest.json').write_text(json.dumps(self.manifest))
        changed={**self.ready,'manifestSha256':source.sha(self.export/'manifest.json')}
        with self.assertRaisesRegex(RuntimeError,'certificate report'):
            s.validate_export(self.export,changed,source)

    def test_metadata_diagnostic_preserves_strict_failure_and_keeps_private_paths_out_of_journal(self):
        extracted=self.extract();private=extracted/'payload/data/custom'
        private.chmod(0o600)
        os.setxattr(private,'user.PRIVATE_ATTRIBUTE_NAME',b'PRIVATE_ATTRIBUTE_VALUE')
        report=self.root/'diagnostic.json'
        output=io.StringIO()
        with contextlib.redirect_stdout(output):
            with self.assertRaisesRegex(RuntimeError,'source inventory'):
                s.validate_export(extracted,self.ready,source,report)
        saved=json.loads(report.read_text())
        self.assertEqual(saved['summary']['differingFields'],{'mode':1,'xattrs':1})
        self.assertEqual(saved['summary']['sourceBytes'],saved['summary']['extractedBytes'])
        self.assertEqual(saved['details'][0]['path'],'data/custom')
        self.assertEqual(report.stat().st_mode & 0o777,0o600)
        self.assertNotIn('PRIVATE_',output.getvalue())
        self.assertNotIn('data/custom',output.getvalue())
        self.assertNotIn('PRIVATE_CUSTOM_FILE',report.read_text())

    def test_diagnostic_distinguishes_missing_files_content_and_timestamp_changes(self):
        before={'bytes':3,'entries':{'PRIVATE_PATH':{'kind':'file','size':3,'sha256':'a','mtimeNs':100,'xattrs':{}},
                                   'PRIVATE_MISSING':{'kind':'file','size':0}}}
        after={'bytes':3,'entries':{'PRIVATE_PATH':{'kind':'file','size':3,'sha256':'b','mtimeNs':125,'xattrs':{}},
                                   'PRIVATE_ADDED':{'kind':'file','size':0}}}
        summary,details=s.inventory_difference(before,after)
        self.assertEqual(summary['differingFields'],{'additional-entry':1,'missing-entry':1,'mtimeNs':1,'sha256':1})
        self.assertEqual(summary['mtimeDeltaNsRange'],[25,25])
        self.assertNotIn('PRIVATE_',json.dumps(summary))
        self.assertEqual(len(details),3)

    def test_small_nonempty_archive_is_allowed_but_zero_stale_or_future_is_rejected(self):
        self.assertLess(self.ready['archiveBytes'],1024**2)
        s.validate_ready(self.ready)
        for changed in ({'archiveBytes':0},{'createdUtc':'20200101T000000Z'},{'createdUtc':'20990101T000000Z'}):
            with self.assertRaises(RuntimeError): s.validate_ready({**self.ready,**changed})

    def test_stream_transfer_checks_exact_size_and_sha(self):
        command=[sys.executable,'-c','import pathlib,sys;sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes())',str(self.archive)]
        destination=self.root/'received.tar.gz'
        s.receive_archive(command,destination,self.ready)
        self.assertEqual(destination.read_bytes(),self.archive.read_bytes())
        with self.assertRaisesRegex(RuntimeError,'published size'):
            s.receive_archive(command,destination,{**self.ready,'archiveBytes':10})
        with self.assertRaisesRegex(RuntimeError,'SHA256'):
            s.receive_archive(command,destination,{**self.ready,'archiveSha256':'0'*64})

    def prepare_environment(self):
        binary=os.environ.get('NPM_COMPOSE_BINARY')
        if not binary: self.skipTest('Native Compose parser required for full offline preparation test.')
        app,backup=self.root/'app',self.root/'backup';app.mkdir();backup.mkdir()
        live=app/'appdata/npm/data/database.sqlite';live.parent.mkdir(parents=True)
        with contextlib.closing(sqlite3.connect(live)) as db,db:
            for table in ('proxy_host','certificate','access_list','dead_host','redirection_host','stream'):
                db.execute('CREATE TABLE '+table+'(id,is_deleted)')
        lock=self.root/'backup.lock';lock.touch()
        model={'name':'npm-nas','services':{'npm':{'container_name':'npm-nas','image':'jc21/nginx-proxy-manager:latest',
            'environment':{'PRIVATE':'SECRET_$$value'},'restart':'unless-stopped',
            'volumes':[{'type':'bind','source':str(live.parent),'target':'/data'},
                       {'type':'bind','source':str(app/'appdata/npm/letsencrypt'),'target':'/etc/letsencrypt'}],
            'ports':[{'target':port,'published':str(host),'host_ip':'192.168.0.220','protocol':'tcp','mode':'ingress'}
                     for port,host in ((80,10080),(81,10081),(443,10443))],
            'networks':{'default':None}}},'networks':{'default':{'name':'npm-nas_default'}}}
        host=app/'stack.yaml';host.write_text(yaml.safe_dump(model))
        stored={'text':host.read_text(),'env':'','path':'/app/data/stacks/npm-nas/docker-compose.yml'}
        restore=load('current_test_restore','prepare-nas-npm.py')
        self.current= {'Name':'/npm-nas','Id':'original-npm-id','Image':'verified-image','State':{'Status':'running','StartedAt':'original-time'},
            'HostConfig':{'PortBindings':restore.PORTS},'Mounts':[{'Destination':'/data','Type':'bind','Source':str(live.parent)}],
            'Config':{'Env':['PRIVATE=SECRET_$value'],'Labels':{}}}
        self.calls=[]
        def query(*args,**kw):
            self.calls.append(args)
            if args[0]=='ip': return 'inet 192.168.0.220/24'
            if args[0]=='findmnt': return (routes.APP_UUID if args[3]==str(app) else routes.BACKUP_UUID)+' ext4\n'
            if args[0]=='ss': return 'LISTEN 0 4096 192.168.0.220:3091 0.0.0.0:*\n'
            if args[:2]==('docker','inspect'):
                items=[]
                for name in args[2:]:
                    if name=='npm-nas':items.append(self.current);continue
                    ports={str(port)+'/tcp':[{'HostIp':'192.168.0.220','HostPort':str(port)}]
                           for container,port in routes.TARGETS.values() if container==name}
                    items.append({'Name':'/'+name,'State':{'Status':'running'},'HostConfig':{
                        'NetworkMode':'host' if name=='fail2ban-ui' else 'bridge','PortBindings':ports}})
                return json.dumps(items)
            raise AssertionError('Unapproved host mutation/query: '+repr(args))
        def compose(*args,**kw):
            self.assertEqual(args[:2],('docker','compose'))
            self.assertIn('config',args)
            result=subprocess.run([binary,*args[2:]],capture_output=True,check=True,timeout=30)
            return result.stdout.decode()
        class TestKey:
            parents=()
            def __str__(self):return '/test/private/key'
            def is_symlink(self):return False
            def is_file(self):return True
            def stat(self):return SimpleNamespace(st_uid=0,st_mode=0o100600)
        self.stack.enter_context(patch.multiple(routes,APP=app,BACKUP=backup,LOCK=lock))
        self.stack.enter_context(patch.object(routes,'run',side_effect=query))
        self.stack.enter_context(patch.object(routes,'mounted'))
        self.stack.enter_context(patch.object(s.os,'geteuid',return_value=0))
        self.stack.enter_context(patch.object(s,'KEY',TestKey()))
        self.stack.enter_context(patch.object(complete,'live_stack',return_value=(stored,host,model)))
        self.stack.enter_context(patch.object(restore,'all_containers',return_value=[]))
        self.stack.enter_context(patch.object(restore,'run',side_effect=compose))
        self.ready_reader=self.stack.enter_context(patch.object(s,'read_ready',return_value=self.ready))
        self.receiver=self.stack.enter_context(patch.object(s,'receive_archive',side_effect=lambda ssh,path,ready:path.write_bytes(self.archive.read_bytes())))
        self.messages=self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        old=app/'compose/npm-restore/cutover';old.mkdir(parents=True);(old/'earlier').write_text('PRESERVE_EARLIER_CANDIDATE')
        return restore,app,live,host,old

    def test_full_offline_preparation_and_retry_keep_live_and_earlier_candidate_unchanged(self):
        restore,app,live,host,old=self.prepare_environment()
        originals=[p.read_bytes() for p in (live,host,old/'earlier')]
        s.prepare(source,complete,private,routes,restore)
        root=app/'compose/npm-restore/cutover-current'
        self.assertEqual({p.name for p in root.iterdir()},s.CONTENTS)
        record=json.loads((root/'prepared.json').read_text())
        self.assertEqual(record['counts']['proxy_host'],28)
        self.assertEqual(len(record['changes']),21)
        self.assertEqual(record['shelfmarkAudio']['certificateId'],86)
        self.assertEqual([p.read_bytes() for p in (live,host,old/'earlier')],originals)
        self.assertFalse(list(root.parent.glob('.npm-current-*')))
        s.prepare(source,complete,private,routes,restore)
        self.receiver.assert_called_once()
        self.assertNotIn('PRIVATE_',self.messages.getvalue())
        self.assertFalse(any('restart' in call or 'stop' in call for call in self.calls))
        (root/'payload/data/custom').write_text('EDITED_CANDIDATE')
        with self.assertRaisesRegex(RuntimeError,'retained for review'):
            s.prepare(source,complete,private,routes,restore)
        self.assertEqual((root/'payload/data/custom').read_text(),'EDITED_CANDIDATE')

    def test_source_export_changed_after_receiving_does_not_publish_candidate(self):
        restore,app,live,host,old=self.prepare_environment()
        self.ready_reader.side_effect=[self.ready,{**self.ready,'archiveSha256':'0'*64}]
        before=live.read_bytes()
        with self.assertRaisesRegex(RuntimeError,'changed during transfer'):
            s.prepare(source,complete,private,routes,restore)
        self.assertFalse((app/'compose/npm-restore/cutover-current').exists())
        self.assertEqual(live.read_bytes(),before)
        self.assertEqual((old/'earlier').read_text(),'PRESERVE_EARLIER_CANDIDATE')


class ArchiveAttackTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)

    def write_archive(self,items):
        path=self.root/'unsafe.tar.gz'
        with tarfile.open(path,'w:gz') as out:
            for item in items:
                data=b'{}' if item.isfile() else b''
                item.size=len(data);out.addfile(item,io.BytesIO(data) if item.isfile() else None)
        return path

    def test_traversal_link_pivots_chain_special_files_and_metadata_links_are_rejected(self):
        def entry(name,kind=tarfile.REGTYPE,target=''):
            item=tarfile.TarInfo(name);item.type=kind;item.linkname=target;return item
        base=[entry('manifest.json'),entry('payload-inventory.json'),entry('payload',tarfile.DIRTYPE)]
        attacks=[
            [entry('../outside')], [entry('/absolute')],
            [entry('payload/link',tarfile.SYMTYPE,'../../outside')],
            [entry('payload/link',tarfile.SYMTYPE,'/etc'),entry('payload/link/private')],
            [entry('payload/fifo',tarfile.FIFOTYPE)],
            [entry('payload/a',tarfile.SYMTYPE,'b'),entry('payload/b',tarfile.SYMTYPE,'a')],
            [entry('payload/file'),entry('payload/link',tarfile.SYMTYPE,'file'),entry('payload/link/child')],
            [entry('payload/hard',tarfile.LNKTYPE,'/outside')],
            [entry('manifest.json',tarfile.SYMTYPE,'payload/file')],
        ]
        for extra in attacks:
            with self.subTest(names=[x.name for x in extra]):
                with self.assertRaises(RuntimeError): s.validate_archive(self.write_archive(base+extra))


class NativeComposeTests(unittest.TestCase):
    def test_runtime_dollars_and_native_parser_keep_current_environment_and_reject_port_changes(self):
        binary=os.environ.get('NPM_COMPOSE_BINARY')
        if not binary: self.skipTest('Set NPM_COMPOSE_BINARY for the native parser regression.')
        with tempfile.TemporaryDirectory() as directory:
            model={'services':{'npm':{'image':'existing','environment':{'PRIVATE':'SECRET_$$value'},
                'labels':{'custom':'LABEL_$$value'},'command':['sh','-c','echo $$value'],
                'ports':[{'target':80,'published':'10080','host_ip':'192.168.0.220','protocol':'tcp','mode':'ingress'}],
                'volumes':[{'type':'bind','source':directory,'target':'/data','bind':{'create_host_path':False}}],
                'networks':{'default':None}}},'networks':{'default':{'name':'npm-nas_default'}}}
            config={'Config':{'Env':['PRIVATE=SECRET_$value'],'Labels':{'custom':'LABEL_$value'},'Cmd':['sh','-c','echo $value']}}
            before=copy.deepcopy(model);wanted=s.runtime_values(model,config)
            self.assertEqual(model,before)
            self.assertEqual(wanted['services']['npm']['environment']['PRIVATE'],'SECRET_$value')
            path=Path(directory)/'test.yaml';path.write_text(yaml.safe_dump(complete.escaped(wanted)))
            result=subprocess.run([binary,'-p','npm-nas','-f',str(path),'config','--format','json'],check=True,capture_output=True)
            rendered=json.loads(result.stdout)
            private.validate_compose(wanted,rendered,complete.escaped)
            rendered['services']['npm']['ports'][0]['published']='80'
            with self.assertRaisesRegex(RuntimeError,'ports'):
                private.validate_compose(wanted,rendered,complete.escaped)


if __name__=='__main__': unittest.main()
