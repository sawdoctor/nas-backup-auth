import contextlib
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'scripts'
if not SCRIPTS.is_dir():
    SCRIPTS = ROOT / 'nas-backup-auth/scripts'
spec = importlib.util.spec_from_file_location('npm_private_proxy', SCRIPTS / 'test-nas-npm-proxy.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


class GuardAndCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_real_node_worker_cannot_start_timers_issue_or_renew(self):
        fixture = ('let timers=0, calls=0; const logger={info:()=>{}}; '
                   'const setInterval=()=>{timers++;};\nconst internalCertificate={\n' + s.TIMER + '\n'
                   '\tcreate: async (access, data) => {\n calls++;\n },\n'
                   '\trenew: async (access, data) => {\n calls++;\n },\n'
                   '\tprocessExpiringHosts:()=>{calls++;}\n};\n').encode()
        with patch.object(s, 'CERT_SHA', hashlib.sha256(fixture).hexdigest()):
            held = s.hold_certificate_worker(fixture)
        check = b'''
internalCertificate.initTimer();
for (const op of ['create','renew']) {
 let blocked=false;
 try { await internalCertificate[op]({},{}); }
 catch(e) { blocked=e.code==='NAS_NPM_TRIAL_CERT_HOLD'; }
 if (!blocked) throw Error('Certificate operation was not blocked');
}
if (calls!==0 || timers!==0) throw Error('Certificate side effect occurred');
'''
        subprocess.run(['node', '--input-type=module'], input=held + check, check=True, capture_output=True)
        with self.assertRaisesRegex(RuntimeError, 'differs from the reviewed'):
            s.hold_certificate_worker(fixture)
        subprocess.run(['node', '--input-type=module', '--check'], input=s.RENDER.encode(), check=True, capture_output=True)

    def test_trial_model_preserves_original_and_uses_only_disposable_binds(self):
        model = {'services': {'npm': {'container_name':'npm-nas', 'image':'existing-tag',
                    'environment':{'PRIVATE':'secret_$value'}, 'ports':['existing'],
                    'volumes':[{'type':'bind','source':'/immutable/data','target':'/data'},
                               {'type':'bind','source':'/immutable/certs','target':'/etc/letsencrypt'}],
                    'networks':{'default':None}}}, 'networks':{'default':{'name':'npm-nas_default'}}}
        before = copy.deepcopy(model)
        current = {'Image':'sha256:verified', 'NetworkSettings':{'Networks':{'npm-nas_default':{}}},
                   'Config':{'Env':['PRIVATE=secret_$value'],'Labels':{}}}
        trial = s.trial_model(model, current, self.root, self.root / 'guard.js')
        self.assertEqual(model, before)
        service = trial['services']['npm']
        self.assertEqual(service['image'], 'sha256:verified')
        self.assertEqual(service['environment'], before['services']['npm']['environment'])
        self.assertTrue(all(p['host_ip']=='127.0.0.1' for p in service['ports']))
        self.assertTrue(all(Path(m['source']).is_relative_to(self.root) for m in service['volumes']))
        self.assertTrue(service['volumes'][-1]['read_only'])
        self.assertEqual(trial['networks']['default'], {'external':True,'name':'npm-nas_default'})

    def test_cleanup_removes_only_owned_container_by_id_and_its_copy(self):
        folder = self.root / 'copy'; folder.mkdir()
        (folder / 'private').write_text('private data')
        (self.root / 'trial.yaml').write_text('definition')
        owner = {'Id':'owned-container-id','Config':{'Labels':{s.LABEL:'token'}}}
        with patch.object(s, 'inspect', side_effect=[owner, None]), patch.object(s, 'command') as command, patch.object(s, 'ERROR_LOG', None):
            s.cleanup_trial('token', folder, self.root)
        self.assertEqual(command.call_args.args, ('docker','rm','-f','owned-container-id'))
        self.assertFalse(folder.exists())
        self.assertFalse((self.root / 'trial.yaml').exists())

    def test_foreign_container_and_daemon_failure_preserve_working_copy(self):
        folder = self.root / 'copy'; folder.mkdir()
        other = {'Id':'foreign','Config':{'Labels':{s.LABEL:'other-token'}}}
        with patch.object(s, 'inspect', return_value=other), patch.object(s, 'command') as command:
            with self.assertRaisesRegex(RuntimeError, 'unrelated'):
                s.cleanup_trial('token', folder, self.root)
        command.assert_not_called()
        self.assertTrue(folder.exists())
        error = subprocess.CompletedProcess([], 1, b'', b'Cannot connect to the Docker daemon')
        with patch.object(s.subprocess, 'run', return_value=error):
            with self.assertRaisesRegex(RuntimeError, 'Docker inspection failed'):
                s.inspect(s.NAME)

    def test_real_sqlite_routes_reject_reintroduced_soundspan(self):
        path = self.root / 'database.sqlite'
        with contextlib.closing(sqlite3.connect(path)) as db, db:
            db.execute('CREATE TABLE proxy_host(id,domain_names,forward_host,forward_port,access_list_id,is_deleted,enabled)')
            db.executemany('INSERT INTO proxy_host VALUES(?,?,?,?,?,0,1)',
                           [(i,json.dumps([f'app-{i}.sawdoctor.uk']),'192.168.0.220',8000+i,0) for i in range(1,30)])
        self.assertEqual(len(s.routes_in(path)),29)
        with contextlib.closing(sqlite3.connect(path)) as db, db:
            db.execute('UPDATE proxy_host SET domain_names=? WHERE id=1', ('["soundspan.sawdoctor.uk"]',))
        with self.assertRaisesRegex(RuntimeError, 'unexpected private-test route'):
            s.routes_in(path)


class ComposeRoundTripTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        spec=importlib.util.spec_from_file_location('candidate_helpers',SCRIPTS/'prepare-nas-npm-cutover.py')
        self.complete=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.complete)
        self.model={'name':'npm-nas','services':{'npm':{'container_name':'npm-nas','image':'existing',
            'environment':{'PRIVATE':'SECRET_$$value'},'labels':{'private-label':'LABEL_$$literal'},
            'command':['sh','-c','echo $$value'],
            'volumes':[{'type':'bind','source':'/original/data','target':'/data','bind':{'create_host_path':False}},
                       {'type':'bind','source':'/original/certs','target':'/etc/letsencrypt','bind':{'create_host_path':False}}],
            'networks':{'default':None}}},'networks':{'default':{'name':'npm-nas_default'}}}
        self.current={'Image':'sha256:'+'a'*64,'NetworkSettings':{'Networks':{'npm-nas_default':{}}},
            'Config':{'Env':['PRIVATE=SECRET_$value'],'Labels':{'private-label':'LABEL_$literal'},
                      'Cmd':['sh','-c','echo $value']}}
        self.wanted=s.trial_model(self.model,self.current,self.root,self.root/'guard.js')

    def test_known_defaults_allowed_but_all_material_changes_rejected(self):
        rendered=self.complete.escaped(self.wanted)
        service=rendered['services']['npm']
        service['entrypoint']=None
        for mount in service['volumes']:
            del mount['bind']['create_host_path']
        rendered['networks']['default']['ipam']={}
        s.validate_compose(self.wanted,rendered,self.complete.escaped)
        variants=[]
        for field,value in [('image','other-image'),('privileged',True),('command',['changed'])]:
            item=copy.deepcopy(rendered);item['services']['npm'][field]=value;variants.append(item)
        for field,value in [('host_ip','0.0.0.0'),('published','443')]:
            item=copy.deepcopy(rendered);item['services']['npm']['ports'][0][field]=value;variants.append(item)
        for field,value in [('read_only',False),('source','/production/certificate.js')]:
            item=copy.deepcopy(rendered);item['services']['npm']['volumes'][2][field]=value;variants.append(item)
        item=copy.deepcopy(rendered);item['services']['npm']['volumes'][0]['bind']['create_host_path']=True;variants.append(item)
        item=copy.deepcopy(rendered);item['networks']['default']['external']=False;variants.append(item)
        item=copy.deepcopy(rendered);item['services']['npm']['environment']['PRIVATE']='OTHER_SECRET';variants.append(item)
        for item in variants:
            with self.assertRaisesRegex(RuntimeError,'round trip differs') as error:
                s.validate_compose(self.wanted,item,self.complete.escaped)
            self.assertNotIn('SECRET',str(error.exception))

    def test_native_compose_default_normalization_and_dollars(self):
        binary=os.environ.get('NPM_COMPOSE_BINARY')
        if not binary:
            self.skipTest('Set NPM_COMPOSE_BINARY to run the native Compose parser regression.')
        import yaml
        path=self.root/'trial.yaml'
        path.write_text(yaml.safe_dump(self.complete.escaped(self.wanted),sort_keys=False))
        result=subprocess.run([binary,'-p','nas-npm-private-test','-f',str(path),'config','--format','json'],
                              capture_output=True,text=True,check=True,timeout=25)
        rendered=json.loads(result.stdout)
        s.validate_compose(self.wanted,rendered,self.complete.escaped)
        self.assertEqual(self.wanted['services']['npm']['environment']['PRIVATE'],'SECRET_$value')
        self.assertEqual(rendered['services']['npm']['environment']['PRIVATE'],'SECRET_$$value')


class UsenetDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.log=self.root/'data/logs/proxy-host-2_error.log'
        self.log.parent.mkdir(parents=True)
        self.row={'id':2,'domain':'usenet.sawdoctor.uk','upstream':'192.168.0.220','port':1337,'accessList':0}

    def test_only_new_errors_are_summarized_without_secrets(self):
        self.log.write_text('OLD_ERROR_SECRET upstream timed out\n')
        offset=s.error_log_offset(self.root)
        with self.log.open('a') as out:
            out.write('usenet-ultimate could not be resolved, request: /api?apikey=NEW_SECRET\n')
            out.write('connect() failed, upstream: http://192.168.0.220:1337/?token=OTHER_SECRET\n')
        private=self.root/'private-error.log'
        with patch.object(s,'ERROR_LOG',private):
            summaries,end=s.fresh_usenet_errors(self.root,offset)
        self.assertEqual(end,self.log.stat().st_size)
        self.assertEqual(summaries[0]['categories'],['dns-resolution'])
        self.assertTrue(summaries[0]['referencesOriginalDockerName'])
        self.assertTrue(summaries[1]['referencesNasIp'])
        self.assertNotIn('SECRET',json.dumps(summaries))
        self.assertNotIn('OLD_ERROR_SECRET',private.read_text())
        self.assertEqual(private.stat().st_mode & 0o777,0o600)
        with patch.object(s,'ERROR_LOG',None):
            self.assertEqual(s.fresh_usenet_errors(self.root,end),([],end))

    def test_retry_preserves_initial_failure_and_separate_new_errors(self):
        self.log.write_text('old unrelated error\n')
        offset=s.error_log_offset(self.root)
        calls=[]
        def request(row,folder):
            calls.append(row)
            if len(calls)==1:
                with self.log.open('a') as out:
                    out.write('usenet-ultimate could not be resolved, private=SECRET\n')
            status=502 if len(calls)==1 else 200
            return {**row,'httpStatus':status,'curlExit':0,'responseReceivedWithTrustedTls':True,'needsAttention':status>=500}
        with patch.object(s,'request_route',side_effect=request),patch.object(s.time,'sleep') as sleep,patch.object(s,'ERROR_LOG',None),patch.object(s,'say') as say:
            report=s.diagnose_usenet(self.row,self.root,offset)
        sleep.assert_called_once_with(2)
        self.assertEqual(len(calls),2)
        self.assertEqual([r['httpStatus'] for r in report['attempts']],[502,200])
        self.assertTrue(report['attempts'][0]['needsAttention'])
        self.assertFalse(report['needsAttention'])
        self.assertEqual(report['attempts'][1]['newNginxErrors'],[])
        self.assertNotIn('SECRET',str(say.call_args_list))

    def test_foreign_route_and_linked_log_are_rejected(self):
        with patch.object(s,'request_route') as request:
            with self.assertRaisesRegex(RuntimeError,'identity differs'):
                s.diagnose_usenet({**self.row,'domain':'other.sawdoctor.uk'},self.root,0)
        request.assert_not_called()
        target=self.root/'foreign';target.write_text('PRIVATE')
        self.log.symlink_to(target)
        with self.assertRaisesRegex(RuntimeError,'not a regular file'):
            s.error_log_offset(self.root)


class ReloadReadinessTests(unittest.TestCase):
    def test_real_linux_process_title_and_start_time_identify_worker_generation(self):
        process=subprocess.Popen(['node','-e',"process.title='nginx: worker process';console.log(process.pid);setInterval(()=>{},1000);"],
                                 stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
        try:
            pid=process.stdout.readline().strip()
            self.assertTrue(pid.isdigit())
            script=("import fs from 'node:fs';\n"+s.WORKER_READINESS+
                    "const workers=nginxWorkers();if(![...workers].some(value=>value.startsWith(process.argv[1]+':'))) throw Error('Real worker identity missing');")
            subprocess.run(['node','--input-type=module','-e',script,pid],capture_output=True,check=True,timeout=10)
        finally:
            process.kill();process.wait();process.stdout.close()

    def test_old_and_new_workers_must_not_overlap_and_timeout_is_enforced(self):
        script="import fs from 'node:fs';\n"+s.WORKER_READINESS+r'''
const before=new Set(['10:100']);
let reads=0,pauses=0;
await waitForNginxWorkers(before,{read:()=>[new Set(['10:100']),new Set(['10:100','11:110']),new Set(['11:110'])][reads++],pause:async()=>{pauses++;}});
if(reads!==3 || pauses!==2) throw Error('Old generation accepted too early');
let now=0,blocked=false;
try {await waitForNginxWorkers(before,{read:()=>before,now:()=>now++,timeoutMs:4,pause:async()=>{}});}
catch(error){blocked=error.message.includes('readiness bound');}
if(!blocked) throw Error('Stuck old worker was accepted');
blocked=false;
try {await waitForNginxWorkers(new Set());} catch(error){blocked=true;}
if(!blocked) throw Error('Missing baseline accepted');
'''
        subprocess.run(['node','--input-type=module'],input=script.encode(),capture_output=True,check=True,timeout=10)
        subprocess.run(['node','--input-type=module','--check'],input=s.render_code(True).encode(),capture_output=True,check=True,timeout=10)
        self.assertIn('expectedRouteCount = 28',s.render_code(True))
        self.assertIn('chaptarr.sawdoctor.uk',s.render_code(True))
        self.assertNotIn('expectedRouteCount = 28',s.render_code(False))

    def test_current_route_list_rejects_retired_chaptarr(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'database.sqlite'
            with contextlib.closing(sqlite3.connect(path)) as db,db:
                db.execute('CREATE TABLE proxy_host(id,domain_names,forward_host,forward_port,access_list_id,is_deleted,enabled)')
                db.executemany('INSERT INTO proxy_host VALUES(?,?,?,?,?,0,1)',
                    [(i,json.dumps([f'app-{i}.sawdoctor.uk']),'192.168.0.220',8000+i,0) for i in range(1,29)])
            self.assertEqual(len(s.routes_in(path,current=True)),28)
            with contextlib.closing(sqlite3.connect(path)) as db,db:
                db.execute('UPDATE proxy_host SET domain_names=? WHERE id=1',('["chaptarr.sawdoctor.uk"]',))
            with self.assertRaisesRegex(RuntimeError,'unexpected private-test route'):
                s.routes_in(path,current=True)


class CurrentCandidateValidationTests(unittest.TestCase):
    def setUp(self):
        path=Path(__file__).with_name('test_npm_current_prepare.py')
        spec=importlib.util.spec_from_file_location('current_candidate_fixture',path)
        self.fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.fixture)
        self.case=self.fixture.CandidateTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.restore,self.app,self.live,self.host,self.old=self.case.prepare_environment()
        self.fixture.s.prepare(self.fixture.source,self.fixture.complete,self.fixture.private,self.fixture.routes,self.restore)
        self.root=self.app/'compose/npm-restore/cutover-current'
        self.record=json.loads((self.root/'prepared.json').read_text())

    def verify(self,record=None):
        return s.validate_current_candidate(self.root,record or self.record,self.case.current,self.fixture.s,self.fixture.source,
                                            self.fixture.complete,self.fixture.routes,self.restore)

    def test_real_current_candidate_source_policy_certificates_and_runtime_identity_pass(self):
        before=self.live.read_bytes()
        identity=self.verify()
        self.assertEqual(set(identity),self.fixture.s.CONTENTS-{'payload'})
        self.assertEqual(len(s.routes_in(self.root/'payload/data/database.sqlite',current=True)),28)
        self.assertEqual(self.live.read_bytes(),before)
        self.assertEqual((self.old/'earlier').read_text(),'PRESERVE_EARLIER_CANDIDATE')

    def test_changed_original_metadata_or_runtime_stack_are_rejected(self):
        with self.assertRaisesRegex(RuntimeError,'live NAS stack changed'):
            self.verify({**self.record,'existingStackSha256':'0'*64})
        (self.root/'source-inventory.json').write_text('{}')
        with self.assertRaisesRegex(RuntimeError,'preserved current source'):
            self.verify()


class StrictHttpsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        cert, key = self.root / 'cert.pem', self.root / 'key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1',
                        '-nodes','-subj','/CN=test.sawdoctor.uk','-addext','subjectAltName=DNS:test.sawdoctor.uk',
                        '-days','1','-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
        class Handler(BaseHTTPRequestHandler):
            status = 401
            def do_GET(self):
                self.send_response(self.status)
                if self.status==401: self.send_header('WWW-Authenticate','Basic realm="fixture"')
                if self.status==302: self.send_header('Location','https://would-leak.example/private')
                self.send_header('Content-Length',str(len(b'PRIVATE_RESPONSE_BODY')))
                self.end_headers()
                self.wfile.write(b'PRIVATE_RESPONSE_BODY')
            def log_message(self,*args): pass
        self.handler=Handler
        class Server(HTTPServer):
            def handle_error(self,request,client_address): pass
        self.server=Server(('127.0.0.1',0),Handler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert,key)
        self.server.socket=context.wrap_socket(self.server.socket,server_side=True)
        thread=threading.Thread(target=self.server.serve_forever,daemon=True);thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(s,'CA_FILE',str(cert)))
        self.stack.enter_context(patch.object(s,'PORTS',{**s.PORTS,'443/tcp':str(self.server.server_port)}))
        self.row={'id':1,'domain':'test.sawdoctor.uk','upstream':'192.168.0.220','port':1,'accessList':5}

    def test_trusted_tls_and_real_http_auth_challenge(self):
        report=s.request_route(self.row,self.root)
        self.assertTrue(report['responseReceivedWithTrustedTls'])
        self.assertEqual(report['httpStatus'],401)
        self.assertTrue(report['httpAuthChallenge'])
        self.assertFalse(report['needsAttention'])
        self.assertFalse(list(self.root.glob('headers-*')))
        self.assertNotIn('PRIVATE_RESPONSE_BODY',json.dumps(report))

    def test_wrong_tls_hostname_fails_without_insecure_fallback(self):
        report=s.request_route({**self.row,'domain':'wrong.sawdoctor.uk'},self.root)
        self.assertEqual(report['curlExit'],60)
        self.assertFalse(report['responseReceivedWithTrustedTls'])
        self.assertTrue(report['needsAttention'])

    def test_mixed_case_saved_domain_still_connects_only_to_loopback(self):
        report=s.request_route({**self.row,'domain':'TEST.sawdoctor.uk'},self.root)
        self.assertEqual(report['curlExit'],0)
        self.assertEqual(report['httpStatus'],401)
        self.assertEqual(report['domain'],'TEST.sawdoctor.uk')

    def test_redirect_does_not_follow_public_production_destination(self):
        self.handler.status=302
        report=s.request_route(self.row,self.root)
        self.assertEqual(report['httpStatus'],302)
        self.assertEqual(report['curlExit'],0)
        self.assertTrue(report['responseReceivedWithTrustedTls'])


if __name__=='__main__':
    unittest.main()
