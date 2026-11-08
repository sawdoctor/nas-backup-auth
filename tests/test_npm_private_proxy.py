import contextlib
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import json
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
        current = {'Image':'sha256:verified', 'NetworkSettings':{'Networks':{'npm-nas_default':{}}}}
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
