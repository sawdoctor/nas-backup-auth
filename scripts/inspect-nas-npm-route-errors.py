#!/usr/bin/env python3
"""Read only the three failed proxy routes; never print credentials or bodies."""
import contextlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
from urllib.parse import urlsplit

APP = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
TARGETS = (
    ('Usenet Ultimate', 'http://192.168.0.220:1337/', 'usenet.sawdoctor.uk'),
    ('Chaptarr', 'http://192.168.0.29:8789/', 'chaptarr.sawdoctor.uk'),
    ('Shelfmark Audio', 'http://192.168.0.220:8084/', 'shelfmark-audio.sawdoctor.uk'),
)


def safe_host(value):
    if not value:
        return None
    try:
        return urlsplit('//' + str(value)).hostname or '[hostname withheld]'
    except ValueError:
        return '[hostname withheld]'


def show(*args, stdin=None, timeout=15):
    try:
        p = subprocess.run(args, input=stdin, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print('Query timed out.', flush=True)
        return
    print(p.stdout.decode(errors='replace').strip(), flush=True)
    if p.returncode:
        print('Query exit:', p.returncode, flush=True)


def main():
    addresses = subprocess.check_output(['ip', '-4', 'addr', 'show'], text=True, timeout=10)
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in addresses or not APP.is_mount():
        raise SystemExit('STOP: run with sudo on the mounted NAS app SSD.')
    base = APP / 'compose/npm-restore'
    report = json.loads((base / 'proxy-test/result.json').read_text())
    if report.get('format') != 'sawdoctor-npm-private-proxy-test-v1':
        raise SystemExit('STOP: the saved proxy-test result differs.')
    print('Saved test errors:', flush=True)
    for row in report.get('routes', []):
        if row.get('needsAttention'):
            message = row.get('curlError', '').splitlines()
            print(json.dumps({'domain': row['domain'], 'upstream': row['upstream'], 'port': row['port'],
                              'http': row['httpStatus'], 'curlExit': row['curlExit'],
                              'tlsMessage': message[0][:400] if message else ''}), flush=True)
    print('\nReviewed candidate settings and old-host references:', flush=True)
    database = base / 'cutover/payload/data/database.sqlite'
    with contextlib.closing(sqlite3.connect(database.as_uri() + '?mode=ro&immutable=1', uri=True)) as db:
        for row in db.execute('SELECT id,domain_names,forward_scheme,forward_host,forward_port,locations,advanced_config '
                              'FROM proxy_host WHERE id IN (2,31,32) ORDER BY id'):
            locations = json.loads(row[5] or '[]') or []
            text = (row[6] or '') + (row[5] or '')
            safe = {'id': row[0], 'domains': json.loads(row[1]), 'scheme': row[2], 'host': safe_host(row[3]), 'port': row[4],
                    'customLocationCount': len(locations),
                    'customConfigReferences': [host for host in ('usenet-ultimate', '192.168.0.29', '192.168.0.220') if host in text]}
            safe['customLocations'] = [{'root': location.get('path') == '/', 'scheme': location.get('forward_scheme'),
                                       'host': safe_host(location.get('forward_host')), 'port': location.get('forward_port')}
                                      for location in locations]
            print(json.dumps(safe), flush=True)
    print('\nCurrent NAS Usenet container:', flush=True)
    show('docker', 'inspect', 'usenet-ultimate-nas', '--format',
         '{{.Name}} State={{.State.Status}} Health={{if .State.Health}}{{.State.Health.Status}}{{end}} Ports={{json .HostConfig.PortBindings}}')
    print('\nDirect upstream access from NAS (response bodies discarded):', flush=True)
    for name, url, host in TARGETS:
        print(name + ':', flush=True)
        show('curl', '--disable', '--silent', '--noproxy', '*', '--connect-timeout', '2', '--max-time', '4',
             '--header', 'Host: ' + host, '--output', '/dev/null', '--write-out', 'HTTP=%{http_code}\n', url, timeout=6)
    print('\nThe same targets from the existing NPM network:', flush=True)
    node = r'''
const http = require('http');
const targets = JSON.parse(process.argv[1]);
Promise.all(targets.map(([name,url,host]) => new Promise(resolve => {
  let done=false;
  function finish(result) { if(done) return; done=true; clearTimeout(timer); resolve({name,...result}); }
  const request=http.get(url,{headers:{Host:host}},response => {
    finish({http:response.statusCode}); response.destroy();
  });
  const timer=setTimeout(() => { request.destroy(); finish({error:'TIMEOUT'}); },3000);
  request.on('error',error => finish({error:error.code || 'HTTP_ERROR'}));
}))).then(results => console.log(JSON.stringify(results)));
'''
    show('docker', 'exec', 'npm-nas', 'node', '-e', node, json.dumps(TARGETS), timeout=10)
    print('\nSaved Shelfmark certificate 73:', flush=True)
    show('openssl', 'x509', '-in', str(base / 'cutover/payload/letsencrypt/live/npm-73/fullchain.pem'),
         '-noout', '-subject', '-dates', '-ext', 'subjectAltName')
    print('\nLive OptiPlex Shelfmark Audio certificate:', flush=True)
    try:
        p = subprocess.run(['openssl', 's_client', '-connect', '192.168.0.29:443', '-servername',
                            'shelfmark-audio.sawdoctor.uk', '-showcerts'], input=b'', capture_output=True, timeout=8)
        certificate = p.stdout
    except subprocess.TimeoutExpired as error:
        certificate = error.stdout or b''
    if b'-----BEGIN CERTIFICATE-----' in certificate:
        show('openssl', 'x509', '-noout', '-subject', '-dates', '-ext', 'subjectAltName', stdin=certificate)
    else:
        print('Live certificate was not received within the time bound.', flush=True)
    print('\nREAD-ONLY ROUTE CHECK COMPLETE.', flush=True)


if __name__ == '__main__':
    main()
