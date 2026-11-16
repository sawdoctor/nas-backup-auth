#!/usr/bin/env python3
"""Restore only the reviewed current NAS Kuma monitoring controls.

Keep current image/users/history, original notification destinations and all
unrelated application controls. Run isolated database tests before live writes.
"""
import contextlib
import copy
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.parse

BASE = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6/compose/production-cutover')
REVIEW = BASE / 'kuma-control-review/worker.py'
REVIEW_SHA = 'ef31f99d8ab2ebb0e57e615b51853d2381c367e330ea33ab71531d7aeb0deef1'
WORK = BASE / 'kuma-control-handover'
SELF = WORK / 'worker.py'
STATE = WORK / 'state.json'
UNIT = 'nas-production-kuma-controls.service'
FORMAT = 'sawdoctor-reviewed-kuma-controls-v1'
NAME = 'uptime-kuma-nas'
IMAGE = 'sha256:7e56461bcf86c4399a782952d73e1108354024421693806b4314927c40c418f5'
TABLES = ('monitor', 'notification', 'monitor_notification')
ACTIVE = {2,3,6,7,8,9,10,14,16,17,18,21,23,27,28}
LINKS = [[i,1] for i in (1,2,3,4,5,6,7,8,9,10,11,12,14,16,27,28)]
STAGED_PORTS = {2:1337,5:3002,17:5055,18:8877,23:61208,25:13378}
HBA_WORK = BASE / 'hba-temperature-handover'
HBA_SHA = '55908c698d9368e53b348fc15dfb4164ae2c6e370a587ea7aa9a866b41b97124'


def say(value): print(value, flush=True)
def require(value, message):
    if not value: raise RuntimeError(message)
def sha(body): return hashlib.sha256(body).hexdigest()
def canonical(value): return json.dumps(value, sort_keys=True, separators=(',', ':'))
def encoded(value): return canonical(value).encode()


def controllers():
    sys.dont_write_bytecode = True
    require(not any(p.is_symlink() for p in (REVIEW, *REVIEW.parents)), 'The reviewed Kuma controller is symbolic.')
    require(sha(REVIEW.read_bytes()) == REVIEW_SHA, 'The reviewed Kuma controller changed.')
    spec = importlib.util.spec_from_file_location('reviewed_kuma_controls', REVIEW)
    inspected = importlib.util.module_from_spec(spec); spec.loader.exec_module(inspected)
    return inspected, *inspected.controllers()


def snapshot(db, inspected, review):
    return {table: sorted(inspected.table(db, table, review), key=canonical) for table in TABLES}


def planned(source, before, inspected, review):
    summary = inspected.summarize_kuma(source, before, review)
    require(all(not row['otherSourceCurrentDifferentFieldNames'] for row in summary['monitors']),
            'An unrelated monitor setting changed; current values retained.')
    require(summary['notifications'] == [{'id':1, 'sameNameAndConfiguration':True,
        'sourceActive':True, 'currentActive':False, 'sourceDefault':False, 'currentDefault':False}],
        'The original/current notification identity or choices differ.')
    require(summary['sourceNotificationLinks'] == LINKS and summary['currentNotificationLinks'] == [],
        'The reviewed notification associations changed.')
    require(not any(row['currentActive'] for row in summary['monitors']), 'A monitor was enabled separately; current choices retained.')
    desired = copy.deepcopy(before)
    old = {row['id']:row for row in source['monitor']}
    for row in desired['monitor']:
        original = old[row['id']]; endpoint = inspected.desired_endpoint(original, review)
        allowed_urls = {original.get('url'), endpoint.get('url')}
        if row['id'] in STAGED_PORTS:
            parsed = urllib.parse.urlsplit(original.get('url') or '')
            require(not parsed.username and not parsed.password, 'An endpoint with embedded credentials needs private review.')
            allowed_urls.add(parsed._replace(scheme='http', netloc='192.168.0.220:'+str(STAGED_PORTS[row['id']])).geturl())
        require(row.get('url') in allowed_urls, 'A full current monitor URL/path changed since staging; retained.')
        require(all(row.get(key) == value for key,value in endpoint.items() if key != 'url'),
                'An unrelated current monitor hostname/port changed.')
        row.update(endpoint); row['active'] = int(row['id'] in ACTIVE)
    for row in desired['notification']:
        require(row['id'] == 1, 'An unreviewed notification was retained.')
        row['active'] = 1; row['is_default'] = 0
    desired['monitor_notification'] = copy.deepcopy(source['monitor_notification'])
    return {table:sorted(desired[table], key=canonical) for table in TABLES}, summary


def write_controls(path, before, after, inspected, review):
    """Atomic control-only SQL; never replace the database/history/users."""
    with contextlib.closing(sqlite3.connect(path.as_uri()+'?mode=rw', uri=True, timeout=10)) as db:
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON'); db.execute('BEGIN IMMEDIATE')
        try:
            current = snapshot(db, inspected, review)
            if current == after: db.rollback(); return False
            require(current == before, 'The current live control baseline changed; no overwrite.')
            for table, allowed in (('monitor', {'active','url','hostname','port'}), ('notification', {'active','is_default'})):
                old = {row['id']:row for row in before[table]}; new = {row['id']:row for row in after[table]}
                require(old.keys() == new.keys(), 'A control identity changed.')
                for identity in old:
                    require(old[identity].keys() == new[identity].keys(), 'A current control schema changed.')
                    fields = sorted(key for key in old[identity] if old[identity][key] != new[identity][key])
                    require(set(fields) <= allowed, 'A proposed edit changes an unrelated field.')
                    if fields:
                        sql = 'UPDATE "'+table+'" SET '+','.join('"'+key+'"=?' for key in fields)+' WHERE id=?'
                        db.execute(sql, [new[identity][key] for key in fields]+[identity])
            db.execute('DELETE FROM monitor_notification')
            columns = {row[1] for row in db.execute('PRAGMA table_info(monitor_notification)')}
            for row in after['monitor_notification']:
                require(set(row) <= columns, 'An original association column is unavailable in the current schema.')
                keys = sorted(row)
                db.execute('INSERT INTO monitor_notification ('+','.join('"'+key+'"' for key in keys)+') VALUES ('+','.join('?' for _ in keys)+')',
                           [row[key] for key in keys])
            require(snapshot(db, inspected, review) == after, 'The written controls differ from the reviewed plan.')
            require(db.execute('PRAGMA quick_check').fetchone()[0] == 'ok', 'Kuma integrity check failed.')
            db.commit(); return True
        except BaseException:
            db.rollback(); raise


def recent_hba_successes(rows, now_us):
    return sorted({int(row.get('__REALTIME_TIMESTAMP','0')) for row in rows
        if str(row.get('MESSAGE','')).startswith('HBA TEMPERATURE COLLECTED:')
        and now_us-180_000_000 <= int(row.get('__REALTIME_TIMESTAMP','0')) <= now_us})


def accept_hba(inspected, native, backup, cutover):
    """Close records from the repaired timer's actual recent successes."""
    target = HBA_WORK/'worker.py'
    require(sha(native.read(target)) == HBA_SHA, 'The repaired HBA worker differs.')
    module = type(sys)('current_hba_bridge'); module.__file__ = str(target)
    exec(compile(native.read(target), str(target), 'exec'), module.__dict__)
    module.verified(module.COLLECTOR, module.COLLECTOR_SHA); module.verified(module.OMV_JOB, module.OMV_JOB_SHA)
    for path, body in module.unit_contents().items():
        require(native.read(path) == body, 'An HBA unit definition changed.')
    timer = inspected.unit_info(native, backup, module.TIMER.name)
    service = backup.unit(native, module.SERVICE.name)
    require(timer.get('ActiveState') == 'active' and timer.get('UnitFileState') == 'enabled'
            and service.get('Result') == 'success', 'Recent HBA service/timer state needs review.')
    temperature = module.cached_temperature(time.time_ns()-120*10**9)
    raw = native.run('journalctl','-b','-u',module.SERVICE.name,'-n','80','--no-pager','-o','json')
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    successes = recent_hba_successes(rows, time.time_ns()//1000)
    require(len(successes) >= 2 and successes[-1]-successes[0] >= 30_000_000, 'Two recent separate HBA collections are not yet visible.')
    state_path = HBA_WORK/'state.json'; repair_path = HBA_WORK/'cache-freshness-repair.json'
    state = json.loads(native.read(state_path)); repair = json.loads(native.read(repair_path))
    require(state.get('format') == module.FORMAT and state.get('cutoverId') == cutover
            and repair.get('format') == 'sawdoctor-hba-cache-freshness-repair-v1'
            and repair.get('cutoverId') == cutover and repair.get('newSha256') == HBA_SHA
            and repair.get('regressionTestsPassed') == 8, 'The reviewed HBA handover/repair records differ.')
    state.update(phase='complete', twoFreshReadingsVerified=True, timerEnabled=True, temperatureC=temperature,
                 acceptedFromRecentTimerReadings=True)
    repair.update(phase='complete', acceptedAfterMediaRecovery=True)
    native.atomic(state_path, state); native.atomic(repair_path, repair)
    return {'accepted':True, 'temperatureC':temperature, 'recentSuccessfulCollections':len(successes)}


def fixture(inspected, review):
    ids = (1,2,3,4,5,6,7,8,9,10,11,12,13,14,16,17,18,21,22,23,24,25,26,27,28)
    source = {'monitor':[{'id':i, 'name':'monitor-'+str(i), 'type':'http', 'active':int(i in inspected.SOURCE_ACTIVE),
        'url':'https://service.sawdoctor.uk/check?key=retained', 'hostname':None, 'port':None, 'method':'GET',
        'auth':'private-unchanged', 'accepted_statuscodes_json':'["200-299"]'} for i in ids],
        'notification':[{'id':1,'name':'existing','config':'private-notification','active':1,'is_default':0}],
        'monitor_notification':[{'monitor_id':i,'notification_id':n} for i,n in LINKS]}
    by_id = {row['id']:row for row in source['monitor']}
    by_id[6]['url'] = 'http://192.168.0.29:81/'
    by_id[10]['url'] = 'http://192.168.0.29:32400/web/'
    by_id[3].update(type='port',hostname='192.168.0.29',port=8081)
    before = copy.deepcopy(source)
    for row in before['monitor']:
        row.update(inspected.desired_endpoint(row, review)); row['active'] = 0
    for row in before['notification']: row['active'] = 0
    before['monitor_notification'] = []
    for table in TABLES: before[table] = sorted(before[table], key=canonical); source[table] = sorted(source[table], key=canonical)
    return source, before


def test_database(path, controls):
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE monitor(id INTEGER PRIMARY KEY,name TEXT,type TEXT,active INTEGER,url TEXT,hostname TEXT,port INTEGER,method TEXT,auth TEXT,accepted_statuscodes_json TEXT)')
        db.execute('CREATE TABLE notification(id INTEGER PRIMARY KEY,name TEXT,config TEXT,active INTEGER,is_default INTEGER)')
        db.execute('CREATE TABLE monitor_notification(monitor_id INTEGER REFERENCES monitor(id),notification_id INTEGER REFERENCES notification(id),PRIMARY KEY(monitor_id,notification_id))')
        db.execute('CREATE TABLE preserved_history(value TEXT)'); db.execute("INSERT INTO preserved_history VALUES('keep users and history')")
        for table in TABLES:
            for row in controls[table]:
                keys = sorted(row); db.execute('INSERT INTO "'+table+'" ('+','.join(keys)+') VALUES ('+','.join('?' for _ in keys)+')',[row[k] for k in keys])


def regressions(inspected, review):
    source, before = fixture(inspected, review); untouched = copy.deepcopy((source,before))
    after, summary = planned(source,before,inspected,review)
    require({row['id'] for row in after['monitor'] if row['active']} == ACTIVE, 'Test: active/paused policy failed.')
    require(source == untouched[0] and before == untouched[1] and all(row['auth']=='private-unchanged' for row in after['monitor']), 'Test: private input/state retention failed.')
    wrong = copy.deepcopy(before); wrong['monitor'][0]['name']='other'
    try: planned(source,wrong,inspected,review)
    except RuntimeError: pass
    else: raise RuntimeError('Test: changed monitor identity was accepted.')
    wrong = copy.deepcopy(before); wrong['notification'][0]['config']='changed'
    try: planned(source,wrong,inspected,review)
    except RuntimeError: pass
    else: raise RuntimeError('Test: changed notification configuration was accepted.')
    with tempfile.TemporaryDirectory(prefix='kuma-control-test-') as temporary:
        root=Path(temporary); path=root/'controls.db'; test_database(path,before)
        require(write_controls(path,before,after,inspected,review), 'Test: control update did not apply.')
        with sqlite3.connect(path) as db:
            require(db.execute('SELECT value FROM preserved_history').fetchone()[0]=='keep users and history','Test: unrelated data changed.')
        require(not write_controls(path,before,after,inspected,review),'Test: idempotent update changed data.')
        path2=root/'changed.db';test_database(path2,before)
        with sqlite3.connect(path2) as db:db.execute("UPDATE monitor SET auth='separate edit' WHERE id=1")
        try: write_controls(path2,before,after,inspected,review)
        except RuntimeError: pass
        else: raise RuntimeError('Test: changed live baseline was overwritten.')
        path3=root/'rollback.db';test_database(path3,before); invalid=copy.deepcopy(after)
        invalid['monitor_notification'][0]['monitor_id']=999
        try: write_controls(path3,before,invalid,inspected,review)
        except sqlite3.IntegrityError: pass
        else: raise RuntimeError('Test: broken foreign key was accepted.')
        with review.database(path3) as db:require(snapshot(db,inspected,review)==before,'Test: SQL rollback failed.')
    now=1_000_000_000
    beats=[{'__REALTIME_TIMESTAMP':str(now-90_000_000),'MESSAGE':'HBA TEMPERATURE COLLECTED: 60 C'},
           {'__REALTIME_TIMESTAMP':str(now-30_000_000),'MESSAGE':'HBA TEMPERATURE COLLECTED: 60 C'}]
    require(len(recent_hba_successes(beats,now))==2,'Test: recent HBA success proof failed.')
    require(recent_hba_successes(beats,now+300_000_000)==[],'Test: stale HBA successes accepted.')
    return 10


def same_kuma(old, before, after):
    return before['Id']==after['Id'] and before['Image']==after['Image'] and before['Config']==after['Config'] \
        and before['HostConfig']==after['HostConfig'] and old.mounts(before)==old.mounts(after) and old.networks(before)==old.networks(after)


def beat_statuses(path, since, review):
    with review.database(path) as db:
        columns={row[1] for row in db.execute('PRAGMA table_info(heartbeat)')}
        if not {'id','monitor_id','status','time'} <= columns:return {}
        marks=','.join('?' for _ in ACTIVE)
        query='SELECT monitor_id,status,time FROM heartbeat WHERE id IN (SELECT MAX(id) FROM heartbeat WHERE monitor_id IN ('+marks+') GROUP BY monitor_id)'
        result={}
        for row in db.execute(query,sorted(ACTIVE)):
            try:
                when=dt.datetime.fromisoformat(str(row['time']).replace('Z','+00:00'))
                if when.tzinfo is None:when=when.replace(tzinfo=dt.timezone.utc)
                if when.timestamp()>=since and type(row['status']) is int:
                    result[row['monitor_id']]=row['status']
            except (TypeError,ValueError):continue
        return result


def worker(inspected, accepted, resume, old, review, boot, backup, native, startup):
    count=regressions(inspected,review)
    say('KUMA CONTROL REGRESSIONS PASSED: '+str(count)+'; only isolated temporary databases used.')
    with boot.boot_lock(native):
        main,current=backup.preflight(native); cutover=main['proof']['cutoverId']
        completion=json.loads(native.read(accepted.STATE))
        require(completion.get('format')==accepted.FORMAT and completion.get('phase')=='complete'
                and completion.get('cutoverId')==cutover,'The accepted current application state differs.')
        try:
            hba=accept_hba(inspected,native,backup,cutover);say('HBA HANDOVER ACCEPTED: '+json.dumps(hba,sort_keys=True))
        except RuntimeError as error:say('HBA SIGN-OFF RETAINED FOR REVIEW: '+str(error))
        row=current[NAME]
        require(row['State']['Running'] and row['Image']==IMAGE,'The reviewed current Kuma version/running state changed; no downgrade requested.')
        path=review.current_database(row,'kuma.db',native)
        require(path.is_relative_to(native.APP/'appdata'),'Kuma storage is outside the current appdata root.')
        status_before=accepted.snapshot(boot,old,{name:r for name,r in current.items() if name!=NAME})
        if STATE.exists():
            state=json.loads(native.read(STATE))
            require(state.get('format')==FORMAT and state.get('cutoverId')==cutover and state.get('image')==row['Image']
                    and state.get('containerId')==row['Id'],'An existing Kuma handover identity changed.')
            before=json.loads(native.read(WORK/'before-controls.json'));after=json.loads(native.read(WORK/'after-controls.json'))
            require(sha(encoded(before))==state['beforeSha256'] and sha(encoded(after))==state['afterSha256'],'A retained control snapshot changed.')
            with review.database(path) as db:live=snapshot(db,inspected,review)
            require(live in (before,after),'Current Kuma controls differ from both retained snapshots.')
        else:
            sealed=json.loads(native.read(inspected.WORK/'kuma-review.json'))
            require(sealed.get('format')==inspected.FORMAT and sealed.get('cutoverId')==cutover and sealed.get('currentImageId')==row['Image'],
                    'The sealed native Kuma review differs.')
            raw=Path(main['raw']);proof=main['proof']
            require(native.digest(raw/'manifest.json')==proof['manifestSha256'],'The frozen source manifest differs.')
            checks=review.source_checks(native,raw,native.helpers()['core'])
            checks={k:v for k,v in checks.items() if k.startswith('data/support.uptime-kuma/')}
            with tempfile.TemporaryDirectory(prefix='.original-kuma-',dir=WORK) as temporary:
                original=review.frozen_databases(native,raw,proof,checks,Path(temporary))['uptime-kuma']
                with review.database(original) as db:source=snapshot(db,inspected,review)
                with review.database(path) as db:before=snapshot(db,inspected,review)
            after,summary=planned(source,before,inspected,review)
            require(all(summary[key]==sealed[key] for key in ('monitors','notifications','sourceNotificationLinks','currentNotificationLinks','proposedActiveIds')),
                    'Current Kuma controls changed since their native review.')
            native.atomic(WORK/'before-controls.json',before);native.atomic(WORK/'after-controls.json',after)
            state={'format':FORMAT,'phase':'prepared','cutoverId':cutover,'image':row['Image'],'containerId':row['Id'],
                'beforeSha256':sha(encoded(before)),'afterSha256':sha(encoded(after)),'regressionTestsPassed':count}
            native.atomic(STATE,state);live=before
        changed=False
        if live!=after:
            native.run('docker','stop','--time','30',row['Id'],timeout=90)
            try:
                require(not native.catalog()[NAME]['State']['Running'],'Kuma did not stop for its consistent control update.')
                write_controls(path,before,after,inspected,review);changed=True
            finally:
                native.run('docker','start',row['Id'],timeout=90)
        try:
            running=old.wait_http(native,NAME,3001)
            require(same_kuma(old,row,running),'The existing Kuma runtime/configuration/bindings changed.')
            with review.database(path) as db:require(snapshot(db,inspected,review)==after,'Restored Kuma control read-back differs.')
        except BaseException:
            if changed:
                native.run('docker','stop','--time','30',row['Id'],timeout=90)
                try:write_controls(path,after,before,inspected,review)
                finally:native.run('docker','start',row['Id'],timeout=90)
            state['phase']='needs-review';native.atomic(STATE,state);raise
        final=native.catalog()
        require(accepted.snapshot(boot,old,{name:r for name,r in final.items() if name!=NAME})==status_before,
                'An unrelated runtime changed during the controlled update; current versions retained.')
        state.update(phase='restored',activeMonitorIds=sorted(ACTIVE),pausedCount=10,notificationLinks=16,notificationDefault=False)
        native.atomic(STATE,state)
        started=dt.datetime.fromisoformat(running['State']['StartedAt'].replace('Z','+00:00')).timestamp()
    say('KUMA MONITORING RESTORED: 15 active / 10 paused; original notification destination and 16 associations restored; default remains off.')
    say('Current image, users, history, auth/TLS settings and all other application runtimes retained. No test notification was sent.')
    deadline=time.monotonic()+120;beats={}
    while time.monotonic()<deadline:
        beats=beat_statuses(path,started,review)
        if len(beats)==len(ACTIVE):break
        time.sleep(5)
    status_names={0:'down',1:'up',2:'pending',3:'maintenance'}
    results=[{'id':i,'status':status_names.get(beats.get(i),'not-yet-observed')} for i in sorted(ACTIVE)]
    state.update(phase='complete',monitorHealth=results)
    native.atomic(STATE,state)
    say('KUMA FIRST CURRENT HEARTBEATS: '+json.dumps(results,sort_keys=True))
    say('REVIEWED NAS KUMA CONTROLS RESTORED. Any down/pending monitor above needs its own endpoint check; credentials and raw errors withheld.')
    say('Source freeze, global cron/host jobs, Tracearr controls and NPM renewal retained for their separate handovers.')


def main():
    os.umask(0o077);args=controllers()
    inspected,accepted,resume,old,review,boot,backup,native,startup=args
    native.safe(WORK);WORK.mkdir(mode=0o700,exist_ok=True)
    if sys.argv[1:]==['--worker']:
        with native.lock(BASE/'.run.lock'):worker(*args)
        return
    require(not sys.argv[1:] and globals().get('RESTORE_APPROVED_KUMA_CONTROLS') is True,'The approved Kuma restoration flag is required.')
    source=globals().get('INSTALL_SOURCE');require(isinstance(source,str),'The complete reviewed Kuma restoration source is required.')
    with native.lock(BASE/'.run.lock'):
        if backup.unit(native,UNIT).get('ActiveState') in ('active','activating','deactivating'):
            say('Kuma restoration is already running.');return
        if SELF.exists():require(native.read(SELF)==source.encode(),'A different Kuma restoration helper was retained.')
        else:native.atomic(SELF,source.encode(),mode=0o700)
        subprocess.run(['systemctl','reset-failed',UNIT],capture_output=True)
        native.run('systemd-run','--unit='+UNIT,'--collect','--property=Type=exec','--property=UMask=0077','--property=RuntimeMaxSec=10min',
            '--description=Restore reviewed NAS Kuma monitoring and original notification links','/usr/bin/python3','-u',str(SELF),'--worker')
    say('Reviewed Kuma restoration started in systemd. Closing SSH is safe.')
    say('Progress: sudo journalctl -u '+UNIT+' -f -n 25 --no-pager -o cat')


if __name__=='__main__':
    try:main()
    except Exception as error:
        say('STOP: '+type(error).__name__+'. '+(str(error) if isinstance(error,RuntimeError) else 'Kuma restoration needs targeted review.')+' Current images/data retained.')
        raise SystemExit(1)
