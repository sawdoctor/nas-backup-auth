#!/usr/bin/env python3
"""Sawdoctor NAS support deployment v1: restore verified support apps for NAS testing."""
import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

SSD=Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
SNAPSHOT=SSD/'migration/support-optiplex/snapshot'
DATA=SSD/'appdata/support-nas'
STACK=SSD/'compose/support-nas'
LOCK=Path('/run/lock/sawdoctor-nas-backup.lock')
SIGNATURE='Sawdoctor NAS support deployment v1'
PROJECT='support-nas'
CORE_SHA='8ebc4f735c61c5f0ea29c509b1bd6279efc05741675ad4e7370ee3b39c71065e'
APPS={
    'homepage':(3002,3000,'Homepage'), 'uptime-kuma':(3001,3001,'Uptime Kuma'),
    'speedtest-tracker':(8765,80,'Speedtest Tracker'), 'wizarr':(5690,5690,'Wizarr'),
    'houndarr':(8877,8877,'Houndarr'), 'tracearr':(7330,3000,'Tracearr'),
    'tracearr-db':(None,5432,'Tracearr PostgreSQL'), 'tracearr-redis':(None,6379,'Tracearr Redis'),
    'glances':(61208,61208,'Glances'), 'kometa':(None,None,'Kometa'),
}
PORTS={8090:8090,8096:None,8081:8081,8082:8082,8989:8989,7878:7878,7879:7879,
    9696:9696,1337:1337,5055:5055,8085:8085,13378:13378,5000:5000,8087:8087,
    8086:8086,8084:8084,8484:8484,3002:3002,3001:3001,8765:8765,5690:5690,
    8877:8877,7330:7330,61208:61208,81:10081}
DOMAINS={'sonarr':8989,'radarr':7878,'radarr4k':7879,'prowlarr':9696,'usenet':1337,
    'nzbdav':8081,'request':5055,'seerr':5055,'silo':8090,'abr':8085,'audiobook':13378,
    'kavita':5000,'libraseer':8484,'shelfmark-audio':8084,'shelfmark-ebook':8086,
    'houndarr':8877,'kuma':3001,'glances':61208,'speedtest':8765,'tracearr':7330,
    'wizarr':5690,'homepage':3002,'omv':80,'dockmon':8001,'nginx':10081}


def log(message): print(message,flush=True)


def run(*args,capture=False,**kwargs):
    return subprocess.run(args,check=True,text=True,stdout=subprocess.PIPE if capture else None,**kwargs).stdout


def atomic_text(path,text,mode=0o600):
    original=path.stat() if path.exists() else None
    fd,temporary=tempfile.mkstemp(prefix='.support-nas-',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as stream:
            stream.write(text);stream.flush();os.fsync(stream.fileno())
        os.chmod(temporary,mode)
        if original: os.chown(temporary,original.st_uid,original.st_gid)
        os.replace(temporary,path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def write_json(path,value): atomic_text(path,json.dumps(value,indent=2)+'\n')


def helpers():
    path=Path('/usr/local/sbin/nas-core-deploy.py')
    if hashlib.sha256(path.read_bytes()).hexdigest()!=CORE_SHA:
        raise RuntimeError('The installed core image verifier is not the tested version.')
    sys.dont_write_bytecode=True
    spec=importlib.util.spec_from_file_location('support_images',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def resolve_images(verifier,manifest,containers):
    """Reuse the previously verified immutable NAS IDs on a deployment retry."""
    cache=STACK/'image-identities.json'
    if cache.is_file() and not cache.is_symlink():
        try:
            records=json.loads(cache.read_text())
            if set(records)!=set(containers):raise ValueError('image list changed')
            archive_ids,configs=verifier.archive_image_identities(SNAPSHOT/'images.tar')
            references=[]
            for name,source in containers.items():
                record=records[name]
                if record['source']!=source['Image'] or record['config'] not in archive_ids.get(source['Image'],set()):
                    raise ValueError('export identity changed')
                if not re.fullmatch(r'sha256:[0-9a-f]{64}',record['nas']):raise ValueError('invalid NAS identity')
                references.append(record['nas'])
            inspected=json.loads(run('docker','image','inspect',*sorted(set(references)),capture=True,stderr=subprocess.DEVNULL))
            by_id={item['Id']:item for item in inspected}
            for record in records.values():
                image=by_id[record['nas']];config=configs[record['config']]
                if (image.get('Os')!=config.get('os') or image.get('Architecture')!=config.get('architecture')
                    or image.get('Variant','')!=config.get('variant','')
                    or image.get('RootFS',{}).get('Layers')!=config['rootfs'].get('diff_ids')):
                    raise ValueError('loaded image metadata changed')
            log('Reusing all previously verified NAS image identities; no image reload is needed.')
            return {name:record['nas'] for name,record in records.items()}
        except (KeyError,ValueError,OSError,subprocess.CalledProcessError):
            log('The saved image identities need fresh verification.')
    return verifier.load_verified_images(SNAPSHOT,manifest,containers,STACK)


def rewrite_urls(value):
    if not isinstance(value,str): return value
    def address(match):
        old=int(match[1]);port=PORTS.get(old)
        return 'http://192.168.0.220:'+str(port) if port else match[0]
    value=re.sub(r'https?://192\.168\.0\.29:([0-9]+)(?![0-9])',address,value)
    def domain(match):
        prefix=match[1].lower();port=DOMAINS.get(prefix)
        if not port:return match[0]
        scheme='https' if prefix=='dockmon' else 'http'
        return scheme+'://192.168.0.220:'+str(port)
    return re.sub(r'https?://([A-Za-z0-9-]+)\.sawdoctor\.uk(?::[0-9]+)?(?=[/\s\"\'#?]|$)',domain,value)


def map_source(source,manifest,data):
    path=Path(source)
    for label,root in sorted(manifest['dataRoots'].items(),key=lambda item:len(item[1]['source']),reverse=True):
        original=Path(root['source'])
        if path.is_relative_to(original):return data/label/path.relative_to(original)
    if source in ('/var/run/docker.sock','/etc/os-release'):return path
    raise RuntimeError('An unexpected support application bind needs review: '+source)


def connect(path):
    con=sqlite3.connect(path)
    if con.execute('PRAGMA quick_check').fetchall()!=[('ok',)]:
        con.close();raise RuntimeError('A copied support database failed integrity checking: '+path.name)
    return con


def finish(con):
    con.commit();con.execute('PRAGMA wal_checkpoint(TRUNCATE)');con.close()


def patch_databases(data):
    con=connect(data/'uptime-kuma/kuma.db')
    try:
        con.execute('UPDATE monitor SET active=0')
        for rowid,url,hostname,port in con.execute('SELECT id,url,hostname,port FROM monitor').fetchall():
            new_url=rewrite_urls(url)
            new_host,new_port=hostname,port
            if hostname=='192.168.0.29' and port in PORTS and PORTS[port]:new_host,new_port='192.168.0.220',PORTS[port]
            con.execute('UPDATE monitor SET url=?,hostname=?,port=? WHERE id=?',(new_url,new_host,new_port,rowid))
        con.execute('UPDATE notification SET active=0,is_default=0')
        con.execute('DELETE FROM monitor_notification')
        finish(con)
    except Exception:con.close();raise
    con=connect(data/'houndarr/houndarr.db')
    try:
        con.execute('UPDATE instances SET enabled=0,missing_enabled=0,cutoff_enabled=0,upgrade_enabled=0')
        for rowid,url in con.execute('SELECT id,url FROM instances').fetchall():
            con.execute('UPDATE instances SET url=? WHERE id=?',(rewrite_urls(url),rowid))
        finish(con)
    except Exception:con.close();raise
    con=connect(data/'speedtest-tracker/database.sqlite')
    try:
        con.execute('DELETE FROM jobs')
        finish(con)
    except Exception:con.close();raise
    con=connect(data/'wizarr/database/database.db')
    try:
        con.execute('UPDATE ldap_configuration SET enabled=0')
        # Account/library server identities remain linked to production Plex
        # until the final Plex migration. Background tasks are disabled in env.
        finish(con)
    except Exception:con.close();raise
    for folder in ('homepage','kometa'):
        for path in (data/folder).rglob('*'):
            if path.is_symlink() or not path.is_file() or path.suffix not in ('.yml','.yaml'):continue
            if path.stat().st_size>4*1024**2:continue
            text=path.read_text();updated=rewrite_urls(text)
            if updated!=text:atomic_text(path,updated,path.stat().st_mode&0o777)


def prepare_data(manifest,data):
    data.chmod(0o755)
    for label,root in manifest['dataRoots'].items():
        if '/' in label or label in ('','.','..'):raise RuntimeError('Unexpected source data label.')
        source=SNAPSHOT/root['snapshot']
        if source.is_symlink() or not source.is_dir() or not source.resolve().is_relative_to(SNAPSHOT.resolve()):
            raise RuntimeError('The copied support data path is not safe: '+label)
        run('cp','-a','--',str(source),str(data/label))
    patch_databases(data)
    # Redis contains BullMQ jobs as well as cache. Retain the copied Redis data
    # for recovery, and give the NAS a fresh queue so source jobs cannot replay.
    recovery=data/'recovery';recovery.mkdir(mode=0o700)
    redis=data/'tracearr-redis';stat=redis.stat()
    os.replace(redis,recovery/'source-tracearr-redis')
    redis.mkdir(mode=stat.st_mode&0o777);os.chown(redis,stat.st_uid,stat.st_gid)


def check_ports(existing):
    own={name+'-nas' for name in APPS}
    targets={str(item[0]) for item in APPS.values() if item[0]}
    for c in existing:
        name=c['Name'].lstrip('/')
        if name in own:
            if (c['Config'].get('Labels') or {}).get('com.docker.compose.project')!=PROJECT:
                raise RuntimeError('An unrelated container uses a NAS support name: '+name)
            continue
        for bindings in (c['HostConfig'].get('PortBindings') or {}).values():
            if any(binding.get('HostPort') in targets for binding in bindings or []):
                raise RuntimeError('Another NAS container reserves a support port: '+name)
    names={c['Name'].lstrip('/') for c in existing}
    for name,(host,_,_) in APPS.items():
        if host and name+'-nas' not in names:
            with socket.socket() as listener:listener.bind(('192.168.0.220',host))


def verify_wizarr_switch(image):
    temporary_id=run('docker','create','--network','none',image,'true',capture=True).strip()
    try:
        with tempfile.TemporaryDirectory(prefix='.wizarr-check-',dir=STACK) as temporary:
            for index,name in enumerate(('__init__.py','background.py','extensions.py')):
                target=Path(temporary)/str(index)
                result=subprocess.run(['docker','cp',temporary_id+':/app/app/'+name,str(target)],
                    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                if result.returncode==0:
                    text=target.read_text(errors='replace')
                    if 'FLASK_SKIP_SCHEDULER' in text:return True
        return False
    finally:
        run('docker','rm','--volumes',temporary_id,capture=True)


def compose_document(containers,manifest,resolved,wizarr_enabled):
    doc={'name':PROJECT,'x-sawdoctor-managed':SIGNATURE,'services':{},'networks':{
        'media-core':{'external':True,'name':'media-core'},'tracearr-db':{'internal':True}}}
    for name,source in containers.items():
        config=source['Config'];env=dict(item.split('=',1) for item in config.get('Env',[]) if '=' in item)
        if name=='homepage':
            hosts=[value.strip() for value in env.get('HOMEPAGE_ALLOWED_HOSTS','').split(',') if value.strip()]
            for host in ('192.168.0.220:3002','192.168.0.220','localhost:3000','homepage-nas:3000'):
                if host not in hosts:hosts.append(host)
            env['HOMEPAGE_ALLOWED_HOSTS']=','.join(hosts)
        if name=='speedtest-tracker':env.update({'APP_URL':'http://192.168.0.220:8765','SPEEDTEST_SCHEDULE':''})
        if name=='wizarr':env.update({'FLASK_SKIP_SCHEDULER':'true','WIZARR_DISABLE_SCHEDULER':'true'})
        if name=='tracearr':env['CORS_ORIGIN']='http://192.168.0.220:7330'
        service={'image':resolved[name],'container_name':name+'-nas','pull_policy':'never','restart':'unless-stopped',
            'environment':{key:value.replace('$','$$') for key,value in env.items()},'volumes':[],
            'logging':{'driver':'json-file','options':{'max-size':'10m','max-file':'3'}}}
        for mount in source.get('Mounts',[]):
            service['volumes'].append({'type':'bind','source':str(map_source(mount['Source'],manifest,DATA)),
                'target':mount['Destination'],'read_only':not mount.get('RW',True),'bind':{'create_host_path':False}})
        for key,target in (('Cmd','command'),('Entrypoint','entrypoint')):
            if config.get(key) is not None:service[target]=[item.replace('$','$$') for item in config[key]]
        if config.get('User'):service['user']=config['User']
        if config.get('WorkingDir'):service['working_dir']=config['WorkingDir']
        if name in ('tracearr-db','tracearr-redis'):
            service['networks']={'tracearr-db':{'aliases':[name]}}
        else:
            service['networks']={'media-core':{'aliases':[name]}}
            if name=='tracearr':
                service['networks']['tracearr-db']={}
                service['depends_on']=['tracearr-db','tracearr-redis']
        if name=='glances':
            if source['HostConfig'].get('PidMode')!='host':raise RuntimeError('Unexpected original Glances PID mode.')
            service['pid']='host'
            if source['HostConfig'].get('CapAdd'):service['cap_add']=source['HostConfig']['CapAdd']
        host,internal,_=APPS[name]
        if host:service['ports']=['192.168.0.220:'+str(host)+':'+str(internal)]
        if name=='kometa' or (name=='wizarr' and not wizarr_enabled):
            service['profiles']=['plex-cutover'];service['restart']='no'
        doc['services'][name]=service
    return doc


def compose(*args):return run('docker','compose','-f',str(STACK/'compose.json'),*args)


def psql(sql):
    result=subprocess.run(['docker','exec','-i','tracearr-db-nas','sh','-c',
        'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -X -q -t -A -v ON_ERROR_STOP=1'],
        input=sql,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
    if result.returncode:
        atomic_text(STACK/'tracearr-database-error.log',result.stderr,0o600)
        raise RuntimeError('NAS Tracearr database preparation failed; details were saved privately in its Compose folder.')
    return result.stdout.strip()


def tracearr_test_sql(schema):
    """Choose verified controls from the actual database schema, before writing."""
    def require(table,columns):
        found=schema.get(table,{})
        for column,kind in columns.items():
            if column not in found or (kind and found[column]!=kind):
                raise RuntimeError('The copied Tracearr schema lacks the expected '+table+'.'+column+' control.')
    require('settings',{'name':None,'value':'jsonb'})
    require('notification_preferences',{'push_enabled':'boolean'})
    statements=['BEGIN;']
    settings={'pollerEnabled':False,'mobileEnabled':False,'backupScheduleType':'disabled',
        'imagePrecacheEnabled':False,'pluginUpdateCheckEnabled':False,
        'externalUrl':'http://192.168.0.220:7330'}
    if 'automations' in schema:
        # Tracearr v3: rules became automations; outbound delivery lives in
        # destinations and newsletters, with encrypted credentials retained.
        controls={'automations':{'is_active':'boolean'},'destinations':{'enabled':'boolean'},
            'newsletters':{'enabled':'boolean'},'request_services':{'enabled':'boolean'}}
        for table,columns in controls.items():
            require(table,columns)
            statements.append('UPDATE public."'+table+'" SET "'+next(iter(columns))+'"=false;')
        settings['serverUpdateCheckEnabled']=False
    elif 'rules' in schema:
        require('rules',{'is_active':'boolean'})
        require('notification_channel_routing',{'discord_enabled':'boolean','webhook_enabled':'boolean','push_enabled':'boolean'})
        statements.extend(['UPDATE public.rules SET is_active=false;',
            'UPDATE public.notification_channel_routing SET discord_enabled=false,webhook_enabled=false,push_enabled=false;'])
        settings.update({name:None for name in ('discordWebhookUrl','customWebhookUrl','ntfyTopic',
            'ntfyAuthToken','pushoverUserKey','pushoverApiToken')})
    else:
        raise RuntimeError('The copied Tracearr schema has neither supported automation layout.')
    statements.append('UPDATE public.notification_preferences SET push_enabled=false;')
    values=["('"+name+"','"+json.dumps(value).replace("'","''")+"'::jsonb)" for name,value in settings.items()]
    statements.append('INSERT INTO public.settings(name,value) VALUES '+','.join(values)+
        ' ON CONFLICT(name) DO UPDATE SET value=excluded.value;')
    statements.append('COMMIT;')
    return '\n'.join(statements)


def prepare_tracearr():
    deadline=time.monotonic()+120
    while True:
        result=subprocess.run(['docker','exec','tracearr-db-nas','sh','-c',
            'pg_isready -q -U "$POSTGRES_USER" -d "$POSTGRES_DB"'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if result.returncode==0:break
        if time.monotonic()>deadline:raise RuntimeError('The copied NAS Tracearr PostgreSQL database did not become ready.')
        time.sleep(2)
    version=psql('SHOW server_version;')
    if not version.startswith('16.'):
        raise RuntimeError('NAS Tracearr did not start with the original PostgreSQL major version 16.')
    schema=json.loads(psql("""SELECT COALESCE(json_object_agg(table_name,columns),'{}'::json)
FROM (SELECT table_name,json_object_agg(column_name,data_type) AS columns
FROM information_schema.columns WHERE table_schema='public' GROUP BY table_name) AS inventory;"""))
    sql=tracearr_test_sql(schema)
    # Validate the entire schema before a single transaction changes test flags.
    # No history, accounts, server tokens or encrypted notification config changes.
    psql(sql)
    (STACK/'tracearr-database-error.log').unlink(missing_ok=True)
    layout='v3 automations/destinations' if 'automations' in schema else 'v2 rules'
    log('Tracearr: PostgreSQL 16 restored using '+layout+'; polling, actions and copied notifications paused.')


def check_http(names):
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    pending={name for name in names if APPS[name][0]}
    deadline=time.monotonic()+240
    while pending and time.monotonic()<deadline:
        for name in list(pending):
            try:
                try:response=opener.open('http://192.168.0.220:'+str(APPS[name][0])+'/',timeout=3)
                except urllib.error.HTTPError as error:response=error
                with response:
                    if response.code<400 or response.code in (401,403):
                        log(APPS[name][2]+': HTTP responding ('+str(response.code)+')');pending.remove(name)
            except OSError:pass
        if pending:time.sleep(2)
    if pending:raise RuntimeError('These NAS support web pages did not become ready: '+', '.join(sorted(pending))+'. Copied settings were retained for retry.')


def addresses(wizarr):
    for name,(host,_,label) in APPS.items():
        if host and (name!='wizarr' or wizarr):log(label+': http://192.168.0.220:'+str(host))
    log('Kometa: configured and stopped until the Plex cutover.')
    if not wizarr:log('Wizarr: configured and stopped; its copied image did not expose the verified background-disable switch.')


def main():
    os.umask(0o077)
    if os.geteuid()!=0 or 'inet 192.168.0.220/' not in run('ip','-4','addr','show',capture=True):
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220.')
    if not SSD.is_mount():raise RuntimeError('The NAS application SSD is not mounted.')
    marker_path=DATA/'install.json'
    for path in (DATA,STACK):
        if path.is_symlink():raise RuntimeError('An unexpected symlink occupies a support deployment path.')
    if DATA.exists():
        if not marker_path.is_file() or json.loads(marker_path.read_text()).get('format')!=SIGNATURE:
            raise RuntimeError('Existing support data lacks a matching migration marker; it was retained.')
        marker=json.loads(marker_path.read_text())
        if marker.get('completed'):
            log('NAS support deployment is already complete. Existing NAS settings were retained.');addresses(marker['wizarrEnabled']);return
    manifest=json.loads((SNAPSHOT/'manifest.json').read_text())
    containers={c['Name'].lstrip('/'):c for c in manifest['containers']}
    if manifest.get('format')!='sawdoctor-support-export-v1' or manifest.get('sourceHost')!='192.168.0.29' or manifest.get('postgresMajor')!='16' or set(containers)!=set(APPS):
        raise RuntimeError('The verified support export with PostgreSQL 16 was not found.')
    ids=run('docker','ps','-aq',capture=True).split()
    current=json.loads(run('docker','inspect',*ids,capture=True)) if ids else []
    check_ports(current)
    verifier=helpers()
    log('Verifying the copied support files and exact Docker images...')
    run('sha256sum','--quiet','-c','SHA256SUMS',cwd=SNAPSHOT)
    log('Waiting for the NAS backup lock...')
    with open(LOCK,'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if not DATA.exists():
            work=Path(tempfile.mkdtemp(prefix='.support-nas-',dir=DATA.parent))
            try:
                log('Restoring support settings/history and applying NAS test settings...')
                prepare_data(manifest,work)
                write_json(work/'install.json',{'format':SIGNATURE,'sourceCreatedUtc':manifest['createdUtc'],
                    'completed':False,'databasePrepared':False})
                os.replace(work,DATA)
            finally:
                if work.exists():shutil.rmtree(work)
        marker=json.loads(marker_path.read_text())
        STACK.mkdir(mode=0o700,parents=True,exist_ok=True)
        path=STACK/'compose.json'
        if path.exists() and json.loads(path.read_text()).get('x-sawdoctor-managed')!=SIGNATURE:
            raise RuntimeError('An unrelated support Compose definition exists.')
        resolved=resolve_images(verifier,manifest,containers)
        if not path.exists():
            wizarr=verify_wizarr_switch(resolved['wizarr'])
            write_json(path,compose_document(containers,manifest,resolved,wizarr))
            marker['wizarrEnabled']=wizarr;write_json(marker_path,marker)
        else:
            doc=json.loads(path.read_text())
            for name,image in resolved.items():doc['services'][name]['image']=image
            write_json(path,doc)
            marker.setdefault('wizarrEnabled',not doc['services']['wizarr'].get('profiles'))
        compose('config','--quiet')
        log('Starting the NAS Tracearr database and fresh Redis queue...')
        compose('up','-d','--pull','never','tracearr-db','tracearr-redis')
        if not marker.get('databasePrepared'):
            prepare_tracearr();marker['databasePrepared']=True;write_json(marker_path,marker)
        log('Starting the NAS support web applications...')
        compose('up','-d','--pull','never','--wait','--wait-timeout','300')
        # Profile containers are created for visibility, with no background work.
        compose('--profile','plex-cutover','create','--pull','never','kometa')
        if not marker['wizarrEnabled']:compose('--profile','plex-cutover','create','--pull','never','wizarr')
    started=set(APPS)-{'kometa'}
    if not marker['wizarrEnabled']:started.remove('wizarr')
    check_http(started)
    with open(LOCK,'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        marker['completed']=True;write_json(marker_path,marker)
    log('\nNAS SUPPORT APPS DEPLOYED. Use the existing logins.')
    log('Kuma monitors/alerts, Houndarr searches, scheduled speed tests and Tracearr polling/rules are paused for initial testing.')
    log('Tracearr history and accounts are retained; the NAS Redis queue starts fresh. The OptiPlex was not changed.')
    addresses(marker['wizarrEnabled'])


if __name__=='__main__':
    try:main()
    except KeyboardInterrupt:raise SystemExit('Interrupted. Prepared NAS support settings were retained for retry.')
    except Exception as error:raise SystemExit('STOP: '+str(error))
