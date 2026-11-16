#!/usr/bin/env python3
"""Compare original/current Tracearr controls without changing production.

Only an isolated disposable PostgreSQL copy is started, with no network or
published port. Keep current NAS data, connections, images and all controls.
"""
import contextlib
import copy
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import uuid

BASE=Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6/compose/production-cutover')
KUMA=BASE/'kuma-control-handover/worker.py'
KUMA_SHA='d9c844f035e69043c093a5c036c86c23b7c4f45ebf245aa53aee384ede40e7c1'
WORK=BASE/'tracearr-control-review'
ORIGINAL=WORK/'worker.py'
ORIGINAL_SHA='b83e7a898fa635b86a6a351fd39efaa9afd63b70b458bff503aad0783c5e46ee'
SELF=WORK/'worker-with-source-image.py'
UNIT='nas-original-tracearr-controls-resume.service'
FORMAT='sawdoctor-original-tracearr-controls-v1'
LIMIT=4*1024**3
TABLES={'automations':'is_active','destinations':'enabled','newsletters':'enabled',
        'notification_preferences':'push_enabled','request_services':'enabled'}
SETTINGS=('pollerEnabled','mobileEnabled','backupScheduleType','imagePrecacheEnabled',
          'pluginUpdateCheckEnabled','serverUpdateCheckEnabled','externalUrl')
SCHEDULES={'disabled','daily','weekly','monthly','manual','hourly','custom'}


def say(value):print(value,flush=True)
def require(value,message):
    if not value:raise RuntimeError(message)
def sha(value):return hashlib.sha256(value).hexdigest()


def controllers():
    sys.dont_write_bytecode=True
    require(not any(p.is_symlink() for p in (KUMA,*KUMA.parents)) and sha(KUMA.read_bytes())==KUMA_SHA,
            'The accepted Kuma handover helper differs.')
    spec=importlib.util.spec_from_file_location('accepted_kuma',KUMA)
    kuma=importlib.util.module_from_spec(spec);spec.loader.exec_module(kuma)
    return kuma,*kuma.controllers()


def repository(reference):
    require(isinstance(reference,str) and re.fullmatch(r'[A-Za-z0-9._:/@-]+',reference),
            'An original PostgreSQL image reference needs review.')
    value=reference.split('@',1)[0]
    if ':' in value.rsplit('/',1)[-1]:value=value.rsplit(':',1)[0]
    for prefix in ('docker.io/','index.docker.io/','registry-1.docker.io/'):
        if value.startswith(prefix):value=value[len(prefix):];break
    return value


def original_reference(source,image):
    require(image.get('Os')=='linux' and image.get('Architecture')=='amd64' and not image.get('Variant'),
            'The original PostgreSQL platform needs separate review.')
    allowed={'timescale/timescaledb','timescale/timescaledb-ha'}
    wanted=repository(source['Config']['Image'])
    candidates={ref for ref in image.get('RepoDigests') or []
                if re.fullmatch(r'[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}',ref)}
    if source['Config']['Image']==image['Id']:
        choices={repository(ref) for ref in candidates if repository(ref) in allowed}
        require(len(choices)==1,'The recorded PostgreSQL repository is unavailable or ambiguous.')
        wanted=next(iter(choices))
    require(wanted in allowed,'The original PostgreSQL repository is outside the reviewed Timescale images.')
    choices={wanted+'@'+ref.split('@',1)[1] for ref in candidates if repository(ref)==wanted}
    require(len(choices)==1,'A unique original PostgreSQL registry digest is unavailable; latest is not used.')
    return next(iter(choices))


def image_regressions(core,cache):
    image={'Id':'sha256:'+'1'*64,'Os':'linux','Architecture':'amd64','Variant':None,
           'RootFS':{'Type':'layers','Layers':['sha256:'+'2'*64]},
           'Config':{'Env':['PGDATA=/var/lib/postgresql/data'],'Cmd':['postgres'],'User':''},
           'RepoDigests':['docker.io/timescale/timescaledb@sha256:'+'3'*64]}
    source={'Image':image['Id'],'Config':{'Image':'timescale/timescaledb:latest-pg16'}}
    require(original_reference(source,image)=='timescale/timescaledb@sha256:'+'3'*64,
            'Test: original immutable repository normalization failed.')
    for kind in ('missing','foreign','ambiguous'):
        changed=copy.deepcopy(image)
        changed['RepoDigests']=[] if kind=='missing' else ['other/unreviewed@sha256:'+'3'*64] if kind=='foreign' else [
            'timescale/timescaledb@sha256:'+'3'*64,'timescale/timescaledb@sha256:'+'4'*64]
        try:original_reference(source,changed)
        except RuntimeError:pass
        else:raise RuntimeError('Test: '+kind+' source digest was accepted.')
    for kind in ('configuration','layers','platform'):
        changed=copy.deepcopy(image)
        if kind=='configuration':changed['Config']['Env']=['PGDATA=/different']
        elif kind=='layers':changed['RootFS']['Layers']=['sha256:'+'5'*64]
        else:changed['Architecture']='arm64'
        require(not cache.same_image(core,image,changed),'Test: changed image '+kind+' was accepted.')
    require(cache.same_image(core,image,copy.deepcopy(image)),'Test: unchanged original image was rejected.')
    return 7


def image_tags(images):
    result={}
    for identity,row in images.items():
        for tag in row.get('RepoTags') or []:result.setdefault(tag,[]).append(identity)
    return {tag:sorted(ids) for tag,ids in result.items()}


def runtime_images(rows):
    return {name:sha(json.dumps({'id':row['Id'],'image':row['Image'],'config':row['Config'],
        'hostConfig':row['HostConfig'],'mounts':sorted(row['Mounts'],key=lambda m:json.dumps(m,sort_keys=True)),
        'running':row['State']['Running'],'status':row['State']['Status'],'started':row['State'].get('StartedAt'),
        'finished':row['State'].get('FinishedAt'),'restartCount':row.get('RestartCount')},sort_keys=True).encode())
        for name,row in rows.items()}


def local_image(source,manifest,native):
    h=native.helpers();core,cache=h['core'],h['cache']
    tests=image_regressions(core,cache)
    say('SOURCE IMAGE REGRESSIONS PASSED: '+str(tests)+'; no network or real image change used by tests.')
    images={row['Id']:row for row in manifest['images']}
    require(source['Image'] in images,'The frozen PostgreSQL image metadata is unavailable.')
    expected=images[source['Image']]
    require(expected.get('Os')=='linux' and expected.get('Architecture')=='amd64' and not expected.get('Variant'),
            'The frozen PostgreSQL platform needs review.')
    current=cache.inventory(core);before_tags=image_tags(current);before_runtime=runtime_images(native.catalog())
    matches=sorted(identity for identity,row in current.items() if cache.same_image(core,expected,row))
    reference=None;record_path=WORK/'source-image-cache.json'
    if record_path.exists():
        previous=json.loads(native.read(record_path))
        require(previous.get('format')=='sawdoctor-tracearr-original-image-cache-v1'
                and previous.get('cutoverId')==manifest['cutoverId'] and previous.get('sourceImage')==source['Image'],
                'A different original-image cache record was retained.')
    if not matches:
        reference=original_reference(source,expected)
        docker_root=Path(native.run('docker','info','--format','{{.DockerRootDir}}').strip())
        native.safe(docker_root)
        size=expected.get('Size')
        require(type(size) is int and 0<size<8*1024**3 and shutil.disk_usage(docker_root).free>2*size+2*1024**3,
                'The original-image cache lacks its bounded download reserve.')
        native.atomic(record_path,{'format':'sawdoctor-tracearr-original-image-cache-v1',
            'cutoverId':manifest['cutoverId'],'phase':'caching','sourceImage':source['Image'],'reference':reference})
        try:
            cache.pull(core,'tracearr-original-db',reference,'linux/amd64',WORK)
            downloaded=json.loads(native.run('docker','image','inspect',reference))
            require(len(downloaded)==1 and cache.same_image(core,expected,downloaded[0]),
                    'The downloaded original PostgreSQL layers/configuration differ; no deployment.')
        finally:
            require(image_tags(cache.inventory(core))==before_tags and runtime_images(native.catalog())==before_runtime,
                    'An existing image tag or production runtime changed during caching; no live deployment requested.')
        current=cache.inventory(core)
        matches=sorted(identity for identity,row in current.items() if cache.same_image(core,expected,row))
    require(matches,'A verified original-equivalent PostgreSQL image is unavailable.')
    selected=source['Image'] if source['Image'] in matches else matches[0]
    require(image_tags(current)==before_tags and runtime_images(native.catalog())==before_runtime,
            'Current image tags/runtimes differ; comparison deferred.')
    native.atomic(record_path,{'format':'sawdoctor-tracearr-original-image-cache-v1',
        'cutoverId':manifest['cutoverId'],'phase':'complete','sourceImage':source['Image'],'reviewImage':selected,
        'reference':reference,'regressionTestsPassed':tests,'existingTagsRetained':True,'productionRuntimesRetained':True})
    say('ORIGINAL POSTGRESQL REVIEW IMAGE VERIFIED. Current database image and all existing tags/containers retained.')
    return selected


def checks_for(native,core,raw,prefix):
    checks={}
    with (raw/'SHA256SUMS').open(encoding='utf-8',errors='surrogateescape') as stream:
        for line in stream:
            require(len(line)<=65536,'An original checksum record exceeds its bound.')
            name,digest=core.parse_checksum(line)
            if name.startswith(prefix+'/'):
                require(name not in checks,'An original PostgreSQL checksum is duplicated.')
                checks[name]=digest
    require(0<len(checks)<=25000,'The original PostgreSQL checksum inventory is absent or oversized.')
    return checks


def copy_verified(stream,target,size,expected):
    require(0<=size<=1024**3,'A frozen PostgreSQL member exceeds its file bound.')
    require(shutil.disk_usage(target.parent).free>size+2*1024**3,'The disposable PostgreSQL copy lacks its disk reserve.')
    digest=hashlib.sha256();count=0
    with target.open('xb') as output:
        while block:=stream.read(1024**2):
            count+=len(block);require(count<=size,'A frozen PostgreSQL member exceeded its size.')
            output.write(block);digest.update(block)
    require(count==size and digest.hexdigest()==expected,'A frozen PostgreSQL copy failed its original checksum.')


def copy_cluster(native,raw,proof,prefix,checks,folder):
    """Copy only checksum-listed regular files; never mount the frozen root."""
    target=folder/'cluster';target.mkdir(mode=0o700)
    missing=set(checks);total=0;owner=None
    candidates=raw/prefix
    use_raw=candidates.is_dir()
    if use_raw:
        for directory,dirs,files in os.walk(candidates,followlinks=False):
            for name in (*dirs,*files):
                path=Path(directory)/name
                require(not path.is_symlink(),'A symbolic original PostgreSQL path requires review.')
        use_raw=all((raw/name).is_file() for name in checks)
    if use_raw:
        for directory,dirs,files in os.walk(candidates,followlinks=False):
            relative=Path(directory).relative_to(candidates)
            (target/relative).mkdir(mode=0o700,parents=True,exist_ok=True)
        for name,expected in checks.items():
            source=raw/name;native.safe(source);size=source.stat().st_size
            total+=size;require(total<=LIMIT,'The original PostgreSQL copy exceeds 4 GiB.')
            path=target/PurePosixPath(name).relative_to(prefix);path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            with source.open('rb') as stream:copy_verified(stream,path,size,expected)
            if path==target/'PG_VERSION':owner=(source.stat().st_uid,source.stat().st_gid)
            missing.remove(name)
    else:
        archive=native.BACKUP/'migration/production-handover/frozen'/proof['cutoverId']/'export.tar.zst'
        native.safe(archive);require(archive.stat().st_size==proof['archiveBytes'],'The retained frozen archive size differs.')
        say('Reading only the original PostgreSQL files from the retained frozen archive...')
        process=subprocess.Popen(['zstd','-dc','--',str(archive)],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        try:
            with tarfile.open(fileobj=process.stdout,mode='r|') as source:
                found=False
                for member in source:
                    name=str(PurePosixPath(member.name))
                    if name!=prefix and not name.startswith(prefix+'/'):
                        if found and not missing:break
                        continue
                    found=True
                    relative=PurePosixPath(name).relative_to(prefix)
                    require(not relative.is_absolute() and '..' not in relative.parts,'An original PostgreSQL member path is unsafe.')
                    path=target/relative
                    if member.isdir():path.mkdir(mode=0o700,parents=True,exist_ok=True);continue
                    require(member.isfile() and name in checks and name in missing,
                            'An unexpected or symbolic original PostgreSQL member requires review.')
                    total+=member.size;require(total<=LIMIT,'The original PostgreSQL copy exceeds 4 GiB.')
                    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                    with source.extractfile(member) as stream:copy_verified(stream,path,member.size,checks[name])
                    if relative==PurePosixPath('PG_VERSION'):owner=(member.uid,member.gid)
                    missing.remove(name)
        finally:
            process.stdout.close()
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=10)
    require(not missing and (target/'PG_VERSION').read_text().strip()=='16','The original PostgreSQL 16 copy is incomplete.')
    require(owner is not None and 0<owner[0]<65536 and 0<=owner[1]<65536,'The original non-root PostgreSQL owner needs review.')
    for directory,dirs,files in os.walk(target,followlinks=False):
        os.chown(directory,*owner);os.chmod(directory,0o700)
        for filename in files:os.chown(Path(directory)/filename,*owner);os.chmod(Path(directory)/filename,0o600)
    return target,owner,{'regularFiles':len(checks),'bytes':total}


def psql(container,sql,source_user=None,source_db=None,owner=None):
    if source_user is None:
        command=['docker','exec','-i',container,'sh','-c',
            'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -X -q -t -A -v ON_ERROR_STOP=1']
    else:
        command=['docker','exec','-i','--user',str(owner[0])+':'+str(owner[1]),container,
                 'psql','-h','/tmp','-U',source_user,'-d',source_db,'-X','-q','-t','-A','-v','ON_ERROR_STOP=1']
    result=subprocess.run(command,input=sql,text=True,capture_output=True,timeout=30)
    require(result.returncode==0,'A read-only Tracearr SQL query failed; no live database was changed.')
    require(len(result.stdout)<=8*1024**2,'The bounded Tracearr control response is oversized.')
    return result.stdout.strip()


def read_controls(query):
    schema=json.loads(query("""BEGIN READ ONLY; SET LOCAL statement_timeout='10s';
SELECT COALESCE(json_object_agg(table_name,cols),'{}'::json) FROM
(SELECT table_name,json_object_agg(column_name,data_type) cols
FROM information_schema.columns WHERE table_schema='public' GROUP BY table_name) t;
COMMIT;"""))
    require(schema.get('settings',{}).get('value')=='jsonb' and 'name' in schema.get('settings',{}),
            'The Tracearr settings schema needs review.')
    for table,field in TABLES.items():
        require(schema.get(table,{}).get(field)=='boolean','A reviewed Tracearr boolean control is unavailable: '+table+'.'+field)
    pieces=["'settings', (SELECT COALESCE(json_agg(to_jsonb(t)),'[]'::json) FROM (SELECT * FROM public.settings WHERE name IN ("+
            ','.join("'"+key+"'" for key in SETTINGS)+")) t)"]
    for table in (*TABLES,'servers'):
        require(table in schema,'An expected Tracearr control/connection table is absent: '+table)
        pieces.append("'"+table+"', (SELECT COALESCE(json_agg(to_jsonb(t)),'[]'::json) FROM (SELECT * FROM public."+table+" LIMIT 1001) t)")
    data=json.loads(query("BEGIN READ ONLY; SET LOCAL statement_timeout='10s';\nSELECT json_build_object("+','.join(pieces)+");\nCOMMIT;"))
    require(all(isinstance(rows,list) and len(rows)<=1000 for rows in data.values()),'A Tracearr control table exceeds its bound.')
    data['schema']={table:schema[table] for table in ('settings',*TABLES,'servers')}
    return data


def safe_origin(value):
    if not isinstance(value,str):return 'withheld/unavailable'
    try:parsed=urllib.parse.urlsplit(value)
    except ValueError:return 'withheld/unavailable'
    if parsed.scheme not in ('http','https') or not parsed.hostname:return 'withheld/unavailable'
    try:return parsed.scheme+'://'+parsed.hostname+(':'+str(parsed.port) if parsed.port else '')
    except ValueError:return 'withheld/unavailable'


def control_summary(source,current):
    output={'settings':{},'tables':{},'serversCurrent':[]}
    old_settings={r['name']:r.get('value') for r in source['settings']}
    live_settings={r['name']:r.get('value') for r in current['settings']}
    for key in SETTINGS:
        def safe(values):
            if key not in values:return 'not present'
            value=values[key]
            if key=='externalUrl':return safe_origin(value)
            if isinstance(value,bool) or value is None:return value
            if key=='backupScheduleType' and isinstance(value,str) and value in SCHEDULES:return value
            return 'withheld; value type needs review'
        output['settings'][key]={'source':safe(old_settings),'current':safe(live_settings)}
    for table,field in TABLES.items():
        old=source[table];live=current[table];common=set(source['schema'][table])&set(current['schema'][table])
        identity='id' if 'id' in common else 'user_id' if 'user_id' in common else None
        detail={'sourceTotal':len(old),'currentTotal':len(live),
                'sourceEnabled':sum(r.get(field) is True for r in old),'currentEnabled':sum(r.get(field) is True for r in live),
                'sourceOnlyColumns':sorted(set(source['schema'][table])-set(current['schema'][table])),
                'currentOnlyColumns':sorted(set(current['schema'][table])-set(source['schema'][table])),
                'identityField':identity,'rows':[]}
        if identity:
            a={str(r[identity]):r for r in old};b={str(r[identity]):r for r in live}
            detail['uniqueIdentities']=len(a)==len(old) and len(b)==len(live)
            for key in sorted(a.keys()|b.keys()):
                before=a.get(key);after=b.get(key)
                detail['rows'].append({'id':key if re.fullmatch(r'[A-Za-z0-9_-]{1,80}',key) else 'withheld',
                    'sourcePresent':before is not None,'currentPresent':after is not None,
                    'sourceEnabled':before.get(field) if before is not None else None,
                    'currentEnabled':after.get(field) if after is not None else None,
                    'otherChangedColumns':sorted(k for k in common if k!=field and before[k]!=after[k]) if before is not None and after is not None else []})
        output['tables'][table]=detail
    for row in current['servers']:
        output['serversCurrent'].append({'type':row.get('type') if row.get('type') in ('plex','jellyfin','emby') else 'not reported',
            'origin':safe_origin(row.get('url') or row.get('server_url') or row.get('serverUrl') or row.get('base_url')),'columnNames':sorted(row)})
    return output


def worker(kuma,inspected,accepted,resume,old,review,boot,backup,native,startup):
    with boot.boot_lock(native):
        main,current=backup.preflight(native);proof=main['proof']
        complete=json.loads(native.read(kuma.STATE))
        require(complete.get('format')==kuma.FORMAT and complete.get('phase')=='complete'
                and complete.get('cutoverId')==proof['cutoverId'],'The current Kuma completion differs.')
        raw=Path(main['raw'])
        require(native.digest(raw/'manifest.json')==proof['manifestSha256'],'The retained original manifest differs.')
        manifest=json.loads(native.read(raw/'manifest.json'))
        require(manifest.get('sourceDockerStopped') is True and manifest.get('cutoverId')==proof['cutoverId'],
                'The original stopped-source capture identity differs.')
        source={r['Name'].lstrip('/'):r for r in manifest['containers']}['tracearr-db']
        descriptor=manifest['dataRoots'].get('support.tracearr-db',{})
        prefix=descriptor.get('snapshot')
        require(prefix=='data/support.tracearr-db','The original PostgreSQL frozen locator needs review.')
        mounts=[m for m in source['Mounts'] if m.get('Destination')=='/var/lib/postgresql/data']
        require(len(mounts)==1 and mounts[0]['Source']==descriptor.get('source'),'The original PostgreSQL mount locator differs.')
        review_image=local_image(source,manifest,native)
        env=dict(item.split('=',1) for item in source['Config'].get('Env',[]) if '=' in item)
        user=env.get('POSTGRES_USER','postgres');database=env.get('POSTGRES_DB',user)
        require(all(isinstance(v,str) and 0<len(v)<=128 and '\x00' not in v for v in (user,database)),
                'The original PostgreSQL database/user identity needs private review.')
        checks=checks_for(native,native.helpers()['core'],raw,prefix)
        identity={name:current[name]['Image'] for name in ('tracearr-nas','tracearr-db-nas','tracearr-redis-nas')}
    with tempfile.TemporaryDirectory(prefix='.tracearr-original-',dir=WORK) as temporary:
        folder=Path(temporary)
        say('Preparing one bounded disposable copy of the exact frozen PostgreSQL files; production remains running...')
        cluster,owner,size=copy_cluster(native,raw,proof,prefix,checks,folder)
        say('Original PostgreSQL copy verified: '+json.dumps(size,sort_keys=True))
        hba=folder/'review-hba.conf';hba.write_text('local all all trust\n');os.chmod(hba,0o644)
        container=None
        with boot.boot_lock(native):
            current=native.catalog()
            require(all(current[n]['State']['Running'] and current[n]['Image']==image for n,image in identity.items()),
                    'A current Tracearr component changed while the disposable copy was prepared.')
            signatures=accepted.snapshot(boot,old,{n:current[n] for n in identity})
            require(backup.unit(native,'nas-backup.service').get('ActiveState') not in ('active','activating','deactivating'),
                    'A production backup is active; no temporary PostgreSQL was started.')
            name='nas-tracearr-original-review-'+uuid.uuid4().hex[:12]
            try:
                result=native.run('docker','create','--pull=never','--name='+name,'--restart=no',
                    '--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges',
                    '--pids-limit=128','--memory=1g','--cpus=1','--user='+str(owner[0])+':'+str(owner[1]),
                    '--tmpfs=/tmp:rw,nosuid,nodev,mode=1777',
                    '--mount=type=bind,src='+str(cluster)+',dst=/var/lib/postgresql/data',
                    '--mount=type=bind,src='+str(hba)+',dst=/review-hba.conf,readonly',
                    '--entrypoint=postgres',review_image,'-D','/var/lib/postgresql/data',
                    '-c','listen_addresses=','-c','unix_socket_directories=/tmp',
                    '-c','hba_file=/review-hba.conf','-c','ssl=off','-c','shared_buffers=64MB',
                    '-c','shared_preload_libraries=timescaledb','-c','timescaledb.telemetry_level=off',timeout=60)
                container=result.strip();require(re.fullmatch(r'[0-9a-f]{64}',container),'The disposable PostgreSQL container identity is unavailable.')
                native.run('docker','start',container,timeout=60)
                deadline=time.monotonic()+120
                while True:
                    ready=subprocess.run(['docker','exec','--user',str(owner[0])+':'+str(owner[1]),container,
                        'pg_isready','-q','-h','/tmp','-U',user,'-d',database],capture_output=True,timeout=10)
                    if ready.returncode==0:break
                    require(time.monotonic()<deadline,'The isolated original PostgreSQL did not become ready; live services retained.')
                    time.sleep(2)
                original=read_controls(lambda sql:psql(container,sql,user,database,owner))
                live=read_controls(lambda sql:psql('tracearr-db-nas',sql))
            except BaseException:
                if container and re.fullmatch(r'[0-9a-f]{64}',container):
                    diagnostic=subprocess.run(['docker','logs','--tail','40',container],capture_output=True,timeout=15)
                    native.atomic(WORK/'original-postgres-private.log',diagnostic.stdout+diagnostic.stderr)
                raise
            finally:
                if container and re.fullmatch(r'[0-9a-f]{64}',container):
                    try:subprocess.run(['docker','stop','--time','20',container],capture_output=True,timeout=45)
                    finally:
                        removed=subprocess.run(['docker','rm','-f',container],capture_output=True,timeout=45)
                        require(removed.returncode==0,'The disposable PostgreSQL container needs explicit cleanup; production was not changed.')
            now=native.catalog()
            require(accepted.snapshot(boot,old,{n:now[n] for n in identity})==signatures,
                    'A live Tracearr runtime changed during the read-only comparison; no live data was written.')
    summary=control_summary(original,live)
    native.atomic(WORK/'original-controls.json',original);native.atomic(WORK/'current-controls.json',live)
    record={'format':FORMAT,'cutoverId':proof['cutoverId'],'phase':'reviewed',
        'sourceImage':source['Image'],'reviewImage':review_image,'currentImages':identity,'temporaryPostgresRemoved':True,
        'originalSha256':sha(json.dumps(original,sort_keys=True).encode()),
        'currentSha256':sha(json.dumps(live,sort_keys=True).encode()),'summary':summary}
    native.atomic(WORK/'report.json',record)
    say('TRACEARR ORIGINAL/CURRENT CONTROLS: '+json.dumps(summary,sort_keys=True))
    say('TRACEARR READ-ONLY COMPARISON COMPLETE. Temporary PostgreSQL and its copied data removed.')
    say('No production restart, control update, history restore, current-image/tag change, source start or global cron release.')


def main():
    os.umask(0o077);args=controllers();native=args[-2];backup=args[-3]
    native.safe(WORK);WORK.mkdir(mode=0o700,exist_ok=True)
    require(sha(native.read(ORIGINAL))==ORIGINAL_SHA,'The retained original Tracearr reviewer changed.')
    if sys.argv[1:]==['--worker']:
        def interrupted(signum,frame):raise RuntimeError('The read-only comparison was interrupted; cleanup requested.')
        signal.signal(signal.SIGTERM,interrupted)
        with native.lock(BASE/'.run.lock'):worker(*args)
        return
    require(not sys.argv[1:],'Unexpected comparison arguments.')
    require(globals().get('CACHE_APPROVED_TRACEARR_REVIEW_IMAGE') is True,'The original-image cache approval flag is required.')
    text=globals().get('INSTALL_SOURCE');require(isinstance(text,str),'The complete comparison source is required.')
    with native.lock(BASE/'.run.lock'):
        if backup.unit(native,UNIT).get('ActiveState') in ('active','activating','deactivating'):
            say('The original/current Tracearr comparison is already running.');return
        if SELF.exists():require(native.read(SELF)==text.encode(),'A different existing Tracearr reviewer was retained.')
        else:native.atomic(SELF,text.encode(),mode=0o700)
        subprocess.run(['systemctl','reset-failed',UNIT],capture_output=True)
        native.run('systemd-run','--unit='+UNIT,'--collect','--property=Type=exec','--property=UMask=0077',
            '--property=RuntimeMaxSec=35min','--description=Compare original Tracearr controls without changing production',
            '/usr/bin/python3','-u',str(SELF),'--worker')
    say('Original PostgreSQL cache and Tracearr comparison started. Closing SSH is safe.')
    say('Progress: sudo journalctl -u '+UNIT+' -f -n 25 --no-pager -o cat')


if __name__=='__main__':
    try:main()
    except Exception as error:
        say('STOP: '+type(error).__name__+'. '+(str(error) if isinstance(error,RuntimeError) else 'The bounded comparison needs targeted review.')+
            ' No production control/data change was requested.')
        raise SystemExit(1)
