#!/usr/bin/env python3
"""Refresh never-started NAS Plex from a verified standby snapshot, without activation."""
import contextlib
import datetime as dt
import fcntl
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

SIGNATURE='Sawdoctor NAS Plex standby refresh v1'
PREPARED='Sawdoctor NAS Plex cutover preparation v1'
FORMAT='sawdoctor-migration-standby-v1'
SSD=Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
BASE=SSD/'migration/nightly-standby'
DATA=SSD/'appdata/plex-nas'
STACK=SSD/'compose/plex-nas'
RECOVERY=STACK/'recovery/before-standby-refresh'
LIBRARY=SSD/'appdata/infinidysk-nas/library'
SCRATCH=Path('/srv/dev-disk-by-uuid-1f12a22e-5cfe-4b02-8d4b-48e9bf5fec6a')
LOCK=Path('/run/lock/sawdoctor-nas-backup.lock')
HELPER=Path('/usr/local/sbin/nas-plex-prepare')
HELPER_SHA='d0e31756a79c596b27dd7d1e735a43472025dd5d4df8478b8c036648dba3e6ba'
WORKER=Path('/run/nas-plex-standby-refresh.py')
SOURCE_IMAGE='sha256:0c2f1122a4275efeea953a9882359f3809b27279d3c3022392e8e610a2eccc67'
IMAGE='lscr.io/linuxserver/plex:1.43.5.11079-b3b13e506-ls331'
PREFS=Path('Library/Application Support/Plex Media Server/Preferences.xml')


def say(value):print(value,flush=True)


def atomic(path,value,mode=0o600):
    if path.is_symlink():raise RuntimeError('An unexpected symbolic refresh file was retained.')
    fd,temporary=tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd,'w') as stream:
            stream.write(value);stream.flush();os.fsync(stream.fileno())
        os.chmod(temporary,mode);os.replace(temporary,path)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)


def run(*args,timeout=120,allowed=(0,)):
    result=subprocess.run(args,text=True,capture_output=True,timeout=timeout)
    if result.returncode not in allowed:
        atomic(STACK/'standby-refresh-error.log',result.stdout+'\n'+result.stderr)
        raise RuntimeError('A refresh command failed; its output was saved privately in the Plex Compose folder.')
    return result.stdout


def digest(path):
    value=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(4*1024**2),b''):value.update(block)
    return value.hexdigest()


def preparation_helper(snapshot):
    if HELPER.is_symlink() or digest(HELPER)!=HELPER_SHA:
        raise RuntimeError('The reviewed original NAS Plex preparation helper is required.')
    sys.dont_write_bytecode=True
    loader=importlib.machinery.SourceFileLoader('plex_standby_preparation',str(HELPER))
    spec=importlib.util.spec_from_file_location(loader.name,HELPER,loader=loader)
    helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
    helper.SNAPSHOT=snapshot
    return helper


def latest_snapshot():
    current=json.loads((BASE/'current.json').read_text())
    snapshot=Path(current['snapshot'])
    if (snapshot.is_symlink() or snapshot.parent.resolve()!=(BASE/'snapshots').resolve()
        or snapshot.name!=current['createdUtc'] or current.get('format')!=FORMAT):
        raise RuntimeError('The verified standby index location differs.')
    expected={key:value for key,value in current.items() if key!='snapshot'}
    if json.loads((snapshot/'_VERIFIED.json').read_text())!=expected:
        raise RuntimeError('The selected standby verification record differs.')
    created=dt.datetime.strptime(current['createdUtc'],'%Y%m%dT%H%M%SZ').replace(tzinfo=dt.timezone.utc)
    age=dt.datetime.now(dt.timezone.utc)-created
    if not -dt.timedelta(minutes=5)<=age<=dt.timedelta(hours=48):
        raise RuntimeError('A verified standby snapshot less than 48 hours old is required.')
    manifest=json.loads((snapshot/'manifest.json').read_text())
    if (manifest.get('format')!=FORMAT or manifest.get('scope')!='standby-only'
        or manifest.get('sourceHost')!='192.168.0.29' or manifest.get('createdUtc')!=current['createdUtc']):
        raise RuntimeError('The selected standby source manifest differs.')
    source=next(item for item in manifest['containers'] if item['Name']=='/plex')
    if source['Image']!=SOURCE_IMAGE:raise RuntimeError('The source Plex image changed; a version review is required.')
    return snapshot,current


def container():return json.loads(run('docker','inspect','plex-nas'))[0]


def validate_container(row):
    if (row['State']['Status']!='created' or row['State']['Running']
        or not row['State'].get('StartedAt','').startswith('0001-')):
        raise RuntimeError('NAS Plex has already been started; its current data was retained for review.')
    if (row['Config']['Image']!=IMAGE or (row['Config'].get('Labels') or {}).get('com.sawdoctor.plex-preparation')!=PREPARED
        or row['HostConfig']['NetworkMode']!='host' or row['HostConfig']['RestartPolicy']['Name']!='no'):
        raise RuntimeError('The prepared NAS Plex configuration differs.')
    expected={'/config':DATA/'config','/flora-test-library':DATA/'flora-test-library','/scratch':SCRATCH,
        '/mnt/media':LIBRARY,'/mnt/nzbdav':Path('/mnt/nzbdav'),'/torbox-cams':Path('/mnt/torbox-media/movies')}
    actual={item['Destination']:Path(item['Source']) for item in row['Mounts'] if item['Type']=='bind'}
    if actual!=expected or len(row['Mounts'])!=6:
        raise RuntimeError('A prepared NAS Plex media binding differs.')
    identities=json.loads((STACK/'image-identities.json').read_text())
    if identities['plex']['source']!=SOURCE_IMAGE or identities['plex']['nas']!=row['Image']:
        raise RuntimeError('The prepared NAS Plex image identity differs.')


def media_paths(root):
    result={}
    for category in ('movies','movies-4k','tv'):
        for directory,folders,files in os.walk(root/category,followlinks=False):
            parent=Path(directory)
            folders[:]=[name for name in folders if not (parent/name).is_symlink()]
            for name in files:
                path=parent/name
                if path.suffix.lower() not in {'.mkv','.mp4','.avi','.m4v','.ts','.strm','.mov'}:continue
                result[str(path.relative_to(root))]=os.readlink(path) if path.is_symlink() else '<regular-file>'
    return result


def coverage(snapshot):
    source=media_paths(snapshot/'data/library');nas=media_paths(LIBRARY)
    return {'sourceVideoPaths':len(source),'matchingNasPaths':sum(nas.get(name)==value for name,value in source.items()),
        'sourcePathsAbsentOnNas':len(source.keys()-nas.keys()),'nasOnlyPaths':len(nas.keys()-source.keys()),
        'differentLinkTargets':sum(name in nas and nas[name]!=value for name,value in source.items())}


def preparation_marker(root):
    marker=root/'.prepared.json'
    if root.is_symlink() or marker.is_symlink():raise RuntimeError('An unexpected symbolic Plex data path was retained.')
    value=json.loads(marker.read_text())
    if value.get('format')!=PREPARED:raise RuntimeError('Unrecognised Plex preparation data was retained.')
    return value


def identity(root):
    value=ET.parse(root/'config'/PREFS).getroot().attrib.get('MachineIdentifier')
    if not value:raise RuntimeError('A copied Plex server identity is unavailable.')
    return value


def swap(work):
    if RECOVERY.exists():raise RuntimeError('A Plex refresh recovery copy already exists; existing data was retained.')
    RECOVERY.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
    DATA.rename(RECOVERY)
    try:work.rename(DATA)
    except BaseException:
        if not DATA.exists():RECOVERY.rename(DATA)
        raise


def refresh():
    if not SSD.is_mount() or not SCRATCH.is_mount():raise RuntimeError('The NAS appdata and scratch filesystems must be mounted.')
    say('Waiting for the NAS backup and standby snapshot locks...')
    with LOCK.open('a') as backup_lock,(BASE/'.run.lock').open('a') as standby_lock:
        fcntl.flock(backup_lock,fcntl.LOCK_EX);fcntl.flock(standby_lock,fcntl.LOCK_EX)
        before=container();validate_container(before)
        if not DATA.exists() and RECOVERY.is_dir() and not RECOVERY.is_symlink():
            preparation_marker(RECOVERY);RECOVERY.rename(DATA)
            say('Restored the prior prepared data after an interrupted directory swap.')
        old_marker=preparation_marker(DATA)
        for path in DATA.parent.glob('.plex-standby-*'):
            owner=path/'.standby-work-owner'
            if (path.is_dir() and not path.is_symlink() and not path.is_mount()
                and owner.is_file() and not owner.is_symlink() and owner.read_text()==SIGNATURE):shutil.rmtree(path)
        snapshot,current=latest_snapshot();helper=preparation_helper(snapshot)
        marker=DATA/'.standby-refreshed.json'
        if marker.exists():
            saved=json.loads(marker.read_text())
            if saved.get('format')!=SIGNATURE or saved.get('sourceCreatedUtc')!=current['createdUtc']:
                raise RuntimeError('NAS Plex was refreshed from a different standby snapshot; its data was retained for review.')
            helper.check_copied_files(DATA)
            say('NAS Plex already has this verified standby snapshot and remains stopped.');return
        size=sum(int(run('du','-sbx','--',str(snapshot/'data'/name)).split()[0]) for name in ('plex-config','flora-test-library'))
        if shutil.disk_usage(DATA.parent).free<size+2*1024**3:raise RuntimeError('More free NAS SSD space is required for the Plex preparation copy.')
        with tempfile.TemporaryDirectory(prefix='.plex-standby-',dir=DATA.parent) as temporary:
            parent=Path(temporary);atomic(parent/'.standby-work-owner',SIGNATURE)
            work=parent/'data';work.mkdir(mode=0o700)
            for source,target in (('plex-config','config'),('flora-test-library','flora-test-library')):
                destination=work/target;destination.mkdir(mode=0o700)
                say('Copying verified standby Plex data: '+target+'...')
                run('rsync','-aHAX','--numeric-ids','--one-file-system','--no-devices','--no-specials',
                    '--',str(snapshot/'data'/source)+'/',str(destination)+'/',timeout=3600)
            say('Verifying every copied Plex/Flora regular file against the standby checksums...')
            helper.check_copied_files(work)
            if identity(work)!=identity(DATA):raise RuntimeError('The copied Plex server identity differs; existing NAS data was retained.')
            report=coverage(snapshot);say('Read-only video-path comparison: '+json.dumps(report,sort_keys=True))
            atomic(work/'.prepared.json',json.dumps(old_marker,indent=2)+'\n')
            atomic(work/'.standby-refreshed.json',json.dumps({'format':SIGNATURE,'sourceCreatedUtc':current['createdUtc'],
                'sourceArchiveSha256':current['sha256'],'coverage':report},indent=2)+'\n')
            latest=container();validate_container(latest)
            if latest['Id']!=before['Id']:raise RuntimeError('The NAS Plex container changed during preparation.')
            swap(work)
        after=container();validate_container(after)
        if after['Id']!=before['Id']:raise RuntimeError('The NAS Plex container identity changed during preparation.')
    say('NAS PLEX STANDBY DATA READY: '+current['createdUtc']+'.')
    say('Latest copied database, preferences, history, identity and Flora links verified. Plex remains created/stopped.')
    say('One prior prepared-data copy is retained in compose/plex-nas/recovery/before-standby-refresh.')
    say('Source-vs-NAS media differences above are reported for the coordinated trial; the live NAS media library was not replaced.')


def main():
    os.umask(0o077)
    if os.geteuid()!=0 or 'inet 192.168.0.220/' not in run('ip','-4','addr','show'):
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220.')
    if sys.argv[1:]==['refresh']:refresh();return
    if sys.argv[1:]:raise RuntimeError('Unknown Plex refresh operation.')
    if run('systemctl','is-active','nas-plex-standby-refresh.service',allowed=(0,3,4)).strip() in ('active','activating'):
        say('NAS Plex standby preparation is already running.');return
    source=globals().get('INSTALL_SOURCE')
    if not source:raise RuntimeError('Use the complete provided Plex refresh command.')
    if WORKER.exists() and (WORKER.is_symlink() or SIGNATURE not in WORKER.read_text()):
        raise RuntimeError('An unrelated runtime helper was retained.')
    atomic(WORKER,source,0o700)
    run('systemctl','reset-failed','nas-plex-standby-refresh.service',allowed=(0,1))
    run('systemd-run','--unit=nas-plex-standby-refresh','--collect',
        '--description=Refresh stopped NAS Plex from verified standby data','/usr/bin/python3','-u',str(WORKER),'refresh')
    say('NAS Plex standby refresh started in the background. Closing SSH is safe.')
    say('Check: sudo journalctl -u nas-plex-standby-refresh.service -n 20 --no-pager -o cat')


if __name__=='__main__':
    try:main()
    except RuntimeError as error:raise SystemExit('STOP: '+str(error))
    except Exception as error:raise SystemExit('STOP: Plex standby preparation failed ('+type(error).__name__+'); private details were withheld.')
