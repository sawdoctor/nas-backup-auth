#!/usr/bin/env python3
"""Read-only comparison of prepared Plex media paths and NAS backing-file metadata."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

SSD=Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
DATA=SSD/'appdata/plex-nas'
LIBRARY=SSD/'appdata/infinidysk-nas/library'
SNAPSHOTS=SSD/'migration/nightly-standby/snapshots'
SIGNATURE='Sawdoctor NAS Plex standby refresh v1'
FORMAT='sawdoctor-migration-standby-v1'
EXTENSIONS={'.mkv','.mp4','.avi','.m4v','.ts','.strm','.mov'}


def paths(root):
    result={}
    for category in ('movies','movies-4k','tv'):
        for directory,folders,files in os.walk(root/category,followlinks=False):
            parent=Path(directory)
            folders[:]=[name for name in folders if not (parent/name).is_symlink()]
            for name in files:
                path=parent/name
                if path.suffix.lower() in EXTENSIONS:
                    result[str(path.relative_to(root))]=os.readlink(path) if path.is_symlink() else None
    return result


def target_for(relative,target):
    if target is None:return None
    value=Path(os.path.normpath(os.path.join('/mnt/media',str(Path(relative).parent),target)))
    return value if value.is_relative_to('/mnt/nzbdav') else None


def metadata_available(target):
    try:
        result=subprocess.run(['stat','-L','--printf=%f:%s','--',str(target)],
            text=True,capture_output=True,timeout=6)
    except subprocess.TimeoutExpired:return 'timeout'
    if result.returncode:return 'unavailable'
    try:
        mode,size=result.stdout.strip().split(':',1)
        return 'available' if stat.S_ISREG(int(mode,16)) and int(size)>0 else 'not_regular'
    except ValueError:return 'unavailable'


def compare(source,nas,probe=metadata_available):
    missing=sorted(source.keys()-nas.keys());nas_only=sorted(nas.keys()-source.keys())
    counts={key:0 for key in ('available','unavailable','timeout','not_regular','unsupported')}
    findings=[]
    for index,relative in enumerate(missing,1):
        target=target_for(relative,source[relative])
        status=probe(target) if target is not None else 'unsupported'
        counts[status]+=1;findings.append({'path':relative,'status':status})
        if index%10==0:print('Checked missing-path metadata: '+str(index)+'/'+str(len(missing)),flush=True)
    summary={'sourceVideoPaths':len(source),'matchingNasPaths':sum(name in nas and nas[name]==value for name,value in source.items()),
        'sourcePathsAbsentOnNas':len(missing),'nasOnlyPaths':len(nas_only),
        'differentLinkTargets':sum(name in nas and nas[name]!=value for name,value in source.items()),
        'missingPathBackingMetadata':counts}
    return summary,findings,nas_only


def audit():
    marker_path=DATA/'.standby-refreshed.json'
    if DATA.is_symlink() or marker_path.is_symlink():raise RuntimeError('An unexpected symbolic Plex preparation path was retained.')
    marker=json.loads(marker_path.read_text())
    if marker.get('format')!=SIGNATURE:raise RuntimeError('The completed Plex standby refresh is required.')
    stamp=marker['sourceCreatedUtc']
    if not isinstance(stamp,str) or len(stamp)!=16 or any(character not in '0123456789TZ' for character in stamp):
        raise RuntimeError('The prepared Plex snapshot timestamp is invalid.')
    snapshot=SNAPSHOTS/stamp
    if snapshot.is_symlink() or not snapshot.is_dir():raise RuntimeError('The prepared Plex snapshot is no longer retained; a fresh preparation review is needed.')
    verified=json.loads((snapshot/'_VERIFIED.json').read_text())
    if (verified.get('format')!=FORMAT or verified.get('createdUtc')!=stamp
        or verified.get('sha256')!=marker.get('sourceArchiveSha256')):
        raise RuntimeError('The Plex preparation and standby verification records differ.')
    live=json.loads(subprocess.check_output(['docker','inspect','plex-nas'],text=True))[0]
    if live['State']['Running']:raise RuntimeError('Keep NAS Plex stopped while preparing its first trial.')
    mount=subprocess.check_output(['findmnt','-rn','--mountpoint','/mnt/nzbdav','-o','FSTYPE,SOURCE'],text=True).split()
    if mount!=['fuse.rclone','nzbdav:']:raise RuntimeError('The expected NAS InfiniDysk mount is unavailable.')
    source=paths(snapshot/'data/library');nas=paths(LIBRARY)
    summary,findings,nas_only=compare(source,nas)
    print('READ-ONLY NAS MEDIA AUDIT: '+json.dumps(summary,sort_keys=True),flush=True)
    print('Missing source paths (status describes NAS backing-file metadata):',flush=True)
    for item in findings:print(item['status']+' | '+item['path'],flush=True)
    print('NAS-only paths retained:',flush=True)
    for relative in nas_only[:30]:print(relative,flush=True)
    if len(nas_only)>30:print('Additional NAS-only paths: '+str(len(nas_only)-30),flush=True)
    print('No library links, databases, containers or settings were changed. No media payload was read.',flush=True)


if __name__=='__main__':
    try:
        if os.geteuid()!=0 or 'inet 192.168.0.220/' not in subprocess.check_output(['ip','-4','addr','show'],text=True):
            raise RuntimeError('Run with sudo on the NAS at 192.168.0.220.')
        if not SSD.is_mount():raise RuntimeError('The NAS appdata filesystem must be mounted.')
        audit()
    except RuntimeError as error:raise SystemExit('STOP: '+str(error))
