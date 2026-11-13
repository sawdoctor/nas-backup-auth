#!/usr/bin/env python3
"""Validate frozen Plex identifiers and finish the already-swapped NAS import.

Plex /identity publishes ProcessedMachineIdentifier. MachineIdentifier remains
separately bound to the source hold. No DB import, claim, scan or root rename.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import subprocess
import sys
import tarfile
import time
import urllib.request
import xml.etree.ElementTree as ET

APP = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
BACKUP = Path('/srv/dev-disk-by-uuid-631e3391-6a42-4158-9aa4-f7718ba0e7e9')
BASE = APP / 'compose/production-cutover'
SELF = BASE / 'finish-plex-identity.py'
EVIDENCE = BASE / 'plex-frozen-identity.json'
NATIVE_SHA = 'ae59ce0542f9c72acc84cbc1888c397fb6a5c2bd730f6e101d2e3da4f62669f1'
STABLE_SHA = '8987e6bdcc2d4bb4d292f92c5fdb2d06663a1d5fecdc8a812e02f93e6a78d4ba'
PLAN_SHA = 'bf4176032a44b7d3e113fbeb212acb5f0bd895f391c81f7543188d3db8779b10'
UNIT = 'nas-production-finish.service'


def say(value): print(value, flush=True)
def sha(value): return hashlib.sha256(value).hexdigest()


def load(path, expected, name):
    if any(p.is_symlink() for p in (path, *path.parents)) or sha(path.read_bytes()) != expected:
        raise RuntimeError('An accepted controller differs: ' + path.name)
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


def identity_fields(body):
    root = ET.fromstring(body)
    raw, processed = root.get('MachineIdentifier', ''), root.get('ProcessedMachineIdentifier', '')
    if not raw or not re.fullmatch(r'[a-fA-F0-9]{40}', processed):
        raise RuntimeError('Plex stored identity fields are incomplete; no identity was generated.')
    return {'machineSha256': sha(raw.encode()), 'processedSha256': sha(processed.encode())}


def validate_identity(prefs, evidence, proof, api=None):
    values = identity_fields(prefs)
    if (values['machineSha256'] != proof['identitySha256']
            or values['machineSha256'] != evidence['machineSha256']
            or values['processedSha256'] != evidence['processedSha256']):
        raise RuntimeError('Stored Plex identifiers differ from the verified frozen source; startup blocked.')
    if api is not None:
        actual = ET.fromstring(api).get('machineIdentifier', '')
        if sha(actual.encode()) != evidence['processedSha256']:
            raise RuntimeError('Plex API processed identity differs from the frozen source; startup acceptance blocked.')
    return values


def source_preferences(native, state):
    raw = Path(state['raw']); relative = 'data/plex-config/' + native.PREFS.as_posix()
    core = native.helpers()['core']; expected = None
    checks = raw / 'SHA256SUMS'; native.safe(checks)
    with checks.open('r', encoding='utf-8', errors='surrogateescape') as stream:
        for line in stream:
            if len(line) > 65536: raise RuntimeError('An oversized frozen checksum entry was retained.')
            name, digest = core.parse_checksum(line)
            if name == relative:
                if expected is not None: raise RuntimeError('A duplicate frozen preferences checksum was retained.')
                expected = digest
    if expected is None: raise RuntimeError('Original frozen Plex preferences checksum is unavailable.')
    archive = BACKUP / 'migration/production-handover/frozen' / state['proof']['cutoverId'] / 'export.tar.zst'
    native.safe(archive)
    if archive.stat().st_size != state['proof']['archiveBytes']:
        raise RuntimeError('The retained verified frozen archive size differs.')
    say('Reading only the original Plex preferences from the retained frozen archive...')
    process = subprocess.Popen(['zstd', '-dc', '--', str(archive)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    body = None
    try:
        with tarfile.open(fileobj=process.stdout, mode='r|') as source:
            for member in source:
                if PurePosixPath(member.name) != PurePosixPath(relative): continue
                if not member.isfile() or not 0 < member.size <= 2 * 1024**2:
                    raise RuntimeError('The original Plex preferences member is not a bounded regular file.')
                with source.extractfile(member) as stream: body = stream.read(2 * 1024**2 + 1)
                break
        if body is None or len(body) > 2 * 1024**2 or sha(body) != expected:
            raise RuntimeError('Original frozen Plex preferences failed their verified checksum.')
        values = identity_fields(body)
        if values['machineSha256'] != state['proof']['identitySha256']:
            raise RuntimeError('Frozen preferences do not match the held source identity.')
        evidence = {'format': 'sawdoctor-frozen-plex-identity-v1', 'cutoverId': state['proof']['cutoverId'],
                    'preferencesSha256': expected, **values}
        if EVIDENCE.exists() and json.loads(native.read(EVIDENCE)) != evidence:
            raise RuntimeError('An earlier frozen Plex identity evidence record differs.')
        native.atomic(EVIDENCE, evidence)
        return evidence
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.terminate()
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=10)


def evidence_for(native, proof):
    value = json.loads(native.read(EVIDENCE))
    if (value.get('format') != 'sawdoctor-frozen-plex-identity-v1'
            or value.get('cutoverId') != proof['cutoverId'] or value.get('machineSha256') != proof['identitySha256']):
        raise RuntimeError('Frozen Plex identity evidence is unavailable for this operation.')
    return value


def wait_plex(native, config, proof):
    evidence = evidence_for(native, proof)
    validate_identity(native.read(config / native.PREFS), evidence, proof)
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs): return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    deadline = time.monotonic() + 120
    while True:
        try:
            with opener.open('http://127.0.0.1:32400/identity', timeout=3) as response:
                result = response.read(65536)
            validate_identity(native.read(config / native.PREFS), evidence, proof, result)
            say('Plex stored and API processed identities match the verified frozen source.')
            return
        except OSError:
            if time.monotonic() >= deadline: raise RuntimeError('Imported Plex did not become ready; data and source hold retained.')
            time.sleep(2)


def controllers():
    native = load(BASE / 'worker.py', NATIVE_SHA, 'native_plex_finish')
    stable = load(BASE / 'stable-mount-runner.py', STABLE_SHA, 'stable_plex_finish')
    plan = native.approved(PLAN_SHA); native.launch_finish = native.run
    stable.install_overrides(native, plan, BASE / 'stable-mount-runner.py', 'nas')
    native.wait_plex = lambda config, proof: wait_plex(native, config, proof)
    old_boot = native.plex_boot_text
    def boot_text():
        text = old_boot()
        old = ('ExecStart=/usr/bin/python3 ' + str(BASE / 'stable-mount-runner.py')
               + ' --boot-plex --runner-sha ' + STABLE_SHA + '\n')
        if text.count(old) != 1: raise RuntimeError('The accepted Plex boot command differs.')
        return text.replace(old, 'ExecStart=/usr/bin/python3 ' + str(SELF)
                            + ' --boot-plex --self-sha ' + native.digest(SELF) + '\n')
    native.plex_boot_text = boot_text
    return native, plan


def validate_swaps(native, plan, state):
    if (state.get('format') != native.FORMAT or state.get('phase') != 'importing'
            or state.get('nasPlanSha256') != PLAN_SHA or len(state.get('roots', [])) != len(plan['liveRoots'])):
        raise RuntimeError('The complete uncommitted root-swap journal is required; do not repeat data import.')
    if {r['live'] for r in state['roots']} != set(plan['liveRoots'].values()):
        raise RuntimeError('The root-swap journal does not cover the accepted live roots exactly.')
    folder = Path(state['folder']); native.safe(folder)
    if folder != BASE / state['proof']['cutoverId']: raise RuntimeError('The operation folder identity differs.')
    marker = json.loads(native.read(native.ACTIVE))
    if marker != {'format': native.FORMAT, 'cutoverId': state['proof']['cutoverId']}: raise RuntimeError('The import guard identity differs.')
    for item in state['roots']:
        if item.get('phase') != 'installed': raise RuntimeError('A root-swap journal entry is incomplete.')
        live, before, incoming = map(Path, (item['live'], item['before'], item['incoming']))
        for path in (live, before, incoming): native.safe(path)
        if not before.is_relative_to(folder / 'rollback') or not incoming.is_relative_to(folder / 'prepared'):
            raise RuntimeError('A retained root location differs.')
        if not live.is_dir() or not before.is_dir() or incoming.exists():
            raise RuntimeError('A live/retained root does not match its completed rename journal.')
    for name in state['units']:
        if native.read(native.UNITS / (name + '.d') / native.DROPIN) != native.CONDITION.encode():
            raise RuntimeError('A persistent import startup guard differs.')
    for item in state['composes']:
        if native.digest(Path(item['live'])) != item['afterSha256'] or native.digest(Path(item['candidate'])) != item['afterSha256']:
            raise RuntimeError('A deployed reviewed core definition changed; finish stopped.')
    if native.digest(Path(plan['plexCompose'])) != plan['plexComposeSha256']:
        raise RuntimeError('The accepted Plex definition changed.')


def finish(native, plan):
    with native.lock(BASE / '.run.lock'):
        state = json.loads(native.read(native.STATE)); validate_swaps(native, plan, state); native.held(state['proof'])
        rows = native.catalog()
        if any(rows[name]['State']['Running'] or rows[name]['HostConfig']['RestartPolicy']['Name'] != 'no' for name in plan['affected']):
            raise RuntimeError('An affected writer is running or restartable; finish precondition needs review.')
        evidence = source_preferences(native, state)
        config = Path(plan['liveRoots']['plex'])
        validate_identity(native.read(config / native.PREFS), evidence, state['proof'])
        say('Completed data swaps and both frozen Plex identity fields verified. Reusing current live databases; no copy, claim or scan.')
        h = native.helpers(); core = h['core']; infini = core.NAMES['nzbdav']
        infini_project = rows[infini]['Config']['Labels']['com.docker.compose.project']
        infini_service = rows[infini]['Config']['Labels']['com.docker.compose.service']
        plex = rows['plex-nas']
        if plex['Image'] != plan['nasImages']['plex'] or plex['Mounts'] != plan['containers']['plex-nas']['Mounts']:
            raise RuntimeError('The stopped Plex image/bindings differ; finish stopped.')
        with native.lock(native.BACKUP_LOCK):
            native.held(state['proof'])
            for item in state['composes']:
                if item['project'] == infini_project:
                    native.run(*native.start_command(item), infini_service, timeout=180)
            h['recovery'].backend_ready(seconds=90)
        # Starting a mount (or its dependent refresh) must never hold BACKUP_LOCK.
        mounts = h['recovery'].host_mounts()
        if '/mnt/nzbdav' not in mounts or (mounts['/mnt/nzbdav']['type'], mounts['/mnt/nzbdav']['source']) != ('fuse.rclone','nzbdav:'):
            say('Starting the NAS media mount outside the backup lock...')
            native.run('systemctl', 'start', native.RCLONE, timeout=300)
        with native.lock(native.BACKUP_LOCK):
            native.held(state['proof'])
            for item in state['composes']:
                services = [s for s in item['services'] if not (item['project'] == infini_project and s == infini_service)]
                if services: native.run(*native.start_command(item), *services, timeout=240)
            for name in plan['affected']:
                if name not in core.NAMES.values() and name not in ('plex-nas','dockmon') and plan['containers'][name]['State']['Running']:
                    native.run('docker', 'start', name, timeout=90)
            say('Starting NAS Plex with its existing imported configuration and the corrected processed-identity check...')
            native.held(state['proof']); native.run('docker','start','plex-nas',timeout=90)
            native.wait_plex(config, state['proof'])
            current = native.catalog(); mounts = h['recovery'].host_mounts()
            for name in (*core.NAMES.values(), 'plex-nas', 'silo-nas-silo-1'):
                if (not current[name]['State']['Running'] or not h['recovery'].ready(current[name],mounts)
                        or h['recovery'].stale_bindings(current[name],mounts)):
                    raise RuntimeError('A production media client is stopped or sees an old FUSE binding: ' + name)
            native.held(state['proof']); state['phase']='awaiting-acceptance'; state['plexIdentityValidated']=True
            native.atomic(native.STATE,state)
        say('CURRENT PLEX AND CORE IMPORTED ON NAS. Frozen stored/API identities and current FUSE bindings verified.')
        say('Source remains held; NAS automation and Dockmon remain held until acceptance. Router and direct remote playback checks are next.')


def main():
    os.umask(0o077)
    if os.geteuid()!=0 or 'inet 192.168.0.220/' not in subprocess.check_output(['ip','-4','addr','show'],text=True,timeout=15):
        raise RuntimeError('Run with sudo on the NAS.')
    if not all(path.is_mount() for path in (APP, BACKUP, Path('/srv/dev-disk-by-uuid-1f12a22e-5cfe-4b02-8d4b-48e9bf5fec6a'))):
        raise RuntimeError('All three NAS SSD mounts are required before finishing the import.')
    native,plan=controllers();args=sys.argv[1:]
    if '--self-sha' in args:
        if args[-2]!='--self-sha' or native.digest(SELF)!=args[-1]:raise RuntimeError('The pinned identity finisher changed.')
        args=args[:-2]
    try:
        if args==['--boot-plex']:
            with native.lock(native.BACKUP_LOCK): native.boot_plex()
            return
        if args==['--commit-core',PLAN_SHA]:
            with native.lock(BASE/'.run.lock'):native.commit_core(PLAN_SHA)
            return
        if len(args)==2 and args[0]=='--worker':
            if native.digest(SELF)!=args[1]:raise RuntimeError('The pinned identity finisher changed.')
            def terminate(signum,frame):raise RuntimeError('NAS identity finish interrupted; retaining writers stopped.')
            signal.signal(signal.SIGTERM,terminate);finish(native,plan);return
        if args:raise RuntimeError('Unsupported identity finish action.')
        source=globals().get('INSTALL_SOURCE')
        if not isinstance(source,str):raise RuntimeError('The complete pinned identity finisher is required.')
        with native.lock(BASE/'.run.lock'):
            state=json.loads(native.read(native.STATE));validate_swaps(native,plan,state);native.held(state['proof'])
            if SELF.exists() and native.read(SELF)!=source.encode():raise RuntimeError('A different identity finisher was retained.')
            if not SELF.exists():native.atomic(SELF,source.encode())
        native.launch_finish('systemd-run','--unit='+UNIT.removesuffix('.service'),'--collect',
            '--description=Finish current NAS Plex import with frozen processed identity verification',
            '--property=Type=exec','--property=UMask=0077','--property=RuntimeMaxSec=2h',
            '--property=TimeoutStopSec=8min','--property=KillMode=mixed',
            '/usr/bin/python3',str(SELF),'--worker',native.digest(SELF))
        say('Guarded Plex identity finish started. Follow '+UNIT+'. No data import or forced scan is repeated.')
    except Exception:
        if len(args)==2 and args[0]=='--worker' and native.ACTIVE.exists():
            try:native.recover()
            except Exception:say('NAS finish recovery needs review; source hold and retained data remain.')
        raise


if __name__=='__main__':
    try:main()
    except Exception as error:
        raise SystemExit('STOP: '+(str(error) if isinstance(error,RuntimeError) else 'NAS Plex finish failed ('+type(error).__name__+'); private details retained.'))
