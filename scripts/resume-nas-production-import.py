#!/usr/bin/env python3
"""Resume the verified NAS import interrupted before its first root rename.

Stop the book-stack dependent and its media mount before acquiring the shared
backup lock. Reuse the accepted adapted payload/plans and native transaction.
No plan edit, new archive, transfer, image pull or forced scan is performed.
"""
import copy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

APP = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
BASE = APP / 'compose/production-cutover'
RUNNER = BASE / 'stable-mount-runner.py'
RUNNER_SHA = '8987e6bdcc2d4bb4d292f92c5fdb2d06663a1d5fecdc8a812e02f93e6a78d4ba'
WORKER = BASE / 'worker.py'
WORKER_SHA = 'ae59ce0542f9c72acc84cbc1888c397fb6a5c2bd730f6e101d2e3da4f62669f1'
PLAN_SHA = 'bf4176032a44b7d3e113fbeb212acb5f0bd895f391c81f7543188d3db8779b10'
SELF = BASE / 'resume-after-mount-stop.py'
UNIT = 'nas-production-resume.service'
BOOKS = 'nas-books.service'


def say(value): print(value, flush=True)


def load(path, expected, name):
    import hashlib
    if any(p.is_symlink() for p in (path, *path.parents)) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise RuntimeError('An accepted recovery controller/input differs: ' + path.name)
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def controllers():
    stable = load(RUNNER, RUNNER_SHA, 'accepted_stable_mounts')
    native = load(WORKER, WORKER_SHA, 'accepted_nas_transaction')
    plan = native.approved(PLAN_SHA)
    native.launch_recovery = native.run
    stable.install_overrides(native, plan, RUNNER, 'nas')
    return stable, native, plan


def service_idle(native, name):
    state = native.unit_state(name)
    return state.get('ActiveState') in ('inactive', 'failed') and state.get('MainPID', '0') == '0'


def validate_recovery(native, plan, state):
    if (state.get('format') != native.FORMAT or state.get('phase') != 'importing'
            or state.get('nasPlanSha256') != PLAN_SHA or state.get('roots') != []):
        raise RuntimeError('Recovery requires the recorded pre-swap importing state; existing data retained.')
    folder = Path(state['folder']); native.safe(folder)
    if folder != BASE / state['proof']['cutoverId'] or Path(state['prepared']) != folder / 'prepared':
        raise RuntimeError('The operation/prepared payload location differs.')
    if (folder / 'rollback').exists() or (folder / 'dockmon-before.db').exists():
        raise RuntimeError('A later transaction stage exists; do not replay the pre-swap recovery.')
    marker = json.loads(native.read(native.ACTIVE))
    if marker != {'format': native.FORMAT, 'cutoverId': state['proof']['cutoverId']}:
        raise RuntimeError('The persistent import guard does not belong to this operation.')
    if not state.get('units') or BOOKS not in state['units']:
        raise RuntimeError('Original NAS automation/book-service ownership is unavailable.')
    for name in state['units']:
        path = native.UNITS / (name + '.d') / native.DROPIN
        if native.read(path) != native.CONDITION.encode(): raise RuntimeError('An import startup guard changed: ' + name)
    for name, live in plan['liveRoots'].items():
        old, incoming = Path(live), folder / 'prepared' / name
        for path in (old, incoming):
            native.safe(path)
            if not path.is_dir() or path.is_mount() or path.stat().st_dev != APP.stat().st_dev:
                raise RuntimeError('A retained live/prepared root is unavailable: ' + name)
    if not state.get('composes'): raise RuntimeError('The completed private Compose adaptations are unavailable.')
    for item in state['composes']:
        if (native.digest(Path(item['live'])) != item['sourceFiles'][item['live']]
                or native.digest(Path(item['before'])) != item['sourceFiles'][item['live']]
                or native.digest(Path(item['candidate'])) != item['afterSha256']):
            raise RuntimeError('A live/before/adapted Compose input changed; recovery stopped.')
    if native.digest(Path(plan['plexCompose'])) != plan['plexComposeSha256']:
        raise RuntimeError('The accepted NAS Plex stack changed.')


def comparable_stopped_row(native, plan, name, row):
    if row['State']['Running'] or row['HostConfig']['RestartPolicy'].get('Name') != 'no':
        raise RuntimeError('An affected NAS writer is running or has automatic restart enabled: ' + name)
    # The interrupted controller intentionally changed only RestartPolicy.
    # Restore that single known field in a disposable comparison object;
    # identity, images, full config, all mounts and every other HostConfig field
    # still have to equal the original accepted plan fingerprint.
    comparison = copy.deepcopy(row)
    comparison['HostConfig']['RestartPolicy'] = copy.deepcopy(plan['containers'][name]['HostConfig']['RestartPolicy'])
    if native.fingerprint(comparison) != plan['fingerprints'][name]:
        raise RuntimeError('An affected NAS runtime differs beyond its controlled restart policy: ' + name)
    return comparison


def resume(native, plan):
    with native.lock(BASE / '.run.lock'):
        state = json.loads(native.read(native.STATE)); validate_recovery(native, plan, state)
        native.held(state['proof'])
        rows = native.catalog()
        for name in plan['affected']: comparable_stopped_row(native, plan, name, rows[name])
        env = dict(v.split('=', 1) for v in plan['containers']['plex-nas']['Config'].get('Env', []) if '=' in v)
        scratch = native.SCRATCH / 'plex-transcode'; native.safe(scratch)
        if scratch.exists() and (not scratch.is_dir() or scratch.stat().st_uid != int(env['PUID'])):
            raise RuntimeError('The existing Plex scratch ownership needs review before any data swap.')
        say('Recovery verified: zero root swaps, original live roots, adapted incoming roots and unchanged Compose files.')
        say('Stopping the book-stack dependent and InfiniDysk mount outside the shared backup lock...')
        native.run('systemctl', 'stop', BOOKS, native.RCLONE, timeout=420)
        if not all(service_idle(native, name) for name in (BOOKS, native.RCLONE)):
            raise RuntimeError('The book-stack/mount stop is still pending; no root swap was attempted.')
        state = json.loads(native.read(native.STATE)); validate_recovery(native, plan, state)
        native.held(state['proof'])
        rows = native.catalog()
        for name in plan['affected']: comparable_stopped_row(native, plan, name, rows[name])

        native_read = native.read; native_fingerprint = native.fingerprint; native_run = native.run
        state_supplied = False

        def read(path, *args, **kwargs):
            nonlocal state_supplied
            body = native_read(path, *args, **kwargs)
            if path == native.STATE and not state_supplied:
                value = json.loads(body)
                if value.get('phase') != 'importing' or value.get('roots') != []:
                    raise RuntimeError('The recovery state changed before transaction entry.')
                value['phase'] = 'adapted'; state_supplied = True
                return (json.dumps(value) + '\n').encode()
            return body

        def fingerprint(row):
            # Native activate performs its original strict comparison once,
            # before starting production; permit only the recorded restart=no.
            name = row['Name'].lstrip('/')
            if name not in plan['affected']: return native_fingerprint(row)
            comparison = copy.deepcopy(row)
            if row['State']['Running'] or row['HostConfig']['RestartPolicy'].get('Name') != 'no':
                raise RuntimeError('An affected NAS writer restarted before recovery: ' + name)
            comparison['HostConfig']['RestartPolicy'] = copy.deepcopy(plan['containers'][name]['HostConfig']['RestartPolicy'])
            return native_fingerprint(comparison)

        def run(*args, **kwargs):
            if args[:3] == ('systemctl', 'stop', native.RCLONE):
                # Both services were stopped above, without BACKUP_LOCK. This
                # must be a no-op at the native transaction's old stop point.
                if not all(service_idle(native, n) for n in (BOOKS, native.RCLONE)):
                    raise RuntimeError('The stopped mount dependency changed; no blocking stop under the backup lock is allowed.')
                say('Mount dependency stop already complete; proceeding with retained-root transaction.')
                return ''
            if args and args[0] == 'sync': say('Fresh data roots installed and retained rollback roots recorded; flushing application SSD...')
            if args[:3] == ('systemctl', 'start', native.RCLONE): say('Starting the new InfiniDysk media mount outside the backup lock...')
            if args[:3] == ('docker', 'start', 'plex-nas'): say('Starting the current source Plex configuration on the NAS...')
            return native_run(*args, **kwargs)

        native.read = read; native.fingerprint = fingerprint; native.run = run
        say('Resuming the original verified import using the existing adapted payload; no recopy or preparation.')
        native.activate(PLAN_SHA)


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in subprocess.check_output(['ip', '-4', 'addr', 'show'], text=True, timeout=15):
        raise RuntimeError('Run with sudo on the NAS.')
    if not all(p.is_mount() for p in (APP, Path('/srv/dev-disk-by-uuid-631e3391-6a42-4158-9aa4-f7718ba0e7e9'),
                                     Path('/srv/dev-disk-by-uuid-1f12a22e-5cfe-4b02-8d4b-48e9bf5fec6a'))):
        raise RuntimeError('The three NAS SSD mounts are required.')
    stable, native, plan = controllers(); args = sys.argv[1:]
    try:
        if len(args) == 2 and args[0] == '--worker':
            if native.digest(SELF) != args[1]: raise RuntimeError('The pinned recovery worker changed.')
            def terminate(signum, frame): raise RuntimeError('NAS guarded resume interrupted; retaining affected writers stopped.')
            signal.signal(signal.SIGTERM, terminate)
            resume(native, plan); return
        if args: raise RuntimeError('Unsupported pre-swap recovery action.')
        source = globals().get('INSTALL_SOURCE')
        if not isinstance(source, str): raise RuntimeError('The complete pinned recovery installer is required.')
        with native.lock(BASE / '.run.lock'):
            state = json.loads(native.read(native.STATE)); validate_recovery(native, plan, state)
            native.held(state['proof'])
            if SELF.exists() and native.read(SELF) != source.encode(): raise RuntimeError('A different recovery worker was retained.')
            if not SELF.exists(): native.atomic(SELF, source.encode())
            record = BASE / 'pre-swap-timeout-recovery.json'
            if not record.exists(): native.atomic(record, {'format': 'sawdoctor-pre-swap-recovery-v1',
                'recordedUtc': dt.datetime.now(dt.timezone.utc).isoformat(), 'priorStateSha256': native.digest(native.STATE),
                'nasPlanSha256': PLAN_SHA, 'reason': 'mount stop waited on book-stack shared backup lock',
                'priorPhase': state['phase'], 'recordedRootSwaps': len(state['roots'])})
        native.launch_recovery('systemd-run', '--unit=' + UNIT.removesuffix('.service'), '--collect',
            '--description=Resume verified NAS production import after dependent mount stop',
            '--property=Type=exec', '--property=UMask=0077', '--property=RuntimeMaxSec=2h',
            '--property=TimeoutStopSec=8min', '--property=KillMode=mixed',
            '/usr/bin/python3', str(SELF), '--worker', native.digest(SELF))
        say('Guarded NAS import resume started. Follow ' + UNIT + '. Original plans and frozen archive retained.')
    except Exception:
        if len(args) == 2 and args[0] == '--worker' and native.ACTIVE.exists():
            try: native.recover()
            except Exception: say('NAS guarded recovery needs review; source hold and original data retained.')
        raise


if __name__ == '__main__':
    try: main()
    except Exception as error:
        raise SystemExit('STOP: ' + (str(error) if isinstance(error, RuntimeError)
                         else 'NAS guarded resume failed (' + type(error).__name__ + '); private details retained.'))
