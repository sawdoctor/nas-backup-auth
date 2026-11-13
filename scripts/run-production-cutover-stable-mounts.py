#!/usr/bin/env python3
"""Run the accepted paired controllers with order-independent mount records.

Keep both prepared plans and installed worker bytes unchanged. Normalize only
the top-level Mounts array order, only when every full mount object matches its
saved counterpart (including duplicates). All other native guards still run.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

APP = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
ROLES = {
    'source': {'address': '192.168.0.29', 'base': Path('/var/lib/sawdoctor-production-cutover'),
               'worker': 'fff1bf3685eea21660fb669e281c467c03d1a66be12e8b9475a1520a9fef13f4',
               'plan': '9e5f46c39b3831d8e7ce005313b5bcaa83a15fbc9824a2f23a46c1ba2e78d506'},
    'nas': {'address': '192.168.0.220', 'base': APP / 'compose/production-cutover',
            'worker': 'ae59ce0542f9c72acc84cbc1888c397fb6a5c2bd730f6e101d2e3da4f62669f1',
            'plan': 'bf4176032a44b7d3e113fbeb212acb5f0bd895f391c81f7543188d3db8779b10'},
}
IMAGES = {
    'nzbdav': '9024f89b6d7c661c92e06b8fa48bad2af319b05d2ba06496f2437842482d2ec6',
    'overseerr': 'd8fab675b55ad293ded98fd71efcfd46054cbad9746534ae1cc4794a88c0b3be',
    'plex': '0c2f1122a4275efeea953a9882359f3809b27279d3c3022392e8e610a2eccc67',
    'prowlarr': '50ccdde38e1ad0834cc05b7eae54e9734ac6af76a1780b99066dd18d37b9802d',
    'radarr': '51a9ac2a9eb47afc833541e5fd6c11b86eb9f810694c22fa2429e3078e9194b2',
    'radarr4k': '51a9ac2a9eb47afc833541e5fd6c11b86eb9f810694c22fa2429e3078e9194b2',
    'sonarr': '673dc4609a5672bc8e46069c86ffcea283a86b48d34a6c93d8da8c24a1b87571',
    'usenet-ultimate': '7a5a171c3fa1f66ef34169aab25ae7e278b6bd77188ff24cd91ae61b15a638bb',
}


def sha(data): return hashlib.sha256(data).hexdigest()


def read(path):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise RuntimeError('A symbolic controller/input path was retained.')
    if not path.is_file() or path.stat().st_size > 32 * 1024**2:
        raise RuntimeError('A bounded installed controller/plan is unavailable.')
    return path.read_bytes()


def canonical(mounts):
    if not isinstance(mounts, list) or any(not isinstance(m, dict) for m in mounts):
        raise RuntimeError('The Docker mount inventory format differs.')
    # Sorting the serialized records preserves every field, value and duplicate.
    return sorted(json.dumps(m, sort_keys=True, separators=(',', ':')) for m in mounts)


def normalize(rows, saved):
    changed = []
    for name, row in rows.items():
        if name not in saved: continue  # Native inventory/identity guards handle additions.
        before, current = saved[name]['Mounts'], row['Mounts']
        if canonical(before) != canonical(current):
            raise RuntimeError('A real mount record differs for ' + name + '; production retained.')
        if before != current:
            row['Mounts'] = before.copy(); changed.append(name)
    if changed:
        print('Order-only Docker mount differences confirmed: ' + ', '.join(changed)
              + '. Complete mount records match; prepared plans retained.', flush=True)
    return rows


def install_overrides(module, plan, runner, role):
    name = 'all_containers' if role == 'source' else 'catalog'
    inventory = getattr(module, name)
    setattr(module, name, lambda: normalize(inventory(), plan['containers']))
    native_run = module.run
    pinned_runner_sha = sha(read(runner))
    actions = {'--hold-worker'} if role == 'source' else {'--receive-worker', '--activate-worker'}

    def run(*args, **kwargs):
        if args and args[0] == 'systemd-run':
            values = list(args)
            try: index = values.index(str(module.WORKER))
            except ValueError: raise RuntimeError('An unexpected controller launch was retained.') from None
            if values[index + 1] not in actions:
                raise RuntimeError('An unexpected controller worker action was retained.')
            values[index] = str(runner)
            values.extend(['--runner-sha', pinned_runner_sha])
            args = tuple(values)
        return native_run(*args, **kwargs)

    module.run = run
    if role == 'nas':
        original_boot_text = module.plex_boot_text

        def boot_text():
            text = original_boot_text()
            old = 'ExecStart=/usr/bin/python3 ' + str(module.WORKER) + ' --boot-plex\n'
            if text.count(old) != 1: raise RuntimeError('The native Plex boot command differs.')
            return text.replace(old, 'ExecStart=/usr/bin/python3 ' + str(runner)
                                + ' --boot-plex --runner-sha ' + pinned_runner_sha + '\n')
        module.plex_boot_text = boot_text


def invoke_native(module, role, args):
    sys.argv = [str(module.WORKER), *args]
    try:
        module.main()
    except Exception:
        # Importing the native module bypasses its __main__ exception footer;
        # retain that footer's stopped-writer recovery on NAS worker failures.
        if role == 'nas' and module.ACTIVE.exists():
            try: module.recover()
            except Exception:
                print('NAS interrupted-import recovery needs review; source hold and original data retained.', flush=True)
        raise


def main():
    if os.geteuid() != 0: raise RuntimeError('Run with sudo on the intended migration host.')
    addresses = subprocess.check_output(['ip', '-4', 'addr', 'show'], text=True, timeout=15)
    roles = [name for name, value in ROLES.items() if 'inet ' + value['address'] + '/' in addresses]
    if len(roles) != 1: raise RuntimeError('The migration host identity is ambiguous or unavailable.')
    role = roles[0]; spec = ROLES[role]; base = spec['base']
    worker = base / 'worker.py'; body = read(worker); plan_body = read(base / 'plan.json')
    if sha(body) != spec['worker'] or sha(plan_body) != spec['plan']:
        raise RuntimeError('The original accepted controller/plan changed; retained.')
    plan = json.loads(plan_body)
    if role == 'source' and any(plan['catalog'][n]['Image'] != 'sha256:' + image for n, image in IMAGES.items()):
        raise RuntimeError('The source images differ from the prepared NAS handoff; source retained.')
    runner = base / 'stable-mount-runner.py'
    args = globals().get('CUTOVER_ACTION', sys.argv[1:])
    if not isinstance(args, list) or not args: raise RuntimeError('An explicit approved controller action is required.')
    if '--runner-sha' in args:
        if len(args) < 3 or args[-2] != '--runner-sha' or sha(read(runner)) != args[-1]:
            raise RuntimeError('The pinned controller runner changed; startup blocked.')
        args = args[:-2]
    source = globals().get('INSTALL_SOURCE')
    if source is not None:
        if not isinstance(source, str): raise RuntimeError('The complete pinned runner source is required.')
        if runner.exists() and read(runner) != source.encode(): raise RuntimeError('A different mount-order runner was retained.')
    elif not runner.exists(): raise RuntimeError('The installed mount-order runner is unavailable.')
    sys.dont_write_bytecode = True
    loader = importlib.util.spec_from_file_location('accepted_cutover_controller', worker)
    module = importlib.util.module_from_spec(loader); loader.loader.exec_module(module)
    if source is not None and not runner.exists(): module.atomic(runner, source.encode())
    install_overrides(module, plan, runner, role)
    allowed = ({'--hold', '--hold-worker', '--abort', '--recover', '--resume'} if role == 'source'
               else {'--receive', '--receive-worker', '--activate', '--activate-worker', '--rollback', '--recover', '--commit-core', '--boot-plex'})
    if args[0] not in allowed: raise RuntimeError('This action is outside the reviewed controller scope.')
    invoke_native(module, role, args)


if __name__ == '__main__':
    try: main()
    except Exception as error:
        raise SystemExit('STOP: ' + (str(error) if isinstance(error, RuntimeError)
                         else 'The mount-order-compatible controller failed (' + type(error).__name__ + '); private details retained.'))
