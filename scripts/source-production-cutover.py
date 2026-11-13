#!/usr/bin/env python3
"""Prepare an approved full-source hold and one fresh, consistent final export.

Default installation/preparation does not stop production. --hold requires the
exact reviewed plan digest. After publication, source return requires a fresh
NAS-stopped receipt. The existing nightly copy and restricted-reader mechanisms
are reused; Docker/cron/timer startup conditions persist across source reboots.
"""
import base64
import contextlib
import datetime as dt
import fcntl
import hashlib
import hmac
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time

FORMAT = 'sawdoctor-production-cutover-v1'
BASE = Path('/var/lib/sawdoctor-production-cutover')
WORKER = BASE / 'worker.py'
PLAN = BASE / 'plan.json'
HOLD = BASE / 'hold.json'
OUTPUT = Path('/home/sawdoctor/nas-production-cutover')
UNITS = Path('/etc/systemd/system')
BOOT = UNITS / 'nas-production-cutover-recover.service'
SUDOERS = Path('/etc/sudoers.d/nas-production-cutover-read')
READER = Path('/usr/local/sbin/nas-migration-export-read')
NIGHTLY = Path('/usr/local/sbin/nas-migration-standby')
TRIAL = Path('/usr/local/sbin/nas-plex-trial')
NIGHTLY_SHA = 'f320f99ad7d07c2db77cc34a937d6b4d831f3b9c7fd8f135351b0dece082fd92'
TRIAL_SHA = '34198d7cd3020989f51b6fc061ac0b152cb62a8274ca6c06494d06ace53775fd'
WORK = Path('/var/lib/sawdoctor-migration-standby/snapshot-work')
SEED = Path('/var/lib/sawdoctor-plex-handover/payload/plex-config')
DROPIN = '95-sawdoctor-production-hold.conf'
CONDITION = '# ' + FORMAT + '\n[Unit]\nConditionPathExists=!' + str(HOLD) + '\n'
PENDING = tuple(map(Path, ('/var/lib/sawdoctor-plex-trial/hold.json',
    '/var/lib/sawdoctor-plex-production-hold/hold.json',
    '/var/lib/sawdoctor-migration-standby/resume.json',
    '/var/lib/sawdoctor-migration-standby/paused-timers.json',
    '/var/lib/sawdoctor-nas-plex-npm-export/resume.json', '/run/plex-daily-backup-active')))
MAX_PAYLOAD = 96 * 1024**3


def say(value): print(value, flush=True)
def sha(value): return hashlib.sha256(value).hexdigest()


def safe(path):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise RuntimeError('A symbolic cutover input/control path was retained: ' + path.name)


def read(path, limit=16 * 1024**2):
    safe(path)
    if not path.is_file() or path.stat().st_size > limit:
        raise RuntimeError('A bounded cutover record is unavailable: ' + path.name)
    return path.read_bytes()


def atomic(path, data, mode=0o600, reference=None):
    safe(path)
    if not isinstance(data, bytes): data = (json.dumps(data, indent=2) + '\n').encode()
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
        if reference is not None:
            shutil.copystat(reference, name); info = reference.stat(); os.chown(name, info.st_uid, info.st_gid)
        os.replace(name, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)
    finally: Path(name).unlink(missing_ok=True)


def run(*args, timeout=30, allowed=(0,), **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, **kwargs)
    if result.returncode not in allowed:
        if BASE.is_dir(): atomic(BASE / 'private-command-error.json', {'command': args, 'stdout': result.stdout, 'stderr': result.stderr})
        raise RuntimeError('A source cutover command failed; private diagnostics retained.')
    return result.stdout


def load(path, expected, name):
    if sha(read(path)) != expected: raise RuntimeError('A reviewed source helper differs: ' + path.name)
    sys.dont_write_bytecode = True
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    value = importlib.util.module_from_spec(spec); loader.exec_module(value)
    return value


def helpers():
    nightly = load(NIGHTLY, NIGHTLY_SHA, 'source_final_nightly')
    nightly.BASE = BASE
    trial = load(TRIAL, TRIAL_SHA, 'source_final_trial')
    trial.FILES['/usr/local/sbin/media-mount-watch.sh'] = '8f3531b26fc3f822067664d3310761e970f7ab7bab97189f927b2cb042d3e73a'
    trial.FILES['/usr/local/sbin/lan-container-start.sh'] = '43671bb9d55da98095a69e59240c08f88f6ed4da5253c40ecb6e37578e2330aa'
    return nightly, trial


@contextlib.contextmanager
def locks():
    with contextlib.ExitStack() as stack:
        for path in (BASE / '.run.lock', Path('/var/lib/sawdoctor-migration-standby/.run.lock'),
                     Path('/run/lock/plex-daily-backup.lock'), Path('/var/lib/sawdoctor-plex-handover/.run.lock'),
                     Path('/run/media-mount-recover.lock'), Path('/run/tmc-deadlock-watch.lock')):
            safe(path); stream = stack.enter_context(path.open('a'))
            try: fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: raise RuntimeError('A source backup/recovery/copy is busy; source retained.') from None
        yield


def owner():
    safe(BASE)
    if BASE.exists():
        if json.loads(read(BASE / 'owner.json')) != {'format': FORMAT}: raise RuntimeError('An unknown source cutover folder was retained.')
    else:
        BASE.mkdir(mode=0o700); atomic(BASE / 'owner.json', {'format': FORMAT})


def fingerprint(row):
    return {'id': row['Id'], 'image': row['Image'], 'mounts': row['Mounts'],
            'configSha256': sha(json.dumps(row['Config'], sort_keys=True).encode()),
            'hostConfigSha256': sha(json.dumps(row['HostConfig'], sort_keys=True).encode())}


def all_containers():
    ids = sorted(set(run('docker', 'ps', '-aq', '--no-trunc').split()))
    if not ids or len(ids) > 100: raise RuntimeError('The source Docker inventory is outside its reviewed bound.')
    return {row['Name'].lstrip('/'): row for row in json.loads(run('docker', 'inspect', *ids))}


def controlled_units(nightly, trial):
    timers = run('systemctl', 'list-unit-files', '--type=timer', '--no-legend', '--no-pager').splitlines()
    names = {line.split()[0] for line in timers if line.split()}
    if len(names) > 100 or any(not re.fullmatch(r'[A-Za-z0-9_.@\\:-]+\.timer', name) for name in names):
        raise RuntimeError('The source timer inventory needs review.')
    names.update(trial.SERVICES)
    names.update(name.removesuffix('.timer') + '.service' for name in nightly.AUX_TIMERS)
    names.update(('docker.service', 'docker.socket', 'cron.service'))
    return sorted(names)


def boot_text():
    return ('# ' + FORMAT + '\n[Unit]\nDescription=Recover an unpublished source production cutover\n'
            'Wants=network-online.target\nAfter=network-online.target docker.service docker.socket\n'
            'ConditionPathExists=' + str(HOLD) + '\n[Service]\nType=oneshot\n'
            'ExecStart=/usr/bin/python3 ' + str(WORKER) + ' --recover\n[Install]\nWantedBy=multi-user.target\n')


def reader_text(original):
    marker = '# ' + FORMAT
    if marker.encode() in original: return original
    if not original.startswith(b'#!/bin/sh\n') or b'SSH_ORIGINAL_COMMAND' not in original:
        raise RuntimeError('The existing restricted transfer reader format differs.')
    addition = (marker + '\ncase "${SSH_ORIGINAL_COMMAND-}" in\n'
                ' production-cutover-status) exec /usr/bin/sudo -n /usr/bin/python3 ' + str(WORKER) + ' --status-private ;;\n'
                ' production-cutover-archive) exec /usr/bin/sudo -n /usr/bin/python3 ' + str(WORKER) + ' --archive ;;\nesac\n')
    return b'#!/bin/sh\n' + addition.encode() + original.split(b'\n', 1)[1]


def reader_permission():
    return ('# ' + FORMAT + '\nsawdoctor ALL=(root) NOPASSWD: /usr/bin/python3 ' + str(WORKER)
            + ' --status-private, /usr/bin/python3 ' + str(WORKER) + ' --archive\n')


def install_reader():
    old = read(READER); new = reader_text(old)
    expected = reader_permission().encode()
    if SUDOERS.exists() and read(SUDOERS) != expected: raise RuntimeError('An existing transfer permission was retained.')
    saved = BASE / 'reader.before'
    if new != old:
        if saved.exists() and read(saved) != old: raise RuntimeError('An earlier reader recovery copy differs.')
        if not saved.exists(): shutil.copy2(READER, saved)
        atomic(READER, new, reference=saved)
    atomic(SUDOERS, expected, mode=0o440)
    run('visudo', '-cf', str(SUDOERS))
    run('sh', '-n', str(READER))


def working_inputs(nightly):
    safe(WORK); safe(SEED)
    if not WORK.is_dir() or WORK.is_mount() or read(WORK / '.standby-owner').decode() != nightly.FORMAT:
        raise RuntimeError('The existing nightly application working tree is not owned.')
    if not SEED.is_dir() or SEED.is_mount() or SEED.stat().st_dev != WORK.stat().st_dev:
        raise RuntimeError('The existing private Plex seed is unavailable on the same filesystem.')
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        target = Path(re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), line.split()[4]))
        if target.is_relative_to(WORK) or target.is_relative_to(SEED):
            raise RuntimeError('A filesystem is mounted inside a private source working tree; retained.')


def prepare():
    nightly, trial = helpers()
    with locks():
        if HOLD.exists() or any(path.exists() or path.is_symlink() for path in PENDING):
            raise RuntimeError('A source hold or pending recovery exists; it was retained.')
        trial.check_cron(); trial.assert_idle()
        for filename, expected in trial.FILES.items():
            if sha(read(Path(filename))) != expected: raise RuntimeError('A source restart helper changed: ' + Path(filename).name)
        catalog = nightly.inspect_source(); nightly.validate_source_networks(catalog)
        roots = nightly.data_roots(catalog)
        roots['plex-config'] = {'source': nightly.ROOTS['plex-config'], 'snapshot': 'data/plex-config', 'kind': 'directory'}
        nightly.source_engine(catalog, roots).check_authorization()
        working_inputs(nightly)
        rows = all_containers()
        units = controlled_units(nightly, trial)
        if any(trial.unit_state(name).get('LoadState') != 'loaded'
               for name in ('docker.service', 'docker.socket', 'cron.service')):
            raise RuntimeError('The source Docker/socket/cron systemd ownership needs review.')
        for name in units:
            path = UNITS / (name + '.d') / DROPIN; safe(path)
            if path.exists(): raise RuntimeError('A source production hold override already exists.')
        safe(BOOT)
        if BOOT.exists(): raise RuntimeError('An earlier source production recovery unit was retained.')
        total = sum(int(run('du', '-sbx', '--', entry['source'], timeout=120).split()[0]) for entry in roots.values())
        if total > MAX_PAYLOAD or shutil.disk_usage(WORK).free < 2 * total + 4 * 1024**3:
            raise RuntimeError('The final source payload/transfer reserve exceeds its bound.')
        plan = {'format': FORMAT, 'preparedUtc': dt.datetime.now(dt.timezone.utc).isoformat(),
                'scope': 'all-source-Docker-applications; Docker/cron/timer startup held; SSH retained',
                'containers': rows, 'fingerprints': {name: fingerprint(row) for name, row in rows.items()},
                'catalog': catalog, 'roots': roots, 'units': units,
                'sourceImages': json.loads(run('docker', 'image', 'inspect', *sorted({row['Image'] for row in catalog.values()}))),
                'unitStates': {name: trial.unit_state(name) for name in units},
                'helperHashes': dict(trial.FILES) | {str(NIGHTLY): NIGHTLY_SHA, str(TRIAL): TRIAL_SHA,
                                                   str(nightly.SOURCE_HELPER): nightly.SOURCE_SHA},
                'workerSha256': sha(read(WORKER)), 'readerSha256': sha(read(READER)),
                'identitySha256': trial.identity(Path(nightly.ROOTS['plex-config'])),
                'payloadEstimateBytes': total, 'sourceStopPerformed': False,
                'freshCaptureRequired': True, 'nasActivationImplementedHere': False}
        if PLAN.exists():
            old = read(PLAN); history = BASE / 'plans'; safe(history)
            history.mkdir(mode=0o700, exist_ok=True)
            saved = history / (sha(old) + '.json')
            if saved.exists() and read(saved) != old: raise RuntimeError('An earlier source plan differs; retained.')
            if not saved.exists(): atomic(saved, old)
        atomic(PLAN, plan)
    say('SOURCE CUTOVER CONTROLS PREPARED. Production remains running; no hold is active.')
    say('Existing copy roots, source helpers, container identities and recovery space checked.')
    say('Proposed outage covers all OptiPlex Docker applications, its NPM, cron and timers; SSH remains available.')
    say('No stop, final copy/archive, startup condition or timer change was performed.')
    say('Only two fixed read-only export requests were added to the existing restricted reader; key restrictions retained.')
    say('Private plan: ' + str(PLAN))
    say('Plan SHA256: ' + sha(read(PLAN)))
    say('Approval and a ready NAS receive/import/rollback controller are still required before --hold.')


def guards_ok(state):
    for name in state['units']:
        path = UNITS / (name + '.d') / DROPIN
        safe(path)
        if not path.is_file() or path.read_text() != CONDITION: return False
    return True


def published(state):
    # Publication is irreversible without NAS-stopped proof, even during a retry.
    return state.get('published') is True


def archive_for(state):
    identity = state.get('cutoverId', '')
    if not re.fullmatch(r'\d{8}T\d{6}Z-[a-f0-9]{16}', identity):
        raise RuntimeError('The source cutover archive identity differs.')
    path = OUTPUT / identity / 'export.tar.zst'; safe(path)
    return path


def source_off(trial):
    for name in ('docker.service', 'docker.socket', 'cron.service'):
        value = trial.unit_state(name)
        if value.get('ActiveState') not in ('inactive', 'failed') or value.get('MainPID', '0') != '0':
            return False
    return not trial.port_open('127.0.0.1')


def status_private():
    if not HOLD.exists(): return {'format': FORMAT, 'held': False}
    state = json.loads(read(HOLD))
    if state.get('format') != FORMAT: raise RuntimeError('An unrelated source hold was retained.')
    _, trial = helpers()
    if not (published(state) and state.get('phase') == 'published' and guards_ok(state) and source_off(trial)):
        return {'format': FORMAT, 'held': False}
    if trial.identity(Path(state['roots']['plex-config']['source'])) != state['identitySha256']:
        raise RuntimeError('Held source Plex identity changed; NAS startup blocked.')
    ready = state['ready']
    archive = archive_for(state)
    if not archive.is_file() or archive.stat().st_size != ready['archiveBytes']:
        raise RuntimeError('The published final archive is unavailable.')
    return {'format': FORMAT, 'held': True, 'cutoverId': state['cutoverId'],
            'receiptKey': state['receiptKey'], 'identitySha256': state['identitySha256'], **ready}


def validate_receipt(token, state, now=None):
    try:
        encoded, signature = token.split('.')
        raw = base64.b64decode(encoded + '=' * (-len(encoded) % 4), altchars=b'-_', validate=True)
        payload = json.loads(raw)
        expected = hmac.new(bytes.fromhex(state['receiptKey']), raw, hashlib.sha256).hexdigest()
        age = int(time.time() if now is None else now) - payload['stoppedAt']
        valid = (hmac.compare_digest(signature, expected) and payload['cutoverId'] == state['cutoverId']
                 and payload['action'] == 'nas-production-stopped' and payload.get('allImportedWritersStopped') is True
                 and -30 <= age <= 600)
    except (ValueError, KeyError, TypeError): valid = False
    if not valid: raise RuntimeError('A fresh matching NAS-production-stopped receipt is required; source remains held.')


def restore(state, receipt=None):
    nightly, trial = helpers()
    if state.get('format') != FORMAT: raise RuntimeError('An unrelated source hold was retained.')
    if published(state) and not state.get('returnAuthorized'):
        validate_receipt(receipt or '', state)
        if trial.port_open('192.168.0.220'): raise RuntimeError('NAS Plex still responds; source remains held.')
        state['returnAuthorized'] = True; atomic(HOLD, state)
    # Interrupted pre-publication installs and authorized restores are resumable;
    # changed existing overrides are always retained for manual review.
    for name in state['units']:
        path = UNITS / (name + '.d') / DROPIN; safe(path)
        if path.exists():
            if path.read_text() != CONDITION: raise RuntimeError('A source hold override changed; recovery files retained.')
        elif published(state) and state.get('phase') != 'restoring':
            raise RuntimeError('A published source hold override is missing; source remains held.')
    state['phase'] = 'restoring'; atomic(HOLD, state)
    for name in state['units']:
        (UNITS / (name + '.d') / DROPIN).unlink(missing_ok=True)
    run('systemctl', 'daemon-reload')
    run('systemctl', 'start', 'docker.service', timeout=90)
    # Reuse the nightly job's dependency-aware source/network restoration.
    catalog = state['catalog']
    for name in ('npm-app-1', 'torbox-media-center', 'glances'):
        if name in state['containers'] and state['containers'][name]['State']['Running']:
            run('docker', 'start', state['containers'][name]['Id'], timeout=90)
    engine = nightly.source_engine(catalog, state['roots'])
    engine.BASE = BASE; engine.STATE = BASE / 'restore-pending.json'; engine.FORMAT = nightly.FORMAT
    pending = {'format': nightly.FORMAT, 'containers': [{'name': name, 'id': row['Id']}
               for name, row in catalog.items() if name not in nightly.LIVE_STATIC and row['State']['Running']],
               'ownsMarker': False, 'restoreBackupTimer': False}
    if not engine.STATE.exists(): engine.record(pending)
    nightly.resume_source_clients(engine, catalog, backup_locked=True)
    for name, row in state['containers'].items():
        if name not in catalog and row['State']['Running']:
            run('docker', 'start', row['Id'], timeout=90)
    for name, previous in state['unitStates'].items():
        if name in ('docker.service', 'docker.socket'): continue
        if previous.get('ActiveState') == 'active' and (name.endswith('.timer') or name == 'cron.service'):
            run('systemctl', 'start', name)
    trial.wait_api(Path(state['roots']['plex-config']['source']), state['identitySha256'])
    run('systemctl', 'disable', BOOT.name, allowed=(0, 1)); BOOT.unlink(missing_ok=True)
    atomic(BASE / ('returned-' + state['cutoverId'] + '.json'), {**state, 'phase': 'returned'}); HOLD.unlink()
    run('systemctl', 'daemon-reload')
    say('SOURCE PRODUCTION RESTORED. Original container policies/helpers/data retained; original active cron/timers restored.')


def hold(approved_sha):
    nightly, trial = helpers()
    with locks():
        if HOLD.exists(): raise RuntimeError('An existing cutover hold needs status/recovery; source retained.')
        body = read(PLAN)
        if not re.fullmatch(r'[a-f0-9]{64}', approved_sha) or sha(body) != approved_sha:
            raise RuntimeError('The explicit approved plan digest differs; no source stop occurred.')
        plan = json.loads(body)
        if plan.get('format') != FORMAT or plan.get('workerSha256') != sha(read(WORKER)):
            raise RuntimeError('The prepared source controller differs; source retained.')
        prepared = dt.datetime.fromisoformat(plan['preparedUtc'])
        if not dt.timedelta() <= dt.datetime.now(dt.timezone.utc) - prepared <= dt.timedelta(hours=24):
            raise RuntimeError('The source cutover plan is expired or future-dated; source retained.')
        if any(path.exists() or path.is_symlink() for path in PENDING): raise RuntimeError('Source backup/recovery is pending.')
        trial.check_cron(); trial.assert_idle()
        if any(sha(read(Path(name))) != expected for name, expected in plan['helperHashes'].items()):
            raise RuntimeError('A prepared source helper changed; source retained.')
        if sha(read(READER)) != plan['readerSha256']: raise RuntimeError('The source transfer reader changed; source retained.')
        current = all_containers()
        if {name: fingerprint(row) for name, row in current.items()} != plan['fingerprints']:
            raise RuntimeError('The source container/configuration inventory changed; source retained.')
        if controlled_units(nightly, trial) != plan['units']: raise RuntimeError('The source timer/control inventory changed.')
        working_inputs(nightly)
        if trial.session_count(Path(plan['roots']['plex-config']['source'])) != 0:
            raise RuntimeError('Plex has active sessions; no source stop occurred.')
        if trial.port_open('192.168.0.220'): raise RuntimeError('NAS Plex port is already active; source retained.')
        if trial.identity(Path(plan['roots']['plex-config']['source'])) != plan['identitySha256']:
            raise RuntimeError('Source Plex identity changed after preparation; source retained.')
        state = {**plan, 'containers': current, 'catalog': {name: current[name] for name in nightly.APP_NAMES},
                 'unitStates': {name: trial.unit_state(name) for name in plan['units']},
                 'cutoverId': dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + secrets.token_hex(8),
                 'receiptKey': secrets.token_hex(32), 'phase': 'holding', 'published': False}
        atomic(HOLD, state)
        try:
            for name in state['units']:
                path = UNITS / (name + '.d') / DROPIN; safe(path)
                if path.exists(): raise RuntimeError('A source hold override already exists.')
                path.parent.mkdir(mode=0o755, exist_ok=True); atomic(path, CONDITION.encode(), mode=0o644)
            atomic(BOOT, boot_text().encode(), mode=0o644)
            run('systemctl', 'daemon-reload'); run('systemctl', 'enable', BOOT.name)
            active = [name for name, value in state['unitStates'].items() if value.get('ActiveState') == 'active'
                      and (name.endswith('.timer') or name == 'cron.service')]
            if active: run('systemctl', 'stop', *active, timeout=90)
            trial.assert_idle()
            say('Stopping approved source Docker applications for one common final capture...')
            # Clients/writers first, InfiniDysk and backing databases last.
            priority = lambda name: (3 if name in ('tracearr-db', 'tracearr-redis') else 2 if name == 'nzbdav' else 0 if name == 'plex' else 1)
            for name in sorted(current, key=priority):
                if current[name]['State']['Running']: run('docker', 'stop', '--timeout', '60', current[name]['Id'], timeout=90)
            if run('docker', 'ps', '-q').strip(): raise RuntimeError('A source Docker application restarted; capture blocked.')
            run('systemctl', 'stop', 'docker.service', 'docker.socket', timeout=120)
            if not guards_ok(state) or not source_off(trial):
                raise RuntimeError('Persistent source startup guards or stopped services did not verify.')
            safe(WORK)
            if read(WORK / '.standby-owner').decode() != nightly.FORMAT: raise RuntimeError('The source working tree owner changed.')
            say('Updating the existing nightly working roots from stopped production; Plex is included...')
            roots = dict(state['roots']); plex = roots.pop('plex-config')
            nightly.copy_roots(WORK, roots, live=False)
            target = WORK / plex['snapshot']; safe(target); target.mkdir(mode=0o700, parents=True, exist_ok=True)
            # Hard links may be reused only from the existing PRIVATE seed,
            # never from running/original production files.
            run('rsync', '-aHAX', '--numeric-ids', '--one-file-system', '--no-devices', '--no-specials',
                '--delete', '--checksum', '--link-dest=' + str(SEED),
                '--exclude=/Library/Application Support/Plex Media Server/Cache/Transcode/***',
                '--', plex['source'] + '/', str(target) + '/', timeout=3600)
            plex_db = 'Library/Application Support/Plex Media Server/Plug-in Support/Databases/com.plexapp.plugins.library.db'
            fresh = {}
            for suffix in ('', '-wal'):
                original = Path(plex['source']) / (plex_db + suffix)
                copied = target / (plex_db + suffix)
                if original.exists():
                    if nightly.digest(original) != nightly.digest(copied): raise RuntimeError('The final Plex database/support file differs from stopped live production.')
                    fresh[suffix or 'main'] = nightly.digest(copied)
                elif copied.exists(): raise RuntimeError('An obsolete Plex WAL was retained; capture blocked.')
            if 'main' not in fresh: raise RuntimeError('The current source Plex library database is missing; publication blocked.')
            manifest = {'format': FORMAT, 'sourceHost': '192.168.0.29', 'scope': 'production-frozen',
                        'createdUtc': dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ'),
                        'cutoverId': state['cutoverId'], 'plexConfigIncluded': True, 'sourceDockerStopped': True,
                        'identitySha256': state['identitySha256'], 'livePlexDatabaseSha256': fresh,
                        'dataRoots': state['roots'], 'containers': list(state['catalog'].values()),
                        'images': plan['sourceImages'] if 'sourceImages' in plan else []}
            # Image metadata is saved in prepare while Docker is running.
            if not manifest['images']: raise RuntimeError('Source image metadata is missing; publication blocked.')
            atomic(WORK / 'manifest.json', manifest)
            run('bash', '-o', 'pipefail', '-c',
                'find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS', cwd=WORK, timeout=3600)
            archive = archive_for(state)
            archive.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            partial = archive.parent / 'export.tar.zst.partial'; safe(partial)
            if archive.exists(): raise RuntimeError('An earlier frozen transfer archive was retained.')
            say('Creating the one final transfer archive from the common stopped source point...')
            run('tar', '--acls', '--xattrs', '--numeric-owner', '--sparse', '--one-file-system',
                '-I', 'zstd -T2 -3', '-cpf', str(partial), '-C', str(WORK), '.', timeout=7200)
            run('zstd', '-t', '--', str(partial), timeout=1800)
            partial.replace(archive)
            state['ready'] = {'archiveSha256': nightly.digest(archive), 'archiveBytes': archive.stat().st_size,
                              'manifestSha256': nightly.digest(WORK / 'manifest.json'),
                              'frozenUtc': manifest['createdUtc'], 'payloadLimitBytes': MAX_PAYLOAD}
            if not guards_ok(state) or not source_off(trial):
                raise RuntimeError('The source did not retain its stopped hold; publication blocked.')
            state['published'] = True; state['phase'] = 'published'; atomic(HOLD, state)
            if not status_private().get('held'): raise RuntimeError('The published source hold proof did not verify.')
        except BaseException:
            # Never auto-resume after a NAS may have received start permission.
            saved = json.loads(read(HOLD))
            if not published(saved):
                try: restore(saved)
                except Exception:
                    raise RuntimeError('Source recovery remains pending. Run sudo python3 ' + str(WORKER)
                                       + ' --recover; no NAS start permission was published. Original data retained.') from None
            raise
    say('CURRENT SOURCE FROZEN AND EXPORTED. Plex, InfiniDysk, library links and application state share this stopped point.')
    say('Source Docker/cron/timer startup remains held across reboot. SSH and all original data are retained.')
    say('The NAS must verify and import this new frozen export before starting production. No source auto-resume after publication.')


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or 'inet 192.168.0.29/' not in run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the OptiPlex.')
    owner()
    args = sys.argv[1:]
    if args == ['--status-private']:
        say(json.dumps(status_private(), sort_keys=True)); return
    if args == ['--archive']:
        if not status_private().get('held'): raise RuntimeError('No verified published source hold is available.')
        with archive_for(json.loads(read(HOLD))).open('rb') as stream: shutil.copyfileobj(stream, sys.stdout.buffer, 4 * 1024**2)
        return
    if args in (['--abort'], ['--recover']) or (len(args) == 2 and args[0] == '--resume'):
        with locks():
            if not HOLD.exists(): say('No source production hold is active.'); return
            state = json.loads(read(HOLD))
            if args == ['--recover'] and published(state) and not state.get('returnAuthorized'):
                say('Published source production hold retained; NAS-stopped proof is required for return.'); return
            restore(state, args[1] if len(args) == 2 else None)
        return
    if len(args) == 2 and args[0] == '--hold-worker':
        def terminate(signum, frame): raise RuntimeError('Source capture cancelled; checking safe source recovery.')
        signal.signal(signal.SIGTERM, terminate)
        hold(args[1]); return
    if len(args) == 2 and args[0] == '--hold':
        if sha(read(PLAN)) != args[1]: raise RuntimeError('The approved source plan digest differs.')
        run('systemd-run', '--unit=source-production-freeze', '--collect',
            '--description=Approved full source hold and consistent final production export',
            '--property=Type=exec', '--property=UMask=0077', '--property=RuntimeMaxSec=3h',
            '--property=TimeoutStopSec=15min', '/usr/bin/python3', str(WORKER), '--hold-worker', args[1])
        say('Approved source freeze started in systemd. Follow source-production-freeze.service.'); return
    if args: raise RuntimeError('Unsupported source cutover action; source retained.')
    source = globals().get('INSTALL_SOURCE')
    if not isinstance(source, str): raise RuntimeError('The complete pinned installer is required for preparation.')
    if WORKER.exists() and read(WORKER) != source.encode(): raise RuntimeError('A different source cutover controller was retained.')
    if not WORKER.exists(): atomic(WORKER, source.encode())
    install_reader(); prepare()


if __name__ == '__main__':
    try: main()
    except Exception as error:
        raise SystemExit('STOP: ' + (str(error) if isinstance(error, RuntimeError)
                         else 'Source cutover failed (' + type(error).__name__ + '); private details withheld.'))
