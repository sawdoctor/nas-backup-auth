#!/usr/bin/env python3
"""Stage a private Plex-only hold proposal. There is NO activation action here.

Reads the reviewed source helpers and existing live precopy; writes only a
bounded proposal under /var/lib/sawdoctor-plex-hold-proposal. Never changes an
installed helper, systemd unit, timer, Docker policy, or Plex data.
"""
import base64
import contextlib
import datetime as dt
import difflib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

FORMAT = 'sawdoctor-plex-hold-proposal-v1'
BASE = Path('/var/lib/sawdoctor-plex-hold-proposal')
# Proposed future marker only: this preparation never creates it.
HOLD = Path('/var/lib/sawdoctor-plex-production-hold/hold.json')
SEED = Path('/var/lib/sawdoctor-plex-handover')
CONFIG = Path('/home/sawdoctor/docker/plex/config')
FLORA = Path('/home/sawdoctor/plex2ultimate/flora-test-library')
IMAGE = 'sha256:0c2f1122a4275efeea953a9882359f3809b27279d3c3022392e8e610a2eccc67'
EXPECTED = {
    '/usr/local/sbin/nas-plex-trial': '34198d7cd3020989f51b6fc061ac0b152cb62a8274ca6c06494d06ace53775fd',
    '/usr/local/sbin/plex-safe-start': '1cc5fcf6e6d80c87600f7710edd8847d63bb0ac49f7e5b2a32bb9c541c46b0c0',
    '/usr/local/sbin/plex-safe-restart': '573d8c41e4aa49e8979d7aa17dc615604f69dbe9e369c1d10c5dd1203288db23',
    '/usr/local/sbin/plex-backup-post': 'aa12775f32f502a3322e36742a344755f6b4fcba4f997dccd87b689514ea29b6',
    '/usr/local/bin/plex-daily-backup.sh': '2b940406adc76ad6a316d5739f4f64c79c0f54cddc54083d4dae4dc27fdd9e66',
    '/usr/local/sbin/media-last-start': 'e73e4d57db65970d91254d294fb112f6afea2c7d5b92f41e29be8da4200c9d59',
    '/usr/local/sbin/media-mount-guard': '911d2873749c688c3ae1e715adc2bdf212d0b0ab09a164f0e424295f49b923aa',
    '/usr/local/sbin/media-mount-watch.sh': '8f3531b26fc3f822067664d3310761e970f7ab7bab97189f927b2cb042d3e73a',
    '/usr/local/sbin/media-mount-recover.sh': '97fe6cca51b456731f606f801b2faf4904e0b31562f1d12e52501b8a209b7e0d',
    '/usr/local/sbin/plex-api-watch': '4b497787247ea8f67dbf1063122b0cedeb678962063ba3aa4c033a6e14b61ae7',
    '/usr/local/sbin/tmc-deadlock-watch': '1d90290a712f5b2954603de26848ddf0c3fb14a11618ab38ed49ffd675a63ec0',
    '/usr/local/sbin/docker-postboot-fix': '621f715ff266af3c5a59d892f1ab6ace1cb90905ebb6b2335e15696987a6b0b3',
    '/usr/local/sbin/lan-container-start.sh': '43671bb9d55da98095a69e59240c08f88f6ed4da5253c40ecb6e37578e2330aa',
    '/usr/local/sbin/nas-migration-standby': 'f320f99ad7d07c2db77cc34a937d6b4d831f3b9c7fd8f135351b0dece082fd92',
}
EXCLUSIVE = ('plex-safe-start', 'plex-safe-restart', 'plex-daily-backup.sh',
             'plex-api-watch', 'tmc-deadlock-watch')
UNITS = ('plex-daily-backup.service', 'plex-api-watch.service', 'tmc-deadlock-watch.service')
LOCKS = (Path('/run/lock/plex-daily-backup.lock'),
         Path('/var/lib/sawdoctor-migration-standby/.run.lock'), SEED / '.run.lock')
PENDING = (HOLD, Path('/var/lib/sawdoctor-plex-trial/hold.json'),
           Path('/var/lib/sawdoctor-migration-standby/resume.json'),
           Path('/var/lib/sawdoctor-migration-standby/paused-timers.json'),
           Path('/var/lib/sawdoctor-nas-plex-npm-export/resume.json'),
           Path('/run/plex-daily-backup-active'))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def safe(path):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise RuntimeError('An unexpected symbolic input/proposal path was retained.')


def read(path, limit=2 * 1024**2):
    safe(path)
    if not path.is_file() or path.stat().st_size > limit:
        raise RuntimeError('A required bounded input is unavailable: ' + path.name)
    return path.read_bytes()


def run(*args, data=None):
    result = subprocess.run(args, input=data, capture_output=True, timeout=20)
    if result.returncode:
        raise RuntimeError('A proposal validation query failed; private output withheld.')
    return result.stdout


def once(text, before, after):
    if text.count(before) != 1:
        raise RuntimeError('A reviewed Plex patch anchor differs; source retained.')
    return text.replace(before, after, 1)


def test_hold():
    # A dangling marker symlink also fails closed. Parent paths are validated
    # separately by the future activator; this file has no activator.
    return '[ -e ' + str(HOLD) + ' ] || [ -L ' + str(HOLD) + ' ]'


def guard(indent='', action='exit 0'):
    return (indent + '# Sawdoctor proposed production Plex hold v1\n'
            + indent + 'if ' + test_hold() + '; then\n'
            + indent + '    echo "Production Plex handover hold: source Plex deferred." >&2\n'
            + indent + '    ' + action + '\n' + indent + 'fi\n')


def patch_helper(name, original):
    text = original.decode('utf-8')
    if not text.startswith('#!') or 'proposed production Plex hold v1' in text:
        raise RuntimeError('An unexpected source helper format was retained.')
    leaf = Path(name).name
    if leaf in EXCLUSIVE:
        first, separator, rest = text.partition('\n')
        if not separator:
            raise RuntimeError('A source helper has no script body.')
        text = first + '\n' + guard() + rest
        if leaf == 'plex-safe-start':
            # Recheck after the existing mount-readiness wait, immediately
            # before start; activation must also drain in-flight helpers.
            anchor = '        /usr/bin/docker start plex >/dev/null 2>&1 || exit 1\n'
            text = once(text, anchor, guard('        ') + anchor)
    elif leaf == 'media-mount-recover.sh':
        text = once(text, 'start_plex() {\n', 'start_plex() {\n' + guard('    ', 'return 0'))
    elif leaf == 'media-mount-watch.sh':
        anchor = 'PLAYERS=(plex)\n'
        proposed = ('\n# Sawdoctor proposed production Plex hold v1\n'
                    'if ' + test_hold() + '; then\n'
                    '    CONSUMERS=(sonarr radarr radarr4k jellyfin)\n'
                    '    PLAYERS=()\nfi\n')
        text = once(text, anchor, anchor + proposed)
    elif leaf == 'docker-postboot-fix':
        old = ('        plex|jellyfin)\n'
               '            /usr/bin/docker update --restart=on-failure:5 "$C" >/dev/null 2>&1\n'
               '            ;;\n')
        new = ('        # Sawdoctor proposed production Plex hold v1\n'
               '        plex)\n'
               '            if ' + test_hold() + '; then\n'
               '                /usr/bin/docker update --restart=no "$C" >/dev/null 2>&1\n'
               '            else\n'
               '                /usr/bin/docker update --restart=on-failure:5 "$C" >/dev/null 2>&1\n'
               '            fi\n'
               '            ;;\n'
               '        jellyfin)\n'
               '            /usr/bin/docker update --restart=on-failure:5 "$C" >/dev/null 2>&1\n'
               '            ;;\n')
        text = once(text, old, new)
    else:
        raise RuntimeError('A helper outside the reviewed Plex patch set was rejected.')
    value = text.encode()
    run('bash', '-n', data=value)
    return value


def proposed_dropin():
    return ('# Sawdoctor proposed production Plex hold v1\n[Unit]\n'
            'ConditionPathExists=!' + str(HOLD) + '\n').encode()


def metadata(path):
    info = path.stat()
    return {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid,
            'mtimeNs': info.st_mtime_ns,
            'xattrs': {n: base64.b64encode(os.getxattr(path, n)).decode()
                       for n in sorted(os.listxattr(path))}}


def inputs():
    originals = {}
    records = {}
    for name, expected in EXPECTED.items():
        path = Path(name)
        data = read(path)
        if sha(data) != expected:
            raise RuntimeError('A source helper differs from the reviewed version: ' + path.name)
        originals[name] = data
        records[name] = {'sha256': expected, **metadata(path)}
    return originals, records


def source_container():
    row, = json.loads(run('docker', 'inspect', 'plex'))
    if (row['Name'] != '/plex' or row['Image'] != IMAGE
            or row['State']['Status'] != 'running' or not row['State']['Running']
            or row['HostConfig']['NetworkMode'] != 'host'
            or row['HostConfig']['RestartPolicy'] != {'Name': 'on-failure', 'MaximumRetryCount': 5}):
        raise RuntimeError('The source Plex container state/image/policy differs; source retained.')
    for destination, source in (('/config', CONFIG), ('/flora-test-library', FLORA)):
        selected = [m for m in row['Mounts'] if m['Destination'] == destination]
        if len(selected) != 1 or selected[0]['Type'] != 'bind' or selected[0]['Source'] != str(source):
            raise RuntimeError('A source Plex data binding differs; source retained.')
    return {'id': row['Id'], 'imageId': row['Image'], 'startedAt': row['State']['StartedAt']}


def seed_check(container):
    state = json.loads(read(SEED / 'state.json'))
    owner = json.loads(read(SEED / 'owner.json'))
    expected_owner = {'format': 'sawdoctor-plex-handover-precopy-v1'}
    if (owner != expected_owner or state.get('format') != expected_owner['format']
            or state.get('phase') != 'seeded-running-not-frozen'
            or state.get('consistentSnapshot') is not False
            or state.get('sourceStopPerformed') is not False
            or state.get('sourceRoots') != {'plex-config': str(CONFIG), 'flora-test-library': str(FLORA)}
            or state.get('container', {}).get('Id') != container['id']
            or state.get('container', {}).get('Image') != container['imageId']):
        raise RuntimeError('The existing live Plex seed differs; it was retained.')
    # A successful daily backup/reboot legitimately changes StartedAt. Do not
    # treat the 8 Nov live seed as consistent or rerun its old worker.
    for leaf in ('plex-config', 'flora-test-library'):
        path = SEED / 'payload' / leaf
        safe(path)
        if not path.is_dir() or path.is_mount():
            raise RuntimeError('An existing private seed root is unavailable.')
    if sha(read(SEED / 'worker.py')) != 'c776af1c4cff9890bf1306d889ba7cf946a2447974cc99eaf9dcda650152434f':
        raise RuntimeError('The existing precopy worker differs; it was not executed.')
    return {'phase': state['phase'], 'consistentSnapshot': False,
            'sourceStopPerformed': False, 'stateSha256': sha(read(SEED / 'state.json'))}


def make_plan(originals, records, container, seed):
    changed = [n for n in EXPECTED if Path(n).name in EXCLUSIVE
               or Path(n).name in ('media-mount-recover.sh', 'media-mount-watch.sh', 'docker-postboot-fix')]
    payload = {}
    patches = []
    for index, name in enumerate(changed):
        before = originals[name]
        after = patch_helper(name, before)
        prefix = f'{index:02d}-' + Path(name).name
        names = {'before': prefix + '.before', 'after': prefix + '.proposed', 'diff': prefix + '.diff'}
        diff = ''.join(difflib.unified_diff(before.decode().splitlines(True),
                                           after.decode().splitlines(True),
                                           fromfile=name, tofile=name + '.proposed')).encode()
        payload[names['before']] = before
        payload[names['after']] = after
        payload[names['diff']] = diff
        patches.append({'path': name, 'beforeSha256': sha(before), 'afterSha256': sha(after),
                        'sourceMetadata': records[name], **names})
    for unit in UNITS:
        payload[unit + '.proposed.conf'] = proposed_dropin()
    plan = {'format': FORMAT, 'preparedUtc': dt.datetime.now(dt.timezone.utc).isoformat(),
            'phase': 'proposal-only-not-installed', 'sourceContainer': container, 'liveSeed': seed,
            'sourceHelpers': records, 'futureHoldMarker': str(HOLD), 'patches': patches,
            'proposedServiceConditions': list(UNITS),
            'sharedRecoveryUnitsRemainEnabled': True,
            'activationImplemented': False, 'sourceStopPerformed': False,
            'plexDataCopied': False, 'installedHelpersChanged': False,
            'pendingReview': ['Drain/reject in-flight restart/backup/mount helpers under shared locks.',
                              'Persist and verify hold across boot before publishing NAS start permission.',
                              'Prepare consistent seed delta, bounded transfer, NAS import and DB verification.',
                              'Require verified NAS-stopped proof before releasing source identity.',
                              'Retire migration job ownership and coordinate public routing separately.']}
    plan['proposalPayloadSha256'] = {n: sha(b) for n, b in payload.items()}
    payload['plan.json'] = (json.dumps(plan, indent=2) + '\n').encode()
    if sum(map(len, payload.values())) > 1024**2:
        raise RuntimeError('The private proposal exceeds its one-MiB bound.')
    return plan, payload


def atomic(path, value):
    safe(path)
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def stage(plan, payload):
    safe(BASE)
    owner = (json.dumps({'format': FORMAT}) + '\n').encode()
    if BASE.exists():
        if read(BASE / 'owner.json') != owner:
            raise RuntimeError('An unrecognized private proposal directory was retained.')
        if {p.name for p in BASE.iterdir()} - (set(payload) | {'owner.json'}):
            raise RuntimeError('The private proposal contains unexpected entries; retained.')
        # A changed existing plan is not silently replaced. An interrupted
        # matching preparation can complete its own missing private files.
        existing = BASE / 'plan.json'
        if existing.exists():
            old = json.loads(read(existing))
            comparable = lambda x: {k: v for k, v in x.items() if k != 'preparedUtc'}
            if comparable(old) != comparable(plan):
                raise RuntimeError('The saved proposal inputs changed; review before replacing it.')
            payload['plan.json'] = read(existing)
        for name, value in payload.items():
            path = BASE / name
            if path.exists() and read(path) != value:
                raise RuntimeError('An existing private proposal file differs; retained.')
    else:
        BASE.mkdir(mode=0o700)
        atomic(BASE / 'owner.json', owner)
    # Publish the complete plan last. No files outside BASE are written.
    for name, value in payload.items():
        if name != 'plan.json' and not (BASE / name).exists():
            atomic(BASE / name, value)
    atomic(BASE / 'plan.json', payload['plan.json'])
    descriptor = os.open(BASE, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def prepare():
    if any(p.exists() or p.is_symlink() for p in PENDING):
        raise RuntimeError('A source hold or pending backup/recovery exists; source retained.')
    with contextlib.ExitStack() as stack:
        for path in LOCKS:
            safe(path)
            handle = stack.enter_context(path.open('rb'))
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError('A backup/standby/precopy is busy; retry after it finishes.') from None
        originals, records = inputs()
        container = source_container()
        seed = seed_check(container)
        plan, payload = make_plan(originals, records, container, seed)
        if source_container() != container or inputs()[1] != records:
            raise RuntimeError('Source inputs changed during preparation; no proposal published.')
        stage(plan, payload)
    print('PLEX HOLD PROPOSAL PREPARED: 14 helper identities verified; 8 proposed script changes; 3 proposed service conditions.', flush=True)
    print('Recent stale-FUSE repair retained. Shared boot/mount recovery remains in the proposal.', flush=True)
    print('Production Plex remains running. No installed helper, timer, unit, restart policy or Plex data changed.', flush=True)
    print('Existing live precopy reused only as a reference; no Plex copy/archive or activation was performed.', flush=True)
    print('Private plan: ' + str(BASE / 'plan.json'), flush=True)
    print('Activation and final consistent transfer still require implementation, validation and cutover approval.', flush=True)


def main():
    os.umask(0o077)
    if sys.argv[1:]:
        raise RuntimeError('This preparer takes no action arguments and cannot activate a hold.')
    if os.geteuid() != 0 or 'inet 192.168.0.29/' not in run('ip', '-4', 'addr', 'show').decode():
        raise RuntimeError('Run with sudo on the OptiPlex, SSH port 48222.')
    prepare()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('STOP: ' + (str(error) if isinstance(error, RuntimeError)
                                   else 'Plex proposal preparation failed (' + type(error).__name__ + '); private details withheld.'))
