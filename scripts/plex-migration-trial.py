#!/usr/bin/env python3
"""A reversible, manually coordinated Plex identity trial on these two hosts."""
import base64
import contextlib
import datetime as dt
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from zoneinfo import ZoneInfo

SIGNATURE = 'Sawdoctor reversible Plex NAS trial v1'
WORKER = Path('/usr/local/sbin/nas-plex-trial')
SOURCE = Path('/var/lib/sawdoctor-plex-trial')
HOLD = SOURCE / 'hold.json'
READER = Path('/usr/local/sbin/nas-migration-export-read')
SUDOERS = Path('/etc/sudoers.d/nas-plex-trial-read')
UNITS = Path('/etc/systemd/system')
BOOT = UNITS / 'nas-plex-trial-recovery.service'
SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
SCRATCH = Path('/srv/dev-disk-by-uuid-1f12a22e-5cfe-4b02-8d4b-48e9bf5fec6a')
NAS = SSD / 'compose/plex-nas/recovery/trial'
NAS_STATE = NAS / 'state.json'
DATA = SSD / 'appdata/plex-nas'
LIBRARY = SSD / 'appdata/infinidysk-nas/library'
PREFS = Path('Library/Application Support/Plex Media Server/Preferences.xml')
SOURCE_CONFIG = Path('/home/sawdoctor/docker/plex/config')
SOURCE_IMAGE = 'sha256:0c2f1122a4275efeea953a9882359f3809b27279d3c3022392e8e610a2eccc67'
IMAGE = 'lscr.io/linuxserver/plex:1.43.5.11079-b3b13e506-ls331'
HOST_KEY = '192.168.0.29 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGI1/hObYOUSPIqGKLePC0eEFvCc8Uoyv+YOmBbVPbgW\n'
GUARD = ('\n# ' + SIGNATURE + '\n'
         'if [ -e ' + str(HOLD) + ' ]; then\n'
         '    echo "Plex NAS trial hold: source helper deferred." >&2\n'
         '    exit 0\nfi\n')
DROPIN = '# ' + SIGNATURE + '\n[Unit]\nConditionPathExists=!' + str(HOLD) + '\n'
READ_PERMISSION = '# ' + SIGNATURE + '\nsawdoctor ALL=(root) NOPASSWD: ' + str(WORKER) + ' source-status-private\n'
FILES = {
    '/usr/local/sbin/plex-safe-start': '1cc5fcf6e6d80c87600f7710edd8847d63bb0ac49f7e5b2a32bb9c541c46b0c0',
    '/usr/local/sbin/plex-safe-restart': '573d8c41e4aa49e8979d7aa17dc615604f69dbe9e369c1d10c5dd1203288db23',
    '/usr/local/sbin/plex-backup-post': 'aa12775f32f502a3322e36742a344755f6b4fcba4f997dccd87b689514ea29b6',
    '/usr/local/bin/plex-daily-backup.sh': '2b940406adc76ad6a316d5739f4f64c79c0f54cddc54083d4dae4dc27fdd9e66',
    '/usr/local/sbin/media-last-start': 'e73e4d57db65970d91254d294fb112f6afea2c7d5b92f41e29be8da4200c9d59',
    '/usr/local/sbin/media-mount-guard': '911d2873749c688c3ae1e715adc2bdf212d0b0ab09a164f0e424295f49b923aa',
    '/usr/local/sbin/media-mount-watch.sh': '6f05577843fa17ae7db7cb3d6dafdc63cc850f8b4b364f0634957151af99ef6a',
    '/usr/local/sbin/media-mount-recover.sh': '97fe6cca51b456731f606f801b2faf4904e0b31562f1d12e52501b8a209b7e0d',
    '/usr/local/sbin/plex-api-watch': '4b497787247ea8f67dbf1063122b0cedeb678962063ba3aa4c033a6e14b61ae7',
    '/usr/local/sbin/tmc-deadlock-watch': '1d90290a712f5b2954603de26848ddf0c3fb14a11618ab38ed49ffd675a63ec0',
    '/usr/local/sbin/docker-postboot-fix': '621f715ff266af3c5a59d892f1ab6ace1cb90905ebb6b2335e15696987a6b0b3',
    '/usr/local/sbin/lan-container-start.sh': '88bf4cef1122615a0c30fcd8adc7334daa853a80fc126d786ae4400a65016afc',
}
SERVICES = ('plex-daily-backup.service', 'plex-api-watch.service', 'media-mount-guard.service',
    'media-mount-watch.service', 'tmc-deadlock-watch.service', 'media-last-start.service',
    'media-stack-boot.service', 'docker-postboot-fix.service', 'docker-postboot-recover.service',
    'lan-container-start.service', 'nas-migration-standby.service',
    'nas-migration-standby-resume.service', 'nas-migration-standby-retry.service')
TIMERS = ('plex-daily-backup.timer', 'plex-api-watch.timer', 'media-mount-guard.timer',
          'media-mount-watch.timer', 'tmc-deadlock-watch.timer', 'nas-migration-standby.timer')
CRON = {
    '/etc/crontab': 'e25eb0e3303ea63ac7452139be788efa86d89a11005288e7150c0ac193d7e1f6',
    '/etc/cron.d/e2scrub_all': 'ec90578ad9633826c39b2e2e95b236d31b53d9fe85e97a3b30a85e52a8aa95af',
    '/etc/cron.d/timeshift-hourly': 'f0aeb3046d024e8060c0420d17493af170ada38ab590497bde636d017017ad48',
    '/var/spool/cron/crontabs/sawdoctor': 'a9e88660ad7e0c896cf06093cedcb880cccb7ffa8c1d8d26bacec92e673e2319',
}
SAFE_PREFS = {'autoEmptyTrash': '0', 'FSEventLibraryUpdatesEnabled': '0',
              'FSEventLibraryPartialScanEnabled': '0', 'ScheduledLibraryUpdatesEnabled': '0'}


def say(value): print(value, flush=True)
def sha(value): return hashlib.sha256(value).hexdigest()
def file_sha(path): return sha(path.read_bytes())


def atomic(path, value, mode=0o600, reference=None):
    if path.is_symlink(): raise RuntimeError('An unexpected symbolic trial file was retained: ' + str(path))
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    temporary = Path(temporary)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(value); stream.flush(); os.fsync(stream.fileno())
        if reference is not None:
            info = reference.stat()
            shutil.copystat(reference, temporary)
            os.chown(temporary, info.st_uid, info.st_gid)
        else: temporary.chmod(mode)
        temporary.replace(path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)
    finally: temporary.unlink(missing_ok=True)


def write_json(path, value): atomic(path, (json.dumps(value, indent=2) + '\n').encode())
def read_json(path):
    if path.is_symlink(): raise RuntimeError('An unexpected symbolic trial record was retained.')
    return json.loads(path.read_text())


def run(*args, timeout=30, allowed=(0,), private=None):
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    if result.returncode not in allowed:
        if private is not None: atomic(private, (result.stdout + '\n' + result.stderr).encode())
        raise RuntimeError('A trial command failed; existing application data was retained.')
    return result.stdout


def host_role():
    if os.geteuid() != 0: raise RuntimeError('Run with sudo.')
    addresses = run('ip', '-4', 'addr', 'show')
    if 'inet 192.168.0.29/' in addresses: return 'source'
    if 'inet 192.168.0.220/' in addresses: return 'nas'
    raise RuntimeError('Run on the OptiPlex or NAS, not another host.')


@contextlib.contextmanager
def locks(paths):
    with contextlib.ExitStack() as stack:
        for path in paths:
            stream = stack.enter_context(Path(path).open('a'))
            try: fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: raise RuntimeError('A backup, snapshot or mount recovery is busy; no Plex stop was attempted.') from None
        yield


def inspect(name): return json.loads(run('docker', 'inspect', name))[0]
def preferences(config): return ET.parse(config / PREFS).getroot()
def identity(config):
    value = preferences(config).get('MachineIdentifier')
    if not value: raise RuntimeError('The existing Plex server identity is missing.')
    return sha(value.encode())


def api(path, config):
    token = preferences(config).get('PlexOnlineToken')
    if not token: raise RuntimeError('The existing Plex API token is missing; no new claim was requested.')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs): return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request('http://127.0.0.1:32400' + path, headers={'X-Plex-Token': token})
    with opener.open(request, timeout=5) as response:
        return ET.fromstring(response.read(2 * 1024**2))


def session_count(config):
    root = api('/status/sessions', config)
    return max(int(root.get('size', '0')), len(list(root)))


def port_open(host):
    try:
        with socket.create_connection((host, 32400), timeout=2): return True
    except ConnectionRefusedError: return False
    # A timeout or routing failure is not proof of a stopped remote server.


def unit_state(name):
    text = run('systemctl', 'show', '--no-pager', '-p', 'Id', '-p', 'LoadState', '-p', 'ActiveState',
               '-p', 'SubState', '-p', 'MainPID', '-p', 'ControlPID', '-p', 'UnitFileState', name, allowed=(0, 1, 4))
    return dict(line.split('=', 1) for line in text.splitlines() if '=' in line)


def assert_idle():
    for name in SERVICES:
        value = unit_state(name)
        if (value.get('MainPID', '0') != '0' or value.get('ControlPID', '0') != '0'
            or value.get('ActiveState') in ('activating', 'deactivating', 'reloading')):
            raise RuntimeError('A source backup/recovery service is busy: ' + name)
    for path in Path('/proc').iterdir():
        if not path.name.isdigit() or int(path.name) == os.getpid(): continue
        try: argv = (path / 'cmdline').read_bytes().split(b'\0')
        except (OSError, ProcessLookupError): continue
        if any(arg.decode(errors='replace') in FILES for arg in argv):
            raise RuntimeError('A source restart helper is already running; wait for it to finish.')


def guarded(original):
    first, separator, rest = original.partition(b'\n')
    if not separator or not first.startswith(b'#!') or b'sh' not in first:
        raise RuntimeError('An unexpected source helper format was retained.')
    return first + b'\n' + GUARD.encode() + rest


def reader_text(original):
    if not original.startswith(b'#!/bin/sh\n') or b'SSH_ORIGINAL_COMMAND' not in original:
        raise RuntimeError('The existing restricted transfer reader differs; it was retained.')
    route = ('# ' + SIGNATURE + '\ncase "${SSH_ORIGINAL_COMMAND-}" in\n'
             '  plex-trial-status) exec /usr/bin/sudo -n ' + str(WORKER) + ' source-status-private ;;\nesac\n')
    return b'#!/bin/sh\n' + route.encode() + original.split(b'\n', 1)[1]


def check_cron():
    actual = {str(path) for path in [Path('/etc/crontab')]
              if path.is_file() and not path.is_symlink()}
    for directory in (Path('/etc/cron.d'), Path('/var/spool/cron/crontabs')):
        if directory.is_dir():
            actual.update(str(path) for path in directory.iterdir()
                          if not path.name.startswith('.') and path.is_file() and not path.is_symlink())
    if actual != set(CRON) or any(file_sha(Path(name)) != value for name, value in CRON.items()):
        raise RuntimeError('The checked source cron inventory changed; it was retained for review.')


def source_plan(row):
    check_cron(); assert_idle()
    pending = (Path('/var/lib/sawdoctor-migration-standby/resume.json'),
               Path('/var/lib/sawdoctor-migration-standby/paused-timers.json'),
               Path('/run/plex-daily-backup-active'))
    if any(path.exists() for path in pending):
        raise RuntimeError('A prior source backup/snapshot still has pending recovery; Plex was retained.')
    if (row['Image'] != SOURCE_IMAGE or row['HostConfig']['NetworkMode'] != 'host'
        or row['Name'] != '/plex' or not row['State']['Running']
        or next(m['Source'] for m in row['Mounts'] if m['Destination'] == '/config') != str(SOURCE_CONFIG)):
        raise RuntimeError('The reviewed source Plex container differs or is not running.')
    plans = []
    for index, (name, expected) in enumerate(FILES.items()):
        path = Path(name)
        if path.is_symlink() or file_sha(path) != expected:
            raise RuntimeError('A source helper changed and was retained: ' + name)
        plans.append({'path': name, 'before': expected, 'after': sha(guarded(path.read_bytes())),
                      'backup': str(SOURCE / 'originals' / str(index))})
    original = READER.read_bytes()
    if READER.is_symlink(): raise RuntimeError('An unexpected transfer-reader symlink was retained.')
    plans.append({'path': str(READER), 'before': sha(original), 'after': sha(reader_text(original)),
                  'backup': str(SOURCE / 'originals/reader')})
    for name in SERVICES + TIMERS:
        path = UNITS / (name + '.d') / '90-nas-plex-trial.conf'
        if path.exists() or path.is_symlink(): raise RuntimeError('A trial unit override already exists; it was retained.')
    for path in (SUDOERS, BOOT):
        if path.exists() or path.is_symlink(): raise RuntimeError('An existing trial control file was retained.')
    return {'format': SIGNATURE, 'phase': 'preparing', 'createdUtc': dt.datetime.now(dt.timezone.utc).isoformat(),
            'trialId': uuid.uuid4().hex, 'receiptKey': secrets.token_hex(32), 'containerId': row['Id'],
            'restartPolicy': row['HostConfig']['RestartPolicy'], 'identitySha256': identity(SOURCE_CONFIG),
            'files': plans, 'timers': {name: unit_state(name) for name in TIMERS}}


def guarded_files_ok(state):
    for item in state['files']:
        path = Path(item['path'])
        if path.is_symlink() or not path.is_file() or file_sha(path) != item['after']: return False
    for name in SERVICES + TIMERS:
        path = UNITS / (name + '.d') / '90-nas-plex-trial.conf'
        if path.is_symlink() or not path.is_file() or path.read_text() != DROPIN: return False
    return SUDOERS.is_file() and not SUDOERS.is_symlink() and SUDOERS.read_text() == READ_PERMISSION


def source_status():
    if not HOLD.is_file() or HOLD.is_symlink(): return {'format': SIGNATURE, 'held': False}
    state = read_json(HOLD)
    if state.get('format') != SIGNATURE: raise RuntimeError('An unrelated source hold record was retained.')
    row = inspect('plex')
    held = (state['phase'] == 'held' and row['Id'] == state['containerId'] and not row['State']['Running']
            and row['State']['Status'] == 'exited' and row['HostConfig']['RestartPolicy']['Name'] == 'no'
            and guarded_files_ok(state) and not port_open('127.0.0.1'))
    if held:
        assert_idle()
        return {'format': SIGNATURE, 'held': True, 'trialId': state['trialId'], 'receiptKey': state['receiptKey'],
                'identitySha256': state['identitySha256'], 'containerId': row['Id']}
    return {'format': SIGNATURE, 'held': False}


def restore_source(state, start):
    # This is allowed automatically only before phase=held. After publication,
    # a NAS-issued stopped receipt is mandatory, even after an SSH interruption.
    for item in state['files']:
        path = Path(item['path']); before = Path(item['backup'])
        if path.is_symlink() or file_sha(path) not in (item['before'], item['after']):
            raise RuntimeError('An edited source helper was retained; the source hold remains in place.')
        if not before.is_file() or before.is_symlink() or file_sha(before) != item['before']:
            raise RuntimeError('An original source helper recovery copy differs; the hold remains in place.')
    for name in SERVICES + TIMERS:
        path = UNITS / (name + '.d') / '90-nas-plex-trial.conf'
        if path.exists() and (path.is_symlink() or path.read_text() != DROPIN):
            raise RuntimeError('An edited trial unit override was retained.')
    for path, expected in ((SUDOERS, READ_PERMISSION), (BOOT, boot_text())):
        if path.exists() and (path.is_symlink() or path.read_text() != expected):
            raise RuntimeError('An edited trial control file was retained.')
    row = inspect('plex')
    if row['Id'] != state['containerId']: raise RuntimeError('The source Plex container changed; the hold remains in place.')
    state['phase'] = 'restoring'; state['releaseAuthorized'] = True; write_json(HOLD, state)
    for item in state['files']:
        path = Path(item['path']); before = Path(item['backup'])
        if file_sha(path) != item['before']: atomic(path, before.read_bytes(), reference=before)
    # Marker is retained until every original script has been restored.
    for name in SERVICES + TIMERS:
        path = UNITS / (name + '.d') / '90-nas-plex-trial.conf'
        path.unlink(missing_ok=True)
        try: path.parent.rmdir()
        except OSError: pass
    SUDOERS.unlink(missing_ok=True)
    policy = state['restartPolicy']; value = policy['Name']
    if policy.get('MaximumRetryCount'): value += ':' + str(policy['MaximumRetryCount'])
    run('docker', 'update', '--restart=' + value, state['containerId'])
    run('systemctl', 'daemon-reload')
    if start:
        run('/usr/local/sbin/plex-safe-start', timeout=330, private=SOURCE / 'private-error.log')
        wait_api(SOURCE_CONFIG, state['identitySha256'])
    for name, previous in state['timers'].items():
        if previous.get('ActiveState') == 'active': run('systemctl', 'start', name)
    run('systemctl', 'disable', 'nas-plex-trial-recovery.service', allowed=(0, 1))
    BOOT.unlink(missing_ok=True)
    state['phase'] = 'complete'
    write_json(SOURCE / 'completed.json', state)
    HOLD.unlink(); run('systemctl', 'daemon-reload')
    say('SOURCE PLEX RESTORED. Original helpers, restart policy and previously active timers restored.')


def boot_text():
    return ('# ' + SIGNATURE + '\n[Unit]\nDescription=Recover an incomplete Plex trial hold preparation\n'
            'Requires=docker.service\nAfter=docker.service\nBefore=' + ' '.join(SERVICES) + '\n'
            'ConditionPathExists=' + str(HOLD) + '\n[Service]\nType=oneshot\n'
            'ExecStart=' + str(WORKER) + ' source-recover\n[Install]\nWantedBy=multi-user.target\n')


def hold_source(daytime=False):
    if HOLD.exists():
        if source_status().get('held'):
            say('SOURCE PLEX HELD FOR NAS TRIAL. Its persistent restart safeguards are already in place.'); return
        raise RuntimeError('An incomplete source trial record exists; run source-recover before retrying.')
    now = dt.datetime.now(ZoneInfo('Europe/London'))
    overnight = 30 <= now.hour * 60 + now.minute < 150
    if not overnight and not (daytime and now.date().isoformat() == '2026-11-04'):
        raise RuntimeError('This daytime exception applies only on 4 November; otherwise use the agreed overnight window.')
    with locks([SOURCE / '.lock', '/var/lib/sawdoctor-migration-standby/.run.lock',
                '/run/lock/plex-daily-backup.lock', '/run/media-mount-recover.lock', '/run/tmc-deadlock-watch.lock']):
        row = inspect('plex'); state = source_plan(row)
        count = session_count(SOURCE_CONFIG)
        if count > (1 if daytime else 0): raise RuntimeError('More Plex sessions are active than this trial permits; Plex was retained.')
        if port_open('192.168.0.220'): raise RuntimeError('NAS port 32400 is already in use; source Plex was retained.')
        say('Preparing a persistent source hold; original source files and timer states are saved privately...')
        originals = SOURCE / 'originals'
        if originals.exists(): raise RuntimeError('A previous source trial recovery folder exists; it was retained.')
        originals.mkdir(mode=0o700)
        for item in state['files']:
            path = Path(item['path']); backup = Path(item['backup'])
            shutil.copy2(path, backup); info = path.stat(); os.chown(backup, info.st_uid, info.st_gid)
            with backup.open('rb') as stream: os.fsync(stream.fileno())
        write_json(HOLD, state)
        try:
            for item in state['files']:
                path = Path(item['path']); original = Path(item['backup'])
                text = reader_text(original.read_bytes()) if path == READER else guarded(original.read_bytes())
                atomic(path, text, reference=original)
            for name in SERVICES + TIMERS:
                path = UNITS / (name + '.d') / '90-nas-plex-trial.conf'
                path.parent.mkdir(mode=0o755, exist_ok=True); atomic(path, DROPIN.encode(), 0o644)
            atomic(SUDOERS, READ_PERMISSION.encode(), 0o440)
            run('visudo', '-cf', str(SUDOERS))
            atomic(BOOT, boot_text().encode(), 0o644)
            run('systemctl', 'daemon-reload'); run('systemctl', 'enable', BOOT.name)
            run('systemctl', 'stop', *[name for name, status in state['timers'].items() if status.get('LoadState') == 'loaded'])
            assert_idle()
            if not guarded_files_ok(state): raise RuntimeError('The source hold files could not be verified.')
            # No caller may start the matching NAS identity until phase=held.
            state['phase'] = 'holding'; write_json(HOLD, state)
            run('docker', 'update', '--restart=no', state['containerId'])
            say('Stopping only source Plex for the authorized trial...')
            run('docker', 'stop', '--time', '40', state['containerId'], timeout=65, private=SOURCE / 'private-error.log')
            if inspect('plex')['State']['Running'] or port_open('127.0.0.1'):
                raise RuntimeError('Source Plex has not fully stopped; NAS activation is blocked.')
            state['phase'] = 'held'; write_json(HOLD, state)
            if not source_status().get('held'): raise RuntimeError('The completed source hold could not be verified.')
        except BaseException:
            # Once held was published it may already have been read by the NAS.
            if read_json(HOLD)['phase'] != 'held': restore_source(state, start=True)
            raise
    say('SOURCE PLEX HELD FOR NAS TRIAL. Its original container and data are retained.')
    say('Source backup/recovery starts are held, including after a reboot. Closing SSH is safe.')
    say('Continue on the NAS with the NAS trial installer. Source Plex will not resume automatically.')


def recover_source():
    if not HOLD.exists(): say('No incomplete source trial preparation.'); return
    with locks([SOURCE / '.lock']):
        state = read_json(HOLD)
        if state.get('format') != SIGNATURE: raise RuntimeError('An unrelated source hold record was retained.')
        if state['phase'] == 'held':
            say('Completed trial hold retained. NAS must be confirmed stopped before source Plex is restored.'); return
        if state['phase'] == 'restoring':
            # A verified receipt is persisted before any post-publication restore.
            if not state.get('releaseAuthorized'):
                raise RuntimeError('Interrupted source restoration needs review; no automatic start was attempted.')
        restore_source(state, start=True)


def private_source_status():
    # The restricted existing SSH reader grants exactly this read-only command.
    # Never send receiptKey to the service journal or ordinary status output.
    say(json.dumps(source_status(), sort_keys=True))


def source_remote():
    key = Path('/root/.ssh/nas-infinidysk-transfer')
    if key.is_symlink() or not key.is_file(): raise RuntimeError('The existing NAS restricted transfer key is required.')
    known = NAS / 'known_hosts'; atomic(known, HOST_KEY.encode())
    text = run('ssh', '-nT', '-p', '22', '-i', str(key), '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
               '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(known),
               '-o', 'ConnectTimeout=8', 'sawdoctor@192.168.0.29', 'plex-trial-status', timeout=20)
    if len(text) > 4096: raise RuntimeError('The source trial status response differs.')
    result = json.loads(text)
    if result.get('format') != SIGNATURE or result.get('held') is not True:
        raise RuntimeError('Source Plex is not verifiably held; NAS Plex remains stopped.')
    if not re.fullmatch(r'[0-9a-f]{64}', result.get('receiptKey', '')):
        raise RuntimeError('The source trial receipt key is invalid.')
    return result


def media_paths(root):
    result = {}
    def visit(directory):
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                if entry.is_dir(follow_symlinks=False): visit(path)
                elif path.suffix.lower() in {'.mkv', '.mp4', '.avi', '.m4v', '.ts', '.strm', '.mov'}:
                    result[str(path.relative_to(root))] = os.readlink(path) if entry.is_symlink() else '<regular-file>'
    for category in ('movies', 'movies-4k', 'tv'): visit(root / category)
    return result


def mount_table(path=Path('/proc/self/mountinfo')):
    result = {}
    for line in path.read_text().splitlines():
        fields = line.split(); separator = fields.index('-')
        decode = lambda value: re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), value)
        result[decode(fields[4])] = {'device': fields[2], 'root': decode(fields[3]), 'type': fields[separator + 1]}
    return result


def validate_nas(row, held):
    if (row['Name'] != '/plex-nas' or row['State']['Running'] or row['State']['Status'] != 'created'
        or not row['State'].get('StartedAt', '').startswith('0001-') or row['Config']['Image'] != IMAGE
        or row['HostConfig']['RestartPolicy']['Name'] != 'no' or row['HostConfig']['NetworkMode'] != 'host'):
        raise RuntimeError('The never-started NAS Plex preparation differs; it was retained.')
    expected = {'/config': DATA / 'config', '/flora-test-library': DATA / 'flora-test-library', '/scratch': SCRATCH,
                '/mnt/media': LIBRARY, '/mnt/nzbdav': Path('/mnt/nzbdav'), '/torbox-cams': Path('/mnt/torbox-media/movies')}
    if len(row['Mounts']) != 6 or {m['Destination']: Path(m['Source']) for m in row['Mounts'] if m['Type'] == 'bind'} != expected:
        raise RuntimeError('A NAS Plex binding differs; it was retained.')
    if row['HostConfig'].get('Devices') != [{'PathOnHost': '/dev/dri', 'PathInContainer': '/dev/dri', 'CgroupPermissions': 'rwm'}]:
        raise RuntimeError('The NAS Intel graphics binding differs.')
    mappings = read_json(SSD / 'compose/plex-nas/image-identities.json')
    if mappings['plex']['source'] != SOURCE_IMAGE or mappings['plex']['nas'] != row['Image']:
        raise RuntimeError('The NAS Plex image identity differs.')
    if identity(DATA / 'config') != held['identitySha256']:
        raise RuntimeError('The source and prepared NAS Plex identities differ.')
    marker = read_json(DATA / '.standby-refreshed.json')
    if marker.get('format') != 'Sawdoctor NAS Plex standby refresh v1': raise RuntimeError('The NAS standby preparation marker differs.')
    stamp = marker['sourceCreatedUtc']
    created = dt.datetime.strptime(stamp, '%Y%m%dT%H%M%SZ').replace(tzinfo=dt.timezone.utc)
    if not -dt.timedelta(minutes=5) <= dt.datetime.now(dt.timezone.utc) - created <= dt.timedelta(hours=48):
        raise RuntimeError('The prepared NAS Plex snapshot is more than 48 hours old; it was retained.')
    snapshot = SSD / 'migration/nightly-standby/snapshots' / stamp
    verified = read_json(snapshot / '_VERIFIED.json')
    if verified.get('sha256') != marker['sourceArchiveSha256']: raise RuntimeError('The prepared standby archive marker differs.')
    source = media_paths(snapshot / 'data/library'); nas = media_paths(LIBRARY)
    if not source or any(nas.get(name) != target for name, target in source.items()):
        raise RuntimeError('Source library links are absent or changed on the NAS; no scan or link replacement was attempted.')
    mounts = mount_table()
    for target, kind in (('/mnt/nzbdav', 'fuse.rclone'), ('/mnt/torbox-media', 'fuse.main.py')):
        if mounts.get(target, {}).get('type') != kind: raise RuntimeError('A required NAS media mount is unavailable.')
    if not os.access('/dev/dri/renderD128', os.R_OK | os.W_OK): raise RuntimeError('The NAS Intel render device is unavailable.')
    return mounts


def wait_api(config, expected_identity):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            result = api('/identity', config)
            if sha(result.get('machineIdentifier', '').encode()) != expected_identity:
                raise RuntimeError('The running Plex server identity differs.')
            if not result.get('version', '').startswith('1.43.5.11079'):
                raise RuntimeError('The running Plex version differs from the reviewed image.')
            return
        except (OSError, ET.ParseError): time.sleep(3)
    raise RuntimeError('Plex did not become responsive within two minutes.')


def bind_check(row, host):
    namespace = mount_table(Path('/proc') / str(row['State']['Pid']) / 'mountinfo')
    for source, target, suffix in (('/mnt/nzbdav', '/mnt/nzbdav', ''), ('/mnt/torbox-media', '/torbox-cams', '/movies')):
        expected = host[source]
        actual = namespace.get(target, {})
        root = expected['root'].rstrip('/') + suffix or '/'
        if actual.get('device') != expected['device'] or actual.get('root') != root:
            raise RuntimeError('NAS Plex received an old media mount; the trial will be stopped.')


def start_nas():
    if NAS_STATE.exists():
        state = read_json(NAS_STATE)
        if state.get('format') == SIGNATURE and state.get('phase') == 'active' and inspect('plex-nas')['State']['Running']:
            source_remote(); say('NAS PLEX TRIAL ACTIVE. Existing trial settings were retained.'); return
        raise RuntimeError('An existing NAS trial record was retained; use nas-stop before another trial.')
    if not SSD.is_mount() or not SCRATCH.is_mount(): raise RuntimeError('NAS appdata and scratch filesystems must be mounted.')
    with locks(['/run/lock/sawdoctor-nas-backup.lock', NAS / '.lock']):
        held = source_remote()
        if port_open('192.168.0.29') or port_open('127.0.0.1'): raise RuntimeError('A Plex port is already active; NAS Plex was retained.')
        row = inspect('plex-nas'); mounts = validate_nas(row, held)
        recovery = run('/usr/local/sbin/nas-media-recovery', 'check', timeout=30)
        if 'Media clients with unavailable/old mounts: none' not in recovery or 'Pending backup recovery records: 0' not in recovery:
            raise RuntimeError('NAS media recovery still has pending clients; Plex was retained.')
        prefs = DATA / 'config' / PREFS
        before = NAS / 'Preferences.before.xml'
        if before.exists(): raise RuntimeError('An earlier NAS trial preference copy was retained.')
        shutil.copy2(prefs, before); info = prefs.stat(); os.chown(before, info.st_uid, info.st_gid)
        state = {'format': SIGNATURE, 'phase': 'preparing', 'trialId': held['trialId'],
                 'receiptKey': held['receiptKey'], 'identitySha256': held['identitySha256'],
                 'containerId': row['Id'], 'preferencesBeforeSha256': file_sha(before),
                 'createdUtc': dt.datetime.now(dt.timezone.utc).isoformat()}
        write_json(NAS_STATE, state)
        root = ET.fromstring(before.read_bytes())
        for key, value in SAFE_PREFS.items(): root.set(key, value)
        atomic(prefs, ET.tostring(root, encoding='utf-8', xml_declaration=True), reference=before)
        try:
            # Recheck the remote hold immediately before the only start.
            if source_remote()['trialId'] != held['trialId']: raise RuntimeError('The source trial changed; NAS Plex stays stopped.')
            say('Starting the prepared NAS Plex container; automatic scans and empty-trash are paused for this trial...')
            run('docker', 'start', row['Id'], timeout=45, private=NAS / 'private-error.log')
            wait_api(DATA / 'config', held['identitySha256'])
            bind_check(inspect('plex-nas'), mounts)
            if source_remote()['trialId'] != held['trialId']: raise RuntimeError('The source hold changed; NAS Plex will stop.')
            state['phase'] = 'active'; write_json(NAS_STATE, state)
        except BaseException:
            run('docker', 'stop', '--time', '30', row['Id'], timeout=50, private=NAS / 'private-error.log')
            state['phase'] = 'stopped'; write_json(NAS_STATE, state)
            say('NAS trial did not finish starting. NAS Plex is stopped; source Plex remains safely held.')
            say('Run sudo /usr/local/sbin/nas-plex-trial nas-stop here to obtain the source return command.')
            raise
    say('NAS PLEX TRIAL ACTIVE: http://192.168.0.220:32400/web')
    say('Plex identity, reviewed version and live NZB/TorBox mount bindings passed. Restart remains disabled.')
    say('Use the direct NAS address for playback/seek tests. Public proxy and router forwarding are unchanged.')
    say('The prepared watch history is from the 4 November snapshot; final handover still needs fresh data.')
    say('To finish: sudo /usr/local/sbin/nas-plex-trial nas-stop')


def make_receipt(state, now=None):
    payload = {'trialId': state['trialId'], 'stoppedAt': int(time.time() if now is None else now),
               'nasContainerId': state['containerId'], 'action': 'nas-plex-stopped'}
    raw = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip('=') + '.' + hmac.new(bytes.fromhex(state['receiptKey']), raw, hashlib.sha256).hexdigest()


def verify_receipt(token, state, now=None):
    try:
        encoded, signature = token.split('.')
        raw = base64.b64decode(encoded + '=' * (-len(encoded) % 4), altchars=b'-_', validate=True)
        payload = json.loads(raw)
        expected = hmac.new(bytes.fromhex(state['receiptKey']), raw, hashlib.sha256).hexdigest()
        age = int(time.time() if now is None else now) - payload['stoppedAt']
        valid = (hmac.compare_digest(signature, expected) and payload['trialId'] == state['trialId']
                 and payload['action'] == 'nas-plex-stopped' and -30 <= age <= 600
                 and re.fullmatch(r'[0-9a-f]{64}', payload['nasContainerId']) is not None)
    except (ValueError, KeyError, TypeError): valid = False
    if not valid: raise RuntimeError('The NAS stopped receipt is invalid or expired; get a fresh one with nas-stop on the NAS.')


def stop_nas():
    with locks(['/run/lock/sawdoctor-nas-backup.lock', NAS / '.lock']):
        state = read_json(NAS_STATE)
        if state.get('format') != SIGNATURE: raise RuntimeError('An unrelated NAS trial record was retained.')
        row = inspect('plex-nas')
        if row['Id'] != state['containerId'] or row['HostConfig']['RestartPolicy']['Name'] != 'no':
            raise RuntimeError('The NAS trial container/restart policy changed; no source return receipt was issued.')
        if row['State']['Running']:
            say('Stopping NAS Plex before returning the server identity to the OptiPlex...')
            run('docker', 'stop', '--time', '40', row['Id'], timeout=65, private=NAS / 'private-error.log')
        if inspect('plex-nas')['State']['Running'] or port_open('127.0.0.1'):
            raise RuntimeError('NAS Plex has not fully stopped; no source return receipt was issued.')
        state['phase'] = 'stopped'; write_json(NAS_STATE, state)
        token = make_receipt(state)
    say('NAS PLEX STOPPED. Source Plex remains held until you run the following on the OptiPlex:')
    say('sudo /usr/local/sbin/nas-plex-trial source-resume ' + token)
    say('This return command expires in ten minutes. Re-run nas-stop here for a fresh command if needed.')


def resume_source(token):
    with locks([SOURCE / '.lock']):
        state = read_json(HOLD)
        if state.get('format') != SIGNATURE or state['phase'] != 'held': raise RuntimeError('The source trial is not in its held phase.')
        verify_receipt(token, state)
        if port_open('192.168.0.220'): raise RuntimeError('NAS port 32400 is active; source Plex stays held.')
        state['releaseAuthorized'] = True; write_json(HOLD, state)
        restore_source(state, start=True)


def install(source, role):
    root = SOURCE if role == 'source' else NAS
    if root.is_symlink(): raise RuntimeError('An unexpected symbolic trial directory was retained.')
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if WORKER.exists() and (WORKER.is_symlink() or SIGNATURE not in WORKER.read_text()):
        raise RuntimeError('An unrelated trial helper already exists; it was retained.')
    if WORKER.exists() and sha(WORKER.read_bytes()) != sha(source):
        raise RuntimeError('A different trial helper is installed; it was retained for review.')
    atomic(WORKER, source, 0o700)
    unit = 'nas-plex-trial-hold' if role == 'source' else 'nas-plex-trial-start'
    state = unit_state(unit + '.service')
    if state.get('ActiveState') in ('active', 'activating', 'deactivating'):
        say('The Plex trial operation is already running.'); return
    run('systemctl', 'reset-failed', unit + '.service', allowed=(0, 1, 4))
    args = ['systemd-run', '--unit=' + unit, '--collect', '--description=Guarded Plex migration trial (' + role + ')',
            '--property=TimeoutStartSec=10min', '--property=UMask=0077']
    if role == 'source': args += ['--property=ExecStopPost=' + str(WORKER) + ' source-recover']
    args += [str(WORKER), 'source-hold' if role == 'source' else 'nas-start']
    if role == 'source': args += ['--daytime-authorized']
    run(*args)
    say('Plex trial ' + ('source hold' if role == 'source' else 'NAS start') + ' started in systemd. Closing SSH is safe.')
    say('Check: sudo journalctl -u ' + unit + '.service -n 25 --no-pager -o cat')


def main():
    os.umask(0o077)
    role = host_role()
    if 'INSTALL_SOURCE' in globals():
        expected = globals().get('INSTALL_ROLE')
        if role != expected: raise RuntimeError('This installer belongs on the ' + str(expected) + ' host.')
        install(globals()['INSTALL_SOURCE'].encode(), role); return
    args = sys.argv[1:]
    if role == 'source':
        if args == ['source-status-private']: private_source_status(); return
        if args == ['source-hold', '--daytime-authorized']: hold_source(daytime=True); return
        if args == ['source-recover']: recover_source(); return
        if len(args) == 2 and args[0] == 'source-resume': resume_source(args[1]); return
    if role == 'nas':
        if args == ['nas-start']: start_nas(); return
        if args == ['nas-stop']: stop_nas(); return
    raise RuntimeError('Use the correct host and documented trial operation.')


if __name__ == '__main__':
    try: main()
    except RuntimeError as error: raise SystemExit('STOP: ' + str(error))
    except Exception as error:
        raise SystemExit('STOP: Plex trial could not complete (' + type(error).__name__ + '). Read the service journal; no source resume is automatic after a completed hold.') from None
