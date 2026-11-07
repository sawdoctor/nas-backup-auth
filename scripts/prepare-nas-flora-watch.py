#!/usr/bin/env python3
"""Stage the original monitor-only Flora queue check; leave its NAS timer disabled."""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import tempfile
import urllib.parse

SIGNATURE = 'Sawdoctor NAS Flora queue monitor v1'
APP_UUID = 'e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6'
BACKUP_UUID = '631e3391-6a42-4158-9aa4-f7718ba0e7e9'
APP = Path('/srv/dev-disk-by-uuid-' + APP_UUID)
BACKUP = Path('/srv/dev-disk-by-uuid-' + BACKUP_UUID)
BASE = BACKUP / 'migration/nightly-standby'
DATA = APP / 'appdata/host-jobs/flora-queue-watch'
HELPER = Path('/usr/local/sbin/nas-flora-queue-watch')
UNIT = Path('/etc/systemd/system/nas-flora-queue-watch.service')
TIMER = Path('/etc/systemd/system/nas-flora-queue-watch.timer')
LOCK = Path('/run/lock/sawdoctor-nas-backup.lock')
SOURCE_SHA = 'befb945811dd40a72821c129d19db606587539dafce6bfb965761f37da25998c'
FORMAT = 'sawdoctor-migration-standby-v1'


def say(text):
    print(text, flush=True)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def no_links(path):
    if any(item.is_symlink() for item in (path, *path.parents)):
        raise RuntimeError('An unexpected symbolic monitor path was retained.')


def read(path, limit=2 * 1024**2):
    no_links(path)
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise RuntimeError('A monitor input is unavailable or exceeds its size limit.')
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    if len(data) > limit or any(getattr(before, key) != getattr(after, key) for key in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
        raise RuntimeError('A monitor input changed during validation.')
    return data


def atomic(path, data, mode=0o600):
    no_links(path)
    fd, temporary = tempfile.mkstemp(prefix='.flora-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            os.fchmod(output.fileno(), mode)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def run(*args, allowed=(0,), input=None):
    result = subprocess.run(args, capture_output=True, text=True, input=input, timeout=20)
    if result.returncode not in allowed:
        raise RuntimeError('A monitor setup query failed; command output was withheld.')
    return result.stdout


def mount(path, uuid):
    no_links(path)
    if not path.is_mount() or run('findmnt', '-rn', '--mountpoint', str(path), '-o', 'UUID,FSTYPE').split() != [uuid, 'ext4']:
        raise RuntimeError('An expected NAS filesystem identity differs.')


@contextlib.contextmanager
def locked(path, shared=False):
    no_links(path)
    with path.open('rb') as handle:
        try:
            fcntl.flock(handle, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('NAS backup, mount recovery or standby work is busy; retry later.') from None
        yield


def source_file():
    current = json.loads(read(BASE / 'current.json'))
    stamp = current.get('createdUtc', '')
    if not re.fullmatch(r'[0-9]{8}T[0-9]{6}Z', stamp) or current.get('format') != FORMAT:
        raise RuntimeError('The current standby identity differs.')
    folder = BASE / 'snapshots' / stamp
    no_links(folder)
    if current.get('snapshot') != str(folder) or json.loads(read(folder / '_VERIFIED.json')) != {key: value for key, value in current.items() if key != 'snapshot'}:
        raise RuntimeError('The current standby locator or verification marker differs.')
    manifest = json.loads(read(folder / 'manifest.json', 8 * 1024**2))
    if (manifest.get('format') != FORMAT or manifest.get('sourceHost') != '192.168.0.29'
            or manifest.get('createdUtc') != stamp or manifest.get('scope') != 'standby-only'
            or manifest.get('dataRoots', {}).get('host.scripts', {}).get('snapshot') != 'data/host.scripts'):
        raise RuntimeError('The standby host-script manifest differs.')
    source = read(folder / 'data/host.scripts/flora-nzbdav-watch.sh')
    if digest(source) != SOURCE_SHA:
        raise RuntimeError('The original Flora monitor changed; review it before adapting.')
    return source, stamp


def assignment(text, key):
    matches = re.findall(r'^' + re.escape(key) + r'="([^"\r\n]*)"$', text, re.M)
    if len(matches) != 1:
        raise RuntimeError('An original Flora setting differs from the reviewed script.')
    return matches[0]


def adapt(source, database):
    if digest(source) != SOURCE_SHA:
        raise RuntimeError('The original Flora monitor identity differs.')
    text = source.decode()
    if (text.count('THRESHOLD_MINUTES=60\n') != 1 or text.count('STOP_NZBDAV=0\n') != 1
            or assignment(text, 'DB') != '/home/sawdoctor/docker/nzbdav/nzbdav-config/db.sqlite'
            or assignment(text, 'LOG') != '/home/sawdoctor/logs/flora-nzbdav-watch.log'):
        raise RuntimeError('The original monitoring-only policy differs.')
    url = urllib.parse.urlsplit(assignment(text, 'KUMA_URL'))
    if (url.scheme != 'http' or url.hostname != '192.168.0.29' or url.port != 3001
            or url.username or url.password or url.query or url.fragment
            or not re.fullmatch(r'/api/push/[A-Za-z0-9_-]{4,200}', url.path)):
        raise RuntimeError('The original private Kuma push endpoint differs.')
    replacements = {'DB': str(database), 'LOG': str(DATA / 'flora-nzbdav-watch.log'),
                    'KUMA_URL': 'http://192.168.0.220:3001' + url.path}
    for key, value in replacements.items():
        if re.search(r'["$`\\\r\n]', value):
            raise RuntimeError('An unsafe NAS monitor setting was rejected.')
        text, count = re.subn(r'^' + key + r'="[^"\r\n]*"$', lambda _: key + '="' + value + '"', text, flags=re.M)
        if count != 1:
            raise RuntimeError('A scoped Flora setting could not be adapted.')
    return text.encode(), url.path.rsplit('/', 1)[1]


def bindings():
    rows = json.loads(run('docker', 'inspect', 'infinidysk-nas', 'uptime-kuma-nas'))
    by_name = {row['Name'].lstrip('/'): row for row in rows}
    result = []
    for name, target, expected, filename in (
            ('infinidysk-nas', '/config', APP / 'appdata/infinidysk-nas', 'db.sqlite'),
            ('uptime-kuma-nas', '/app/data', APP / 'appdata/support-nas/uptime-kuma', 'kuma.db')):
        row = by_name.get(name, {})
        mounts = [Path(item['Source']) for item in row.get('Mounts', []) if item.get('Type') == 'bind' and item.get('Destination') == target]
        if not row.get('State', {}).get('Running') or len(mounts) != 1:
            raise RuntimeError('The running NAS monitor dependencies or config bindings differ.')
        path = mounts[0]
        no_links(path)
        if not path.is_dir() or not path.resolve().is_relative_to(expected.resolve()):
            raise RuntimeError('A monitor database binding is outside its expected NAS appdata.')
        no_links(path / filename)
        if not (path / filename).is_file():
            raise RuntimeError('An expected NAS monitoring database is unavailable.')
        result.append(path / filename)
    return tuple(result)


def inspect_databases(database, kuma, token):
    @contextlib.contextmanager
    def connect(path):
        no_links(path)
        connection = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=5)
        try:
            connection.execute('PRAGMA query_only=ON')
            yield connection
        finally:
            connection.close()
    with connect(database) as connection:
        columns = {str(row[1]).lower() for row in connection.execute('PRAGMA table_info(QueueItems)')}
        if not {'jobname', 'createdat'}.issubset(columns):
            raise RuntimeError('The NAS queue schema differs from the original monitor queries.')
        count, age = connection.execute("SELECT COUNT(*), CAST((strftime('%s','now') - strftime('%s', MIN(CreatedAt))) / 60 AS INTEGER) FROM QueueItems").fetchone()
    if count and age is None:
        raise RuntimeError('The NAS queue timestamp format needs review before monitoring.')
    with connect(kuma) as connection:
        monitors = connection.execute("SELECT active FROM monitor WHERE type='push' AND push_token=?", (token,)).fetchall()
    if len(monitors) != 1 or monitors[0][0] not in (0, 1):
        raise RuntimeError('The matching copied NAS Kuma push monitor is unavailable or ambiguous.')
    return {'queueItems': count, 'oldestQueueAgeMinutes': age if count else 0,
            'thresholdMinutes': 60, 'stuckByOriginalRule': bool(count and age >= 60),
            'matchingNasKumaPushMonitors': 1, 'nasKumaMonitorActive': bool(monitors[0][0]),
            'stopInfinidysk': False, 'pushRequestSent': False}


def unit_texts():
    return {UNIT: f'''# {SIGNATURE}
[Unit]
Description=Report NAS InfiniDysk queue age to Uptime Kuma
After=docker.service
RequiresMountsFor={APP}
[Service]
Type=oneshot
UMask=0077
ExecStart={HELPER} --run
SuccessExitStatus=2
TimeoutStartSec=65
Nice=10
'''.encode(), TIMER: f'''# {SIGNATURE}
[Unit]
Description=NAS Flora queue monitor every 15 minutes
[Timer]
OnCalendar=*-*-* *:0/15:00 Europe/London
Persistent=false
Unit={UNIT.name}
[Install]
WantedBy=timers.target
'''.encode()}


def paused_units():
    for path in (UNIT, TIMER):
        output = run('systemctl', 'show', path.name, '-p', 'LoadState', '-p', 'ActiveState', '-p', 'UnitFileState', allowed=(0, 1, 4))
        props = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
        if (props.get('LoadState') not in ('loaded', 'not-found') or props.get('ActiveState') not in ('inactive', 'failed')
                or props.get('UnitFileState', '') not in ('', 'disabled', 'static')):
            raise RuntimeError('A Flora monitor unit is active, enabled or has an unexpected state; it was retained.')


def staged():
    state = json.loads(read(DATA / 'prepared.json'))
    if state.get('format') != SIGNATURE or state.get('sourceSha256') != SOURCE_SHA or digest(read(HELPER)) != state.get('helperSha256'):
        raise RuntimeError('The staged Flora helper or preparation record differs.')
    source = read(DATA / 'original.sh')
    no_links(DATA / 'flora-nzbdav-watch.log')
    database, kuma = Path(state['database']), Path(state['kumaDatabase'])
    for path, root, filename in ((database, APP / 'appdata/infinidysk-nas', 'db.sqlite'),
                                 (kuma, APP / 'appdata/support-nas/uptime-kuma', 'kuma.db')):
        no_links(path)
        if not path.is_absolute() or path.name != filename or not path.resolve().is_relative_to(root.resolve()):
            raise RuntimeError('A staged monitor database path is outside its NAS appdata.')
    runtime, token = adapt(source, database)
    if read(DATA / 'runtime.sh') != runtime or digest(runtime) != state.get('runtimeSha256'):
        raise RuntimeError('The staged Flora runtime differs from the scoped adaptation.')
    return database, kuma, token


def prepare(source_code):
    mount(BACKUP, BACKUP_UUID)
    with locked(BASE / '.run.lock', shared=True):
        paused_units()
        source, stamp = source_file()
        database, kuma = bindings()
        runtime, token = adapt(source, database)
        run('/usr/bin/bash', '-n', input=runtime.decode())
        for executable in ('sqlite3', 'curl', 'tee', 'date', 'cut', 'docker'):
            try:
                run('/usr/bin/which', executable)
            except RuntimeError:
                raise RuntimeError('The NAS needs the ' + executable + ' command before this monitor can be staged.') from None
        summary = inspect_databases(database, kuma, token)
        files = {HELPER: (source_code, 0o700), DATA / 'original.sh': (source, 0o600), DATA / 'runtime.sh': (runtime, 0o700)}
        files.update({path: (data, 0o644) for path, data in unit_texts().items()})
        no_links(DATA)
        no_links(DATA / 'flora-nzbdav-watch.log')
        if DATA.exists():
            extras = {path.name for path in DATA.iterdir()} - {'original.sh', 'runtime.sh', 'prepared.json', 'flora-nzbdav-watch.log'}
            if extras:
                raise RuntimeError('Unrecognized Flora preparation files were retained.')
        for path, (data, mode) in files.items():
            no_links(path)
            if path.exists() and (read(path) != data or stat.S_IMODE(path.stat().st_mode) != mode):
                raise RuntimeError('An existing Flora setup file differs; it was retained.')
        record = {'format': SIGNATURE, 'sourceSnapshot': stamp, 'sourceSha256': SOURCE_SHA,
                  'runtimeSha256': digest(runtime), 'helperSha256': digest(source_code),
                  'database': str(database), 'kumaDatabase': str(kuma),
                  'thresholdMinutes': 60, 'timerEnabled': False, 'stopInfinidysk': False}
        record_data = (json.dumps(record, indent=2) + '\n').encode()
        if (DATA / 'prepared.json').exists() and read(DATA / 'prepared.json') != record_data:
            raise RuntimeError('An existing Flora preparation record differs; it was retained.')
        DATA.mkdir(mode=0o700, parents=True, exist_ok=True)
        for path, (data, mode) in files.items():
            if not path.exists():
                path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                atomic(path, data, mode)
        if not (DATA / 'prepared.json').exists():
            atomic(DATA / 'prepared.json', record_data)
        run('systemctl', 'daemon-reload')
        paused_units()
    say('Read-only NAS queue/Kuma plan: ' + json.dumps(summary, sort_keys=True))
    say('NAS FLORA QUEUE MONITOR PREPARED: original logic retained, threshold 60 minutes, timer disabled.')
    say('No alert push, InfiniDysk stop/restart, cloud write or source-host change was made.')
    say('Later read-only check: sudo ' + str(HELPER) + ' --plan')


def main():
    os.umask(0o077)
    args = sys.argv[1:]
    if args not in ([], ['--plan'], ['--run']):
        raise RuntimeError('Use no arguments to stage, --plan to inspect, or the scheduled --run.')
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the NAS.')
    mount(APP, APP_UUID)
    with locked(LOCK, shared=args == ['--plan']):
        if not args:
            source = globals().get('INSTALL_SOURCE')
            if source is None and '__file__' in globals():
                source = Path(__file__).read_text()
            if not source:
                raise RuntimeError('Use the complete reviewed Flora preparation command.')
            prepare(source.encode())
            return
        database, kuma, token = staged()
        if args == ['--plan']:
            if bindings() != (database, kuma):
                raise RuntimeError('The current monitor bindings differ from the staged paths.')
            summary = inspect_databases(database, kuma, token)
            say('Read-only NAS queue/Kuma plan: ' + json.dumps(summary, sort_keys=True))
            return
        # Only the later enabled timer uses this path. Original STOP_NZBDAV=0
        # and the exact adapted bytes are revalidated before every invocation.
        result = subprocess.run(['/usr/bin/bash', str(DATA / 'runtime.sh')], timeout=55)
        raise SystemExit(result.returncode)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        say('STOP: ' + (str(error) if isinstance(error, RuntimeError) else type(error).__name__))
        sys.exit(1)
