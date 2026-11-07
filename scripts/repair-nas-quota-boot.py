#!/usr/bin/env python3
"""Skip duplicate quota activation only for three verified NAS filesystems."""
import contextlib
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile

SSDUUID = 'e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6'
BACKUP_UUID = '631e3391-6a42-4158-9aa4-f7718ba0e7e9'
UUIDS = (SSDUUID, '1f12a22e-5cfe-4b02-8d4b-48e9bf5fec6a', BACKUP_UUID)
TARGETS = tuple('/srv/dev-disk-by-uuid-' + item for item in UUIDS)
SSD = Path(TARGETS[0])
CHECKER = Path('/usr/local/libexec/nas-quota-boot-check')
BASE = Path('/usr/lib/systemd/system/quotaon@.service')
SYSTEM = Path('/etc/systemd/system')
WORK = SSD / 'compose/quota-boot'
LOCK = Path('/run/lock/sawdoctor-nas-backup.lock')
UNIT = 'nas-quota-boot-repair'
DROPIN = '50-nas-already-enabled.conf'
FORMAT = 'sawdoctor-nas-quota-boot-precheck-v1'

ORIGINAL_CHECKER_SHA = 'e2893f0d23c3d0dc34f566072e330396643eea08deb7911b1e2546b97be9584b'
ORIGINAL_CHECKER_CODE = r'''#!/usr/bin/python3
"""Read-only systemd ExecCondition: 1=already on, 0=enable normally, 255=error."""
import os
from pathlib import Path
import re
import subprocess
import sys

TARGETS = ('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6',
           '/srv/dev-disk-by-uuid-1f12a22e-5cfe-4b02-8d4b-48e9bf5fec6a')

def quota_state(path):
    if path not in TARGETS or not Path(path).is_mount() or Path(path).is_symlink():
        raise RuntimeError('The expected NAS quota mount is unavailable.')
    identity = subprocess.run(['/usr/bin/findmnt', '-rn', '--mountpoint', path, '-o', 'UUID,FSTYPE'],
                              capture_output=True, text=True, timeout=15)
    uuid = path.removeprefix('/srv/dev-disk-by-uuid-')
    if identity.returncode or identity.stdout.split() != [uuid, 'ext4']:
        raise RuntimeError('The NAS quota filesystem identity differs.')
    result = subprocess.run(['/usr/sbin/quotaon', '-p', '-u', '-g', path],
                            capture_output=True, text=True, timeout=15,
                            env={**os.environ, 'LC_ALL': 'C', 'LANG': 'C'})
    pattern = r'(user|group) quota on ' + re.escape(path) + r' \(/dev/[^()\s]+\) is (on|off)'
    rows = [re.fullmatch(pattern, line) for line in result.stdout.splitlines()]
    if (result.stderr.strip() or len(rows) != 2 or not all(rows)
            or {row[1] for row in rows} != {'user', 'group'}):
        raise RuntimeError('The NAS user/group quota state could not be verified.')
    state = {row[1]: row[2] for row in rows}
    # quotaon -p returns the number of enabled quotas, not a success/failure code.
    # Require that count to match both complete, validated state lines.
    if result.returncode != sum(value == 'on' for value in state.values()):
        raise RuntimeError('The NAS quota query exit status differs from its reported states.')
    return state

def main():
    if os.geteuid() != 0 or len(sys.argv) != 2:
        raise RuntimeError('Use this quota condition as root with one expected NAS mount.')
    state = quota_state(sys.argv[1])
    if all(value == 'on' for value in state.values()):
        print('NAS user/group quotas are already on; duplicate quota activation skipped.', flush=True)
        return 1
    print('NAS quotas need activation; retaining the packaged quotaon command.', flush=True)
    return 0

if __name__ == '__main__':
    try:
        code = main()
    except Exception as error:
        print('NAS quota precheck failed: ' + str(error), file=sys.stderr, flush=True)
        code = 255
    sys.exit(code)
'''
CHECKER_CODE = ORIGINAL_CHECKER_CODE.replace(
    "           '/srv/dev-disk-by-uuid-1f12a22e-5cfe-4b02-8d4b-48e9bf5fec6a')",
    "           '/srv/dev-disk-by-uuid-1f12a22e-5cfe-4b02-8d4b-48e9bf5fec6a',\n"
    "           '/srv/dev-disk-by-uuid-" + BACKUP_UUID + "')", 1)


def say(message):
    print(message, flush=True)


def no_links(path):
    for item in (path, *path.parents):
        if item.is_symlink():
            raise RuntimeError('An unexpected symbolic quota repair path was retained.')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(*args, timeout=30):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('A quota repair command failed; inspect the quota service journal.')
    return result.stdout


def atomic(path, data, mode=0o600):
    no_links(path)
    fd, temporary = tempfile.mkstemp(prefix='.nas-quota-', dir=path.parent)
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


def checker_namespace():
    namespace = {'__name__': 'quota_checker_preflight'}
    exec(compile(CHECKER_CODE, str(CHECKER), 'exec'), namespace)
    return namespace


def dropin():
    return ('# ' + FORMAT + '\n[Service]\nExecCondition=' + str(CHECKER) + ' %f\n').encode()


def properties(unit):
    output = run('systemctl', 'show', '--no-pager', unit, '-p', 'FragmentPath',
                 '-p', 'DropInPaths', '-p', 'ActiveState')
    return dict(line.split('=', 1) for line in output.splitlines() if '=' in line)


def expected_dropin(props, destination, allow_absent=False):
    # systemctl quotes string-list paths and doubles literal backslashes.
    # These fixed ASCII destinations need only the plain and quoted forms;
    # compare the complete value so additional overrides still fail closed.
    actual = props.get('DropInPaths')
    return ((allow_absent and actual == '')
            or actual in (destination, json.dumps(destination)))


def template_check(text):
    required = {'ExecStart=/usr/sbin/quotaon -ug %f', 'Type=oneshot',
                'RemainAfterExit=yes', 'DefaultDependencies=no', 'BindsTo=%i.mount'}
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith('#')]
    if (not required.issubset(lines) or sum(line.startswith('ExecStart=') for line in lines) != 1
            or any(line.startswith(('ExecCondition=', 'ExecStartPre=', 'ExecStartPost=')) for line in lines)):
        raise RuntimeError('The packaged quota activation service differs from the supplied definition.')


def filesystem_check(path):
    uuid = path.removeprefix('/srv/dev-disk-by-uuid-')
    output = run('tune2fs', '-l', 'UUID=' + uuid)
    values = dict(line.split(':', 1) for line in output.splitlines() if ':' in line)
    if ('quota' not in values.get('Filesystem features', '').split()
            or values.get('User quota inode', '').strip() != '3'
            or values.get('Group quota inode', '').strip() != '4'):
        raise RuntimeError('The NAS internal quota features differ from the inspected filesystems.')


def plan():
    if digest(ORIGINAL_CHECKER_CODE.encode()) != ORIGINAL_CHECKER_SHA:
        raise RuntimeError('The reviewed original quota checker identity differs.')
    no_links(BASE)
    template = BASE.read_bytes()
    template_check(template.decode())
    no_links(CHECKER)
    if CHECKER.exists() and (not CHECKER.is_file() or CHECKER.read_bytes() not in
                             (ORIGINAL_CHECKER_CODE.encode(), CHECKER_CODE.encode())
                             or stat.S_IMODE(CHECKER.stat().st_mode) != 0o700 or CHECKER.stat().st_uid != 0):
        raise RuntimeError('An existing quota condition helper differs; it was retained.')
    check = checker_namespace()['quota_state']
    entries = []
    for path in TARGETS:
        filesystem_check(path)
        if check(path) != {'user': 'on', 'group': 'on'}:
            raise RuntimeError('Both quotas must already be on before installing this startup-only repair.')
        unit = run('systemd-escape', '--path', '--template=quotaon@.service', path).strip()
        if not re.fullmatch(r'quotaon@[A-Za-z0-9\\x-]+\.service', unit):
            raise RuntimeError('An unexpected quota unit identity was rejected.')
        destination = SYSTEM / (unit + '.d') / DROPIN
        no_links(destination)
        props = properties(unit)
        if (props.get('FragmentPath') != str(BASE)
                or not expected_dropin(props, str(destination), allow_absent=True)
                or props.get('ActiveState') not in ('inactive', 'failed', 'active')):
            raise RuntimeError('An existing quota override or active transition needs review.')
        if destination.parent.exists():
            extras = [item for item in destination.parent.glob('*.conf') if item != destination]
            if extras:
                raise RuntimeError('An unrelated quota override was retained.')
        if destination.exists() and (not destination.is_file() or destination.read_bytes() != dropin()):
            raise RuntimeError('An edited quota condition override was retained.')
        entries.append({'unit': unit, 'mount': path, 'dropin': str(destination)})
    return template, entries


def record(phase, template, entries):
    no_links(WORK)
    WORK.mkdir(mode=0o700, parents=True, exist_ok=True)
    atomic(WORK / 'result.json', (json.dumps({
        'format': FORMAT, 'phase': phase,
        'updatedUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'packagedTemplateSha256': digest(template), 'checkerSha256': digest(CHECKER_CODE.encode()),
        'entries': entries, 'quotaLimitsChanged': False, 'filesystemFeaturesChanged': False,
        'mountOptionsChanged': False, 'applicationServicesChanged': False}, indent=2) + '\n').encode())


def repair():
    no_links(LOCK)
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('NAS backup/recovery is busy; retry the quota repair later.') from None
        say('Verifying all three quota mounts and the existing packaged startup definitions...')
        template, entries = plan()
        CHECKER.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        if CHECKER.exists() and CHECKER.read_bytes() == ORIGINAL_CHECKER_CODE.encode():
            no_links(WORK)
            WORK.mkdir(mode=0o700, parents=True, exist_ok=True)
            previous = WORK / 'checker.before-fikwot'
            no_links(previous)
            if previous.exists() and (not previous.is_file() or previous.read_bytes() != ORIGINAL_CHECKER_CODE.encode()):
                raise RuntimeError('A different original-checker recovery copy was retained.')
            if not previous.exists():
                atomic(previous, ORIGINAL_CHECKER_CODE.encode())
            atomic(CHECKER, CHECKER_CODE.encode(), 0o700)
        elif not CHECKER.exists():
            atomic(CHECKER, CHECKER_CODE.encode(), 0o700)
        for item in entries:
            destination = Path(item['dropin'])
            destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            if not destination.exists():
                atomic(destination, dropin(), 0o644)
        record('installed', template, entries)
        run('systemctl', 'daemon-reload')
        try:
            for item in entries:
                run('systemctl', 'start', item['unit'], timeout=60)
                props = properties(item['unit'])
                if not expected_dropin(props, item['dropin']):
                    raise RuntimeError('The loaded quota override differs from the expected single precheck.')
                if props.get('ActiveState') not in ('inactive', 'active'):
                    raise RuntimeError('The quota startup unit did not reach its expected skipped/active state.')
                if checker_namespace()['quota_state'](item['mount']) != {'user': 'on', 'group': 'on'}:
                    raise RuntimeError('The user/group quotas did not remain enabled after the startup check.')
                say(item['mount'] + ': user/group quotas ON; startup precheck verified.')
            if BASE.read_bytes() != template:
                raise RuntimeError('The packaged quota definition changed during repair.')
            record('complete', template, entries)
        except BaseException:
            record('verification-needs-review', template, entries)
            raise
    say('NAS QUOTA BOOT PRECHECK INSTALLED. All three filesystems retain user/group quotas ON.')
    say('The FIKWOT backup SSD is now covered by the same scoped precheck as the other two drives.')
    say('Mount options, filesystem features, limits, applications and OptiPlex were retained.')
    say('The precheck intentionally skips an already-enabled unit; inactive/skipped is expected.')


def guard():
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the NAS.')
    no_links(SSD)
    if not SSD.is_mount():
        raise RuntimeError('The NAS application SSD is not mounted.')


def main():
    os.umask(0o077)
    guard()
    if sys.argv[1:] == ['--worker']:
        def terminate(_number, _frame):
            raise SystemExit(143)
        signal.signal(signal.SIGTERM, terminate)
        repair()
        return
    if sys.argv[1:]:
        raise RuntimeError('Unknown quota boot repair operation.')
    result = subprocess.run(['systemctl', 'show', UNIT + '.service', '-p', 'LoadState', '-p', 'ActiveState'],
                            capture_output=True, text=True, timeout=15)
    state = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    if (result.returncode not in (0, 1) or state.get('LoadState') not in ('loaded', 'not-found')
            or state.get('ActiveState') not in ('active', 'activating', 'deactivating', 'inactive', 'failed')):
        raise RuntimeError('The background quota repair service state is unavailable.')
    if state['ActiveState'] in ('active', 'activating', 'deactivating'):
        say('The NAS quota boot repair is already running.')
        return
    source = globals().get('INSTALL_SOURCE')
    if source is None and '__file__' in globals():
        source = Path(__file__).read_text()
    if not source:
        raise RuntimeError('Use the complete reviewed quota repair command.')
    folder = Path(tempfile.mkdtemp(prefix='nas-quota-boot-repair-', dir='/run'))
    worker = folder / 'worker.py'
    worker.write_text(source)
    worker.chmod(0o600)
    try:
        run('systemd-run', '--unit=' + UNIT, '--collect', '--property=Type=exec',
            '--property=UMask=0077', '--property=RuntimeMaxSec=5min',
            '--description=Skip duplicate NAS quota activation on verified internal-quota filesystems',
            '/usr/bin/python3', '-u', str(worker), '--worker')
    except BaseException:
        worker.unlink(missing_ok=True)
        folder.rmdir()
        raise
    say('NAS quota boot repair started in systemd. Closing SSH is safe.')
    say('Check: sudo journalctl -u ' + UNIT + '.service -n 20 --no-pager -o cat')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        say('STOP: ' + (str(error) if isinstance(error, RuntimeError) else type(error).__name__))
        sys.exit(1)
    finally:
        if sys.argv[1:] == ['--worker'] and '__file__' in globals():
            executable = Path(__file__)
            if (executable.parent.parent == Path('/run')
                    and executable.parent.name.startswith('nas-quota-boot-repair-')
                    and executable.name == 'worker.py' and not executable.is_symlink()):
                executable.unlink(missing_ok=True)
                executable.parent.rmdir()
