#!/usr/bin/env python3
"""Activate the accepted NPM copy on existing NAS LAN ports, with rollback."""
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import types
import urllib.request
import uuid
import yaml

APP_UUID = 'e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6'
APP = Path('/srv/dev-disk-by-uuid-' + APP_UUID)
WORK = APP / 'compose/npm-restore/lan-activation'
LIVE = APP / 'appdata/npm'
STACK = None  # Selected from the candidate and Dockmon's matching verified path.
LOCK = Path('/run/lock/sawdoctor-nas-backup.lock')
FORMAT = 'sawdoctor-npm-lan-activation-v1'
LABEL = 'net.sawdoctor.npm-lan-activation'
JAIL = 'sawdoctor-npm-auth'
PIN = 'd2dd820b2337373275a5928d3c9bb55388caa2e6'
PIN_SHA = '7ba938e5d4f2332571284c9742ba8b9a0f74d1fd49cf7431a32b18e6163abe63'
PREVIOUS_WORKER_SHA = '770396aef373e466abb7815868854053c203a423fa180ae21d75d12dc4dfe53c'
PORTS = {'80/tcp': [{'HostIp': '192.168.0.220', 'HostPort': '10080'}],
         '81/tcp': [{'HostIp': '192.168.0.220', 'HostPort': '10081'}],
         '443/tcp': [{'HostIp': '192.168.0.220', 'HostPort': '10443'}]}


def say(message):
    print(message, flush=True)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def safe(path):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise RuntimeError('An unexpected symbolic activation/recovery path was retained.')


def read(path, limit=16 * 1024**2):
    safe(path)
    with path.open('rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise RuntimeError('An activation input is unavailable or exceeds its size bound.')
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise RuntimeError('An activation input exceeds its size bound.')
    return data


def atomic(path, data, reference=None):
    safe(path)
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    temporary = Path(temporary)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        if reference is not None:
            info = reference.stat()
            if temporary.stat().st_uid != info.st_uid or temporary.stat().st_gid != info.st_gid:
                os.chown(temporary, info.st_uid, info.st_gid)
            shutil.copystat(reference, temporary)
        temporary.replace(path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def command(*args, stdin=None, timeout=30):
    result = subprocess.run(args, input=stdin, capture_output=True, timeout=timeout)
    if result.returncode:
        if WORK.is_dir():
            atomic(WORK / 'private-error.log', (result.stdout + b'\n' + result.stderr)[-1024**2:])
        raise RuntimeError('A NAS proxy activation command failed; details were retained privately.')
    return result.stdout


def inspect():
    result = subprocess.run(['docker', 'inspect', 'npm-nas'], capture_output=True, timeout=20)
    if result.returncode:
        if b'No such object:' in result.stderr or b'No such container:' in result.stderr:
            return None
        raise RuntimeError('Docker inspection failed; recovery files were retained.')
    rows = json.loads(result.stdout)
    if len(rows) != 1 or rows[0].get('Name') != '/npm-nas':
        raise RuntimeError('The NAS proxy identity differs.')
    return rows[0]


def host():
    if os.geteuid() != 0 or b'inet 192.168.0.220/' not in command('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the NAS.')
    safe(APP)
    if not APP.is_mount() or command('findmnt', '-rn', '--mountpoint', str(APP), '-o', 'UUID,FSTYPE').split() != [APP_UUID.encode(), b'ext4']:
        raise RuntimeError('The NAS application SSD identity differs.')


def compose(*args):
    return command('docker', 'compose', '-p', 'npm-nas', '-f', str(STACK), *args, timeout=150)


def verified_stack_path(value):
    path = Path(value)
    if (path.parent != APP / 'appdata/dockmon/stacks/npm-nas'
            or path.name not in ('compose.yaml', 'compose.yml', 'docker-compose.yaml', 'docker-compose.yml')):
        raise RuntimeError('The recorded stack is outside the existing Dockmon NPM stack directory.')
    safe(path)
    return path


def state():
    return json.loads(read(WORK / 'state.json'))


def save(record):
    atomic(WORK / 'state.json', (json.dumps(record, indent=2) + '\n').encode())


def security():
    return {'ssh': {key: command('fail2ban-client', 'get', 'sshd', key).decode() for key in
                    ('ignoreip', 'maxretry', 'findtime', 'bantime', 'actions')},
            'jailConfig': sha(read(Path('/etc/fail2ban/jail.d/sawdoctor-npm-auth.local'))),
            'jailAction': sha(read(Path('/etc/fail2ban/action.d/sawdoctor-npm-docker.conf')))}


def jail_reload():
    # The old log tree was renamed. Restart only this jail so its file watches
    # attach to the new inodes; --unban is deliberately not requested.
    command('fail2ban-client', 'reload', '--restart', JAIL)
    paths = command('fail2ban-client', 'get', JAIL, 'logpath').decode()
    logs = list((LIVE / 'data/logs').glob('proxy-host-*_error.log'))
    if not logs or any(str(p) not in paths for p in logs):
        raise RuntimeError('The NPM jail did not reopen the current proxy error logs.')


def ready(held=False):
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        result = subprocess.run(['curl', '--disable', '--silent', '--noproxy', '*', '--max-time', '2',
                                 '--output', '/dev/null', '--write-out', '%{http_code}',
                                 'http://192.168.0.220:10081/api/'], capture_output=True, timeout=4)
        if result.returncode == 0 and result.stdout.strip() == b'200':
            break
        time.sleep(2)
    else:
        raise RuntimeError('The NAS proxy backend did not become ready within 100 seconds.')
    if held:
        logs = subprocess.run(['docker', 'logs', 'npm-nas'], capture_output=True, timeout=20)
        if logs.returncode or b'NAS PRIVATE TRIAL: CERTIFICATE RENEWAL HELD' not in logs.stdout + logs.stderr:
            raise RuntimeError('The NAS backend certificate-renewal hold was not confirmed.')


def runtime(current, record):
    mounts = {m['Destination']: (m.get('Source'), m.get('RW')) for m in current.get('Mounts', [])}
    if (current.get('Image') != record['image'] or current.get('State', {}).get('Status') != 'running'
            or current.get('Config', {}).get('Labels', {}).get(LABEL) != record['token']
            or current.get('HostConfig', {}).get('PortBindings') != PORTS
            or set(current.get('NetworkSettings', {}).get('Networks', {})) != {'npm-nas_default'}
            or mounts != {'/data': (str(LIVE / 'data'), True), '/etc/letsencrypt': (str(LIVE / 'letsencrypt'), True),
                          '/app/internal/certificate.js': (str(WORK / 'certificate-held.js'), False)}):
        raise RuntimeError('The activated NAS proxy runtime differs from its reviewed definition.')


def activation_model(model, current, stage):
    result = stage.runtime_values(copy.deepcopy(model), current)
    service = result['services']['npm']
    if set(result['services']) != {'npm'} or service.get('container_name') != 'npm-nas':
        raise RuntimeError('The existing NAS proxy stack identity differs.')
    if {m.get('target') for m in service.get('volumes', [])} != {'/data', '/etc/letsencrypt'}:
        raise RuntimeError('The existing NAS proxy storage targets differ.')
    for mount in service['volumes']:
        if mount.get('type') != 'bind' or mount.get('read_only'):
            raise RuntimeError('The existing proxy writable bind definition differs.')
        mount['source'] = str(LIVE / ('data' if mount['target'] == '/data' else 'letsencrypt'))
        mount.setdefault('bind', {})['create_host_path'] = False
    service['volumes'].append({'type': 'bind', 'source': str(WORK / 'certificate-held.js'),
                              'target': '/app/internal/certificate.js', 'read_only': True,
                              'bind': {'create_host_path': False}})
    # Retain the readable registry reference so update notifications still work.
    # live_stack checks its loaded image; up cannot pull or build anything.
    service['pull_policy'] = 'never'
    return result


def validate_test(test, candidate, record):
    flags = ('automaticRenewalHeld', 'certificateCreateAndRenewHeld', 'temporaryContainerRemoved',
             'temporaryPayloadRemoved', 'existingNasProxyUnchanged', 'candidateUnchanged',
             'currentCandidate', 'newNginxWorkerGenerationReady')
    rows = test.get('routes', [])
    if (test.get('format') != 'sawdoctor-npm-private-proxy-test-v1'
            or test.get('status') != 'route-responses-checked' or test.get('candidatePath') != str(candidate)
            or test.get('sourceSnapshot') != record['sourceSnapshot'] or len(rows) != 28
            or len({r.get('domain', '').lower() for r in rows}) != 28 or not all(test.get(k) is True for k in flags)
            or any(r.get('needsAttention') is not False or r.get('curlExit') != 0
                   or r.get('responseReceivedWithTrustedTls') is not True for r in rows)):
        raise RuntimeError('The successful current 28-route private test is required before activation.')


def rollback(record):
    global STACK
    if (record.get('format') != FORMAT or record.get('status') not in
            ('activating', 'nas-lan-active-renewal-held', 'rollback-needs-review')):
        raise RuntimeError('No matching active NAS proxy operation is available to roll back.')
    STACK = verified_stack_path(record.get('stack', ''))
    if record.get('live') != str(LIVE):
        raise RuntimeError('The saved recovery paths differ from the fixed NAS proxy paths.')
    original = WORK / 'recovery/stack.before.yaml'
    if sha(read(original)) != record['oldStackSha256']:
        raise RuntimeError('The saved original proxy definition differs; recovery files retained.')
    if sha(read(STACK)) not in (record['oldStackSha256'], record['activeStackSha256']):
        raise RuntimeError('The proxy stack changed after activation; its definition/data were retained.')
    active = inspect()
    if active:
        owned = active['Config'].get('Labels', {}).get(LABEL) == record['token']
        if not owned and active['Id'] != record['oldContainerId']:
            raise RuntimeError('An unrelated proxy replaced this operation; no container was stopped.')
        command('docker', 'stop', '-t', '20', active['Id'], timeout=30)
        if owned:
            command('docker', 'rm', active['Id'])
    failed = WORK / 'retained-activated-data'
    safe(failed); failed.mkdir(mode=0o700, exist_ok=True)
    for name in ('data', 'letsencrypt'):
        original_tree, live_tree = WORK / 'recovery' / name, LIVE / name
        safe(original_tree); safe(live_tree)
        if original_tree.exists():
            if (failed / name).exists():
                raise RuntimeError('A previous retained activated tree is present; recovery files retained.')
            if live_tree.exists():
                live_tree.rename(failed / name)
            original_tree.rename(live_tree)
    atomic(STACK, read(original), reference=original)
    compose('up', '-d', '--no-deps', '--pull', 'never', '--no-build', '--force-recreate', 'npm')
    ready()
    jail_reload()
    record.update(status='rolled-back', rollbackUtc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
    save(record)
    say('NAS PROXY ROLLED BACK. Original NAS data/definition restored; imported working data retained privately.')


def activate(private):
    global STACK
    complete, routes, restore, (stage, source) = private.load_current_helpers()
    if (WORK / 'state.json').exists():
        previous = state()
        if previous.get('format') == FORMAT and previous.get('status') == 'nas-lan-active-renewal-held':
            STACK = verified_stack_path(previous.get('stack', ''))
            runtime(inspect() or {}, previous)
            if (sha(read(STACK)) != previous['activeStackSha256']
                    or sha(read(WORK / 'certificate-held.js')) != previous['certificateWorkerSha256']):
                raise RuntimeError('The activated stack has since changed; it was retained.')
            say('NAS proxy is already active on its existing LAN ports; no new import/restart was performed.')
            return
        raise RuntimeError('An earlier activation/recovery record exists; its data was retained for review.')
    current = routes.target_bindings()
    candidate = APP / 'compose/npm-restore/cutover-current'
    record = json.loads(routes.read(candidate / 'prepared.json'))
    expected = json.loads(routes.read(candidate / 'payload-inventory.json', 16 * 1024**2))
    if (complete.inventory(candidate / 'payload') != expected
            or complete.file_digest(candidate / 'payload-inventory.json') != record.get('payloadInventorySha256')
            or complete.file_digest(candidate / 'ready.yaml') != record.get('readySha256')):
        raise RuntimeError('The accepted current candidate changed; it was retained.')
    metadata = private.validate_current_candidate(candidate, record, current, stage, source, complete, routes, restore)
    validate_test(json.loads(read(APP / 'compose/npm-restore/proxy-test-current/result.json')), candidate, record)
    stored, stack, model = complete.live_stack(routes, restore, current)
    STACK = verified_stack_path(record.get('existingStackPath', ''))
    if stack != STACK:
        raise RuntimeError('The current Dockmon stack path differs from the verified candidate record.')
    if current['HostConfig'].get('PortBindings') != PORTS:
        raise RuntimeError('The NAS proxy ports differ from the reviewed 10080/10081/10443 bindings.')
    safe(LIVE); safe(STACK)
    for name in ('data', 'letsencrypt'):
        safe(LIVE / name)
        if not (LIVE / name).is_dir() or (LIVE / name).is_mount():
            raise RuntimeError('The existing NAS proxy data directory differs.')
    if shutil.disk_usage(APP).free < 1024**3:
        raise RuntimeError('At least 1 GiB free application storage is required.')
    before_security = security()
    logpaths = command('fail2ban-client', 'get', JAIL, 'logpath')
    if str(LIVE / 'data/logs/').encode() not in logpaths:
        raise RuntimeError('The NPM jail is not watching the retained NAS proxy log path.')
    all_containers = restore.all_containers()
    if any(c['Id'] != current['Id'] and any(m.get('Type') == 'bind' and
            Path(m.get('Source', '/')).is_relative_to(LIVE) for m in c.get('Mounts', [])) for c in all_containers):
        raise RuntimeError('Another container directly uses the NAS proxy data; it was retained.')
    if set(current['NetworkSettings']['Networks']) != {'npm-nas_default'}:
        raise RuntimeError('The current NAS proxy network differs.')
    held = private.hold_certificate_worker(command('docker', 'exec', 'npm-nas', 'cat', '/app/internal/certificate.js'))
    command('docker', 'exec', '-i', 'npm-nas', 'node', '--input-type=module', '--check', stdin=held)
    guard = WORK / 'certificate-held.js'; atomic(guard, held); guard.chmod(0o644)
    proposed = activation_model(model, current, stage)
    token = uuid.uuid4().hex
    proposed['services']['npm'].setdefault('labels', {})[LABEL] = token
    text = yaml.safe_dump(complete.escaped(proposed), sort_keys=False).encode()
    definition = WORK / 'active.yaml'; atomic(definition, text)
    rendered = json.loads(command('docker', 'compose', '-p', 'npm-nas', '-f', str(definition), 'config', '--format', 'json'))
    private.validate_compose(proposed, rendered, complete.escaped)
    staged = WORK / 'payload'; safe(staged)
    if staged.exists() or (WORK / 'recovery').exists():
        raise RuntimeError('An earlier activation copy exists; it was retained.')
    staged.mkdir(mode=0o700)
    say('Copying the accepted NPM payload and retaining its exact source metadata...')
    command('rsync', '-aHAX', '--numeric-ids', '--one-file-system', '--no-devices', '--no-specials',
            '--', str(candidate / 'payload') + '/', str(staged) + '/', timeout=180)
    actual = complete.inventory(staged)
    if actual != expected:
        stage.restore_copied_modes(staged, expected, actual)
    if complete.inventory(staged) != expected:
        raise RuntimeError('The private activation copy differs from the accepted candidate.')
    # This is the last running/empty-container and Dockmon check before stopping only NAS NPM.
    if routes.target_bindings()['Id'] != current['Id'] or complete.live_stack(routes, restore, current)[0] != stored:
        raise RuntimeError('The current NAS proxy/stack changed during preparation.')
    recovery = WORK / 'recovery'; recovery.mkdir(mode=0o700)
    command('cp', '--preserve=all', '--', str(STACK), str(recovery / 'stack.before.yaml'))
    operation = {'format': FORMAT, 'status': 'activating', 'token': token, 'image': current['Image'],
                 'oldContainerId': current['Id'], 'stack': str(STACK), 'live': str(LIVE),
                 'oldStackSha256': sha(read(STACK)), 'activeStackSha256': sha(text),
                 'candidateMetadata': metadata, 'sourceSnapshot': record['sourceSnapshot'],
                 'security': before_security, 'certificateWorkerSha256': sha(held)}
    save(operation)
    try:
        say('Activating only NAS NPM on 10080/10081/10443; source public NPM remains untouched...')
        command('docker', 'stop', '-t', '20', current['Id'], timeout=30)
        for name in ('data', 'letsencrypt'):
            (LIVE / name).rename(recovery / name)
            (staged / name).rename(LIVE / name)
        atomic(STACK, text, reference=recovery / 'stack.before.yaml')
        compose('up', '-d', '--no-deps', '--pull', 'never', '--no-build', '--force-recreate', 'npm')
        active = inspect() or {}; runtime(active, operation)
        if private.environment(active['Config'].get('Env')) != private.environment(current['Config'].get('Env')):
            raise RuntimeError('The activated proxy environment differs from its original runtime.')
        # Read through Dockmon's own API to confirm its editor sees the installed definition.
        stored_after = json.loads(restore.run('docker', 'exec', 'dockmon', 'python', '-c', restore.STORAGE_CODE, restore.STORAGE_SHA))
        if stored_after['text'].encode() != text or stored_after['env'] != stored['env']:
            raise RuntimeError('Dockmon did not retain the activated stack and original environment files.')
        ready(held=True)
        output = command('docker', 'exec', '-i', '--workdir', '/app', 'npm-nas', 'node', '--input-type=module',
                         stdin=private.render_code(current=True).encode(), timeout=90)
        if b'NPM_PRIVATE_ROUTES_RENDERED=28' not in output or b'NPM_PRIVATE_NEW_WORKERS_READY' not in output:
            raise RuntimeError('The active proxy route regeneration/readiness did not complete.')
        jail_reload()
        if security() != before_security:
            raise RuntimeError('The existing SSH settings or NPM jail files changed during activation.')
        if complete.inventory(candidate / 'payload') != expected or any(
                sha(read(candidate / name, 64 * 1024**2)) != value for name, value in metadata.items()):
            raise RuntimeError('The immutable offline candidate changed during activation.')
        operation.update(status='nas-lan-active-renewal-held', containerId=active['Id'],
                         activatedUtc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                         routesRendered=28, publicHandover=False, certificateOperationsHeld=True)
        save(operation)
    except BaseException:
        say('NAS activation did not complete; restoring its original proxy/data...')
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        try:
            rollback(operation)
        except Exception:
            operation['status'] = 'rollback-needs-review'; save(operation)
            say('STOP: Automatic NAS rollback needs review. Recovery and imported data were retained; OptiPlex was not changed.')
        raise
    say('NAS NPM ACTIVE ON EXISTING LAN PORTS: 28 routes regenerated; certificate operations held.')
    say('Source accounts/ACLs/signing keys/certificates imported. Existing NAS data and stack retained for rollback.')
    say('NPM jail reopened the unchanged log path; SSH settings retained. No image pull/build or public/source change.')
    say('Login check: http://192.168.0.220:10081/ using the existing OptiPlex NPM account.')
    say('Rollback: sudo python3 ' + str(WORK / 'worker.py') + ' --rollback')
    say('Small operation record: ' + str(WORK / 'state.json'))


def load_private():
    url = 'https://raw.githubusercontent.com/sawdoctor/nas-backup-auth/' + PIN + '/scripts/test-nas-npm-proxy.py'
    with urllib.request.urlopen(url, timeout=30) as response:
        data = response.read(128 * 1024 + 1)
    if sha(data) != PIN_SHA:
        raise RuntimeError('The pinned successful proxy-test dependency failed integrity verification.')
    module = types.ModuleType('_accepted_npm_private_test')
    exec(compile(data, url, 'exec'), module.__dict__)
    return module


def install_worker(data):
    worker = WORK / 'worker.py'
    if worker.exists() and read(worker) != data:
        previous = read(worker)
        allowed = {'worker.py', 'private-error.log'}
        if sha(previous) != PREVIOUS_WORKER_SHA or {p.name for p in WORK.iterdir()} - allowed:
            raise RuntimeError('A different worker or existing activation state was retained for review.')
        # The failed preflight created no data copy/recovery/state. Preserve the
        # exact reviewed old worker before replacing only that installer file.
        atomic(WORK / 'worker.before-stack-path-fix.py', previous)
    if not worker.exists() or read(worker) != data:
        atomic(worker, data); worker.chmod(0o700)
    return worker


def main():
    os.umask(0o077)
    host()
    safe(WORK); WORK.mkdir(mode=0o700, parents=True, exist_ok=True)
    if sys.argv[1:] in (['--worker'], ['--worker-rollback']):
        safe(LOCK)
        with LOCK.open('rb') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError('NAS backup/recovery is busy; retry later.') from None
            def interrupted(signum, frame):
                raise RuntimeError('NAS activation was interrupted; rollback was requested.')
            signal.signal(signal.SIGTERM, interrupted)
            if sys.argv[1:] == ['--worker-rollback']:
                rollback(state())
            else:
                activate(load_private())
        return
    if sys.argv[1:] not in ([], ['--rollback']):
        raise RuntimeError('Only --rollback is supported as an installer argument.')
    unit = 'nas-npm-lan-activation'
    for name in (unit, 'nas-npm-current-prepare', 'nas-npm-current-test', 'nas-npm-proxy-test', 'nas-npm-usenet-test'):
        if subprocess.run(['systemctl', 'is-active', '--quiet', name + '.service'], capture_output=True).returncode == 0:
            raise RuntimeError('A NAS proxy operation is already running; check its journal.')
    worker = WORK / 'worker.py'
    data = globals().get('INSTALL_SOURCE')
    if not isinstance(data, str):
        if Path(__file__).resolve() != worker:
            raise RuntimeError('The complete pinned installer source is required.')
        data = read(worker).decode()
    worker = install_worker(data.encode())
    subprocess.run(['systemctl', 'reset-failed', unit + '.service'], capture_output=True)
    command('systemd-run', '--unit=' + unit, '--collect', '--description=Activate verified NAS NPM on existing LAN ports with renewal held',
            '--property=Type=exec', '--property=UMask=0077', '--property=RuntimeMaxSec=8min',
            '--property=TimeoutStopSec=2min', '--property=KillMode=mixed', '/usr/bin/python3', str(worker),
            '--worker-rollback' if sys.argv[1:] == ['--rollback'] else '--worker')
    say('NAS private proxy ' + ('rollback' if sys.argv[1:] == ['--rollback'] else 'activation') + ' started in systemd. Closing SSH is safe.')
    say('Progress: sudo journalctl -u ' + unit + '.service -n 25 --no-pager -o cat')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('STOP: ' + (str(error) if isinstance(error, RuntimeError) else
                                   'NAS proxy activation failed (' + type(error).__name__ + '); details withheld.'))
