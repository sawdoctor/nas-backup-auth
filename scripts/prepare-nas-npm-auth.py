#!/usr/bin/env python3
"""Install/test one direct-IPv4 NPM HTTP-basic-auth jail, retaining SSH."""
import contextlib
import datetime
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

APP_UUID = 'e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6'
APP = Path('/srv/dev-disk-by-uuid-' + APP_UUID)
LOGS = APP / 'appdata/npm/data/logs'
WORK = APP / 'compose/npm-auth'
LOCK = Path('/run/lock/sawdoctor-nas-backup.lock')
JAIL = 'sawdoctor-npm-auth'
ACTION = Path('/etc/fail2ban/action.d/sawdoctor-npm-docker.conf')
CONFIG = Path('/etc/fail2ban/jail.d/sawdoctor-npm-auth.local')
TEST_IP = '203.0.113.123'
CHAINS = (('saw-npm-web', '10080:10081'), ('saw-npm-tls', '10443'))
# Official https://www.cloudflare.com/ips-v4, reviewed 7 November 2026.
# A changed list requires review before any files/firewall state are changed.
CF = tuple(sorted('''173.245.48.0/20 103.21.244.0/22 103.22.200.0/22
103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20
188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15
104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22'''.split()))
ACTION_TEXT = '''# Sawdoctor NAS direct IPv4 NPM HTTP-auth v1
[INCLUDES]
before = iptables.conf

[Definition]
_ipt_chain_rule = -p $proto -m conntrack --ctorigdst 192.168.0.220 --ctorigdstport <hostports> -j f2b-<name>

[Init]
chain = DOCKER-USER
protocol = tcp
blocktype = DROP
lockingopt = -w 5
hostports = 10080:10081
'''


def say(message):
    print(message, flush=True)


def no_links(path):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise RuntimeError('An unexpected symbolic setup path was retained.')


def read(path):
    no_links(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 2 * 1024**2:
        raise RuntimeError('A setup input is unavailable or unexpectedly large.')
    return path.read_bytes()


def atomic(path, data, mode=0o600):
    no_links(path)
    fd, temporary = tempfile.mkstemp(prefix='.npm-auth-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def run(*args, allowed=(0,)):
    result = subprocess.run(args, capture_output=True, text=True, timeout=25,
                            env={**os.environ, 'LC_ALL': 'C', 'LANG': 'C'})
    if result.returncode not in allowed:
        raise RuntimeError('A local proxy-auth check failed: ' + args[0] + '. Raw output was withheld.')
    return result


def client(*args, allowed=(0,)):
    return run('fail2ban-client', *args, allowed=allowed).stdout


def jail_names(text):
    match = re.search(r'Jail list:\s*([^\n]*)', text)
    if not match:
        raise RuntimeError('The active jail list could not be verified.')
    return {name.strip() for name in match[1].split(',') if name.strip()}


def cf_ranges():
    # The human-facing www endpoint can reject requests from server networks.
    # Use Cloudflare's documented, unauthenticated public IP-list API instead.
    try:
        with urllib.request.urlopen('https://api.cloudflare.com/client/v4/ips', timeout=15) as response:
            data = response.read(16385)
    except urllib.error.HTTPError as error:
        raise RuntimeError('Cloudflare IP-list API returned HTTP ' + str(error.code)
                           + '; no setup files were changed.') from None
    except (urllib.error.URLError, TimeoutError):
        raise RuntimeError('Cloudflare IP-list API could not be reached; no setup files were changed.') from None
    if len(data) > 16384:
        raise RuntimeError('The Cloudflare range list is unexpectedly large.')
    document = json.loads(data)
    ranges = document.get('result', {}).get('ipv4_cidrs') if isinstance(document, dict) else None
    if (not isinstance(document, dict) or document.get('success') is not True
            or not isinstance(ranges, list) or not all(isinstance(line, str) for line in ranges)):
        raise RuntimeError('Cloudflare IP-list API returned an unexpected response; no setup files were changed.')
    parsed = tuple(sorted(str(ipaddress.IPv4Network(line)) for line in ranges))
    if parsed != CF:
        raise RuntimeError('Cloudflare ranges differ from the reviewed list; no setup change was made.')
    return parsed


def configuration(ranges):
    ignored = ' '.join(('127.0.0.0/8', '192.168.0.0/24', '::/0', *ranges))
    return (f'''# Sawdoctor NAS direct IPv4 NPM HTTP-auth v1
[{JAIL}]
enabled = true
filter = nginx-http-auth[mode=normal]
backend = polling
logpath = {LOGS}/proxy-host-*_error.log tail
usedns = no
ignoreip = {ignored}
maxretry = 5
findtime = 10m
bantime = 24h
action = sawdoctor-npm-docker[name=saw-npm-web, actname=saw-npm-web, hostports="10080:10081"]
         sawdoctor-npm-docker[name=saw-npm-tls, actname=saw-npm-tls, hostports=10443]
''').encode()


def check_files(files):
    for path, data in files.items():
        no_links(path)
        if path.exists() and read(path) != data:
            raise RuntimeError('An existing proxy-auth file differs; it was retained.')


def ssh_state():
    return {key: client('get', 'sshd', key) for key in
            ('ignoreip', 'maxretry', 'findtime', 'bantime', 'actions')}


def filter_test():
    prefix = datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S') + ' [error] 12#12: *1 '
    suffix = ', client: ' + TEST_IP + ', server: nas-test.invalid, request: "GET / HTTP/1.1", host: "nas-test.invalid"'
    samples = (
        (prefix + 'user "nas-test": password mismatch' + suffix, 1),
        (prefix + 'user "nas-test" was not found in "/data/access/1"' + suffix, 1),
        (prefix + 'open() "/data/test" failed (2: No such file or directory)' + suffix, 0),
    )
    for text, expected in samples:
        output = run('fail2ban-regex', text, 'nginx-http-auth[mode=normal]').stdout
        summary = re.search(r'Lines:\s+1 lines,\s+0 ignored,\s+(\d+) matched,\s+(\d+) missed', output)
        if not summary or tuple(map(int, summary.groups())) != (expected, 1 - expected):
            raise RuntimeError('The packaged HTTP-auth filter did not pass positive/negative sample checks.')


def preflight():
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show').stdout:
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220.')
    no_links(APP)
    if not APP.is_mount() or run('findmnt', '-rn', '--mountpoint', str(APP), '-o', 'UUID,FSTYPE').stdout.split() != [APP_UUID, 'ext4']:
        raise RuntimeError('The NAS application SSD identity differs.')
    current = json.loads(run('docker', 'inspect', 'npm-nas').stdout)[0]
    ports = {str(port): [{'HostIp': '192.168.0.220', 'HostPort': str(host)}]
             for port, host in (('80/tcp', 10080), ('81/tcp', 10081), ('443/tcp', 10443))}
    mounts = [m for m in current.get('Mounts', []) if m.get('Destination') == '/data']
    if (current['State']['Status'] != 'running' or current['HostConfig'].get('NetworkMode') != 'npm-nas_default'
            or current['HostConfig'].get('PortBindings') != ports or len(mounts) != 1
            or mounts[0].get('Type') != 'bind' or mounts[0].get('Source') != str(LOGS.parent)):
        raise RuntimeError('The NPM runtime/bindings differ; review the actual log location before setup.')
    no_links(LOGS)
    logs = list(LOGS.glob('proxy-host-*_error.log'))
    if not logs or any(p.is_symlink() or not p.is_file() for p in logs):
        raise RuntimeError('The current NPM proxy error logs are unavailable or symbolic.')
    if run('systemctl', 'is-active', 'fail2ban.service').stdout.strip() != 'active':
        raise RuntimeError('The native Fail2ban service is not active.')
    jails = jail_names(client('status'))
    if 'sshd' not in jails or jails - {'sshd', JAIL}:
        raise RuntimeError('Unexpected active jails require review; existing jails were retained.')
    run('iptables', '-w', '5', '-S', 'DOCKER-USER')
    run('iptables', '-w', '5', '-C', 'FORWARD', '-j', 'DOCKER-USER')
    base = read(Path('/etc/fail2ban/action.d/iptables.conf')).decode()
    if not all(token in base for token in ('_ipt_chain_rule =', '%(_ipt_chain_rule)s', '<_ipt_add_rules>', '<_ipt_del_rules>', '<_ipt_check_rules>')):
        raise RuntimeError('The packaged iptables action does not match the required inherited interface.')
    read(Path('/etc/fail2ban/filter.d/nginx-http-auth.conf'))
    filter_test()
    before_ssh = ssh_state()
    if '192.168.0.0/24' not in before_ssh['ignoreip']:
        raise RuntimeError('The expected SSH LAN exclusion is unavailable.')
    ranges = cf_ranges()
    files = {ACTION: ACTION_TEXT.encode(), CONFIG: configuration(ranges)}
    check_files(files)
    return files, before_ssh, JAIL in jails


def rule_present(name, port):
    jump = run('iptables', '-w', '5', '-C', 'DOCKER-USER', '-p', 'tcp', '-m', 'conntrack',
               '--ctorigdst', '192.168.0.220', '--ctorigdstport', port,
               '-j', 'f2b-' + name, allowed=(0, 1)).returncode == 0
    ban = run('iptables', '-w', '5', '-C', 'f2b-' + name, '-s', TEST_IP,
              '-j', 'DROP', allowed=(0, 1)).returncode == 0
    return jump and ban


def ban_test():
    try:
        client('set', JAIL, 'banip', TEST_IP)
        for _ in range(20):
            if all(rule_present(name, port) for name, port in CHAINS):
                break
            time.sleep(0.25)
        else:
            raise RuntimeError('The reserved-IP ban did not produce both scoped Docker rules.')
    finally:
        client('set', JAIL, 'unbanip', TEST_IP, allowed=(0, 255))
        # Wait for the asynchronous unban. Delete only the reserved test rule
        # if cleanup is delayed; never flush chains or touch another address.
        for _ in range(20):
            remaining = [name for name, _ in CHAINS if run('iptables', '-w', '5', '-C',
                         'f2b-' + name, '-s', TEST_IP, '-j', 'DROP', allowed=(0, 1)).returncode == 0]
            if not remaining:
                break
            time.sleep(0.25)
        else:
            for name in remaining:
                run('iptables', '-w', '5', '-D', 'f2b-' + name, '-s', TEST_IP, '-j', 'DROP')
            raise RuntimeError('The reserved test rule was removed directly; review the jail unban action.')


def install():
    no_links(LOCK)
    with LOCK.open('rb') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('NAS backup/recovery is busy; retry later.') from None
        say('Checking the NPM bindings, packaged filter/action and current SSH settings...')
        files, before_ssh, was_active = preflight()
        created = []
        try:
            check_files(files)
            for path, data in files.items():
                if not path.exists():
                    atomic(path, data, 0o644)
                    created.append(path)
            check_files(files)
            run('fail2ban-client', '-t')
            say('Configuration and filter checks passed. Loading only the NPM HTTP-auth jail...')
            client('reload', '--if-exists', JAIL)
            if JAIL not in jail_names(client('status')):
                raise RuntimeError('The proxy-auth jail was not loaded.')
            if ssh_state() != before_ssh:
                raise RuntimeError('SSH jail settings changed during setup; review them before cutover.')
            say('Testing the scoped Docker ban and unban with reserved IP ' + TEST_IP + '...')
            ban_test()
            if ssh_state() != before_ssh:
                raise RuntimeError('SSH jail settings changed during the test.')
            no_links(WORK)
            WORK.mkdir(parents=True, exist_ok=True, mode=0o700)
            result = {'format': 'sawdoctor-nas-npm-auth-v1', 'completedUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      'jail': JAIL, 'logRoot': str(LOGS), 'threshold': {'maxretry': 5, 'findtimeSeconds': 600, 'bantimeSeconds': 86400},
                      'scope': 'direct-ipv4-http-basic-auth-only', 'cloudflareIpv4Ignored': list(CF),
                      'reservedIpBanUnbanPassed': True, 'sshSettingsRetained': True,
                      'files': {str(p): hashlib.sha256(v).hexdigest() for p, v in files.items()}}
            atomic(WORK / 'result.json', (json.dumps(result, indent=2) + '\n').encode())
        except BaseException:
            if not was_active:
                # Stop only this newly added jail, and remove only new files
                # still identical to our payload. Existing matching files stay.
                with contextlib.suppress(Exception):
                    client('stop', JAIL, allowed=(0, 255))
                for path in reversed(created):
                    if path.exists() and not path.is_symlink() and read(path) == files[path]:
                        path.unlink()
            raise
        say('NAS NPM HTTP-AUTH JAIL READY. Reserved-IP ban/unban and SSH-setting checks passed.')
        say('Scope: direct IPv4 NPM access-list HTTP-password failures; five attempts/10 minutes, 24-hour ban.')
        say('LAN, IPv6 and reviewed Cloudflare ranges are excluded from this new jail. SSH jail is retained.')
        say('Cloudflare-proxied visitor blocking and application-login protection are not tested by this jail.')
        say('No container restart, proxy/route change, backup or snapshot was performed.')
        say('Recheck/update this jail logpath if the NPM /data bind changes at final handover.')
        say('Small result record: ' + str(WORK / 'result.json'))


def main():
    if sys.argv[1:] == ['--worker']:
        try:
            install()
        finally:
            script = Path(sys.argv[0])
            if script.parent == Path('/run') and script.name.startswith('nas-npm-auth-'):
                script.unlink(missing_ok=True)
        return
    if sys.argv[1:]:
        raise RuntimeError('No setup arguments are expected.')
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show').stdout:
        raise RuntimeError('Run with sudo on the NAS.')
    if run('systemctl', 'is-active', '--quiet', 'nas-npm-auth-prepare.service', allowed=(0, 3, 4)).returncode == 0:
        say('NPM auth preparation is already running; check its journal.')
        return
    source = globals().get('INSTALL_SOURCE')
    if not isinstance(source, str) or not source.startswith('#!/usr/bin/env python3\n'):
        raise RuntimeError('The complete pinned installer source is required.')
    fd, path = tempfile.mkstemp(prefix='nas-npm-auth-', suffix='.py', dir='/run')
    with os.fdopen(fd, 'w') as stream:
        os.fchmod(stream.fileno(), 0o700)
        stream.write(source)
    try:
        run('systemctl', 'reset-failed', 'nas-npm-auth-prepare.service', allowed=(0, 1))
        run('systemd-run', '--unit=nas-npm-auth-prepare', '--collect',
            '--description=Prepare and test scoped NAS NPM HTTP authentication bans',
            '--property=Type=exec', '--property=UMask=0077', '--property=TimeoutStartSec=4min',
            '/usr/bin/python3', path, '--worker')
    except BaseException:
        Path(path).unlink(missing_ok=True)
        raise
    say('NAS NPM auth setup started in systemd. Closing SSH is safe.')
    say('Progress: sudo journalctl -u nas-npm-auth-prepare.service -n 20 --no-pager -o cat')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        if isinstance(error, RuntimeError):
            raise SystemExit('STOP: ' + str(error))
        raise SystemExit('STOP: Proxy-auth preparation failed (' + type(error).__name__ + '); private details withheld.')
