#!/usr/bin/env python3
"""Privately capture OptiPlex host jobs and stage them, inactive, on the NAS."""
import ast
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shlex
import subprocess
import tarfile
import tempfile

FORMAT = 'sawdoctor-host-jobs-export-v1'
SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
OUTPUT = Path('/home/sawdoctor/nas-host-jobs-export')
READER = Path('/usr/local/sbin/nas-migration-export-read')
KEY = Path('/root/.ssh/nas-infinidysk-transfer')
KEY_BLOB = 'AAAAC3NzaC1lZDI1NTE5AAAAILc56w99kcthdhVVsUuXQxChc1Smtlx6ju+xZPLNIpSE'
HOST_KEY = '192.168.0.29 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGI1/hObYOUSPIqGKLePC0eEFvCc8Uoyv+YOmBbVPbgW\n'
LIMIT = 32 * 1024**2
SEEDS = '''
/usr/local/bin/media-acquisition-watchdog.sh
/usr/local/bin/nzbdav-daily-backup.sh
/usr/local/bin/nzbdav-safe-restart.sh
/usr/local/bin/nzbdav-update
/usr/local/bin/plex-daily-backup.sh
/usr/local/bin/uu-update
/usr/local/bin/uu-rollback
/usr/local/sbin/abs-user-provisioner.py
/usr/local/sbin/docker-postboot-fix
/usr/local/sbin/lan-container-start.sh
/usr/local/sbin/media-last-start
/usr/local/sbin/media-mount-guard
/usr/local/sbin/media-mount-recover.sh
/usr/local/sbin/media-mount-watch.sh
/usr/local/sbin/media-mounts-ready
/usr/local/sbin/plex-api-watch
/usr/local/sbin/plex-backup-post
/usr/local/sbin/plex-safe-restart
/usr/local/sbin/plex-safe-start
/usr/local/sbin/reattach-ebook-containers
/usr/local/sbin/tmc-deadlock-watch
/usr/local/sbin/torbox-audiobook-archive
/usr/local/sbin/torbox-memory-monitor-24h
/home/sawdoctor/scripts/flora-nzbdav-watch.sh
/home/sawdoctor/scripts/torbox-audiobook-import.sh
/home/sawdoctor/docker/scripts/backup_configs.sh
/home/sawdoctor/docker/torbox-media-center/fix-torbox-cache.sh
/home/sawdoctor/docker/torbox-media-center/clear-torbox-torrents.py
'''.split()
UNIT_PREFIXES = ('abs-user-provisioner', 'cloudflared', 'docker-postboot-',
                 'lan-container-start', 'media-', 'nzbdav-', 'plex-', 'rclone-',
                 'tmc-', 'torbox-')
PATHS = re.compile(r'(?<![A-Za-z0-9_])/(?:usr/local/(?:bin|sbin|libexec)|home/sawdoctor|root|etc)/(?:[A-Za-z0-9_.@+/-]+)')


def log(message):
    print(message, flush=True)


def run(*args, check=True, timeout=30, **kwargs):
    result = subprocess.run(args, text=True, stderr=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, timeout=timeout, **kwargs)
    if check and result.returncode:
        raise RuntimeError('A host-file capture or transfer command failed; no application jobs were changed.')
    return result


def atomic(path, text, mode=0o600, owner=None):
    if path.is_symlink():
        raise RuntimeError('An unexpected symbolic export path needs review.')
    fd, temporary = tempfile.mkstemp(prefix='.host-jobs-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(text); stream.flush(); os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        if owner:
            os.chown(temporary, *owner)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024**2), b''):
            value.update(block)
    return value.hexdigest()


def script(path, data):
    return path.suffix in ('.py', '.sh', '.bash', '.pl') or data.startswith(b'#!')


def python_dependencies(path, data):
    """Follow local imports without executing any copied Python code."""
    if path.suffix != '.py' and b'python' not in data.split(b'\n', 1)[0]:
        return set()
    try:
        tree = ast.parse(data.decode())
    except (SyntaxError, UnicodeError):
        return set()
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(item.name for item in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                modules.add(node.module)
            modules.update((node.module + '.' if node.module else '') + item.name
                           for item in node.names if item.name != '*')
    found = set()
    parents = set(list(path.parents)[:3])
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.startswith(('/home/sawdoctor/', '/usr/local/')):
            candidate = Path(node.value)
            if candidate.is_dir() and not candidate.is_symlink():
                parents.add(candidate)
    for parent in parents:
        if not str(parent).startswith(('/home/sawdoctor/', '/usr/local/')):
            continue
        for module in modules:
            if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]*', module):
                continue
            relative = Path(*module.split('.'))
            for candidate in (parent / relative.with_suffix('.py'), parent / relative / '__init__.py'):
                if candidate.is_file() and not candidate.is_symlink():
                    found.add(candidate)
    return found


def reader_update(original):
    marker = '# Sawdoctor private host-jobs export v1'
    if marker in original:
        return original
    if not original.startswith('#!/bin/sh\n') or 'SSH_ORIGINAL_COMMAND' not in original:
        raise RuntimeError('The restricted transfer reader differs from the expected helper; leaving it untouched.')
    routes = f'''{marker}
case "${{SSH_ORIGINAL_COMMAND-}}" in
  host-jobs) exec /bin/cat {OUTPUT}/export.tar.gz ;;
  host-jobs-sha256) exec /bin/cat {OUTPUT}/export.sha256 ;;
esac
'''
    return '#!/bin/sh\n' + routes + original.split('\n', 1)[1]


def check_authorization():
    path = Path('/home/sawdoctor/.ssh/authorized_keys')
    if path.is_symlink() or not path.is_file() or READER.is_symlink() or not READER.is_file():
        raise RuntimeError('The existing restricted NAS transfer setup is not available.')
    matches = []
    for line in path.read_text().splitlines():
        if line.strip() and not line.lstrip().startswith('#'):
            fields = shlex.split(line)
            if fields[-3:] == ['ssh-ed25519', KEY_BLOB, 'nas-infinidysk-transfer']:
                matches.append(fields[0])
    if len(matches) != 1 or not all(value in matches[0] for value in
            ('from=192.168.0.220', 'restrict', 'command=' + str(READER))):
        raise RuntimeError('The original NAS transfer authorization needs review; no SSH keys were changed.')


def collect(work):
    manifest = {'format': FORMAT, 'sourceHost': '192.168.0.29',
                'createdUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'files': [], 'units': {}, 'missing': [], 'diagnostics': {}}
    pending = {Path(value) for value in SEEDS}
    for path in Path('/etc/systemd/system').glob('*'):
        if path.suffix in ('.service', '.timer') and path.name.startswith(UNIT_PREFIXES):
            if path.is_symlink():
                if not str(path.resolve()).startswith(('/usr/lib/systemd/', '/lib/systemd/')):
                    pending.add(path.resolve())
            else:
                pending.add(path)
            values = run('systemctl', 'show', path.name, '-p', 'ActiveState',
                         '-p', 'SubState', '-p', 'UnitFileState', '-p', 'Result', check=False).stdout
            manifest['units'][path.name] = dict(line.split('=', 1) for line in values.splitlines() if '=' in line)
            for dropin in Path(str(path) + '.d').glob('*.conf'):
                pending.add(dropin)
    pending.update(Path('/etc/cron.d').glob('*'))
    pending.update(Path('/var/spool/cron/crontabs').glob('*'))
    pending.update(Path(value) for value in ('/etc/crontab', '/etc/anacrontab', '/etc/rc.local'))
    seen, total = set(), 0
    while pending:
        path = min(pending); pending.remove(path)
        if path in seen:
            continue
        seen.add(path)
        if path.is_symlink() or not path.is_file():
            manifest['missing'].append(str(path)); continue
        filesystem = run('findmnt', '-n', '-T', str(path), '-o', 'FSTYPE').stdout.strip()
        if filesystem not in ('ext4', 'xfs', 'btrfs'):
            raise RuntimeError('A referenced host file is not on local storage; capture stopped.')
        before = path.stat()
        if before.st_size > 2 * 1024**2:
            raise RuntimeError('A host-file dependency is unexpectedly large; capture stopped.')
        data = path.read_bytes(); after = path.stat(); total += len(data)
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise RuntimeError('A host file changed during capture; rerun this small export.')
        if total > LIMIT or len(manifest['files']) >= 500:
            raise RuntimeError('Host-file capture exceeded its small-bundle limit.')
        name = hashlib.sha256(str(path).encode()).hexdigest()[:20] + '-' + path.name
        destination = work / 'files' / name
        destination.write_bytes(data); destination.chmod(0o600)
        text = data.decode(errors='replace')
        refs = sorted(set(PATHS.findall(text)))
        manifest['files'].append({'source': str(path), 'snapshot': 'files/' + name,
                                  'sha256': hashlib.sha256(data).hexdigest(), 'mode': before.st_mode & 0o777,
                                  'uid': before.st_uid, 'gid': before.st_gid,
                                  'script': script(path, data), 'references': refs})
        for ref in refs:
            candidate = Path(ref)
            if (candidate in seen or candidate.is_symlink() or not candidate.is_file()
                    or candidate.stat().st_size > 2 * 1024**2
                    or re.search(r'\.(bak|backup|before|retired)', candidate.name)):
                continue
            body = candidate.read_bytes()
            if script(candidate, body) or candidate.suffix.lower() in ('.env', '.conf', '.ini', '.json', '.yaml', '.yml'):
                pending.add(candidate)
        pending.update(python_dependencies(path, data))
        if path.suffix in ('.service', '.conf'):
            for line in text.splitlines():
                if line.strip().startswith('EnvironmentFile='):
                    for value in shlex.split(line.split('=', 1)[1]):
                        candidate = Path(value.lstrip('-'))
                        if candidate.is_absolute() and candidate.is_file():
                            pending.add(candidate)
    for unit in ('torbox-audiobook-archive.service', 'plex-api-watch.service'):
        text = run('journalctl', '-u', unit, '-n', '70', '--no-pager', '-o', 'cat', check=False).stdout
        name = 'diagnostics/' + unit + '.log'
        (work / name).write_text(text); (work / name).chmod(0o600)
        flags = []
        for label, pattern in (
                ('Google/API quota or rate limit', r'quota|rate.?limit|429'),
                ('Missing file or command', r'No such file|not found|FileNotFoundError'),
                ('Permission or authorization failure', r'Permission denied|unauthori[sz]ed|401|403'),
                ('Python exception', r'Traceback|\w+Error:'),
                ('Mount or filesystem error', r'Transport endpoint|not mounted|Input/output error')):
            if re.search(pattern, text, re.I):
                flags.append(label)
        manifest['diagnostics'][unit] = {'snapshot': name, 'flags': flags}
    (work / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    files = sorted(path for path in work.rglob('*') if path.is_file())
    (work / 'SHA256SUMS').write_text(''.join(digest(path) + '  ' + path.relative_to(work).as_posix() + '\n' for path in files))
    return manifest


def export_source():
    check_authorization()
    if OUTPUT.is_symlink():
        raise RuntimeError('Unexpected source export directory.')
    OUTPUT.mkdir(mode=0o700, exist_ok=True)
    marker = OUTPUT / 'export.json'
    if any(OUTPUT.iterdir()) and (not marker.is_file() or json.loads(marker.read_text()).get('format') != FORMAT):
        raise RuntimeError('An unrecognized source export folder already exists.')
    account = pwd.getpwnam('sawdoctor')
    with open('/run/lock/sawdoctor-nas-host-jobs-export.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not marker.exists():
            atomic(marker, json.dumps({'format': FORMAT, 'status': 'preparing'}) + '\n',
                   owner=(account.pw_uid, account.pw_gid))
        log('Capturing host scripts, helper dependencies, unit files, cron entries and private failure logs...')
        with tempfile.TemporaryDirectory(prefix='.host-jobs-', dir=OUTPUT) as directory:
            work = Path(directory); (work / 'files').mkdir(mode=0o700); (work / 'diagnostics').mkdir(mode=0o700)
            manifest = collect(work)
            archive = OUTPUT / 'export.tar.gz.incomplete'
            if archive.is_symlink():
                raise RuntimeError('Unexpected partial export path.')
            with tarfile.open(archive, 'w:gz') as destination:
                for path in sorted(work.rglob('*')):
                    if path.is_file():
                        destination.add(path, arcname=path.relative_to(work).as_posix(), recursive=False)
            archive.chmod(0o600); os.chown(archive, account.pw_uid, account.pw_gid)
            archive.replace(OUTPUT / 'export.tar.gz')
        atomic(OUTPUT / 'export.sha256', digest(OUTPUT / 'export.tar.gz') + '  export.tar.gz\n',
               owner=(account.pw_uid, account.pw_gid))
        atomic(marker, json.dumps({'format': FORMAT, 'createdUtc': manifest['createdUtc']}) + '\n',
               owner=(account.pw_uid, account.pw_gid))
        updated = reader_update(READER.read_text())
        with tempfile.NamedTemporaryFile('w', dir=READER.parent, delete=False) as check:
            temporary = Path(check.name); check.write(updated)
        try:
            run('/bin/sh', '-n', str(temporary))
            atomic(READER, updated, 0o755)
        finally:
            temporary.unlink(missing_ok=True)
        os.chown(OUTPUT, account.pw_uid, account.pw_gid); OUTPUT.chmod(0o700)
    log('HOST JOBS EXPORT READY: ' + str(len(manifest['files'])) + ' private files captured.')
    log('Application services and schedules were not changed. Existing transfer-key restrictions were retained.')
    log('Run this same command on the NAS to copy and verify the bundle without installing its jobs.')


def verify_files(destination, names):
    expected = {}
    for line in (destination / 'SHA256SUMS').read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if not match or match[2] not in names or match[2] in expected:
            raise RuntimeError('The host-job checksum list is invalid.')
        expected[match[2]] = match[1]
    if set(expected) != names - {'SHA256SUMS'}:
        raise RuntimeError('The host-job checksum list is incomplete.')
    for name, value in expected.items():
        path = destination / name
        if path.is_symlink() or not path.resolve().is_relative_to(destination.resolve()) or digest(path) != value:
            raise RuntimeError('A staged host file failed verification.')
    manifest = json.loads((destination / 'manifest.json').read_text())
    if manifest.get('format') != FORMAT or manifest.get('sourceHost') != '192.168.0.29':
        raise RuntimeError('Unexpected host-job export identity.')
    sources = set()
    for entry in manifest['files']:
        path = PurePosixPath(entry['source'])
        if (not path.is_absolute() or '..' in path.parts or entry['source'] in sources
                or entry['snapshot'] not in expected or not entry['snapshot'].startswith('files/')
                or entry['sha256'] != expected[entry['snapshot']]):
            raise RuntimeError('The source host-file manifest is inconsistent.')
        sources.add(entry['source'])
    return manifest


def extract_checked(archive, destination):
    with tarfile.open(archive, 'r:gz') as source:
        members = source.getmembers(); names = set(); total = 0
        for member in members:
            path = PurePosixPath(member.name); total += member.size
            if (not member.isfile() or path.is_absolute() or '..' in path.parts
                    or member.name in names or total > LIMIT or len(members) > 550
                    or member.size > 2 * 1024**2
                    or not re.fullmatch(r'(?:manifest\.json|SHA256SUMS|files/[0-9a-f]{20}-[A-Za-z0-9_.@+-]+|diagnostics/[A-Za-z0-9_.@+-]+\.log)', member.name)):
                raise RuntimeError('An unsafe or oversized host-job archive member was rejected.')
            names.add(member.name)
        for member in members:
            path = destination / member.name; path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with source.extractfile(member) as reader:
                path.write_bytes(reader.read())
            path.chmod(0o600)
    return verify_files(destination, names)


def stage_nas():
    if not SSD.is_mount() or not KEY.is_file() or KEY.is_symlink():
        raise RuntimeError('The NAS application SSD and existing private transfer key are required.')
    stage = SSD / 'migration/host-jobs-optiplex'
    if stage.is_symlink():
        raise RuntimeError('Unexpected host-job staging path.')
    stage.mkdir(mode=0o700, parents=True, exist_ok=True); stage.chmod(0o700)
    if (stage / '.copy.lock').is_symlink():
        raise RuntimeError('Unexpected transfer lock path.')
    with (stage / '.copy.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        known = stage / 'known_hosts'; atomic(known, HOST_KEY)
        ssh = ['ssh', '-nT', '-p', '22', '-i', str(KEY), '-o', 'BatchMode=yes',
               '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
               '-o', 'UserKnownHostsFile=' + str(known), '-o', 'ConnectTimeout=15',
               'sawdoctor@192.168.0.29']
        checksum = run(*ssh, 'host-jobs-sha256').stdout
        match = re.fullmatch(r'([0-9a-f]{64})  export.tar.gz\n?', checksum)
        if not match:
            raise RuntimeError('Run the host-job capture on the OptiPlex first.')
        expected = match[1]; archive = stage / 'export.tar.gz'
        if archive.is_symlink():
            raise RuntimeError('Unexpected staged archive path.')
        if archive.exists() and digest(archive) != expected:
            raise RuntimeError('A different existing host-job archive was retained for review.')
        if not archive.exists():
            log('Copying the private host-job bundle from the OptiPlex...')
            with tempfile.NamedTemporaryFile(dir=stage, delete=False) as temporary:
                part = Path(temporary.name)
                try:
                    result = subprocess.run(ssh + ['host-jobs'], stdout=temporary,
                                            stderr=subprocess.DEVNULL, timeout=180)
                    temporary.flush(); os.fsync(temporary.fileno())
                    if result.returncode or part.stat().st_size > LIMIT or digest(part) != expected:
                        raise RuntimeError('The private host-job transfer failed its integrity check.')
                    part.replace(archive)
                finally:
                    part.unlink(missing_ok=True)
        snapshot = stage / 'snapshot'
        if snapshot.is_symlink():
            raise RuntimeError('Unexpected host-job snapshot path.')
        if snapshot.exists():
            marker = stage / 'staged.json'
            if not marker.is_file() or json.loads(marker.read_text()).get('archiveSha256') != expected:
                raise RuntimeError('An existing unrecognized host-job snapshot was retained.')
            names = {path.relative_to(snapshot).as_posix() for path in snapshot.rglob('*') if path.is_file()}
            manifest = verify_files(snapshot, names)
        else:
            with tempfile.TemporaryDirectory(prefix='.host-jobs-', dir=stage) as directory:
                work = Path(directory) / 'snapshot'; work.mkdir(mode=0o700)
                manifest = extract_checked(archive, work)
                work.rename(snapshot)
            atomic(stage / 'staged.json', json.dumps({'format': FORMAT, 'archiveSha256': expected}) + '\n')
        log('HOST-JOB SNAPSHOT VERIFIED ON NAS: ' + str(snapshot))
        log('Copied files: ' + str(len(manifest['files'])) + '. No source jobs were installed or enabled.')
        for unit in ('tmc-deadlock-watch.service', 'torbox-audiobook-archive.service', 'plex-daily-backup.service',
                     'plex-api-watch.timer', 'media-mount-guard.timer', 'abs-user-provisioner.timer'):
            value = manifest['units'].get(unit, {})
            log(unit + ': source ' + value.get('ActiveState', 'not recorded') + '/' + value.get('SubState', '?')
                + ', ' + value.get('UnitFileState', '?'))
        for unit, record in manifest['diagnostics'].items():
            log(unit + ' private log indicators: ' + (', '.join(record['flags']) or 'no known error class detected'))
        for entry in manifest['files']:
            if 'torbox' in entry['source'].lower() or 'tmc-' in entry['source'].lower():
                log('TorBox helper captured: ' + entry['source'])
        for path in Path('/var/lib/openmediavault/cron.d').glob('userdefined-*'):
            if path.is_file() and path.stat().st_size < 128 * 1024:
                body = path.read_text(errors='replace')
                labels = [label for label, pattern in (
                    ('temperature/sensor monitoring', r'temp|sensors|sas3|hba'),
                    ('backup', r'backup|fsarchiver'), ('rclone/mount', r'rclone|fusermount'),
                    ('container control', r'docker|podman')) if re.search(pattern, body, re.I)]
                log('Existing OMV scheduled task: ' + path.name + ' | ' + (', '.join(labels) or 'purpose needs review'))
    log('Next: review the copied implementations and adapt only the required jobs to NAS paths and containers.')


def main():
    os.umask(0o077)
    if os.geteuid() != 0:
        raise RuntimeError('Run with sudo.')
    addresses = run('ip', '-4', 'addr', 'show').stdout
    if 'inet 192.168.0.29/' in addresses:
        export_source()
    elif 'inet 192.168.0.220/' in addresses:
        stage_nas()
    else:
        raise RuntimeError('Run on the OptiPlex or NAS, identified by its LAN address.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        log('STOP: ' + (str(error) if isinstance(error, RuntimeError) else
                       'Host-job capture could not finish (' + type(error).__name__ + ').'))
        raise SystemExit(1)
