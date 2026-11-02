#!/usr/bin/env python3
"""Capture the omitted host-job packages/state and stage them without activation."""
import contextlib
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import time
import types
import urllib.request

KIND = 'sawdoctor-host-job-dependencies-v1'
SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
SOURCE = Path('/home/sawdoctor/nas-host-jobs-export/dependencies')
STAGE = SSD / 'migration/host-jobs-optiplex/dependencies'
ENV = Path('/etc/torbox-audiobook-archive.env')
ARCHIVER = '/usr/local/lib/torbox-audiobooks/scripts/torbox_audiobook_archive.py'
REMOTE = 'gdrive:nas-backups/openmediavault/migration-review/host-job-dependencies-20261102.txt'
POLICY_KEYS = {'SHELFMARK_CONFIG_DIR', 'TORBOX_ARCHIVE_MAX_BACKUPS',
               'TORBOX_ARCHIVE_STATE_DIR', 'TORBOX_AUDIOBOOK_LIBRARY',
               'TORBOX_MOUNT_PATH', 'TORBOX_VAULT_MOUNT', 'TORBOX_VAULT_REMOTE'}
SKIP = {'.git', '__pycache__', '.venv', 'venv', 'node_modules', 'cache', 'backups'}
PACKAGE_ROOTS = (Path('/usr/local/lib/torbox-audiobooks'), Path('/usr/local/lib/plex-backup-bin'))
EXTRA_FILES = (Path('/usr/local/sbin/torbox-audiobook-archive'), ENV,
               Path('/etc/systemd/system/torbox-audiobook-archive.service'),
               Path('/etc/systemd/system/torbox-audiobook-archive.timer'))


def helper(path, commit, expected, name):
    url = 'https://raw.githubusercontent.com/sawdoctor/nas-backup-auth/' + commit + '/scripts/' + path
    data = urllib.request.urlopen(url, timeout=30).read()
    if hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError('A pinned migration helper failed its integrity check.')
    module = types.ModuleType(name); sys.modules[name] = module
    exec(compile(data, url, 'exec'), module.__dict__)
    return module


def env_values(path):
    values = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.removeprefix('export ').split('=', 1)
        parts = shlex.split(value, comments=True)
        values[key.strip()] = ' '.join(parts)
    return values


def collect(work, base):
    manifest = {'format': base.FORMAT, 'kind': KIND, 'sourceHost': '192.168.0.29',
                'createdUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'files': [], 'units': {}, 'diagnostics': {}, 'missing': [], 'links': [],
                'policy': {}, 'archiveState': {}}
    if not Path(ARCHIVER).is_file():
        raise RuntimeError('The archive implementation is not at its recorded /usr/local/lib path.')
    values = env_values(ENV)
    manifest['policy'] = {key: value for key, value in values.items() if key in POLICY_KEYS}
    seen = set(); total = 0

    def add(path, state=False):
        nonlocal total
        if str(path) in seen:
            return
        if path.is_symlink():
            manifest['links'].append({'source': str(path), 'target': os.readlink(path)})
        resolved = path.resolve()
        if not resolved.is_file():
            return
        filesystem = base.run('findmnt', '-n', '-T', str(resolved), '-o', 'FSTYPE').stdout.strip()
        if filesystem not in ('ext4', 'xfs', 'btrfs'):
            raise RuntimeError('A dependency is not on a local filesystem; leaving it untouched.')
        before = resolved.stat()
        if before.st_size > 2 * 1024**2:
            raise RuntimeError('A host-job dependency is unexpectedly large.')
        data = resolved.read_bytes(); after = resolved.stat(); total += len(data)
        if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
            raise RuntimeError('A dependency changed during capture; rerun the small export.')
        if len(manifest['files']) >= 500 or total > base.LIMIT:
            raise RuntimeError('Dependency capture exceeded its small-bundle limit.')
        name = hashlib.sha256(str(path).encode()).hexdigest()[:20] + '-' + path.name
        target = work / 'files' / name; target.write_bytes(data); target.chmod(0o600)
        manifest['files'].append({'source': str(path), 'snapshot': 'files/' + name,
            'sha256': hashlib.sha256(data).hexdigest(), 'mode': before.st_mode & 0o777,
            'uid': before.st_uid, 'gid': before.st_gid,
            'script': base.script(path, data), 'role': 'archive-state' if state else 'implementation'})
        seen.add(str(path))
        if state and path.name == 'archive-state.json':
            document = json.loads(data)
            if isinstance(document, dict):
                manifest['archiveState']['version'] = document.get('version')
                for key in ('origins', 'backups'):
                    value = document.get(key)
                    if isinstance(value, (dict, list)):
                        manifest['archiveState'][key + 'Count'] = len(value)

    for root in PACKAGE_ROOTS:
        if not root.is_dir():
            manifest['missing'].append(str(root)); continue
        for directory, folders, files in os.walk(root, followlinks=False):
            parent = Path(directory)
            folders[:] = [name for name in folders if name not in SKIP and not (parent / name).is_symlink()]
            for name in sorted(files):
                path = parent / name
                if root.name == 'plex-backup-bin' or path.suffix.lower() in (
                        '.py', '.sh', '.toml', '.txt', '.json', '.yaml', '.yml', '.ini', '.cfg', '.conf'):
                    # Standard binaries may be symlinked into the wrapper PATH;
                    # record that reference rather than copying Docker itself.
                    if path.is_symlink() and not str(path.resolve()).startswith(('/usr/local/', '/home/sawdoctor/')):
                        manifest['links'].append({'source': str(path), 'target': os.readlink(path)})
                    else:
                        add(path)
    for path in EXTRA_FILES:
        if path.is_file():
            add(path)
    state = Path(values.get('TORBOX_ARCHIVE_STATE_DIR', '/home/sawdoctor/.local/state/torbox-audiobooks'))
    if not state.is_absolute() or state.is_symlink():
        raise RuntimeError('The archive-state directory is not a real absolute path.')
    manifest['archiveState']['sourceDirectory'] = str(state)
    if state.is_dir():
        lock = state / 'archive.lock'
        with contextlib.ExitStack() as stack:
            if lock.is_file() and not lock.is_symlink():
                handle = stack.enter_context(lock.open('r'))
                deadline = time.monotonic() + 60; reported = False
                while True:
                    try:
                        fcntl.flock(handle, fcntl.LOCK_SH | fcntl.LOCK_NB); break
                    except BlockingIOError:
                        if not reported:
                            print('Waiting briefly for the active archive job to release its state...', flush=True); reported = True
                        if time.monotonic() > deadline:
                            raise RuntimeError('The archive job is still busy; rerun capture after it finishes. It was not stopped.')
                        time.sleep(2)
            for path in sorted(state.rglob('*.json')):
                if not path.is_symlink() and path.resolve().is_relative_to(state.resolve()):
                    add(path, state=True)
        manifest['archiveState']['copiedFiles'] = sum(entry['role'] == 'archive-state' for entry in manifest['files'])
    else:
        manifest['archiveState']['copiedFiles'] = 0
    if not any(entry['source'] == ARCHIVER for entry in manifest['files']):
        raise RuntimeError('The required archive implementation was not captured.')
    (work / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    files = sorted(path for path in work.rglob('*') if path.is_file())
    (work / 'SHA256SUMS').write_text(''.join(base.digest(path) + '  ' + path.relative_to(work).as_posix() + '\n' for path in files))
    return manifest


def reader_routes(original):
    marker = '# Sawdoctor missing host-job dependencies v1'
    if marker in original:
        return original
    if not original.startswith('#!/bin/sh\n') or 'SSH_ORIGINAL_COMMAND' not in original:
        raise RuntimeError('The existing restricted transfer reader needs review.')
    addition = f'''{marker}
case "${{SSH_ORIGINAL_COMMAND-}}" in
  host-job-dependencies) exec /bin/cat {SOURCE}/export.tar.gz ;;
  host-job-dependencies-sha256) exec /bin/cat {SOURCE}/export.sha256 ;;
esac
'''
    return '#!/bin/sh\n' + addition + original.split('\n', 1)[1]


def source_export(base):
    parent_marker = SOURCE.parent / 'export.json'
    if SOURCE.parent.is_symlink() or not parent_marker.is_file() or json.loads(parent_marker.read_text()).get('format') != base.FORMAT:
        raise RuntimeError('The original verified host-job export is required first.')
    base.OUTPUT = SOURCE
    base.collect = lambda work: collect(work, base)
    base.reader_update = reader_routes
    base.export_source()
    print('Missing package, wrapper and available archive state captured; the existing jobs were not changed.')


def nas_stage(base):
    if not SSD.is_mount() or not base.KEY.is_file() or base.KEY.is_symlink():
        raise RuntimeError('The mounted NAS SSD and existing private transfer key are required.')
    if STAGE.is_symlink() or STAGE.parent.is_symlink():
        raise RuntimeError('Unexpected dependency staging path.')
    STAGE.mkdir(mode=0o700, parents=True, exist_ok=True); STAGE.chmod(0o700)
    lock_path = STAGE / '.copy.lock'
    if lock_path.is_symlink():
        raise RuntimeError('Unexpected dependency transfer lock.')
    with lock_path.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        known = STAGE / 'known_hosts'; base.atomic(known, base.HOST_KEY)
        ssh = ['ssh', '-nT', '-p', '22', '-i', str(base.KEY), '-o', 'BatchMode=yes',
               '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
               '-o', 'UserKnownHostsFile=' + str(known), '-o', 'ConnectTimeout=15',
               'sawdoctor@192.168.0.29']
        checksum = base.run(*ssh, 'host-job-dependencies-sha256').stdout
        match = re.fullmatch(r'([0-9a-f]{64})  export.tar.gz\n?', checksum)
        if not match:
            raise RuntimeError('Run this dependency capture on the OptiPlex first.')
        expected = match[1]; archive = STAGE / 'export.tar.gz'
        if archive.is_symlink() or (archive.exists() and base.digest(archive) != expected):
            raise RuntimeError('A different existing dependency archive was retained for review.')
        if not archive.exists():
            print('Copying the missing package and state privately from the OptiPlex...', flush=True)
            with tempfile.NamedTemporaryFile(dir=STAGE, delete=False) as temporary:
                part = Path(temporary.name)
                try:
                    result = subprocess.run(ssh + ['host-job-dependencies'], stdout=temporary,
                                            stderr=subprocess.DEVNULL, timeout=180)
                    temporary.flush(); os.fsync(temporary.fileno())
                    if result.returncode or part.stat().st_size > base.LIMIT or base.digest(part) != expected:
                        raise RuntimeError('The dependency transfer failed verification.')
                    part.replace(archive)
                finally:
                    part.unlink(missing_ok=True)
        snapshot = STAGE / 'snapshot'; marker = STAGE / 'staged.json'
        if snapshot.is_symlink():
            raise RuntimeError('Unexpected dependency snapshot path.')
        if snapshot.exists():
            if not marker.is_file() or json.loads(marker.read_text()).get('archiveSha256') != expected:
                raise RuntimeError('An unrecognized dependency snapshot was retained.')
            names = {path.relative_to(snapshot).as_posix() for path in snapshot.rglob('*') if path.is_file()}
            manifest = base.verify_files(snapshot, names)
        else:
            with tempfile.TemporaryDirectory(prefix='.dependencies-', dir=STAGE) as directory:
                work = Path(directory) / 'snapshot'; work.mkdir(mode=0o700)
                manifest = base.extract_checked(archive, work)
                if manifest.get('kind') != KIND or not any(entry['source'] == ARCHIVER for entry in manifest['files']):
                    raise RuntimeError('The required archive package is missing from this export.')
                work.rename(snapshot)
            base.atomic(marker, json.dumps({'format': KIND, 'archiveSha256': expected}) + '\n')
        if manifest.get('kind') != KIND or not any(entry['source'] == ARCHIVER for entry in manifest['files']):
            raise RuntimeError('The required archive package is missing from this export.')
        review = helper('upload-host-job-review.py', '5781660e2910fa38fe17f5e328b8abf742a6bb2d',
                        '036d4e112e1e6f675172caf1e2f170ec67507ab77b4c330f9ca19d3fc5ca215a', 'dependency_review')
        payload, count = review.load_review(snapshot)
        document = json.loads(payload); document['kind'] = KIND
        document['policy'] = {key: value for key, value in manifest.get('policy', {}).items() if key in POLICY_KEYS}
        document['archiveStateSummary'] = manifest.get('archiveState', {})
        document['links'] = manifest.get('links', [])
        payload = (json.dumps(document, ensure_ascii=False, indent=2) + '\n').encode()
        print('Dependencies verified. Uploading their private code review using the existing NAS backup connection...', flush=True)
        with tempfile.NamedTemporaryFile(prefix='nas-dependency-review-', suffix='.txt') as temporary:
            temporary.write(payload); temporary.flush(); os.fsync(temporary.fileno())
            result = subprocess.run(['rclone', '--config', '/root/.config/rclone/rclone.conf',
                                     'copyto', temporary.name, REMOTE, '--tpslimit', '2', '--retries', '3'], timeout=300)
        if result.returncode:
            raise RuntimeError('Dependencies are staged, but the private review upload needs retrying on the NAS.')
        print('HOST-JOB DEPENDENCIES READY: ' + str(len(manifest['files'])) + ' files; ' + str(count) + ' source files available for review.')
        print('Saved archive-state files copied: ' + str(manifest.get('archiveState', {}).get('copiedFiles', 0)))
        print('Review SHA256: ' + hashlib.sha256(payload).hexdigest())
        print('No archive, cleanup, Plex or watchdog jobs were enabled.')


def main():
    os.umask(0o077)
    if os.geteuid() != 0:
        raise RuntimeError('Run with sudo.')
    addresses = subprocess.check_output(['ip', '-4', 'addr', 'show'], text=True)
    if 'inet 192.168.0.29/' not in addresses and 'inet 192.168.0.220/' not in addresses:
        raise RuntimeError('Run on the OptiPlex or NAS, identified by its LAN address.')
    base = helper('stage-migration-host-jobs.py', '89ad264edb83b7287e3e1b051646e93df8654d7d',
                  'e6ed2b698831319fe0f0a7980756936b37fc2760fd15b922449a1bb2a4aceddc', 'dependency_transfer')
    if 'inet 192.168.0.29/' in addresses:
        source_export(base)
    else:
        nas_stage(base)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('STOP: ' + (str(error) if isinstance(error, RuntimeError) else
                                   'Dependency capture could not finish (' + type(error).__name__ + ').'))
