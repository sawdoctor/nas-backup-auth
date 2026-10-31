#!/usr/bin/env python3
"""Receive and verify the private six-app OptiPlex export on the NAS."""
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import time

SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
KEY = Path('/root/.ssh/nas-infinidysk-transfer')
HOST_KEY = '192.168.0.29 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGI1/hObYOUSPIqGKLePC0eEFvCc8Uoyv+YOmBbVPbgW\n'
NAMES = {'sonarr', 'radarr', 'radarr4k', 'prowlarr', 'usenet-ultimate', 'overseerr'}


def log(message):
    print(message, flush=True)


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            digest.update(block)
    return digest.hexdigest()


def write_marker(path, document):
    fd, temporary = tempfile.mkstemp(prefix='.staged-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(document, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def ssh_base(known_hosts):
    return ['ssh', '-nT', '-p', '22', '-i', str(KEY), '-o', 'BatchMode=yes',
        '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
        '-o', 'UserKnownHostsFile=' + str(known_hosts), '-o', 'ConnectTimeout=15',
        '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3', 'sawdoctor@192.168.0.29']


def small_read(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        data = process.stdout.read(512)
        if len(data) >= 512:
            raise RuntimeError('Run the new OptiPlex export installer first; its transfer helper is not ready.')
        code = process.wait(timeout=30)
        if code == 255:
            raise RuntimeError('SSH transfer authentication or connection failed. The existing NAS key was retained.')
        return data.decode('ascii', errors='strict') if code == 0 else None
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def validate_tar(archive):
    process = subprocess.Popen(['zstd', '-dc', '--', str(archive)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    paths, links = set(), set()
    try:
        with tarfile.open(fileobj=process.stdout, mode='r|') as source:
            for member in source:
                name = PurePosixPath(member.name)
                if name.is_absolute() or '..' in name.parts or member.isdev() or member.isfifo():
                    raise RuntimeError('The export contains an unsafe archive member.')
                paths.add(name)
                if member.issym():
                    links.add(name)
                if member.islnk():
                    target = PurePosixPath(member.linkname)
                    if target.is_absolute() or '..' in target.parts:
                        raise RuntimeError('The export contains an unsafe hardlink.')
        for name in paths:
            if any(parent in links for parent in name.parents):
                raise RuntimeError('The export places files under a symlink.')
        while process.stdout.read(1048576):
            pass
        if process.wait() != 0:
            raise RuntimeError('The export decompression check failed.')
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.terminate()
            process.wait()


def main():
    os.umask(0o077)
    addresses = subprocess.check_output(['ip', '-4', 'addr', 'show'], text=True)
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in addresses:
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220.')
    if not SSD.is_mount() or not KEY.is_file():
        raise RuntimeError('The appdata SSD and existing NAS transfer key must be available.')
    stage = SSD / 'migration/core-optiplex'
    if stage.is_symlink():
        raise RuntimeError('Unexpected migration staging symlink.')
    stage.mkdir(parents=True, mode=0o700, exist_ok=True)
    stage.chmod(0o700)
    with open(stage / '.copy.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        known_hosts = stage / 'known_hosts'
        if known_hosts.is_symlink():
            raise RuntimeError('Unexpected host-key path.')
        known_hosts.write_text(HOST_KEY)
        known_hosts.chmod(0o600)
        ssh = ssh_base(known_hosts)
        log('Waiting for the OptiPlex core export to finish...')
        deadline = time.monotonic() + 2 * 3600
        report = 0
        while True:
            metadata = small_read(ssh + ['core-sha256'])
            if metadata:
                match = re.fullmatch(r'([a-f0-9]{64})  export\.tar\.zst\n?', metadata)
                if not match:
                    raise RuntimeError('The source did not return the expected core archive checksum.')
                expected = match.group(1)
                break
            status = small_read(ssh + ['core-status']) or ''
            if 'ActiveState=failed' in status:
                raise RuntimeError('The OptiPlex export failed. Read: sudo journalctl -u nas-core-export.service -n 60 --no-pager')
            if time.monotonic() > deadline:
                raise RuntimeError('The source export is not ready after two hours. Rerun once it completes.')
            if time.monotonic() > report:
                log('Source is still preparing the export; NAS applications continue running.')
                report = time.monotonic() + 30
            time.sleep(5)
        archive = stage / 'export.tar.zst'
        if archive.is_symlink():
            raise RuntimeError('Unexpected archive symlink.')
        if archive.exists():
            if file_hash(archive) != expected:
                raise RuntimeError('A different existing archive occupies this staging path; it was retained.')
            log('The verified core archive is already on the NAS.')
        else:
            part = stage / 'export.tar.zst.part'
            if part.is_symlink():
                raise RuntimeError('Unexpected partial-archive symlink.')
            log('Copying the private export from the OptiPlex...')
            digest = hashlib.sha256()
            received, report = 0, 0
            with tempfile.TemporaryFile() as errors, part.open('wb') as destination:
                process = subprocess.Popen(ssh + ['core'], stdout=subprocess.PIPE, stderr=errors)
                try:
                    for block in iter(lambda: process.stdout.read(1048576), b''):
                        if shutil.disk_usage(stage).free < 512 * 1024**2:
                            raise RuntimeError('Stopping before staging fills the NAS SSD.')
                        destination.write(block)
                        digest.update(block)
                        received += len(block)
                        if time.monotonic() > report:
                            log('Received ' + str(round(received / 1024**2)) + ' MiB...')
                            report = time.monotonic() + 5
                    if process.wait() != 0:
                        raise RuntimeError('The SSH copy did not complete. Rerun to retry the staging transfer.')
                    destination.flush()
                    os.fsync(destination.fileno())
                finally:
                    process.stdout.close()
                    if process.poll() is None:
                        process.terminate()
                        process.wait()
            if digest.hexdigest() != expected:
                raise RuntimeError('The copied archive failed its SHA256 check; it was not activated.')
            os.replace(part, archive)
        snapshot = stage / 'snapshot'
        if snapshot.is_symlink():
            raise RuntimeError('Unexpected snapshot symlink.')
        if snapshot.exists():
            marker_path = stage / 'staged.json'
            if marker_path.exists():
                marker = json.loads(marker_path.read_text())
                if marker.get('archiveSha256') != expected:
                    raise RuntimeError('A different snapshot already exists; it was retained.')
            else:
                # Recover a termination between the verified snapshot rename and marker write.
                run('sha256sum', '--quiet', '-c', 'SHA256SUMS', cwd=snapshot)
                manifest = json.loads((snapshot / 'manifest.json').read_text())
                write_marker(marker_path, {'archiveSha256': expected, 'createdUtc': manifest['createdUtc']})
        else:
            log('Checking archive paths, extracting and verifying every exported file...')
            validate_tar(archive)
            if shutil.disk_usage(stage).free < 3 * archive.stat().st_size + 512 * 1024**2:
                raise RuntimeError('The NAS SSD needs more free staging space before extraction.')
            work = Path(tempfile.mkdtemp(prefix='.snapshot-', dir=stage))
            try:
                run('tar', '--acls', '--xattrs', '--numeric-owner', '-I', 'zstd', '-xpf', str(archive), '-C', str(work))
                run('sha256sum', '--quiet', '-c', 'SHA256SUMS', cwd=work)
                manifest = json.loads((work / 'manifest.json').read_text())
                if (manifest.get('format') != 'sawdoctor-core-export-v1'
                    or manifest.get('sourceHost') != '192.168.0.29'
                    or {c['Name'].lstrip('/') for c in manifest['containers']} != NAMES):
                    raise RuntimeError('The export is not the expected six-app OptiPlex snapshot.')
                os.replace(work, snapshot)
                write_marker(stage / 'staged.json', {'archiveSha256': expected,
                    'createdUtc': manifest['createdUtc']})
            finally:
                if work.exists():
                    shutil.rmtree(work)
    log('\nCORE SNAPSHOT VERIFIED ON NAS: ' + str(snapshot))
    log('Sonarr, Radarr, Radarr 4K, Prowlarr, Usenet Ultimate and Seerr are ready for NAS deployment.')
    log('Configuration and exact images are staged. The six new NAS containers have not been started.')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit('\nInterrupted. Rerun to continue staging.')
    except Exception as error:
        raise SystemExit('STOP: ' + str(error))
