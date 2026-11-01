#!/usr/bin/env python3
"""Upload verified host-job source text privately for the requested review.

Uses the existing NAS backup remote. Does not install, enable or execute any
copied job. Credential config files (.env/rclone.conf) are omitted; original
script/unit source can still contain credentials and must remain private.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tempfile

SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
SNAPSHOT = SSD / 'migration/host-jobs-optiplex/snapshot'
REMOTE = 'gdrive:nas-backups/openmediavault/migration-review/host-jobs-code-20261101.txt'


def load_review(snapshot):
    manifest = json.loads((snapshot / 'manifest.json').read_text())
    if manifest.get('format') != 'sawdoctor-host-jobs-export-v1' or manifest.get('sourceHost') != '192.168.0.29':
        raise RuntimeError('The verified OptiPlex host-job snapshot is not available.')
    result = {'format': 'sawdoctor-host-jobs-code-review-v1',
              'createdUtc': manifest['createdUtc'], 'sourceHost': manifest['sourceHost'],
              'units': manifest['units'], 'files': [], 'diagnostics': [], 'omittedSettings': []}
    for entry in manifest['files']:
        source = PurePosixPath(entry['source']); relative = PurePosixPath(entry['snapshot'])
        path = snapshot / relative
        if (relative.is_absolute() or '..' in relative.parts or path.is_symlink()
                or not path.resolve().is_relative_to(snapshot.resolve()) or not path.is_file()
                or path.stat().st_size > 2 * 1024**2):
            raise RuntimeError('An unsafe or unexpected host-job snapshot path was rejected.')
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != entry['sha256']:
            raise RuntimeError('A copied host-job file failed its integrity check.')
        unit = str(source).startswith('/etc/systemd/')
        cron = str(source).startswith(('/etc/cron', '/var/spool/cron/'))
        if entry.get('script') or unit or cron:
            result['files'].append({'source': str(source), 'sha256': entry['sha256'],
                                    'content': data.decode('utf-8', errors='replace')})
        else:
            # The policy settings may matter later, but no credential values
            # are needed to inspect control flow. Record names, not values.
            keys = []
            for line in data.decode(errors='replace').splitlines():
                if line.strip() and not line.lstrip().startswith(('#', ';', '[')) and '=' in line:
                    key = line.split('=', 1)[0].strip().removeprefix('export ')
                    if key and all(character.isalnum() or character in '_-.' for character in key):
                        keys.append(key)
            result['omittedSettings'].append({'source': str(source), 'keys': sorted(set(keys))})
    sums = {}
    for line in (snapshot / 'SHA256SUMS').read_text().splitlines():
        checksum, name = line.split('  ', 1); sums[name] = checksum
    for unit, item in manifest['diagnostics'].items():
        relative = PurePosixPath(item['snapshot']); path = snapshot / relative
        if (relative.is_absolute() or '..' in relative.parts or path.is_symlink()
                or not path.resolve().is_relative_to(snapshot.resolve()) or path.stat().st_size > 2 * 1024**2):
            raise RuntimeError('An unsafe diagnostic path was rejected.')
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != sums.get(relative.as_posix()):
            raise RuntimeError('A copied diagnostic file failed verification.')
        result['diagnostics'].append({'unit': unit, 'content': data.decode(errors='replace')})
    payload = (json.dumps(result, ensure_ascii=False, indent=2) + '\n').encode()
    if len(payload) > 8 * 1024**2:
        raise RuntimeError('The review text is unexpectedly large; no upload was attempted.')
    return payload, len(result['files'])


def main():
    os.umask(0o077)
    addresses = subprocess.check_output(['ip', '-4', 'addr', 'show'], text=True)
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in addresses:
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220.')
    if not SSD.is_mount():
        raise RuntimeError('The NAS application SSD is not mounted.')
    payload, count = load_review(SNAPSHOT)
    print('Uploading the private script review using the existing NAS backup connection...', flush=True)
    # A seekable, private temporary file lets the installed rclone retry an
    # upload without asking for another copy or leaving a review file on disk.
    with tempfile.NamedTemporaryFile(prefix='nas-host-jobs-review-', suffix='.txt') as temporary:
        temporary.write(payload); temporary.flush(); os.fsync(temporary.fileno())
        result = subprocess.run(['rclone', '--config', '/root/.config/rclone/rclone.conf',
                                 'copyto', temporary.name, REMOTE,
                                 '--tpslimit', '2', '--retries', '3'], timeout=300)
    if result.returncode:
        raise RuntimeError('The private review upload did not complete.')
    print('PRIVATE SCRIPT REVIEW UPLOADED: ' + str(count) + ' script/unit/cron files.')
    print('Review SHA256: ' + hashlib.sha256(payload).hexdigest())
    print('Existing jobs, schedules and sharing permissions were not changed.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('STOP: ' + (str(error) if isinstance(error, RuntimeError) else
                                   'Private script review could not finish (' + type(error).__name__ + ').'))
