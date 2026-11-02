#!/usr/bin/env python3
"""Prepare the copied NAS audiobook archiver and check it without cloud writes."""
import configparser
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile
import time

SIGNATURE = 'Sawdoctor NAS audiobook archive v1'
SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
SNAPSHOT = SSD / 'migration/host-jobs-optiplex/dependencies/snapshot'
BOOKS = SSD / 'migration/books-optiplex/snapshot/manifest.json'
DATA = SSD / 'appdata/host-jobs/torbox-audiobook-archive'
CONFIG = SSD / 'appdata/books-cloud/rclone.conf'
BINARY = Path('/usr/local/libexec/infinidysk-rclone')
UNIT = Path('/etc/systemd/system/nas-torbox-audiobook-archive.service')
TIMER = Path('/etc/systemd/system/nas-torbox-audiobook-archive.timer')
LOCK = Path('/run/lock/sawdoctor-nas-backup.lock')
PACKAGES = {
    '/usr/local/lib/torbox-audiobooks/scripts/torbox_audiobook_archive.py':
        ('scripts/torbox_audiobook_archive.py', 'aa03da6ec856eab4e62bbd12805339dee89025720a63cc2100f7b993265aabd4'),
    '/usr/local/lib/torbox-audiobooks/shelfmark/__init__.py':
        ('shelfmark/__init__.py', 'f0cda3e777670829f78727dbd39b53737e24d1173c6ab078bc970325e048a372'),
    '/usr/local/lib/torbox-audiobooks/shelfmark/torbox_airlock.py':
        ('shelfmark/torbox_airlock.py', 'dbec9fd39040801c1c22faad22f59d2231561abe7cf51657d75a1ab6d752ff9b'),
}


def say(message):
    print(message, flush=True)


def run(*args, timeout=30, env=None):
    return subprocess.run(args, text=True, capture_output=True, timeout=timeout, env=env)


def atomic(path, data):
    if path.is_symlink():
        raise RuntimeError('An unexpected symbolic archive path was preserved.')
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
            temporary.chmod(0o600); temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def copied_files(snapshot):
    if snapshot.is_symlink():
        raise RuntimeError('Unexpected dependency snapshot path.')
    manifest = json.loads((snapshot / 'manifest.json').read_text())
    if (manifest.get('format') != 'sawdoctor-host-jobs-export-v1'
            or manifest.get('kind') != 'sawdoctor-host-job-dependencies-v1'
            or manifest.get('sourceHost') != '192.168.0.29'):
        raise RuntimeError('The verified dependency snapshot is required.')
    result = {}
    for entry in manifest['files']:
        relative = PurePosixPath(entry['snapshot']); path = snapshot / relative
        if (relative.is_absolute() or '..' in relative.parts or path.is_symlink()
                or not path.resolve().is_relative_to(snapshot.resolve()) or path.stat().st_size > 2 * 1024**2):
            raise RuntimeError('An unexpected copied dependency path was rejected.')
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != entry['sha256'] or entry['source'] in result:
            raise RuntimeError('A copied dependency failed verification.')
        result[entry['source']] = data
    for source, (_relative, expected) in PACKAGES.items():
        if hashlib.sha256(result.get(source, b'')).hexdigest() != expected:
            raise RuntimeError('The archive implementation differs from the reviewed copy.')
    return manifest, result


def mapped_path(original, source, current):
    path = Path(original)
    candidates = sorted(source['Mounts'], key=lambda mount: len(mount['Source']), reverse=True)
    for mount in candidates:
        if mount['Type'] != 'bind' or not path.is_relative_to(mount['Source']):
            continue
        target = next((item for item in current['Mounts'] if item['Type'] == 'bind'
                       and item['Destination'] == mount['Destination']), None)
        if target is None:
            break
        mapped = Path(target['Source']) / path.relative_to(mount['Source'])
        if '..' in mapped.parts or mapped.is_symlink() or not mapped.resolve().is_relative_to((SSD / 'appdata/books-nas').resolve()) or not mapped.is_dir():
            raise RuntimeError('A book application path is outside its installed NAS appdata.')
        return mapped
    raise RuntimeError('Could not map the recorded library/configuration to the current NAS bindings.')


def validate_state(data):
    state = json.loads(data)
    if not isinstance(state, dict) or state.get('version') != 1 or any(not isinstance(state.get(key), dict) for key in ('origins', 'backups')):
        raise RuntimeError('The saved archive state requires review; it was preserved.')
    return state


def install(manifest, files, library, shelfmark):
    marker = DATA / 'install.json'
    for path in (DATA, DATA.parent, marker, UNIT, TIMER):
        if path.is_symlink():
            raise RuntimeError('An unexpected archive installation path was preserved.')
    state_source = manifest.get('archiveState', {}).get('sourceDirectory', '').rstrip('/') + '/archive-state.json'
    state_data = files.get(state_source)
    if state_data is None:
        raise RuntimeError('The copied archive ledger is required; no empty replacement was created.')
    validate_state(state_data)
    for path in (UNIT, TIMER):
        if path.exists() and SIGNATURE not in path.read_text():
            raise RuntimeError('An unrelated archive unit was preserved.')
    for unit in (UNIT.name, TIMER.name):
        if run('systemctl', 'is-active', '--quiet', unit).returncode == 0 or run('systemctl', 'is-enabled', '--quiet', unit).returncode == 0:
            raise RuntimeError('The NAS archive job is already enabled/active; its settings were retained.')
    if DATA.exists() and (not marker.is_file() or json.loads(marker.read_text()).get('format') != SIGNATURE):
        raise RuntimeError('Unrecognized archive appdata was preserved.')
    environment = {
        'HOME': '/root', 'PYTHONDONTWRITEBYTECODE': '1',
        'PATH': str(DATA / 'runtime/bin') + ':/usr/sbin:/usr/bin:/sbin:/bin',
        'SHELFMARK_CONFIG_DIR': str(shelfmark), 'TORBOX_AUDIOBOOK_LIBRARY': str(library),
        'TORBOX_MOUNT_PATH': '/mnt/torbox-audiobooks', 'TORBOX_VAULT_MOUNT': '/mnt/gdrive-torbox-archive',
        'TORBOX_VAULT_REMOTE': 'gdrive:Shelfmark-TorBox-Archive', 'TORBOX_SOURCE_REMOTE': 'torbox-audiobooks:',
        'TORBOX_ARCHIVE_STATE_DIR': str(DATA / 'state'), 'TORBOX_ARCHIVE_MAX_BACKUPS': '2',
        'RCLONE_CONFIG': str(CONFIG),
    }
    if not DATA.exists():
        DATA.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='.archive-', dir=DATA.parent) as temporary:
            work = Path(temporary) / 'data'; work.mkdir(mode=0o700)
            for source, (relative, _expected) in PACKAGES.items():
                target = work / 'runtime' / relative; target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                atomic(target, files[source])
            (work / 'runtime/bin').mkdir(mode=0o700)
            (work / 'runtime/bin/rclone').symlink_to(BINARY)
            (work / 'state').mkdir(mode=0o700)
            atomic(work / 'state/archive-state.json', state_data)
            atomic(work / 'archive.env', ''.join(key + '=' + json.dumps(value) + '\n' for key, value in environment.items()).encode())
            atomic(work / 'install.json', (json.dumps({'format': SIGNATURE, 'sourceCreatedUtc': manifest['createdUtc'], 'environment': environment}, indent=2) + '\n').encode())
            work.rename(DATA)
    else:
        recorded = json.loads(marker.read_text())
        if recorded.get('environment') != environment:
            raise RuntimeError('Installed NAS archive paths/settings differ; they were retained for review.')
        for _source, (relative, expected) in PACKAGES.items():
            path = DATA / 'runtime' / relative
            if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise RuntimeError('An installed archive program changed; it was retained for review.')
        validate_state((DATA / 'state/archive-state.json').read_bytes())
        if (DATA / 'runtime/bin/rclone').resolve() != BINARY.resolve():
            raise RuntimeError('The installed archive binary link differs; it was retained.')
    service = f'''# {SIGNATURE}
[Unit]
Description=NAS TorBox audiobook protection and verified backup vault
After=network-online.target nas-books.service nas-rclone-torbox-audiobooks.service nas-rclone-gdrive-torbox-archive.service
Wants=network-online.target
Requires=nas-rclone-torbox-audiobooks.service nas-rclone-gdrive-torbox-archive.service
RequiresMountsFor={SSD}

[Service]
Type=oneshot
EnvironmentFile={DATA}/archive.env
ExecStart=/usr/bin/python3 {DATA}/runtime/scripts/torbox_audiobook_archive.py --apply
UMask=0077
Nice=10
TimeoutStartSec=4h
'''
    timer = f'''# {SIGNATURE}
[Unit]
Description=NAS audiobook archive schedule; enable only after source writer handover

[Timer]
OnBootSec=10min
OnUnitActiveSec=10min
AccuracySec=30s
Unit={UNIT.name}

[Install]
WantedBy=timers.target
'''
    atomic(UNIT, service.encode()); UNIT.chmod(0o644)
    atomic(TIMER, timer.encode()); TIMER.chmod(0o644)
    if run('systemctl', 'daemon-reload').returncode:
        raise RuntimeError('Archive files are prepared, but unit reload failed.')
    return environment


def error_class(text):
    for label, pattern in (
            ('Google/API quota or rate limit', r'quota|rate.?limit|429'),
            ('Authorization denied', r'401|403|unauthori[sz]ed|invalid_grant'),
            ('Unsupported rclone command/flag', r'unknown command|unknown flag'),
            ('Remote file/path unavailable', r'not found|404|does not exist|directory not found'),
            ('Connection timeout or network failure', r'timed? ?out|connection refused|no such host')):
        if re.search(pattern, text, re.I):
            return label
    return 'Detailed error saved privately'


def checks(environment):
    child = dict(environment)
    say('Running the copied archive in read-only plan mode...')
    result = run('/usr/bin/python3', str(DATA / 'runtime/scripts/torbox_audiobook_archive.py'), timeout=240, env=child)
    atomic(DATA / 'preflight-plan.log', (result.stdout + result.stderr).encode())
    try:
        report = json.loads(result.stdout)
    except ValueError:
        raise RuntimeError('Archive plan did not return valid JSON; details are saved in its appdata.') from None
    summary = {key: len(report.get(key, [])) for key in (
        'already_protected', 'pending_protection', 'unmatched_links', 'errors', 'vault_links_need_review')}
    say('Plan counts: ' + json.dumps(summary, sort_keys=True))
    if result.returncode or report.get('mode') != 'plan':
        raise RuntimeError('The archive is installed and paused; its read-only plan needs review.')
    state = validate_state((DATA / 'state/archive-state.json').read_bytes())
    sample = next((entry['identity'] for entry in state['backups'].values()
                   if isinstance(entry, dict) and isinstance(entry.get('identity'), dict)
                   and entry['identity'].get('source') and entry['identity'].get('destination')), None)
    if sample is None:
        raise RuntimeError('The copied ledger has no source/destination pair to check; archive remains paused.')
    results = {}
    for label, remote in (('TorBox source', sample['source']), ('GDrive vault', sample['destination'])):
        name, separator, relative = remote.partition(':')
        if not separator or name != ('torbox-audiobooks' if label == 'TorBox source' else 'gdrive') or '..' in PurePosixPath(relative).parts:
            raise RuntimeError('An unexpected saved remote path requires review.')
        params = json.dumps({'fs': name + ':', 'remote': relative, 'opt': {'showHash': True}})
        response = run(str(BINARY), 'rc', '--loopback', 'operations/stat', '--json', params,
                       '--config', str(CONFIG), '--contimeout', '10s', '--timeout', '30s', '--retries', '1', timeout=90)
        atomic(DATA / ('preflight-' + name + '.log'), (response.stdout + response.stderr).encode())
        if response.returncode:
            raise RuntimeError(label + ' metadata check failed: ' + error_class(response.stdout + response.stderr) + '. Archive remains paused.')
        item = json.loads(response.stdout).get('item')
        results[label] = 'present' if item and item.get('IsDir') is False else 'missing'
        say(label + ' metadata: ' + results[label])
    atomic(DATA / 'preflight-summary.json', (json.dumps({'format': SIGNATURE, 'mode': 'read-only', 'counts': summary, 'metadata': results}, indent=2) + '\n').encode())
    say('NAS AUDIOBOOK ARCHIVE PREPARED: original program and saved ledger installed; timer disabled.')
    say('Read-only checks completed. No protection, archive transfers or playback-link changes were made.')


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show').stdout or not SSD.is_mount():
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220 with its SSD mounted.')
    if not BINARY.is_file() or not CONFIG.is_file():
        raise RuntimeError('The existing NAS media rclone and cloud configuration are required.')
    config = configparser.ConfigParser(interpolation=None); config.read(CONFIG)
    if not config.get('gdrive', 'client_id', fallback='').strip() or not config.has_section('torbox-audiobooks'):
        raise RuntimeError('The existing custom NAS cloud connection is required; no authentication was changed.')
    manifest, files = copied_files(SNAPSHOT)
    original = json.loads(BOOKS.read_text())
    if original.get('format') != 'sawdoctor-books-export-v1' or original.get('sourceHost') != '192.168.0.29':
        raise RuntimeError('The original verified books manifest is required for exact path mapping.')
    current = run('docker', 'inspect', 'audiobookshelf-test-nas', 'shelfmark-torbox-nas')
    if current.returncode:
        raise RuntimeError('The installed NAS audiobook applications must be available.')
    current = {entry['Name'].lstrip('/'): entry for entry in json.loads(current.stdout)}
    source = {entry['Name'].lstrip('/'): entry for entry in original['containers']}
    for entry in current.values():
        if (entry['Config'].get('Labels') or {}).get('com.docker.compose.project') != 'books-nas':
            raise RuntimeError('An audiobook container is outside the installed NAS books project.')
    policy = manifest['policy']
    library = mapped_path(policy['TORBOX_AUDIOBOOK_LIBRARY'], source['audiobookshelf-test'], current['audiobookshelf-test-nas'])
    shelfmark = mapped_path(policy['SHELFMARK_CONFIG_DIR'], source['shelfmark-torbox'], current['shelfmark-torbox-nas'])
    for target, remote in (('/mnt/torbox-audiobooks', 'torbox-audiobooks:'), ('/mnt/gdrive-torbox-archive', 'gdrive:Shelfmark-TorBox-Archive')):
        mounted = run('findmnt', '-n', '--mountpoint', target, '-o', 'FSTYPE,SOURCE')
        if mounted.returncode or mounted.stdout.split() != ['fuse.rclone', remote]:
            raise RuntimeError('A required NAS audiobook cloud mount is unavailable.')
    say('Preparing the copied archive on NAS paths with the existing custom cloud connection...')
    with LOCK.open('a') as lock:
        announced = False
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB); break
            except BlockingIOError:
                if not announced:
                    say('Waiting for the NAS backup lock...'); announced = True
                time.sleep(2)
        environment = install(manifest, files, library, shelfmark)
        checks(environment)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('STOP: ' + (str(error) if isinstance(error, RuntimeError) else 'NAS archive preparation failed (' + type(error).__name__ + '); existing data was retained.'))
