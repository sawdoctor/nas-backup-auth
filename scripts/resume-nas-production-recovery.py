#!/usr/bin/env python3
"""Resume existing mount recovery and finish an already verified backup.

Current upgraded applications remain authoritative. Only the two mount-recovery
unit conditions are released. No images, Compose files, databases, source jobs,
cron or application schedules are restored or changed.
"""
import copy
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.request

APP = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
BASE = APP / 'compose/production-cutover'
WORK = BASE / 'media-recovery-handover'
SELF = WORK / 'worker.py'
RECORD = WORK / 'state.json'
BACKUP_HELPER = BASE / 'backup-handover/worker.py'
BACKUP_SHA = 'b5d38a2377b52867abf7b5a1625d19fb66217f282622134e6e40d09c35e2a0e8'
UNIT = 'nas-production-recovery.service'
FORMAT = 'sawdoctor-production-media-recovery-release-v1'
RELEASE = ('nas-media-recovery.service', 'nas-media-recovery.timer')
SET_NAME = 'nas-20261115T091448Z'
MANUAL_UPDATES = {'speedtest-tracker-nas', 'silo-nas-silo-1'}


def say(value): print(value, flush=True)
def sha(body): return hashlib.sha256(body).hexdigest()
def now(): return dt.datetime.now(dt.timezone.utc).isoformat()


def backup_module():
    import importlib.util
    if any(path.is_symlink() for path in (BACKUP_HELPER, *BACKUP_HELPER.parents)):
        raise RuntimeError('The accepted backup handover controller is symbolic.')
    body = BACKUP_HELPER.read_bytes()
    if sha(body) != BACKUP_SHA: raise RuntimeError('The accepted backup handover controller changed.')
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('accepted_backup_recovery', BACKUP_HELPER)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def mounts(row):
    return sorted(json.dumps(value, sort_keys=True) for value in row['Mounts'])


def runtime_signature(rows):
    return {name: {'id': row['Id'], 'image': row['Image'], 'running': row['State']['Running'],
                   'config': sha(json.dumps(row['Config'], sort_keys=True).encode()),
                   'hostConfig': sha(json.dumps(row['HostConfig'], sort_keys=True).encode()),
                   'mounts': mounts(row)} for name, row in rows.items()}


def approved_manual_update(old, current, archive_mtime):
    if current['Name'].lstrip('/') not in MANUAL_UPDATES or not current['State']['Running']:
        raise RuntimeError('A changed backup-baseline container needs separate review.')
    created = dt.datetime.fromisoformat(current['Created'].replace('Z', '+00:00')).timestamp()
    if created <= archive_mtime:
        raise RuntimeError('A container changed before the application archive finished; backup consistency needs review.')
    if mounts(old) != mounts(current):
        raise RuntimeError('A manually updated application has changed persistent/media bindings.')
    old_labels, new_labels = old['Config'].get('Labels') or {}, current['Config'].get('Labels') or {}
    if any(old_labels.get(key) != new_labels.get(key) for key in
           ('com.docker.compose.project', 'com.docker.compose.service')):
        raise RuntimeError('A manually updated application changed Compose ownership.')
    if any(old['HostConfig'].get(key) != current['HostConfig'].get(key) for key in ('NetworkMode', 'PortBindings')):
        raise RuntimeError('A manually updated application changed its network bindings.')
    return {'name': current['Name'].lstrip('/'), 'beforeContainerId': old['Id'], 'afterContainerId': current['Id'],
            'beforeImageId': old['Image'], 'afterImageId': current['Image'], 'createdUtc': current['Created'],
            'reason': 'user manual update/recreation after application archive; original data/network/Compose bindings retained'}


def backup_assessment(native, backup, rows):
    if backup.unit(native, 'nas-backup.service').get('Result') != 'success':
        raise RuntimeError('The already completed normal NAS backup is not successful.')
    directory = backup.BACKUP / 'backups/sets' / SET_NAME
    if native.read(directory / '_COMPLETE', 1024) != b'Sawdoctor NAS backup v1\n' or not (directory / '_UPLOADED').is_file():
        raise RuntimeError('The verified local/cloud backup completion markers are unavailable.')
    record = json.loads(native.read(backup.RECORD))
    original = {row['Name'].lstrip('/'): row for row in json.loads(native.read(directory / 'containers.json'))}
    mtime = (directory / 'applications.tar.zst').stat().st_mtime
    accepted = []
    for before in record['runningBefore']:
        name = before['name']; current = rows.get(name); old = original.get(name)
        if current is None or not current['State']['Running']:
            raise RuntimeError('An application has not recovered: ' + name)
        if old is None or (old['Id'], old['Image']) != (before['id'], before['image']):
            raise RuntimeError('The original backup container metadata differs from its handover baseline.')
        if (current['Id'], current['Image']) != (before['id'], before['image']):
            accepted.append(approved_manual_update(old, current, mtime))
    return record, accepted


def current_guard(native, backup):
    native.approved(backup.PLAN_SHA)
    main = json.loads(native.read(native.STATE))
    if main.get('phase') != 'awaiting-acceptance': raise RuntimeError('A tested NAS import awaiting final ownership is required.')
    if json.loads(native.read(native.ACTIVE)) != {'format': native.FORMAT, 'cutoverId': main['proof']['cutoverId']}:
        raise RuntimeError('The remaining migration hold identity differs.')
    native.held(main['proof'])
    for name in ('nas-backup.service', 'nas-production-backups.service', 'nas-production-books.service'):
        if backup.unit(native, name)['ActiveState'] in ('active', 'activating', 'deactivating'):
            raise RuntimeError('A backup/import is still active; leave it running: ' + name)
    rows = native.catalog(); recovery = native.helpers()['recovery']
    if recovery.saved_ids(): raise RuntimeError('A backup has pending container recovery IDs.')
    if any(native.dockmon_notify(native.dockmon_database(rows['dockmon'])).values()):
        raise RuntimeError('Dockmon automatic actions must remain off.')
    host = recovery.host_mounts()
    for row in rows.values():
        if row['State']['Running'] and recovery.dependencies(row) and not recovery.ready(row, host):
            raise RuntimeError('A host media mount is unavailable; no recovery conditions were released.')
    backup_assessment(native, backup, rows)
    return main, rows, recovery


def release_locked(native, backup):
    main, rows, recovery = current_guard(native, backup)
    documents = recovery.unit_documents()
    for name in RELEASE:
        if native.read(native.UNITS / name) != documents[name].encode():
            raise RuntimeError('An installed media-recovery unit changed; retained.')
    record = json.loads(native.read(RECORD)) if RECORD.exists() else None
    if record and (record.get('format') != FORMAT or record.get('cutoverId') != main['proof']['cutoverId']):
        raise RuntimeError('An unrelated mount-recovery handover record was retained.')
    paths = [native.UNITS / (name + '.d') / native.DROPIN for name in RELEASE]
    for path in paths:
        if path.exists():
            if native.read(path) != native.CONDITION.encode(): raise RuntimeError('A media-recovery override was edited; retained.')
        elif record is None:
            raise RuntimeError('An expected media-recovery hold is missing without a release record.')
    if record is None:
        record = {'format': FORMAT, 'cutoverId': main['proof']['cutoverId'], 'createdUtc': now(),
                  'phase': 'prepared', 'releasedUnits': list(RELEASE), 'beforeRuntime': runtime_signature(rows)}
        native.atomic(RECORD, record)
    if record.get('phase') == 'complete': return record
    record.update(phase='releasing', updatedUtc=now()); native.atomic(RECORD, record)
    for path in paths:
        if path.exists(): path.unlink(); native.sync_dir(path.parent)
    native.run('systemctl', 'daemon-reload')
    record.update(phase='released', updatedUtc=now()); native.atomic(RECORD, record)
    say('Released only the existing media-recovery service/timer conditions; current source/cron/startup/application holds retained.')
    return record


def probe_updated_application(native, row):
    health = row['State'].get('Health', {}).get('Status', 'none')
    if health not in ('none', 'healthy'): raise RuntimeError('A manually updated application is not healthy yet.')
    ports = {bind['HostPort'] for key, values in (row['HostConfig'].get('PortBindings') or {}).items()
             if key.endswith('/tcp') for bind in values or []
             if bind.get('HostIp', '') in ('', '0.0.0.0', '192.168.0.220')}
    if len(ports) != 1: raise RuntimeError('A manually updated application needs a reviewed web endpoint.')
    port = next(iter(ports))
    if not re.fullmatch(r'[0-9]{1,5}', port): raise RuntimeError('An application port is invalid.')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs): return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try: response = opener.open('http://192.168.0.220:' + port + '/', timeout=5)
    except urllib.error.HTTPError as error: response = error
    with response:
        if not (200 <= response.code < 400 or response.code in (401, 403)):
            raise RuntimeError('A manually updated application web endpoint failed.')
        say('Current updated application responding: ' + row['Name'].lstrip('/') + ' HTTP=' + str(response.code))


def boot_image_inventory(native, rows):
    result = []
    for name, row in sorted(rows.items()):
        if row['HostConfig']['RestartPolicy']['Name'] not in ('', 'no'): continue
        labels = row['Config'].get('Labels') or {}
        project, service = labels.get('com.docker.compose.project'), labels.get('com.docker.compose.service')
        paths = labels.get('com.docker.compose.project.config_files', '').split(',')
        entry = {'name': name, 'runtimeImageId': row['Image'], 'runtimeImageReference': row['Config']['Image']}
        try:
            if not project or not service or len(paths) != 1 or not paths[0]: raise RuntimeError('Compose identity unavailable')
            path = Path(paths[0])
            if path.is_relative_to('/app/data/stacks'):
                path = APP / 'appdata/dockmon/stacks' / path.relative_to('/app/data/stacks')
            path = path.resolve(strict=True)
            if not path.is_relative_to(APP) or path.stat().st_size > 4 * 1024**2: raise RuntimeError('Unreviewed Compose path')
            model = json.loads(native.run('docker', 'compose', '-p', project, '-f', str(path), 'config', '--format', 'json'))
            image = model['services'][service]['image']
            local = json.loads(native.run('docker', 'image', 'inspect', image))[0]['Id']
            entry.update(project=project, service=service, path=str(path), fileSha256=sha(path.read_bytes()),
                         composeImage=image, sameLocalImage=local == row['Image'])
        except Exception as error: entry['notVerified'] = type(error).__name__
        result.append(entry)
    return result


def complete(native, backup, record):
    if record.get('phase') == 'complete':
        say('Media recovery and post-backup acceptance already completed; no extra backup or restart requested.'); return
    # Never hold BACKUP_LOCK while starting a service that acquires it itself.
    native.run('systemctl', 'start', 'nas-media-recovery.service', timeout=180)
    native.run('systemctl', 'enable', '--now', 'nas-media-recovery.timer')
    with native.lock(native.BACKUP_LOCK):
        _main, rows = backup.preflight(native)
        if runtime_signature(rows) != record['beforeRuntime']:
            raise RuntimeError('An image/configuration/running state changed during mount recovery; retained for review.')
        previous, accepted = backup_assessment(native, backup, rows)
        for update in accepted: probe_updated_application(native, rows[update['name']])
        # Keep the original baseline intact. Record each explicit newer-version
        # exception separately rather than pretending no update occurred.
        previous.update(phase='complete', completedUtc=now(), backupSet=SET_NAME, sampleRestore='pending',
                        currentContainerImagesPreserved=not bool(accepted), acceptedManualUpdates=accepted,
                        completionController=FORMAT)
        native.atomic(backup.RECORD, previous)
        inventory = boot_image_inventory(native, rows)
        native.atomic(WORK / 'boot-image-inventory.json', {'format': FORMAT, 'applications': inventory})
        record.update(phase='complete', completedUtc=now(), acceptedManualUpdates=accepted, backupSet=SET_NAME,
                      bootImageIssues=[item['name'] for item in inventory if item.get('notVerified') or not item.get('sameLocalImage')])
        native.atomic(RECORD, record)
    say('NAS MEDIA RECOVERY RESTORED. Current media bindings and backup recovery checks passed; one-minute recovery timer active.')
    say('CURRENT NAS BACKUP ACCEPTED. Existing SSD/GDrive set reused; no new backup, image pull or data import.')
    say('Manual updates accepted with original data/network/Compose bindings: ' + (', '.join(item['name'] for item in accepted) or 'none'))
    say('Current Plex identity, source hold and Dockmon notify-only policy passed. Original backup baseline retained.')
    say('Startup Compose image entries needing reconciliation before boot ownership: ' + (', '.join(record['bootImageIssues']) or 'none found'))
    say('Cron, final boot ownership, application schedules/alerts, NPM renewal and sample restore remain separate tasks.')


def main():
    os.umask(0o077); backup = backup_module(); backup.guard()
    native = backup.load(BASE / 'worker.py', backup.NATIVE_SHA, 'media_release_native')
    if sys.argv[1:] == ['--worker']:
        with native.lock(BASE / '.run.lock'):
            with native.lock(native.BACKUP_LOCK): record = release_locked(native, backup)
            complete(native, backup, record)
        return
    if sys.argv[1:] or globals().get('RESUME_APPROVED_MEDIA_RECOVERY') is not True:
        raise RuntimeError('The approved current-NAS media-recovery release flag is required.')
    if backup.unit(native, UNIT)['ActiveState'] in ('active', 'activating', 'deactivating'):
        say('NAS media-recovery handover is already running.'); return
    source = globals().get('INSTALL_SOURCE')
    if not isinstance(source, str): raise RuntimeError('The complete reviewed controller source is required.')
    with native.lock(BASE / '.run.lock'), native.lock(native.BACKUP_LOCK):
        native.safe(WORK); WORK.mkdir(mode=0o700, exist_ok=True)
        if SELF.exists() and native.read(SELF) != source.encode(): raise RuntimeError('A different media-recovery controller was retained.')
        native.atomic(SELF, source.encode())
    subprocess.run(['systemctl', 'reset-failed', UNIT], capture_output=True, timeout=15)
    native.run('systemd-run', '--unit=' + UNIT, '--collect', '--property=Type=exec', '--property=UMask=0077',
               '--property=RuntimeMaxSec=15min', '--description=Restore current NAS media recovery and accept verified backup',
               '/usr/bin/python3', '-u', str(SELF), '--worker')
    say('Current NAS mount-recovery handover started in systemd. Closing SSH is safe.')
    say('Progress: sudo journalctl -u ' + UNIT + ' -f -n 25 --no-pager -o cat')


if __name__ == '__main__':
    try: main()
    except Exception as error:
        say('STOP: ' + (str(error) if isinstance(error, RuntimeError) else type(error).__name__) +
            '. Verified backup and current application data/images retained.'); raise SystemExit(1)
