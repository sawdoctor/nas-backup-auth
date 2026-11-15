#!/usr/bin/env python3
"""Release only NAS backup ownership, preserving current upgraded applications.

The original import guard, cron and other jobs remain held. The existing
combined backup captures Plex/applications/OMV once and verifies its GDrive copy.
No frozen images, Compose files or application databases are restored here.
"""
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

APP = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
BACKUP = Path('/srv/dev-disk-by-uuid-631e3391-6a42-4158-9aa4-f7718ba0e7e9')
BASE = APP / 'compose/production-cutover'
WORK = BASE / 'backup-handover'
SELF = WORK / 'worker.py'
RECORD = WORK / 'state.json'
BACKUP_WORKER = Path('/usr/local/sbin/nas-backup')
NATIVE_SHA = 'ae59ce0542f9c72acc84cbc1888c397fb6a5c2bd730f6e101d2e3da4f62669f1'
IDENTITY_SHA = '068495226906f5a3674d3464e1124b25e472d13ad7419a1d9a98545e7d99d96f'
PLAN_SHA = 'bf4176032a44b7d3e113fbeb212acb5f0bd895f391c81f7543188d3db8779b10'
LEGACY_SHA = '1b3cbdf0446bf95ecbaea26cb2a9c1a0c63a2687fd725ae0ad9ab0f1d7693133'
FORMAT = 'sawdoctor-production-backup-ownership-v1'
UNIT = 'nas-production-backups.service'
RELEASE_UNITS = ('nas-backup.service', 'nas-backup-resume.service', 'nas-backup.timer')
EXCLUSIONS = tuple('compose/production-cutover/*/' + leaf for leaf in ('incoming', 'rollback', 'prepared'))
ALL_EXCLUSIONS = EXCLUSIONS + ('compose/plex-nas/recovery/before-standby-refresh',
                              'compose/infinidysk-nas/recovery/before-latest')


def say(value): print(value, flush=True)
def sha(body): return hashlib.sha256(body).hexdigest()
def now(): return dt.datetime.now(dt.timezone.utc).isoformat()


def load(path, expected, name):
    if any(p.is_symlink() for p in (path, *path.parents)) or sha(path.read_bytes()) != expected:
        raise RuntimeError('An accepted backup/identity controller differs: ' + path.name)
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def patch_backup(original):
    if sha(original) != LEGACY_SHA:
        raise RuntimeError('The installed backup worker differs from the reviewed version; retained.')
    text = original.decode()
    anchor = "  --exclude='appdata/silo/download-artifacts/*' \\\n"
    needed = 'NEEDED=$(du -sbx "$SSD/appdata" "$SSD/compose" "${VOLUMES[@]/#/$SSD/}"'
    if text.count(anchor) != 1 or text.count(needed) != 1:
        raise RuntimeError('The reviewed backup archive/space selection differs; retained.')
    addition = ''.join("  --exclude='" + item + "' \\\n" for item in EXCLUSIONS)
    options = ''.join(" --exclude='*/" + item + "'" for item in ALL_EXCLUSIONS)
    return text.replace(anchor, anchor + addition, 1).replace(needed, needed.replace('du -sbx', 'du -sbx' + options), 1).encode()


def unit(native, name):
    text = native.run('systemctl', 'show', '--no-pager', '--full', name,
                      '-p', 'LoadState', '-p', 'ActiveState', '-p', 'SubState',
                      '-p', 'Result', '-p', 'ExecMainStartTimestampMonotonic', '-p', 'MainPID')
    return dict(line.split('=', 1) for line in text.splitlines() if '=' in line)


def mounted(native, path, uuid):
    if not path.is_mount() or native.run('findmnt', '-rn', '--mountpoint', str(path), '-o', 'UUID,FSTYPE').split() != [uuid, 'ext4']:
        raise RuntimeError('An expected application/backup SSD is not mounted with its recorded UUID.')


def preflight(native):
    plan = native.approved(PLAN_SHA)
    state = json.loads(native.read(native.STATE))
    if (state.get('phase') != 'awaiting-acceptance' or not state.get('roots')
            or any(item.get('phase') != 'installed' for item in state['roots'])):
        raise RuntimeError('The completed, accepted live NAS import is required; no backup controls changed.')
    active = json.loads(native.read(native.ACTIVE))
    if active != {'format': native.FORMAT, 'cutoverId': state['proof']['cutoverId']}:
        raise RuntimeError('The remaining migration guard differs; retained.')
    native.held(state['proof'])
    identity = load(BASE / 'finish-plex-identity.py', IDENTITY_SHA, 'backup_plex_identity')
    identity.wait_plex(native, Path(plan['liveRoots']['plex']), state['proof'])
    mounted(native, APP, 'e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
    mounted(native, BACKUP, '631e3391-6a42-4158-9aa4-f7718ba0e7e9')
    target = native.run('/bin/bash', '-c', '''set -eo pipefail
set +u
. /etc/default/openmediavault
. /usr/share/openmediavault/scripts/helper-functions
ref=$(omv_config_get /config/system/backup/sharedfolderref)
printf '%s\\0%s\\0%s' "$(omv_get_sharedfolder_path "$ref")" "$(omv_get_sharedfolder_mount_dir "$ref")" "$(omv_config_get /config/system/backup/method)"
''').split('\0')
    if len(target) != 3 or target[2] != 'fsarchiver' or [Path(x).resolve() for x in target[:2]] != [BACKUP / 'backups', BACKUP]:
        raise RuntimeError('OMV backup must still target the existing spare SSD using fsarchiver.')
    for name in RELEASE_UNITS:
        if unit(native, name).get('LoadState') != 'loaded':
            raise RuntimeError('An existing NAS backup unit is unavailable: ' + name)
    if unit(native, 'nas-backup.service')['ActiveState'] in ('active', 'activating', 'deactivating'):
        raise RuntimeError('A normal NAS backup is already running; let it finish.')
    if native.helpers()['recovery'].saved_ids():
        raise RuntimeError('An earlier backup has pending container recovery; resolve it first.')
    for name in ('nas-backup-upload.service', 'nas-backup-restore-test.service',
                 'nas-production-books.service', 'nas-production-kometa-image.service',
                 'nas-production-activate.service', 'nas-production-resume.service',
                 'nas-production-finish.service', 'nas-image-registry-identities.service'):
        if unit(native, name).get('ActiveState') in ('active', 'activating', 'deactivating'):
            raise RuntimeError('Another migration/backup job is running: ' + name)
    rows = native.catalog()
    for name in ('plex-nas', 'infinidysk-nas', 'dockmon'):
        if name not in rows or not rows[name]['State']['Running']:
            raise RuntimeError('A required current NAS application is not running: ' + name)
    if any(native.dockmon_notify(native.dockmon_database(rows['dockmon'])).values()):
        raise RuntimeError('Dockmon automatic actions must remain off during this backup handover.')
    recovery = native.helpers()['recovery']; mounts = recovery.host_mounts()
    for row in rows.values():
        if row['State']['Running'] and recovery.dependencies(row):
            if not recovery.ready(row, mounts) or recovery.stale_bindings(row, mounts):
                raise RuntimeError('A running application has unavailable/stale media bindings: ' + row['Name'].lstrip('/'))
    return state, rows


def configure_locked(native):
    state, rows = preflight(native)
    record = json.loads(native.read(RECORD)) if RECORD.exists() else None
    if record and (record.get('format') != FORMAT or record.get('cutoverId') != state['proof']['cutoverId']):
        raise RuntimeError('An unrelated backup handover record was retained.')
    before = WORK / 'nas-backup.before'
    original = native.read(BACKUP_WORKER)
    if record:
        saved = native.read(before)
        if sha(saved) != LEGACY_SHA:
            raise RuntimeError('The retained original backup worker differs.')
        proposed = patch_backup(saved)
        if original not in (saved, proposed):
            raise RuntimeError('The backup worker was edited after handover preparation; retained.')
    else:
        proposed = patch_backup(original)
    guards = {name: native.UNITS / (name + '.d') / native.DROPIN for name in RELEASE_UNITS}
    for name, path in guards.items():
        if path.exists():
            if native.read(path) != native.CONDITION.encode():
                raise RuntimeError('A backup-specific migration override was edited; retained: ' + name)
        elif not record:
            raise RuntimeError('An expected backup-specific migration override is missing: ' + name)
    native.run('bash', '-n', input=proposed.decode())
    if record is None:
        if before.exists(): raise RuntimeError('An unjournalled backup recovery copy was retained.')
        native.atomic(before, original, mode=0o700)
        record = {'format': FORMAT, 'phase': 'prepared', 'createdUtc': now(),
                  'cutoverId': state['proof']['cutoverId'], 'beforeSha256': sha(original),
                  'afterSha256': sha(proposed), 'releasedUnits': list(RELEASE_UNITS),
                  'excludedRetainedTrees': list(EXCLUSIONS), 'runningBefore': [
                      {'name': name, 'id': row['Id'], 'image': row['Image']}
                      for name, row in rows.items() if row['State']['Running']],
                  'backupStartBefore': unit(native, 'nas-backup.service')['ExecMainStartTimestampMonotonic']}
        native.atomic(RECORD, record)
    if record.get('phase') == 'complete':
        say('This backup handover already completed; no duplicate backup was started.')
        return record
    if original != proposed:
        native.atomic(BACKUP_WORKER, proposed, reference=BACKUP_WORKER)
    if native.read(BACKUP_WORKER) != proposed: raise RuntimeError('The reviewed backup scope did not verify.')
    # Record intent before removing the first condition. Missing conditions are
    # accepted on retry only when this same cutover journal already exists.
    record.update(phase='releasing', updatedUtc=now()); native.atomic(RECORD, record)
    for path in guards.values():
        if path.exists(): path.unlink(); native.sync_dir(path.parent)
    # Keep ACTIVE, its reboot guard, cron and every unrelated job condition.
    native.run('systemctl', 'daemon-reload')
    record.update(phase='released', updatedUtc=now()); native.atomic(RECORD, record)
    say('Released only the three existing NAS backup conditions; cron/other migration controls remain held.')
    say('Retained import/rollback payloads excluded from both routine archives and backup space estimates.')
    return record


def arm_and_verify(native, record):
    if record['phase'] == 'complete': return
    # The caller has released BACKUP_LOCK. Persistent timers may run immediately.
    native.run('systemctl', 'enable', '--now', 'nas-backup.timer')
    say('Nightly combined NAS backup restored at its existing 02:00 UK schedule; checking its catch-up run...')
    requested = record.get('runRequested', False)
    deadline = time.monotonic() + 7 * 3600
    started = False; next_report = 0
    while time.monotonic() < deadline:
        status = unit(native, 'nas-backup.service')
        started = (status['ExecMainStartTimestampMonotonic'] != record['backupStartBefore']
                   and status['ExecMainStartTimestampMonotonic'] not in ('', '0'))
        active = status['ActiveState'] in ('active', 'activating', 'deactivating')
        if not started and not active and not requested:
            # A newly enabled timer need not catch up if its old timestamp was
            # cleared. Request the same existing unit once; systemd coalesces it.
            record.update(runRequested=True, phase='backup-running', updatedUtc=now())
            native.atomic(RECORD, record); requested = True
            native.run('systemctl', 'start', '--no-block', 'nas-backup.service')
        elif started and not active:
            if status.get('Result') != 'success':
                raise RuntimeError('The NAS backup did not complete successfully; read nas-backup.service journal.')
            break
        if time.monotonic() >= next_report:
            say('Existing nas-backup.service: ' + status['ActiveState'] + '/' + status['SubState'] + '; waiting for local/cloud completion...')
            next_report = time.monotonic() + 30
        time.sleep(3)
    else:
        raise RuntimeError('The backup is still running or needs review; no application was forcibly stopped by this monitor.')
    sets = BACKUP / 'backups/sets'
    candidates = [p for p in sets.glob('nas-*') if p.is_dir() and not p.is_symlink()
                  and (p / '_COMPLETE').is_file() and (p / '_UPLOADED').is_file()
                  and (p / '_COMPLETE').read_bytes() == b'Sawdoctor NAS backup v1\n'
                  and (p / '_COMPLETE').stat().st_mtime >= dt.datetime.fromisoformat(record['createdUtc']).timestamp() - 2]
    if not candidates: raise RuntimeError('No new completed, cloud-verified backup set was found.')
    latest = max(candidates, key=lambda p: p.name)
    rows = native.catalog()
    for previous in record['runningBefore']:
        row = rows.get(previous['name'])
        if (row is None or row['Id'] != previous['id'] or row['Image'] != previous['image']
                or not row['State']['Running']):
            raise RuntimeError('A previously running application changed or has not recovered: ' + previous['name'])
    if native.helpers()['recovery'].saved_ids(): raise RuntimeError('A backup container recovery record remains pending.')
    recovery = native.helpers()['recovery']; mounts = recovery.host_mounts()
    for row in rows.values():
        if row['State']['Running'] and recovery.dependencies(row):
            if not recovery.ready(row, mounts) or recovery.stale_bindings(row, mounts):
                raise RuntimeError('A post-backup application media binding needs recovery: ' + row['Name'].lstrip('/'))
    state = json.loads(native.read(native.STATE)); native.held(state['proof'])
    identity = load(BASE / 'finish-plex-identity.py', IDENTITY_SHA, 'post_backup_identity')
    plan = native.approved(PLAN_SHA)
    identity.wait_plex(native, Path(plan['liveRoots']['plex']), state['proof'])
    record.update(phase='complete', completedUtc=now(), backupSet=latest.name,
                  sampleRestore='pending', currentContainerImagesPreserved=True)
    native.atomic(RECORD, record)
    say('CURRENT NAS BACKUP COMPLETE: Plex/applications and OMV on spare SSD; existing worker verified Google Drive copy.')
    say('Previously running applications recovered with the same container/image identities; Plex identity/media bindings passed.')
    say('Nightly NAS backup timer restored. Source remains held; cron, final reboot ownership and NPM renewal remain separate.')
    say('Backup set: ' + latest.name)
    say('Sample restore remains the next verification step; this result is not a full restore test.')


def guard():
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in subprocess.check_output(['ip', '-4', 'addr', 'show'], text=True, timeout=10):
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220.')


def main():
    os.umask(0o077); guard()
    native = load(BASE / 'worker.py', NATIVE_SHA, 'production_backup_native')
    if sys.argv[1:] == ['--worker']:
        with native.lock(BASE / '.run.lock'):
            with native.lock(native.BACKUP_LOCK):
                record = configure_locked(native)
            arm_and_verify(native, record)
        return
    if sys.argv[1:]: raise RuntimeError('Unknown backup handover action.')
    if globals().get('RESUME_APPROVED_NAS_BACKUPS') is not True:
        raise RuntimeError('The approved NAS backup handover flag is required.')
    if unit(native, UNIT).get('ActiveState') in ('active', 'activating', 'deactivating'):
        say('NAS backup handover is already running; follow ' + UNIT + '.'); return
    source = globals().get('INSTALL_SOURCE')
    if not isinstance(source, str): raise RuntimeError('The complete reviewed backup handover source is required.')
    with native.lock(BASE / '.run.lock'), native.lock(native.BACKUP_LOCK):
        native.safe(WORK); WORK.mkdir(mode=0o700, exist_ok=True)
        if SELF.exists() and native.read(SELF) != source.encode():
            raise RuntimeError('A different backup handover controller was retained.')
        native.atomic(SELF, source.encode())
    # A collected/never-started transient unit has no failure state to reset.
    subprocess.run(['systemctl', 'reset-failed', UNIT], capture_output=True, timeout=15)
    native.run('systemd-run', '--unit=' + UNIT, '--collect', '--property=Type=exec',
               '--property=UMask=0077', '--property=RuntimeMaxSec=8h',
               '--description=Restore existing NAS backup schedule and verify current production backup',
               '/usr/bin/python3', '-u', str(SELF), '--worker')
    say('NAS backup-only handover started in systemd. Closing SSH is safe.')
    say('The existing backup briefly stops applications for a consistent archive, then restores them.')
    say('Progress: sudo journalctl -fu ' + UNIT + ' -n 20 --no-pager -o cat')
    say('Detailed backup: sudo journalctl -u nas-backup.service -n 20 --no-pager -o cat')


if __name__ == '__main__':
    try: main()
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        say('STOP: ' + (str(error) if isinstance(error, RuntimeError) else type(error).__name__) +
            '. No frozen images or application data were restored.'); sys.exit(1)
