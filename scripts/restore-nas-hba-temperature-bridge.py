#!/usr/bin/env python3
"""Restore only HBA collection while the original OMV cron owner is held.

Keep the existing collector and OMV job byte-for-byte. The bridge skips
collection when cron is active and can be retired at the later cron handover.
Boot collection depends only on local hashes, never on source SSH or Docker.
"""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

BASE = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6/compose/production-cutover')
REVIEW = BASE / 'kuma-control-review/worker.py'
REVIEW_SHA = 'ef31f99d8ab2ebb0e57e615b51853d2381c367e330ea33ab71531d7aeb0deef1'
WORK = BASE / 'hba-temperature-handover'
SELF = WORK / 'worker.py'
STATE = WORK / 'state.json'
FORMAT = 'sawdoctor-hba-temperature-bridge-v1'
UNIT = 'nas-hba-temperature-handover.service'
COLLECTOR = Path('/usr/local/sbin/hba-temp-collect')
COLLECTOR_SHA = 'c326301b51ba62a1aee7e098756f5acc38b98fcba6dfe59752e3691456edfe96'
OMV_JOB = Path('/var/lib/openmediavault/cron.d/userdefined-5afc8576-fdb1-4fc9-b9f5-272c5f6d474e')
OMV_JOB_SHA = '685855ee3a4eb963b6f9a441b9bd03d3f66511b4b7a135a4540bed624f97181e'
CACHE = Path('/run/hba-temp')
SERVICE = Path('/etc/systemd/system/nas-hba-temperature-bridge.service')
TIMER = Path('/etc/systemd/system/nas-hba-temperature-bridge.timer')


def say(value): print(value, flush=True)


def verified(path, checksum):
    if any(item.is_symlink() for item in (path, *path.parents)) or not path.is_file() or path.stat().st_size > 512 * 1024:
        raise RuntimeError('A reviewed HBA file is missing, symbolic or oversized.')
    if hashlib.sha256(path.read_bytes()).hexdigest() != checksum:
        raise RuntimeError('A reviewed HBA collector/job changed; existing source retained.')


def cron_state():
    result = subprocess.run(['systemctl', 'show', '--no-pager', 'cron.service', '-p', 'ActiveState'],
        text=True, capture_output=True, timeout=10, check=True)
    fields = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    state = fields.get('ActiveState')
    if state not in ('active', 'activating', 'deactivating', 'inactive', 'failed'):
        raise RuntimeError('Cron ownership is unavailable; bridge collection was skipped.')
    return state


def cached_temperature(after_ns):
    if CACHE.is_symlink() or not CACHE.is_file() or CACHE.stat().st_size > 32 or CACHE.stat().st_mtime_ns < after_ns:
        raise RuntimeError('The existing HBA collector did not refresh its cache.')
    text = CACHE.read_text().strip()
    if not text.isascii() or not text.isdigit() or not 0 <= int(text) <= 200:
        raise RuntimeError('The HBA cache is not a bounded numeric temperature.')
    return int(text)


def collect():
    # This local-only path is also used at boot; do not load migration/source
    # controllers or acquire their backup/application locks here.
    if cron_state() in ('active', 'activating', 'deactivating'):
        say('HBA BRIDGE SKIPPED: original cron owner is running.'); return None
    verified(COLLECTOR, COLLECTOR_SHA); verified(OMV_JOB, OMV_JOB_SHA)
    with open('/run/lock/sawdoctor-hba-temperature.lock', 'a') as lock:
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            say('HBA BRIDGE SKIPPED: a previous bridge collection is still running.'); return None
        if cron_state() not in ('inactive', 'failed'):
            say('HBA BRIDGE SKIPPED: cron ownership is changing.'); return None
        previous_cache = CACHE.stat() if CACHE.exists() else None
        subprocess.run([str(COLLECTOR)], capture_output=True, timeout=20, check=True)
        temperature = cached_temperature(0)
        refreshed_cache = CACHE.stat()
        if previous_cache is not None and (previous_cache.st_dev, previous_cache.st_ino) == (refreshed_cache.st_dev, refreshed_cache.st_ino):
            raise RuntimeError('The existing HBA collector did not replace its cache.')
    say('HBA TEMPERATURE COLLECTED: ' + str(temperature) + ' C; original collector retained.')
    return temperature


def unit_contents():
    service = '''[Unit]
Description=Collect existing NAS HBA temperature while OMV cron is held
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -u ''' + str(SELF) + ''' --collect
TimeoutStartSec=35
UMask=0077
'''
    timer = '''[Unit]
Description=Temporary HBA temperature collection until original cron handover

[Timer]
OnBootSec=60s
OnUnitActiveSec=60s
AccuracySec=5s
Unit=nas-hba-temperature-bridge.service

[Install]
WantedBy=timers.target
'''
    return {SERVICE: service.encode(), TIMER: timer.encode()}


def controllers():
    verified(REVIEW, REVIEW_SHA)
    spec = importlib.util.spec_from_file_location('reviewed_kuma_hba', REVIEW)
    inspected = importlib.util.module_from_spec(spec); spec.loader.exec_module(inspected)
    return (inspected, *inspected.controllers())


def worker(inspected, accepted, resume, old, review, boot, backup, native, startup):
    with boot.boot_lock(native):
        main, current = backup.preflight(native)
        completion = json.loads(native.read(accepted.STATE))
        if completion.get('phase') != 'complete' or completion.get('format') != accepted.FORMAT or completion.get('cutoverId') != main['proof']['cutoverId']:
            raise RuntimeError('The current application acceptance differs.')
        before = accepted.snapshot(boot, old, current)
        verified(COLLECTOR, COLLECTOR_SHA); verified(OMV_JOB, OMV_JOB_SHA)
        if cron_state() != 'inactive' or not native.ACTIVE.exists():
            raise RuntimeError('The reviewed inactive cron/migration ownership changed; no bridge installed.')
        report = json.loads(native.read(inspected.WORK / 'hba-review.json'))
        if report.get('collectorSha256') != COLLECTOR_SHA or report.get('relatedUnits') != {}:
            raise RuntimeError('The reviewed HBA owner differs; no duplicate owner installed.')
        record = {'format': FORMAT, 'cutoverId': main['proof']['cutoverId'], 'phase': 'prepared',
            'collectorSha256': COLLECTOR_SHA, 'originalOmvJobSha256': OMV_JOB_SHA, 'skipWhenCronRuns': True}
        if STATE.exists():
            prior = json.loads(native.read(STATE))
            if prior.get('format') != FORMAT or prior.get('cutoverId') != record['cutoverId']:
                raise RuntimeError('An unrelated HBA handover record was retained.')
        for path, data in unit_contents().items():
            native.safe(path)
            if path.exists() and native.read(path) != data:
                raise RuntimeError('A different existing HBA bridge unit was retained.')
        native.atomic(STATE, record)
        for path, data in unit_contents().items():
            if not path.exists(): native.atomic(path, data, mode=0o644)
    # Start the persistent timer/collector outside the shared backup lock.
    native.run('systemctl', 'daemon-reload')
    native.run('systemctl', 'enable', '--now', TIMER.name)
    native.run('systemctl', 'start', SERVICE.name, timeout=45)
    first = CACHE.stat().st_mtime_ns if CACHE.is_file() else 0
    first_value = cached_temperature(time.time_ns() - 45 * 10**9)
    say('HBA INITIAL READING: ' + str(first_value) + ' C. Waiting for the timer to collect a second fresh reading...')
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        if CACHE.is_file() and CACHE.stat().st_mtime_ns > first:
            second_value = cached_temperature(first + 1); break
        if cron_state() != 'inactive': raise RuntimeError('Cron ownership changed during the timer check; current source retained.')
        time.sleep(4)
    else: raise RuntimeError('A second scheduled HBA reading was not observed; bridge retained for targeted review.')
    with boot.boot_lock(native):
        _main, final = backup.preflight(native)
        if accepted.snapshot(boot, old, final) != before:
            raise RuntimeError('An application runtime changed during HBA handover; no application data restored.')
        if backup.unit(native, TIMER.name).get('ActiveState') != 'active' or cron_state() != 'inactive':
            raise RuntimeError('The HBA timer/cron owner did not retain the reviewed state.')
        verified(COLLECTOR, COLLECTOR_SHA); verified(OMV_JOB, OMV_JOB_SHA)
        record.update(phase='complete', twoFreshReadingsVerified=True, temperatureC=second_value, timerEnabled=True)
        native.atomic(STATE, record)
    say('NAS HBA TEMPERATURE COLLECTION RESTORED: two fresh readings verified; one-minute bridge enabled for reboot.')
    say('Existing collector/OMV job, all containers and main cron/job holds retained. Bridge skips whenever cron runs; retire it at final cron handover.')


def main():
    os.umask(0o077)
    if sys.argv[1:] == ['--collect']:
        collect(); return
    sys.dont_write_bytecode = True
    args = controllers(); inspected, accepted, resume, old, review, boot, backup, native, startup = args
    native.safe(WORK); WORK.mkdir(mode=0o700, exist_ok=True)
    if sys.argv[1:] == ['--worker']:
        with native.lock(BASE / '.run.lock'): worker(*args)
        return
    if sys.argv[1:] or globals().get('RESTORE_APPROVED_HBA_COLLECTION') is not True:
        raise RuntimeError('The approved HBA collection restoration flag is required.')
    source = globals().get('INSTALL_SOURCE')
    if not isinstance(source, str): raise RuntimeError('The complete reviewed HBA bridge source is required.')
    with native.lock(BASE / '.run.lock'):
        if backup.unit(native, UNIT).get('ActiveState') in ('active', 'activating', 'deactivating'):
            say('HBA restoration is already running.'); return
        if SELF.exists() and native.read(SELF) != source.encode(): raise RuntimeError('A different HBA bridge helper was retained.')
        if not SELF.exists(): native.atomic(SELF, source.encode(), mode=0o700)
        subprocess.run(['systemctl', 'reset-failed', UNIT], capture_output=True)
        native.run('systemd-run', '--unit=' + UNIT, '--collect', '--property=Type=exec', '--property=UMask=0077', '--property=RuntimeMaxSec=5min',
            '--description=Restore existing HBA temperature collection while cron is held', '/usr/bin/python3', '-u', str(SELF), '--worker')
    say('HBA collection restoration started in systemd. Closing SSH is safe.')
    say('Progress: sudo journalctl -u ' + UNIT + ' -f -n 20 --no-pager -o cat')


if __name__ == '__main__':
    try: main()
    except Exception as error:
        say('STOP: ' + type(error).__name__ + '. ' + str(error) + ' Existing collector, OMV job and applications retained.'); raise SystemExit(1)
