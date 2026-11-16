#!/usr/bin/env python3
"""Correct only the exact installed HBA bridge cache-freshness comparison.

Run eight isolated regression cases before changing the worker. Keep its
original source, collector, OMV job and unit definitions. Then resume the
existing two-reading handover without releasing global cron or touching apps.
"""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import types
from unittest.mock import mock_open, patch

BASE = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6/compose/production-cutover')
WORK = BASE / 'hba-temperature-handover'
TARGET = WORK / 'worker.py'
ORIGINAL = WORK / 'worker-before-cache-freshness.py'
SELF = WORK / 'repair-cache-freshness.py'
RECORD = WORK / 'cache-freshness-repair.json'
UNIT = 'nas-hba-temperature-freshness.service'
OLD_SHA = 'fbd591947d67f1e92897008d9ecc892685473007d9b501cc6751ea08afadf60f'
NEW_SHA = '55908c698d9368e53b348fc15dfb4164ae2c6e370a587ea7aa9a866b41b97124'
BEFORE = """        before_ns = time.time_ns()
        subprocess.run([str(COLLECTOR)], capture_output=True, timeout=20, check=True)
        temperature = cached_temperature(before_ns)"""
AFTER = """        previous_cache = CACHE.stat() if CACHE.exists() else None
        subprocess.run([str(COLLECTOR)], capture_output=True, timeout=20, check=True)
        temperature = cached_temperature(0)
        refreshed_cache = CACHE.stat()
        if previous_cache is not None and (previous_cache.st_dev, previous_cache.st_ino) == (refreshed_cache.st_dev, refreshed_cache.st_ino):
            raise RuntimeError('The existing HBA collector did not replace its cache.')"""


def say(value): print(value, flush=True)
def sha(data): return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition: raise RuntimeError(message)


def read_safe(path):
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'A symbolic HBA control path was retained.')
    require(path.is_file() and path.stat().st_size < 1024**2, 'A required bounded HBA worker is unavailable.')
    return path.read_bytes()


def candidate():
    current = read_safe(TARGET)
    if sha(current) == OLD_SHA: old = current
    elif sha(current) == NEW_SHA:
        old = read_safe(ORIGINAL)
        require(sha(old) == OLD_SHA, 'The retained original HBA worker differs.')
    else: raise RuntimeError('The installed HBA worker is not either exact reviewed version.')
    text = old.decode()
    require(text.count(BEFORE) == 1, 'The exact freshness patch target is not unique.')
    new = text.replace(BEFORE, AFTER).encode()
    require(sha(new) == NEW_SHA, 'The corrected HBA worker checksum differs.')
    compile(new, str(TARGET), 'exec')
    return old, new, current


def load_bridge(source):
    module = types.ModuleType('verified_hba_bridge')
    module.__file__ = str(TARGET)
    exec(compile(source, str(TARGET), 'exec'), module.__dict__)
    return module


def regression_tests(source):
    """No real collector, scheduler, root lock or migration controller runs."""
    bridge = load_bridge(source)
    cases = ('coarse-clock', 'first-cache', 'unchanged', 'same-inode',
             'invalid-number', 'symbolic-cache', 'collector-failure', 'cron-active')
    for case in cases:
        with tempfile.TemporaryDirectory(prefix='hba-freshness-test-') as temporary:
            folder = Path(temporary); cache = folder / 'cache'
            if case != 'first-cache': cache.write_text('41\n')
            calls = []
            def runner(args, **kwargs):
                require(args == [str(bridge.COLLECTOR)] and kwargs.get('check') is True, 'Unexpected regression command.')
                calls.append(args)
                if case == 'collector-failure': raise subprocess.CalledProcessError(1, args)
                if case == 'unchanged': return subprocess.CompletedProcess(args, 0)
                if case == 'same-inode':
                    cache.write_text('59\n'); return subprocess.CompletedProcess(args, 0)
                if case == 'symbolic-cache':
                    cache.unlink(); target = folder / 'other'; target.write_text('59\n'); cache.symlink_to(target)
                    return subprocess.CompletedProcess(args, 0)
                temporary_cache = folder / 'new-cache'
                temporary_cache.write_text('not numeric\n' if case == 'invalid-number' else '59\n')
                # Intentionally earlier than userspace time, like a coarser
                # inode timestamp. Atomic replacement must still be accepted.
                os.utime(temporary_cache, ns=(1_000_000_000, 1_000_000_000))
                temporary_cache.replace(cache)
                return subprocess.CompletedProcess(args, 0)
            expected_error = case in ('unchanged', 'same-inode', 'invalid-number', 'symbolic-cache', 'collector-failure')
            with patch.object(bridge, 'CACHE', cache), patch.object(bridge, 'verified'), \
                 patch.object(bridge, 'cron_state', return_value='active' if case == 'cron-active' else 'inactive'), \
                 patch.object(bridge.subprocess, 'run', side_effect=runner), \
                 patch.object(bridge.fcntl, 'flock'), patch('builtins.open', mock_open()), \
                 patch.object(bridge, 'say'):
                try: value = bridge.collect()
                except (RuntimeError, subprocess.CalledProcessError):
                    require(expected_error, 'A positive freshness regression failed: ' + case)
                else:
                    require(not expected_error, 'A stale/invalid freshness regression was accepted: ' + case)
                    require(value is None if case == 'cron-active' else value == 59, 'An unexpected regression temperature was accepted.')
            if case == 'cron-active': require(calls == [], 'The active-cron test executed a collector.')
    return len(cases)


def unit_state(name):
    result = subprocess.run(['systemctl', 'show', name, '--no-pager', '-p', 'LoadState', '-p', 'ActiveState', '-p', 'UnitFileState'],
                            text=True, capture_output=True, timeout=10)
    return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)


def verify_units(bridge, native):
    for path, body in bridge.unit_contents().items():
        require(native.read(path) == body, 'An existing HBA bridge unit differs; retained without replacement.')


def worker():
    old, new, current = candidate()
    count = regression_tests(new)
    say('HBA FRESHNESS REGRESSIONS PASSED: ' + str(count) + '; no real collector or scheduler used by tests.')
    bridge = load_bridge(current)
    args = bridge.controllers()
    inspected, accepted, resume, original_apps, review, boot, backup, native, startup = args
    with native.lock(BASE / '.run.lock'):
        require(unit_state(bridge.UNIT).get('ActiveState') not in ('active', 'activating', 'deactivating'), 'The original HBA handover is still running.')
        main, _rows = backup.preflight(native)
        progress = json.loads(native.read(bridge.STATE))
        require(progress.get('format') == bridge.FORMAT and progress.get('cutoverId') == main['proof']['cutoverId']
                and progress.get('phase') in ('prepared', 'complete'), 'The existing HBA progress record differs.')
        require(bridge.cron_state() == 'inactive', 'Cron ownership changed; the bridge repair was retained.')
        bridge.verified(bridge.COLLECTOR, bridge.COLLECTOR_SHA)
        bridge.verified(bridge.OMV_JOB, bridge.OMV_JOB_SHA)
        verify_units(bridge, native)
        if RECORD.exists():
            prior = json.loads(native.read(RECORD))
            require(prior.get('format') == 'sawdoctor-hba-cache-freshness-repair-v1'
                    and prior.get('cutoverId') == main['proof']['cutoverId']
                    and prior.get('oldSha256') == OLD_SHA and prior.get('newSha256') == NEW_SHA,
                    'An unrelated freshness repair record was retained.')
        status = unit_state(bridge.TIMER.name)
        require(status.get('LoadState') == 'loaded' and status.get('UnitFileState') == 'enabled'
                and status.get('ActiveState') == 'active', 'The existing enabled/active HBA timer ownership changed.')
        require(read_safe(TARGET) == current, 'The HBA worker changed during repair preparation.')
        native.run('systemctl', 'stop', bridge.TIMER.name)
        try:
            deadline = time.monotonic() + 40
            while unit_state(bridge.SERVICE.name).get('ActiveState') in ('active', 'activating', 'deactivating'):
                require(time.monotonic() < deadline, 'The current collector did not finish; it was not killed.')
                time.sleep(1)
            require(read_safe(TARGET) == current, 'The worker changed while the timer was paused.')
            if ORIGINAL.exists(): require(read_safe(ORIGINAL) == old, 'A different pre-fix worker was retained.')
            else: native.atomic(ORIGINAL, old, mode=0o700)
            if current != new: native.atomic(TARGET, new, reference=TARGET)
            require(sha(read_safe(TARGET)) == NEW_SHA, 'Corrected worker read-back differs.')
            native.atomic(RECORD, {'format': 'sawdoctor-hba-cache-freshness-repair-v1',
                'phase': 'patched', 'cutoverId': main['proof']['cutoverId'], 'oldSha256': OLD_SHA,
                'newSha256': NEW_SHA, 'regressionTestsPassed': count, 'collectorAndUnitsRetained': True})
        finally:
            verify_units(bridge, native)
            native.run('systemctl', 'start', bridge.TIMER.name)
        say('HBA FRESHNESS CHECK CORRECTED. Original worker retained; collector, OMV job and timer definitions unchanged.')
        fixed = load_bridge(new)
        # We already own the application lock. Call its worker directly;
        # it keeps its own backup-lock ordering and two-reading checks.
        fixed.worker(*fixed.controllers())
        final = json.loads(native.read(RECORD)); final['phase'] = 'complete'; native.atomic(RECORD, final)
        subprocess.run(['systemctl', 'reset-failed', bridge.UNIT], capture_output=True)
    say('HBA CACHE FRESHNESS REPAIR COMPLETE. Current temperature collection and two-reading handover verified.')


def main():
    os.umask(0o077); sys.dont_write_bytecode = True
    if sys.argv[1:] == ['--worker']:
        def interrupted(_signum, _frame): raise RuntimeError('Freshness repair interrupted; current state retained.')
        signal.signal(signal.SIGTERM, interrupted); signal.signal(signal.SIGINT, interrupted)
        worker(); return
    require(not sys.argv[1:] and globals().get('REPAIR_APPROVED_HBA_FRESHNESS') is True, 'The approved freshness repair flag is required.')
    source = globals().get('INSTALL_SOURCE')
    require(isinstance(source, str), 'The complete reviewed repair source is required.')
    _old, _new, current = candidate()
    bridge = load_bridge(current)
    inspected, accepted, resume, original_apps, review, boot, backup, native, startup = bridge.controllers()
    with native.lock(BASE / '.run.lock'):
        if unit_state(UNIT).get('ActiveState') in ('active', 'activating', 'deactivating'):
            say('The HBA freshness repair is already running.'); return
        if SELF.exists(): require(native.read(SELF) == source.encode(), 'A different repair helper was retained.')
        else: native.atomic(SELF, source.encode(), mode=0o700)
        subprocess.run(['systemctl', 'reset-failed', UNIT], capture_output=True)
        native.run('systemd-run', '--unit=' + UNIT, '--collect', '--property=Type=exec',
                   '--property=UMask=0077', '--property=RuntimeMaxSec=5min',
                   '--description=Correct only HBA cache freshness and resume existing verification',
                   '/usr/bin/python3', '-u', str(SELF), '--worker')
    say('HBA freshness repair started; regression tests run on this NAS before patching.')
    say('Progress: sudo journalctl -u ' + UNIT + ' -f -n 25 --no-pager -o cat')


if __name__ == '__main__':
    try: main()
    except Exception as error:
        say('STOP: ' + type(error).__name__ + '. ' + str(error) + ' Existing collector, job and application data retained.')
        raise SystemExit(1)
