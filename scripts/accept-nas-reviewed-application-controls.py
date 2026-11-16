#!/usr/bin/env python3
"""Accept the already-active original schedules without recreating an app.

Only the natively observed Speedtest PS1 dollar escaping may be normalized,
and only while its actual value and every non-schedule variable match the
retained same-image baseline. Keep the progressed resume worker unchanged.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

BASE = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6/compose/production-cutover')
WORK = BASE / 'application-control-handover'
RESUME = WORK / 'resume.py'
RESUME_SHA = '15018c30fb6bd05133ee79cd7e6636ad87bf109c92c1861716bb8fd17df81cae'
SELF = WORK / 'accept-current.py'
STATE = WORK / 'current-acceptance.json'
UNIT = 'nas-production-application-controls-accept.service'
FORMAT = 'sawdoctor-current-application-controls-acceptance-v1'
SPEEDTEST = 'speedtest-tracker-nas'
SCHEDULE = '30 4 * * *'


def say(value): print(value, flush=True)


def controllers():
    sys.dont_write_bytecode = True
    if any(path.is_symlink() for path in (RESUME, *RESUME.parents)) or hashlib.sha256(RESUME.read_bytes()).hexdigest() != RESUME_SHA:
        raise RuntimeError('The retained progressed application resume changed.')
    spec = importlib.util.spec_from_file_location('retained_application_resume', RESUME)
    resume = importlib.util.module_from_spec(spec); spec.loader.exec_module(resume)
    return (resume, *resume.controllers())


def validate_speedtest(resume, old, before, after, definition, image, owner):
    if before.get('Name') != '/' + SPEEDTEST or after.get('Name') != '/' + SPEEDTEST:
        raise RuntimeError('The prompt normalization is limited to the reviewed Speedtest container.')
    previous, actual = old.env(before), old.env(after)
    if previous.get('SPEEDTEST_SCHEDULE') != '' or actual.get('SPEEDTEST_SCHEDULE') != SCHEDULE:
        raise RuntimeError('The retained blank/original active Speedtest schedule differs.')
    intended = dict(previous, SPEEDTEST_SCHEDULE=SCHEDULE)
    if actual != intended:
        raise RuntimeError('Speedtest environment changed beyond its original schedule; values withheld.')
    expected = old.expected_environment(definition, image)
    mismatches = {key for key in actual.keys() | expected.keys() if key not in actual or key not in expected or actual[key] != expected[key]}
    if mismatches != {'PS1'} or not isinstance(expected.get('PS1'), str) or '$$' not in expected['PS1'] or expected['PS1'].replace('$$', '$') != actual['PS1']:
        raise RuntimeError('The environment difference is not the exact reviewed PS1 dollar escaping; values withheld.')
    verified = copy.deepcopy(definition)
    verified.setdefault('environment', {})['PS1'] = actual['PS1']
    # Only the in-memory comparison copy changes; the actual PS1 is proved
    # unchanged above, and no Compose/container environment is written.
    resume.validate_runtime(old, before, after, verified, image, owner)


def snapshot(boot, old, rows):
    return {'runtime': boot.runtime_signature(rows),
        'policies': {name: copy.deepcopy(row['HostConfig'].get('RestartPolicy')) for name, row in rows.items()},
        'networks': {name: old.networks(row) for name, row in rows.items()}}


def worker(resume, old, review, boot, backup, native, startup):
    with boot.boot_lock(native):
        if backup.unit(native, resume.UNIT).get('ActiveState') in ('active', 'activating', 'deactivating'):
            raise RuntimeError('The earlier resume is still running.')
        main, current = backup.preflight(native); _body, record = resume.check_record(old, native, main)
        original_snapshot = snapshot(boot, old, current)
        progress = json.loads(native.read(resume.STATE)); baseline = WORK / 'resume-speedtest-before.json'
        if (progress.get('format') != resume.FORMAT or progress.get('cutoverId') != record['cutoverId']
                or progress.get('phase') not in ('needs-review', 'complete')
                or progress.get('oldWorkerSha256') != resume.PREVIOUS_SHA
                or native.digest(baseline) != progress.get('speedtestBeforeSha256')):
            raise RuntimeError('The retained progressed resume/baseline identity differs.')
        before_speedtest = json.loads(native.read(baseline))
        if STATE.exists():
            accepted = json.loads(native.read(STATE))
            if (accepted.get('format') != FORMAT or accepted.get('cutoverId') != record['cutoverId']
                    or accepted.get('speedtestBeforeSha256') != progress['speedtestBeforeSha256']):
                raise RuntimeError('A different current-version acceptance record was retained.')

        houndarr = current['houndarr-nas']
        if houndarr['Image'] != record['images']['houndarr-nas']:
            raise RuntimeError('The completed Houndarr image changed.')
        database = review.current_database(houndarr, 'houndarr.db', native)
        with review.database(database) as db: old.check_houndarr(review, old.houndarr_rows(db), applied=True)
        say('HOUNDARR ACCEPTED: missing-only settings retained; no database write or restart.')

        saved = json.loads(native.read(backup.BACKUP / 'backups/sets' / resume.BASELINE_SET / 'containers.json'))
        before = [row for row in saved if row['Name'] == '/wizarr-nas']
        if (len(before) != 1 or before[0]['Image'] != record['images']['wizarr-nas']
                or any(old.env(before[0]).get(key) != 'true' for key in old.ENV['wizarr-nas'])):
            raise RuntimeError('The reviewed same-image Wizarr baseline differs.')
        wizarr_task = resume.task_for(native, startup, current, 'wizarr-nas', record['images']['wizarr-nas'])
        owner = resume.verified_current_owner(native, wizarr_task, record)
        wizarr = old.wait_http(native, 'wizarr-nas', 5690)
        dns_fields = resume.validate_runtime(old, before[0], wizarr, wizarr_task['definition'], wizarr_task['imageInfo'], owner)
        if any(old.env(wizarr).get(key, '').lower() not in ('', 'false', '0') for key in old.ENV['wizarr-nas']):
            raise RuntimeError('A Wizarr scheduler override remains enabled.')
        say('WIZARR ACCEPTED: current scheduler/runtime/bindings verified; no restart.')

        task = resume.task_for(native, startup, current, SPEEDTEST, record['images'][SPEEDTEST])
        owner = resume.verified_current_owner(native, task, record)
        if task['definition'].get('environment', {}).get('SPEEDTEST_SCHEDULE') != SCHEDULE:
            raise RuntimeError('The checksum-verified original Speedtest schedule differs.')
        speedtest = old.wait_http(native, SPEEDTEST, 8765)
        validate_speedtest(resume, old, before_speedtest, speedtest, task['definition'], task['imageInfo'], owner)
        say('SPEEDTEST ACCEPTED: original 04:30 schedule already active; same image, storage, networks and all other environment values retained.')
        say('PS1 comparison normalized only the proven Compose dollar escaping; actual prompt value unchanged and withheld.')

        _main, final = backup.preflight(native)
        if snapshot(boot, old, final) != original_snapshot:
            raise RuntimeError('An application runtime changed during acceptance; current data retained.')
        resume.verify_prepared_files(native, record)
        if not native.ACTIVE.exists(): raise RuntimeError('The separate cron/job hold disappeared.')
        record.update(phase='complete', completed=['houndarr-nas', 'wizarr-nas', SPEEDTEST],
            resume={'format': resume.FORMAT, 'baselineSet': resume.BASELINE_SET, 'onlyEmptyDnsNormalized': True,
                    'speedtestPS1DollarEscapingVerified': True})
        progress.update(phase='complete', speedtestImage=speedtest['Image'], onlySpeedtestRecreated=True,
            completionByCurrentAcceptance=True, speedtestPS1DollarEscapingVerified=True)
        accepted = {'format': FORMAT, 'phase': 'complete', 'cutoverId': record['cutoverId'], 'retainedResumeSha256': RESUME_SHA,
            'speedtestBeforeSha256': progress['speedtestBeforeSha256'], 'noApplicationRestartOrRecreation': True,
            'wizarrAcceptedDnsFields': dns_fields, 'speedtestPromptValueRetained': True}
        native.atomic(old.STATE, record); native.atomic(resume.STATE, progress); native.atomic(STATE, accepted)
        subprocess.run(['systemctl', 'reset-failed', old.UNIT, resume.UNIT], capture_output=True)
    say('REVIEWED NAS APPLICATION CONTROLS RESTORED. Houndarr, Wizarr and Speedtest accepted on their current running versions.')
    say('NO APPLICATION RESTART OR RECREATION. Only completion records updated; progressed workers, Compose, images, settings and databases retained.')
    say('Kuma, Tracearr, host cron/jobs and NPM renewal remain for their separate handovers.')
    say('Small completion record: ' + str(STATE))


def main():
    os.umask(0o077); resume, old, review, boot, backup, native, startup = controllers(); native.safe(WORK)
    if sys.argv[1:] == ['--worker']:
        def interrupted(_signal, _frame): raise RuntimeError('Acceptance interrupted; current applications retained.')
        signal.signal(signal.SIGTERM, interrupted); signal.signal(signal.SIGINT, interrupted)
        with native.lock(BASE / '.run.lock'): worker(resume, old, review, boot, backup, native, startup)
        return
    if sys.argv[1:] or globals().get('ACCEPT_APPROVED_APPLICATION_CONTROLS') is not True:
        raise RuntimeError('The approved current application acceptance flag is required.')
    source = globals().get('INSTALL_SOURCE')
    if not isinstance(source, str): raise RuntimeError('The complete reviewed acceptance source is required.')
    with native.lock(BASE / '.run.lock'):
        for unit in (UNIT, resume.UNIT):
            if backup.unit(native, unit).get('ActiveState') in ('active', 'activating', 'deactivating'):
                say('An application handover is already running; leave its current worker intact.'); return
        if SELF.exists() and native.read(SELF) != source.encode():
            raise RuntimeError('A different acceptance helper was retained.')
        if not SELF.exists(): native.atomic(SELF, source.encode(), mode=0o700)
        subprocess.run(['systemctl', 'reset-failed', UNIT], capture_output=True)
        native.run('systemd-run', '--unit=' + UNIT, '--collect', '--property=Type=exec', '--property=UMask=0077', '--property=RuntimeMaxSec=10min',
            '--description=Accept current NAS application controls without another restart', '/usr/bin/python3', '-u', str(SELF), '--worker')
    say('Current application acceptance started in systemd. Closing SSH is safe.')
    say('Progress: sudo journalctl -u ' + UNIT + ' -f -n 25 --no-pager -o cat')


if __name__ == '__main__':
    try: main()
    except Exception as error:
        say('STOP: ' + type(error).__name__ + '. ' + str(error) + ' Current applications and their completed steps retained.')
        raise SystemExit(1)
