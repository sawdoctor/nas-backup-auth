#!/usr/bin/env python3
"""Accept healthy Wizarr using empty-DNS normalization; resume Speedtest only.

Retain completed Houndarr and running Wizarr. No Compose/data import, image
pull, DNS setting change, source restart, Kuma/Tracearr/cron/NPM release.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import urllib.parse

BASE = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6/compose/production-cutover')
WORK = BASE / 'application-control-handover'
SELF = WORK / 'resume.py'
STATE = WORK / 'resume-state.json'
PREVIOUS = WORK / 'worker.py'
PREVIOUS_SHA = '63eed55a06c85c951455207918f4e95abd868f8acd540900e1db2a84ad5a8dfc'
BASELINE_SET = 'nas-20261115T091448Z'
UNIT = 'nas-production-application-controls-resume.service'
FORMAT = 'sawdoctor-reviewed-application-controls-resume-v1'
DNS = ('Dns', 'DnsOptions', 'DnsSearch')


def say(value): print(value, flush=True)
def sha(value): return hashlib.sha256(value).hexdigest()


def controllers():
    sys.dont_write_bytecode = True
    if any(path.is_symlink() for path in (PREVIOUS, *PREVIOUS.parents)) or sha(PREVIOUS.read_bytes()) != PREVIOUS_SHA:
        raise RuntimeError('The paused application worker changed.')
    spec = importlib.util.spec_from_file_location('accepted_application_controls', PREVIOUS)
    old = importlib.util.module_from_spec(spec); spec.loader.exec_module(old)
    return (old, *old.controllers())


def normalized_host_config(value):
    result = copy.deepcopy(value)
    for field in DNS:
        if field in result and result[field] is None: result[field] = []
    return result


def validate_runtime(old, before, after, definition, image):
    if before['Image'] != after['Image']: raise RuntimeError('A selected current image changed.')
    if old.mounts(before) != old.mounts(after): raise RuntimeError('A selected persistent/media binding changed.')
    if old.networks(before) != old.networks(after): raise RuntimeError('A selected network/alias binding changed.')
    a, b = normalized_host_config(before['HostConfig']), normalized_host_config(after['HostConfig'])
    if a != b:
        fields = sorted(key for key in a.keys() | b.keys() if a.get(key) != b.get(key))
        raise RuntimeError('Real HostConfig differences retained for review (field names only): ' + ', '.join(fields))
    if old.env(after) != old.expected_environment(definition, image):
        raise RuntimeError('A selected environment differs from the current Compose/image defaults; values withheld.')
    left, right = copy.deepcopy(before['Config']), copy.deepcopy(after['Config'])
    for value in (left, right):
        for field in ('Env', 'Image', 'Labels'): value.pop(field, None)
    if (not definition.get('hostname') and re.fullmatch(r'[a-f0-9]{12}', left.get('Hostname', ''))
            and right.get('Hostname') == after['Id'][:12]):
        left.pop('Hostname'); right.pop('Hostname')
    if left != right:
        fields = sorted(key for key in left.keys() | right.keys() if left.get(key) != right.get(key))
        raise RuntimeError('Unrelated Config differences retained for review: ' + ', '.join(fields))
    keys = ('com.docker.compose.project', 'com.docker.compose.service', 'com.docker.compose.project.config_files', 'com.docker.compose.project.working_dir')
    for key in keys:
        if (before['Config'].get('Labels') or {}).get(key) != (after['Config'].get('Labels') or {}).get(key):
            raise RuntimeError('A selected Compose owner changed.')
    return [field for field in DNS if before['HostConfig'].get(field) != after['HostConfig'].get(field)]


def verify_prepared_files(native, record):
    for item in record['files']:
        for key, checksum in (('before', 'beforeSha256'), ('prepared', 'afterSha256'), ('path', 'afterSha256')):
            path = Path(item[key])
            if not path.is_relative_to(native.APP) or native.digest(path) != item[checksum]:
                raise RuntimeError('A retained/current scheduler definition changed; no file overwritten.')


def task_for(native, startup, current, name, expected_image):
    row = current[name]
    if not row['State']['Running'] or row['Image'] != expected_image: raise RuntimeError('A selected running version differs from the reviewed operation.')
    context = startup.compose_context(row); model = startup.compose_model(native, context); service = startup.service_for(model, row)
    definition = model['services'][service]
    if startup.local_image(definition['image']) != expected_image: raise RuntimeError('A selected current Compose image tag moved; no pull or recreation requested.')
    image = json.loads(native.run('docker', 'image', 'inspect', '--', row['Image']))[0]
    return {'name': name, 'before': row, 'context': context, 'service': service, 'definition': definition, 'imageInfo': image}


def recreate_speedtest(old, native, startup, task):
    before, context = task['before'], task['context']
    if startup.local_image(task['definition']['image']) != before['Image']: raise RuntimeError('The current Speedtest image reference moved.')
    command = ['docker', 'compose', '-p', context['project'], '--project-directory', str(context['directory']), '--profile', '*']
    for path in context['files']: command += ['-f', str(path)]
    command += ['up', '-d', '--no-deps', '--pull', 'never', '--no-build', task['service']]
    native.run(*command, timeout=240)
    after = old.wait_http(native, 'speedtest-tracker-nas', 8765)
    validate_runtime(old, before, after, task['definition'], task['imageInfo'])
    return after


def kuma_inventory(review, native, current, report):
    try:
        path = review.current_database(current['uptime-kuma-nas'], 'kuma.db', native)
        with review.database(path) as db:
            monitors = review.rows(db, 'monitor', ('id', 'name', 'type', 'active'), ('url', 'hostname', 'port', 'docker_container', 'docker_host'))
        active = set(report['results']['uptime-kuma']['sourceActiveMonitorIds']); result = []
        for row in sorted(monitors, key=lambda row: row['id']):
            parsed = urllib.parse.urlsplit(row.get('url') or '')
            origin = parsed.scheme + '://' + (parsed.hostname or '') + (':' + str(parsed.port) if parsed.port else '') if parsed.scheme in ('http', 'https') else None
            host = row.get('hostname'); container = row.get('docker_container'); docker_host = row.get('docker_host')
            result.append({'id': row['id'], 'name': row['name'][:100], 'type': row['type'],
                'currentActive': review.flag(row['active']), 'sourceActive': row['id'] in active, 'urlOrigin': origin,
                'hostname': host if host is None or isinstance(host, str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,253}', host) else 'withheld',
                'port': row.get('port') if row.get('port') is None or type(row.get('port')) is int else 'withheld',
                'dockerContainer': container if container is None or isinstance(container, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', container) else 'withheld',
                'dockerHostId': docker_host if docker_host is None or type(docker_host) is int else 'withheld'})
        return result
    except Exception as error: return {'notVerified': type(error).__name__}


def check_record(old, native, main):
    body = native.read(old.STATE); record = json.loads(body)
    if record.get('format') != old.FORMAT or record.get('cutoverId') != main['proof']['cutoverId']:
        raise RuntimeError('The paused application handover identity differs.')
    if record.get('phase') == 'needs-review' and record.get('completed') == ['houndarr-nas']: pass
    elif record.get('phase') == 'complete' and record.get('resume', {}).get('format') == FORMAT: pass
    else: raise RuntimeError('The application handover is not the reviewed partial operation.')
    verify_prepared_files(native, record)
    return body, record


def worker(old, review, boot, backup, native, startup):
    with boot.boot_lock(native):
        main, current = backup.preflight(native); body, record = check_record(old, native, main)
        report = old.reviewed_report(native, main)
        houndarr = current['houndarr-nas']
        if houndarr['Image'] != record['images']['houndarr-nas']: raise RuntimeError('The completed Houndarr version changed; retained.')
        path = review.current_database(houndarr, 'houndarr.db', native)
        with review.database(path) as db: old.check_houndarr(review, old.houndarr_rows(db), applied=True)
        say('HOUNDARR ALREADY COMPLETE: missing-only settings verified read-only; no restart or database write.')
        saved = json.loads(native.read(backup.BACKUP / 'backups/sets' / BASELINE_SET / 'containers.json'))
        before = [row for row in saved if row['Name'] == '/wizarr-nas']
        if len(before) != 1 or before[0]['Image'] != record['images']['wizarr-nas']:
            raise RuntimeError('The reviewed same-image Wizarr baseline differs.')
        before = before[0]
        if any(old.env(before).get(field) != 'true' for field in old.ENV['wizarr-nas']): raise RuntimeError('The saved Wizarr staging baseline differs.')
        wizarr_task = task_for(native, startup, current, 'wizarr-nas', record['images']['wizarr-nas'])
        wizarr = old.wait_http(native, 'wizarr-nas', 5690)
        accepted_dns = validate_runtime(old, before, wizarr, wizarr_task['definition'], wizarr_task['imageInfo'])
        if any(old.env(wizarr).get(field, '').lower() not in ('', 'false', '0') for field in old.ENV['wizarr-nas']):
            raise RuntimeError('A Wizarr scheduler override remains enabled.')
        say('WIZARR ACCEPTED: healthy current image/settings/bindings; only empty DNS representations and generated hostname normalized. No Wizarr restart.')
        say('Wizarr empty-DNS fields accepted: ' + ', '.join(accepted_dns))
        speed = task_for(native, startup, current, 'speedtest-tracker-nas', record['images']['speedtest-tracker-nas'])
        if speed['definition'].get('environment', {}).get('SPEEDTEST_SCHEDULE') != '30 4 * * *':
            raise RuntimeError('The already prepared original Speedtest schedule differs.')
        baseline_path = WORK / 'resume-speedtest-before.json'
        if STATE.exists():
            state = json.loads(native.read(STATE))
            if state.get('format') != FORMAT or state.get('cutoverId') != record['cutoverId'] or native.digest(baseline_path) != state['speedtestBeforeSha256']:
                raise RuntimeError('An existing resume/baseline identity differs.')
            speed['before'] = json.loads(native.read(baseline_path))
        else:
            if record['phase'] != 'needs-review' or old.env(speed['before']).get('SPEEDTEST_SCHEDULE') != '':
                raise RuntimeError('The pending Speedtest state differs from the native review.')
            if baseline_path.exists(): raise RuntimeError('An unjournalled Speedtest resume baseline was retained.')
            native.atomic(WORK / 'resume-original-state.json', body); native.atomic(baseline_path, speed['before'])
            state = {'format': FORMAT, 'cutoverId': record['cutoverId'], 'phase': 'prepared',
                     'oldWorkerSha256': PREVIOUS_SHA, 'speedtestBeforeSha256': native.digest(baseline_path),
                     'wizarrAcceptedDnsFields': accepted_dns, 'wizarrBaselineSet': BASELINE_SET}
            native.atomic(STATE, state)
        untouched = boot.runtime_signature({name: row for name, row in current.items() if name != 'speedtest-tracker-nas'})
        try:
            state['phase'] = 'applying'; native.atomic(STATE, state)
            row = native.catalog()['speedtest-tracker-nas']; schedule = old.env(row).get('SPEEDTEST_SCHEDULE')
            if schedule == '': row = recreate_speedtest(old, native, startup, speed)
            elif schedule == '30 4 * * *':
                row = old.wait_http(native, 'speedtest-tracker-nas', 8765)
                validate_runtime(old, speed['before'], row, speed['definition'], speed['imageInfo'])
            else: raise RuntimeError('A current Speedtest schedule was changed separately; retained.')
            if old.env(row).get('SPEEDTEST_SCHEDULE') != '30 4 * * *': raise RuntimeError('The original Speedtest schedule was not retained.')
            say('SPEEDTEST RESTORED: 30 4 * * *; same image, storage, networks and remaining runtime settings verified.')
            _main, final = backup.preflight(native)
            if boot.runtime_signature({name: row for name, row in final.items() if name != 'speedtest-tracker-nas'}) != untouched:
                raise RuntimeError('An unrelated application runtime changed during this resume; retained for review.')
            verify_prepared_files(native, record)
            if not native.ACTIVE.exists(): raise RuntimeError('The remaining cron/job migration hold disappeared.')
            record.update(phase='complete', completed=['houndarr-nas', 'wizarr-nas', 'speedtest-tracker-nas'],
                resume={'format': FORMAT, 'baselineSet': BASELINE_SET, 'onlyEmptyDnsNormalized': True})
            native.atomic(old.STATE, record)
            state.update(phase='complete', speedtestImage=row['Image'], onlySpeedtestRecreated=True)
            native.atomic(STATE, state)
            subprocess.run(['systemctl', 'reset-failed', old.UNIT], capture_output=True)
        except BaseException:
            state['phase'] = 'needs-review'; native.atomic(STATE, state); raise
        inventory = kuma_inventory(review, native, final, report); native.atomic(WORK / 'kuma-current-monitor-inventory.json', inventory)
        say('KUMA CURRENT MONITOR INVENTORY (read-only; URL paths/query credentials withheld): ' + json.dumps(inventory, sort_keys=True))
        status = native.run('systemctl', 'show', 'nas-backup.service', '--no-pager', '-p', 'ActiveState', '-p', 'Result',
                            '-p', 'ConditionResult', '-p', 'ExecMainStartTimestamp', '-p', 'ExecMainExitTimestamp')
        say('BACKUP LAST RUN (read-only): ' + json.dumps(dict(line.split('=', 1) for line in status.splitlines() if '=' in line), sort_keys=True))
    say('REVIEWED NAS APPLICATION CONTROLS RESTORED. Completed Houndarr/Wizarr retained; pending Speedtest schedule active on its current image.')
    say('No Houndarr/Wizarr restart, image pull, application data restore, source/cron/job/NPM/Tracearr or Kuma control change.')
    say('Small resume record: ' + str(STATE))


def main():
    os.umask(0o077); old, review, boot, backup, native, startup = controllers(); native.safe(WORK)
    if sys.argv[1:] == ['--worker']:
        def interrupted(_signal, _frame): raise RuntimeError('Application resume interrupted; current images/data retained for review.')
        signal.signal(signal.SIGTERM, interrupted); signal.signal(signal.SIGINT, interrupted)
        with native.lock(BASE / '.run.lock'): worker(old, review, boot, backup, native, startup)
        return
    if sys.argv[1:] or globals().get('RESUME_APPROVED_APPLICATION_CONTROLS') is not True:
        raise RuntimeError('The approved application resume flag is required.')
    source = globals().get('INSTALL_SOURCE')
    if not isinstance(source, str): raise RuntimeError('The complete reviewed resume source is required.')
    with native.lock(BASE / '.run.lock'):
        if backup.unit(native, UNIT).get('ActiveState') in ('active', 'activating', 'deactivating'):
            say('Reviewed application resume is already running.'); return
        if SELF.exists() and native.read(SELF) != source.encode(): raise RuntimeError('A different resume worker was retained.')
        if not SELF.exists(): native.atomic(SELF, source.encode(), mode=0o700)
        subprocess.run(['systemctl', 'reset-failed', UNIT], capture_output=True)
        native.run('systemd-run', '--unit=' + UNIT, '--collect', '--property=Type=exec', '--property=UMask=0077', '--property=RuntimeMaxSec=20min',
                   '--description=Accept verified current Wizarr and activate only pending Speedtest schedule', '/usr/bin/python3', '-u', str(SELF), '--worker')
    say('Reviewed application resume started in systemd. Closing SSH is safe.')
    say('Progress: sudo journalctl -u ' + UNIT + ' -f -n 35 --no-pager -o cat')


if __name__ == '__main__':
    try: main()
    except Exception as error:
        say('STOP: ' + type(error).__name__ + '. ' + str(error) + ' Current application data/images and completed steps retained.')
        raise SystemExit(1)
