#!/usr/bin/env python3
"""Read the paused Speedtest comparison; never recreate or accept an app."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import urllib.error
import urllib.request

RESUME = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6/compose/production-cutover/application-control-handover/resume.py')
RESUME_SHA = '15018c30fb6bd05133ee79cd7e6636ad87bf109c92c1861716bb8fd17df81cae'
NAME = 'speedtest-tracker-nas'
SCHEDULE = '30 4 * * *'


def differences(actual, expected):
    return {'missingNames': sorted(expected.keys() - actual.keys()),
            'additionalNames': sorted(actual.keys() - expected.keys()),
            'differentNames': sorted(key for key in actual.keys() & expected.keys() if actual[key] != expected[key])}


def environment_report(actual, expected, before):
    intended = dict(before, SPEEDTEST_SCHEDULE=SCHEDULE)
    detail = []
    for key in sorted(actual.keys() | expected.keys()):
        if key in actual and key in expected and actual[key] == expected[key]: continue
        detail.append({'name': key, 'presentInCurrent': key in actual, 'presentInRenderedCompose': key in expected,
            'sameAsSavedBefore': key in actual and key in before and actual[key] == before[key],
            'renderedDollarEscapesOnly': key in actual and key in expected and isinstance(expected[key], str)
                and '$$' in expected[key] and expected[key].replace('$$', '$') == actual[key]})
    return {'currentVsRenderedCompose': differences(actual, expected),
            'currentVsSavedBeforePlusOriginalSchedule': differences(actual, intended),
            'onlyOriginalScheduleChanged': actual == intended, 'mismatches': detail}


def http_status():
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs): return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open('http://192.168.0.220:8765/', timeout=5) as response: return response.code
    except urllib.error.HTTPError as error: return error.code
    except OSError: return 'unavailable'


def inspect(resume, old, native, startup):
    record = json.loads(native.read(old.STATE)); state = json.loads(native.read(resume.STATE))
    if record.get('format') != old.FORMAT or state.get('format') != resume.FORMAT or state.get('cutoverId') != record.get('cutoverId'):
        raise RuntimeError('The paused application/resume identities differ.')
    baseline = resume.WORK / 'resume-speedtest-before.json'
    if native.digest(baseline) != state.get('speedtestBeforeSha256'):
        raise RuntimeError('The retained pre-resume Speedtest baseline changed.')
    before = json.loads(native.read(baseline)); current = native.catalog()
    row = current[NAME]; task = resume.task_for(native, startup, current, NAME, record['images'][NAME])
    resume.verify_prepared_files(native, record)
    owner = resume.verified_current_owner(native, task, record)
    actual = old.env(row); expected = old.expected_environment(task['definition'], task['imageInfo'])
    schedule = actual.get('SPEEDTEST_SCHEDULE')
    summary = {'originalPhase': record.get('phase'), 'originalCompleted': record.get('completed'), 'resumePhase': state.get('phase'),
        'running': row['State']['Running'], 'health': row['State'].get('Health', {}).get('Status', 'none'),
        'http': http_status(), 'currentSchedule': schedule if schedule in ('', SCHEDULE) else 'withheld',
        'sameContainerAsSavedBefore': row['Id'] == before['Id'], 'sameImageAsSavedBefore': row['Image'] == before['Image'],
        'composeImageMatchesRuntime': startup.local_image(task['definition']['image']) == row['Image'],
        'preparedScheduleIsOriginal': task['definition'].get('environment', {}).get('SPEEDTEST_SCHEDULE') == SCHEDULE,
        'sameMounts': old.mounts(before) == old.mounts(row), 'sameNetworks': old.networks(before) == old.networks(row),
        'hostConfigDifferentFieldNames': sorted(key for key in before['HostConfig'].keys() | row['HostConfig'].keys()
            if resume.normalized_host_config(before['HostConfig']).get(key) != resume.normalized_host_config(row['HostConfig']).get(key)),
        'currentOwnerMatchesRecordedDefinition': all((row['Config'].get('Labels') or {}).get(key) == value for key, value in owner.items())}
    left, right = copy.deepcopy(before['Config']), copy.deepcopy(row['Config'])
    for value in (left, right):
        for field in ('Env', 'Image', 'Labels'): value.pop(field, None)
    summary['otherConfigDifferentFieldNames'] = sorted(key for key in left.keys() | right.keys() if left.get(key) != right.get(key))
    return summary, environment_report(actual, expected, old.env(before))


def main():
    sys.dont_write_bytecode = True
    if any(path.is_symlink() for path in (RESUME, *RESUME.parents)) or hashlib.sha256(RESUME.read_bytes()).hexdigest() != RESUME_SHA:
        raise RuntimeError('The installed corrected resume source changed.')
    spec = importlib.util.spec_from_file_location('paused_application_resume', RESUME)
    resume = importlib.util.module_from_spec(spec); spec.loader.exec_module(resume)
    old, _review, _boot, _backup, native, startup = resume.controllers()
    status = native.run('systemctl', 'show', resume.UNIT, '--no-pager', '-p', 'ActiveState').strip()
    if status in ('ActiveState=active', 'ActiveState=activating', 'ActiveState=deactivating'):
        raise RuntimeError('The application resume is still running; let it finish first.')
    summary, environment = inspect(resume, old, native, startup)
    print('SPEEDTEST CURRENT/BINDINGS:', json.dumps(summary, sort_keys=True), flush=True)
    print('SPEEDTEST ENVIRONMENT DIFF (names/booleans only; values withheld):', json.dumps(environment, sort_keys=True), flush=True)
    print('READ-ONLY SPEEDTEST DIFF COMPLETE. No service, image, container, setting, journal or database changed.', flush=True)


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print('STOP:', type(error).__name__, 'Speedtest comparison unavailable; current services and data retained.', flush=True)
        raise SystemExit(1)
