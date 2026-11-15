#!/usr/bin/env python3
"""Explain the paused Wizarr runtime check without changing any application."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request

BASE = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6/compose/production-cutover')
WORKER = BASE / 'application-control-handover/worker.py'
WORKER_SHA = '63eed55a06c85c951455207918f4e95abd868f8acd540900e1db2a84ad5a8dfc'


def safe_host_diff(before, after):
    result = {}
    safe_strings = {'CgroupnsMode', 'IpcMode', 'NetworkMode', 'PidMode', 'UTSMode', 'UsernsMode', 'Runtime', 'CpusetCpus', 'CpusetMems'}
    for key in sorted(before.keys() | after.keys()):
        a, b = before.get(key), after.get(key)
        if a == b: continue
        if key in ('Binds', 'Mounts'):
            result[key] = {'beforeCount': len(a or []), 'currentCount': len(b or [])}
        elif all(value is None or type(value) in (bool, int, float) for value in (a, b)) or key in safe_strings or key in ('ConsoleSize', 'RestartPolicy'):
            result[key] = {'before': a, 'current': b}
        elif key == 'LogConfig':
            result[key] = {'beforeDriver': (a or {}).get('Type'), 'currentDriver': (b or {}).get('Type'),
                           'beforeOptionNames': sorted((a or {}).get('Config') or {}), 'currentOptionNames': sorted((b or {}).get('Config') or {})}
            for field in ('max-size', 'max-file', 'mode', 'compress'):
                values = [(row or {}).get('Config', {}).get(field) for row in (a, b)]
                if values[0] != values[1] and all(value is None or isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9.]{0,40}', value) for value in values):
                    result[key][field] = {'before': values[0], 'current': values[1]}
        else: result[key] = {'different': True, 'valuesWithheld': True}
    return result


def env_diff(actual, expected):
    return {'missingNames': sorted(expected.keys() - actual.keys()), 'additionalNames': sorted(actual.keys() - expected.keys()),
            'differentNames': sorted(key for key in actual.keys() & expected.keys() if actual[key] != expected[key])}


def scheduler_values(row, restoration):
    result = {}
    for key in ('FLASK_SKIP_SCHEDULER', 'WIZARR_DISABLE_SCHEDULER', 'SPEEDTEST_SCHEDULE'):
        value = restoration.env(row).get(key)
        if value is None: result[key] = 'not set'
        elif value.lower() in ('', 'true', 'false', '0', '1') or key == 'SPEEDTEST_SCHEDULE' and value == '30 4 * * *': result[key] = value
        else: result[key] = 'value withheld'
    return result


def http_status():
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs): return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open('http://192.168.0.220:5690/', timeout=5) as response: return response.code
    except urllib.error.HTTPError as error: return error.code
    except OSError: return 'unavailable'


def main():
    sys.dont_write_bytecode = True
    if any(path.is_symlink() for path in (WORKER, *WORKER.parents)) or hashlib.sha256(WORKER.read_bytes()).hexdigest() != WORKER_SHA:
        raise RuntimeError('The paused application-control worker changed.')
    spec = importlib.util.spec_from_file_location('paused_application_controls', WORKER)
    restoration = importlib.util.module_from_spec(spec); spec.loader.exec_module(restoration)
    review, boot, backup, native, startup = restoration.controllers()
    state = json.loads(native.read(restoration.STATE)); current = native.catalog(); row = current['wizarr-nas']
    print('PAUSED OPERATION:', json.dumps({'phase': state.get('phase'), 'completed': state.get('completed')}, sort_keys=True), flush=True)
    if state.get('format') != restoration.FORMAT or state.get('phase') != 'needs-review':
        raise RuntimeError('The expected paused application-control record is unavailable.')
    context = startup.compose_context(row); model = startup.compose_model(native, context); service = startup.service_for(model, row)
    definition = model['services'][service]
    image = json.loads(native.run('docker', 'image', 'inspect', '--', row['Image']))[0]
    print('CURRENT WIZARR:', json.dumps({'running': row['State']['Running'], 'health': row['State'].get('Health', {}).get('Status', 'none'),
        'http': http_status(), 'imageMatchesOperation': row['Image'] == state['images']['wizarr-nas'],
        'composeImageMatchesRuntime': startup.local_image(definition['image']) == row['Image'],
        'schedulerEnvironment': scheduler_values(row, restoration),
        'environmentVsCurrentCompose': env_diff(restoration.env(row), restoration.expected_environment(definition, image))}, sort_keys=True), flush=True)
    accepted = json.loads(native.read(backup.RECORD)); name = accepted.get('backupSet', '')
    if not re.fullmatch(r'nas-\d{8}T\d{6}Z', name): raise RuntimeError('The accepted backup set name differs.')
    saved = json.loads(native.read(backup.BACKUP / 'backups/sets' / name / 'containers.json'))
    matches = [item for item in saved if item['Name'] == '/wizarr-nas']
    if len(matches) != 1: raise RuntimeError('The original backup Wizarr record is unavailable.')
    before = matches[0]; same_image = before['Image'] == state['images']['wizarr-nas']
    print('SAVED BASELINE:', json.dumps({'backupSet': name, 'imageMatchesOperation': same_image,
        'oldSchedulerEnvironment': scheduler_values(before, restoration)}, sort_keys=True), flush=True)
    if same_image:
        print('WIZARR BINDINGS:', json.dumps({'sameNormalizedMounts': restoration.mounts(before) == restoration.mounts(row),
            'sameNormalizedNetworks': restoration.networks(before) == restoration.networks(row),
            'beforeNetworks': restoration.networks(before), 'currentNetworks': restoration.networks(row)}, sort_keys=True), flush=True)
        print('WIZARR HOSTCONFIG DIFFERENCES:', json.dumps(safe_host_diff(before['HostConfig'], row['HostConfig']), sort_keys=True), flush=True)
        left, right = copy.deepcopy(before['Config']), copy.deepcopy(row['Config'])
        for value in (left, right):
            for field in ('Env', 'Image', 'Labels'): value.pop(field, None)
        print('OTHER CONFIG DIFFERENT FIELD NAMES:', json.dumps(sorted(key for key in left.keys() | right.keys() if left.get(key) != right.get(key))), flush=True)
    else:
        print('No same-image saved runtime baseline; no difference was waived.', flush=True)
    print('SPEEDTEST CURRENT:', json.dumps({'running': current['speedtest-tracker-nas']['State']['Running'],
        'imageMatchesOperation': current['speedtest-tracker-nas']['Image'] == state['images']['speedtest-tracker-nas'],
        'schedulerEnvironment': scheduler_values(current['speedtest-tracker-nas'], restoration)}, sort_keys=True), flush=True)
    print('READ-ONLY WIZARR DIFF COMPLETE. No service, setting, image, container or database changed.', flush=True)


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print('STOP:', type(error).__name__, str(error), flush=True); raise SystemExit(1)
