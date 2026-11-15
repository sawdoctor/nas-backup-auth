#!/usr/bin/env python3
"""Restore the three natively reviewed NAS application controls only.

Houndarr: missing-only searches; Wizarr: remove staging scheduler overrides;
Speedtest: original 04:30 schedule. Retain current images and databases.
Kuma is inspected, never enabled here. No source/cron/NPM/Tracearr change.
"""
import contextlib
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import yaml

APP = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
BASE = APP / 'compose/production-cutover'
WORK = BASE / 'application-control-handover'
SELF = WORK / 'worker.py'
STATE = WORK / 'state.json'
REVIEW = BASE / 'application-control-review/worker.py'
REVIEW_SHA = 'd0a996fb49fe97030a139f34865d468f4437d1763d481be328c46963f5b06189'
UNIT = 'nas-production-application-controls.service'
FORMAT = 'sawdoctor-reviewed-application-controls-v1'
NAMES = {'houndarr-nas', 'wizarr-nas', 'speedtest-tracker-nas'}
FLAGS = ('enabled', 'missing_enabled', 'cutoff_enabled', 'upgrade_enabled')
ENV = {'wizarr-nas': {'FLASK_SKIP_SCHEDULER': None, 'WIZARR_DISABLE_SCHEDULER': None},
       'speedtest-tracker-nas': {'SPEEDTEST_SCHEDULE': '30 4 * * *'}}


def say(value): print(value, flush=True)
def sha(value): return hashlib.sha256(value).hexdigest()
def env(row): return dict(item.split('=', 1) for item in row['Config'].get('Env', []) if '=' in item)


def controllers():
    sys.dont_write_bytecode = True
    if any(path.is_symlink() for path in (REVIEW, *REVIEW.parents)) or sha(REVIEW.read_bytes()) != REVIEW_SHA:
        raise RuntimeError('The reviewed original-control comparison changed.')
    spec = importlib.util.spec_from_file_location('restore_original_controls', REVIEW)
    review = importlib.util.module_from_spec(spec); spec.loader.exec_module(review)
    boot, backup, native = review.controllers()
    startup, _release, _backup, _native = boot.controllers()
    return review, boot, backup, native, startup


def reviewed_report(native, main):
    report = json.loads(native.read(BASE / 'application-control-review/report.json'))
    if report.get('format') != 'sawdoctor-original-application-controls-v1' or report.get('cutoverId') != main['proof']['cutoverId']:
        raise RuntimeError('The accepted original/current comparison is unavailable.')
    results = report['results']; instances = results['houndarr']['instances']
    expected = {1: 'radarr', 2: 'radarr4k', 3: 'sonarr'}
    if {row['id']: row.get('application') for row in instances} != expected:
        raise RuntimeError('The three original Houndarr instances differ.')
    for row in instances:
        if row.get('sameInstance') is not True or row['source'] != dict(zip(FLAGS, (True, True, False, False))):
            raise RuntimeError('Original Houndarr policy differs from the native review.')
    if results['wizarr'] != {'sourceEnvironment': {'FLASK_SKIP_SCHEDULER': 'not set', 'WIZARR_DISABLE_SCHEDULER': 'not set'},
            'currentEnvironment': {'FLASK_SKIP_SCHEDULER': 'true', 'WIZARR_DISABLE_SCHEDULER': 'true'},
            'sourceEnabledLdapIds': [], 'currentEnabledLdapIds': []}:
        raise RuntimeError('The native Wizarr scheduler/LDAP review differs.')
    if results['speedtest-tracker']['source'] != {'SPEEDTEST_SCHEDULE': '30 4 * * *'}:
        raise RuntimeError('The native original Speedtest schedule differs.')
    return report


def houndarr_rows(db):
    db.row_factory = sqlite3.Row
    return [dict(row) for row in db.execute('SELECT id,url,enabled,missing_enabled,cutoff_enabled,upgrade_enabled FROM instances ORDER BY id')]


def check_houndarr(review, records, applied=False):
    if {row['id']: review.arr_identity(row['url']) for row in records} != {1: 'radarr', 2: 'radarr4k', 3: 'sonarr'}:
        raise RuntimeError('Current Houndarr instance identities changed.')
    for row in records:
        values = {field: review.flag(row[field]) for field in FLAGS}
        if not values['enabled'] or values['cutoff_enabled'] or values['upgrade_enabled']:
            raise RuntimeError('A current Houndarr enable/search preference differs; retained.')
        if applied and not values['missing_enabled']:
            raise RuntimeError('A reviewed missing-search flag was not retained.')


def patch_environment(body, service, changes, startup):
    text = body.decode()
    if any(isinstance(event, yaml.AliasEvent) or getattr(event, 'anchor', None) is not None for event in yaml.parse(text)):
        raise RuntimeError('An anchored Compose document requires separate review.')
    tree = yaml.compose(text, Loader=yaml.SafeLoader)
    services = startup.mapping_value(tree, 'services')
    node = startup.mapping_value(startup.mapping_value(services, service), 'environment')
    before = yaml.safe_load(body); value = before['services'][service]['environment']
    if isinstance(value, dict):
        updated = dict(value)
        for key, new in changes.items():
            if new is None: updated.pop(key, None)
            else: updated[key] = new
    elif isinstance(value, list) and all(isinstance(item, str) for item in value):
        updated = [item for item in value if item.split('=', 1)[0] not in changes]
        updated += [key + '=' + new for key, new in changes.items() if new is not None]
    else: raise RuntimeError('A Compose environment is not an explicit map/list.')
    token = text[node.start_mark.index:node.end_mark.index]
    suffix = re.search(r'\s*$', token).group()
    replacement = json.dumps(updated, ensure_ascii=False) + suffix
    result = text[:node.start_mark.index] + replacement + text[node.end_mark.index:]
    expected = copy.deepcopy(before); expected['services'][service]['environment'] = updated
    if yaml.safe_load(result) != expected: raise RuntimeError('An environment edit changes unrelated Compose fields.')
    return result.encode()


def repository(reference): return reference.split('@', 1)[0].rsplit(':', 1)[0] if ':' in reference.rsplit('/', 1)[-1] else reference.split('@', 1)[0]


def image_reference(native, startup, row, original):
    info = json.loads(native.run('docker', 'image', 'inspect', '--', row['Image']))[0]
    candidates = [row['Config']['Image'], original['Config']['Image'], *(info.get('RepoTags') or [])]
    expected = repository(original['Config']['Image'])
    for value in dict.fromkeys(candidates):
        if not value.startswith('sha256:') and repository(value) == expected and startup.local_image(value) == row['Image']:
            return value, info
    raise RuntimeError('A current named image identity needs review; no application was recreated.')


def mounts(row):
    return sorted((item['Type'], item['Source'], item['Destination'], item.get('RW'), item.get('Propagation', '')) for item in row['Mounts'])


def networks(row):
    return {key: {'id': value['NetworkID'], 'aliases': sorted(alias for alias in value.get('Aliases') or []
            if alias not in (row['Id'], row['Id'][:12]))} for key, value in row['NetworkSettings']['Networks'].items()}


def expected_environment(definition, image):
    result = dict(item.split('=', 1) for item in image['Config'].get('Env') or [] if '=' in item)
    for key, value in definition.get('environment', {}).items():
        if value is None: result.pop(key, None)
        else: result[key] = str(value)
    return result


def prepare(native, startup, current, original):
    contexts = {}; models = {}; bodies = {}; tasks = []
    for name, changes in ENV.items():
        row = current[name]
        if not row['State']['Running'] or any(item['Type'] != 'bind' for item in row['Mounts']):
            raise RuntimeError('A selected scheduler application is stopped or has an anonymous/named volume requiring review.')
        before_env = env(row)
        if name == 'wizarr-nas' and any(before_env.get(key, '').lower() != 'true' for key in changes):
            raise RuntimeError('A current Wizarr scheduler override changed; retained.')
        if name == 'speedtest-tracker-nas' and before_env.get('SPEEDTEST_SCHEDULE') != '':
            raise RuntimeError('The current Speedtest schedule changed; retained.')
        context = startup.compose_context(row); key = (context['project'], context['files'], context['directory'])
        if key not in contexts:
            contexts[key] = context; models[key] = startup.compose_model(native, context)
        model = models[key]; service = startup.service_for(model, row)
        if len(context['files']) != 1: raise RuntimeError('A layered scheduler environment requires separate review.')
        path = context['files'][0]
        if path not in bodies: bodies[path] = native.read(path, 4 * 1024**2)
        ref, image = image_reference(native, startup, row, original[name.removesuffix('-nas')])
        if model['services'][service].get('image') != ref:
            old_raw = yaml.safe_load(bodies[path])['services'][service]['image']
            bodies[path] = startup.patch_images(bodies[path], {service: (old_raw, ref)})
        bodies[path] = patch_environment(bodies[path], service, changes, startup)
        model['services'][service]['image'] = ref
        for field, value in changes.items():
            if value is None: model['services'][service]['environment'].pop(field, None)
            else: model['services'][service]['environment'][field] = value
        if name == 'wizarr-nas' and any(expected_environment(model['services'][service], image).get(field, '').lower() not in ('', 'false', '0') for field in changes):
            raise RuntimeError('The current Wizarr image has an unexpected scheduler-disable default.')
        tasks.append({'name': name, 'context': context, 'service': service, 'before': row, 'imageInfo': image,
                      'definition': copy.deepcopy(model['services'][service])})
    files = []; replacements = {}
    for path, body in bodies.items():
        identifier = sha(str(path).encode()); before = WORK / ('before-' + identifier + '.yaml'); candidate = WORK / ('prepared-' + identifier + '.yaml')
        if before.exists() or candidate.exists(): raise RuntimeError('A prior scheduler preparation requires review; copies retained.')
        original_body = native.read(path); native.atomic(before, original_body); native.atomic(candidate, body)
        files.append({'path': str(path), 'before': str(before), 'prepared': str(candidate), 'beforeSha256': sha(original_body), 'afterSha256': sha(body)})
        replacements[path] = candidate
    for key, context in contexts.items():
        if startup.compose_model(native, context, replacements) != models[key]:
            raise RuntimeError('The proposed scheduler changes alter another merged Compose field.')
    return files, tasks


def wait_http(native, name, port):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs): return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    deadline = time.monotonic() + 150
    while True:
        row = native.catalog().get(name)
        if row and row['State']['Running'] and row['State'].get('Health', {}).get('Status') not in ('starting', 'unhealthy'):
            try:
                with opener.open('http://192.168.0.220:' + str(port) + '/', timeout=4) as response:
                    if response.code < 400: return row
            except urllib.error.HTTPError as error:
                if error.code in (301, 302, 303, 307, 308, 401, 403): return row
            except OSError: pass
        if time.monotonic() >= deadline: raise RuntimeError('A selected application did not recover HTTP readiness: ' + name)
        time.sleep(2)


def restore_houndarr(review, native, row, database):
    native.run('docker', 'stop', '--time', '30', row['Id'], timeout=60)
    try:
        with contextlib.closing(sqlite3.connect(database.as_uri() + '?mode=rw', uri=True, timeout=5)) as db:
            check_houndarr(review, houndarr_rows(db))
            backup_path = WORK / 'houndarr-before.sqlite'
            if backup_path.exists(): raise RuntimeError('A prior Houndarr rollback database was retained.')
            with contextlib.closing(sqlite3.connect(backup_path)) as saved:
                db.backup(saved)
                if saved.execute('PRAGMA quick_check').fetchone()[0] != 'ok': raise RuntimeError('The Houndarr safety copy failed integrity checking.')
            db.execute('BEGIN IMMEDIATE')
            try:
                db.execute('UPDATE instances SET missing_enabled=1 WHERE id IN (1,2,3) AND missing_enabled=0')
                check_houndarr(review, houndarr_rows(db), applied=True)
                if db.total_changes > 3: raise RuntimeError('The Houndarr mode update changed unexpected rows/triggers.')
                db.commit()
            except BaseException: db.rollback(); raise
    finally:
        native.run('docker', 'start', row['Id'], timeout=90)
    current = wait_http(native, 'houndarr-nas', 8877)
    if current['Id'] != row['Id'] or current['Image'] != row['Image'] or current['Config'] != row['Config'] or mounts(current) != mounts(row):
        raise RuntimeError('Houndarr runtime changed unexpectedly; current data retained.')
    with review.database(database) as db: check_houndarr(review, houndarr_rows(db), applied=True)
    say('HOUNDARR RESTORED: missing-only searches on Radarr, Radarr4K and Sonarr; instance enables, cutoff/upgrade choices and encrypted credentials retained.')


def recreate(native, startup, task):
    name, before, context = task['name'], task['before'], task['context']
    reference = task['definition']['image']
    if startup.local_image(reference) != before['Image']: raise RuntimeError('A selected image tag moved before recreation; versions retained.')
    command = ['docker', 'compose', '-p', context['project'], '--project-directory', str(context['directory']), '--profile', '*']
    for path in context['files']: command += ['-f', str(path)]
    command += ['up', '-d', '--no-deps', '--pull', 'never', '--no-build', task['service']]
    native.run(*command, timeout=240)
    after = wait_http(native, name, 5690 if name == 'wizarr-nas' else 8765)
    if (after['Image'] != before['Image'] or mounts(after) != mounts(before) or networks(after) != networks(before)
            or after['HostConfig'] != before['HostConfig'] or env(after) != expected_environment(task['definition'], task['imageInfo'])):
        raise RuntimeError('A selected scheduler runtime differs beyond the reviewed environment; current files/data retained: ' + name)
    left, right = copy.deepcopy(before['Config']), copy.deepcopy(after['Config'])
    for value in (left, right):
        for field in ('Env', 'Image', 'Labels'): value.pop(field, None)
    if not task['definition'].get('hostname') and re.fullmatch(r'[a-f0-9]{12}', left.get('Hostname', '')) and right.get('Hostname') == after['Id'][:12]:
        left.pop('Hostname'); right.pop('Hostname')
    if left != right: raise RuntimeError('An unrelated selected runtime setting changed: ' + name)
    say(('WIZARR SCHEDULER RESTORED' if name == 'wizarr-nas' else 'SPEEDTEST SCHEDULE RESTORED: 30 4 * * *')
        + '; current image, persistent mounts, networks and other settings verified.')


def kuma_details(review, native, main, report, current):
    try:
        raw = Path(main['raw']); proof = main['proof']
        if native.digest(raw / 'manifest.json') != proof['manifestSha256']: raise RuntimeError('Original manifest changed.')
        checks = review.source_checks(native, raw, native.helpers()['core'])
        with tempfile.TemporaryDirectory(prefix='.kuma-review-', dir=WORK) as temporary:
            original = review.frozen_databases(native, raw, proof, checks, Path(temporary))['uptime-kuma']
            live_path = review.current_database(current['uptime-kuma-nas'], 'kuma.db', native)
            with review.database(original) as old, review.database(live_path) as live:
                fields = ('id', 'name', 'type', 'active'); optional = ('url', 'hostname', 'port')
                source = {row['id']: row for row in review.rows(old, 'monitor', fields, optional)}
                target = {row['id']: row for row in review.rows(live, 'monitor', fields, optional)}
                result = []
                for identity in report['results']['uptime-kuma']['monitorIdentityMismatchIds']:
                    a, b = source.get(identity), target.get(identity)
                    def safe(row):
                        if row is None: return {'missing': True}
                        parsed = urllib.parse.urlsplit(row.get('url') or '')
                        origin = parsed.scheme + '://' + (parsed.hostname or '') + (':' + str(parsed.port) if parsed.port else '') if parsed.scheme in ('http', 'https') else None
                        host = row.get('hostname')
                        return {'type': row['type'], 'active': review.flag(row['active']), 'urlOrigin': origin,
                            'hostname': host if host is None or re.fullmatch(r'[A-Za-z0-9_.:-]{1,253}', host) else 'withheld', 'port': row.get('port')}
                    result.append({'id': identity, 'source': safe(a), 'current': safe(b),
                        'sameName': a is not None and b is not None and a['name'] == b['name'],
                        'sameUrlPath': a is not None and b is not None and urllib.parse.urlsplit(a.get('url') or '').path == urllib.parse.urlsplit(b.get('url') or '').path})
                return result
    except Exception as error: return {'notVerified': type(error).__name__}


def worker(review, boot, backup, native, startup):
    with boot.boot_lock(native):
        if STATE.exists(): raise RuntimeError('An existing application-control journal requires review; no step was blindly repeated.')
        main, current = backup.preflight(native); report = reviewed_report(native, main)
        if json.loads(native.read(boot.RECORD)).get('phase') != 'complete': raise RuntimeError('Accepted boot ownership is required.')
        for name in NAMES:
            if name not in current or not current[name]['State']['Running']: raise RuntimeError('A selected current application is not running.')
        database = review.current_database(current['houndarr-nas'], 'houndarr.db', native)
        with review.database(database) as db: check_houndarr(review, houndarr_rows(db))
        manifest = json.loads(native.read(Path(main['raw']) / 'manifest.json'))
        if native.digest(Path(main['raw']) / 'manifest.json') != main['proof']['manifestSha256']: raise RuntimeError('The original image provenance changed.')
        original = {row['Name'].lstrip('/'): row for row in manifest['containers']}
        details = kuma_details(review, native, main, report, current)
        say('KUMA MONITOR DIFFERENCES (no monitor/notification changed): ' + json.dumps(details, sort_keys=True))
        files, tasks = prepare(native, startup, current, original)
        state = {'format': FORMAT, 'cutoverId': main['proof']['cutoverId'], 'phase': 'prepared', 'files': files,
                 'images': {name: current[name]['Image'] for name in NAMES}, 'completed': [], 'kumaDifferences': details}
        native.atomic(STATE, state)
        untouched = boot.runtime_signature({name: row for name, row in current.items() if name not in NAMES})
        try:
            state['phase'] = 'applying'; native.atomic(STATE, state)
            for item in files:
                if sha(native.read(Path(item['path']))) != item['beforeSha256']: raise RuntimeError('A prepared Compose layer changed before application.')
            for item in files: native.atomic(Path(item['path']), native.read(Path(item['prepared'])), reference=Path(item['path']))
            restore_houndarr(review, native, current['houndarr-nas'], database)
            state['completed'].append('houndarr-nas'); native.atomic(STATE, state)
            for task in tasks:
                recreate(native, startup, task); state['completed'].append(task['name']); native.atomic(STATE, state)
            _main, final = backup.preflight(native)
            if boot.runtime_signature({name: row for name, row in final.items() if name not in NAMES}) != untouched:
                raise RuntimeError('An unrelated application runtime changed; retained for review.')
            if not native.ACTIVE.exists(): raise RuntimeError('The remaining migration job hold disappeared.')
            state['phase'] = 'complete'; native.atomic(STATE, state)
        except BaseException:
            state['phase'] = 'needs-review'; native.atomic(STATE, state); raise
    say('REVIEWED NAS APPLICATION CONTROLS RESTORED. Houndarr missing-only searches, Wizarr scheduler and original daily 04:30 Speedtest schedule.')
    say('Current image versions and persistent data retained. Only Houndarr restarted; only Wizarr/Speedtest recreated. Other application runtimes retained.')
    say('Kuma was not changed; monitor review remains. Tracearr, cron/host jobs, NPM renewal and source holds unchanged.')
    say('Small operation record: ' + str(STATE))


def main():
    os.umask(0o077); review, boot, backup, native, startup = controllers(); native.safe(WORK); WORK.mkdir(mode=0o700, exist_ok=True)
    if sys.argv[1:] == ['--worker']:
        def interrupted(_signal, _frame): raise RuntimeError('Application handover interrupted; current versions/data retained for review.')
        signal.signal(signal.SIGTERM, interrupted); signal.signal(signal.SIGINT, interrupted)
        with native.lock(BASE / '.run.lock'): worker(review, boot, backup, native, startup)
        return
    if sys.argv[1:] or globals().get('RESTORE_APPROVED_APPLICATION_CONTROLS') is not True:
        raise RuntimeError('The approved reviewed-application-controls flag is required.')
    source = globals().get('INSTALL_SOURCE')
    if not isinstance(source, str): raise RuntimeError('The complete reviewed worker source is required.')
    with native.lock(BASE / '.run.lock'):
        if backup.unit(native, UNIT).get('ActiveState') in ('active', 'activating', 'deactivating'):
            say('Reviewed application restoration is already running.'); return
        if SELF.exists() and native.read(SELF) != source.encode(): raise RuntimeError('A different application-control worker was retained.')
        if not SELF.exists(): native.atomic(SELF, source.encode(), mode=0o700)
        subprocess.run(['systemctl', 'reset-failed', UNIT], capture_output=True)
        native.run('systemd-run', '--unit=' + UNIT, '--collect', '--property=Type=exec', '--property=UMask=0077', '--property=RuntimeMaxSec=30min',
                   '--description=Restore reviewed Houndarr Wizarr and Speedtest controls on current NAS versions', '/usr/bin/python3', '-u', str(SELF), '--worker')
    say('Reviewed NAS application restoration started in systemd. Closing SSH is safe.')
    say('Progress: sudo journalctl -u ' + UNIT + ' -f -n 35 --no-pager -o cat')


if __name__ == '__main__':
    try: main()
    except Exception as error:
        say('STOP: ' + type(error).__name__ + '. Reviewed application restoration paused; any completed steps and current images/data are retained for targeted review. ' + str(error))
        raise SystemExit(1)
