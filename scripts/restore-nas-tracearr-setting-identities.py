#!/usr/bin/env python3
"""Restore reviewed Tracearr controls while retaining current NAS history."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import urllib.parse

BASE = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6/compose/production-cutover')
REVIEW = BASE / 'tracearr-control-review/worker-with-source-image.py'
REVIEW_SHA = '8dc851ab294ef9f976d61b7c4f509a6c2c22d5bea6c52ceb754a168d79f33670'
WORK = BASE / 'tracearr-control-handover'
ORIGINAL_WORKER = WORK / 'worker.py'
ORIGINAL_SHA = '82a86b14a6cbac1ec76e725645105ee6ce5e8844327e5a32f9d376afa9909812'
DEVICE_WORKER = WORK / 'worker-with-original-device-choices.py'
DEVICE_SHA = '39ea8651eaa4feafe42ff863b5bcff7b502c0d923e098fc8e336d731dc5065a7'
SELF = WORK / 'worker-with-setting-identities.py'
STATE = WORK / 'state.json'
UNIT = 'nas-production-tracearr-controls-schema.service'
FORMAT = 'sawdoctor-reviewed-tracearr-controls-v1'
APP = 'tracearr-nas'
DEFAULTS = {'pollerEnabled', 'imagePrecacheEnabled', 'pluginUpdateCheckEnabled', 'serverUpdateCheckEnabled'}
TABLES = ('settings', 'automations', 'destinations', 'notification_preferences')
SETTINGS = DEFAULTS | {'mobileEnabled', 'backupScheduleType', 'externalUrl'}
DEVICE_CHOICES = ('on_stream_started', 'on_stream_stopped', 'on_trust_score_changed')
PUSH_FIELDS = ('on_violation_detected', 'on_stream_started', 'on_stream_stopped', 'on_new_device',
               'on_trust_score_changed', 'on_server_down', 'on_server_up')
REQUEST_PROGRESS = {'version', 'sync_cursor', 'last_counts', 'last_sync_at', 'last_full_sync_at', 'last_sync_error', 'updated_at'}
SERVER_PROGRESS = {'version', 'latest_version', 'location_version', 'location_synced_version', 'historical_at', 'updated_at'}


def say(value):
    print(value, flush=True)


def require(value, message):
    if not value:
        raise RuntimeError(message)


def encoded(value):
    return json.dumps(value, sort_keys=True).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def literal(value):
    return "'" + value.replace("'", "''") + "'"


def json_sql(value):
    return literal(json.dumps(value, sort_keys=True)) + '::jsonb'


def do_block(body):
    body = body.rstrip() + ('' if body.rstrip().endswith(';') else ';')
    tag = '$trace_' + sha(body.encode())[:20] + '$'
    while tag in body:
        tag = tag[:-1] + '_$'
    return 'DO ' + tag + '\n' + body + '\n' + tag + ';\n'


def controllers():
    sys.dont_write_bytecode = True
    require(not any(p.is_symlink() for p in (REVIEW, *REVIEW.parents)) and sha(REVIEW.read_bytes()) == REVIEW_SHA,
            'The accepted Tracearr comparison helper differs.')
    spec = importlib.util.spec_from_file_location('accepted_tracearr_review', REVIEW)
    reviewer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reviewer)
    return reviewer, *reviewer.controllers()


def controls(data):
    result = {}
    for table in TABLES:
        key = 'name' if table == 'settings' else 'id'
        result[table] = {str(row[key]): copy.deepcopy(row) for row in data[table]}
        require(len(result[table]) == len(data[table]), 'A control identity is duplicated.')
    return result


def protected(data):
    return {table: {str(row['id']): {k: v for k, v in row.items() if k not in omitted}
                    for row in data[table]}
            for table, omitted in (('servers', SERVER_PROGRESS), ('request_services', REQUEST_PROGRESS))}


RUNTIME_JS = r"""const fs=require('fs');
const build=JSON.parse(fs.readFileSync('/app/.build-info.json','utf8'));
const text=fs.readFileSync('/app/apps/server/dist/services/settings.js','utf8');
const match=text.match(/const PUBLIC_DEFAULTS\s*=\s*\{([\s\S]*?)\n\};/);
const keys=['pollerEnabled','imagePrecacheEnabled','pluginUpdateCheckEnabled','serverUpdateCheckEnabled'];
const defaults=Object.fromEntries(keys.map(k=>[k,!!match && new RegExp('\\b'+k+'\\s*:\\s*true\\b').test(match[1])]));
const push=fs.readFileSync('/app/apps/server/dist/services/pushDelivery.js','utf8').replace(/\s/g,'');
console.log(JSON.stringify({version:build.version,commit:build.commit,defaults,
  sourceDefaultFallback:text.includes('ALL_DEFAULTS[key]'),
  allTrueDeviceGuard:push.includes('rows.every((row)=>PUSH_PREFERENCES.every((key)=>row[key]))')}));
"""


def check_runtime(evidence):
    require(str(evidence.get('version', '')).removeprefix('v') == '3.1.7'
            and evidence.get('sourceDefaultFallback') is True and evidence.get('allTrueDeviceGuard') is True
            and set(evidence.get('defaults', {})) == DEFAULTS and all(evidence['defaults'].values()),
            'The installed Tracearr version/default or device-migration behavior needs review before writes.')


def runtime_evidence():
    result = subprocess.run(['docker', 'exec', APP, 'node', '-e', RUNTIME_JS], capture_output=True, text=True, timeout=20)
    require(result.returncode == 0, 'Installed Tracearr runtime evidence needs review; no app/control changed.')
    evidence = json.loads(result.stdout)
    say('TRACEARR INSTALLED RUNTIME: ' + json.dumps(evidence, sort_keys=True))
    check_runtime(evidence)
    return evidence


def plan(original, live, sealed):
    require(all(original['schema'][t] == live['schema'][t] for t in TABLES),
            'A selected original/current control schema changed.')
    before = controls(live)
    after = copy.deepcopy(before)
    source = controls(original)
    for table, field, count in (('automations', 'is_active', 5), ('destinations', 'enabled', 2)):
        require(len(source[table]) == len(before[table]) == count and source[table].keys() == before[table].keys(),
                'A reviewed automation/destination identity changed.')
        for identity, current in before[table].items():
            prior = source[table][identity]
            require(prior[field] is True and current[field] is False
                    and {k: v for k, v in prior.items() if k != field} == {k: v for k, v in current.items() if k != field},
                    'A reviewed automation/destination differs beyond its held enable switch.')
            after[table][identity][field] = True
    require(original['newsletters'] == live['newsletters'] == [], 'Newsletter choices changed; preserved.')
    prefs = before['notification_preferences']
    original_prefs = source['notification_preferences']
    require(len(prefs) == len(original_prefs) == 2 and prefs.keys() == original_prefs.keys(),
            'Paired-device identities changed; no overwrite.')
    summary = []
    for identity, row in prefs.items():
        prior = original_prefs[identity]
        require(prior['push_enabled'] is True and row['push_enabled'] is False
                and prior['mobile_session_id'] == row['mobile_session_id'], 'A held device push switch or identity changed.')
        require(all(prior.get(k) is True and row.get(k) is False for k in DEVICE_CHOICES),
                'The three device switches differ from the exact original-on/current-off native evidence.')
        for field in DEVICE_CHOICES:
            after['notification_preferences'][identity][field] = prior[field]
        summary.append({'id': identity, 'originalChoicesRestored': {k: prior[k] for k in DEVICE_CHOICES}})
        after['notification_preferences'][identity]['push_enabled'] = True
    say('TRACEARR ORIGINAL DEVICE CHOICES VERIFIED: ' + json.dumps(summary, sort_keys=True))
    require(all(row.get(field) is True for row in after['notification_preferences'].values() for field in PUSH_FIELDS),
            'Other device mutes would change shared senders at startup; retained for targeted review before any change.')
    settings, source_settings = before['settings'], source['settings']
    require(set(settings) == SETTINGS, 'The reviewed current settings set changed.')
    for name in DEFAULTS:
        require(name not in source_settings and settings[name]['value'] is False,
                'An original-absent/default override changed separately; retained.')
        del after['settings'][name]
    for name, value, held in (('mobileEnabled', True, False), ('backupScheduleType', 'daily', 'disabled')):
        require(source_settings.get(name, {}).get('value') == value and settings[name]['value'] == held,
                'An original/current mobile or backup choice changed.')
        after['settings'][name]['value'] = value
    address = source_settings.get('externalUrl', {}).get('value')
    parsed = urllib.parse.urlsplit(address or '')
    require(parsed.scheme == 'https' and parsed.hostname == 'tracearr.sawdoctor.uk' and parsed.port is None
            and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment and parsed.path in ('', '/'),
            'The original external address needs private review.')
    require(settings['externalUrl']['value'] in ('http://192.168.0.220:7330', 'http://192.168.0.220:7330/'),
            'The current external address changed separately; retained.')
    after['settings']['externalUrl']['value'] = address
    require(len(live['servers']) == 1 and live['servers'][0]['type'] == 'plex'
            and live['servers'][0]['url'].rstrip('/') == 'http://192.168.0.220:32400', 'The working NAS Plex endpoint changed.')
    for table in ('servers', 'request_services'):
        require({r['id'] for r in live[table]} == {r['id'] for r in sealed[table]}, 'A current connection identity changed.')
    require(len(live['request_services']) == 1 and live['request_services'][0]['enabled'] is True,
            'The current enabled request service differs; retained.')
    validate_edits(before, after)
    return before, after


def validate_edits(before, after):
    require(set(before) == set(after) == set(TABLES), 'A control plan table changed.')
    require((before['settings'].keys() ^ after['settings'].keys()) <= DEFAULTS, 'An unrelated setting would be added/deleted.')
    for key in before['settings'].keys() | after['settings'].keys():
        for row in (before['settings'].get(key), after['settings'].get(key)):
            require(row is None or (set(row) == {'id', 'name', 'value'} and row['name'] == key
                    and type(row['id']) is int and row['id'] > 0), 'The setting identity schema needs review.')
        a, b = before['settings'].get(key), after['settings'].get(key)
        require(a is None or b is None or a['id'] == b['id'], 'An existing setting identity would change.')
        require(before['settings'].get(key) == after['settings'].get(key) or key in SETTINGS, 'An unrelated setting would change.')
    for table, field in (('automations', 'is_active'), ('destinations', 'enabled'), ('notification_preferences', 'push_enabled')):
        require(before[table].keys() == after[table].keys(), 'A control row identity would change.')
        for identity, a in before[table].items():
            b = after[table][identity]
            allowed = {field, *DEVICE_CHOICES} if table == 'notification_preferences' else {field}
            changed = {k for k in a if a[k] != b[k]}
            require(a.keys() == b.keys() and changed <= allowed and all(type(b[k]) is bool for k in allowed),
                    'An unrelated rule/notification field would change.')
            if table == 'notification_preferences':
                require(all(a[k] is not b[k] and type(a[k]) is bool for k in DEVICE_CHOICES),
                        'The three reviewed device flags must change together, including during rollback.')


def view_sql(schema):
    require(schema in ('public', 'pg_temp'), 'The SQL schema is outside the reviewed scope.')
    parts = []
    for table in TABLES:
        key = 'name' if table == 'settings' else 'id'
        where = ' WHERE name IN (' + ','.join(literal(k) for k in sorted(SETTINGS)) + ')' if table == 'settings' else ''
        parts += [literal(table), "(SELECT COALESCE(jsonb_object_agg(t." + key + "::text,to_jsonb(t)),'{}'::jsonb) FROM "
                  + schema + '."' + table + '" t' + where + ')']
    return 'jsonb_build_object(' + ','.join(parts) + ')'


def changes_sql(before, after, schema='public'):
    validate_edits(before, after)
    require(schema in ('public', 'pg_temp'), 'The SQL schema is outside the reviewed scope.')
    statements = []
    for name in sorted(before['settings'].keys() | after['settings'].keys()):
        a, b = before['settings'].get(name), after['settings'].get(name)
        if a == b:
            continue
        if b is None:
            statements.append('DELETE FROM ' + schema + '.settings WHERE name=' + literal(name) + ';')
        elif a is None:
            statements.append('INSERT INTO ' + schema + '.settings(id,name,value) OVERRIDING SYSTEM VALUE VALUES ('
                              + str(b['id']) + ',' + literal(name) + ',' + json_sql(b['value']) + ');')
        else:
            statements.append('UPDATE ' + schema + '.settings SET value=' + json_sql(b['value'])
                              + ' WHERE id=' + str(a['id']) + ' AND name=' + literal(name) + ';')
    for table, field in (('automations', 'is_active'), ('destinations', 'enabled'), ('notification_preferences', 'push_enabled')):
        fields = (field, *DEVICE_CHOICES) if table == 'notification_preferences' else (field,)
        for identity, row in before[table].items():
            edits = ['"' + k + '"=' + str(after[table][identity][k]).lower()
                     for k in fields if row[k] != after[table][identity][k]]
            if edits:
                statements.append('UPDATE ' + schema + '."' + table + '" SET ' + ','.join(edits)
                                  + ' WHERE id=' + literal(identity) + ';')
    return do_block('BEGIN\nIF (' + view_sql(schema) + ') IS DISTINCT FROM ' + json_sql(before)
            + " THEN RAISE EXCEPTION 'Reviewed control baseline changed'; END IF;\n" + '\n'.join(statements)
            + '\nIF (' + view_sql(schema) + ') IS DISTINCT FROM ' + json_sql(after)
            + " THEN RAISE EXCEPTION 'Control readback differs'; END IF;\nEND")


def execute(sql, native):
    command = ['docker', 'exec', '-i', 'tracearr-db-nas', 'sh', '-c',
               'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -X -q -t -A -v ON_ERROR_STOP=1']
    result = subprocess.run(command, input="SET standard_conforming_strings=on; SET timezone='UTC';\n" + sql,
                            capture_output=True, text=True, timeout=40)
    if result.returncode:
        native.atomic(WORK / 'private-sql-error.log', result.stderr.encode())
        raise RuntimeError('The control SQL failed; private diagnostics retained. Any uncommitted transaction is rolled back.')
    return result.stdout.strip()


def database_tests(before, after, native):
    sql = "BEGIN; SET LOCAL statement_timeout='20s';\n"
    for table in TABLES:
        sql += 'CREATE TEMP TABLE "' + table + '" (LIKE public."' + table + '" INCLUDING ALL) ON COMMIT DROP;\n'
        for row in before[table].values():
            override = ' OVERRIDING SYSTEM VALUE' if table == 'settings' else ''
            sql += 'INSERT INTO pg_temp."' + table + '"' + override + ' SELECT * FROM jsonb_populate_record(NULL::pg_temp."' + table + '",'
            sql += json_sql(row) + ');\n'
    sql += changes_sql(before, after, 'pg_temp') + changes_sql(after, before, 'pg_temp')
    sql += do_block("BEGIN\nBEGIN\nUPDATE pg_temp.notification_preferences SET push_enabled=true;\n"
            "RAISE EXCEPTION 'intentional test rollback';\nEXCEPTION WHEN raise_exception THEN\n"
            "IF SQLERRM <> 'intentional test rollback' THEN RAISE; END IF;\nEND;\nIF (" + view_sql('pg_temp')
            + ') IS DISTINCT FROM ' + json_sql(before) + " THEN RAISE EXCEPTION 'Temporary rollback failed'; END IF;\n"
            "END")
    sql += "ROLLBACK;\nSELECT 'TEMPORARY TRACEARR CONTROL TESTS PASSED';\n"
    require(execute(sql, native) == 'TEMPORARY TRACEARR CONTROL TESTS PASSED', 'The temporary PostgreSQL tests did not pass.')
    say('TRACEARR CONTROL DATABASE TESTS PASSED: temporary-table forward/reverse/readback and rollback. No persistent rows changed by tests.')


def apply(before, after, native):
    locks = ','.join('public."' + name + '"' for name in TABLES)
    execute("BEGIN; SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='15s';\nLOCK TABLE " + locks
            + ' IN SHARE ROW EXCLUSIVE MODE;\n' + changes_sql(before, after) + 'COMMIT;\n', native)


def same_runtime(old, before, after):
    return (before['Id'] == after['Id'] and before['Image'] == after['Image'] and before['Config'] == after['Config']
            and before['HostConfig'] == after['HostConfig'] and old.mounts(before) == old.mounts(after)
            and old.networks(before) == old.networks(after))


def startup_proof(native, row):
    deadline = time.monotonic() + 45
    while True:
        result = subprocess.run(['docker', 'logs', '--since', row['State']['StartedAt'], '--tail', '2000', row['Id']],
                                capture_output=True, text=True, timeout=15)
        text = result.stdout + result.stderr
        proof = {'poller': 'Starting session poller' in text, 'dailyBackup': 'Scheduled daily backup at cron:' in text}
        if result.returncode == 0 and all(proof.values()):
            return proof
        require(time.monotonic() < deadline, 'HTTP recovered but poller/daily scheduler startup evidence needs review.')
        time.sleep(3)


def worker(reviewer, kuma, inspected, accepted, resume, old, review, boot, backup, native, startup):
    with boot.boot_lock(native):
        main, rows = backup.preflight(native)
        cutover = main['proof']['cutoverId']
        require(backup.unit(native, reviewer.UNIT).get('ActiveState') not in ('active', 'activating', 'deactivating'),
                'The original/current comparison is still running.')
        report = json.loads(native.read(reviewer.WORK / 'report.json'))
        require(report.get('format') == reviewer.FORMAT and report.get('phase') == 'reviewed'
                and report.get('cutoverId') == cutover and report.get('temporaryPostgresRemoved') is True,
                'The accepted native Tracearr review differs.')
        original = json.loads(native.read(reviewer.WORK / 'original-controls.json'))
        saved = json.loads(native.read(reviewer.WORK / 'current-controls.json'))
        require(sha(encoded(original)) == report['originalSha256'] and sha(encoded(saved)) == report['currentSha256'],
                'A private original/current snapshot changed.')
        row = rows[APP]
        require(row['State']['Running'] and all(rows[n]['Image'] == image for n, image in report['currentImages'].items()),
                'A reviewed current Tracearr component version changed.')
        evidence = runtime_evidence()
        live = reviewer.read_controls(lambda sql: execute(sql, native))
        if STATE.exists():
            state = json.loads(native.read(STATE))
            require(state.get('format') == FORMAT and state.get('cutoverId') == cutover
                    and state.get('containerId') == row['Id'] and state.get('image') == row['Image'],
                    'An existing Tracearr restoration identity differs.')
            before = json.loads(native.read(WORK / 'before-controls.json'))
            after = json.loads(native.read(WORK / 'after-controls.json'))
            require(sha(encoded(before)) == state['beforeSha256'] and sha(encoded(after)) == state['afterSha256'],
                    'A retained Tracearr control plan changed.')
            require(controls(live) in (before, after), 'Current controls differ from both retained plans.')
        else:
            before, after = plan(original, live, saved)
            database_tests(before, after, native)
            native.atomic(WORK / 'before-controls.json', before)
            native.atomic(WORK / 'after-controls.json', after)
            state = {'format': FORMAT, 'phase': 'prepared', 'cutoverId': cutover, 'containerId': row['Id'], 'image': row['Image'],
                     'beforeSha256': sha(encoded(before)), 'afterSha256': sha(encoded(after)), 'version': evidence['version']}
            native.atomic(STATE, state)
        others = accepted.snapshot(boot, old, {n: r for n, r in rows.items() if n != APP})
        connections = protected(live)
        writing = controls(live) != after
        try:
            if writing:
                native.run('docker', 'stop', '--time', '30', row['Id'], timeout=90)
                try:
                    stopped = reviewer.read_controls(lambda sql: execute(sql, native))
                    require(controls(stopped) == before and protected(stopped) == connections, 'The live baseline changed before writing.')
                    apply(before, after, native)
                    state['phase'] = 'applied'
                    native.atomic(STATE, state)
                finally:
                    native.run('docker', 'start', row['Id'], timeout=90)
            running = old.wait_http(native, APP, 7330)
            require(same_runtime(old, row, running), 'The existing Tracearr runtime/bindings changed.')
            result = reviewer.read_controls(lambda sql: execute(sql, native))
            require(controls(result) == after and protected(result) == connections,
                    'A control or retained Plex/request/device choice changed at startup.')
            proof = startup_proof(native, running)
        except BaseException:
            state['phase'] = 'needs-review'
            native.atomic(STATE, state)
            if writing:
                native.run('docker', 'stop', '--time', '30', row['Id'], timeout=90)
                try:
                    actual = controls(reviewer.read_controls(lambda sql: execute(sql, native)))
                    require(actual in (before, after), 'Control rollback retained: current controls have a separate change.')
                    if actual == after:
                        apply(after, before, native)
                finally:
                    native.run('docker', 'start', row['Id'], timeout=90)
            raise
        require(accepted.snapshot(boot, old, {n: r for n, r in native.catalog().items() if n != APP}) == others,
                'An unrelated runtime changed during the controlled restoration; current data retained.')
        state.update(phase='complete', automationsEnabled=5, destinationsEnabled=2, mobilePushEnabled=2,
                     originalThreeDeviceChoicesRestored=True, defaultOverridesRemoved=sorted(DEFAULTS), startup=proof,
                     currentPlexAndRequestBindingsRetained=True)
        native.atomic(STATE, state)
    say('REVIEWED NAS TRACEARR CONTROLS RESTORED: original five automations, two destinations and two mobile push switches active.')
    say('Original daily backup and public address restored; four held overrides removed so verified defaults apply.')
    say('Three original device choices restored; all other preferences, NAS Plex/request connections, image and history retained.')
    say('Session poller and daily backup scheduler startup observed. Only the existing Tracearr app was stopped/started.')
    say('PostgreSQL, Redis, host cron/job holds, NPM renewal hold and source production freeze retained.')


def pending_owners(native):
    names = ('cron.service', 'nas-abs-user-provisioner.timer', 'nas-flora-queue-watch.timer',
             'nas-torbox-audiobook-archive.timer', 'nas-torbox-watch.timer',
             'nas-hba-temperature-bridge.timer', 'nas-backup.timer')
    result = subprocess.run(['systemctl', 'show', '--no-pager', *names, '-p', 'Id', '-p', 'ActiveState',
                             '-p', 'UnitFileState', '-p', 'ConditionResult', '-p', 'DropInPaths',
                             '-p', 'NextElapseUSecRealtime'], capture_output=True, text=True, timeout=20)
    if result.returncode:
        return {'available': False}
    units = [dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
             for block in result.stdout.strip().split('\n\n') if block.strip()]
    npm = native.catalog().get('npm-nas', {})
    return {'units': units, 'npmRunning': npm.get('State', {}).get('Running'),
            'npmCertificateModuleBinds': [{'source': row.get('Source'), 'destination': row.get('Destination')}
                for row in npm.get('Mounts', []) if row.get('Destination', '').endswith('/internal/certificate.js')
                or 'certificate-held.js' in row.get('Source', '')]}


def main():
    os.umask(0o077)
    args = controllers()
    backup, native = args[-3:-1]
    native.safe(WORK)
    WORK.mkdir(mode=0o700, exist_ok=True)
    require(sha(native.read(ORIGINAL_WORKER)) == ORIGINAL_SHA, 'The retained first Tracearr restoration worker changed.')
    require(sha(native.read(DEVICE_WORKER)) == DEVICE_SHA, 'The retained device-choice correction worker changed.')
    if sys.argv[1:] == ['--worker']:
        def interrupted(signum, frame):
            raise RuntimeError('Tracearr restoration interrupted; controlled recovery requested.')
        signal.signal(signal.SIGTERM, interrupted)
        with native.lock(BASE / '.run.lock'):
            worker(*args)
        try:
            say('REMAINING HOST OWNERS (read-only): ' + json.dumps(pending_owners(native), sort_keys=True))
        except Exception:
            say('Remaining-owner readout unavailable; completed Tracearr restoration retained.')
        return
    require(not sys.argv[1:] and globals().get('RESTORE_APPROVED_TRACEARR_CONTROLS') is True,
            'The approved Tracearr restoration flag is required.')
    source = globals().get('INSTALL_SOURCE')
    require(isinstance(source, str), 'The complete Tracearr restoration source is required.')
    with native.lock(BASE / '.run.lock'):
        if backup.unit(native, UNIT).get('ActiveState') in ('active', 'activating', 'deactivating'):
            say('Reviewed Tracearr restoration is already running.')
            return
        if SELF.exists():
            require(native.read(SELF) == source.encode(), 'A different Tracearr restoration worker was retained.')
        else:
            native.atomic(SELF, source.encode(), mode=0o700)
        subprocess.run(['systemctl', 'reset-failed', UNIT], capture_output=True)
        native.run('systemd-run', '--unit=' + UNIT, '--collect', '--property=Type=exec', '--property=UMask=0077',
                   '--property=RuntimeMaxSec=15min', '--property=TimeoutStopSec=240',
                   '--description=Restore reviewed Tracearr controls on current NAS data',
                   '/usr/bin/python3', '-u', str(SELF), '--worker')
    say('Reviewed Tracearr restoration started. Closing SSH is safe.')
    say('Progress: sudo journalctl -u ' + UNIT + ' -f -n 35 --no-pager -o cat')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        say('STOP: ' + type(error).__name__ + '. ' + (str(error) if isinstance(error, RuntimeError)
            else 'Targeted Tracearr restoration needs review.') + ' Current images/history retained.')
        raise SystemExit(1)
