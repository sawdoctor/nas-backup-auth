#!/usr/bin/env python3
"""Restore accepted NAS boot owners while retaining separate migration/job holds.

Use existing media/book startup units, native Docker restart policies for local
services, and the planned current-version Plex entry. No image/data import,
source restart, cloud remount, forced application restart or reboot.
"""
import contextlib
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
import yaml

APP = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
BASE = APP / 'compose/production-cutover'
WORK = BASE / 'boot-handover'
SELF = WORK / 'worker.py'
RECORD = WORK / 'state.json'
ACCEPTED = WORK / 'accepted.json'
UNIT = 'nas-production-boot-ownership.service'
FORMAT = 'sawdoctor-current-nas-boot-ownership-v1'
STARTUP = BASE / 'startup-image-handover/worker.py'
STARTUP_SHA = '0bae9fd022244940f35c93c0bba2ed320210c4a8fde8b563746c666dae13634a'
BOOK = Path('/usr/local/sbin/nas-books-deploy.py')
BOOK_SHA = '16889a58d366a86f01e580b8efab8fed5e04cbaee6843e4240ddd87f5c0f9bc9'
TORBOX = Path('/usr/local/sbin/nas-torbox-media')
TORBOX_SHA = '5872d4a12c65b2d0feb78f9cb4b562dbef4af69a2831f0f47f57d30b702990ca'
MEDIA = {'silo-nas-silo-1', 'sonarr-nas', 'radarr-nas', 'radarr4k-nas'}
BOOK_NAMES = {name + '-nas' for name in ('abr-shelfmark-bridge', 'audiobookrequest', 'audiobookshelf-test',
    'kavita', 'sabnzbd-ebooks', 'shelfmark-ebooks', 'shelfmark-torbox', 'stackarr-ebooks')}
LOCAL = {'dockmon', 'infinidysk-nas', 'kometa-nas', 'prowlarr-nas', 'seerr-nas', 'usenet-ultimate-nas'}
POLICIES = {**{name: 'on-failure:5' for name in MEDIA | BOOK_NAMES | {'plex-nas'}},
            **{name: 'unless-stopped' for name in LOCAL}}
RELEASE = ('nas-media-boot.service', 'nas-books.service')


def say(value): print(value, flush=True)
def sha(value): return hashlib.sha256(value).hexdigest()


def controllers():
    if any(path.is_symlink() for path in (STARTUP, *STARTUP.parents)) or sha(STARTUP.read_bytes()) != STARTUP_SHA:
        raise RuntimeError('The accepted startup controller changed.')
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('boot_accepted_startup', STARTUP)
    startup = importlib.util.module_from_spec(spec); spec.loader.exec_module(startup)
    release = startup.load(startup.RELEASE_HELPER, startup.RELEASE_SHA, 'boot_accepted_recovery')
    backup = release.backup_module(); backup.guard()
    native = backup.load(BASE / 'worker.py', backup.NATIVE_SHA, 'boot_current_native')
    return startup, release, backup, native


def policy_dict(value):
    name, _, retry = value.partition(':')
    return {'Name': name, 'MaximumRetryCount': int(retry) if retry else 0}


@contextlib.contextmanager
def boot_lock(native):
    # A one-minute media-recovery tick can briefly own the same lock at boot.
    # Wait for that normal operation instead of failing Plex into a long backup.
    deadline = time.monotonic() + 120
    with contextlib.ExitStack() as stack:
        while True:
            try:
                stack.enter_context(native.lock(native.BACKUP_LOCK)); break
            except RuntimeError as error:
                if str(error) != 'NAS backup/recovery/import is busy; retry after it finishes.' or time.monotonic() >= deadline:
                    raise
                time.sleep(1)
        yield


def runtime_signature(rows):
    result = {}
    for name, row in rows.items():
        host = copy.deepcopy(row['HostConfig'])
        if name in POLICIES: host.pop('RestartPolicy', None)
        result[name] = {'id': row['Id'], 'image': row['Image'], 'running': row['State']['Running'],
            'started': row['State'].get('StartedAt'), 'restartCount': row.get('RestartCount'),
            'config': sha(json.dumps(row['Config'], sort_keys=True).encode()),
            'host': sha(json.dumps(host, sort_keys=True).encode()),
            'mounts': sorted(json.dumps(mount, sort_keys=True) for mount in row['Mounts'])}
    return result


def owned_audit(startup, native, rows):
    contexts = {}; models = {}; items = []; images = {}
    if not set(POLICIES) <= rows.keys(): raise RuntimeError('An accepted startup container is missing.')
    for name in sorted(POLICIES):
        row = rows[name]; context = startup.compose_context(row)
        key = (context['project'], context['files'], context['directory'])
        if key not in contexts:
            contexts[key] = context; models[key] = startup.compose_model(native, context)
        service = startup.service_for(models[key], row)
        definition = models[key]['services'][service]; image = definition.get('image')
        if image not in images: images[image] = startup.local_image(image)
        if images[image] != row['Image']: raise RuntimeError('A current Compose image differs: ' + name)
        items.append({'name': name, 'key': key, 'service': service, 'restart': definition.get('restart', 'no')})
    return items, contexts, models


def patch_policies(body, changes, startup):
    text = body.decode(); tree = yaml.compose(text, Loader=yaml.SafeLoader)
    services = startup.mapping_value(tree, 'services'); spans = []
    for service, (old, new) in changes.items():
        node = startup.mapping_value(startup.mapping_value(services, service), 'restart')
        if not isinstance(node, yaml.ScalarNode) or node.value != old:
            raise RuntimeError('A restart field is missing, inherited or interpolated; current files retained.')
        token = text[node.start_mark.index:node.end_mark.index]
        if '\n' in token or token.startswith(('*', '&')): raise RuntimeError('An aliased/multiline restart field needs review.')
        spans.append((node.start_mark.index, node.end_mark.index, json.dumps(new)))
    spans.sort()
    if any(a[1] > b[0] for a, b in zip(spans, spans[1:])): raise RuntimeError('Restart scalar aliases overlap.')
    for start, end, value in reversed(spans): text = text[:start] + value + text[end:]
    before, after = yaml.safe_load(body), yaml.safe_load(text)
    expected = dict(before); expected['services'] = {key: dict(value) for key, value in before['services'].items()}
    for service, (_old, new) in changes.items(): expected['services'][service]['restart'] = new
    if after != expected: raise RuntimeError('More than approved restart fields would change.')
    return text.encode()


def plex_spec(row):
    return {'mounts': sorted(json.dumps(mount, sort_keys=True) for mount in row['Mounts']),
            'network': row['HostConfig']['NetworkMode'], 'devices': row['HostConfig'].get('Devices')}


def unit_documents(native):
    plex = ('# ' + FORMAT + '\n[Unit]\nDescription=Start current accepted Plex after NAS media mounts\n'
        'Requires=docker.service\nWants=network-online.target nas-backup-resume.service nas-media-boot.service '
        'nas-infinidysk-rclone.service nas-torbox-media.service\n'
        'After=docker.service network-online.target nas-backup-resume.service nas-media-boot.service nas-books.service '
        'nas-infinidysk-rclone.service nas-torbox-media.service\nPartOf=docker.service\n'
        'RequiresMountsFor=' + str(APP) + ' ' + str(native.SCRATCH) + '\nStartLimitIntervalSec=0\n'
        'ConditionPathExists=' + str(ACCEPTED) + '\n[Service]\nType=oneshot\nRemainAfterExit=yes\nUMask=0077\n'
        'ExecStart=/usr/bin/python3 ' + str(SELF) + ' --boot-plex --self-sha ' + native.digest(SELF) + '\n'
        'Restart=on-failure\nRestartSec=1min\nTimeoutStartSec=5min\n[Install]\nWantedBy=multi-user.target\n')
    return {
        'nas-production-plex.service': plex,
        'nas-production-import-guard.service.d/98-sawdoctor-production-boot-owned.conf':
            '# ' + FORMAT + '\n[Unit]\nConditionPathExists=!' + str(ACCEPTED) + '\n',
        'nas-backup.service.d/98-sawdoctor-production-boot-owned.conf':
            '# ' + FORMAT + '\n[Unit]\nWants=nas-production-plex.service\nAfter=nas-production-plex.service\n',
    }


def check_order(native, documents, books):
    units = set(RELEASE) | set(books.MOUNT_UNITS) | {'nas-production-import-guard.service', 'nas-production-plex.service',
        'nas-backup.service', 'nas-backup-resume.service', 'nas-torbox-media.service', 'docker.service'}
    graph = {}
    for unit in units:
        graph[unit] = set(native.run('systemctl', 'show', '--no-pager', unit, '-p', 'After', '--value').split())
    for path, text in documents.items():
        owner = path.split('.d/', 1)[0]
        graph.setdefault(owner, set())
        for line in text.splitlines():
            if line.startswith('After='): graph[owner].update(line[6:].split())
    def visit(unit, chain):
        if unit in chain: raise RuntimeError('The proposed NAS boot order contains a dependency cycle.')
        for parent in graph.get(unit, ()): visit(parent, chain | {unit})
    for unit in graph: visit(unit, set())


def prepare(native, backup, startup, release):
    main, rows = backup.preflight(native)
    startup.sample_passed(native, backup)
    image_record = json.loads(native.read(startup.RECORD))
    if image_record.get('phase') != 'complete' or image_record.get('cutoverId') != main['proof']['cutoverId']:
        raise RuntimeError('Current startup image reconciliation must be complete.')
    current_torbox = native.digest(TORBOX)
    if current_torbox != TORBOX_SHA:
        say('Installed TorBox boot helper SHA256: ' + current_torbox)
        raise RuntimeError('TorBox does not match the reviewed empty-folder boot repair; no boot ownership changed.')
    say('TorBox helper matches the reviewed empty-folder boot repair; existing helper retained.')
    books = backup.load(BOOK, BOOK_SHA, 'boot_current_books')
    recovery = native.helpers()['recovery']
    for unit in ('nas-media-boot.service', 'nas-backup-resume.service', 'nas-infinidysk-rclone.service', 'nas-torbox-media.service'):
        if backup.unit(native, unit).get('ActiveState') != 'active':
            raise RuntimeError('An existing mount/recovery owner is not active; live verification deferred: ' + unit)
    known = {'nas-books.service': books.unit_text(), 'nas-media-boot.service': recovery.unit_documents()['nas-media-boot.service'],
             'nas-production-import-guard.service': native.guard_text()}
    for unit, text in known.items():
        if native.read(native.UNITS / unit) != text.encode(): raise RuntimeError('An existing boot owner unit changed: ' + unit)
    if set(recovery.settings()['autostart']) != MEDIA or {name + '-nas' for name in books.APPS} != BOOK_NAMES:
        raise RuntimeError('The existing media/book boot membership differs.')
    plan = native.approved(backup.PLAN_SHA)
    manifest_path = Path(main['raw']) / 'manifest.json'
    if native.digest(manifest_path) != main['proof']['manifestSha256']: raise RuntimeError('Original policy provenance changed.')
    source = {row['Name'].lstrip('/'): row for row in json.loads(native.read(manifest_path))['containers']}
    source_names = {value: key for key, value in native.helpers()['core'].NAMES.items()}
    for name in LOCAL:
        original = plan['containers'].get(name, source.get(source_names.get(name, name.removesuffix('-nas')), {}))
        if original.get('HostConfig', {}).get('RestartPolicy', {}).get('Name') != 'unless-stopped':
            raise RuntimeError('A local-service original restart policy needs review: ' + name)
    for name in MEDIA:
        if plan['containers'][name]['HostConfig']['RestartPolicy'] != policy_dict('on-failure:5'):
            raise RuntimeError('A prior NAS mount-aware policy differs: ' + name)
    if source['plex']['HostConfig']['RestartPolicy'] != policy_dict('on-failure:5'):
        raise RuntimeError('The original Plex crash-restart policy differs.')
    if any(not rows[name]['State']['Running'] for name in POLICIES): raise RuntimeError('An accepted application is not running.')
    items, contexts, models = owned_audit(startup, native, rows)
    book_contexts = [context for context in contexts.values() if context['project'] == 'books-nas']
    if len(book_contexts) != 1 or len(book_contexts[0]['files']) != 1:
        raise RuntimeError('The existing book startup project is ambiguous.')
    if yaml.safe_load(native.read(book_contexts[0]['files'][0])).get('x-sawdoctor-managed') != books.SIGNATURE:
        raise RuntimeError('The existing book startup marker differs.')
    expected_compose = {name: ('unless-stopped' if name == 'dockmon' else 'on-failure:5' if name == 'silo-nas-silo-1' else 'no') for name in POLICIES}
    changes = {}
    for item in items:
        name = item['name']; current = rows[name]['HostConfig']['RestartPolicy']
        if current != policy_dict('no') or item['restart'] != expected_compose[name]:
            raise RuntimeError('A current staged restart policy changed; retained: ' + name)
        if item['restart'] == POLICIES[name]: continue
        paths = contexts[item['key']]['files']
        if len(paths) != 1: raise RuntimeError('A layered restart policy edit requires separate review.')
        changes.setdefault(paths[0], {})[item['service']] = (item['restart'], POLICIES[name])
    original_files = {path: native.read(path, 4 * 1024**2) for context in contexts.values() for path in context['files']}
    files = []; candidates = {}
    for path, updates in changes.items():
        key = sha(str(path).encode()); before = WORK / ('before-' + key + '.yaml'); prepared = WORK / ('prepared-' + key + '.yaml')
        body = patch_policies(original_files[path], updates, startup)
        for retained, expected in ((before, original_files[path]), (prepared, body)):
            if retained.exists() and native.read(retained) != expected:
                raise RuntimeError('A retained boot-policy preparation differs; all copies retained.')
            if not retained.exists(): native.atomic(retained, expected)
        candidates[path] = prepared
        files.append({'path': str(path), 'before': str(before), 'prepared': str(prepared),
                      'beforeSha256': sha(original_files[path]), 'afterSha256': sha(body)})
    for key, context in contexts.items():
        expected = copy.deepcopy(models[key])
        for path in context['files']:
            for service, (_old, new) in changes.get(path, {}).items(): expected['services'][service]['restart'] = new
        if startup.compose_model(native, context, candidates) != expected:
            raise RuntimeError('The staged boot model changes more than restart policies; live files retained.')
    documents = unit_documents(native); check_order(native, documents, books)
    prepared_unit = WORK / 'nas-production-plex.service'; native.atomic(prepared_unit, documents['nas-production-plex.service'].encode())
    native.run('systemd-analyze', 'verify', str(prepared_unit), timeout=90)
    for relative in documents:
        if (native.UNITS / relative).exists(): raise RuntimeError('A new boot ownership unit/drop-in already exists; retained.')
    for unit in RELEASE:
        if native.read(native.UNITS / (unit + '.d') / native.DROPIN) != native.CONDITION.encode():
            raise RuntimeError('A remaining media/book import hold differs.')
    if ACCEPTED.exists(): raise RuntimeError('An unjournalled boot acceptance marker was retained.')
    if runtime_signature(native.catalog()) != runtime_signature(rows): raise RuntimeError('A runtime changed during boot preparation.')
    if any(native.read(path) != body for path, body in original_files.items()): raise RuntimeError('A Compose layer changed during boot preparation.')
    record = {'format': FORMAT, 'phase': 'prepared', 'cutoverId': main['proof']['cutoverId'],
              'files': files, 'documents': documents, 'beforeRuntime': runtime_signature(rows),
              'beforePolicies': {name: rows[name]['HostConfig']['RestartPolicy'] for name in POLICIES},
              'plexSpec': plex_spec(rows['plex-nas']), 'releasedUnits': list(RELEASE), 'torboxHelperSha256': TORBOX_SHA}
    native.atomic(RECORD, record)
    return record


def rollback_configuration(native, record):
    if ACCEPTED.exists(): ACCEPTED.unlink(); native.sync_dir(ACCEPTED.parent)
    for unit in RELEASE:
        path = native.UNITS / (unit + '.d') / native.DROPIN
        if not path.exists(): native.atomic(path, native.CONDITION.encode(), mode=0o644)
    for item in reversed(record['files']):
        path = Path(item['path'])
        if sha(native.read(path)) == item['afterSha256']:
            native.atomic(path, native.read(Path(item['before'])), reference=path)
    rows = native.catalog()
    for name in POLICIES:
        if rows[name]['Id'] == record['beforeRuntime'][name]['id'] and rows[name]['HostConfig']['RestartPolicy'] == policy_dict(POLICIES[name]):
            native.run('docker', 'update', '--restart=no', name)
    for relative, body in record['documents'].items():
        path = native.UNITS / relative
        if path.exists() and native.read(path) == body.encode(): path.unlink(); native.sync_dir(path.parent)
    native.run('systemctl', 'daemon-reload')
    record['phase'] = 'stopped'; native.atomic(RECORD, record)


def configure_locked(native, backup, startup, release):
    if RECORD.exists():
        record = json.loads(native.read(RECORD))
        if record.get('format') != FORMAT or record.get('phase') not in ('configured', 'complete'):
            raise RuntimeError('An interrupted boot ownership journal requires review; current applications retained.')
        return record
    record = prepare(native, backup, startup, release)
    try:
        record['phase'] = 'applying'; native.atomic(RECORD, record)
        for item in record['files']:
            path = Path(item['path'])
            if sha(native.read(path)) != item['beforeSha256']: raise RuntimeError('A Compose file changed before policy replacement.')
            native.atomic(path, native.read(Path(item['prepared'])), reference=path)
        for name, value in POLICIES.items(): native.run('docker', 'update', '--restart=' + value, name)
        for relative, body in record['documents'].items():
            path = native.UNITS / relative; path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            native.atomic(path, body.encode(), mode=0o644)
        native.run('systemctl', 'daemon-reload')
        rows = native.catalog(); items, _contexts, _models = owned_audit(startup, native, rows)
        if runtime_signature(rows) != record['beforeRuntime'] or any(rows[name]['HostConfig']['RestartPolicy'] != policy_dict(value) for name, value in POLICIES.items()):
            raise RuntimeError('Unexpected runtime change during boot-policy restoration.')
        if any(item['restart'] != POLICIES[item['name']] for item in items): raise RuntimeError('Docker and Compose restart policies differ.')
        native.held(json.loads(native.read(native.STATE))['proof'])
        for unit in RELEASE:
            path = native.UNITS / (unit + '.d') / native.DROPIN
            if native.read(path) != native.CONDITION.encode(): raise RuntimeError('A startup hold changed before release.')
            path.unlink(); native.sync_dir(path.parent)
        native.atomic(ACCEPTED, {'format': FORMAT, 'cutoverId': record['cutoverId']})
        record['phase'] = 'configured'; native.atomic(RECORD, record)
        native.run('systemctl', 'daemon-reload')
    except BaseException:
        rollback_configuration(native, record)
        raise
    return record


def boot_plex(native, backup, release):
    record = json.loads(native.read(RECORD)); accepted = json.loads(native.read(ACCEPTED)); main = json.loads(native.read(native.STATE))
    if (record.get('format') != FORMAT or record.get('phase') not in ('configured', 'complete')
            or accepted != {'format': FORMAT, 'cutoverId': record.get('cutoverId')}
            or record['cutoverId'] != main['proof']['cutoverId']):
        raise RuntimeError('Accepted current NAS boot ownership is unavailable.')
    plan = native.approved(backup.PLAN_SHA)
    identity = backup.load(BASE / 'finish-plex-identity.py', backup.IDENTITY_SHA, 'current_boot_plex_identity')
    recovery = native.module(Path('/usr/local/sbin/nas-media-recovery'), native.HELPERS['recovery'][1], 'current_boot_media')
    with boot_lock(native):
        row = native.catalog()['plex-nas']
        if plex_spec(row) != record['plexSpec'] or not row['Config']['Image'].startswith('lscr.io/linuxserver/plex:'):
            raise RuntimeError('The current Plex bindings, devices, network or image repository changed; startup deferred.')
        if not recovery.ready(row, recovery.host_mounts()): raise RuntimeError('Plex media mounts are not ready; startup deferred.')
        config = Path(plan['liveRoots']['plex'])
        identity.validate_identity(native.read(config / native.PREFS), identity.evidence_for(native, main['proof']), main['proof'])
        if not row['State']['Running']: native.run('docker', 'start', row['Id'], timeout=90)
        identity.wait_plex(native, config, main['proof'])
        row = native.catalog()['plex-nas']
        if recovery.stale_bindings(row, recovery.host_mounts()): raise RuntimeError('Plex retains a stale media binding; startup needs review.')
    say('Current Plex boot entry verified; local source identity and mount bindings retained.')


def activate(native, backup, startup, release, record):
    # Enabling/starting lock-owning units is always outside BACKUP_LOCK.
    native.run('systemctl', 'enable', 'nas-media-boot.service', 'nas-books.service', 'nas-production-plex.service')
    native.run('systemctl', 'disable', '--now', 'nas-migration-standby.timer')
    # No Wants=nas-books.service: the enabled book owner is ordered before Plex
    # at boot, but this live verification must not trigger a Compose redeploy.
    native.run('systemctl', 'start', 'nas-production-plex.service', timeout=330)
    plex_unit = backup.unit(native, 'nas-production-plex.service')
    if plex_unit.get('ActiveState') != 'active' or plex_unit.get('SubState') != 'exited' or plex_unit.get('Result') != 'success':
        raise RuntimeError('The current Plex boot unit did not complete its live verification.')
    with native.lock(native.BACKUP_LOCK):
        _main, rows = backup.preflight(native)
        items, _contexts, _models = owned_audit(startup, native, rows)
        if runtime_signature(rows) != record['beforeRuntime']:
            raise RuntimeError('A runtime changed during live boot verification; current applications retained for review.')
        if any(item['restart'] != POLICIES[item['name']] for item in items): raise RuntimeError('Final Compose restart policies differ.')
        for name, value in POLICIES.items():
            if rows[name]['HostConfig']['RestartPolicy'] != policy_dict(value): raise RuntimeError('A final Docker restart policy differs.')
        for relative, body in record['documents'].items():
            if native.read(native.UNITS / relative) != body.encode(): raise RuntimeError('A final boot ownership unit differs.')
        if not native.ACTIVE.exists(): raise RuntimeError('The separate cron/job migration hold unexpectedly disappeared.')
        record['phase'] = 'complete'; native.atomic(RECORD, record)
    say('CURRENT NAS BOOT OWNERSHIP RESTORED. All19 Docker/Compose restart policies agree with their existing NAS owners.')
    say('Six local services use Docker unless-stopped; four media clients, eight books and Plex use mount-aware startup with on-failure:5.')
    say('Plex production boot unit enabled and live-verified. Current image versions, container IDs/start times, settings and storage retained.')
    say('Only media/book boot holds released; accepted-boot condition prevents the old import stop guard from stopping this accepted NAS at reboot.')
    say('Original import-active marker still holds cron/remaining jobs. Obsolete NAS standby timer disabled; source production remains held.')
    say('NO REBOOT PERFORMED. A controlled reboot check is still needed. Application controls, host jobs and NPM renewal remain separate.')
    say('Small boot ownership record: ' + str(RECORD))


def main():
    os.umask(0o077); startup, release, backup, native = controllers()
    args = sys.argv[1:]
    if args[:1] == ['--boot-plex']:
        if len(args) != 3 or args[1] != '--self-sha' or native.digest(SELF) != args[2]: raise RuntimeError('The pinned Plex boot controller changed.')
        boot_plex(native, backup, release); return
    if args == ['--worker']:
        def terminate(_signum, _frame): raise RuntimeError('Boot ownership configuration interrupted; current data retained.')
        signal.signal(signal.SIGTERM, terminate)
        with native.lock(BASE / '.run.lock'):
            with native.lock(native.BACKUP_LOCK): record = configure_locked(native, backup, startup, release)
            activate(native, backup, startup, release, record)
        return
    if args or globals().get('RESTORE_APPROVED_BOOT_OWNERSHIP') is not True:
        raise RuntimeError('The approved NAS boot ownership flag is required.')
    if backup.unit(native, UNIT).get('ActiveState') in ('active', 'activating', 'deactivating'):
        say('Current NAS boot ownership restoration is already running.'); return
    source = globals().get('INSTALL_SOURCE')
    if not isinstance(source, str): raise RuntimeError('The complete reviewed boot controller source is required.')
    with native.lock(BASE / '.run.lock'):
        native.safe(WORK); WORK.mkdir(mode=0o700, exist_ok=True)
        if SELF.exists() and native.read(SELF) != source.encode(): raise RuntimeError('A different boot ownership controller was retained.')
        native.atomic(SELF, source.encode())
    subprocess.run(['systemctl', 'reset-failed', UNIT], capture_output=True, timeout=15)
    native.run('systemd-run', '--unit=' + UNIT, '--collect', '--property=Type=exec', '--property=UMask=0077',
               '--property=RuntimeMaxSec=20min', '--description=Restore accepted current NAS boot owners without releasing pending jobs',
               '/usr/bin/python3', '-u', str(SELF), '--worker')
    say('Current NAS boot ownership restoration started in systemd. Closing SSH is safe.')
    say('Progress: sudo journalctl -u ' + UNIT + ' -f -n 35 --no-pager -o cat')


if __name__ == '__main__':
    try: main()
    except Exception as error:
        say('STOP: ' + (str(error) if isinstance(error, RuntimeError) else type(error).__name__) +
            '. Current application images/data and source hold retained; no reboot requested.'); raise SystemExit(1)
