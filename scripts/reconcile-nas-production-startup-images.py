#!/usr/bin/env python3
"""Reconcile three reviewed stale Compose image scalars to current local images.

Read all Compose layers/profiles and resolve adopted service names by the unique
container_name. Retain file bytes except approved image scalar spans. Never run
up/pull/start/restart or release startup/job/application guards in this step.
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

APP = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
BASE = APP / 'compose/production-cutover'
WORK = BASE / 'startup-image-handover'
SELF = WORK / 'worker.py'
RECORD = WORK / 'state.json'
UNIT = 'nas-production-startup-images.service'
FORMAT = 'sawdoctor-current-startup-images-v1'
RELEASE_HELPER = BASE / 'media-recovery-handover/worker.py'
RELEASE_SHA = 'c89c2c57890ce257580df1f8c74a0247a1cc4addfe1f1ecb366b2fcbd7e9b0ff'
FIXES = {
    'sabnzbd-ebooks-nas': {
        'old': 'sha256:3ec9eef2aca6ede916b9b1cdd62003389e16a08a6cb9be78f9820cd606391578',
        'image': 'lscr.io/linuxserver/sabnzbd:latest',
        'running': 'sha256:2bdcbbb87a7ae92dd37ce84a48c17478e9fa4dd0dc5c3349e9278d5afad26131',
        'path': 'appdata/dockmon/stacks/books-nas/compose.yaml'},
    'seerr-nas': {
        'old': 'sha256:61f6fa0cf472caa95736d00fa624aea848f687b2ac899c2370a509de93e8abba',
        'image': 'ghcr.io/seerr-team/seerr:latest',
        'running': 'sha256:7d1119e0cbe4ac2ccfedc22318c1b06eb43596a83bdd54bf6e2dbd5506b67629',
        'path': 'appdata/dockmon/stacks/media-core-nas/compose.yaml'},
    'sonarr-nas': {
        'old': 'sha256:d752b65bfe30a7348214fca1c5a7249384c21ee0d40452e4a32377807959ad19',
        'image': 'lscr.io/linuxserver/sonarr:latest',
        'running': 'sha256:38ba522062892eb140f61d0d196eeacc1d058fefdcc3bf03cbffb35fdcf80c14',
        'path': 'appdata/dockmon/stacks/media-core-nas/compose.yaml'},
}


def say(value): print(value, flush=True)
def sha(value): return hashlib.sha256(value).hexdigest()


def load(path, expected, name):
    if any(item.is_symlink() for item in (path, *path.parents)) or sha(path.read_bytes()) != expected:
        raise RuntimeError('An accepted controller changed; startup files retained.')
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def host_path(value):
    path = Path(value)
    if not path.is_absolute(): raise RuntimeError('A relative Compose label path needs separate review.')
    if path.is_relative_to('/app/data/stacks'):
        path = APP / 'appdata/dockmon/stacks' / path.relative_to('/app/data/stacks')
    result = path.resolve(strict=True)
    if not result.is_relative_to(APP.resolve(strict=True)):
        raise RuntimeError('A Compose path is outside the NAS application SSD.')
    return result


def compose_context(row):
    labels = row['Config'].get('Labels') or {}
    project = labels.get('com.docker.compose.project', '')
    paths = labels.get('com.docker.compose.project.config_files', '').split(',')
    if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,127}', project) or not 1 <= len(paths) <= 8 or any(not path for path in paths):
        raise RuntimeError('A running container has unavailable Compose ownership: ' + row['Name'].lstrip('/'))
    files = tuple(host_path(path) for path in paths)
    if len(set(files)) != len(files): raise RuntimeError('Duplicate Compose layer paths require review.')
    if any(not path.is_file() or path.stat().st_size > 4 * 1024**2 for path in files):
        raise RuntimeError('A Compose layer is not a bounded regular file.')
    directory = host_path(labels.get('com.docker.compose.project.working_dir') or str(files[0].parent))
    if not directory.is_dir(): raise RuntimeError('The original Compose project directory is unavailable.')
    return {'project': project, 'files': files, 'directory': directory}


def compose_model(native, context, replacements=None):
    replacements = replacements or {}
    command = ['docker', 'compose', '-p', context['project'], '--project-directory', str(context['directory']), '--profile', '*']
    for path in context['files']: command += ['-f', str(replacements.get(path, path))]
    command += ['config', '--format', 'json']
    model = json.loads(native.run(*command, timeout=90))
    if not isinstance(model.get('services'), dict): raise RuntimeError('A Compose model has no service dictionary.')
    return model


def service_for(model, row):
    name = row['Name'].lstrip('/')
    label = (row['Config'].get('Labels') or {}).get('com.docker.compose.service')
    matches = [key for key, service in model['services'].items() if service.get('container_name') == name]
    if len(matches) == 1: return matches[0]
    if matches: raise RuntimeError('A container_name is repeated in its Compose model.')
    service = model['services'].get(label)
    if not isinstance(service, dict) or service.get('container_name'):
        raise RuntimeError('The current container has no unique service in the merged Compose model: ' + name)
    number = (row['Config'].get('Labels') or {}).get('com.docker.compose.container-number', '1')
    project = (row['Config'].get('Labels') or {}).get('com.docker.compose.project')
    if name not in (f'{project}-{label}-{number}', f'{project}_{label}_{number}'):
        raise RuntimeError('A generated Compose container name differs from its labels.')
    return label


def local_image(reference):
    if not isinstance(reference, str) or not reference or len(reference) > 512 or reference.startswith('-'):
        raise RuntimeError('An image reference needs separate review.')
    result = subprocess.run(['docker', 'image', 'inspect', '--', reference], text=True,
                            capture_output=True, timeout=20)
    if result.returncode: return None
    rows = json.loads(result.stdout)
    if len(rows) != 1 or not re.fullmatch(r'sha256:[a-f0-9]{64}', rows[0].get('Id', '')):
        raise RuntimeError('A local image identity is ambiguous.')
    return rows[0]['Id']


def image_audit(native, rows):
    contexts = {}; models = {}; entries = []; image_cache = {}
    for name, row in sorted(rows.items()):
        if row['HostConfig']['RestartPolicy']['Name'] not in ('', 'no'): continue
        context = compose_context(row)
        key = (context['project'], context['files'], context['directory'])
        if key not in models:
            contexts[key] = context; models[key] = compose_model(native, context)
        service = service_for(models[key], row)
        image = models[key]['services'][service].get('image')
        if not image: raise RuntimeError('A current Compose service has no recorded local image: ' + name)
        if image not in image_cache: image_cache[image] = local_image(image)
        entries.append({'name': name, 'contextKey': key, 'service': service, 'image': image,
                        'runtimeImageId': row['Image'], 'sameLocalImage': image_cache[image] == row['Image'],
                        'labelService': (row['Config'].get('Labels') or {}).get('com.docker.compose.service')})
    if not set(FIXES) <= {item['name'] for item in entries}:
        raise RuntimeError('One of the three reviewed applications changed startup ownership; files retained.')
    return entries, contexts, models


def mapping_value(node, key):
    import yaml
    if not isinstance(node, yaml.MappingNode): raise RuntimeError('A Compose mapping is not explicit.')
    values = [value for name, value in node.value if name.value == key]
    if len(values) != 1: raise RuntimeError('A Compose key is missing or repeated; files retained.')
    return values[0]


def patch_images(body, updates):
    """Patch scalar spans; preserve comments, ordering, paths, mounts and env."""
    import yaml
    text = body.decode('utf-8'); tree = yaml.compose(text, Loader=yaml.SafeLoader)
    services = mapping_value(tree, 'services'); changes = []
    for service, (before, after) in updates.items():
        node = mapping_value(mapping_value(services, service), 'image')
        if not isinstance(node, yaml.ScalarNode) or node.tag != 'tag:yaml.org,2002:str' or node.value != before:
            raise RuntimeError('The reviewed image scalar is inherited/interpolated or differs; files retained.')
        token = text[node.start_mark.index:node.end_mark.index]
        if '\n' in token or token.startswith(('*', '&')):
            raise RuntimeError('A multiline or aliased image scalar requires separate review.')
        changes.append((node.start_mark.index, node.end_mark.index, json.dumps(after)))
    ordered = sorted(changes)
    if any(a[1] > b[0] for a, b in zip(ordered, ordered[1:])):
        raise RuntimeError('Aliased image scalar spans overlap; files retained.')
    for start, end, value in reversed(ordered): text = text[:start] + value + text[end:]
    old, new = yaml.safe_load(body), yaml.safe_load(text)
    expected = dict(old)
    expected['services'] = {key: dict(value) for key, value in old['services'].items()}
    for service, (_before, after) in updates.items(): expected['services'][service]['image'] = after
    if new != expected: raise RuntimeError('More than the reviewed image fields would change; files retained.')
    return text.encode('utf-8')


def reviewed_fixes(entries, contexts, rows):
    updates = {}
    for item in entries:
        if item['sameLocalImage']: continue
        name = item['name']; rule = FIXES.get(name)
        if rule is None:
            raise RuntimeError('Another image differs after the corrected Compose audit: ' + name)
        row = rows[name]; paths = contexts[item['contextKey']]['files']; expected = (APP / rule['path']).resolve(strict=True)
        if (paths != (expected,) or item['image'] != rule['old'] or row['Image'] != rule['running']
                or row['Config']['Image'] != rule['image'] or local_image(rule['image']) != row['Image']):
            raise RuntimeError('A reviewed running image/tag or source scalar changed; files retained: ' + name)
        updates.setdefault(expected, {})[item['service']] = (rule['old'], rule['image'])
    return updates


def sample_passed(native, backup):
    path = backup.BACKUP / 'backups/restore-check/result.json'
    result = json.loads(native.read(path, 1024**2))
    accepted = json.loads(native.read(backup.RECORD))
    if (result.get('format') != 'sawdoctor-nas-backup-sample-restore-v1' or result.get('phase') != 'complete'
            or result.get('backupSet') != accepted.get('backupSet') or accepted.get('phase') != 'complete'
            or result.get('cloudRecoveryFilesMatched') != 4 or result.get('temporaryCopiesRemoved') is not True
            or result.get('applicationsStarted') is not False or result.get('databaseRows', 0) < 1):
        raise RuntimeError('The accepted backup sample restore has not completed successfully; startup files retained.')
    return result


def sanitized(entries, contexts):
    return [{'name': item['name'], 'service': item['service'], 'labelService': item['labelService'],
             'composeImage': item['image'], 'runtimeImageId': item['runtimeImageId'],
             'sameLocalImage': item['sameLocalImage'], 'project': contexts[item['contextKey']]['project'],
             'paths': [str(path) for path in contexts[item['contextKey']]['files']]}
            for item in entries]


def apply_locked(native, backup, release):
    main, rows = backup.preflight(native)
    media = json.loads(native.read(release.RECORD))
    if media.get('phase') != 'complete' or media.get('cutoverId') != main['proof']['cutoverId']:
        raise RuntimeError('The successful current mount-recovery handover is required.')
    sample = sample_passed(native, backup)
    record = json.loads(native.read(RECORD)) if RECORD.exists() else None
    if record:
        if record.get('format') != FORMAT or record.get('cutoverId') != main['proof']['cutoverId']:
            raise RuntimeError('An unrelated startup-image journal was retained.')
        if record.get('phase') == 'complete':
            say('Current startup image reconciliation is already complete; no files rewritten.'); return
        raise RuntimeError('An interrupted startup-image journal needs review; current applications retained.')
    signature = release.runtime_signature(rows)
    entries, contexts, models = image_audit(native, rows)
    updates = reviewed_fixes(entries, contexts, rows)
    for item in entries:
        say('Startup image: ' + item['name'] + '; service=' + item['service'] +
            '; layers=' + str(len(contexts[item['contextKey']]['files'])) +
            '; current=' + str(item['sameLocalImage']))
    originals = {path: native.read(path, 4 * 1024**2) for context in contexts.values() for path in context['files']}
    candidates = {}; retained = []
    for path, changes in updates.items():
        key = sha(str(path).encode()); before = WORK / ('before-' + key + '.yaml'); prepared = WORK / ('prepared-' + key + '.yaml')
        if before.exists() or prepared.exists(): raise RuntimeError('An unjournalled Compose recovery copy was retained.')
        body = patch_images(originals[path], changes)
        native.atomic(before, originals[path]); native.atomic(prepared, body)
        candidates[path] = prepared
        retained.append({'path': str(path), 'before': str(before), 'prepared': str(prepared),
                         'beforeSha256': sha(originals[path]), 'afterSha256': sha(body), 'services': sorted(changes)})
    for key, context in contexts.items():
        expected = copy.deepcopy(models[key])
        for path in context['files']:
            for service, (_old, new) in updates.get(path, {}).items(): expected['services'][service]['image'] = new
        if compose_model(native, context, candidates) != expected:
            raise RuntimeError('The staged Compose model changes more than reviewed image references; live files retained.')
    if release.runtime_signature(native.catalog()) != signature:
        raise RuntimeError('A running container changed during preparation; live files retained.')
    if any(native.read(path, 4 * 1024**2) != body for path, body in originals.items()):
        raise RuntimeError('A Compose layer changed during preparation; live files retained.')
    record = {'format': FORMAT, 'phase': 'prepared', 'cutoverId': main['proof']['cutoverId'],
              'backupSet': sample['backupSet'], 'files': retained, 'beforeRuntime': signature,
              'beforeAudit': sanitized(entries, contexts), 'applicationsRestarted': False}
    native.atomic(RECORD, record)
    try:
        record['phase'] = 'applying'; native.atomic(RECORD, record)
        for item in retained:
            path = Path(item['path'])
            if sha(native.read(path)) != item['beforeSha256']: raise RuntimeError('A Compose file changed before replacement.')
            native.atomic(path, native.read(Path(item['prepared'])), reference=path)
        after_entries, after_contexts, _models = image_audit(native, rows)
        if any(not item['sameLocalImage'] for item in after_entries):
            raise RuntimeError('The final current-image audit differs.')
        if release.runtime_signature(native.catalog()) != signature:
            raise RuntimeError('A running container changed during reconciliation; inspect the retained journal.')
        native.held(main['proof'])
        record.update(phase='complete', afterAudit=sanitized(after_entries, after_contexts))
        native.atomic(RECORD, record)
    except Exception:
        # Restore only our exact newly written scalar edits. Never overwrite a
        # file subsequently edited by the user, Dockmon or another process.
        for item in reversed(retained):
            path = Path(item['path'])
            if sha(native.read(path)) == item['afterSha256']:
                native.atomic(path, native.read(Path(item['before'])), reference=path)
        record['phase'] = 'stopped'; native.atomic(RECORD, record)
        raise
    say('CURRENT STARTUP IMAGE REFERENCES RECONCILED. ' + str(len(retained)) + ' Compose files; only the three reviewed image fields changed where needed.')
    say('All ' + str(len(after_entries)) + ' currently held-startup containers match their merged Compose image definitions, including all layers/profiles and adopted service names.')
    say('Current container/image identities and full runtime configurations retained; no application restart, image pull or tag change.')
    say('Plex stays on its current version. Boot/restart ownership, cron/jobs, application controls and NPM renewal remain held for their separate handover.')
    say('Small operation record: ' + str(RECORD))


def main():
    os.umask(0o077)
    release = load(RELEASE_HELPER, RELEASE_SHA, 'accepted_media_recovery')
    backup = release.backup_module(); backup.guard()
    native = backup.load(BASE / 'worker.py', backup.NATIVE_SHA, 'startup_image_native')
    if sys.argv[1:] == ['--worker']:
        def terminate(_signum, _frame): raise RuntimeError('Startup image reconciliation interrupted; retained journal requires review.')
        signal.signal(signal.SIGTERM, terminate)
        with native.lock(BASE / '.run.lock'), native.lock(native.BACKUP_LOCK):
            apply_locked(native, backup, release)
        return
    if sys.argv[1:] or globals().get('RECONCILE_APPROVED_STARTUP_IMAGES') is not True:
        raise RuntimeError('The approved current-image reconciliation flag is required.')
    if backup.unit(native, UNIT).get('ActiveState') in ('active', 'activating', 'deactivating'):
        say('Current startup image reconciliation is already running.'); return
    sample_passed(native, backup)
    source = globals().get('INSTALL_SOURCE')
    if not isinstance(source, str): raise RuntimeError('The complete reviewed reconciliation source is required.')
    with native.lock(BASE / '.run.lock'):
        native.safe(WORK); WORK.mkdir(mode=0o700, exist_ok=True)
        if SELF.exists() and native.read(SELF) != source.encode(): raise RuntimeError('A different startup-image controller was retained.')
        native.atomic(SELF, source.encode())
    subprocess.run(['systemctl', 'reset-failed', UNIT], capture_output=True, timeout=15)
    native.run('systemd-run', '--unit=' + UNIT, '--collect', '--property=Type=exec', '--property=UMask=0077',
               '--property=RuntimeMaxSec=15min', '--description=Reconcile reviewed NAS Compose images to current running versions',
               '/usr/bin/python3', '-u', str(SELF), '--worker')
    say('Current-version startup image reconciliation started in systemd. Closing SSH is safe.')
    say('Progress: sudo journalctl -u ' + UNIT + ' -f -n 35 --no-pager -o cat')


if __name__ == '__main__':
    try: main()
    except Exception as error:
        say('STOP: ' + (str(error) if isinstance(error, RuntimeError) else type(error).__name__) +
            '. Current images, application data and startup/job holds retained.'); raise SystemExit(1)
