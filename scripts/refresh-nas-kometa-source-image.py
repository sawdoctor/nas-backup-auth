#!/usr/bin/env python3
"""Cache frozen Kometa image, recreate only its stopped container, resume import."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import yaml

APP = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
BASE = APP / 'compose/production-cutover'
WORK = BASE / 'kometa-image-refresh'
SELF = WORK / 'worker.py'
STATE = WORK / 'state.json'
STARTER = BASE / 'kometa-handover/worker.py'
STARTER_SHA = '5a2e0bf3bad87b798efbf82082a155f2cf73f1b835be4560896d527c66405a14'
FORMAT = 'sawdoctor-frozen-kometa-image-refresh-v1'


def say(value): print(value, flush=True)
def sha(body): return hashlib.sha256(body).hexdigest()


class ComposeLoader(yaml.SafeLoader):
    # Compose uses YAML1.2: restart:no and environment ON/OFF are strings.
    yaml_implicit_resolvers = copy.deepcopy(yaml.SafeLoader.yaml_implicit_resolvers)


for initial, resolvers in list(ComposeLoader.yaml_implicit_resolvers.items()):
    ComposeLoader.yaml_implicit_resolvers[initial] = [item for item in resolvers if item[0] not in
                                                   ('tag:yaml.org,2002:bool', 'tag:yaml.org,2002:timestamp')]
ComposeLoader.add_implicit_resolver('tag:yaml.org,2002:bool', re.compile(r'^(?:true|True|TRUE|false|False|FALSE)$'), list('tTfF'))


def compose_model(body):
    value = yaml.load(body, Loader=ComposeLoader)
    if not isinstance(value, dict) or not isinstance(value.get('services'), dict):
        raise RuntimeError('The existing shared Compose document is not a service mapping.')
    return value


def starter_module():
    if any(p.is_symlink() for p in (STARTER, *STARTER.parents)) or sha(STARTER.read_bytes()) != STARTER_SHA:
        raise RuntimeError('The previously installed pinned Kometa handover differs.')
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('verified_kometa_starter', STARTER)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def repository(reference):
    if not isinstance(reference, str) or not re.fullmatch(r'[A-Za-z0-9._:/@-]+', reference):
        raise RuntimeError('A recorded image repository reference differs.')
    value = reference.split('@', 1)[0]
    if ':' in value.rsplit('/', 1)[-1]: value = value.rsplit(':', 1)[0]
    for prefix in ('docker.io/', 'index.docker.io/', 'registry-1.docker.io/'):
        if value.startswith(prefix): value = value[len(prefix):]; break
    return value


def immutable_reference(source, image):
    if image.get('Os') != 'linux' or image.get('Architecture') != 'amd64' or image.get('Variant'):
        raise RuntimeError('Frozen Kometa requires an unreviewed image platform.')
    wanted = repository(source['Config']['Image'])
    if wanted.rsplit('/', 1)[-1] != 'kometa':
        raise RuntimeError('The frozen source is not the reviewed Kometa repository.')
    choices = {value for value in image.get('RepoDigests') or []
               if re.fullmatch(r'[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}', value)
               and repository(value) == wanted}
    if len(choices) != 1:
        raise RuntimeError('A unique immutable digest for the current frozen Kometa image is unavailable.')
    return next(iter(choices))


def preserve_others(rows):
    # Ignore changing health probes and Docker mount ordering. Keep identities,
    # starts and full configuration so an unexpected other-service change stops.
    return {name: {'id': row['Id'], 'image': row['Image'], 'config': row['Config'],
                   'hostConfig': row['HostConfig'],
                   'mounts': sorted(row['Mounts'], key=lambda item: json.dumps(item, sort_keys=True)),
                   'running': row['State']['Running'], 'status': row['State']['Status'],
                   'startedAt': row['State'].get('StartedAt'), 'finishedAt': row['State'].get('FinishedAt'),
                   'restartCount': row.get('RestartCount')}
            for name, row in rows.items() if name != 'kometa-nas'}


def compose_path(native, current):
    labels = current['Config'].get('Labels') or {}
    if labels.get('com.docker.compose.project') != 'support-nas' or labels.get('com.docker.compose.service') != 'kometa':
        raise RuntimeError('The accepted Kometa Compose project/service differs.')
    files = labels.get('com.docker.compose.project.config_files', '').split(',')
    if len(files) != 1:
        raise RuntimeError('An unexpected multi-file Kometa Compose definition was retained.')
    canonical = APP / 'appdata/dockmon/stacks/support-nas/compose.yaml'
    path = Path(files[0])
    if path == Path('/app/data/stacks/support-nas/compose.yaml'): path = canonical
    if path.is_symlink():
        if path != APP / 'compose/support-nas/compose.json' or os.readlink(path) != str(canonical):
            raise RuntimeError('An unrecognized Kometa Compose compatibility link was retained.')
        path = canonical
    native.safe(path)
    if not path.is_relative_to(APP) or not path.is_file():
        raise RuntimeError('The accepted NAS Kometa Compose file is unavailable.')
    return path


def candidate_model(model, source, image_id, starter, old):
    service = model.get('services', {}).get('kometa')
    if not isinstance(service, dict) or service.get('container_name') != 'kometa-nas' or service.get('depends_on'):
        raise RuntimeError('Kometa definition is not an isolated existing service.')
    if service.get('restart', 'no') != 'no':
        raise RuntimeError('The accepted stopped Kometa restart policy differs.')
    proposed = copy.deepcopy(model); target = proposed['services']['kometa']
    target['image'] = image_id; target['pull_policy'] = 'never'; target['restart'] = 'no'
    # Reapply the actual frozen container environment/command, including the
    # image defaults that may differ from the older NAS image. Never add --run.
    env = starter.environment(source)
    target['environment'] = {key: value.replace('$', '$$') for key, value in env.items()}
    for origin, destination in (('Cmd', 'command'), ('Entrypoint', 'entrypoint')):
        value = source['Config'].get(origin)
        if value is None: target.pop(destination, None)
        else:
            if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                raise RuntimeError('The frozen Kometa command format differs.')
            target[destination] = [item.replace('$', '$$') for item in value]
    for origin, destination in (('User', 'user'), ('WorkingDir', 'working_dir')):
        value = source['Config'].get(origin)
        if value: target[destination] = value.replace('$', '$$')
        else: target.pop(destination, None)
    simulated = copy.deepcopy(old)
    simulated['Config'].update({key: copy.deepcopy(source['Config'].get(key))
                                for key in ('Env', 'Cmd', 'Entrypoint', 'User', 'WorkingDir')})
    starter.validate_runtime(source, simulated)
    if {k: v for k, v in proposed['services'].items() if k != 'kometa'} != {
            k: v for k, v in model['services'].items() if k != 'kometa'}:
        raise RuntimeError('An unrelated service definition changed; retained.')
    return proposed


def compose(native, path, *args):
    return native.run('docker', 'compose', '-p', 'support-nas', '--project-directory', str(path.parent),
                      '-f', str(path), '--profile', 'plex-cutover', *args, timeout=240)


def worker():
    starter = starter_module()
    native = starter.load_module(BASE / 'worker.py', starter.NATIVE_SHA, 'kometa_image_native')
    with native.lock(BASE / '.run.lock'), native.lock(native.BACKUP_LOCK):
        plan = native.approved(starter.PLAN_SHA)
        state = json.loads(native.read(native.STATE))
        if state.get('phase') not in ('awaiting-acceptance', 'committed-core') or state.get('plexIdentityValidated') is not True:
            raise RuntimeError('The verified live NAS Plex/core import is required.')
        raw, manifest, source = starter.frozen_manifest(native, state)
        native.held(state['proof']); starter.plex_identity(native, plan, state)
        h = native.helpers(); cache, core = h['cache'], h['core']
        expected = {row['Id']: row for row in manifest['images']}[source['Image']]
        rows = native.catalog(); others = preserve_others(rows)
        if STATE.exists():
            operation = json.loads(native.read(STATE))
            if operation.get('format') != FORMAT or operation.get('cutoverId') != state['proof']['cutoverId']:
                raise RuntimeError('An existing Kometa image operation belongs to another capture.')
            old = json.loads(native.read(WORK / 'rollback/container.before.json'))
            path = Path(operation['compose'])
            if path != compose_path(native, old):
                raise RuntimeError('The retained Kometa Compose locator differs.')
        else:
            if starter.STATE.exists():
                raise RuntimeError('Kometa data handover already began; inspect it before changing its container.')
            old = rows['kometa-nas']
            if old['State']['Running'] or old['HostConfig']['RestartPolicy']['Name'] != 'no':
                raise RuntimeError('Kometa must still be stopped with restart=no.')
            if len(old['Mounts']) != 1 or native.config_bind(old, '/config') != APP / 'appdata/support-nas/kometa':
                raise RuntimeError('The existing NAS Kometa config binding differs.')
            path = compose_path(native, old)
            # Check command/env adaptation before any image download or deployment.
            original = compose_model(native.read(path, 2 * 1024**2))
            candidate_model(original, source, old['Image'], starter, old)
            images = cache.inventory(core)
            matches = sorted(identity for identity, image in images.items() if cache.same_image(core, expected, image))
            references = sorted({source['Config']['Image'], old['Config']['Image']})
            tags = cache.tag_bindings(images, references)
            if not matches:
                reference = immutable_reference(source, expected)
                docker_root = Path(json.loads(native.run('docker', 'info', '--format', '{{json .DockerRootDir}}'))).resolve(strict=True)
                if shutil.disk_usage(docker_root).free < 2 * max(0, int(expected.get('Size', 0))) + 2 * 1024**3:
                    raise RuntimeError('The Docker image filesystem lacks the download/reserve space bound.')
                cache.pull(core, 'kometa', reference, 'linux/amd64', WORK)
                downloaded = json.loads(native.run('docker', 'image', 'inspect', reference))
                if len(downloaded) != 1 or not cache.same_image(core, expected, downloaded[0]):
                    raise RuntimeError('Downloaded Kometa image runtime/layers/platform differ from frozen source.')
                images = cache.inventory(core)
                matches = sorted(identity for identity, image in images.items() if cache.same_image(core, expected, image))
            if not matches or cache.tag_bindings(images, references) != tags:
                raise RuntimeError('The exact Kometa cache or existing image tags differ; no deployment.')
            if preserve_others(native.catalog()) != others:
                raise RuntimeError('An unrelated container changed during caching; deployment deferred.')
            proposed = candidate_model(original, source, matches[0], starter, old)
            encoded = yaml.safe_dump(proposed, sort_keys=False, allow_unicode=True).encode()
            private = WORK / 'compose.candidate.yaml'; native.atomic(private, encoded)
            baseline = json.loads(compose(native, path, 'config', '--format', 'json'))
            candidate = json.loads(native.run('docker', 'compose', '-p', 'support-nas', '--project-directory', str(path.parent),
                                             '-f', str(private), '--profile', 'plex-cutover', 'config', '--format', 'json'))
            a, b = copy.deepcopy(baseline), copy.deepcopy(candidate)
            a['services'].pop('kometa'); b['services'].pop('kometa')
            if a != b:
                raise RuntimeError('Normalized non-Kometa Compose settings differ; no deployment.')
            before = WORK / 'rollback'; native.safe(before); before.mkdir(mode=0o700, exist_ok=True)
            native.atomic(before / 'compose.before.yaml', native.read(path, 2 * 1024**2))
            native.atomic(before / 'container.before.json', old)
            operation = {'format': FORMAT, 'cutoverId': state['proof']['cutoverId'], 'phase': 'prepared',
                         'compose': str(path), 'beforeSha256': native.digest(path), 'afterSha256': sha(encoded),
                         'image': matches[0], 'sourceImage': source['Image'], 'oldContainerId': old['Id']}
            native.atomic(STATE, operation)
            say('Exact frozen Kometa image cached; candidate changes only Kometa. Existing config root retained.')
        if operation['phase'] not in ('prepared', 'compose-installed', 'container-ready'):
            raise RuntimeError('The retained Kometa image operation needs review.')
        current_digest = native.digest(path)
        if current_digest not in (operation['beforeSha256'], operation['afterSha256']):
            raise RuntimeError('Kometa shared Compose file was edited; original/candidate retained.')
        if operation['phase'] != 'container-ready':
            if starter.STATE.exists():
                raise RuntimeError('Kometa data handover began before the container refresh completed; retained.')
            current = native.catalog().get('kometa-nas')
            if current and (current['State']['Running'] or current['HostConfig']['RestartPolicy']['Name'] != 'no'):
                raise RuntimeError('Kometa became running/restartable; container replacement deferred.')
            if current_digest != operation['afterSha256']:
                body = native.read(WORK / 'compose.candidate.yaml', 2 * 1024**2)
                if sha(body) != operation['afterSha256']:
                    raise RuntimeError('The retained Kometa candidate changed.')
                native.atomic(path, body, reference=path)
            operation['phase'] = 'compose-installed'; native.atomic(STATE, operation)
            native.held(state['proof'])
            say('Recreating only the stopped Kometa container with the verified source image...')
            compose(native, path, 'create', '--no-build', '--pull', 'never', '--force-recreate', 'kometa')
            rows = native.catalog(); current = rows['kometa-nas']
            if preserve_others(rows) != others:
                raise RuntimeError('An unrelated container changed during Kometa creation; retained for review.')
            local = json.loads(native.run('docker', 'image', 'inspect', current['Image']))[0]
            if current['Image'] != operation['image'] or not cache.same_image(core, expected, local):
                raise RuntimeError('Recreated Kometa does not use the exact verified frozen image.')
            if current['Mounts'] != old['Mounts']:
                raise RuntimeError('Recreated Kometa config binding differs; not started.')
            starter.validate_runtime(source, current)
            operation['containerId'] = current['Id']; operation['phase'] = 'container-ready'
            native.atomic(STATE, operation)
        else:
            current = native.catalog()['kometa-nas']
            if current['Id'] != operation['containerId'] or current['Image'] != operation['image']:
                raise RuntimeError('The refreshed Kometa runtime changed; no data handover resumed.')
        native.held(state['proof'])
    # The original worker acquires the same locks. Release them before resuming.
    say('KOMETA SOURCE IMAGE INSTALLED. Resuming the existing frozen configuration/credential handover...')
    starter.worker()


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or not APP.is_mount() or 'inet 192.168.0.220/' not in subprocess.check_output(
            ['ip', '-4', 'addr', 'show'], text=True, timeout=10):
        raise RuntimeError('Run with sudo on the NAS at192.168.0.220.')
    if len(sys.argv) == 3 and sys.argv[1] == '--worker':
        if sha(SELF.read_bytes()) != sys.argv[2]: raise RuntimeError('The pinned Kometa image worker changed.')
        worker(); return
    if sys.argv[1:] or globals().get('REFRESH_APPROVED_KOMETA_IMAGE') is not True:
        raise RuntimeError('The explicit approved Kometa image-refresh flag is required.')
    source = globals().get('INSTALL_SOURCE')
    if not isinstance(source, str): raise RuntimeError('The exact installer source is required.')
    starter = starter_module()
    native = starter.load_module(BASE / 'worker.py', starter.NATIVE_SHA, 'kometa_image_installer')
    native.approved(starter.PLAN_SHA); native.safe(WORK); WORK.mkdir(mode=0o700, exist_ok=True)
    owner = WORK / 'owner.json'
    if owner.exists() and json.loads(native.read(owner)) != {'format': FORMAT}:
        raise RuntimeError('An unrelated Kometa image work folder was retained.')
    if not owner.exists(): native.atomic(owner, {'format': FORMAT})
    encoded = source.encode()
    if SELF.exists() and native.read(SELF) != encoded:
        raise RuntimeError('A different Kometa image worker was retained.')
    if not SELF.exists(): native.atomic(SELF, encoded)
    if native.unit_state('nas-production-kometa-image.service')['ActiveState'] in ('active', 'activating', 'deactivating'):
        raise RuntimeError('Kometa image refresh is already active.')
    native.run('systemd-run', '--unit=nas-production-kometa-image', '--collect',
               '--description=Install exact frozen Kometa image and resume approved handover',
               '--property=Type=exec', '--property=Nice=10', '--property=TimeoutStopSec=30',
               '/usr/bin/python3', str(SELF), '--worker', sha(encoded))
    say('Exact Kometa image refresh/resume started in systemd. Closing SSH is safe.')
    say('Progress: sudo journalctl -fu nas-production-kometa-image.service -n 20 --no-pager -o cat')


if __name__ == '__main__':
    try: main()
    except Exception as exc:
        raise SystemExit('STOP: ' + (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__))
