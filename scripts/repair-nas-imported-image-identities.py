#!/usr/bin/env python3
"""Restore recorded registry identities of running imported images, never update apps."""
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys

APP = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
BASE = APP / 'compose/production-cutover'
WORK = BASE / 'image-registry-identities'
SELF = WORK / 'worker.py'
STATE = WORK / 'state.json'
STARTER = BASE / 'kometa-handover/worker.py'
STARTER_SHA = '5a2e0bf3bad87b798efbf82082a155f2cf73f1b835be4560896d527c66405a14'
SUPPORT = APP / 'migration/support-optiplex'
FORMAT = 'sawdoctor-imported-image-registry-identities-v1'
UNIT = 'nas-image-registry-identities.service'
OFFICIAL_IMAGES = {'redis', 'postgres', 'mariadb', 'mysql', 'nginx', 'alpine', 'busybox', 'python', 'node'}


def say(value): print(value, flush=True)
def sha(body): return hashlib.sha256(body).hexdigest()


def load(path, expected, name):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise RuntimeError('A reviewed image helper is symbolic.')
    body = path.read_bytes()
    if sha(body) != expected: raise RuntimeError('A reviewed image helper changed.')
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    exec(compile(body, str(path), 'exec'), value.__dict__)
    return value


def repository(reference):
    if not isinstance(reference, str) or not re.fullmatch(r'[A-Za-z0-9._:/@-]+', reference): return None
    if reference.startswith('sha256:'): return None
    name = reference.split('@', 1)[0]
    if ':' in name.rsplit('/', 1)[-1]: name = name.rsplit(':', 1)[0]
    first = name.split('/', 1)[0]
    if '/' not in name or ('.' not in first and ':' not in first and first != 'localhost'):
        name = 'docker.io/' + name
    for prefix in ('index.docker.io/', 'registry-1.docker.io/'):
        if name.startswith(prefix): name = 'docker.io/' + name[len(prefix):]
    if name.startswith('docker.io/') and '/' not in name[len('docker.io/'):]:
        name = 'docker.io/library/' + name[len('docker.io/'):]
    return name


def digest_reference(reference):
    repo = repository(reference)
    if not repo or not re.fullmatch(r'[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}', reference): return None
    return repo + '@' + reference.rsplit('@', 1)[1]


def tag_reference(reference):
    repo = repository(reference)
    if not repo or '@' in reference: return None
    last = reference.rsplit('/', 1)[-1]
    tag = last.rsplit(':', 1)[1] if ':' in last else 'latest'
    return repo + ':' + tag


def support_manifest(native, core):
    root = SUPPORT / 'snapshot'
    if not root.exists(): return None
    body = native.read(root / 'manifest.json')
    marker = json.loads(native.read(SUPPORT / 'staged.json'))
    found = []
    with (root / 'SHA256SUMS').open('r', encoding='utf-8', errors='surrogateescape') as stream:
        for line in stream:
            if len(line) > 65536: raise RuntimeError('An old support checksum entry exceeds its bound.')
            name, expected = core.parse_checksum(line)
            if name == 'manifest.json': found.append(expected)
    value = json.loads(body)
    if (found != [sha(body)] or value.get('format') != 'sawdoctor-support-export-v1'
            or value.get('sourceHost') != '192.168.0.29' or value.get('createdUtc') != marker.get('createdUtc')
            or not re.fullmatch(r'[a-f0-9]{64}', marker.get('archiveSha256', ''))):
        raise RuntimeError('The retained support image metadata is not the original verified snapshot.')
    return value


def saved_links(image, rows, manifests, core, cache):
    """Only saved source digests for identical content/runtime and known repos."""
    hints = {repository(tag) for tag in image.get('RepoTags') or []}
    hints.update(repository(row['Config']['Image']) for row in rows)
    hints.discard(None)
    service_names = {row['Name'].lstrip('/').removesuffix('-nas') for row in rows}
    aliases = {'seerr': 'overseerr', 'infinidysk': 'nzbdav'}
    service_names.update(aliases.get(name, name) for name in list(service_names))
    for row in rows:
        service = (row['Config'].get('Labels') or {}).get('com.docker.compose.service')
        if service: service_names.add(aliases.get(service, service))
    choices, tags = set(), set()
    for manifest in manifests:
        source_images = {item['Id']: item for item in manifest['images']}
        matching = {identity for identity, candidate in source_images.items()
                    if cache.same_image(core, candidate, image)}
        for source in manifest['containers']:
            if source['Image'] not in matching: continue
            source_repo = repository(source['Config']['Image'])
            if not source_repo: continue
            if (source_repo.startswith('docker.io/library/')
                    and source_repo.removeprefix('docker.io/library/') not in OFFICIAL_IMAGES):
                # Containerd can expose synthetic RepoDigests on locally built
                # images. Do not treat a local Compose build as Docker Hub.
                continue
            # Missing local tags are accepted only with an exact source-service
            # match, not by guessing which repository a bare image ID belongs to.
            if source_repo not in hints and (hints or source['Name'].lstrip('/') not in service_names): continue
            original = source['Config']['Image']
            if '@' not in original and not original.startswith('sha256:'):
                if ':' not in original.rsplit('/', 1)[-1]: original += ':latest'
                tags.add(tag_reference(original))
            for ref in source_images[source['Image']].get('RepoDigests') or []:
                if (re.fullmatch(r'[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}', ref)
                        and repository(ref) == source_repo): choices.add(digest_reference(ref))
    return sorted(choices), sorted(tags)


def tag_plan(identity, references, tags, active_images):
    result, blocked = [], []
    for ref in references:
        owners = tags.get(ref, [])
        if owners == [identity]: continue
        if any(owner != identity and owner in active_images for owner in owners):
            blocked.append(ref); continue
        result.append({'reference': ref, 'beforeImageIds': owners, 'afterImageId': identity})
    return result, blocked


def all_tags(images):
    result = {}
    for identity, image in images.items():
        for tag in image.get('RepoTags') or []: result.setdefault(tag_reference(tag), []).append(identity)
    return {tag: sorted(ids) for tag, ids in result.items()}


def containers_fingerprint(rows):
    return {name: {'id': row['Id'], 'image': row['Image'], 'startedAt': row['State'].get('StartedAt'),
                   'running': row['State']['Running'], 'restartCount': row.get('RestartCount'),
                   'config': sha(json.dumps(row['Config'], sort_keys=True).encode()),
                   'hostConfig': sha(json.dumps(row['HostConfig'], sort_keys=True).encode()),
                   'mounts': sorted((json.dumps(item, sort_keys=True) for item in row['Mounts']))}
            for name, row in rows.items()}


def verify_registry_link(core, cache, before, reference, pulled, after):
    if (pulled['Id'] != before['Id'] or after['Id'] != before['Id']
            or digest_reference(reference) not in {digest_reference(ref) for ref in after.get('RepoDigests') or []}
            or not cache.same_image(core, before, after)):
        raise RuntimeError('A recorded registry digest did not attach to the existing exact image; no container was changed.')


def skip_setting(native, plan):
    path = Path(plan['dockmonDatabase']); native.safe(path)
    with contextlib.closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as db:
        fields = {row[1] for row in db.execute('PRAGMA table_info(global_settings)')}
        if 'skip_compose_containers' not in fields: return None
        row = db.execute('SELECT skip_compose_containers FROM global_settings LIMIT 1').fetchone()
        return bool(row[0]) if row else None


def worker():
    starter = load(STARTER, STARTER_SHA, 'registry_source_proof')
    native = starter.load_module(BASE / 'worker.py', starter.NATIVE_SHA, 'registry_cutover_native')
    with native.lock(BASE / '.run.lock'), native.lock(native.BACKUP_LOCK):
        plan = native.approved(starter.PLAN_SHA); main = json.loads(native.read(native.STATE))
        if main.get('phase') not in ('awaiting-acceptance', 'committed-core'):
            raise RuntimeError('The current imported production core is required.')
        _, manifest, _ = starter.frozen_manifest(native, main)
        native.held(main['proof'])
        h = native.helpers(); core, cache = h['core'], h['cache']
        if any(native.dockmon_notify(Path(plan['dockmonDatabase'])).values()):
            raise RuntimeError('Dockmon automatic installation/restart/pruning must remain disabled.')
        manifests = [manifest]
        legacy = support_manifest(native, core)
        if legacy: manifests.append(legacy)
        rows = native.catalog(); before = containers_fingerprint(rows)
        images = cache.inventory(core); tags_before = all_tags(images)
        wanted = {}
        for row in rows.values(): wanted.setdefault(row['Image'], []).append(row)
        targets, unresolved, known = [], [], []
        for identity, users in wanted.items():
            image = images[identity]; names = sorted(row['Name'].lstrip('/') for row in users)
            choices, original_tags = saved_links(image, users, manifests, core, cache)
            if len(choices) != 1:
                if image.get('RepoDigests'): known.extend(names)
                else: unresolved.append({'containers': names, 'reason': 'no_unique_recorded_digest', 'candidateCount': len(choices)})
                continue
            changes, blocked = tag_plan(identity, original_tags, tags_before, set(wanted))
            if blocked: unresolved.append({'containers': names, 'reason': 'recorded_tag_also_used_by_another_container'})
            if image.get('RepoDigests') and not changes:
                known.extend(names); continue
            if image.get('Os') != 'linux' or image.get('Architecture') != 'amd64' or image.get('Variant'):
                unresolved.append({'containers': names, 'reason': 'unreviewed_platform'}); continue
            targets.append({'imageId': identity, 'containers': names, 'reference': choices[0],
                            'needsRegistryDigest': not bool(image.get('RepoDigests')),
                            'tagChanges': changes, 'status': 'pending'})
        targets.sort(key=lambda item: ('tracearr-nas' not in item['containers'], item['containers']))
        operation = {'format': FORMAT, 'cutoverId': main['proof']['cutoverId'], 'phase': 'working',
                     'alreadyHaveRegistryIdentity': known, 'targets': targets, 'unresolved': unresolved,
                     'originalTagBindings': tags_before,
                     'skipComposeContainers': skip_setting(native, plan), 'applicationsRestarted': 0,
                     'applicationVersionsChanged': 0}
        if STATE.exists():
            previous = native.read(STATE)
            record = json.loads(previous)
            if record.get('format') != FORMAT or record.get('cutoverId') != main['proof']['cutoverId']:
                raise RuntimeError('An unrelated previous registry-identity record was retained.')
            history = WORK / ('previous-' + sha(previous)[:16] + '.json')
            if not history.exists(): native.atomic(history, previous)
            operation['previousRecord'] = str(history)
        native.atomic(STATE, operation)
        say('Registry identity/name repair candidates: ' + str(sum(len(item['containers']) for item in targets))
            + ' containers; missing registry digests on ' + str(sum(len(item['containers']) for item in targets if item['needsRegistryDigest'])) + '.')
        say('Dockmon skip-Compose setting: ' + str(operation['skipComposeContainers']) + '; automatic actions remain off.')
        say('Only original source tags may be reattached to existing running image IDs; old images and prior tag bindings are retained.')
        docker_root = Path(native.run('docker', 'info', '--format', '{{.DockerRootDir}}').strip())
        expected_tags = dict(tags_before)
        for index, item in enumerate(targets, 1):
            identity = item['imageId']; image = images[identity]; size = image.get('Size', 0)
            if item['needsRegistryDigest'] and (not 0 < size < 12 * 1024**3 or shutil.disk_usage(docker_root).free < 2 * size + 4 * 1024**3):
                raise RuntimeError('Exact-image registry metadata refresh lacks its expansion/reserve budget.')
            label = ' / '.join(item['containers'])
            say('Restoring existing registry identity: ' + label + ' (' + str(index) + '/' + str(len(targets)) + ')...')
            # Immutable digest only: this does not move a :latest tag, install
            # newer application code in a container or recreate any service.
            if item['needsRegistryDigest']:
                try:
                    cache.pull(core, 'registry-' + str(index), item['reference'], 'linux/amd64', WORK)
                    pulled = json.loads(native.run('docker', 'image', 'inspect', item['reference']))[0]
                    current = json.loads(native.run('docker', 'image', 'inspect', identity))[0]
                    verify_registry_link(core, cache, image, item['reference'], pulled, current)
                except RuntimeError:
                    if all_tags(cache.inventory(core)) != expected_tags or containers_fingerprint(native.catalog()) != before:
                        raise RuntimeError('The image/container isolation check failed after a registry request.') from None
                    item['status'] = 'unresolved'
                    unresolved.append({'containers': item['containers'], 'reason': 'exact_registry_link_unavailable'})
                    native.atomic(STATE, operation)
                    say('Exact old registry identity unavailable for ' + label + '; keeping its running image and original names.')
                    continue
            if all_tags(cache.inventory(core)) != expected_tags:
                raise RuntimeError('An image tag changed concurrently; no container was recreated.')
            for change in item['tagChanges']:
                # Cached source images were deliberately started by immutable
                # ID. Restore their original name only to that same running
                # ID, never to a newer tag pulled from the registry.
                native.run('docker', 'image', 'tag', identity, change['reference'])
                expected_tags[change['reference']] = [identity]
                say('Original image name restored to the already-running version: ' + change['reference'])
            if all_tags(cache.inventory(core)) != expected_tags:
                raise RuntimeError('The recorded image-name repair did not verify.')
            if containers_fingerprint(native.catalog()) != before:
                raise RuntimeError('A container changed concurrently during metadata repair; current state retained.')
            item['status'] = 'restored'; native.atomic(STATE, operation)
            say('Existing registry identity verified: ' + label)
        if any(native.dockmon_notify(Path(plan['dockmonDatabase'])).values()):
            raise RuntimeError('Dockmon automatic-action settings changed during metadata repair.')
        if containers_fingerprint(native.catalog()) != before or all_tags(cache.inventory(core)) != expected_tags:
            raise RuntimeError('Final running-container/image-tag isolation check failed.')
        operation['phase'] = 'complete'; native.atomic(STATE, operation)
    say('EXISTING IMAGE REGISTRY IDENTITIES/NAMES CHECKED/REPAIRED. Zero application upgrades or restarts.')
    say('Only recorded source names were restored to already-running image IDs; prior tag bindings retained in the operation record.')
    for item in unresolved:
        say('Needs separate identity review: ' + ', '.join(item['containers']) + ' (' + item['reason'] + ')')
    if operation['skipComposeContainers']:
        say('Turn OFF Skip Docker Compose containers before the fleet check; leave every Auto-update switch OFF.')
    say('Now use Dockmon Check All Now, or tracearr-nas / Updates / Check Now. This is detection, not Update Now.')
    say('Operation record: ' + str(STATE))


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or not APP.is_mount() or 'inet 192.168.0.220/' not in subprocess.check_output(['ip', '-4', 'addr', 'show'], text=True, timeout=10):
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220.')
    if len(sys.argv) == 3 and sys.argv[1] == '--worker':
        if sha(SELF.read_bytes()) != sys.argv[2]: raise RuntimeError('The pinned registry identity worker changed.')
        worker(); return
    if sys.argv[1:] or globals().get('REPAIR_APPROVED_IMAGE_IDENTITIES') is not True:
        raise RuntimeError('The approved registry-identity repair flag is required.')
    source = globals().get('INSTALL_SOURCE')
    if not isinstance(source, str): raise RuntimeError('The exact installed source is required.')
    starter = load(STARTER, STARTER_SHA, 'registry_installer')
    native = starter.load_module(BASE / 'worker.py', starter.NATIVE_SHA, 'registry_installer_native')
    native.approved(starter.PLAN_SHA); native.safe(WORK); WORK.mkdir(mode=0o700, exist_ok=True)
    owner = WORK / 'owner.json'
    if owner.exists() and json.loads(native.read(owner)) != {'format': FORMAT}:
        raise RuntimeError('An unrelated registry-identity work folder exists.')
    if not owner.exists(): native.atomic(owner, {'format': FORMAT})
    if native.unit_state(UNIT)['ActiveState'] in ('active', 'activating', 'deactivating'):
        raise RuntimeError('The registry-identity repair is already active.')
    body = source.encode()
    if SELF.exists() and native.read(SELF) != body: raise RuntimeError('A different identity worker was retained.')
    if not SELF.exists(): native.atomic(SELF, body)
    native.run('systemd-run', '--unit=' + UNIT.removesuffix('.service'), '--collect',
               '--description=Restore existing imported image registry identities without app updates',
               '--property=Type=exec', '--property=Nice=10', '--property=TimeoutStopSec=30',
               '/usr/bin/python3', str(SELF), '--worker', sha(body))
    say('Existing image identity repair started in systemd. Closing SSH is safe.')
    say('Progress: sudo journalctl -fu ' + UNIT + ' -n 20 --no-pager -o cat')


if __name__ == '__main__':
    try: main()
    except Exception as error:
        raise SystemExit('STOP: ' + (str(error) if isinstance(error, RuntimeError) else type(error).__name__))
