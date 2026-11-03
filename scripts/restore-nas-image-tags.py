#!/usr/bin/env python3
"""Restore original readable image references in three adopted Dockmon stacks."""
import copy
import fcntl
import json
import os
from pathlib import Path
import subprocess
import tempfile
import yaml

SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
STACKS = SSD / 'appdata/dockmon/stacks'
RECOVERY = SSD / 'compose/dockmon-adoption/recovery/image-tags'
LOCK = Path('/run/lock/sawdoctor-nas-backup.lock')
REFERENCES = {
    'abr-shelfmark-bridge': 'abr-shelfmark-bridge:local',
    'audiobookrequest': 'markbeep/audiobookrequest:1',
    'audiobookshelf-test': 'ghcr.io/advplyr/audiobookshelf:latest',
    'kavita': 'ghcr.io/kareadita/kavita:latest',
    'sabnzbd-ebooks': 'lscr.io/linuxserver/sabnzbd:latest',
    'shelfmark-ebooks': 'ghcr.io/calibrain/shelfmark:v1.4.0',
    'shelfmark-torbox': 'ghcr.io/sawdoctor/shelfmark-torbox:0.1.0-torbox.1',
    'stackarr-ebooks': 'ghcr.io/sawdoctor/libraseer:latest',
    'torbox-media-center': 'ghcr.io/torbox-app/torbox-media-center:main',
    'glances': 'nicolargo/glances:latest',
    'homepage': 'ghcr.io/gethomepage/homepage:latest',
    'houndarr': 'ghcr.io/av1155/houndarr:latest',
    'kometa': 'kometateam/kometa:latest',
    'speedtest-tracker': 'lscr.io/linuxserver/speedtest-tracker:latest',
    'tracearr': 'ghcr.io/connorgallopo/tracearr:latest',
    'tracearr-db': 'timescale/timescaledb:latest-pg16',
    'tracearr-redis': 'redis:7-alpine',
    'uptime-kuma': 'louislam/uptime-kuma:2',
    'wizarr': 'ghcr.io/wizarrrr/wizarr:latest',
}
PROJECTS = {
    'books-nas': ('books-optiplex', ('abr-shelfmark-bridge', 'audiobookrequest',
        'audiobookshelf-test', 'kavita', 'sabnzbd-ebooks', 'shelfmark-ebooks',
        'shelfmark-torbox', 'stackarr-ebooks')),
    'support-nas': ('support-optiplex', ('glances', 'homepage', 'houndarr',
        'kometa', 'speedtest-tracker', 'tracearr', 'tracearr-db', 'tracearr-redis',
        'uptime-kuma', 'wizarr')),
    'torbox-media-center-nas': ('books-optiplex', ('torbox-media-center',)),
}


def say(message):
    print(message, flush=True)


def run(*args):
    result = subprocess.run(args, text=True, capture_output=True, timeout=90)
    if result.returncode:
        raise RuntimeError('Local Docker validation failed; command output was withheld to protect settings.')
    return result.stdout


def atomic(path, data, mode=0o600):
    if path.is_symlink():
        raise RuntimeError('Unexpected symbolic output path: ' + str(path))
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            temporary.chmod(mode)
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def image(reference, optional=False):
    result = subprocess.run(['docker', 'image', 'inspect', reference],
                            text=True, capture_output=True, timeout=30)
    if optional and result.returncode and 'no such image' in result.stderr.lower():
        return None
    if result.returncode:
        raise RuntimeError('Could not inspect a local image: ' + reference)
    return json.loads(result.stdout)[0]


def model(project, path):
    return json.loads(run('docker', 'compose', '-p', project,
        '--project-directory', str(path.parent), '--profile', '*',
        '-f', str(path), 'config', '--format', 'json'))


def runtime():
    ids = run('docker', 'ps', '-aq').split()
    containers = json.loads(run('docker', 'inspect', *ids)) if ids else []
    return {item['Name'].lstrip('/'): item for item in containers}


def fingerprint(containers):
    return {name: (item['Id'], item['Image'], item['State']['StartedAt'],
                   item['State']['Status']) for name, item in containers.items()}


def prepare(project, bundle, names, containers):
    path = STACKS / project / 'compose.yaml'
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('The adopted Dockmon stack is unavailable: ' + project)
    original = path.read_bytes()
    document = yaml.safe_load(original)
    if set(document.get('services', {})) != set(names):
        raise RuntimeError('The stack service list has changed: ' + project)
    manifest = json.loads((SSD / 'migration' / bundle / 'snapshot/manifest.json').read_text())
    sources = {item['Name'].lstrip('/'): item for item in manifest['containers']}
    identities = json.loads((SSD / 'compose' / project / 'image-identities.json').read_text())
    replacement = copy.deepcopy(document)
    tags = {}
    for name in names:
        reference = REFERENCES[name]
        source = sources[name]
        current = containers[name + '-nas']
        labels = current['Config'].get('Labels') or {}
        service = document['services'][name]
        identity = identities[name]
        if (source['Config']['Image'] != reference or identity['source'] != source['Image']
                or identity['nas'] != current['Image']
                or labels.get('com.docker.compose.project') != project
                or labels.get('com.docker.compose.service') != name
                or service.get('container_name') != name + '-nas'):
            raise RuntimeError('The verified source/running image mapping differs: ' + name)
        if image(service['image'])['Id'] != current['Image']:
            raise RuntimeError('The configured image differs from the running image: ' + name)
        existing = image(reference, optional=True)
        if existing and existing['Id'] != current['Image']:
            raise RuntimeError('An existing local tag points to another image; it was retained: ' + reference)
        if name == 'kometa' and ('plex-cutover' not in service.get('profiles', [])
                                 or current['State']['Running']):
            raise RuntimeError('Kometa must remain stopped behind its Plex cutover profile.')
        replacement['services'][name]['image'] = reference
        if not existing:
            tags[reference] = current['Image']
    text = yaml.safe_dump(replacement, sort_keys=False, allow_unicode=True).encode()
    with tempfile.NamedTemporaryFile(dir=path.parent, suffix='.yaml', delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(text)
            stream.flush()
            temporary.chmod(0o600)
            before = model(project, path)
            expected = copy.deepcopy(before)
            for name in names:
                expected['services'][name]['image'] = REFERENCES[name]
            if model(project, temporary) != expected:
                raise RuntimeError('Compose validation changed settings beyond image references: ' + project)
        finally:
            temporary.unlink(missing_ok=True)
    return {'project': project, 'path': path, 'original': original, 'text': text,
            'mode': path.stat().st_mode & 0o777, 'tags': tags, 'names': names}


def apply(plans, containers):
    RECOVERY.mkdir(mode=0o700, parents=True, exist_ok=True)
    if RECOVERY.is_symlink():
        raise RuntimeError('Unexpected symbolic recovery directory.')
    changed = []
    for plan in plans:
        backup = RECOVERY / (plan['project'] + '.before.yaml')
        if not backup.exists():
            atomic(backup, plan['original'])
        if backup.is_symlink():
            raise RuntimeError('Unexpected symbolic recovery file.')
    try:
        for plan in plans:
            for reference, image_id in plan['tags'].items():
                # Recheck at the point of mutation; never replace another tag.
                existing = image(reference, optional=True)
                if existing and existing['Id'] != image_id:
                    raise RuntimeError('A local tag changed during preparation: ' + reference)
                if not existing:
                    run('docker', 'image', 'tag', image_id, reference)
            if plan['path'].read_bytes() != plan['original']:
                raise RuntimeError('A Dockmon stack was edited during preparation; retry after editing is finished.')
            changed.append(plan)
            atomic(plan['path'], plan['text'], plan['mode'])
        if fingerprint(runtime()) != fingerprint(containers):
            raise RuntimeError('Container state changed during the operation; Compose edits were rolled back.')
    except BaseException:
        for plan in reversed(changed):
            if plan['path'].read_bytes() == plan['text']:
                atomic(plan['path'], plan['original'], plan['mode'])
        raise
    for plan in plans:
        say(plan['project'] + ': original image tags restored (' + str(len(plan['names'])) + ' services).')
    say('DOCKMON IMAGE TAGS RESTORED. All 19 source image references are readable again.')
    say('Existing containers, installed images, start times and Kometa cutover profile are unchanged.')
    say('Custom build versions and database majors retained. No image downloads or redeployments were performed.')
    say('Private Compose recovery copies: ' + str(RECOVERY))


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or not SSD.is_mount() or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220 with its application SSD mounted.')
    say('Waiting for the NAS backup lock...')
    with LOCK.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        containers = runtime()
        plans = []
        for project, (bundle, names) in PROJECTS.items():
            say('Checking image identities and Compose settings: ' + project)
            plans.append(prepare(project, bundle, names, containers))
        apply(plans, containers)


if __name__ == '__main__':
    try:
        main()
    except RuntimeError as error:
        raise SystemExit('STOP: ' + str(error))
    except Exception as error:
        raise SystemExit('STOP: Local validation could not finish (' + type(error).__name__
                         + '); configuration values were withheld.')
