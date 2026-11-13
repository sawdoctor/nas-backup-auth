#!/usr/bin/env python3
"""Report only image versions and local source-equivalent images; no mutations."""
import json
import os
from pathlib import Path
import re
import subprocess

BACKUP = Path('/srv/dev-disk-by-uuid-631e3391-6a42-4158-9aa4-f7718ba0e7e9')
STANDBY = BACKUP / 'migration/nightly-standby'
BASE = BACKUP / 'migration/production-handover/core-preparation'
NAMES = {'sonarr': 'sonarr-nas', 'radarr': 'radarr-nas',
         'radarr4k': 'radarr4k-nas', 'prowlarr': 'prowlarr-nas'}
VERSION_LABELS = ('build_version', 'org.opencontainers.image.version',
                  'org.label-schema.version')


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError('A read-only Docker query failed; private output withheld.')
    return result.stdout


def read(path):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise RuntimeError('An unexpected symbolic report input was retained.')
    if not path.is_file() or path.stat().st_size > 16 * 1024**2:
        raise RuntimeError('A bounded preparation report is unavailable.')
    return json.loads(path.read_bytes())


def signature(image):
    layers = image.get('RootFS', {}).get('Layers')
    if not layers or not image.get('Os') or not image.get('Architecture'):
        return None
    return image['Os'], image['Architecture'], image.get('Variant') or '', tuple(layers)


def version(image):
    labels = image.get('Config', {}).get('Labels') or {}
    return {key: str(labels[key])[:500] for key in VERSION_LABELS if key in labels}


def report():
    current = read(BASE / 'current.json')
    stamp = current.get('sourceCreatedUtc', '')
    if not re.fullmatch(r'\d{8}T\d{6}Z', stamp):
        raise RuntimeError('The completed private candidate identity differs.')
    candidate = BASE / stamp
    if current.get('candidate') != str(candidate):
        raise RuntimeError('The private candidate path differs.')
    plan = read(candidate / 'plan.json')
    verified = read(STANDBY / 'snapshots' / stamp / '_VERIFIED.json')
    if (plan.get('candidateOnly') is not True or plan.get('sourceCreatedUtc') != stamp
            or plan.get('sourceArchiveSha256') != current.get('sourceArchiveSha256')
            or verified.get('sha256') != current.get('sourceArchiveSha256')
            or verified.get('createdUtc') != stamp):
        raise RuntimeError('The completed plan and verified standby identities differ.')
    manifest = read(STANDBY / 'snapshots' / stamp / 'manifest.json')
    if manifest.get('createdUtc') != stamp or manifest.get('sourceHost') != '192.168.0.29':
        raise RuntimeError('The selected source image metadata differs.')
    sources = {row['Name'].lstrip('/'): row for row in manifest['containers']}
    source_images = {row['Id']: row for row in manifest['images']}
    nas = {row['Name'].lstrip('/'): row for row in json.loads(run('docker', 'inspect', *NAMES.values()))}
    ids = sorted(set(run('docker', 'image', 'ls', '--all', '--quiet', '--no-trunc').split()))
    if not ids or len(ids) > 500 or any(not re.fullmatch(r'sha256:[a-f0-9]{64}', value) for value in ids):
        raise RuntimeError('The local image inventory exceeds the bounded report.')
    local = {row['Id']: row for row in json.loads(run('docker', 'image', 'inspect', *ids))}
    print('Prepared application snapshot: ' + stamp, flush=True)
    for name, nas_name in NAMES.items():
        source = source_images[sources[name]['Image']]
        target = local[nas[nas_name]['Image']]
        wanted = signature(source)
        matches = sorted(key for key, value in local.items() if wanted and signature(value) == wanted)
        print(json.dumps({'application': name,
                          'sourceImage': sources[name]['Config']['Image'], 'sourceVersion': version(source),
                          'nasImage': nas[nas_name]['Config']['Image'], 'nasVersion': version(target),
                          'sourceEquivalentLocalImageIds': matches}, sort_keys=True), flush=True)
    print('READ-ONLY IMAGE COMPARISON COMPLETE. No pull, load, tag, restart, database or configuration change.', flush=True)


if __name__ == '__main__':
    try:
        if os.geteuid() != 0 or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show'):
            raise RuntimeError('Run with sudo on the NAS.')
        if not BACKUP.is_mount():
            raise RuntimeError('The backup SSD is not mounted.')
        report()
    except Exception as error:
        raise SystemExit('STOP: ' + (str(error) if isinstance(error, RuntimeError)
                         else 'Read-only image report failed (' + type(error).__name__ + '); private details withheld.'))
