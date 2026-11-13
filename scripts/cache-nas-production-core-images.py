#!/usr/bin/env python3
"""Cache exact source images by saved digest; never deploy or change live tags."""
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

BASE = Path('/srv/dev-disk-by-uuid-631e3391-6a42-4158-9aa4-f7718ba0e7e9/migration/production-handover/core-preparation')
CORE = BASE / 'worker.py'
CORE_SHA = 'f9ebaa67446d43e93cdbf4ee3088fb326b09bf6656c4ad13ee7142d0d92f8b84'
WORKER = BASE / 'cache-source-images.py'
UNIT = 'nas-production-core-images.service'
BACKUP_LOCK = Path('/run/lock/sawdoctor-nas-backup.lock')
FORMAT = 'sawdoctor-source-core-image-cache-v1'
PULL_REPOSITORIES = {'sonarr': 'lscr.io/linuxserver/sonarr',
                     'radarr': 'lscr.io/linuxserver/radarr',
                     'radarr4k': 'lscr.io/linuxserver/radarr',
                     'prowlarr': 'ghcr.io/hotio/prowlarr'}


def helper():
    if any(p.is_symlink() for p in (CORE, *CORE.parents)) or hashlib.sha256(CORE.read_bytes()).hexdigest() != CORE_SHA:
        raise RuntimeError('The accepted private-core preparer differs; it was retained.')
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('accepted_core_preparer', CORE)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def same_image(core, source, nas):
    if not core.image_content_matches(source, nas):
        return False
    # Match runtime configuration too: identical layers alone are insufficient.
    a, b = source.get('Config') or {}, nas.get('Config') or {}
    fields = ('Env', 'Cmd', 'Entrypoint', 'User', 'WorkingDir', 'Volumes',
              'ExposedPorts', 'Labels', 'Shell', 'StopSignal', 'Healthcheck', 'OnBuild')
    return all((a.get(key) or None) == (b.get(key) or None) for key in fields)


def saved_digest(name, image):
    repository = PULL_REPOSITORIES.get(name)
    if not repository:
        raise RuntimeError('An additional source image needs separate review: ' + name)
    matches = sorted({value for value in image.get('RepoDigests', [])
                      if re.fullmatch(re.escape(repository) + r'@sha256:[a-f0-9]{64}', value)})
    if len(matches) != 1:
        raise RuntimeError('An exact saved registry digest is unavailable or ambiguous: ' + name)
    return matches[0]


def inventory(core):
    ids = sorted(set(core.run('docker', 'image', 'ls', '--all', '--quiet', '--no-trunc').split()))
    if not ids or len(ids) > 500 or any(not re.fullmatch(r'sha256:[a-f0-9]{64}', value) for value in ids):
        raise RuntimeError('The local Docker image inventory exceeds its bound.')
    return {row['Id']: row for row in json.loads(core.run('docker', 'image', 'inspect', *ids))}


def tag_bindings(images, references):
    return {ref: sorted(key for key, row in images.items() if ref in (row.get('RepoTags') or []))
            for ref in references}


def containers(core):
    rows = json.loads(core.run('docker', 'inspect', *core.NAMES.values()))
    return {row['Name'].lstrip('/'): {**core.fingerprint(row),
            'startedAt': row['State'].get('StartedAt'), 'restartCount': row.get('RestartCount'),
            'running': row['State'].get('Running'), 'status': row['State'].get('Status'),
            'finishedAt': row['State'].get('FinishedAt'),
            'restartPolicy': row['HostConfig']['RestartPolicy']} for row in rows}


def pull(core, name, reference, platform, folder):
    core.say('Caching exact recorded source image: ' + name + ' (' + platform + ')...')
    log = folder / ('pull-' + name + '.log'); core.safe(log)
    with log.open('wb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        with subprocess.Popen(['docker', 'image', 'pull', '--platform', platform, reference],
                              stdout=stream, stderr=subprocess.STDOUT) as process:
            deadline = time.monotonic() + 1800
            try:
                while True:
                    try:
                        code = process.wait(timeout=30)
                        break
                    except subprocess.TimeoutExpired:
                        if time.monotonic() >= deadline:
                            raise RuntimeError('The exact image download exceeded its time limit: ' + name)
                        core.say('Still caching recorded source image: ' + name + '...')
                if code:
                    raise RuntimeError('The exact image download failed for ' + name + '; private download log retained.')
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill(); process.wait(timeout=10)


def stage(core):
    with contextlib.ExitStack() as stack:
        for path in (BASE / '.run.lock', BACKUP_LOCK, core.STANDBY / '.run.lock'):
            core.safe(path); stream = stack.enter_context(path.open('a'))
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError('NAS backup/receive/preparation is busy; cached data retained.') from None
        source, record, manifest = core.snapshot()
        candidate = BASE / record['createdUtc']
        plan_file = candidate / 'plan.json'
        plan = json.loads(core.read(plan_file))
        if (plan.get('candidateOnly') is not True or plan.get('sourceArchiveSha256') != record['sha256']
                or plan.get('sourceCreatedUtc') != record['createdUtc']):
            raise RuntimeError('A completed private core plan for the current snapshot is required.')
        source_rows = {row['Name'].lstrip('/'): row for row in manifest['containers']}
        source_images = {row['Id']: row for row in manifest['images']}
        images = inventory(core); before = containers(core)
        references = sorted({source_rows[name]['Config']['Image'] for name in core.NAMES})
        before_tags = tag_bindings(images, references)
        requests = {}
        expected = {name: source_images[source_rows[name]['Image']] for name in core.NAMES}
        for name, image in expected.items():
            if image.get('Os') != 'linux' or image.get('Architecture') != 'amd64' or image.get('Variant'):
                raise RuntimeError('A source image platform requires separate review: ' + name)
            if not any(same_image(core, image, value) for value in images.values()):
                reference = saved_digest(name, image)
                requests.setdefault(reference, (name, image))
        docker_root = Path(json.loads(core.run('docker', 'info', '--format', '{{json .DockerRootDir}}'))).resolve(strict=True)
        required = 2 * 1024**3 + sum(max(0, int(image.get('Size', 0))) * 2 for _, image in requests.values())
        if shutil.disk_usage(docker_root).free < required:
            raise RuntimeError('The Docker image filesystem lacks the download/reserve space bound.')
        folder = candidate / 'image-cache'; core.safe(folder)
        folder.mkdir(mode=0o700, exist_ok=True)
        marker = folder / 'owner.json'
        identity = {'format': FORMAT, 'sourceArchiveSha256': record['sha256']}
        if marker.exists():
            if json.loads(core.read(marker)) != identity:
                raise RuntimeError('A different image-cache record was retained.')
        elif list(folder.iterdir()):
            raise RuntimeError('An unrecognized image-cache folder was retained.')
        else:
            core.atomic(marker, identity)
        for reference, (name, expected_image) in requests.items():
            pull(core, name, reference, 'linux/amd64', folder)
            downloaded = json.loads(core.run('docker', 'image', 'inspect', reference))
            if len(downloaded) != 1 or not same_image(core, expected_image, downloaded[0]):
                raise RuntimeError('A cached image configuration/layer/platform differs from the source: ' + name)
            images[downloaded[0]['Id']] = downloaded[0]
        images = inventory(core)
        result = {}
        for name, image in expected.items():
            matches = sorted(key for key, row in images.items() if same_image(core, image, row))
            if not matches:
                raise RuntimeError('A verified source-equivalent image is missing: ' + name)
            result[name] = {'sourceImage': source_rows[name]['Image'], 'sourceReference': source_rows[name]['Config']['Image'],
                            'nasImage': matches[0], 'sourceMetadataSha256': hashlib.sha256(json.dumps(image, sort_keys=True).encode()).hexdigest()}
        if containers(core) != before or tag_bindings(images, references) != before_tags:
            raise RuntimeError('A running container or existing source tag changed during staging; cached images retained for review.')
        core.atomic(folder / 'result.json', {'format': FORMAT, 'sourceCreatedUtc': record['createdUtc'],
                    'sourceArchiveSha256': record['sha256'], 'corePlanSha256': core.digest(plan_file),
                    'images': result, 'downloadedUniqueImages': len(requests), 'candidateOnly': True,
                    'sourceHeld': False, 'activationImplemented': False})
        core.say('SOURCE CORE IMAGES CACHED AND VERIFIED: ' + str(len(result)) + ' applications; ' + str(len(requests)) + ' unique images downloaded.')
        core.say('Image runtime configuration, layers and platform match the recorded source. Current containers and existing tags retained.')
        core.say('Private data/Compose plan retained. Final frozen transfer, import and activation are still required.')
        core.say('Image mapping: ' + str(folder / 'result.json'))


def main():
    os.umask(0o077); core = helper()
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in core.run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the NAS.')
    if not core.APP.is_mount() or not core.BACKUP.is_mount():
        raise RuntimeError('The existing application and backup SSD mounts are required.')
    core.owner()
    if sys.argv[1:] == ['--worker']:
        stage(core); return
    if sys.argv[1:]:
        raise RuntimeError('Image caching has no activation arguments.')
    if subprocess.run(['systemctl', 'is-active', '--quiet', UNIT], capture_output=True).returncode == 0:
        core.say('Source image caching is already running; check its journal.'); return
    source = globals().get('INSTALL_SOURCE')
    if not isinstance(source, str):
        raise RuntimeError('The complete pinned image-cache installer is required.')
    if WORKER.exists() and core.read(WORKER) != source.encode():
        raise RuntimeError('A different image-cache worker was retained.')
    if not WORKER.exists():
        core.atomic(WORKER, source.encode())
    subprocess.run(['systemctl', 'reset-failed', UNIT], capture_output=True)
    core.run('systemd-run', '--unit=' + UNIT.removesuffix('.service'), '--collect',
             '--description=Cache exact recorded source core images without deploying containers',
             '--property=Type=exec', '--property=UMask=0077', '--property=Nice=10',
             '--property=RuntimeMaxSec=2h', '--property=TimeoutStopSec=30s',
             '/usr/bin/python3', str(WORKER), '--worker')
    core.say('Exact source-image caching started in systemd. Closing SSH is safe.')
    core.say('Progress: sudo journalctl -fu ' + UNIT + ' -n 12 --no-pager -o cat')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('STOP: ' + (str(error) if isinstance(error, RuntimeError)
                         else 'Source image caching failed (' + type(error).__name__ + '); private details withheld.'))
