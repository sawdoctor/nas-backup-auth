#!/usr/bin/env python3
"""Privately read the current image's stock certificate code, never apply it."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

WORK = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6/compose/production-cutover/npm-renewal-handover')
ORIGINAL = WORK / 'worker.py'
ORIGINAL_SHA = '1348d0c2e23b6967d385bc50217ba7fa1ece56b2e686d7a314be363ee9ac7ce5'
OOM = WORK / 'worker-with-oom-defaults.py'
OOM_SHA = 'de276d9ffb8fd895ef58bd9b9828c8125abca30f24d9c3d3f70244560ae172da'
SELF = WORK / 'review-current-stock-module.py'
UNIT = 'nas-current-npm-module-review.service'
REMOTE = 'gdrive:nas-backups/openmediavault/migration-review/nas-npm-current-stock-module-20261118.txt'


class ReviewComplete(Exception):
    pass


def load(path, expected, name):
    if any(p.is_symlink() for p in (path, *path.parents)) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise RuntimeError('A retained pinned NPM handover worker differs; no proxy changed.')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def document(source, package, image):
    metadata = json.loads(package)
    if not isinstance(metadata, dict):
        raise RuntimeError('The current stock package metadata is not an object.')
    text = source.decode('utf-8')
    if len(source) > 1024**2:
        raise RuntimeError('The stock certificate module exceeds its review bound.')
    return {'format': 'sawdoctor-current-npm-stock-module-review-v1', 'image': image,
            'modulePath': '/app/internal/certificate.js', 'moduleSha256': hashlib.sha256(source).hexdigest(),
            'package': {k: metadata.get(k) for k in ('name', 'version', 'type', 'engines')},
            'moduleSource': text}


def configure(module, oom):
    oom.configure(module)
    original_controllers = module.controllers
    original_say = module.say
    captured = {}

    def say(message):
        if message.startswith('NAS NPM renewal handover started in systemd.'):
            message = 'Current-image NPM source review started in systemd. Closing SSH is safe; live proxy remains unchanged.'
        original_say(message)

    def controllers():
        result = original_controllers()
        captured['native'] = result[-1]
        return result

    def capture(source):
        native = captured['native']
        probe_model = module.yaml.safe_load(native.read(WORK / 'unstarted-probe.yaml'))
        probe_name = probe_model['services']['npm']['container_name']
        module.require(re.fullmatch(r'npm-renewal-probe-[a-f0-9]{12}', probe_name), 'The owned unstarted probe name differs.')
        probe = json.loads(module.run(native, 'docker', 'inspect', probe_name))[0]
        module.require(probe['State']['Status'] == 'created' and not probe['State']['Running']
                       and probe['Image'] == module.IMAGE
                       and probe['Config'].get('Labels', {}).get('com.docker.compose.project') == probe_name,
                       'The current-image review probe is not the verified unstarted container.')
        package = module.stock_file(native, probe_name, '/app/package.json')
        proof = document(source, package, probe['Image'])
        payload = (json.dumps(proof, sort_keys=True, indent=2) + '\n').encode()
        target = WORK / 'private-current-stock-module.json'
        native.atomic(target, payload)
        native.run('rclone', '--config', '/root/.config/rclone/rclone.conf', 'copyto', str(target), REMOTE,
                   '--tpslimit', '2', '--retries', '2', '--contimeout', '10s', '--timeout', '45s', timeout=120)
        module.say('CURRENT NPM STOCK MODULE REVIEW: ' + json.dumps({
            'package': proof['package'], 'image': proof['image'], 'moduleSha256': proof['moduleSha256'],
            'privateReviewSha256': hashlib.sha256(payload).hexdigest()}, sort_keys=True))
        # This unwinds the original worker's finally, removing the probe and
        # releasing locks before the outer entry point reports success.
        # It occurs before any live Compose write, state plan or proxy restart.
        raise ReviewComplete()

    module.controllers = controllers
    module.verify_stock = capture
    module.say = say
    module.SELF = SELF
    module.UNIT = UNIT
    return module


def main():
    module = load(ORIGINAL, ORIGINAL_SHA, 'review_pinned_npm')
    module.require(not module.STATE.exists(), 'A live renewal handover state exists; do not replay the pre-change review.')
    oom = load(OOM, OOM_SHA, 'review_pinned_oom')
    configure(module, oom)
    if sys.argv[1:] != ['--worker']:
        module.require(globals().get('REVIEW_CURRENT_NPM_MODULE') is True, 'The current-image review flag is required.')
    module.INSTALL_SOURCE = globals().get('INSTALL_SOURCE')
    module.RESUME_APPROVED_NPM_RENEWAL = True
    try:
        module.main()
    except ReviewComplete:
        print('CURRENT NPM MODULE REVIEW COMPLETE. Unstarted probe removed; live proxy, certificates and renewal hold unchanged.', flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        message = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        print('STOP: ' + message + ' Live NPM retained.', flush=True)
        raise SystemExit(1)
