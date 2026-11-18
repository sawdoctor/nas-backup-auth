#!/usr/bin/env python3
"""Resume the pinned NPM handover with one nullable Docker boolean normalized."""
import hashlib
import importlib.util
import json
from pathlib import Path

WORK = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6/compose/production-cutover/npm-renewal-handover')
ORIGINAL = WORK / 'worker.py'
ORIGINAL_SHA = '1348d0c2e23b6967d385bc50217ba7fa1ece56b2e686d7a314be363ee9ac7ce5'
SELF = WORK / 'worker-with-oom-defaults.py'
UNIT = 'nas-production-npm-renewal-resume.service'


def configure(module):
    original_signature = module.runtime_signature

    def signature(row):
        value = row['HostConfig'].get('OomKillDisable')
        module.require(value is None or type(value) is bool,
                       'Docker OomKillDisable has an unexpected non-boolean representation; runtime retained.')
        result = original_signature(row)
        result['host']['OomKillDisable'] = False if value is None else value
        module.say('NPM OOM POLICY (read-only): ' + json.dumps({
            'container': row.get('Name'), 'configuredDisable': value,
            'effectiveDisable': result['host']['OomKillDisable']}, sort_keys=True))
        return result

    module.runtime_signature = signature
    module.SELF = SELF
    module.UNIT = UNIT
    return module


def main():
    if any(p.is_symlink() for p in (ORIGINAL, *ORIGINAL.parents)):
        raise RuntimeError('The retained original renewal worker path is symbolic.')
    data = ORIGINAL.read_bytes()
    if hashlib.sha256(data).hexdigest() != ORIGINAL_SHA:
        raise RuntimeError('The retained original renewal worker differs; no proxy changed.')
    spec = importlib.util.spec_from_file_location('original_current_npm_renewal', ORIGINAL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    configure(module)
    module.INSTALL_SOURCE = globals().get('INSTALL_SOURCE')
    module.RESUME_APPROVED_NPM_RENEWAL = globals().get('RESUME_APPROVED_NPM_RENEWAL')
    module.main()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        message = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        print('STOP: ' + message + ' Current certificates, data and source freeze retained.', flush=True)
        raise SystemExit(1)
