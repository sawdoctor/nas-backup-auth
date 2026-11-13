#!/usr/bin/env python3
"""Check a prepared NAS handoff before explicitly launching the source hold.

Does not install or modify the accepted source controller or its prepared plan.
Invocation is an outage action; provide --hold and the NAS preparation token
only after the user approves the concrete source/NAS cutover window.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

BASE = Path('/var/lib/sawdoctor-production-cutover')
WORKER = BASE / 'worker.py'
WORKER_SHA = 'fff1bf3685eea21660fb669e281c467c03d1a66be12e8b9475a1520a9fef13f4'
NAMES = {'plex', 'nzbdav', 'sonarr', 'radarr', 'radarr4k', 'prowlarr', 'usenet-ultimate', 'overseerr'}


def validate(token, plan_data, worker_data):
    if len(token) > 8192: raise RuntimeError('The NAS readiness token exceeds its bound.')
    try: ready = json.loads(base64.b64decode(token, altchars=b'-_', validate=True))
    except (ValueError, UnicodeError): raise RuntimeError('The NAS readiness token is invalid.') from None
    if (ready.get('format') != 'sawdoctor-nas-production-cutover-v1'
            or any(not re.fullmatch('[a-f0-9]{64}', ready.get(k, '')) for k in ('nasPlanSha256', 'sourcePlanSha256'))
            or set(ready.get('sourceImages', {})) != NAMES):
        raise RuntimeError('The complete prepared NAS controller handoff is required.')
    if hashlib.sha256(worker_data).hexdigest() != WORKER_SHA:
        raise RuntimeError('The installed source controller differs; production retained.')
    if hashlib.sha256(plan_data).hexdigest() != ready['sourcePlanSha256']:
        raise RuntimeError('The NAS and source preparation plan digests disagree; production retained.')
    plan = json.loads(plan_data)
    if plan.get('format') != 'sawdoctor-production-cutover-v1' or plan.get('workerSha256') != WORKER_SHA:
        raise RuntimeError('The source prepared plan/controller identity differs.')
    if any(plan['catalog'][name]['Image'] != image for name, image in ready['sourceImages'].items()):
        raise RuntimeError('A source image changed since the NAS cache mapping; no outage was started.')
    return ready['sourcePlanSha256']


def main():
    if os.geteuid() != 0 or 'inet 192.168.0.29/' not in subprocess.check_output(['ip', '-4', 'addr', 'show'], text=True):
        raise RuntimeError('Run with sudo on the OptiPlex.')
    args = sys.argv[1:]
    if len(args) != 2 or args[0] != '--hold':
        raise RuntimeError('This is the outage launcher. Explicit approval and --hold NAS_READINESS_TOKEN are required.')
    for path in (WORKER, BASE / 'plan.json'):
        if any(p.is_symlink() for p in (path, *path.parents)): raise RuntimeError('A symbolic source control path was retained.')
    digest = validate(args[1], (BASE / 'plan.json').read_bytes(), WORKER.read_bytes())
    subprocess.run(['/usr/bin/python3', str(WORKER), '--hold', digest], check=True)


if __name__ == '__main__':
    try: main()
    except Exception as error:
        raise SystemExit('STOP: ' + (str(error) if isinstance(error, RuntimeError) else 'The source approval handoff failed; private details withheld.'))
