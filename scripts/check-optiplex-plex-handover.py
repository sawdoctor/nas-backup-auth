#!/usr/bin/env python3
"""Read current Plex handover inputs without stopping or changing services."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import urllib.request
import xml.etree.ElementTree as ET

HELPERS = (
    '/usr/local/sbin/nas-plex-trial',
    '/usr/local/sbin/plex-safe-start',
    '/usr/local/sbin/plex-safe-restart',
    '/usr/local/sbin/plex-backup-post',
    '/usr/local/bin/plex-daily-backup.sh',
    '/usr/local/sbin/media-last-start',
    '/usr/local/sbin/media-mount-guard',
    '/usr/local/sbin/media-mount-watch.sh',
    '/usr/local/sbin/media-mount-recover.sh',
    '/usr/local/sbin/plex-api-watch',
    '/usr/local/sbin/tmc-deadlock-watch',
    '/usr/local/sbin/docker-postboot-fix',
    '/usr/local/sbin/lan-container-start.sh',
    '/usr/local/sbin/nas-migration-standby',
)


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise RuntimeError('A read-only host query failed; private output was withheld.')
    return result.stdout


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def main():
    if os.geteuid() != 0 or 'inet 192.168.0.29/' not in run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the OptiPlex, SSH port48222.')
    row = json.loads(run('docker', 'inspect', 'plex'))[0]
    config = next(Path(m['Source']) for m in row['Mounts'] if m['Destination'] == '/config')
    if config != Path('/home/sawdoctor/docker/plex/config') or config.is_symlink():
        raise RuntimeError('The source Plex configuration path differs; it was retained.')
    print('SOURCE PLEX: ' + json.dumps({
        'state': row['State']['Status'], 'image': row['Config']['Image'], 'imageId': row['Image'],
        'network': row['HostConfig']['NetworkMode'], 'restart': row['HostConfig']['RestartPolicy']}, sort_keys=True), flush=True)
    try:
        prefs = config / 'Library/Application Support/Plex Media Server/Preferences.xml'
        token = ET.fromstring(prefs.read_bytes()).get('PlexOnlineToken')
        if not token:
            raise RuntimeError('No local Plex API token')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        request = urllib.request.Request('http://127.0.0.1:32400/status/sessions', headers={'X-Plex-Token': token})
        with opener.open(request, timeout=5) as response:
            data = response.read(1024**2 + 1)
        if len(data) > 1024**2:
            raise RuntimeError('Session response exceeds bound')
        print('ACTIVE PLEX SESSIONS: ' + str(len(ET.fromstring(data))), flush=True)
    except Exception as error:
        print('ACTIVE PLEX SESSIONS: unavailable (' + type(error).__name__ + '); no stop attempted.', flush=True)
    print('Current source helper SHA256 values:', flush=True)
    for name in HELPERS:
        path = Path(name)
        identity = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() and not path.is_symlink() else 'missing-or-symbolic'
        print(identity + '  ' + name, flush=True)
    print('Backup and standby source state:', flush=True)
    print(run('systemctl', 'show', 'plex-daily-backup.service', 'nas-migration-standby.service', '--no-pager',
              '-p', 'Id', '-p', 'ActiveState', '-p', 'Result', '-p', 'ExecMainExitTimestamp'), end='', flush=True)
    pending = ('/var/lib/sawdoctor-plex-trial/hold.json',
               '/var/lib/sawdoctor-migration-standby/resume.json',
               '/var/lib/sawdoctor-migration-standby/paused-timers.json', '/run/plex-daily-backup-active')
    print('Existing hold/pending-recovery paths: ' + json.dumps([p for p in pending if Path(p).exists()]), flush=True)
    print(run('df', '-h', '/'), end='', flush=True)
    print('READ-ONLY PLEX HANDOVER CHECK COMPLETE. No stop, snapshot, timer, configuration or routing change was made.', flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('STOP: ' + (str(error) if isinstance(error, RuntimeError)
                                   else 'Read-only handover check failed (' + type(error).__name__ + '); details withheld.'))
