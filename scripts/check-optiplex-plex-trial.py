#!/usr/bin/env python3
"""Read-only source Plex trial preflight; does not install, stop or schedule anything."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.request
import xml.etree.ElementTree as ET

FILES = {
    '/usr/local/sbin/plex-safe-start': '1cc5fcf6e6d80c87600f7710edd8847d63bb0ac49f7e5b2a32bb9c541c46b0c0',
    '/usr/local/sbin/plex-backup-post': 'aa12775f32f502a3322e36742a344755f6b4fcba4f997dccd87b689514ea29b6',
    '/usr/local/bin/plex-daily-backup.sh': '2b940406adc76ad6a316d5739f4f64c79c0f54cddc54083d4dae4dc27fdd9e66',
    '/usr/local/sbin/media-last-start': 'e73e4d57db65970d91254d294fb112f6afea2c7d5b92f41e29be8da4200c9d59',
    '/usr/local/sbin/media-mount-guard': '911d2873749c688c3ae1e715adc2bdf212d0b0ab09a164f0e424295f49b923aa',
    '/usr/local/sbin/media-mount-watch.sh': '6f05577843fa17ae7db7cb3d6dafdc63cc850f8b4b364f0634957151af99ef6a',
    '/usr/local/sbin/plex-api-watch': '4b497787247ea8f67dbf1063122b0cedeb678962063ba3aa4c033a6e14b61ae7',
    '/usr/local/sbin/tmc-deadlock-watch': '1d90290a712f5b2954603de26848ddf0c3fb14a11618ab38ed49ffd675a63ec0',
    '/usr/local/sbin/docker-postboot-fix': '621f715ff266af3c5a59d892f1ab6ace1cb90905ebb6b2335e15696987a6b0b3',
    '/usr/local/sbin/lan-container-start.sh': '88bf4cef1122615a0c30fcd8adc7334daa853a80fc126d786ae4400a65016afc',
}
UNITS = ('plex-daily-backup.timer', 'plex-daily-backup.service',
         'plex-api-watch.timer', 'plex-api-watch.service',
         'media-mount-guard.timer', 'media-mount-guard.service',
         'media-mount-watch.timer', 'media-mount-watch.service',
         'tmc-deadlock-watch.timer', 'tmc-deadlock-watch.service',
         'media-last-start.service', 'media-stack-boot.service',
         'docker-postboot-fix.service', 'docker-postboot-recover.service',
         'lan-container-start.service', 'nas-migration-standby.timer',
         'nas-migration-standby.service', 'nas-migration-standby-resume.service',
         'nas-migration-standby-retry.service')


def run(*args):
    result = subprocess.run(args, text=True, capture_output=True, timeout=20)
    if result.returncode:
        raise RuntimeError('A read-only source status check failed; command details were not displayed.')
    return result.stdout


def hash_file(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def sessions(config):
    preferences = config / 'Library/Application Support/Plex Media Server/Preferences.xml'
    token = ET.fromstring(preferences.read_bytes()).attrib.get('PlexOnlineToken')
    if not token: return None
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs): return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request('http://127.0.0.1:32400/status/sessions', headers={'X-Plex-Token': token})
    with opener.open(request, timeout=5) as response:
        root = ET.fromstring(response.read(1024 * 1024))
    return len(list(root))


def main():
    if os.geteuid() != 0 or 'inet 192.168.0.29/' not in run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the OptiPlex (sawdoctor@Server), not the NAS.')
    print('Read-only OptiPlex Plex trial checks; all services stay running...', flush=True)
    row = json.loads(run('docker', 'inspect', 'plex'))[0]
    config = next(Path(mount['Source']) for mount in row['Mounts'] if mount['Destination'] == '/config')
    if str(config) != '/home/sawdoctor/docker/plex/config':
        raise RuntimeError('The source Plex configuration path differs; it was retained.')
    try: count = sessions(config)
    except (OSError, ValueError, ET.ParseError): count = None
    print('SOURCE PLEX: ' + json.dumps({'state': row['State']['Status'], 'image': row['Config']['Image'],
        'network': row['HostConfig']['NetworkMode'], 'restart': row['HostConfig']['RestartPolicy']['Name'],
        'activeSessions': count}, sort_keys=True), flush=True)
    changed = []
    for name, expected in FILES.items():
        path = Path(name)
        actual = hash_file(path) if path.is_file() and not path.is_symlink() else None
        status = 'matches copied review' if actual == expected else 'needs review'
        if actual != expected: changed.append(name)
        print('SOURCE HELPER: ' + name + ' | ' + status, flush=True)
    output = run('systemctl', 'show', '--no-pager', '-p', 'Id', '-p', 'LoadState', '-p', 'ActiveState',
                 '-p', 'SubState', '-p', 'MainPID', '-p', 'UnitFileState', *UNITS)
    for group in output.strip().split('\n\n'):
        value = dict(line.split('=', 1) for line in group.splitlines() if '=' in line)
        if value.get('Id'): print('SOURCE UNIT: ' + json.dumps(value, sort_keys=True), flush=True)
    cron = [Path('/etc/crontab')]
    for directory in (Path('/etc/cron.d'), Path('/var/spool/cron/crontabs')):
        if directory.is_dir(): cron.extend(sorted(directory.iterdir()))
    for path in cron:
        if not path.is_file() or path.is_symlink() or path.name.startswith('.'): continue
        lines = [line.strip() for line in path.read_text(errors='replace').splitlines()
                 if line.strip() and not line.lstrip().startswith('#')]
        related = [line for line in lines if re.search(r'(?i)plex|docker|media|backup|restart|reboot', line)]
        helpers = sorted(set(re.findall(r'/usr/local/(?:sbin|bin)/[A-Za-z0-9_.-]+', '\n'.join(related))))
        print('SOURCE CRON: ' + json.dumps({'file': str(path), 'sha256': hash_file(path),
              'relatedLines': len(related), 'referencedLocalHelpers': helpers}, sort_keys=True), flush=True)
    print('SOURCE TRIAL PREFLIGHT: ' + json.dumps({'changedOrMissingHelpers': changed,
        'activePlexSessions': count, 'trialStarted': False, 'servicesChanged': False}, sort_keys=True), flush=True)
    print('No Plex stop, snapshot, timer change or trial was started. No API tokens or cron command values were displayed.', flush=True)


if __name__ == '__main__':
    try: main()
    except RuntimeError as error: raise SystemExit('STOP: ' + str(error))
    except Exception as error: raise SystemExit('STOP: Read-only trial preflight could not finish (' + type(error).__name__ + '); no services were changed.') from None
