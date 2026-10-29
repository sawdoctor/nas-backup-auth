#!/usr/bin/env python3
"""Authorise NAS GDrive by pasting Google's loopback response into the terminal."""
import base64
import configparser
import datetime
import fcntl
import getpass
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import secrets
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request


def config_from(raw):
    result = configparser.ConfigParser(interpolation=None)
    result.read_string(raw.decode())
    return result


def save_config(path, cfg):
    buffer = io.StringIO()
    cfg.write(buffer)
    fd, name = tempfile.mkstemp(prefix='.nas-gdrive-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(buffer.getvalue())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def callback_code(address, state):
    parsed = urllib.parse.urlsplit(address.strip())
    if (parsed.scheme != 'http' or parsed.hostname != '127.0.0.1'
            or parsed.port != 53682 or parsed.path != '/'
            or parsed.username or parsed.password or parsed.fragment):
        raise RuntimeError('Paste the complete final http://127.0.0.1:53682/ address from Chrome.')
    values = urllib.parse.parse_qs(parsed.query)
    received_state = values.get('state', [])
    if len(received_state) != 1 or not secrets.compare_digest(received_state[0], state):
        raise RuntimeError('That address belongs to another sign-in attempt; use the new link above.')
    if 'error' in values:
        raise RuntimeError('Google approval was declined. Rerun when ready to approve it.')
    codes = values.get('code', [])
    if len(codes) != 1 or not codes[0]:
        raise RuntimeError('The final address has no Google authorization code.')
    return codes[0]


def authorise_without_tunnel(cfg):
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    redirect = 'http://127.0.0.1:53682/'
    params = dict(client_id=cfg.get('gdrive', 'client_id'), redirect_uri=redirect,
                  response_type='code', scope='https://www.googleapis.com/auth/drive',
                  access_type='offline', prompt='consent', state=state,
                  code_challenge=challenge, code_challenge_method='S256')
    print('\nOpen this Google link in your usual browser and approve access:\n', flush=True)
    print('https://accounts.google.com/o/oauth2/v2/auth?' + urllib.parse.urlencode(params), flush=True)
    print('\nAfter approval, Chrome will show a localhost connection error. That is expected here.', flush=True)
    print('Copy the COMPLETE address from Chrome (Ctrl+L, Ctrl+C). Paste it below and press Enter.', flush=True)
    print('The pasted address stays hidden. Paste it in this terminal, not in chat.\n', flush=True)
    address = getpass.getpass('Final browser address: ')
    code = callback_code(address, state)
    payload = urllib.parse.urlencode(dict(client_id=cfg.get('gdrive', 'client_id'),
        client_secret=cfg.get('gdrive', 'client_secret'), code=code,
        code_verifier=verifier, redirect_uri=redirect, grant_type='authorization_code')).encode()
    request = urllib.request.Request('https://oauth2.googleapis.com/token', data=payload,
                                     headers={'Content-Type': 'application/x-www-form-urlencoded'})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            token = json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError(f'Google token exchange returned HTTP {error.code}; active config was not changed.') from None
    if not token.get('access_token') or not token.get('refresh_token'):
        raise RuntimeError('Google did not return an offline token; active config was not changed.')
    return {key: token[key] for key in ('access_token', 'refresh_token', 'token_type') if key in token}


UPLOAD_WORKER = r'''#!/bin/bash
set -euo pipefail
umask 077
exec 9>/run/lock/sawdoctor-nas-backup.lock
flock -w 30 9
ssd=/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6
mountpoint -q "$ssd"
root="$ssd/backups/sets"
cloud=gdrive:nas-backups/openmediavault/sets
marker='Sawdoctor NAS backup v1'
rc() {
  rclone --config /root/.config/rclone/rclone.conf \
    --contimeout 15s --timeout 2m --retries 5 --retries-sleep 15s \
    --low-level-retries 10 --tpslimit 2 --tpslimit-burst 2 \
    --stats 30s --stats-log-level NOTICE --stats-one-line "$@"
}
filter=(--exclude '/_COMPLETE' --exclude '/_UPLOADED')
shopt -s nullglob
for directory in "$root"/nas-*; do
  [[ "${directory##*/}" =~ ^nas-[0-9]{8}T[0-9]{6}Z$ ]] || continue
  [ -d "$directory" ] && [ ! -L "$directory" ] || continue
  [ "$(cat "$directory/_COMPLETE" 2>/dev/null)" = "$marker" ] || continue
  [ ! -e "$directory/_UPLOADED" ] || continue
  echo "Checking local files: ${directory##*/}"
  (cd "$directory"; sha256sum --quiet -c SHA256SUMS)
  destination="$cloud/${directory##*/}"
  echo "Uploading existing backup: ${directory##*/}"
  rc copy "$directory" "$destination" --checksum --transfers 1 --checkers 2 "${filter[@]}"
  rc check "$directory" "$destination" --one-way --checkers 2 "${filter[@]}"
  rc copyto "$directory/_COMPLETE" "$destination/_COMPLETE" --checksum
  touch "$directory/_UPLOADED"
  echo "VERIFIED CLOUD BACKUP: $destination"
done
echo 'Existing backup upload finished successfully.'
'''


def retry_existing_backup():
    worker = Path('/usr/local/sbin/nas-backup-retry-upload')
    if worker.is_symlink():
        raise RuntimeError('The upload helper path is a symlink; leaving it unchanged.')
    worker.write_text(UPLOAD_WORKER)
    worker.chmod(0o700)
    active = subprocess.run(['systemctl', 'is-active', '--quiet', 'nas-backup-upload.service'])
    if active.returncode != 0:
        subprocess.run(['systemd-run', '--unit=nas-backup-upload', '--collect',
                        '--property=Type=oneshot', '--property=UMask=0077',
                        '--property=TimeoutStartSec=6h', '--property=Nice=10',
                        '--property=IOSchedulingClass=idle', str(worker)], check=True)
    print('The existing backup upload is running in the background.')
    print('Watch progress: sudo journalctl -u nas-backup-upload.service -f')


def main():
    os.umask(0o077)
    if os.geteuid() != 0:
        raise RuntimeError('Run this command with sudo.')
    addresses = subprocess.check_output(['ip', '-4', 'addr', 'show'], text=True)
    if 'inet 192.168.0.220/' not in addresses:
        raise RuntimeError('Run this on the NAS at 192.168.0.220.')
    lock = open('/run/lock/sawdoctor-nas-backup.lock', 'a')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise RuntimeError('A NAS backup is running; retry after it finishes.') from None
    rclone = shutil.which('rclone')
    if not rclone:
        raise RuntimeError('rclone is not installed.')
    source = Path('/home/sawdoctor/nas-gdrive-client.json')
    if source.is_symlink() or not source.is_file():
        raise RuntimeError('The NAS client JSON file is missing or is a symlink.')
    source.chmod(0o600)
    document = json.loads(source.read_text())
    credentials = document.get('installed', {})
    if credentials.get('project_id') != 'sawdoctor-nas-backups':
        raise RuntimeError('This JSON is not the Desktop client for sawdoctor-nas-backups.')
    client_id = credentials.get('client_id', '')
    secret = credentials.get('client_secret', '')
    if not client_id.endswith('.apps.googleusercontent.com') or not secret:
        raise RuntimeError('The downloaded JSON is missing the client ID or client secret.')
    active = Path('/root/.config/rclone/rclone.conf')
    if active.is_symlink():
        raise RuntimeError('The active rclone config is a symlink; leaving it unchanged.')
    original = active.read_bytes()
    cfg = config_from(original)
    if cfg.get('gdrive', 'type', fallback='') != 'drive':
        raise RuntimeError('The active gdrive remote is not a Google Drive remote.')
    # A completed connection needs no second Google login on a repeated invocation.
    if (cfg.get('gdrive', 'client_id', fallback='') == client_id
            and json.loads(cfg.get('gdrive', 'token', fallback='{}')).get('refresh_token')):
        subprocess.run([rclone, '--config', str(active), '--contimeout', '15s',
                        '--timeout', '2m', '--retries', '2', 'about', 'gdrive:', '--json'],
                       stdout=subprocess.DEVNULL, check=True)
        print('The NAS already uses this client and its GDrive connection works.')
        return
    candidate = active.with_name('nas-gdrive-candidate.conf')
    if candidate.is_symlink():
        raise RuntimeError('The candidate config is a symlink; leaving it unchanged.')
    if candidate.exists():
        staged = config_from(candidate.read_bytes())
        if staged.get('gdrive', 'client_id', fallback='') != client_id:
            raise RuntimeError('A candidate for another client exists; leaving it unchanged.')
        for key in ('client_id', 'client_secret', 'scope', 'token'):
            if staged.has_option('gdrive', key):
                cfg.set('gdrive', key, staged.get('gdrive', key))
            else:
                cfg.remove_option('gdrive', key)
        save_config(candidate, cfg)
    else:
        cfg.set('gdrive', 'client_id', client_id)
        cfg.set('gdrive', 'client_secret', secret)
        cfg.set('gdrive', 'scope', 'drive')
        cfg.remove_option('gdrive', 'token')
        save_config(candidate, cfg)
    token = json.loads(cfg.get('gdrive', 'token', fallback='{}'))
    if not token.get('refresh_token'):
        token = authorise_without_tunnel(cfg)
        cfg.set('gdrive', 'token', json.dumps(token, separators=(',', ':')))
        save_config(candidate, cfg)
    cfg = config_from(candidate.read_bytes())
    token = json.loads(cfg.get('gdrive', 'token', fallback='{}'))
    if not token.get('refresh_token'):
        raise RuntimeError('Google did not return an offline refresh token; active config was not changed.')
    # Check refresh with the new client now, instead of waiting for the access token to expire.
    token['expiry'] = '2000-01-01T00:00:00Z'
    cfg.set('gdrive', 'token', json.dumps(token, separators=(',', ':')))
    save_config(candidate, cfg)
    print('Checking the new Google token and Drive access...', flush=True)
    subprocess.run([rclone, '--config', str(candidate), '--contimeout', '15s',
                    '--timeout', '2m', '--retries', '2', 'about', 'gdrive:', '--json'],
                   stdout=subprocess.DEVNULL, check=True)
    if hashlib.sha256(active.read_bytes()).digest() != hashlib.sha256(original).digest():
        raise RuntimeError('The active config changed during setup; the authorised candidate is preserved.')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    backup = active.with_name('rclone.before-own-client-' + stamp + '.conf')
    with backup.open('xb') as stream:
        stream.write(original)
        stream.flush()
        os.fsync(stream.fileno())
    candidate.chmod(0o600)
    os.replace(candidate, active)
    print('NAS GDrive authorised, refresh verified, and new connection activated.')
    print('The old configuration is saved privately. The existing backup is ready to retry.')


if __name__ == '__main__':
    try:
        main()
        retry_existing_backup()
    except KeyboardInterrupt:
        raise SystemExit('\nSetup interrupted; rerun to continue.')
    except subprocess.CalledProcessError:
        raise SystemExit('Google/rclone did not complete successfully. The active config was not replaced.')
    except Exception as error:
        raise SystemExit('STOP: ' + str(error))
