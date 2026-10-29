#!/usr/bin/env python3
"""Authorise the NAS GDrive client through an existing SSH browser tunnel."""
import configparser
import datetime
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


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
        print('Choose y for auto config / use web browser. Choose n for Shared Drive if asked.', flush=True)
        print('Open the printed http://127.0.0.1:53682/auth?... link in FydeOS Chrome.', flush=True)
        with open('/dev/tty', 'r') as terminal:
            subprocess.run([rclone, '--config', str(candidate), '--auth-no-open-browser',
                            'config', 'reconnect', 'gdrive:'], stdin=terminal, check=True)
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
    except KeyboardInterrupt:
        raise SystemExit('\nSetup interrupted; rerun to continue.')
    except subprocess.CalledProcessError:
        raise SystemExit('Google/rclone did not complete successfully. The active config was not replaced.')
    except Exception as error:
        raise SystemExit('STOP: ' + str(error))
