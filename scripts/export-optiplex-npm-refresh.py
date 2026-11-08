#!/usr/bin/env python3
"""Capture only live NPM for NAS handover, without stopping applications."""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import shlex
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time

FORMAT = 'sawdoctor-npm-live-refresh-v1'
SOURCE_IMAGE = 'sha256:4393e642e233e5efd5adeb7f10918d4aaea71c9ed875b94190273fc8e87f9594'
DATA = Path('/home/sawdoctor/docker/npm/data')
CERTS = Path('/home/sawdoctor/docker/npm/letsencrypt')
OUTPUT = Path('/home/sawdoctor/nas-npm-refresh')
STATE = Path('/var/lib/sawdoctor-npm-refresh')
READER = Path('/usr/local/sbin/nas-migration-export-read')
KEYS = Path('/home/sawdoctor/.ssh/authorized_keys')
KEY_BLOB = 'AAAAC3NzaC1lZDI1NTE5AAAAILc56w99kcthdhVVsUuXQxChc1Smtlx6ju+xZPLNIpSE'
CA_FILE = '/etc/ssl/certs/ca-certificates.crt'
LIMIT = 512 * 1024**2
EXCLUDES = ('/database.sqlite', '/database.sqlite-wal', '/database.sqlite-shm', '/database.sqlite-journal', '/logs/***')
MARKER = '# Sawdoctor NPM live refresh read-only transfer v1'


def say(message):
    print(message, flush=True)


def no_links(path):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise RuntimeError('An unexpected symbolic refresh path was retained.')


def sha(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024**2), b''):
            value.update(block)
    return value.hexdigest()


def run(*args, timeout=30):
    result = subprocess.run(args, capture_output=True, timeout=timeout,
                            env={**os.environ, 'LC_ALL': 'C', 'LANG': 'C'})
    if result.returncode:
        raise RuntimeError('An NPM capture command failed; private output was withheld.')
    return result.stdout


def atomic(path, data, mode=0o600, owner=None):
    no_links(path)
    fd, name = tempfile.mkstemp(prefix='.npm-refresh-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            if owner:
                os.fchown(stream.fileno(), *owner)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def reader_text(original):
    addition = (MARKER + '\ncase "${SSH_ORIGINAL_COMMAND-}" in\n'
                '  npm-refresh) exec /bin/cat ' + shlex.quote(str(OUTPUT / 'export.tar.gz')) + ' ;;\n'
                '  npm-refresh-ready) exec /bin/cat ' + shlex.quote(str(OUTPUT / 'ready.json')) + ' ;;\n'
                'esac\n')
    if not original.startswith('#!/bin/sh\n') or 'SSH_ORIGINAL_COMMAND' not in original:
        raise RuntimeError('The existing restricted transfer reader needs review.')
    if MARKER in original:
        if original.count(MARKER) != 1 or not original.startswith('#!/bin/sh\n' + addition):
            raise RuntimeError('The existing NPM refresh transfer routes differ.')
        return original
    return '#!/bin/sh\n' + addition + original.split('\n', 1)[1]


def authorization():
    for path in (READER, KEYS):
        no_links(path)
        if not path.is_file() or path.stat().st_size > 256 * 1024:
            raise RuntimeError('The existing restricted NAS transfer setup is unavailable.')
    if READER.stat().st_uid != 0 or stat.S_IMODE(READER.stat().st_mode) & 0o022:
        raise RuntimeError('The existing transfer reader ownership/mode needs review.')
    matches = []
    for line in KEYS.read_text().splitlines():
        if line.strip() and not line.lstrip().startswith('#'):
            fields = shlex.split(line)
            if fields[-3:] == ['ssh-ed25519', KEY_BLOB, 'nas-infinidysk-transfer']:
                matches.append(fields[0])
    if len(matches) != 1 or not all(x in matches[0] for x in (
            'from=192.168.0.220', 'restrict', 'command=' + str(READER))):
        raise RuntimeError('The original restricted NAS key authorization differs; keys were retained.')
    original = READER.read_text()
    updated = reader_text(original)
    syntax = subprocess.run(['sh', '-n'], input=updated.encode(), capture_output=True, timeout=10)
    if syntax.returncode:
        raise RuntimeError('The fixed-path transfer reader did not pass shell validation.')
    return original, updated


def container():
    records = json.loads(run('docker', 'inspect', 'npm-app-1'))
    if len(records) != 1:
        raise RuntimeError('The source proxy container is unavailable.')
    item = records[0]
    binds = {m['Destination']: m for m in item.get('Mounts', []) if m['Destination'] in ('/data', '/etc/letsencrypt')}
    if (item['Image'] != SOURCE_IMAGE or item['State']['Status'] != 'running'
            or set(binds) != {'/data', '/etc/letsencrypt'}
            or any(binds[k].get('Type') != 'bind' or binds[k].get('Source') != str(v)
                   for k, v in (('/data', DATA), ('/etc/letsencrypt', CERTS)))):
        raise RuntimeError('The current source NPM image/state/data bindings differ; nothing was stopped.')
    return {key: item[key] for key in ('Id', 'Image')} | {'startedAt': item['State']['StartedAt']}


def snapshot_database(source, destination):
    no_links(source)
    if not source.is_file() or source.stat().st_size > 64 * 1024**2:
        raise RuntimeError('The source NPM SQLite database is unavailable or too large.')
    started = time.monotonic()
    def progress(status, remaining, total):
        if time.monotonic() - started > 30:
            raise RuntimeError('The online SQLite copy exceeded its time bound.')
    with contextlib.closing(sqlite3.connect(source.as_uri() + '?mode=ro', uri=True, timeout=5)) as live, \
            contextlib.closing(sqlite3.connect(destination)) as copied:
        live.backup(copied, pages=128, progress=progress, sleep=0.05)
        copied.execute('PRAGMA journal_mode=DELETE')
        if copied.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
            raise RuntimeError('The consistent NPM database copy failed its integrity check.')
        logical = hashlib.sha256()
        for line in copied.iterdump():
            logical.update(line.encode()); logical.update(b'\n')
    shutil.copystat(source, destination)
    info = source.stat()
    os.chown(destination, info.st_uid, info.st_gid)
    return logical.hexdigest()


def inventory(root):
    no_links(root)
    result, total = {}, 0
    for folder, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(folder) / name
            info = path.lstat()
            item = {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid,
                    'mtimeNs': info.st_mtime_ns,
                    'xattrs': {key: hashlib.sha256(os.getxattr(path, key, follow_symlinks=False)).hexdigest()
                               for key in sorted(os.listxattr(path, follow_symlinks=False))}}
            if stat.S_ISLNK(info.st_mode):
                if not path.resolve().is_relative_to(root.resolve()):
                    raise RuntimeError('An NPM snapshot link escapes its copied tree.')
                item.update(kind='link', target=os.readlink(path))
            elif stat.S_ISREG(info.st_mode):
                total += info.st_size
                if total > LIMIT:
                    raise RuntimeError('The NPM capture exceeds its 512 MiB copy bound.')
                item.update(kind='file', size=info.st_size, sha256=sha(path))
            elif stat.S_ISDIR(info.st_mode):
                item.update(kind='directory')
            else:
                raise RuntimeError('An unexpected special file was retained outside the copy.')
            result[str(path.relative_to(root))] = item
            if total > LIMIT or len(result) > 15000:
                raise RuntimeError('The NPM capture exceeds its 512 MiB/15000-entry bound.')
    return {'bytes': total, 'entries': result}


def source_size(root, omit_data=False):
    total, count = 0, 0
    for folder, dirs, files in os.walk(root, followlinks=False):
        if omit_data and Path(folder) == root:
            dirs[:] = [name for name in dirs if name != 'logs']
            files = [name for name in files if name not in {
                'database.sqlite', 'database.sqlite-wal', 'database.sqlite-shm', 'database.sqlite-journal'}]
        for name in dirs + files:
            info = (Path(folder) / name).lstat()
            if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)):
                raise RuntimeError('An unexpected special source NPM file needs review.')
            total += info.st_size if stat.S_ISREG(info.st_mode) else 0
            count += 1
            if total > LIMIT or count > 15000:
                raise RuntimeError('The source NPM data exceeds its 512 MiB/15000-entry copy bound.')
    return total


def validate_policy(database, payload):
    counts, ids, shelfmark = {}, {}, None
    with contextlib.closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)) as db:
        for table in ('proxy_host', 'certificate', 'access_list', 'user', 'redirection_host', 'dead_host', 'stream'):
            counts[table] = db.execute('SELECT count(*) FROM ' + table + ' WHERE is_deleted=0').fetchone()[0]
        for identity, names, certid, enabled in db.execute(
                'SELECT id,domain_names,certificate_id,enabled FROM proxy_host WHERE is_deleted=0'):
            names = json.loads(names)
            if any(name.lower().rstrip('.') in ('soundspan.sawdoctor.uk', 'chaptarr.sawdoctor.uk') for name in names):
                raise RuntimeError('A retired Soundspan/Chaptarr route is still active in source NPM; current settings were retained.')
            if 'shelfmark-audio.sawdoctor.uk' in names:
                shelfmark = {'proxyId': identity, 'certificateId': certid, 'enabled': enabled}
            if enabled and certid:
                ids.setdefault(certid, set()).update(names)
        if shelfmark is None or not shelfmark['enabled'] or not shelfmark['certificateId']:
            raise RuntimeError('The corrected Shelfmark Audio source route is unavailable.')
        for identity, names in sorted(ids.items()):
            record = db.execute('SELECT provider FROM certificate WHERE id=? AND is_deleted=0', (identity,)).fetchone()
            if record is None or record[0] not in ('letsencrypt', 'other'):
                raise RuntimeError('An active source route refers to an unavailable certificate.')
            folder = ((payload / 'letsencrypt/live') if record[0] == 'letsencrypt' else (payload / 'data/custom_ssl')) / ('npm-' + str(identity))
            cert, key = folder / 'fullchain.pem', folder / 'privkey.pem'
            if any(not path.resolve().is_relative_to(payload.resolve()) or not path.is_file() for path in (cert, key)):
                raise RuntimeError('An active source certificate/key is unavailable or outside the copied tree.')
            public = run('openssl', 'x509', '-in', str(cert), '-pubkey', '-noout')
            parsed = subprocess.run(['openssl', 'pkey', '-pubin', '-outform', 'DER'], input=public, capture_output=True, timeout=10)
            if parsed.returncode or parsed.stdout != run('openssl', 'pkey', '-in', str(key), '-pubout', '-outform', 'DER'):
                raise RuntimeError('A copied certificate and its private key differ (record ' + str(identity) + ').')
            for name in sorted(names):
                try:
                    run('openssl', 'verify', '-purpose', 'sslserver', '-verify_hostname', name,
                        '-CAfile', CA_FILE, '-untrusted', str(cert), str(cert))
                except RuntimeError:
                    raise RuntimeError('TLS certificate record ' + str(identity) + ' does not validate for ' + name + '; source settings retained.') from None
    return counts, shelfmark, len(ids)


def copy_tree(source, destination, exclusions=()):
    args = ['rsync', '-aHAX', '--numeric-ids', '--one-file-system', '--no-devices', '--no-specials']
    args += ['--exclude=' + value for value in exclusions]
    run(*args, '--', str(source) + '/', str(destination) + '/', timeout=180)
    return args


def unchanged_copy(args, source, destination):
    # Checks content hashes as well as metadata; private names never enter the journal.
    changes = run(*args, '--checksum', '--dry-run', '--itemize-changes', '--', str(source) + '/', str(destination) + '/', timeout=180)
    if changes.strip():
        raise RuntimeError('NPM files changed during the online copy; retry after the current proxy edit/renewal finishes.')


def capture():
    if os.geteuid() != 0 or b'inet 192.168.0.29/' not in run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run this on the OptiPlex, not the NAS.')
    for tool in ('rsync', 'docker', 'openssl', 'tar'):
        if not shutil.which(tool):
            raise RuntimeError('The NPM capture needs the existing ' + tool + ' command.')
    for path in (DATA, CERTS, OUTPUT, STATE):
        no_links(path)
    before = container()
    original, updated = authorization()
    if not DATA.is_dir() or not CERTS.is_dir() or source_size(DATA, True) + source_size(CERTS) > LIMIT:
        raise RuntimeError('The source proxy-only data exceeds its 512 MiB copy bound.')
    account = pwd.getpwnam('sawdoctor')
    STATE.mkdir(mode=0o700, exist_ok=True)
    if STATE.stat().st_uid != 0 or stat.S_IMODE(STATE.stat().st_mode) & 0o077:
        raise RuntimeError('The private source capture-state permissions differ.')
    if shutil.disk_usage(STATE).free < 2 * LIMIT + 128 * 1024**2:
        raise RuntimeError('At least 1.2 GiB free space is required for the bounded proxy-only copy.')
    no_links(STATE / '.capture.lock')
    with (STATE / '.capture.lock').open('a') as lock, Path('/run/lock/plex-daily-backup.lock').open('a') as backup:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(backup, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('A source backup/snapshot/capture is running; it was not interrupted.') from None
        OUTPUT.mkdir(mode=0o700, exist_ok=True)
        if any(p.name not in ('export.tar.gz', 'ready.json') or p.is_symlink() or not p.is_file() for p in OUTPUT.iterdir()):
            raise RuntimeError('The refresh output directory contains unexpected entries; they were retained.')
        if any(OUTPUT.iterdir()):
            ready = json.loads((OUTPUT / 'ready.json').read_text())
            if ready.get('format') != FORMAT or sha(OUTPUT / 'export.tar.gz') != ready.get('archiveSha256'):
                raise RuntimeError('The earlier proxy refresh differs; it was retained.')
        os.chown(OUTPUT, account.pw_uid, account.pw_gid); OUTPUT.chmod(0o700)
        with tempfile.TemporaryDirectory(prefix='.capture-', dir=STATE) as temporary:
            work = Path(temporary)
            say('Making a consistent online NPM database copy; Plex and NPM remain running...')
            db = work / 'database.sqlite'
            logical = snapshot_database(DATA / 'database.sqlite', db)
            payload = work / 'payload'; payload.mkdir(mode=0o700)
            data_args = copy_tree(DATA, payload / 'data', EXCLUDES)
            cert_args = copy_tree(CERTS, payload / 'letsencrypt')
            unchanged_copy(data_args, DATA, payload / 'data')
            unchanged_copy(cert_args, CERTS, payload / 'letsencrypt')
            second = work / 'database-after.sqlite'
            if snapshot_database(DATA / 'database.sqlite', second) != logical:
                raise RuntimeError('Source NPM settings changed during capture; the incomplete copy was discarded.')
            data_info = (payload / 'data').stat()
            db.replace(payload / 'data/database.sqlite')
            os.utime(payload / 'data', ns=(data_info.st_atime_ns, data_info.st_mtime_ns))
            say('Checking retired routes and certificate names, trust chains and matching private keys...')
            counts, shelfmark, checked = validate_policy(payload / 'data/database.sqlite', payload)
            inventory_data = inventory(payload)
            unchanged_copy(data_args, DATA, payload / 'data')
            unchanged_copy(cert_args, CERTS, payload / 'letsencrypt')
            if snapshot_database(DATA / 'database.sqlite', second) != logical or container() != before or READER.read_text() != original:
                raise RuntimeError('The source proxy/settings/reader changed during verification; current state was retained.')
            manifest = {'format': FORMAT, 'createdUtc': time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()),
                        'sourceHost': '192.168.0.29', 'container': before, 'databaseLogicalSha256': logical,
                        'databaseSha256': sha(payload / 'data/database.sqlite'), 'counts': counts,
                        'shelfmarkAudio': shelfmark, 'checkedCertificateKeyPairs': checked,
                        'retiredDomains': ['soundspan.sawdoctor.uk', 'chaptarr.sawdoctor.uk'],
                        'omitted': ['data/logs', 'raw-live-database-and-journals'], 'sourceStopped': False}
            (work / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True) + '\n')
            (work / 'payload-inventory.json').write_text(json.dumps(inventory_data, sort_keys=True) + '\n')
            archive = work / 'export.tar.gz'
            run('tar', '--acls', '--xattrs', '--numeric-owner', '-czpf', str(archive), '-C', str(work),
                'manifest.json', 'payload-inventory.json', 'payload', timeout=180)
            if archive.stat().st_size > LIMIT + 32 * 1024**2:
                raise RuntimeError('The compressed proxy-only export exceeds its bound.')
            ready = {'format': FORMAT, 'createdUtc': manifest['createdUtc'], 'archiveSha256': sha(archive),
                     'archiveBytes': archive.stat().st_size, 'payloadBytes': inventory_data['bytes'],
                     'manifestSha256': sha(work / 'manifest.json'), 'inventorySha256': sha(work / 'payload-inventory.json')}
            run('tar', '-tzf', str(archive), timeout=60)
            if container() != before or READER.read_text() != original:
                raise RuntimeError('The source proxy/reader changed before publication; current state retained.')
            # OUTPUT may be on another filesystem; copy+fsync there before atomic publication.
            fd, staged_name = tempfile.mkstemp(prefix='.npm-export-', dir=OUTPUT)
            staged = Path(staged_name)
            try:
                with os.fdopen(fd, 'wb') as target, archive.open('rb') as source:
                    shutil.copyfileobj(source, target, 1024**2)
                    target.flush(); os.fsync(target.fileno())
                    os.fchmod(target.fileno(), 0o400); os.fchown(target.fileno(), account.pw_uid, account.pw_gid)
                if sha(staged) != ready['archiveSha256']:
                    raise RuntimeError('The private transfer archive failed its final checksum.')
                staged.replace(OUTPUT / 'export.tar.gz')
            finally:
                staged.unlink(missing_ok=True)
            atomic(OUTPUT / 'ready.json', (json.dumps(ready, sort_keys=True) + '\n').encode(), 0o400,
                   (account.pw_uid, account.pw_gid))
            recovery = STATE / 'reader.before'
            if not recovery.exists():
                atomic(recovery, original.encode())
            if updated != original:
                atomic(READER, updated.encode(), stat.S_IMODE(READER.stat().st_mode))
            atomic(STATE / 'result.json', (json.dumps({**ready, 'counts': counts, 'shelfmarkAudio': shelfmark,
                   'checkedCertificateKeyPairs': checked, 'sourceUnchanged': True}, indent=2) + '\n').encode())
        say('CURRENT OPTIPLEX NPM COPY READY: ' + json.dumps(counts, sort_keys=True))
        say('Shelfmark Audio certificate names/trust/key verified; certificate record ' + str(shelfmark['certificateId']) + '.')
        say('Soundspan and Chaptarr are absent from active routes. Copy: ' + str(ready['archiveBytes'] // 1024**2) + ' MiB.')
        say('Plex, NPM, provider connections, timers, public routing and certificate renewal ownership were retained.')
        say('Only two fixed read-only export requests were added to the existing restricted NAS transfer reader; no key permissions were broadened.')
        say('Temporary uncompressed files removed. One current proxy-only archive retained for NAS collection.')


def main():
    os.umask(0o077)
    if sys.argv[1:] == ['--worker']:
        def interrupted(signum, frame):
            raise RuntimeError('The bounded NPM copy was interrupted; temporary-copy cleanup requested.')
        signal.signal(signal.SIGTERM, interrupted)
        try:
            capture()
        finally:
            path = Path(sys.argv[0])
            if path.parent == Path('/run') and path.name.startswith('npm-live-refresh-'):
                path.unlink(missing_ok=True)
        return
    if sys.argv[1:] or os.geteuid() != 0 or b'inet 192.168.0.29/' not in run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo and no arguments on the OptiPlex.')
    if subprocess.run(['systemctl', 'is-active', '--quiet', 'nas-npm-live-export.service'], capture_output=True, timeout=15).returncode == 0:
        say('The NPM-only export is already running; check its journal.'); return
    source = globals().get('INSTALL_SOURCE')
    if not isinstance(source, str) or not source.startswith('#!/usr/bin/env python3\n'):
        raise RuntimeError('The complete pinned NPM capture installer is required.')
    fd, name = tempfile.mkstemp(prefix='npm-live-refresh-', suffix='.py', dir='/run')
    with os.fdopen(fd, 'w') as stream:
        os.fchmod(stream.fileno(), 0o700); stream.write(source)
    try:
        subprocess.run(['systemctl', 'reset-failed', 'nas-npm-live-export.service'], capture_output=True, timeout=15)
        run('systemd-run', '--unit=nas-npm-live-export', '--collect', '--description=Capture current OptiPlex NPM without stopping applications',
            '--property=Type=exec', '--property=UMask=0077', '--property=RuntimeMaxSec=10min', '/usr/bin/python3', name, '--worker')
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise
    say('Current NPM-only export started in systemd. Closing SSH is safe.')
    say('Progress: sudo journalctl -u nas-npm-live-export.service -n 20 --no-pager -o cat')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        if isinstance(error, RuntimeError):
            raise SystemExit('STOP: ' + str(error))
        raise SystemExit('STOP: NPM capture failed (' + type(error).__name__ + '); private details withheld.')
