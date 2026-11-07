#!/usr/bin/env python3
"""Complete a bounded, verified offline NPM restore; never activate it."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import types
import urllib.request
import yaml

PIN = '429eea919dcc029a4c8279915d651f98839b94f9'
HELPERS = {
    'routes': ('prepare-nas-npm-routes.py', '15516852f1f1fb02bc7647a1c2f72097b7e37c0bf834ec5a5e9a0e95ea92d7a2'),
    'restore': ('prepare-nas-npm.py', 'ff074e2273d62ac47a56b4fcc807b6af2ff409d65a3c2c4f3f6c8a236471c10e'),
}
FORMAT = 'sawdoctor-npm-complete-offline-v1'
LIMIT = 512 * 1024**2


def say(message):
    print(message, flush=True)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load_helpers():
    loaded = {}
    for name, (filename, expected) in HELPERS.items():
        url = 'https://raw.githubusercontent.com/sawdoctor/nas-backup-auth/' + PIN + '/scripts/' + filename
        with urllib.request.urlopen(url, timeout=20) as response:
            data = response.read(128 * 1024 + 1)
        if digest(data) != expected:
            raise RuntimeError('A pinned preparation dependency failed its integrity check.')
        module = types.ModuleType('_reviewed_npm_' + name)
        exec(compile(data, filename, 'exec'), module.__dict__)
        loaded[name] = module
    return loaded['routes'], loaded['restore']


def command(*args, binary=False, timeout=30):
    result = subprocess.run(args, capture_output=True, text=not binary, timeout=timeout)
    if result.returncode:
        raise RuntimeError('A complete-restore validation command failed; private output was withheld.')
    return result.stdout


def file_digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024**2), b''):
            h.update(block)
    return h.hexdigest()


def inventory(root):
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError('A complete-restore payload directory is unavailable or symbolic.')
    records, total, count = {}, 0, 0
    for folder, directories, files in os.walk(root, followlinks=False):
        for name in sorted(directories + files):
            path = Path(folder) / name
            relative = str(path.relative_to(root))
            info = path.lstat()
            item = {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid,
                    'mtimeNs': info.st_mtime_ns,
                    'xattrs': {key: digest(os.getxattr(path, key, follow_symlinks=False))
                               for key in sorted(os.listxattr(path, follow_symlinks=False))}}
            if stat.S_ISLNK(info.st_mode):
                if not path.resolve().is_relative_to(root.resolve()):
                    raise RuntimeError('A copied NPM link escapes its source tree; review it first.')
                item.update(kind='link', target=os.readlink(path))
            elif stat.S_ISREG(info.st_mode):
                item.update(kind='file', size=info.st_size, sha256=file_digest(path))
                total += info.st_size
            elif stat.S_ISDIR(info.st_mode):
                item['kind'] = 'directory'
            else:
                raise RuntimeError('An unexpected special file was retained outside the restore copy.')
            count += 1
            if total > LIMIT or count > 15000:
                raise RuntimeError('NPM preparation exceeds the 512 MiB/15000-entry copy bound.')
            records[relative] = item
    return {'bytes': total, 'entries': records}


def escaped(value):
    # The input model already has resolved values. Preserve literal dollars on
    # the next Compose parse, including credentials, instead of interpolating.
    if isinstance(value, str):
        return value.replace('$', '$$')
    if isinstance(value, list):
        return [escaped(v) for v in value]
    if isinstance(value, dict):
        return {k: escaped(v) for k, v in value.items()}
    return value


def certificate_checks(data, certs):
    with contextlib.closing(sqlite3.connect((data / 'database.sqlite').as_uri() + '?mode=ro', uri=True)) as db:
        ids = {r[0] for r in db.execute('SELECT certificate_id FROM proxy_host WHERE is_deleted=0 AND enabled=1') if r[0]}
        for identity in sorted(ids):
            row = db.execute('SELECT provider FROM certificate WHERE id=? AND is_deleted=0', (identity,)).fetchone()
            if not row:
                raise RuntimeError('A referenced certificate record is unavailable.')
            folder = (certs / 'live' if row[0] == 'letsencrypt' else data / 'custom_ssl') / ('npm-' + str(identity))
            certificate, key = folder / 'fullchain.pem', folder / 'privkey.pem'
            try:
                command('openssl', 'x509', '-in', str(certificate), '-noout', '-checkend', '0')
            except RuntimeError:
                raise RuntimeError('TLS certificate record ' + str(identity) + ' failed expiry/read validation; original files were retained.') from None
            certificate_public = command('openssl', 'x509', '-in', str(certificate), '-pubkey', '-noout', binary=True)
            result = subprocess.run(['openssl', 'pkey', '-pubin', '-outform', 'DER'], input=certificate_public,
                                    capture_output=True, timeout=15)
            key_public = command('openssl', 'pkey', '-in', str(key), '-pubout', '-outform', 'DER', binary=True)
            if result.returncode or result.stdout != key_public:
                raise RuntimeError('A copied TLS certificate and private key do not match (record ' + str(identity) + ').')
    return len(ids)


def live_stack(routes, restore, current):
    identities = json.loads(routes.read(restore.CACHE))['npm-app-1']
    if identities.get('source') != restore.SOURCE_IMAGE or identities.get('nas') != current['Image']:
        raise RuntimeError('The source/NAS NPM image transfer mapping differs.')
    tagged = json.loads(restore.run('docker', 'image', 'inspect', 'jc21/nginx-proxy-manager:latest'))[0]
    if tagged['Id'] != current['Image']:
        raise RuntimeError('The local NPM image tag changed; it was not pulled or replaced.')
    stored = json.loads(restore.run('docker', 'exec', 'dockmon', 'python', '-c', restore.STORAGE_CODE, restore.STORAGE_SHA))
    container_path = Path(stored['path'])
    if not container_path.is_relative_to('/app/data/stacks/npm-nas'):
        raise RuntimeError('The Dockmon NPM stack location differs.')
    host_path = routes.APP / 'appdata/dockmon' / container_path.relative_to('/app/data')
    if routes.read(host_path).decode() != stored['text']:
        raise RuntimeError('Dockmon and host NPM stack definitions differ.')
    model = json.loads(restore.run('docker', 'compose', '-p', 'npm-nas', '-f', str(host_path), 'config', '--format', 'json'))
    return stored, host_path, model


def prepare(routes, restore):
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in routes.run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the NAS.')
    routes.mounted(routes.APP, routes.APP_UUID)
    routes.mounted(routes.BACKUP, routes.BACKUP_UUID)
    for program in ('rsync', 'openssl', 'sha256sum'):
        if not shutil.which(program):
            raise RuntimeError('The complete preparation needs the ' + program + ' command.')
    root = routes.APP / 'compose/npm-restore/cutover'
    with routes.locked(routes.LOCK), routes.locked(routes.BASE / '.run.lock', shared=True):
        current = routes.target_bindings()
        source_db, stamp, source_sha = routes.source()
        plan = json.loads(routes.read(routes.WORK / 'plan.json'))
        proposal_bytes = routes.read(routes.WORK / 'database.sqlite', 64 * 1024**2)
        if (plan.get('format') != routes.PLAN_FORMAT or plan.get('status') != 'offline-proposal-only'
                or plan.get('sourceDatabaseSha256') != source_sha or plan.get('databaseSha256') != digest(proposal_bytes)):
            raise RuntimeError('The accepted route proposal or current source database changed; regenerate/review the route proposal first.')
        with contextlib.closing(sqlite3.connect(source_db.as_uri() + '?mode=ro', uri=True)) as original, \
             contextlib.closing(sqlite3.connect((routes.WORK / 'database.sqlite').as_uri() + '?mode=ro', uri=True)) as proposed:
            changes = routes.edits(routes.routes(original))
            if plan.get('changes') != changes:
                raise RuntimeError('The accepted upstream plan was edited; it was retained.')
            routes.compare_all(original, proposed, changes)
        folder = source_db.parents[2]
        manifest = json.loads(routes.read(folder / 'manifest.json', 8 * 1024**2))
        if manifest.get('dataRoots', {}).get('npm-letsencrypt', {}).get('snapshot') != 'data/npm-letsencrypt':
            raise RuntimeError('The verified standby certificate-root record is unavailable.')
        roots = {'data': folder / 'data/npm-data', 'letsencrypt': folder / 'data/npm-letsencrypt'}
        say('Checking the bounded NPM data/certificate trees from standby ' + stamp + '...')
        source_inventory = {name: inventory(path) for name, path in roots.items()}
        total = sum(value['bytes'] for value in source_inventory.values())
        if total > LIMIT or shutil.disk_usage(routes.APP).free < max(1024**3, total * 2 + 64 * 1024**2):
            raise RuntimeError('The NPM copy exceeds its 512 MiB bound or local free-space preflight.')
        containers = restore.all_containers()
        if any(Path(m.get('Source', '/')).is_relative_to(root) for c in containers for m in c.get('Mounts', []) if m.get('Type') == 'bind'):
            raise RuntimeError('A container references the candidate tree; it was retained.')
        routes.no_links(root)
        expected = {'format': FORMAT, 'sourceSnapshot': stamp, 'sourceDatabaseSha256': source_sha,
                    'proposalDatabaseSha256': digest(proposal_bytes)}
        stored, host_path, model = live_stack(routes, restore, current)
        env_sha = digest(json.dumps(stored['env'], sort_keys=True).encode())
        if root.exists():
            if {p.name for p in root.iterdir()} != {'prepared.json', 'payload-inventory.json', 'payload', 'ready.yaml'}:
                raise RuntimeError('An existing complete candidate has unexpected files; it was retained.')
            record = json.loads(routes.read(root / 'prepared.json'))
            wanted = json.loads(routes.read(root / 'payload-inventory.json', 16 * 1024**2))
            if (any(record.get(k) != v for k, v in expected.items()) or record.get('nasImage') != current.get('Image')
                    or record.get('existingStackSha256') != digest(stored['text'].encode())
                    or record.get('existingStackEnvSha256') != env_sha
                    or file_digest(root / 'payload-inventory.json') != record.get('payloadInventorySha256')
                    or inventory(root / 'payload') != wanted or file_digest(root / 'ready.yaml') != record.get('readySha256')):
                raise RuntimeError('An existing complete candidate differs; it was retained for review.')
            say('The matching complete offline NPM candidate remains verified; no extra copy was made.')
            return
        root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.TemporaryDirectory(prefix='.npm-complete-', dir=root.parent) as temporary:
            staged = Path(temporary) / 'candidate'
            staged.mkdir(mode=0o700)
            restore.SNAPSHOT, restore.WORK, restore.DATA = folder, staged, staged / 'payload'
            restore.prepare_data(expected)
            copied = staged / 'payload'
            for name in roots:
                if inventory(copied / name) != source_inventory[name]:
                    raise RuntimeError('A copied NPM file/link/permission/xattr differs from the verified source.')
            database = copied / 'data/database.sqlite'
            before = database.stat()
            database.write_bytes(proposal_bytes)
            os.utime(database, ns=(before.st_atime_ns, before.st_mtime_ns))
            with contextlib.closing(sqlite3.connect(source_db.as_uri() + '?mode=ro', uri=True)) as original, \
                 contextlib.closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)) as proposed:
                routes.compare_all(original, proposed, changes)
            counts = restore.database_report(database, copied / 'letsencrypt')
            keys = json.loads(routes.read(copied / 'data/keys.json', 256 * 1024))
            if not isinstance(keys, dict) or not keys:
                raise RuntimeError('The copied NPM signing-key file is unavailable or invalid.')
            checked_certificates = certificate_checks(copied / 'data', copied / 'letsencrypt')
            restore.DATA = root / 'payload'
            proposed_model = restore.candidate(model, current, current['Image'])
            ready = staged / 'ready.yaml'
            ready.write_text(yaml.safe_dump(escaped(proposed_model), sort_keys=False))
            ready.chmod(0o600)
            rendered = json.loads(restore.run('docker', 'compose', '-p', 'npm-nas', '-f', str(ready), 'config', '--format', 'json'))
            if rendered.get('services') != proposed_model.get('services') or rendered.get('networks') != proposed_model.get('networks'):
                raise RuntimeError('The offline Compose round trip changed runtime settings.')
            payload_inventory = inventory(copied)
            inventory_file = staged / 'payload-inventory.json'
            inventory_file.write_text(json.dumps(payload_inventory, sort_keys=True) + '\n')
            inventory_file.chmod(0o600)
            now = routes.target_bindings()
            if (now['Id'], now['Image'], now['State'].get('StartedAt')) != (current['Id'], current['Image'], current['State'].get('StartedAt')):
                raise RuntimeError('The live NAS proxy changed during preparation.')
            if live_stack(routes, restore, now)[0] != stored or file_digest(source_db) != source_sha:
                raise RuntimeError('The source database or current Dockmon stack changed during preparation.')
            record = {**expected, 'status': 'complete-offline-not-activated', 'sourceBytes': total,
                      'counts': counts, 'changedUpstreams': len(changes), 'checkedCertificateKeyPairs': checked_certificates,
                      'nasImage': current['Image'], 'existingContainerId': current['Id'],
                      'existingStackPath': str(host_path), 'existingStackSha256': digest(stored['text'].encode()),
                      'existingStackEnvSha256': env_sha,
                      'readySha256': file_digest(ready), 'payloadInventorySha256': file_digest(inventory_file),
                      'fail2banLogpathAtActivation': str(root / 'payload/data/logs/proxy-host-*_error.log')}
            (staged / 'prepared.json').write_text(json.dumps(record, indent=2) + '\n')
            (staged / 'prepared.json').chmod(0o600)
            staged.rename(root)
        say('COMPLETE NAS NPM RESTORE PREPARED OFFLINE: ' + json.dumps(counts, sort_keys=True))
        say('Copied ' + str(total) + ' bytes; 21 upstream changes retained; TLS key-pair checks: ' + str(checked_certificates) + '.')
        say('Source signing keys, accounts, access lists and custom files are retained privately.')
        say('Candidate definition: ' + str(root / 'ready.yaml'))
        say('No proxy/container restart, certificate renewal, router change or application stop was started.')
        say('Activation still needs proxy/security tests, renewal-ownership handover and the NPM jail logpath update.')


def main():
    if sys.argv[1:] == ['--worker']:
        try:
            prepare(*load_helpers())
        finally:
            path = Path(sys.argv[0])
            if path.parent == Path('/run') and path.name.startswith('nas-npm-complete-'):
                path.unlink(missing_ok=True)
        return
    if sys.argv[1:] or os.geteuid() != 0 or 'inet 192.168.0.220/' not in command('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo and no arguments on the NAS.')
    active = subprocess.run(['systemctl', 'is-active', '--quiet', 'nas-npm-cutover-prepare.service'], capture_output=True, timeout=15)
    if active.returncode == 0:
        say('Complete NPM preparation is already running; check its journal.')
        return
    source = globals().get('INSTALL_SOURCE')
    if not isinstance(source, str) or not source.startswith('#!/usr/bin/env python3\n'):
        raise RuntimeError('The complete pinned installer source is required.')
    fd, path = tempfile.mkstemp(prefix='nas-npm-complete-', suffix='.py', dir='/run')
    with os.fdopen(fd, 'w') as stream:
        os.fchmod(stream.fileno(), 0o700)
        stream.write(source)
    try:
        subprocess.run(['systemctl', 'reset-failed', 'nas-npm-cutover-prepare.service'], capture_output=True, timeout=15)
        command('systemd-run', '--unit=nas-npm-cutover-prepare', '--collect', '--description=Prepare complete verified NAS NPM restore offline',
                '--property=Type=exec', '--property=UMask=0077', '--property=RuntimeMaxSec=10min', '/usr/bin/python3', path, '--worker')
    except BaseException:
        Path(path).unlink(missing_ok=True)
        raise
    say('Complete offline NPM preparation started in systemd. Closing SSH is safe.')
    say('Progress: sudo journalctl -u nas-npm-cutover-prepare.service -n 20 --no-pager -o cat')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        if isinstance(error, RuntimeError):
            raise SystemExit('STOP: ' + str(error))
        raise SystemExit('STOP: Complete NPM preparation failed (' + type(error).__name__ + '); private details withheld.')
