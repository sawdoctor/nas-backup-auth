#!/usr/bin/env python3
"""Collect the current NPM-only export and prepare a new offline NAS copy."""
import contextlib
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import types
import urllib.request
import yaml

FORMAT = 'sawdoctor-npm-current-offline-v1'
EXPORT_FORMAT = 'sawdoctor-npm-live-refresh-v1'
HELPERS = {
    'source': ('a53b0ad1f067f0911b18e71db27028bd9ed068d6', 'export-optiplex-npm-refresh.py', '70e44f1ecb7d020f3b00c960da366466ff4b4073734a7d7cd023c4554968ce92'),
    'complete': ('d913c6318bde2dbdd94fbe64c1d6b3cf9640f1fa', 'prepare-nas-npm-cutover.py', '009889cbb655f24e44dc4097e3c8ced6a5344ca1c1bf99ec5712bd220aa12749'),
    'private': ('69c5b34b62c1a08817a9fd57a550c98f6d033a41', 'test-nas-npm-proxy.py', 'ca5b3d6a7db977a50fb8a37e03a4bc1c2ddeac6fffceb72c9a5bd0e4edb7cfe6'),
}
KEY = Path('/root/.ssh/nas-infinidysk-transfer')
HOST_KEY = '192.168.0.29 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGI1/hObYOUSPIqGKLePC0eEFvCc8Uoyv+YOmBbVPbgW\n'
LIMIT = 512 * 1024**2
RETIRED = ['soundspan.sawdoctor.uk', 'chaptarr.sawdoctor.uk']
CONTENTS = {'prepared.json', 'payload-inventory.json', 'payload', 'ready.yaml',
            'source-manifest.json', 'source-inventory.json', 'source-database.sqlite'}


def say(message):
    print(message, flush=True)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load_helpers():
    result = {}
    for name, (pin, filename, wanted) in HELPERS.items():
        url = 'https://raw.githubusercontent.com/sawdoctor/nas-backup-auth/' + pin + '/scripts/' + filename
        with urllib.request.urlopen(url, timeout=30) as response:
            data = response.read(128 * 1024 + 1)
        if digest(data) != wanted:
            raise RuntimeError('A pinned current-NPM helper failed its integrity check.')
        item = types.ModuleType('_current_npm_' + name)
        exec(compile(data, filename, 'exec'), item.__dict__)
        result[name] = item
    routes, restore = result['complete'].load_helpers()
    routes.KEEP_SOURCE = {k: v for k, v in routes.KEEP_SOURCE.items() if k not in ('soundspan', 'chaptarr')}
    return result['source'], result['complete'], result['private'], routes, restore


def ssh_command(known):
    return ['ssh', '-nT', '-p', '22', '-i', str(KEY), '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(known),
            '-o', 'ConnectTimeout=15', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3',
            'sawdoctor@192.168.0.29']


def read_ready(ssh):
    result = subprocess.run(ssh + ['npm-refresh-ready'], capture_output=True, timeout=30)
    if result.returncode or len(result.stdout) > 4096:
        raise RuntimeError('The current OptiPlex NPM export metadata could not be read over the existing restricted connection.')
    value = json.loads(result.stdout)
    validate_ready(value)
    return value


def validate_ready(value):
    if value.get('format') != EXPORT_FORMAT or not re.fullmatch(r'\d{8}T\d{6}Z', value.get('createdUtc', '')):
        raise RuntimeError('The current source NPM export identity differs.')
    if any(not re.fullmatch(r'[0-9a-f]{64}', value.get(k, '')) for k in ('archiveSha256', 'manifestSha256', 'inventorySha256')):
        raise RuntimeError('The source NPM export checksums are unavailable.')
    for field, maximum in (('archiveBytes', LIMIT + 32 * 1024**2), ('payloadBytes', LIMIT)):
        if type(value.get(field)) is not int or not 0 < value[field] <= maximum:
            raise RuntimeError('The source NPM export size is empty or exceeds its bound.')
    created = datetime.strptime(value['createdUtc'], '%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc).timestamp()
    age = time.time() - created
    if age < -120 or age > 6 * 3600:
        raise RuntimeError('The NPM-only source export is more than six hours old or has a future timestamp; refresh it first.')


def receive_archive(ssh, destination, ready):
    process = subprocess.Popen(ssh + ['npm-refresh'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        deadline, received = time.monotonic() + 180, 0
        with selectors.DefaultSelector() as selector, destination.open('wb') as output:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                if time.monotonic() > deadline:
                    raise RuntimeError('The bounded NPM-only transfer timed out.')
                if not selector.select(1):
                    continue
                block = os.read(process.stdout.fileno(), 128 * 1024)
                if not block:
                    break
                received += len(block)
                if received > ready['archiveBytes']:
                    raise RuntimeError('The NPM transfer grew beyond its published size; temporary data retained only until cleanup.')
                output.write(block)
            output.flush(); os.fsync(output.fileno())
        if process.wait(timeout=10) or received != ready['archiveBytes']:
            raise RuntimeError('The NPM export transfer did not match its published byte count.')
        if file_digest(destination) != ready['archiveSha256']:
            raise RuntimeError('The transferred NPM archive failed its SHA256 check.')
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.kill(); process.wait()


def file_digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024**2), b''):
            result.update(block)
    return result.hexdigest()


def normal_link(member, target):
    value = PurePosixPath(target)
    if value.is_absolute():
        raise RuntimeError('An absolute NPM archive link was rejected.')
    parts = list(member.parent.parts)
    for part in value.parts:
        if part == '..':
            if not parts:
                raise RuntimeError('An escaping NPM archive link was rejected.')
            parts.pop()
        elif part != '.':
            parts.append(part)
    value = PurePosixPath(*parts)
    if not value.parts or value.parts[0] != 'payload':
        raise RuntimeError('An NPM archive link escapes the private payload.')
    return value


def validate_archive(archive):
    members, symbolic, hardlinks, total = {}, {}, {}, 0
    with tarfile.open(archive, mode='r:gz') as stream:
        for item in stream:
            name = PurePosixPath(item.name)
            if (name.is_absolute() or '..' in name.parts or name in members
                    or not (name.parts and (name.parts[0] == 'payload' or str(name) in ('manifest.json', 'payload-inventory.json')))
                    or not (item.isdir() or item.isfile() or item.issym() or item.islnk())):
                raise RuntimeError('An unsafe or unexpected NPM archive entry was rejected before extraction.')
            if str(name) in ('manifest.json', 'payload-inventory.json') and not item.isfile():
                raise RuntimeError('An NPM archive metadata entry is not a regular file.')
            members[name] = item
            total += item.size if item.isfile() else 0
            if total > LIMIT + 16 * 1024**2 or len(members) > 15010:
                raise RuntimeError('The NPM archive exceeds its unpacked-size/entry bound.')
            if item.issym():
                symbolic[name] = normal_link(name, item.linkname)
            if item.islnk():
                target = PurePosixPath(item.linkname)
                if target.is_absolute() or '..' in target.parts or not target.parts or target.parts[0] != 'payload':
                    raise RuntimeError('An unsafe NPM archive hardlink was rejected.')
                hardlinks[name] = target
    if not {PurePosixPath('manifest.json'), PurePosixPath('payload-inventory.json'), PurePosixPath('payload')} <= members.keys():
        raise RuntimeError('The NPM archive is missing its metadata/payload root.')
    if not members[PurePosixPath('payload')].isdir():
        raise RuntimeError('The NPM archive payload root is not a directory.')
    for name in members:
        if any(parent in symbolic or parent in hardlinks for parent in name.parents):
            raise RuntimeError('An NPM archive entry is nested beneath a link.')
    for target in list(symbolic.values()) + list(hardlinks.values()):
        if (target not in members or not members[target].isfile()
                or any(parent in symbolic or parent in hardlinks for parent in target.parents)):
            raise RuntimeError('An NPM archive link does not point directly to a regular payload file.')
    return total


def inventory_difference(expected, actual):
    fields, details, xattrs = {}, [], {'added': {}, 'removed': {}, 'changed': {}}
    deltas = []
    before, after = expected.get('entries', {}), actual.get('entries', {})
    safe_xattrs = {'system.posix_acl_access', 'system.posix_acl_default', 'security.selinux', 'security.capability'}
    total = 0
    for path in sorted(set(before) | set(after)):
        old, new = before.get(path), after.get(path)
        if old == new:
            continue
        total += 1
        changed = ({'missing-entry': {'expected': old, 'actual': None}} if new is None else
                   {'additional-entry': {'expected': None, 'actual': new}} if old is None else
                   {key: {'expected': old.get(key), 'actual': new.get(key)} for key in sorted(set(old) | set(new))
                    if old.get(key) != new.get(key)})
        for key in changed:
            fields[key] = fields.get(key, 0) + 1
        if old is not None and new is not None:
            if 'mtimeNs' in changed:
                deltas.append(new['mtimeNs'] - old['mtimeNs'])
            a, b = old.get('xattrs', {}), new.get('xattrs', {})
            for key in set(a) | set(b):
                if a.get(key) != b.get(key):
                    group = 'added' if key not in a else 'removed' if key not in b else 'changed'
                    safe = key if key in safe_xattrs else '[other xattr name withheld]'
                    xattrs[group][safe] = xattrs[group].get(safe, 0) + 1
        if len(details) < 500:
            details.append({'path': path, 'differences': changed})
    summary = {'differingEntries': total, 'differingFields': fields,
               'sourceBytes': expected.get('bytes'), 'extractedBytes': actual.get('bytes'),
               'xattrDifferences': xattrs}
    if deltas:
        summary['mtimeDeltaNsRange'] = [min(deltas), max(deltas)]
    return summary, details


def validate_export(extracted, ready, source, diagnostic_path=None):
    if (file_digest(extracted / 'manifest.json') != ready['manifestSha256']
            or file_digest(extracted / 'payload-inventory.json') != ready['inventorySha256']):
        raise RuntimeError('The received source NPM metadata failed its SHA256 checks.')
    manifest = json.loads((extracted / 'manifest.json').read_text())
    expected = json.loads((extracted / 'payload-inventory.json').read_text())
    if (manifest.get('format') != EXPORT_FORMAT or manifest.get('sourceHost') != '192.168.0.29'
            or manifest.get('createdUtc') != ready['createdUtc'] or manifest.get('sourceStopped') is not False
            or manifest.get('container', {}).get('Image') != source.SOURCE_IMAGE
            or manifest.get('retiredDomains') != RETIRED
            or manifest.get('shelfmarkAudio', {}).get('certificateId') != 86):
        raise RuntimeError('The current NPM export differs from the reviewed source/retirement/certificate report.')
    payload = extracted / 'payload'
    actual = source.inventory(payload)
    if actual != expected or expected['bytes'] != ready['payloadBytes']:
        summary, details = inventory_difference(expected, actual)
        say('NPM INVENTORY DIFFERENCE SUMMARY: ' + json.dumps(summary, sort_keys=True))
        if diagnostic_path is not None:
            report = {'format': 'sawdoctor-npm-inventory-diff-v1', 'archiveSha256': ready['archiveSha256'],
                      'inventorySha256': ready['inventorySha256'], 'summary': summary, 'details': details,
                      'detailLimit': 500, 'containsFileContents': False}
            source.atomic(diagnostic_path, (json.dumps(report, indent=2) + '\n').encode(), 0o600)
            say('Private metadata-only comparison: ' + str(diagnostic_path))
        raise RuntimeError('A received NPM file, permission, xattr, timestamp or link differs from its source inventory.')
    database = payload / 'data/database.sqlite'
    if file_digest(database) != manifest['databaseSha256'] or any(Path(str(database) + suffix).exists() for suffix in ('-wal', '-shm', '-journal')):
        raise RuntimeError('The consistent source NPM database differs or contains live journal files.')
    counts, shelfmark, checked = source.validate_policy(database, payload)
    if counts != manifest['counts'] or shelfmark != manifest['shelfmarkAudio'] or checked != manifest['checkedCertificateKeyPairs']:
        raise RuntimeError('The received active NPM policy or certificate report differs from the source.')
    keys = json.loads((payload / 'data/keys.json').read_text())
    if not isinstance(keys, dict) or not keys:
        raise RuntimeError('The source NPM signing keys are unavailable.')
    return manifest


def edit_upstreams(staged, routes):
    database = staged / 'payload/data/database.sqlite'
    original = staged / 'source-database.sqlite'
    shutil.copy2(database, original)
    info = database.stat()
    with contextlib.closing(sqlite3.connect(original.as_uri() + '?mode=ro', uri=True)) as before:
        changes = routes.edits(routes.routes(before))
        with contextlib.closing(sqlite3.connect(database)) as after, after:
            for item in changes:
                changed = after.execute('UPDATE proxy_host SET forward_host=? WHERE id=? AND forward_host=?',
                                        (item['newHost'], item['id'], item['oldHost'])).rowcount
                if changed != 1:
                    raise RuntimeError('A current source upstream changed before the offline edit.')
        with contextlib.closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)) as after:
            routes.compare_all(before, after, changes)
    os.utime(database, ns=(info.st_atime_ns, info.st_mtime_ns))
    return changes


def runtime_values(model, current):
    value = copy.deepcopy(model)
    config = current['Config']
    env = dict(item.split('=', 1) for item in config.get('Env', []) if '=' in item)
    service = value['services']['npm']
    for key, setting in service.get('environment', {}).items():
        if key not in env:
            if setting is not None:
                raise RuntimeError('A configured NPM environment variable is absent from the live container.')
        else:
            service['environment'][key] = env[key]
    for key in service.get('labels', {}):
        if key not in config.get('Labels', {}):
            raise RuntimeError('A configured NPM label is absent from the live container.')
        service['labels'][key] = config['Labels'][key]
    for field, name in (('command', 'Cmd'), ('entrypoint', 'Entrypoint')):
        if service.get(field) is not None:
            if config.get(name) is None:
                raise RuntimeError('An explicit NPM command/entrypoint differs from the live container.')
            service[field] = config[name]
    return value


def fingerprint(item):
    return item['Id'], item['Image'], item['State']['Status'], item['State']['StartedAt']


def prepare(source, complete, private, routes, restore):
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in routes.run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the NAS.')
    routes.mounted(routes.APP, routes.APP_UUID)
    routes.mounted(routes.BACKUP, routes.BACKUP_UUID)
    routes.no_links(KEY)
    if not KEY.is_file() or KEY.stat().st_uid != 0 or stat.S_IMODE(KEY.stat().st_mode) & 0o077:
        raise RuntimeError('The existing private NAS transfer key is unavailable or has unexpected permissions.')
    root = routes.APP / 'compose/npm-restore/cutover-current'
    routes.no_links(root)
    root.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with routes.locked(routes.LOCK):
        current = routes.target_bindings()
        stored, host_path, model = complete.live_stack(routes, restore, current)
        before = fingerprint(current)
        if shutil.disk_usage(routes.APP).free < 2 * LIMIT + 128 * 1024**2:
            raise RuntimeError('At least 1.2 GiB free space is required for bounded NPM-only collection.')
        for container in restore.all_containers():
            if any(Path(m.get('Source', '/')).is_relative_to(root) for m in container.get('Mounts', []) if m.get('Type') == 'bind'):
                raise RuntimeError('A container is using the new candidate tree; current data was retained.')
        with tempfile.TemporaryDirectory(prefix='.npm-current-', dir=root.parent) as temporary:
            work = Path(temporary)
            known = work / 'known_hosts'; known.write_text(HOST_KEY); known.chmod(0o600)
            ssh = ssh_command(known)
            ready = read_ready(ssh)
            env_sha = digest(json.dumps(stored['env'], sort_keys=True).encode())
            if root.exists():
                if {p.name for p in root.iterdir()} != CONTENTS:
                    raise RuntimeError('The current candidate contains unexpected files; it was retained.')
                record = json.loads(routes.read(root / 'prepared.json'))
                wanted = json.loads(routes.read(root / 'payload-inventory.json', 16 * 1024**2))
                if (record.get('format') != FORMAT or record.get('status') != 'current-offline-not-activated'
                        or record.get('sourceExport') != ready or record.get('nasImage') != current['Image']
                        or record.get('existingStackSha256') != digest(stored['text'].encode())
                        or record.get('existingStackEnvSha256') != env_sha
                        or source.inventory(root / 'payload') != wanted
                        or file_digest(root / 'payload-inventory.json') != record.get('payloadInventorySha256')
                        or file_digest(root / 'ready.yaml') != record.get('readySha256')
                        or file_digest(root / 'source-manifest.json') != ready['manifestSha256']
                        or file_digest(root / 'source-inventory.json') != ready['inventorySha256']
                        or file_digest(root / 'source-database.sqlite') != record.get('sourceDatabaseSha256')):
                    raise RuntimeError('An existing current candidate differs; it was retained for review.')
                say('The matching current NPM candidate remains verified; no additional copy was made.')
                return
            say('Collecting the small current NPM-only export over the existing restricted connection...')
            archive = work / 'export.tar.gz'
            receive_archive(ssh, archive, ready)
            say('NPM archive SHA256 verified: ' + str(ready['archiveBytes']) + ' bytes compressed; '
                + str(ready['payloadBytes']) + ' bytes payload.')
            if read_ready(ssh) != ready:
                raise RuntimeError('The source export changed during transfer; retry with its current completed copy.')
            validate_archive(archive)
            extracted = work / 'extracted'; extracted.mkdir(mode=0o700)
            source.run('tar', '--acls', '--xattrs', '--xattrs-include=*', '--numeric-owner', '--delay-directory-restore',
                       '-xzpf', str(archive), '-C', str(extracted), timeout=180)
            say('Verifying source metadata, private files, certificate names and key pairs...')
            manifest = validate_export(extracted, ready, source, root.parent / 'current-inventory-diff.json')
            staged = work / 'candidate'; extracted.rename(staged)
            (staged / 'manifest.json').rename(staged / 'source-manifest.json')
            (staged / 'payload-inventory.json').rename(staged / 'source-inventory.json')
            changes = edit_upstreams(staged, routes)
            counts, shelfmark, checked = source.validate_policy(staged / 'payload/data/database.sqlite', staged / 'payload')
            if counts != manifest['counts'] or shelfmark != manifest['shelfmarkAudio']:
                raise RuntimeError('The offline upstream edits changed unrelated source policy.')
            restore.DATA = root / 'payload'
            proposed = runtime_values(restore.candidate(model, current, current['Image']), current)
            definition = staged / 'ready.yaml'
            definition.write_text(yaml.safe_dump(complete.escaped(proposed), sort_keys=False)); definition.chmod(0o600)
            rendered = json.loads(restore.run('docker', 'compose', '-p', 'npm-nas', '-f', str(definition), 'config', '--format', 'json'))
            private.validate_compose(proposed, rendered, complete.escaped)
            payload_inventory = source.inventory(staged / 'payload')
            inventory_path = staged / 'payload-inventory.json'
            inventory_path.write_text(json.dumps(payload_inventory, sort_keys=True) + '\n'); inventory_path.chmod(0o600)
            now = routes.target_bindings()
            if fingerprint(now) != before or complete.live_stack(routes, restore, now)[0] != stored or read_ready(ssh) != ready:
                raise RuntimeError('The current NAS proxy/stack or source export changed; the live configuration was retained.')
            record = {'format': FORMAT, 'status': 'current-offline-not-activated', 'sourceExport': ready,
                      'sourceSnapshot': ready['createdUtc'], 'sourceDatabaseSha256': manifest['databaseSha256'],
                      'retiredDomains': RETIRED, 'counts': counts, 'changes': changes, 'shelfmarkAudio': shelfmark,
                      'checkedCertificateKeyPairs': checked, 'nasImage': current['Image'], 'existingContainerId': current['Id'],
                      'existingStackPath': str(host_path), 'existingStackSha256': digest(stored['text'].encode()),
                      'existingStackEnvSha256': env_sha, 'readySha256': file_digest(definition),
                      'payloadInventorySha256': file_digest(inventory_path),
                      'fail2banLogpathAtActivation': str(root / 'payload/data/logs/proxy-host-*_error.log')}
            (staged / 'prepared.json').write_text(json.dumps(record, indent=2) + '\n'); (staged / 'prepared.json').chmod(0o600)
            staged.rename(root)
        say('CURRENT NAS NPM CANDIDATE READY OFFLINE: ' + json.dumps(counts, sort_keys=True))
        say('Only 21 upstream addresses changed; accounts, access lists, signing keys, custom settings and certificate86 retained.')
        say('Soundspan/Chaptarr remain retired; four OptiPlex routes remain: jellyfin, maintainarr, dockhand, listenarr.')
        say('Candidate: ' + str(root / 'ready.yaml'))
        say('Existing NAS/OptiPlex proxies, public routing, renewal ownership, Fail2ban and the earlier candidate were retained.')
        say('Temporary transfer archive removed. Activation and private tests remain pending.')


def main():
    os.umask(0o077)
    if sys.argv[1:] == ['--worker']:
        def interrupted(signum, frame):
            raise RuntimeError('The bounded NPM collection was interrupted; temporary-copy cleanup requested.')
        signal.signal(signal.SIGTERM, interrupted)
        try:
            prepare(*load_helpers())
        finally:
            path = Path(sys.argv[0])
            if path.parent == Path('/run') and path.name.startswith('npm-current-'):
                path.unlink(missing_ok=True)
        return
    addresses = subprocess.run(['ip', '-4', 'addr', 'show'], capture_output=True, timeout=15)
    if sys.argv[1:] or os.geteuid() != 0 or addresses.returncode or b'inet 192.168.0.220/' not in addresses.stdout:
        raise RuntimeError('Run with sudo and no arguments on the NAS.')
    if subprocess.run(['systemctl', 'is-active', '--quiet', 'nas-npm-current-prepare.service'], capture_output=True, timeout=15).returncode == 0:
        say('Current NPM collection is already running; check its journal.'); return
    source = globals().get('INSTALL_SOURCE')
    if not isinstance(source, str) or not source.startswith('#!/usr/bin/env python3\n'):
        raise RuntimeError('The complete pinned current-NPM installer is required.')
    fd, name = tempfile.mkstemp(prefix='npm-current-', suffix='.py', dir='/run')
    with os.fdopen(fd, 'w') as stream:
        os.fchmod(stream.fileno(), 0o700); stream.write(source)
    try:
        subprocess.run(['systemctl', 'reset-failed', 'nas-npm-current-prepare.service'], capture_output=True, timeout=15)
        result = subprocess.run(['systemd-run', '--unit=nas-npm-current-prepare', '--collect',
            '--description=Prepare current NPM restore offline on NAS', '--property=Type=exec', '--property=UMask=0077',
            '--property=RuntimeMaxSec=12min', '--property=TimeoutStopSec=45s', '--property=KillMode=mixed',
            '/usr/bin/python3', name, '--worker'], capture_output=True, timeout=20)
        if result.returncode:
            raise RuntimeError('The bounded NAS collection service could not be started.')
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise
    say('Current NPM collection/preparation started in systemd. Closing SSH is safe.')
    say('Progress: sudo journalctl -u nas-npm-current-prepare.service -n 20 --no-pager -o cat')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        if isinstance(error, RuntimeError):
            raise SystemExit('STOP: ' + str(error))
        raise SystemExit('STOP: Current NPM preparation failed (' + type(error).__name__ + '); private details withheld.')
