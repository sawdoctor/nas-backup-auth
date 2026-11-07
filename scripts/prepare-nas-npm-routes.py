#!/usr/bin/env python3
"""Stage only an offline NPM route database proposal; never activate a proxy."""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile

APP_UUID = 'e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6'
BACKUP_UUID = '631e3391-6a42-4158-9aa4-f7718ba0e7e9'
APP = Path('/srv/dev-disk-by-uuid-' + APP_UUID)
BACKUP = Path('/srv/dev-disk-by-uuid-' + BACKUP_UUID)
BASE = BACKUP / 'migration/nightly-standby'
WORK = APP / 'compose/npm-restore/route-plan'
LOCK = Path('/run/lock/sawdoctor-nas-backup.lock')
FORMAT = 'sawdoctor-migration-standby-v1'
PLAN_FORMAT = 'sawdoctor-npm-route-plan-v1'
SOURCE_IMAGE = 'sha256:4393e642e233e5efd5adeb7f10918d4aaea71c9ed875b94190273fc8e87f9594'
SUFFIX = '.sawdoctor.uk'
# domain: (verified NAS container, its published IPv4 host port)
TARGETS = {
    'usenet': ('usenet-ultimate-nas', 1337), 'prowlarr': ('prowlarr-nas', 9696),
    'nzbdav': ('infinidysk-nas', 8081), 'request': ('seerr-nas', 5055),
    'sonarr': ('sonarr-nas', 8989), 'radarr': ('radarr-nas', 7878),
    'kuma': ('uptime-kuma-nas', 3001), 'homepage': ('homepage-nas', 3002),
    'radarr4k': ('radarr4k-nas', 7879), 'wizarr': ('wizarr-nas', 5690),
    'speedtest': ('speedtest-tracker-nas', 8765), 'glances': ('glances-nas', 61208),
    'houndarr': ('houndarr-nas', 8877), 'tracearr': ('tracearr-nas', 7330),
    'fail2ban': ('fail2ban-ui', 3091), 'audiobook': ('audiobookshelf-test-nas', 13378),
    'shelfmark-audio': ('shelfmark-torbox-nas', 8084),
    'abr': ('audiobookrequest-nas', 8085), 'libraseer': ('stackarr-ebooks-nas', 8484),
    'shelfmark-ebook': ('shelfmark-ebooks-nas', 8086), 'kavita': ('kavita-nas', 5000),
}
EXISTING_NAS = {'dockmon': ('https', 8001), 'omv': ('http', 80), 'silo': ('http', 8090)}
KEEP_SOURCE = {'jellyfin': 8096, 'maintainarr': 6246, 'soundspan': 3030,
               'dockhand': 3180, 'listenarr': 4545, 'chaptarr': 8789}


def say(message):
    print(message, flush=True)


def no_links(path):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise RuntimeError('An unexpected symbolic route-plan path was retained.')


def read(path, limit=2 * 1024**2):
    no_links(path)
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise RuntimeError('A route-plan input is unavailable or exceeds its size bound.')
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if len(data) > limit or any(getattr(before, k) != getattr(after, k) for k in fields):
        raise RuntimeError('A route-plan input changed while being read.')
    return data


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run(*args, allowed=(0,)):
    result = subprocess.run(args, capture_output=True, text=True, timeout=25)
    if result.returncode not in allowed:
        raise RuntimeError('A route-plan host query failed; raw settings were withheld.')
    return result.stdout


@contextlib.contextmanager
def locked(path, shared=False):
    no_links(path)
    with path.open('rb') as handle:
        try:
            fcntl.flock(handle, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('NAS backup/recovery or standby work is busy; retry later.') from None
        yield


def mounted(path, uuid):
    no_links(path)
    if not path.is_mount() or run('findmnt', '-rn', '--mountpoint', str(path), '-o', 'UUID,FSTYPE').split() != [uuid, 'ext4']:
        raise RuntimeError('An expected NAS SSD is unavailable or has a different identity.')


def checksums(path, wanted):
    no_links(path)
    seen = set()
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError('The standby checksum list is unavailable.')
        while True:
            line = stream.readline(65537)
            if not line:
                break
            if len(line) > 65536:
                raise RuntimeError('A checksum line exceeds its size bound.')
            match = re.fullmatch(rb'([a-f0-9]{64})  \./([^\r\n]+)\n?', line)
            if not match:
                continue
            member = match[2].decode('utf-8')
            if member in wanted:
                if member in seen or sha(wanted[member]) != match[1].decode():
                    raise RuntimeError('A selected NPM source checksum differs.')
                seen.add(member)
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if seen != set(wanted) or any(getattr(before, k) != getattr(after, k) for k in fields):
        raise RuntimeError('Required NPM checksums are missing or changed.')


def source():
    current = json.loads(read(BASE / 'current.json'))
    stamp = current.get('createdUtc', '')
    if not re.fullmatch(r'\d{8}T\d{6}Z', stamp) or current.get('format') != FORMAT:
        raise RuntimeError('The current standby identity differs.')
    folder = BASE / 'snapshots' / stamp
    no_links(folder)
    if (current.get('snapshot') != str(folder) or json.loads(read(folder / '_VERIFIED.json'))
            != {k: v for k, v in current.items() if k != 'snapshot'}):
        raise RuntimeError('The standby locator or verified marker differs.')
    manifest_bytes = read(folder / 'manifest.json', 8 * 1024**2)
    manifest = json.loads(manifest_bytes)
    roots = manifest.get('dataRoots', {})
    npm = [c for c in manifest.get('containers', []) if c.get('Name') == '/npm-app-1']
    if (manifest.get('format') != FORMAT or manifest.get('sourceHost') != '192.168.0.29'
            or manifest.get('scope') != 'standby-only' or manifest.get('createdUtc') != stamp
            or roots.get('npm-data', {}).get('snapshot') != 'data/npm-data'
            or len(npm) != 1 or npm[0].get('Image') != SOURCE_IMAGE):
        raise RuntimeError('The source NPM standby manifest/image differs.')
    database = folder / 'data/npm-data/database.sqlite'
    data = read(database, 64 * 1024**2)
    if any(Path(str(database) + suffix).exists() for suffix in ('-wal', '-journal')):
        raise RuntimeError('The standby NPM database unexpectedly has a write journal.')
    checksums(folder / 'SHA256SUMS', {'manifest.json': manifest_bytes, 'data/npm-data/database.sqlite': data})
    return database, stamp, sha(data)


def routes(db):
    required = {'id', 'is_deleted', 'enabled', 'domain_names', 'forward_scheme', 'forward_host', 'forward_port'}
    columns = [r[1] for r in db.execute('PRAGMA table_info(proxy_host)')]
    if not required <= set(columns):
        raise RuntimeError('The source NPM route schema differs.')
    result = {}
    for row in db.execute('SELECT id,domain_names,forward_scheme,forward_host,forward_port,enabled FROM proxy_host WHERE is_deleted=0'):
        names = json.loads(row[1])
        if not isinstance(names, list) or len(names) != 1 or not isinstance(names[0], str):
            raise RuntimeError('A source route has unexpected domain aliases; review its plan.')
        domain = names[0].lower().rstrip('.')
        if not domain.endswith(SUFFIX) or domain in result or type(row[4]) is not int:
            raise RuntimeError('Source routes contain an unexpected or duplicate domain.')
        result[domain] = {'id': row[0], 'scheme': row[2], 'host': row[3], 'port': row[4], 'enabled': row[5]}
    expected = {name + SUFFIX for name in (*TARGETS, *EXISTING_NAS, *KEEP_SOURCE)}
    if set(result) != expected:
        raise RuntimeError('The current source route set changed; review it before preparing edits.')
    return result


def edits(rows):
    result = []
    for name, (_, port) in TARGETS.items():
        domain = name + SUFFIX
        row = rows[domain]
        host = 'usenet-ultimate' if name == 'usenet' else '192.168.0.29'
        if (row['scheme'], row['host'], row['port'], row['enabled']) != ('http', host, port, 1):
            raise RuntimeError('A reviewed source upstream changed; no route proposal was applied.')
        result.append({'id': row['id'], 'domain': domain, 'oldHost': host, 'newHost': '192.168.0.220',
                       'port': port, 'scheme': 'http'})
    for name, (scheme, port) in EXISTING_NAS.items():
        row = rows[name + SUFFIX]
        if (row['scheme'], row['host'], row['port'], row['enabled']) != (scheme, '192.168.0.220', port, 1):
            raise RuntimeError('An existing NAS upstream changed; review it before preparing edits.')
    for name, port in KEEP_SOURCE.items():
        row = rows[name + SUFFIX]
        if (row['scheme'], row['host'], row['port'], row['enabled']) != ('http', '192.168.0.29', port, 1):
            raise RuntimeError('A retained source upstream changed; review it before preparing edits.')
    return result


def target_bindings():
    names = sorted({container for container, _ in TARGETS.values()} | {'npm-nas', 'dockmon', 'silo-nas-silo-1'})
    found = {c['Name'].lstrip('/'): c for c in json.loads(run('docker', 'inspect', *names))}
    if set(found) != set(names):
        raise RuntimeError('A required NAS container record is unavailable.')
    for name in names:
        if found[name]['State']['Status'] != 'running':
            raise RuntimeError('A required NAS proxy target is not running.')
    for domain, (name, port) in TARGETS.items():
        if name == 'fail2ban-ui':
            if found[name]['HostConfig']['NetworkMode'] != 'host':
                raise RuntimeError('The Fail2ban UI network mode differs.')
            continue
        ports = found[name]['HostConfig'].get('PortBindings') or {}
        if not any(key.endswith('/tcp') and item.get('HostIp') == '192.168.0.220'
                   and item.get('HostPort') == str(port) for key, values in ports.items() for item in (values or [])):
            raise RuntimeError('A reviewed NAS application published port differs.')
    listeners = run('ss', '-H', '-ltn').splitlines()
    if not any('192.168.0.220:3091' in line.split() for line in listeners):
        raise RuntimeError('The expected Fail2ban UI host listener is unavailable.')
    npm = found['npm-nas']
    mounts = [m for m in npm.get('Mounts', []) if m.get('Destination') == '/data']
    if len(mounts) != 1 or mounts[0].get('Type') != 'bind' or mounts[0].get('Source') != str(APP / 'appdata/npm/data'):
        raise RuntimeError('The live NAS NPM data binding changed; review the route plan first.')
    live_path = APP / 'appdata/npm/data/database.sqlite'
    no_links(live_path)
    with contextlib.closing(sqlite3.connect(live_path.as_uri() + '?mode=ro', uri=True, timeout=10)) as live:
        live.execute('PRAGMA query_only=ON')
        live.execute('BEGIN')
        for table in ('proxy_host', 'certificate', 'access_list', 'dead_host', 'redirection_host', 'stream'):
            if live.execute('SELECT count(*) FROM ' + table + ' WHERE is_deleted=0').fetchone()[0]:
                raise RuntimeError('The NAS proxy now has records to preserve; review a merge plan first.')
    return npm


def compare_all(source_db, candidate_db, changes):
    schemas = lambda db: db.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name').fetchall()
    if schemas(source_db) != schemas(candidate_db):
        raise RuntimeError('The proposal changed the source database schema.')
    by_id = {item['id']: item for item in changes}
    tables = [r[0] for r in source_db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    for name in tables:
        quoted = '"' + name.replace('"', '""') + '"'
        expected = source_db.execute('SELECT * FROM ' + quoted + ' ORDER BY rowid').fetchall()
        actual = candidate_db.execute('SELECT * FROM ' + quoted + ' ORDER BY rowid').fetchall()
        if name == 'proxy_host':
            cols = [r[1] for r in source_db.execute('PRAGMA table_info(proxy_host)')]
            position, identity = cols.index('forward_host'), cols.index('id')
            adjusted = []
            for row in expected:
                values = list(row)
                if row[identity] in by_id:
                    values[position] = by_id[row[identity]]['newHost']
                adjusted.append(tuple(values))
            expected = adjusted
        if expected != actual:
            raise RuntimeError('The proposal differs outside its 21 destination-address changes.')
    if candidate_db.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
        raise RuntimeError('The proposed database did not pass its integrity check.')


def stage():
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the NAS at 192.168.0.220.')
    mounted(APP, APP_UUID)
    mounted(BACKUP, BACKUP_UUID)
    with locked(LOCK), locked(BASE / '.run.lock', shared=True):
        say('Reading the verified standby NPM database and checking NAS target bindings...')
        npm_before = target_bindings()
        path, stamp, source_sha = source()
        with contextlib.closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=10)) as original:
            original.execute('PRAGMA query_only=ON')
            original.execute('BEGIN')
            if original.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
                raise RuntimeError('The standby NPM database failed its integrity check.')
            changes = edits(routes(original))
            if shutil.disk_usage(APP).free < path.stat().st_size * 2 + 16 * 1024**2:
                raise RuntimeError('The application SSD lacks space for this bounded database proposal.')
            no_links(WORK)
            if WORK.exists():
                if {p.name for p in WORK.iterdir()} != {'database.sqlite', 'plan.json'}:
                    raise RuntimeError('An existing route-plan directory has unexpected files; it was retained.')
                previous = json.loads(read(WORK / 'plan.json'))
                if previous.get('format') != PLAN_FORMAT or sha(read(WORK / 'database.sqlite', 64 * 1024**2)) != previous.get('databaseSha256'):
                    raise RuntimeError('An existing route plan was edited; it was retained.')
            WORK.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with tempfile.TemporaryDirectory(prefix='.npm-route-plan-', dir=WORK.parent) as temporary:
                tmp = Path(temporary)
                candidate = tmp / 'database.sqlite'
                with contextlib.closing(sqlite3.connect(candidate)) as proposed:
                    original.backup(proposed)
                    proposed.execute('PRAGMA journal_mode=DELETE')
                    with proposed:
                        for item in changes:
                            if proposed.execute('UPDATE proxy_host SET forward_host=? WHERE id=? AND forward_host=?',
                                                (item['newHost'], item['id'], item['oldHost'])).rowcount != 1:
                                raise RuntimeError('A source route changed before its proposal was prepared.')
                    compare_all(original, proposed, changes)
                candidate.chmod(0o600)
                if sha(read(path, 64 * 1024**2)) != source_sha or target_bindings()['Id'] != npm_before['Id']:
                    raise RuntimeError('The source or live proxy changed while planning.')
                plan = {'format': PLAN_FORMAT, 'status': 'offline-proposal-only', 'sourceSnapshot': stamp,
                        'sourceDatabaseSha256': source_sha, 'databaseSha256': sha(read(candidate, 64 * 1024**2)),
                        'changes': changes, 'alreadyNas': sorted(name + SUFFIX for name in EXISTING_NAS),
                        'retainedOptiplex': sorted(name + SUFFIX for name in KEEP_SOURCE),
                        'certificateAndSigningKeyFilesIncluded': False,
                        'allOtherDatabaseValuesRetained': True}
                record = tmp / 'plan.json'
                record.write_text(json.dumps(plan, indent=2) + '\n')
                record.chmod(0o600)
                WORK.mkdir(exist_ok=True, mode=0o700)
                for name in ('database.sqlite', 'plan.json'):
                    (tmp / name).replace(WORK / name)
        say('NAS NPM ROUTE PROPOSAL PREPARED from standby ' + stamp + '.')
        say('21 destination addresses changed in the offline copy; schemes and ports retained.')
        say('3 routes already target the NAS. 6 retained OptiPlex routes: ' + ', '.join(sorted(KEEP_SOURCE)) + '.')
        say('All other database values, accounts, ACLs and custom settings compare unchanged.')
        say('Proposal database size: ' + str((WORK / 'database.sqlite').stat().st_size) + ' bytes.')
        say('Private proposal: ' + str(WORK / 'plan.json'))
        say('This is not a complete deployable NPM restore: certificate/signing-key files are not included.')
        say('No live proxy, Fail2ban rule, container, public routing or OptiPlex setting was changed.')


def main():
    if sys.argv[1:] == ['--worker']:
        try:
            stage()
        finally:
            script = Path(sys.argv[0])
            if script.parent == Path('/run') and script.name.startswith('nas-npm-routes-'):
                script.unlink(missing_ok=True)
        return
    if sys.argv[1:]:
        raise RuntimeError('No preparation arguments are expected.')
    if os.geteuid() != 0 or 'inet 192.168.0.220/' not in run('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the NAS.')
    if run('systemctl', 'is-active', 'nas-npm-routes-prepare.service', allowed=(0, 3, 4)).strip() == 'active':
        say('Route preparation is already running; check its journal.')
        return
    source_text = globals().get('INSTALL_SOURCE')
    if not isinstance(source_text, str) or not source_text.startswith('#!/usr/bin/env python3\n'):
        raise RuntimeError('The complete pinned preparation source is required.')
    fd, path = tempfile.mkstemp(prefix='nas-npm-routes-', suffix='.py', dir='/run')
    with os.fdopen(fd, 'w') as output:
        os.fchmod(output.fileno(), 0o700)
        output.write(source_text)
    try:
        run('systemctl', 'reset-failed', 'nas-npm-routes-prepare.service', allowed=(0, 1))
        run('systemd-run', '--unit=nas-npm-routes-prepare', '--collect', '--description=Prepare offline NAS NPM route proposal',
            '--property=Type=exec', '--property=UMask=0077', '--property=RuntimeMaxSec=4min',
            '/usr/bin/python3', path, '--worker')
    except BaseException:
        Path(path).unlink(missing_ok=True)
        raise
    say('Offline NAS NPM route preparation started in systemd. Closing SSH is safe.')
    say('Progress: sudo journalctl -u nas-npm-routes-prepare.service -n 20 --no-pager -o cat')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        if isinstance(error, RuntimeError):
            raise SystemExit('STOP: ' + str(error))
        raise SystemExit('STOP: Route preparation failed (' + type(error).__name__ + '); private details withheld.')
