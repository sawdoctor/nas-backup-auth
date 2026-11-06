#!/usr/bin/env python3
"""Update existing standby scope/retention only; never start a snapshot."""
import ast
import contextlib
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import types
import urllib.request

FORMAT = 'sawdoctor-migration-standby-scope-update-v1'
WORKER = Path('/usr/local/sbin/nas-migration-standby')
SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
SOURCE_BASE = Path('/var/lib/sawdoctor-migration-standby')
NAS_BASE = SSD / 'migration/nightly-standby'
SOURCE_BEFORE_SHA = '28ef7662899fadf562a475d796d7bdae7e88dd0926bb3960ed0f548b71221f63'
SOURCE_AFTER_SHA = '0d1154b7c1a3d6534e5f22e4ad1313433f043e03beb43609b98e251978998901'
NEW_WORKER_URL = 'https://raw.githubusercontent.com/sawdoctor/nas-backup-auth/2ea1698727d06b17096be1e9d45fa2b08cb993d6/scripts/install-migration-standby-sync.py'
PLEX_BACKUP = Path('/usr/local/bin/plex-daily-backup.sh')
PLEX_BACKUP_SHA = '2b940406adc76ad6a316d5739f4f64c79c0f54cddc54083d4dae4dc27fdd9e66'
NAS_HELPER = Path('/usr/local/sbin/nas-plex-npm-stage')
NAS_HELPER_SHA = '29bdb0e6a73ec3e71042b7d4bfd4acf42067d39083a820c088e3cea8a91f21b1'
OLD_PRUNE = "def prune_snapshots(root, current):\n    finished = []\n    for path in root.iterdir():\n        if path.is_symlink() or not path.is_dir() or not re.fullmatch('[0-9]{8}T[0-9]{6}Z', path.name):\n            continue\n        marker = path / '_VERIFIED.json'\n        if marker.is_file() and json.loads(marker.read_text()).get('format') == FORMAT:\n            finished.append(path)\n    for path in sorted(finished)[:-2]:\n        if path != current:\n            shutil.rmtree(path)"
NEW_PRUNE = "def prune_snapshots(root, current):\n    finished = []\n    for path in root.iterdir():\n        if path.is_symlink() or not path.is_dir() or not re.fullmatch('[0-9]{8}T[0-9]{6}Z', path.name):\n            continue\n        marker = path / '_VERIFIED.json'\n        if marker.is_file() and json.loads(marker.read_text()).get('format') == FORMAT:\n            finished.append(path)\n    # Keep the two newest standby copies AND the newest verified full Plex copy.\n    # This preserves the last full rollback while lean snapshots are trialled.\n    keep = set(sorted(finished)[-2:]) | {current}\n    full = [path for path in finished if (path/'data/plex-config').is_dir()\n            and not (path/'data/plex-config').is_symlink()]\n    if full:\n        keep.add(max(full))\n    for path in sorted(finished):\n        if path not in keep:\n            shutil.rmtree(path)"
EXPECTED_ASSIGNMENTS = {"SIGNATURE":"Constant(value='Sawdoctor nightly migration standby snapshots v1')","FORMAT":"Constant(value='sawdoctor-migration-standby-v1')","WORKER":"Call(func=Name(id='Path', ctx=Load()), args=[Constant(value='/usr/local/sbin/nas-migration-standby')], keywords=[])","SSD":"Call(func=Name(id='Path', ctx=Load()), args=[Constant(value='/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')], keywords=[])","NAS_BASE":"BinOp(left=Name(id='SSD', ctx=Load()), op=Div(), right=Constant(value='migration/nightly-standby'))","NAS_HELPER":"Call(func=Name(id='Path', ctx=Load()), args=[Constant(value='/usr/local/sbin/nas-plex-npm-stage')], keywords=[])","NAS_SHA":"Constant(value='29bdb0e6a73ec3e71042b7d4bfd4acf42067d39083a820c088e3cea8a91f21b1')","APP_NAMES":"Tuple(elts=[Constant(value='plex'), Constant(value='npm-app-1'), Constant(value='kometa'), Constant(value='houndarr'), Constant(value='homepage'), Constant(value='uptime-kuma'), Constant(value='speedtest-tracker'), Constant(value='wizarr'), Constant(value='tracearr'), Constant(value='sonarr'), Constant(value='radarr'), Constant(value='radarr4k'), Constant(value='prowlarr'), Constant(value='usenet-ultimate'), Constant(value='overseerr'), Constant(value='abr-shelfmark-bridge'), Constant(value='audiobookrequest'), Constant(value='audiobookshelf-test'), Constant(value='kavita'), Constant(value='sabnzbd-ebooks'), Constant(value='shelfmark-ebooks'), Constant(value='shelfmark-torbox'), Constant(value='stackarr-ebooks'), Constant(value='nzbdav'), Constant(value='tracearr-redis'), Constant(value='tracearr-db'), Constant(value='glances'), Constant(value='torbox-media-center')], ctx=Load())"}


def say(value):
    print(value, flush=True)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def no_links(path):
    for item in (path, *path.parents):
        if item.is_symlink():
            raise RuntimeError('An unexpected symbolic update path was retained.')


def atomic(path, data, mode=0o600, owner=None):
    no_links(path)
    fd, temporary = tempfile.mkstemp(prefix='.scope-update-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            os.fchmod(output.fileno(), mode)
            if owner:
                os.fchown(output.fileno(), *owner)
            output.write(data); output.flush(); os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def locked(stack, path):
    no_links(path)
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    handle = stack.enter_context(os.fdopen(descriptor, 'a'))
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise RuntimeError('A standby or backup operation is active; the worker was retained.') from None


def inactive(unit):
    result = subprocess.run(['systemctl', 'show', '--no-pager', unit, '-p', 'ActiveState', '--value'],
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15)
    if result.returncode or result.stdout.strip() not in ('inactive', 'failed'):
        raise RuntimeError('The related service is busy or unavailable; no worker was changed: ' + unit)


def nas_patch(original):
    text = original.decode()
    tree = ast.parse(text)
    values = {node.targets[0].id: ast.dump(node.value, include_attributes=False)
              for node in tree.body if isinstance(node, ast.Assign) and len(node.targets) == 1
              and isinstance(node.targets[0], ast.Name)}
    if any(values.get(key) != value for key, value in EXPECTED_ASSIGNMENTS.items()):
        raise RuntimeError('The existing NAS standby identity differs; it was retained.')
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'prune_snapshots']
    if len(nodes) != 1:
        raise RuntimeError('The NAS retention function needs review; the worker was retained.')
    actual = ast.get_source_segment(text, nodes[0])
    structure = ast.dump(nodes[0], include_attributes=False)
    old_structure = ast.dump(ast.parse(OLD_PRUNE).body[0], include_attributes=False)
    new_structure = ast.dump(ast.parse(NEW_PRUNE).body[0], include_attributes=False)
    if structure == new_structure:
        return original
    if structure != old_structure or text.count(actual) != 1:
        raise RuntimeError('The NAS retention logic differs from the reviewed function; it was retained.')
    updated = text.replace(actual, NEW_PRUNE, 1).encode()
    compile(updated, str(WORKER), 'exec')
    return updated


def source_candidate(original):
    if sha(original) == SOURCE_AFTER_SHA:
        return original
    if sha(original) != SOURCE_BEFORE_SHA:
        raise RuntimeError('The installed source standby worker differs; it was retained.')
    say('Downloading the reviewed smaller-snapshot worker...')
    with urllib.request.urlopen(NEW_WORKER_URL, timeout=30) as response:
        updated = response.read(262144)
    if sha(updated) != SOURCE_AFTER_SHA:
        raise RuntimeError('The replacement worker integrity check failed; the original was retained.')
    compile(updated, str(WORKER), 'exec')
    return updated


def validate_helper(path, expected):
    no_links(path)
    if not path.is_file() or sha(path.read_bytes()) != expected:
        raise RuntimeError('A required reviewed backup/transfer helper differs; the worker was retained.')


def install_locked(role, base, original, proposed):
    no_links(WORKER)
    if WORKER.read_bytes() != original:
        raise RuntimeError('The installed worker changed during preparation; it was retained.')
    inactive('nas-migration-standby.service')
    inactive('nas-migration-standby-install.service')
    if role == 'source':
        inactive('plex-daily-backup.service')
        if any((base / name).exists() or (base / name).is_symlink()
               for name in ('resume.json', 'paused-timers.json')):
            raise RuntimeError('Source recovery is pending; its worker and state were retained.')
        validate_helper(PLEX_BACKUP, PLEX_BACKUP_SHA)
        # Only definitions are loaded from the exact verified replacement.
        # The read-only check lists completed cloud backup names/sizes.
        review = types.ModuleType('reviewed_standby_scope')
        review.__file__ = str(WORKER)
        exec(compile(proposed, str(WORKER), 'exec'), review.__dict__)
        review.BASE = base
        say('Checking the existing Plex backup and its completed GDrive archive...')
        backup = review.external_plex_backup()
        say('Completed Plex cloud backup found: ' + backup['remote'].rsplit('/', 1)[1])
    else:
        validate_helper(NAS_HELPER, NAS_HELPER_SHA)
    if proposed == original:
        say('This standby scope update is already applied on ' + role + '.')
        return
    work = base / 'scope-change'
    no_links(work)
    work.mkdir(mode=0o700, exist_ok=True)
    before = work / 'worker.before'
    record = work / 'applied.json'
    if before.exists():
        no_links(before)
        if before.read_bytes() != original:
            raise RuntimeError('A different previous-worker copy was retained; no update was made.')
    else:
        if record.exists() or record.is_symlink():
            raise RuntimeError('An unexpected update record was retained.')
        atomic(before, original)
    info = WORKER.stat()
    if not stat.S_ISREG(info.st_mode):
        raise RuntimeError('The existing worker is not a regular file.')
    atomic(WORKER, proposed, stat.S_IMODE(info.st_mode), (info.st_uid, info.st_gid))
    atomic(record, (json.dumps({'format': FORMAT, 'role': role, 'beforeSha256': sha(original),
        'afterSha256': sha(proposed), 'updatedUtc': datetime.datetime.now(datetime.timezone.utc).isoformat()},
        indent=2) + '\n').encode())
    say('STANDBY SCOPE UPDATED ON ' + ('OPTIPLEX' if role == 'source' else 'NAS') + '.')
    if role == 'source':
        say('Future nightly snapshots omit Plex config; Plex stays running and its existing daily GDrive backup is retained.')
        say('Other apps, scripts, Flora/library links and recovery remain covered. Source pauses still use 00:30-02:30 UK time.')
    else:
        say('Retention keeps the two newest standby copies plus the last full Plex standby snapshot.')
    say('No snapshot, application stop, timer change, restore or data cleanup was started.')
    say('One small previous-worker recovery copy: ' + str(before))


def main():
    os.umask(0o077)
    if os.geteuid() != 0:
        raise RuntimeError('Run with sudo on the NAS first, then on the OptiPlex.')
    addresses = subprocess.check_output(['ip', '-4', 'addr', 'show'], text=True, timeout=15)
    source = 'inet 192.168.0.29/' in addresses
    nas = 'inet 192.168.0.220/' in addresses
    if source == nas:
        raise RuntimeError('The known NAS or OptiPlex LAN address is required.')
    role, base = ('source', SOURCE_BASE) if source else ('nas', NAS_BASE)
    if nas and not SSD.is_mount():
        raise RuntimeError('The NAS application SSD is not mounted.')
    no_links(base); no_links(WORKER)
    if not base.is_dir() or not WORKER.is_file():
        raise RuntimeError('The existing standby installation is required.')
    original = WORKER.read_bytes()
    proposed = source_candidate(original) if source else nas_patch(original)
    with contextlib.ExitStack() as stack:
        locked(stack, base / '.run.lock')
        locked(stack, Path('/run/lock/plex-daily-backup.lock') if source
               else Path('/run/lock/sawdoctor-nas-backup.lock'))
        install_locked(role, base, original, proposed)


if __name__ == '__main__':
    try:
        main()
    except RuntimeError as error:
        raise SystemExit('STOP: ' + str(error))
    except Exception as error:
        raise SystemExit('STOP: Scope update did not finish (' + type(error).__name__ + '); existing recovery copy retained if created.')
