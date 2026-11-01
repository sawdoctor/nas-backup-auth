#!/usr/bin/env python3
"""Read-only OptiPlex/NAS host-job inventory. No raw commands or secrets printed."""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess

SSD = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
TOPICS = {'Plex': r'plex', 'TorBox': r'torbox', 'symlinks': r'symlink|readlink|ln\s+-[^\n]*s',
          'backup/archive': r'backup|archive|timeshift|fsarchiver',
          'mount/rclone': r'rclone|fusermount|mountpoint',
          'restart/recovery': r'restart|watchdog|safe.restart|recovery',
          'InfiniDysk': r'nzbdav|infinidysk', 'books': r'audiobook|shelfmark|kavita',
          'Kometa': r'kometa|uk.us', 'migration helper': r'nas-(?:infinidysk|books|core|support)-export|nas-migration-export'}
SKIP = {'.git', '.cache', '.ssh', '.npm', '.cargo', '.rustup', '.local', '__pycache__',
        'node_modules', 'site-packages', 'venv', '.venv', 'source', 'Library',
        'Metadata', 'Media', 'logs', 'cache', 'rclone-cache', 'migration', 'backups'}
REFERENCES = re.compile(r'''(?<![A-Za-z0-9_])/(?:usr/local/(?:bin|sbin|libexec)|home/sawdoctor|root|etc)/(?:[A-Za-z0-9_.@+/-]+)''')
SCRIPT_SUFFIXES = {'.sh', '.py', '.bash', '.pl'}


def run(*args):
    try:
        return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              text=True, timeout=25)
    except (OSError, subprocess.TimeoutExpired):
        return subprocess.CompletedProcess(args, 1, '')


def read(path, limit=2 * 1024**2):
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
            return ''
        return path.read_text(errors='replace')
    except OSError:
        return ''


def topics(text):
    return [name for name, pattern in TOPICS.items() if re.search(pattern, text, re.I)]


def references(text):
    return sorted(set(REFERENCES.findall(text)))


def command_summary(command):
    """Expose executable/script names and control actions, never argument values."""
    paths = references(command)
    try:
        words = shlex.split(command)
    except ValueError:
        words = []
    programs = []
    if words and re.fullmatch(r'[A-Za-z0-9_./+-]+', words[0]) and '=' not in words[0]:
        programs.append(words[0])
    controls = []
    for match in re.finditer(r'\b(docker|systemctl|rclone|rsync|tar|find|ln|python3?|bash|sh)\b', command):
        controls.append(match[1])
    actions = [match[1] + ':' + match[2] for match in re.finditer(
        r'\b(docker|systemctl)\s+(start|stop|restart|reload|try-restart|exec)\b', command)]
    return ' ; '.join(filter(None, [
        'program=' + ','.join(programs) if programs else '',
        'tools=' + ','.join(sorted(set(controls))) if controls else '',
        'actions=' + ','.join(sorted(set(actions))) if actions else '',
        'paths=' + ','.join(paths) if paths else ''])) or 'shell command (arguments hidden)'


def script_info(path):
    text = read(path)
    if not text or not (path.suffix.lower() in SCRIPT_SUFFIXES or text.startswith('#!')):
        return None
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None
    return {'path': str(path), 'hash': digest,
            'topics': topics(str(path) + '\n' + text), 'references': references(text)}


def cron_jobs():
    jobs, references_found = [], set()
    files = [(Path('/etc/crontab'), None)]
    files += [(path, None) for path in sorted(Path('/etc/cron.d').glob('*'))]
    spool = Path('/var/spool/cron/crontabs')
    if spool.is_dir():
        files += [(path, path.name) for path in sorted(spool.iterdir()) if path.is_file()]
    for path, owner in files:
        for number, line in enumerate(read(path).splitlines(), 1):
            line = line.strip()
            if not line or line.startswith('#') or re.match(r'^[A-Za-z_][A-Za-z0-9_]*\s*=', line):
                continue
            count = (1 if line.startswith('@') else 5) + (0 if owner else 1)
            parts = line.split(None, count)
            if len(parts) != count + 1:
                continue
            schedule = ' '.join(parts[:1 if line.startswith('@') else 5])
            user = owner or parts[count - 1]
            command = parts[-1]
            jobs.append((f'{path}:{number}', schedule, user, command_summary(command)))
            references_found.update(references(command))
    print('\nCRON JOBS (active, non-comment entries)')
    if not jobs:
        print('No crontab entries found.')
    for origin, schedule, user, command in jobs:
        print(origin + ' | ' + schedule + ' | user=' + user)
        print('  ' + command)
    print('\nRUN-PARTS JOBS / ANACRON')
    for interval in ('hourly', 'daily', 'weekly', 'monthly'):
        for path in sorted(Path('/etc/cron.' + interval).glob('*')):
            if not path.is_file() or not os.access(path, os.X_OK) or not re.fullmatch(r'[A-Za-z0-9_-]+', path.name):
                continue
            package = run('dpkg-query', '-S', str(path))
            label = package.stdout.split(': ', 1)[0] if package.returncode == 0 else 'custom/unowned'
            print(str(path) + ' | ' + label)
            references_found.add(str(path))
            references_found.update(references(read(path)))
    for line in read(Path('/etc/anacrontab')).splitlines():
        line = line.strip()
        if line and not line.startswith('#') and not re.match(r'^[A-Za-z_][A-Za-z0-9_]*\s*=', line):
            fields = line.split(None, 3)
            if len(fields) == 4:
                print('anacron: ' + ' '.join(fields[:3]) + ' | ' + command_summary(fields[3]))
    pending = run('atq')
    if pending.stdout.strip():
        print('Pending at jobs: ' + str(len(pending.stdout.splitlines())) + ' (job bodies not displayed).')
    return references_found


def unit_details(text):
    commands, paths, calendars = [], set(), []
    text = text.replace('\\\n', ' ')
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', ';')) or '=' not in line:
            continue
        key, value = line.split('=', 1)
        if key.startswith('Exec'):
            commands.append(key + ': ' + command_summary(value))
            paths.update(references(value))
        elif key in ('OnCalendar', 'OnBootSec', 'OnUnitActiveSec', 'OnUnitInactiveSec', 'Unit', 'Persistent'):
            if re.fullmatch(r'[A-Za-z0-9_*.@/ :+,=~!-]+', value):
                calendars.append(key + '=' + value)
    return commands, paths, calendars


def host_units():
    catalog = run('systemctl', 'list-unit-files', '--type=service', '--type=timer', '--no-legend', '--no-pager').stdout
    names = {line.split()[0] for line in catalog.splitlines() if line.split()
             and (topics(line.split()[0]) or line.startswith('cloudflared.'))}
    for folder in (Path('/etc/systemd/system'), Path('/usr/local/lib/systemd/system')):
        names.update(path.name for path in folder.glob('*') if path.suffix in ('.service', '.timer') and not path.is_symlink())
    paths = set()
    print('\nHOST SERVICES AND TIMERS (custom or media-related)')
    for name in sorted(names):
        status = run('systemctl', 'show', name, '-p', 'ActiveState', '-p', 'SubState',
                     '-p', 'UnitFileState', '-p', 'FragmentPath', '-p', 'TriggeredBy', '-p', 'Triggers', '-p', 'User').stdout
        values = dict(line.split('=', 1) for line in status.splitlines() if '=' in line)
        body = run('systemctl', 'cat', name).stdout
        commands, refs, calendars = unit_details(body)
        print(name + ' | ' + values.get('ActiveState', '?') + '/' + values.get('SubState', '?')
              + ' | ' + values.get('UnitFileState', '?') + ' | ' + values.get('FragmentPath', '?'))
        print('  User=' + (values.get('User') or 'root/default'))
        if values.get('TriggeredBy'):
            print('  TriggeredBy=' + values['TriggeredBy'])
        for line in calendars + commands:
            print('  ' + line)
        paths.update(refs)
    print('\nALL SYSTEM TIMER SCHEDULES')
    print(run('systemctl', 'list-timers', '--all', '--no-pager').stdout.strip())
    print('\nUSER UNIT FILES')
    found = False
    for folder in (Path('/home/sawdoctor/.config/systemd/user'), Path('/root/.config/systemd/user')):
        for path in sorted(folder.glob('*')):
            if path.suffix not in ('.service', '.timer') or path.is_symlink():
                continue
            found = True; print(str(path) + ' | activation requires user-session check')
            commands, refs, calendars = unit_details(read(path))
            for line in calendars + commands:
                print('  ' + line)
            paths.update(refs)
    if not found:
        print('No user service/timer files found in the two account directories.')
    local = Path('/etc/rc.local')
    body = read(local)
    if body:
        print('\nLEGACY BOOT HOOK: /etc/rc.local')
        print('Executable:', os.access(local, os.X_OK), '| topics:', ', '.join(topics(body)))
        paths.add(str(local)); paths.update(references(body))
    return paths


def scan_scripts(roots, referenced):
    found = {}; visited = 0; limited = False
    for root in roots:
        if not root.is_dir():
            continue
        device = root.stat().st_dev
        for directory, folders, files in os.walk(root, followlinks=False):
            current = Path(directory); depth = len(current.relative_to(root).parts)
            keep = []
            for folder in folders:
                path = current / folder
                if folder in SKIP or (folder.startswith('nas-') and folder.endswith('-export')) or path.is_symlink():
                    continue
                try:
                    if path.stat().st_dev == device and depth < 5:
                        keep.append(folder)
                except OSError:
                    pass
            folders[:] = keep
            for name in files:
                visited += 1
                if visited > 30000:
                    limited = True; break
                path = current / name
                if path.suffix.lower() not in SCRIPT_SUFFIXES and not os.access(path, os.X_OK):
                    continue
                info = script_info(path)
                if info and info['topics']:
                    found[str(path)] = info
            if limited:
                break
        if limited:
            break
    # Follow literal script references from jobs and other scripts, to depth 4.
    pending = set(referenced) | {reference for info in found.values() for reference in info['references']}
    seen = set()
    for _ in range(4):
        extra = set()
        for value in sorted(pending - seen):
            seen.add(value)
            info = found.get(value) or script_info(Path(value))
            if info:
                found[value] = info; extra.update(info['references'])
        pending = extra - seen
    print('\nHOST / CUSTOM SCRIPT FILES')
    for path, info in sorted(found.items()):
        print(path + ' | sha256=' + info['hash'][:16] + ' | ' + ', '.join(info['topics']))
        refs = [p for p in info['references'] if Path(p).suffix.lower() in SCRIPT_SUFFIXES or p.startswith('/usr/local/')]
        if refs:
            print('  script references: ' + ', '.join(refs))
    if limited:
        print('Scan reached its 30,000-file bound; job-referenced scripts were still checked separately.')
    print('File scan stays on local filesystems; app source checkouts and caches are skipped.')
    return found


def nas_staged_jobs():
    print('\nSOURCE HOST FILES CAPTURED IN NAS SNAPSHOTS')
    captured = {}
    for snapshot in sorted((SSD / 'migration').glob('*-optiplex/snapshot')):
        try:
            manifest = json.loads((snapshot / 'manifest.json').read_text())
        except (OSError, ValueError):
            continue
        units = manifest.get('hostUnits', {})
        if units:
            print(snapshot.parent.name + ' | captured source unit records: ' + ', '.join(sorted(units)))
        entries = manifest.get('hostFiles', [])
        entries = list(entries.values()) if isinstance(entries, dict) else list(entries)
        # App roots also contain custom bridges/hooks and the TorBox patches.
        # Record only local scripts, never follow copied library symlinks.
        for label, root in manifest.get('dataRoots', {}).items():
            directory = snapshot / root['snapshot']
            if directory.is_symlink() or not directory.is_dir() or not directory.resolve().is_relative_to(snapshot.resolve()):
                continue
            for parent, folders, files in os.walk(directory, followlinks=False):
                parent = Path(parent); depth = len(parent.relative_to(directory).parts)
                folders[:] = [name for name in folders if name not in SKIP and depth < 4
                              and not (parent / name).is_symlink()]
                for name in files:
                    path = parent / name
                    if path.suffix.lower() not in SCRIPT_SUFFIXES or path.is_symlink():
                        continue
                    info = script_info(path)
                    if not info or not info['topics']:
                        continue
                    relative = path.relative_to(directory)
                    candidates = [SSD / 'appdata/books-nas' / label / relative,
                                  SSD / 'appdata/support-nas' / label / relative,
                                  SSD / 'appdata/media-core-nas' / label / relative]
                    entries.append({'source': str(Path(root['source']) / relative),
                                    'snapshot': path.relative_to(snapshot).as_posix(),
                                    'nasCandidates': candidates})
        for entry in entries:
            if not isinstance(entry, dict) or 'source' not in entry or 'snapshot' not in entry:
                continue
            path = snapshot / entry['snapshot']
            if not path.resolve().is_relative_to(snapshot.resolve()):
                continue
            info = script_info(path)
            source = entry['source']
            if info or source.endswith(('.service', '.timer')):
                digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() and not path.is_symlink() else ''
                local = Path(source)
                installed = bool(digest and local.is_file() and not local.is_symlink()
                                 and local.stat().st_size < 2 * 1024**2
                                 and hashlib.sha256(local.read_bytes()).hexdigest() == digest)
                matches = [str(candidate) for candidate in entry.get('nasCandidates', [])
                           if candidate.is_file() and not candidate.is_symlink()
                           and candidate.stat().st_size < 2 * 1024**2
                           and hashlib.sha256(candidate.read_bytes()).hexdigest() == digest]
                captured[(source, digest)] = (installed, matches)
    for (source, digest), (installed, matches) in sorted(captured.items()):
        print(source + ' | copied=' + ('yes' if digest else 'missing')
              + ' | same path/content installed=' + ('yes' if installed else 'not confirmed')
              + ' | sha256=' + digest[:16])
        if matches:
            print('  Matching NAS app file: ' + ', '.join(matches))
    print('A staged source file is not proof that its job is installed or enabled. NAS replacements can have different names and content.')


def main():
    addresses = run('ip', '-4', 'addr', 'show').stdout
    if os.geteuid() != 0:
        raise RuntimeError('Run with sudo.')
    if 'inet 192.168.0.29/' in addresses:
        role = 'OPTIPLEX'; roots = [Path('/usr/local/bin'), Path('/usr/local/sbin'), Path('/usr/local/libexec'), Path('/home/sawdoctor')]
    elif 'inet 192.168.0.220/' in addresses:
        role = 'NAS'; roots = [Path('/usr/local/bin'), Path('/usr/local/sbin'), Path('/usr/local/libexec')]
    else:
        raise RuntimeError('Run on the OptiPlex or NAS, identified by its LAN address.')
    print('HOST-JOB AUDIT: ' + role)
    print('Read-only report. Credentials, raw script bodies and raw command arguments are omitted.')
    refs = cron_jobs() | host_units()
    scan_scripts(roots, refs)
    if role == 'NAS':
        nas_staged_jobs()
    print('\nAUDIT COMPLETE. No jobs, containers, mounts or application files were changed.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('STOP: ' + (str(error) if isinstance(error, RuntimeError) else
                         'The read-only audit could not finish (' + type(error).__name__ + ').'))
        raise SystemExit(1)
