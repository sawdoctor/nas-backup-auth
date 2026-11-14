#!/usr/bin/env python3
"""Repair Homepage tile hrefs using current enabled NPM proxy-host records.

Only href fields outside widget trees are changed. Existing public URLs,
widget/API URLs, API keys, private administration links and all other settings
are retained. NPM is read-only. A small original config copy is retained and
only Homepage is restarted when its links actually change.
"""
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import yaml

APP = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
WORK = APP / 'compose/production-cutover/homepage-link-repair'
LOCK = Path('/run/lock/sawdoctor-nas-backup.lock')
LOCAL = {'192.168.0.220', '192.168.0.29'}
PRIVATE_PORTS = {22, 80, 81, 443, 3180, 8001, 9000, 9443, 10081}
PRIVATE_NAMES = {'omv', 'openmediavault', 'dockmon', 'dockhand', 'portainer', 'npm', 'nginx', 'nginxproxymanager'}
DOMAIN = re.compile(r'^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.sawdoctor\.uk$', re.I)


def say(value): print(value, flush=True)
def sha(body): return hashlib.sha256(body).hexdigest()


def safe(path):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise RuntimeError('An unexpected symbolic Homepage repair path was retained.')


def routes(database):
    safe(database)
    db = sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=5)
    db.row_factory = sqlite3.Row
    try:
        db.execute('PRAGMA query_only=ON')
        required = {'domain_names', 'forward_host', 'forward_port', 'enabled', 'is_deleted', 'certificate_id'}
        columns = {row[1] for row in db.execute('PRAGMA table_info(proxy_host)')}
        if not required <= columns:
            raise RuntimeError('The current NPM proxy-host schema differs; no Homepage change made.')
        result = {}
        for row in db.execute('SELECT domain_names,forward_host,forward_port FROM proxy_host WHERE enabled=1 AND is_deleted=0 AND certificate_id>0'):
            if row['forward_host'] != '192.168.0.220':
                continue
            port = int(row['forward_port'])
            if port in PRIVATE_PORTS:
                continue
            domains = json.loads(row['domain_names'])
            if not isinstance(domains, list):
                raise RuntimeError('An NPM domain list is malformed; no Homepage change made.')
            for domain in domains:
                if isinstance(domain, str) and DOMAIN.fullmatch(domain):
                    result.setdefault(port, set()).add(domain.lower())
        return result
    finally:
        db.close()


def repair(text, mapping):
    # Use scalar marks, rather than reserialising YAML: comments, credentials,
    # environment templates and every unselected byte remain unchanged.
    document = yaml.compose(text)
    changes, skipped = [], []
    protected, active = set(), set()
    nodes = 0
    def children(node):
        if isinstance(node, yaml.MappingNode):
            return [child for pair in node.value for child in pair]
        return node.value if isinstance(node, yaml.SequenceNode) else []
    def protect(node):
        if id(node) in protected: return
        protected.add(id(node))
        for child in children(node): protect(child)
    def validate(node, names=(), depth=0):
        nonlocal nodes
        nodes += 1
        if nodes > 10000 or depth > 24:
            raise RuntimeError('Homepage structure exceeds its repair bound.')
        if id(node) in active:
            raise RuntimeError('Recursive Homepage aliases require review.')
        active.add(id(node))
        if isinstance(node, yaml.MappingNode):
            for key, child in node.value:
                label = key.value if isinstance(key, yaml.ScalarNode) else ''
                if label == 'widget' or re.sub(r'[^a-z0-9]', '', label.lower()) in PRIVATE_NAMES:
                    protect(child)
                validate(key, names, depth + 1)
                validate(child, (*names, label), depth + 1)
        elif isinstance(node, yaml.SequenceNode):
            for child in node.value: validate(child, names, depth + 1)
        active.remove(id(node))
    if document is None: return text, changes, skipped
    validate(document)
    edits = {}
    def visit(node, names=()):
        if id(node) in protected: return
        if isinstance(node, yaml.MappingNode):
            label = names[-1] if names else 'Homepage'
            private_name = re.sub(r'[^a-z0-9]', '', label.lower()) in PRIVATE_NAMES
            values = {key.value: value for key, value in node.value if isinstance(key, yaml.ScalarNode)}
            href_node = values.get('href')
            if isinstance(href_node, yaml.ScalarNode) and not private_name and id(href_node) not in protected:
                href = href_node.value; url = urllib.parse.urlsplit(href)
                if url.scheme in ('http', 'https') and url.hostname in LOCAL:
                    port = url.port or (443 if url.scheme == 'https' else 80)
                    if url.username is not None or url.password is not None:
                        raise RuntimeError('A tile contains embedded credentials; no config was written.')
                    options = mapping.get(port, set()) if port not in PRIVATE_PORTS else set()
                    span = (href_node.start_mark.index, href_node.end_mark.index)
                    anchored = text[span[0]:span[1]].lstrip().startswith('&')
                    if len(options) == 1 and not anchored:
                        domain = next(iter(options))
                        if not DOMAIN.fullmatch(domain):
                            raise RuntimeError('A proposed tile hostname is not an existing service hostname.')
                        target = url._replace(scheme='https', netloc=domain).geturl()
                        if span not in edits:
                            edits[span] = json.dumps(target, ensure_ascii=False)
                            changes.append({'tile': label, 'oldEndpoint': url.hostname + ':' + str(port), 'publicHost': domain})
                    else:
                        skipped.append({'tile': label, 'port': port, 'reason': 'private, missing, ambiguous or anchored route'})
            for key, child in node.value:
                if isinstance(key, yaml.ScalarNode) and key.value != 'widget':
                    visit(child, (*names, key.value))
        elif isinstance(node, yaml.SequenceNode):
            for child in node.value: visit(child, names)
    visit(document)
    output = text
    for (start, end), value in sorted(edits.items(), reverse=True):
        output = output[:start] + value + output[end:]
    yaml.compose(output)  # Syntax check without evaluating Homepage templates.
    return output, changes, skipped


def write_config(path, body, original):
    descriptor, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(body); stream.flush(); os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), original.st_mode & 0o777)
            os.fchown(stream.fileno(), original.st_uid, original.st_gid)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def inspect_tracearr():
    """Only endpoint metadata and the polling flag, never tokens or full rows."""
    command = ['docker', 'exec', '-i', 'tracearr-db-nas', 'sh', '-c',
               'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -X -q -t -A -v ON_ERROR_STOP=1']
    def query(sql):
        result = subprocess.run(command, input='BEGIN READ ONLY;\n' + sql + '\nROLLBACK;\n',
                                capture_output=True, text=True, timeout=15)
        if result.returncode:
            raise RuntimeError('Tracearr endpoint inspection unavailable; no Tracearr change made.')
        return json.loads(result.stdout.strip())
    try:
        tables = query("SELECT COALESCE(json_agg(table_name),'[]'::json) FROM information_schema.tables WHERE table_schema='public';")
        if 'servers' in tables:
            rows = query("""SELECT COALESCE(json_agg(json_build_object(
              'id',row_to_json(s)->'id','name',row_to_json(s)->'name',
              'type',COALESCE(row_to_json(s)->'type',row_to_json(s)->'provider'),
              'url',COALESCE(row_to_json(s)->'url',row_to_json(s)->'server_url',row_to_json(s)->'serverUrl'))),'[]'::json)
              FROM (SELECT * FROM public.servers LIMIT 16) AS s;""")
            for row in rows:
                value = row.get('url')
                shown = '[URL field unavailable]'
                if isinstance(value, str):
                    parsed = urllib.parse.urlsplit(value)
                    if parsed.scheme in ('http', 'https') and parsed.hostname:
                        shown = parsed.scheme + '://' + parsed.hostname + (':' + str(parsed.port) if parsed.port else '')
                say('Tracearr server: ' + json.dumps({'id': row.get('id'), 'name': row.get('name'), 'type': row.get('type'), 'endpoint': shown}))
        else:
            say('Tracearr server table names: ' + json.dumps([name for name in tables if 'server' in name]))
        if 'settings' in tables:
            rows = query("SELECT COALESCE(json_agg(json_build_object('name',name,'value',value)),'[]'::json) FROM public.settings WHERE name='pollerEnabled';")
            for row in rows:
                say('Tracearr pollerEnabled: ' + (str(row['value']) if type(row.get('value')) is bool else '[not a literal boolean]'))
    except Exception:
        say('Tracearr endpoint inspection unavailable; no Tracearr change was made.')


def main():
    if globals().get('APPLY_HOMEPAGE_PUBLIC_LINKS') is not True:
        raise RuntimeError('The explicit Homepage-link apply flag is required.')
    if os.geteuid() != 0 or not APP.is_mount():
        raise RuntimeError('Run with sudo on the NAS with its application SSD mounted.')
    if 'inet 192.168.0.220/' not in subprocess.check_output(['ip', '-4', 'addr', 'show'], text=True, timeout=5):
        raise RuntimeError('Run on the NAS at192.168.0.220.')
    rows = json.loads(subprocess.check_output(['docker', 'inspect', 'homepage-nas', 'npm-nas'], text=True, timeout=15))
    catalog = {row['Name'].lstrip('/'): row for row in rows}
    for name in ('homepage-nas', 'npm-nas'):
        if not catalog[name]['State']['Running']:
            raise RuntimeError(name + ' must be running before repairing its links.')
    def bound(name, destination):
        values = [Path(item['Source']) for item in catalog[name]['Mounts'] if item['Destination'] == destination and item['Type'] == 'bind']
        if len(values) != 1 or not values[0].is_relative_to(APP):
            raise RuntimeError('An accepted NAS configuration binding differs.')
        safe(values[0]); return values[0]
    config = bound('homepage-nas', '/app/config') / 'services.yaml'; safe(config)
    database = bound('npm-nas', '/data') / 'database.sqlite'
    safe(LOCK)
    with LOCK.open('a') as lock:
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise RuntimeError('NAS backup/recovery is busy; no config changed.') from None
        old = config.read_bytes(); info = config.stat()
        if len(old) > 2 * 1024**2:
            raise RuntimeError('Homepage config exceeds its size bound.')
        result, changes, skipped = repair(old.decode('utf-8'), routes(database))
        if not changes:
            say('No unambiguous LAN tile links could be changed; no file or service change.')
            say('Skipped tiles: ' + json.dumps(skipped))
            inspect_tracearr()
            return
        body = result.encode('utf-8')
        safe(WORK); WORK.mkdir(mode=0o700, exist_ok=True)
        stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        backup = WORK / ('services.before-' + stamp + '.yaml')
        descriptor = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(old); stream.flush(); os.fsync(stream.fileno())
        if config.read_bytes() != old:
            raise RuntimeError('Homepage was edited concurrently; no live change made.')
        write_config(config, body, info)
        summary = {'beforeSha256': sha(old), 'afterSha256': sha(body), 'backup': str(backup), 'changes': changes, 'skipped': skipped}
        summary_path = WORK / ('change-' + stamp + '.json')
        descriptor = os.open(summary_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, 'w') as stream: json.dump(summary, stream, indent=2)
        for change in changes:
            say(change['tile'] + ' -> https://' + change['publicHost'])
        say('Restarting only Homepage to load the corrected tile links...')
        subprocess.run(['docker', 'restart', '--timeout', '15', 'homepage-nas'], check=True, capture_output=True, timeout=45)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        try:
            with opener.open('http://192.168.0.220:3002/', timeout=3) as response:
                if response.status == 200: break
        except OSError:
            pass
        time.sleep(1)
    else:
        raise RuntimeError('Links are saved; Homepage did not become ready in45seconds. Original config retained.')
    say('HOMEPAGE TILE LINKS RESTORED: ' + str(len(changes)) + '. Widget/API configuration and existing public links retained.')
    say('Original config: ' + str(backup))
    if skipped: say('Skipped tiles: ' + json.dumps(skipped))
    say('Fully close and reopen the Homepage APK to discard its cached tile data.')
    inspect_tracearr()


if __name__ == '__main__':
    try: main()
    except Exception as exc:
        raise SystemExit('STOP: ' + (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__))
