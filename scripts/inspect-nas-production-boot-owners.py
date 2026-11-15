#!/usr/bin/env python3
"""Read existing restart policies and boot owners before scoped ownership release."""
import hashlib
import json
from pathlib import Path
import yaml

APP = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
BASE = APP / 'compose/production-cutover'
STARTUP = BASE / 'startup-image-handover/worker.py'
STARTUP_SHA = '0bae9fd022244940f35c93c0bba2ed320210c4a8fde8b563746c666dae13634a'
BOOK = Path('/usr/local/sbin/nas-books-deploy.py')
BOOK_SHA = '16889a58d366a86f01e580b8efab8fed5e04cbaee6843e4240ddd87f5c0f9bc9'


def policy(value):
    if not isinstance(value, dict): return 'not-recorded'
    name = value.get('Name', 'not-recorded')
    return name + (':' + str(value['MaximumRetryCount']) if name == 'on-failure' and value.get('MaximumRetryCount') else '')


def main():
    if any(path.is_symlink() for path in (STARTUP, *STARTUP.parents)):
        raise RuntimeError('The installed startup controller path is symbolic.')
    body = STARTUP.read_bytes()
    if hashlib.sha256(body).hexdigest() != STARTUP_SHA:
        raise RuntimeError('The installed startup controller changed.')
    startup = {'__name__': 'read_boot_owners', '__file__': str(STARTUP)}
    exec(compile(body, str(STARTUP), 'exec'), startup)
    release = startup['load'](startup['RELEASE_HELPER'], startup['RELEASE_SHA'], 'boot_owner_recovery')
    backup = release.backup_module(); backup.guard()
    native = backup.load(BASE / 'worker.py', backup.NATIVE_SHA, 'boot_owner_native')
    main_state, rows = backup.preflight(native)
    record = json.loads(native.read(startup['RECORD']))
    if record.get('phase') != 'complete' or record.get('cutoverId') != main_state['proof']['cutoverId']:
        raise RuntimeError('The completed current startup-image reconciliation is required.')
    plan = native.approved(backup.PLAN_SHA)
    manifest_path = Path(main_state['raw']) / 'manifest.json'
    if native.digest(manifest_path) != main_state['proof']['manifestSha256']:
        raise RuntimeError('The retained original source manifest changed.')
    manifest = json.loads(native.read(manifest_path))
    if manifest.get('cutoverId') != main_state['proof']['cutoverId'] or manifest.get('sourceHost') != '192.168.0.29':
        raise RuntimeError('The retained original source policy identity differs.')
    source = {row['Name'].lstrip('/'): row for row in manifest['containers']}
    recovery = native.helpers()['recovery']
    books = backup.load(BOOK, BOOK_SHA, 'boot_owner_books')
    core_names = {value: key for key, value in native.helpers()['core'].NAMES.items()}
    entries, contexts, models = startup['image_audit'](native, rows)
    if any(not item['sameLocalImage'] for item in entries):
        raise RuntimeError('A current Compose image changed after reconciliation.')
    signature = release.runtime_signature(rows)
    autostart = recovery.settings()['autostart']
    book_names = {name + '-nas' for name in books.APPS}
    print('CURRENT BOOT POLICIES (no values changed):', flush=True)
    for item in entries:
        name = item['name']; row = rows[name]
        service = models[item['contextKey']]['services'][item['service']]
        owner = ('nas-books.service' if name in book_names else
                 'nas-media-boot.service' if name in autostart else
                 'nas-production-plex.service (not yet installed)' if name == 'plex-nas' else 'Docker daemon')
        before_nas = plan.get('containers', {}).get(name, {}).get('HostConfig', {}).get('RestartPolicy')
        original_name = core_names.get(name, name.removesuffix('-nas'))
        before_source = source.get(original_name, {}).get('HostConfig', {}).get('RestartPolicy')
        print(name + ': runtime=' + policy(row['HostConfig']['RestartPolicy']) +
              '; compose=' + str(service.get('restart', 'no')) + '; priorNAS=' + policy(before_nas) +
              '; source=' + policy(before_source) + '; owner=' + owner, flush=True)
    print('MEDIA BOOT MEMBERS: ' + ', '.join(sorted(autostart)), flush=True)
    book_contexts = [context for context in contexts.values() if context['project'] == 'books-nas']
    if len(book_contexts) != 1 or len(book_contexts[0]['files']) != 1:
        raise RuntimeError('The current book project is ambiguous.')
    book_raw = yaml.safe_load(native.read(book_contexts[0]['files'][0]))
    print('BOOK MANAGED MARKER MATCH: ' + str(book_raw.get('x-sawdoctor-managed') == books.SIGNATURE), flush=True)
    known = {'nas-books.service': books.unit_text(), **recovery.unit_documents(),
             'nas-production-import-guard.service': native.guard_text()}
    units = ['nas-production-import-guard.service', 'nas-media-boot.service', 'nas-books.service',
             'nas-production-plex.service', 'nas-backup-resume.service', 'nas-infinidysk-rclone.service',
             'nas-torbox-media.service', 'nas-backup.service']
    print('CURRENT BOOT UNIT ORDER:', flush=True)
    for unit in units:
        value = native.run('systemctl', 'show', '--no-pager', '--full', unit, '-p', 'LoadState',
                           '-p', 'ActiveState', '-p', 'UnitFileState', '-p', 'After', '-p', 'Requires', '-p', 'DropInPaths')
        values = dict(line.split('=', 1) for line in value.splitlines() if '=' in line)
        own = lambda key: sorted(name for name in values.get(key, '').split()
                                if name.startswith('nas-') or name in ('docker.service', 'network-online.target'))
        document = native.UNITS / unit
        exact = native.read(document) == known[unit].encode() if unit in known and document.exists() else None
        print(json.dumps({'unit': unit, 'load': values.get('LoadState'), 'active': values.get('ActiveState'),
              'enabled': values.get('UnitFileState'), 'after': own('After'), 'requires': own('Requires'),
              'dropIns': values.get('DropInPaths', '').split(), 'knownUnitMatches': exact}), flush=True)
    print('BACKEND/MOUNT HELPER IDENTITIES:', flush=True)
    for filename, expected in recovery.HELPERS.items():
        print(Path(filename).name + ': known=' + str(native.digest(Path(filename)) == expected), flush=True)
    if release.runtime_signature(native.catalog()) != signature:
        raise RuntimeError('A current container changed during the readout; keep the existing holds.')
    print('BOOT OWNERSHIP READOUT COMPLETE. No service, policy, Compose, guard or application data changed.', flush=True)


if __name__ == '__main__':
    try: main()
    except Exception as error:
        raise SystemExit('STOP: ' + (str(error) if isinstance(error, RuntimeError) else type(error).__name__) +
                         '. Existing boot/job holds and current applications retained.')
