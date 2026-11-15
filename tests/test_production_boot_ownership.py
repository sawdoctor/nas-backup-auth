"""Boot ownership preserves current apps and separate pending job conditions."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
import yaml

ROOT = Path(__file__).resolve().parents[1]
def module(filename, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
r = module('restore-nas-production-boot-ownership.py', 'current_boot')
s = module('reconcile-nas-production-startup-images.py', 'current_boot_startup')


class Fixture:
    def __init__(self, root):
        self.root = root; self.app = root / 'app'; self.app.mkdir(); self.work = self.app / 'boot'; self.work.mkdir()
        self.units = root / 'units'; self.units.mkdir(); self.rows = {}; self.originals = {}; self.images = {}; self.calls = []; self.held = []
        self.books = types.SimpleNamespace(APPS={name.removesuffix('-nas'): {} for name in r.BOOK_NAMES},
            SIGNATURE='existing book marker', MOUNT_UNITS=['nas-infinidysk-rclone.service'], unit_text=lambda: '# existing book unit\n')
        self.recovery = types.SimpleNamespace(unit_documents=lambda: {'nas-media-boot.service': '# existing media unit\n'},
            settings=lambda: {'autostart': sorted(r.MEDIA)}, ready=lambda row, mounts: True,
            host_mounts=lambda: {}, stale_bindings=lambda row, mounts: False)
        names = {'nzbdav': 'infinidysk-nas', 'overseerr': 'seerr-nas', 'radarr': 'radarr-nas',
                 'radarr4k': 'radarr4k-nas', 'sonarr': 'sonarr-nas', 'prowlarr': 'prowlarr-nas', 'usenet-ultimate': 'usenet-ultimate-nas'}
        self.helper = types.SimpleNamespace(NAMES=names)
        self.plan = {'containers': {}, 'liveRoots': {'plex': str(self.app / 'plex-config')}, 'nasImages': {'plex': 'obsolete-frozen-image'}}
        Path(self.plan['liveRoots']['plex']).mkdir(); (Path(self.plan['liveRoots']['plex']) / 'Preferences.xml').write_text('private preferences')
        self.main = {'proof': {'cutoverId': 'same-source-hold'}, 'raw': str(root / 'raw')}
        source = []
        models = {}
        for index, name in enumerate(sorted(r.POLICIES)):
            project = ('books-nas' if name in r.BOOK_NAMES else 'media-core-nas' if name in r.MEDIA - {'silo-nas-silo-1'} or name == 'seerr-nas'
                       else 'silo-nas' if name == 'silo-nas-silo-1' else 'support-nas' if name == 'kometa-nas' else name)
            service = name.removesuffix('-nas')
            if name == 'silo-nas-silo-1': service = 'silo'
            if name == 'seerr-nas': service = 'overseerr'
            path = self.app / 'stacks' / project / 'compose.yaml'; path.parent.mkdir(parents=True, exist_ok=True)
            definition = models.setdefault(path, {'services': {}})
            if project == 'books-nas': definition['x-sawdoctor-managed'] = self.books.SIGNATURE
            restart = 'unless-stopped' if name == 'dockmon' else 'on-failure:5' if name == 'silo-nas-silo-1' else 'no'
            reference = 'lscr.io/linuxserver/plex:current' if name == 'plex-nas' else 'repository/' + name + ':latest'
            image = 'sha256:' + hashlib.sha256(name.encode()).hexdigest(); self.images[reference] = image
            definition['services'][service] = {'container_name': name, 'image': reference, 'restart': restart,
                'environment': {'SECRET': 'NEVER-PRINT-THIS'}, 'volumes': ['/actual-data:/config']}
            row = {'Name': '/' + name, 'Id': 'container-' + name, 'Image': image, 'RestartCount': 0,
                'State': {'Running': True, 'StartedAt': 'original-start'},
                'Mounts': [{'Type': 'bind', 'Source': '/actual-data', 'Destination': '/config', 'RW': True}],
                'Config': {'Image': reference, 'Env': ['SECRET=private'], 'Labels': {
                    'com.docker.compose.project': project, 'com.docker.compose.service': service,
                    'com.docker.compose.project.config_files': str(path), 'com.docker.compose.project.working_dir': str(path.parent)}},
                'HostConfig': {'RestartPolicy': r.policy_dict('no'), 'NetworkMode': 'host' if name == 'plex-nas' else 'media-core',
                               'Devices': [{'PathOnHost': '/dev/dri'}] if name == 'plex-nas' else []}}
            self.rows[name] = row
            prior = 'on-failure:5' if name in r.MEDIA else 'unless-stopped' if name in r.LOCAL else 'no'
            self.plan['containers'][name] = {'HostConfig': {'RestartPolicy': r.policy_dict(prior)}}
            original = next((key for key, value in names.items() if value == name), name.removesuffix('-nas'))
            source.append({'Name': '/' + original, 'HostConfig': {'RestartPolicy': r.policy_dict('on-failure:5' if name == 'plex-nas' else 'unless-stopped')}})
        # Kometa is sourced from the frozen manifest; it had no NAS plan entry.
        del self.plan['containers']['kometa-nas']
        for path, doc in models.items():
            data = ('# retained comments\n' + yaml.safe_dump(doc, sort_keys=False)).encode(); path.write_bytes(data); path.chmod(0o640)
            self.originals[path] = data
        raw = Path(self.main['raw']); raw.mkdir(); manifest = raw / 'manifest.json'; manifest.write_text(json.dumps({'containers': source}))
        self.main['proof']['manifestSha256'] = self.digest(manifest)
        self.state = self.app / 'main.json'; self.state.write_text(json.dumps(self.main))
        self.active = self.app / 'import-active'; self.active.write_text('existing hold')
        self.image_record = self.app / 'image-state.json'; self.image_record.write_text(json.dumps({'phase': 'complete', 'cutoverId': 'same-source-hold'}))
        self.torbox = root / 'torbox'; self.torbox.write_bytes(b'reviewed empty-folder helper')
        for unit, body in {'nas-books.service': self.books.unit_text(), 'nas-media-boot.service': '# existing media unit\n',
                           'nas-production-import-guard.service': '# existing import guard\n'}.items():
            (self.units / unit).write_text(body)
        self.condition = '# held\n[Unit]\nConditionPathExists=!' + str(self.active) + '\n'
        for unit in (*r.RELEASE, 'cron.service', 'nas-flora-queue-watch.timer'):
            path = self.units / (unit + '.d'); path.mkdir(); (path / '96-hold.conf').write_text(self.condition)
        self.edges = {'nas-media-boot.service': ['nas-production-import-guard.service', 'nas-infinidysk-rclone.service'],
                      'nas-books.service': ['nas-infinidysk-rclone.service', 'nas-production-import-guard.service'],
                      'nas-torbox-media.service': ['nas-backup-resume.service'],
                      'nas-backup.service': ['nas-books.service', 'nas-media-boot.service']}
        self.unit_active = False
        self.native = types.SimpleNamespace(UNITS=self.units, SCRATCH=root / 'scratch', STATE=self.state, ACTIVE=self.active,
            DROPIN='96-hold.conf', CONDITION=self.condition, BACKUP_LOCK=root / 'backup.lock', PREFS=Path('Preferences.xml'),
            HELPERS={'recovery': (root / 'recovery', 'reviewed')}, read=self.read, digest=self.digest, atomic=self.atomic,
            run=self.run, catalog=lambda: copy.deepcopy(self.rows), approved=lambda sha: self.plan,
            helpers=lambda: {'recovery': self.recovery, 'core': self.helper}, guard_text=lambda: '# existing import guard\n',
            held=lambda proof: self.held.append(proof), sync_dir=lambda path: None, lock=self.lock,
            module=lambda *args: self.recovery)
        self.backup = types.SimpleNamespace(PLAN_SHA='accepted', IDENTITY_SHA='accepted',
            preflight=lambda native: (copy.deepcopy(self.main), copy.deepcopy(self.rows)),
            load=lambda *args: self.books, unit=lambda native, unit: {'ActiveState': 'active' if self.unit_active or unit != 'nas-production-plex.service' else 'inactive',
                'SubState': 'exited' if self.unit_active or unit != 'nas-production-plex.service' else 'dead', 'Result': 'success'})
        self.startup = types.SimpleNamespace(RECORD=self.image_record, sample_passed=lambda *args: None,
            compose_context=s.compose_context, compose_model=s.compose_model, service_for=s.service_for,
            local_image=lambda name: self.images.get(name), mapping_value=s.mapping_value)
        self.release = object()

    @staticmethod
    def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
    @staticmethod
    def read(path, limit=None): return path.read_bytes()
    @staticmethod
    def atomic(path, value, **kwargs):
        path.write_bytes(value if isinstance(value, bytes) else (json.dumps(value) + '\n').encode())
    @contextlib.contextmanager
    def lock(self, path): yield
    def run(self, *args, **kwargs):
        self.calls.append(args)
        if args[:2] == ('docker', 'compose'):
            if args[-3:] != ('config', '--format', 'json'): raise AssertionError('Compose mutation requested')
            doc = {'services': {}}
            for i, arg in enumerate(args):
                if arg == '-f':
                    value = yaml.safe_load(Path(args[i+1]).read_text()); doc['services'].update(value.get('services', {}))
                    if 'x-sawdoctor-managed' in value: doc['x-sawdoctor-managed'] = value['x-sawdoctor-managed']
            return json.dumps(doc)
        if args[:2] == ('docker', 'update'):
            name = args[-1]; self.rows[name]['HostConfig']['RestartPolicy'] = r.policy_dict(args[2].split('=', 1)[1]); return ''
        if args[:2] == ('docker', 'start'):
            row = next(value for value in self.rows.values() if value['Id'] == args[2]); row['State']['Running'] = True; return ''
        if args[:2] == ('systemctl', 'show'): return ' '.join(self.edges.get(args[3], ()))
        if args[:3] == ('systemctl', 'start', 'nas-production-plex.service'): self.unit_active = True; return ''
        if args[0] in ('systemctl', 'systemd-analyze'): return ''
        raise AssertionError('Unexpected runtime action: ' + str(args))

    @contextlib.contextmanager
    def patched(self):
        self.self_file = self.work / 'worker.py'; self.self_file.write_text('reviewed boot controller')
        with patch.object(r, 'APP', self.app), patch.object(r, 'WORK', self.work), patch.object(r, 'SELF', self.self_file), \
             patch.object(r, 'RECORD', self.work / 'state.json'), patch.object(r, 'ACCEPTED', self.work / 'accepted.json'), \
             patch.object(r, 'TORBOX', self.torbox), patch.object(r, 'TORBOX_SHA', self.digest(self.torbox)), \
             patch.object(s, 'APP', self.app), contextlib.redirect_stdout(io.StringIO()) as output:
            yield output


class BootTransaction(unittest.TestCase):
    def test_full_owner_configuration_changes_policies_only_and_retains_other_job_guards(self):
        with tempfile.TemporaryDirectory() as folder:
            f = Fixture(Path(folder)); before = copy.deepcopy(f.rows)
            with f.patched() as output:
                record = r.configure_locked(f.native, f.backup, f.startup, f.release)
                r.activate(f.native, f.backup, f.startup, f.release, record)
                self.assertTrue(r.ACCEPTED.exists())
                self.assertEqual(json.loads(r.RECORD.read_text())['phase'], 'complete')
                docs = r.unit_documents(f.native)
            self.assertEqual(r.runtime_signature(before), r.runtime_signature(f.rows))
            for name, value in r.POLICIES.items(): self.assertEqual(f.rows[name]['HostConfig']['RestartPolicy'], r.policy_dict(value))
            self.assertTrue(f.active.exists()); self.assertEqual(f.state.read_text(), json.dumps(f.main))
            for unit in r.RELEASE: self.assertFalse((f.units / (unit + '.d') / '96-hold.conf').exists())
            for unit in ('cron.service', 'nas-flora-queue-watch.timer'):
                self.assertEqual((f.units / (unit + '.d') / '96-hold.conf').read_text(), f.condition)
            plex = docs['nas-production-plex.service']
            wants = next(line for line in plex.splitlines() if line.startswith('Wants='))
            self.assertNotIn('nas-books.service', wants)
            self.assertIn('nas-books.service', next(line for line in plex.splitlines() if line.startswith('After=')))
            self.assertIn('ConditionPathExists=!' + str(f.work / 'accepted.json'), docs['nas-production-import-guard.service.d/98-sawdoctor-production-boot-owned.conf'])
            self.assertEqual((f.units / 'nas-production-import-guard.service').read_text(), '# existing import guard\n')
            self.assertNotIn('NEVER-PRINT-THIS', output.getvalue())
            self.assertFalse(any(call[:2] in (('docker', 'restart'), ('docker', 'stop'), ('docker', 'pull')) for call in f.calls))
            self.assertEqual([call for call in f.calls if call[:2] == ('systemctl', 'start')], [('systemctl', 'start', 'nas-production-plex.service')])
            for path, old in f.originals.items():
                before_doc, after_doc = yaml.safe_load(old), yaml.safe_load(path.read_text())
                for key in before_doc['services']:
                    before_doc['services'][key]['restart'] = after_doc['services'][key]['restart']
                self.assertEqual(before_doc, after_doc); self.assertEqual(path.stat().st_mode & 0o777, 0o640)

    def test_unknown_torbox_bytes_stop_before_any_boot_mutation(self):
        with tempfile.TemporaryDirectory() as folder:
            f = Fixture(Path(folder))
            with f.patched(), patch.object(r, 'TORBOX_SHA', 'unreviewed'), self.assertRaisesRegex(RuntimeError, 'TorBox does not match'):
                r.configure_locked(f.native, f.backup, f.startup, f.release)
            self.assertFalse(any(call[:2] == ('docker', 'update') for call in f.calls))
            for path, body in f.originals.items(): self.assertEqual(path.read_bytes(), body)

    def test_inactive_existing_mount_owner_is_not_started_as_a_side_effect(self):
        with tempfile.TemporaryDirectory() as folder:
            f = Fixture(Path(folder)); f.backup.unit = lambda native, unit: {'ActiveState': 'inactive'}
            with f.patched(), self.assertRaisesRegex(RuntimeError, 'not active'):
                r.configure_locked(f.native, f.backup, f.startup, f.release)
            self.assertFalse(any(call[:2] in (('docker', 'update'), ('systemctl', 'start')) for call in f.calls))

    def test_dependency_cycle_is_rejected_before_policy_updates(self):
        with tempfile.TemporaryDirectory() as folder:
            f = Fixture(Path(folder)); f.edges['nas-backup-resume.service'] = ['nas-production-plex.service']
            with f.patched(), self.assertRaisesRegex(RuntimeError, 'dependency cycle'):
                r.configure_locked(f.native, f.backup, f.startup, f.release)
            self.assertFalse(any(call[:2] == ('docker', 'update') for call in f.calls))
            for path, body in f.originals.items(): self.assertEqual(path.read_bytes(), body)

    def test_partial_policy_update_failure_restores_our_edits_and_original_holds(self):
        with tempfile.TemporaryDirectory() as folder:
            f = Fixture(Path(folder)); original_run = f.native.run; failed = False; count = 0
            def fault(*args, **kwargs):
                nonlocal failed, count
                if args[:2] == ('docker', 'update') and not failed:
                    count += 1
                    if count == 5: failed = True; raise RuntimeError('simulated update failure')
                return original_run(*args, **kwargs)
            f.native.run = fault
            with f.patched(), self.assertRaisesRegex(RuntimeError, 'update failure'):
                r.configure_locked(f.native, f.backup, f.startup, f.release)
            for row in f.rows.values(): self.assertEqual(row['HostConfig']['RestartPolicy'], r.policy_dict('no'))
            for path, body in f.originals.items(): self.assertEqual(path.read_bytes(), body)
            for unit in r.RELEASE: self.assertEqual((f.units / (unit + '.d') / '96-hold.conf').read_text(), f.condition)
            self.assertFalse((f.work / 'accepted.json').exists())

    def test_skipped_plex_unit_does_not_claim_complete_boot_verification(self):
        with tempfile.TemporaryDirectory() as folder:
            f = Fixture(Path(folder))
            with f.patched():
                record = r.configure_locked(f.native, f.backup, f.startup, f.release)
                f.backup.unit = lambda native, unit: {'ActiveState': 'inactive', 'SubState': 'dead', 'Result': 'success'}
                with self.assertRaisesRegex(RuntimeError, 'did not complete'):
                    r.activate(f.native, f.backup, f.startup, f.release, record)
                self.assertEqual(json.loads(r.RECORD.read_text())['phase'], 'configured')

    def test_shell_native_no_restart_scalar_is_parsed_without_other_changes(self):
        source = b'services:\n  item:\n    restart: no\n    image: current\n'
        body = r.patch_policies(source, {'item': ('no', 'on-failure:5')}, s)
        self.assertEqual(body, source.replace(b'restart: no', b'restart: "on-failure:5"'))

    def test_aliased_service_cannot_change_an_unapproved_policy(self):
        source = b'services:\n  item: &shared\n    restart: "no"\n  other: *shared\n'
        with self.assertRaisesRegex(RuntimeError, 'More than'):
            r.patch_policies(source, {'item': ('no', 'on-failure:5')}, s)


class PlexBoot(unittest.TestCase):
    def boot_case(self, root):
        f = Fixture(root)
        identity = types.SimpleNamespace(evidence_for=lambda *args: {}, validate_identity=lambda *args: None,
                                         wait_plex=lambda *args: None)
        f.backup.load = lambda *args: identity
        return f

    def commit_marker(self, f):
        record = {'format': r.FORMAT, 'phase': 'complete', 'cutoverId': 'same-source-hold', 'plexSpec': r.plex_spec(f.rows['plex-nas'])}
        r.RECORD.write_text(json.dumps(record)); r.ACCEPTED.write_text(json.dumps({'format': r.FORMAT, 'cutoverId': 'same-source-hold'}))

    def test_boot_accepts_a_later_current_plex_image_without_source_access_or_recreation(self):
        with tempfile.TemporaryDirectory() as folder:
            f = self.boot_case(Path(folder))
            with f.patched():
                self.commit_marker(f)
                f.rows['plex-nas']['Image'] = 'sha256:' + '8'*64
                f.rows['plex-nas']['Config']['Image'] = 'lscr.io/linuxserver/plex:future-user-update'
                r.boot_plex(f.native, f.backup, f.release)
            self.assertFalse(f.held)
            self.assertFalse(any(call[0] == 'docker' for call in f.calls))

    def test_stopped_current_plex_is_started_only_after_local_mount_and_identity_checks(self):
        with tempfile.TemporaryDirectory() as folder:
            f = self.boot_case(Path(folder))
            with f.patched():
                self.commit_marker(f); f.rows['plex-nas']['State']['Running'] = False
                r.boot_plex(f.native, f.backup, f.release)
            self.assertEqual([call for call in f.calls if call[0] == 'docker'], [('docker', 'start', f.rows['plex-nas']['Id'])])
            self.assertFalse(f.held)

    def test_unavailable_mount_or_changed_binding_blocks_plex_start(self):
        for cause in ('mount', 'binding'):
            with tempfile.TemporaryDirectory() as folder:
                f = self.boot_case(Path(folder))
                with f.patched():
                    self.commit_marker(f); f.rows['plex-nas']['State']['Running'] = False
                    if cause == 'mount': f.recovery.ready = lambda *args: False
                    else: f.rows['plex-nas']['Mounts'][0]['Source'] = '/unexpected-data'
                    with self.assertRaises(RuntimeError): r.boot_plex(f.native, f.backup, f.release)
                self.assertFalse(any(call[0] == 'docker' for call in f.calls))

    def test_brief_recovery_lock_contention_is_waited_out_without_swallowing_body_errors(self):
        calls = []
        @contextlib.contextmanager
        def lock(path):
            calls.append(path)
            if len(calls) < 3: raise RuntimeError('NAS backup/recovery/import is busy; retry after it finishes.')
            yield
        native = types.SimpleNamespace(lock=lock, BACKUP_LOCK=Path('/shared'))
        with patch.object(r.time, 'sleep') as wait:
            with self.assertRaisesRegex(RuntimeError, 'body failure'):
                with r.boot_lock(native): raise RuntimeError('body failure')
        self.assertEqual(len(calls), 3); self.assertEqual(wait.call_count, 2)


if __name__ == '__main__': unittest.main()
