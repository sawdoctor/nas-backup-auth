"""Current-image file edits must not redeploy or revert updated applications."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('startup_images', ROOT / 'scripts/reconcile-nas-production-startup-images.py')
r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)


def container(name, image, reference, path, project, service):
    return {'Name': '/' + name, 'Id': 'container-' + name, 'Image': image, 'State': {'Running': True},
            'Mounts': [], 'Config': {'Image': reference, 'Env': ['SECRET=never-print'], 'Labels': {
                'com.docker.compose.project': project, 'com.docker.compose.service': service,
                'com.docker.compose.project.config_files': str(path),
                'com.docker.compose.project.working_dir': str(path.parent)}},
            'HostConfig': {'RestartPolicy': {'Name': 'no'}, 'NetworkMode': 'existing'}}


class ComposeIdentity(unittest.TestCase):
    def test_adopted_service_is_found_by_unique_container_name(self):
        row = container('plex-nas', 'current', 'version', Path('/not-used'), 'plex-nas', 'plex')
        model = {'services': {'plex-nas': {'container_name': 'plex-nas', 'image': 'version'}}}
        self.assertEqual(r.service_for(model, row), 'plex-nas')
        model['services']['duplicate'] = model['services']['plex-nas'].copy()
        with self.assertRaisesRegex(RuntimeError, 'repeated'): r.service_for(model, row)

    def test_layered_generated_container_name_is_checked(self):
        row = container('silo-nas-silo-1', 'current', 'latest', Path('/not-used'), 'silo-nas', 'silo')
        model = {'services': {'silo': {'image': 'latest'}}}
        self.assertEqual(r.service_for(model, row), 'silo')
        row['Name'] = '/unrelated'
        with self.assertRaisesRegex(RuntimeError, 'generated Compose'): r.service_for(model, row)

    def test_multiple_layers_keep_order_project_directory_and_all_profiles(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(r, 'APP', Path(folder)):
            root = Path(folder); paths = [root / name for name in ('base.yml', 'override.yml', 'media.yml', 'media.json')]
            for path in paths: path.write_text('services: {}\n')
            row = container('silo-nas-silo-1', 'image', 'image', paths[0], 'silo-nas', 'silo')
            row['Config']['Labels']['com.docker.compose.project.config_files'] = ','.join(map(str, paths))
            context = r.compose_context(row); calls = []
            native = types.SimpleNamespace(run=lambda *args, **kwargs: calls.append(args) or '{"services": {}}')
            staged = root / 'private/prepared.yaml'
            r.compose_model(native, context, {paths[0]: staged})
            command = calls[0]
            self.assertEqual(context['files'], tuple(paths))
            self.assertEqual(command[command.index('--profile') + 1], '*')
            self.assertEqual(command[command.index('--project-directory') + 1], str(root))
            self.assertEqual([command[i+1] for i, value in enumerate(command) if value == '-f'], [str(staged), *map(str, paths[1:])])
            self.assertEqual(command[-3:], ('config', '--format', 'json'))

    def test_compose_paths_outside_app_disk_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(r, 'APP', Path(folder)):
            with self.assertRaisesRegex(RuntimeError, 'outside'): r.host_path('/etc/passwd')


class ScalarEdits(unittest.TestCase):
    def test_yaml_comments_unicode_and_every_nonimage_byte_are_preserved(self):
        body = '# unchanged é\nservices:\n  app:\n    image: "old" # keep\n    environment:\n      LITERAL: "$(nothing) $HOME `nothing`"\n    volumes: ["/current:/config"]\n'.encode()
        actual = r.patch_images(body, {'app': ('old', 'repo/app:latest')})
        self.assertEqual(actual, body.replace(b'"old"', b'"repo/app:latest"'))

    def test_json_two_service_scalars_only(self):
        old = {'services': {'a': {'image': 'old-a', 'restart': 'no'}, 'b': {'image': 'old-b', 'profiles': ['hold']}}}
        new = r.patch_images(json.dumps(old).encode(), {'a': ('old-a', 'new-a'), 'b': ('old-b', 'new-b')})
        expected = copy.deepcopy(old); expected['services']['a']['image'] = 'new-a'; expected['services']['b']['image'] = 'new-b'
        self.assertEqual(json.loads(new), expected)

    def test_shared_service_alias_cannot_change_an_unapproved_service(self):
        body = b'services:\n  a: &shared\n    image: old\n  b: *shared\n'
        with self.assertRaisesRegex(RuntimeError, 'More than'): r.patch_images(body, {'a': ('old', 'new')})

    def test_unexpected_or_interpolated_image_is_rejected(self):
        for value in ('different', '${APP_IMAGE}'):
            with self.assertRaisesRegex(RuntimeError, 'differs'):
                r.patch_images(('services:\n  app:\n    image: ' + value + '\n').encode(), {'app': ('old', 'new')})


class Transaction(unittest.TestCase):
    def setup_case(self, root):
        app = root / 'app'; app.mkdir(); work = root / 'private'; work.mkdir()
        rows = {}; models = {}; originals = {}; image_ids = {}; calls = []; writes = []
        for name, rule in r.FIXES.items():
            path = app / rule['path']; path.parent.mkdir(parents=True, exist_ok=True)
            models.setdefault(path, {'services': {}})['services'][name] = {
                'container_name': name, 'image': rule['old'], 'restart': 'no',
                'environment': {'SECRET': 'do-not-print'}, 'volumes': ['/real-data:/config']}
            project = 'books-nas' if name.startswith('sabnzbd') else 'media-core-nas'
            rows[name] = container(name, rule['running'], rule['image'], path, project, name.removesuffix('-nas'))
            image_ids[rule['old']] = 'sha256:' + '0'*64; image_ids[rule['image']] = rule['running']
        plex_path = app / 'appdata/dockmon/stacks/plex-nas/compose.yaml'; plex_path.parent.mkdir(parents=True)
        models[plex_path] = {'services': {'plex-nas': {'container_name': 'plex-nas', 'image': 'plex:current-version', 'restart': 'no'}}}
        rows['plex-nas'] = container('plex-nas', 'sha256:'+'9'*64, 'plex:current-version', plex_path, 'plex-nas', 'plex')
        image_ids['plex:current-version'] = rows['plex-nas']['Image']
        for path, document in models.items():
            body = ('# keep this file\n' + yaml.safe_dump(document, sort_keys=False)).encode(); path.write_bytes(body); path.chmod(0o640)
            originals[path] = body
        media = root / 'media.json'; media.write_text(json.dumps({'phase': 'complete', 'cutoverId': 'same-hold'}))
        backup_record = root / 'backup.json'; backup_record.write_text(json.dumps({'phase': 'complete', 'backupSet': 'nas-example'}))
        result = root / 'backups/restore-check/result.json'; result.parent.mkdir(parents=True)
        result.write_text(json.dumps({'format': 'sawdoctor-nas-backup-sample-restore-v1', 'phase': 'complete',
            'backupSet': 'nas-example', 'cloudRecoveryFilesMatched': 4, 'temporaryCopiesRemoved': True,
            'applicationsStarted': False, 'databaseRows': 18721}))
        def run(*args, **kwargs):
            calls.append(args)
            if args[:2] != ('docker', 'compose') or args[-3:] != ('config', '--format', 'json'):
                raise AssertionError('unexpected command mutation')
            document = {'services': {}}
            for i, value in enumerate(args):
                if value == '-f': document['services'].update(yaml.safe_load(Path(args[i+1]).read_text())['services'])
            return json.dumps(document)
        def atomic(path, data, **kwargs):
            writes.append(path)
            path.write_bytes(data if isinstance(data, bytes) else (json.dumps(data)+'\n').encode())
        native = types.SimpleNamespace(read=lambda path, limit=None: path.read_bytes(), run=run, atomic=atomic,
                                       catalog=lambda: copy.deepcopy(rows), held=lambda proof: None)
        backup = types.SimpleNamespace(BACKUP=root, RECORD=backup_record,
            preflight=lambda native: ({'proof': {'cutoverId': 'same-hold'}}, copy.deepcopy(rows)))
        release = types.SimpleNamespace(RECORD=media,
            runtime_signature=lambda rows: json.dumps(rows, sort_keys=True))
        return types.SimpleNamespace(app=app, work=work, rows=rows, originals=originals, images=image_ids,
            native=native, backup=backup, release=release, calls=calls, writes=writes, result=result)

    @contextlib.contextmanager
    def patched(self, case):
        with patch.object(r, 'APP', case.app), patch.object(r, 'WORK', case.work), \
             patch.object(r, 'RECORD', case.work / 'state.json'), \
             patch.object(r, 'local_image', side_effect=lambda image: case.images.get(image)), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            yield output

    def test_full_reconciliation_only_changes_three_images_in_two_files(self):
        with tempfile.TemporaryDirectory() as folder:
            case = self.setup_case(Path(folder)); before_rows = copy.deepcopy(case.rows)
            with self.patched(case) as output: r.apply_locked(case.native, case.backup, case.release)
            for path, before in case.originals.items():
                expected = before
                for rule in r.FIXES.values():
                    if path == case.app / rule['path']:
                        expected = expected.replace(rule['old'].encode(), ('"' + rule['image'] + '"').encode())
                self.assertEqual(path.read_bytes(), expected)
                self.assertEqual(path.stat().st_mode & 0o777, 0o640)
            self.assertEqual(case.rows, before_rows)
            self.assertNotIn('do-not-print', output.getvalue())
            record = json.loads((case.work / 'state.json').read_text())
            self.assertEqual(record['phase'], 'complete'); self.assertEqual(len(record['files']), 2)
            self.assertFalse(record['applicationsRestarted'])
            self.assertTrue(all(item['sameLocalImage'] for item in record['afterAudit']))
            self.assertTrue(case.calls)

    def test_pending_sample_restore_prevents_any_file_preparation(self):
        with tempfile.TemporaryDirectory() as folder:
            case = self.setup_case(Path(folder)); data = json.loads(case.result.read_text()); data['phase'] = 'checking'; case.result.write_text(json.dumps(data))
            with self.patched(case), self.assertRaisesRegex(RuntimeError, 'sample restore'):
                r.apply_locked(case.native, case.backup, case.release)
            self.assertFalse(case.writes)

    def test_unreviewed_mismatch_or_tag_moved_to_different_image_prevents_edits(self):
        for cause in ('plex-mismatch', 'latest-tag-moved'):
            with tempfile.TemporaryDirectory() as folder:
                case = self.setup_case(Path(folder))
                target = 'plex:current-version' if cause == 'plex-mismatch' else r.FIXES['seerr-nas']['image']
                case.images[target] = 'sha256:' + '7'*64
                with self.patched(case), self.assertRaises(RuntimeError): r.apply_locked(case.native, case.backup, case.release)
                self.assertFalse(case.writes)
                for path, body in case.originals.items(): self.assertEqual(path.read_bytes(), body)

    def test_staged_nonimage_compose_difference_prevents_live_edits(self):
        with tempfile.TemporaryDirectory() as folder:
            case = self.setup_case(Path(folder)); original = case.native.run
            def unexpected(*args, **kwargs):
                doc = json.loads(original(*args, **kwargs))
                if any(str(case.work / 'prepared-') in arg for arg in args): doc['networks'] = {'unexpected': {}}
                return json.dumps(doc)
            case.native.run = unexpected
            with self.patched(case), self.assertRaisesRegex(RuntimeError, 'more than reviewed'):
                r.apply_locked(case.native, case.backup, case.release)
            for path, body in case.originals.items(): self.assertEqual(path.read_bytes(), body)
            self.assertFalse((case.work / 'state.json').exists())

    def test_failure_on_second_live_write_rolls_back_only_our_exact_edits(self):
        with tempfile.TemporaryDirectory() as folder:
            case = self.setup_case(Path(folder)); original = case.native.atomic; written = []; failed = False
            def fault(path, data, **kwargs):
                nonlocal failed
                if path in case.originals and data != case.originals[path] and not failed:
                    if written: failed = True; raise RuntimeError('simulated second-write failure')
                    written.append(path)
                return original(path, data, **kwargs)
            case.native.atomic = fault
            with self.patched(case), self.assertRaisesRegex(RuntimeError, 'second-write'):
                r.apply_locked(case.native, case.backup, case.release)
            for path, body in case.originals.items(): self.assertEqual(path.read_bytes(), body)
            self.assertEqual(json.loads((case.work / 'state.json').read_text())['phase'], 'stopped')


if __name__ == '__main__': unittest.main()
