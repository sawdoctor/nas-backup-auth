"""Exact-version metadata repair and original-name recovery without app updates."""
import contextlib
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    value = importlib.util.module_from_spec(spec)
    exec(compile((SCRIPTS / filename).read_bytes(), str(SCRIPTS / filename), 'exec'), value.__dict__)
    return value


m = module('image_identity_repair', 'repair-nas-imported-image-identities.py')
core = module('identity_core', 'prepare-nas-production-core.py')
cache = module('identity_cache', 'cache-nas-production-core-images.py')


def image(identity, tag=None, digest=None, layer='layer-a'):
    return {'Id': identity, 'Os': 'linux', 'Architecture': 'amd64', 'Size': 100,
            'RootFS': {'Layers': [layer]}, 'Config': {'Env': ['VERSION=1'], 'Cmd': ['serve']},
            'RepoTags': [tag] if tag else [], 'RepoDigests': [digest] if digest else []}


def container(name, identity, ref=None):
    return {'Name': '/' + name, 'Image': identity, 'Id': name + '-container-id',
            'Config': {'Image': ref or identity, 'Labels': {'com.docker.compose.service': name.removesuffix('-nas')}},
            'State': {'Running': True, 'StartedAt': 'original-start'}, 'RestartCount': 0,
            'HostConfig': {'RestartPolicy': {'Name': 'no'}}, 'Mounts': []}


class ImageIdentities(unittest.TestCase):
    def fixture(self):
        digest = 'ghcr.io/example/tracearr@sha256:' + 'a' * 64
        source = image('source-manifest-id', 'ghcr.io/example/tracearr:latest', digest)
        local = image('sha256:' + 'c' * 64, 'ghcr.io/example/tracearr:latest')
        row = container('tracearr-nas', local['Id'])
        old = container('tracearr', source['Id'], 'ghcr.io/example/tracearr:latest')
        return local, row, {'images': [source], 'containers': [old]}, digest

    def test_recorded_digest_is_selected_by_full_content_not_cross_engine_id(self):
        local, row, manifest, digest = self.fixture()
        refs, tags = m.saved_links(local, [row], [manifest], core, cache)
        self.assertEqual(refs, [digest]); self.assertEqual(tags, ['ghcr.io/example/tracearr:latest'])

    def test_changed_layer_or_runtime_is_never_used_as_existing_version(self):
        local, row, manifest, _ = self.fixture()
        for change in ('layer', 'config'):
            current = copy.deepcopy(local)
            if change == 'layer': current['RootFS']['Layers'] = ['different-layer']
            else: current['Config']['Cmd'] = ['different-command']
            self.assertEqual(m.saved_links(current, [row], [manifest], core, cache), ([], []))

    def test_bare_id_needs_matching_original_service_to_recover_registry_name(self):
        local, row, manifest, digest = self.fixture(); local['RepoTags'] = []
        self.assertEqual(m.saved_links(local, [row], [manifest], core, cache)[0], [digest])
        row['Name'] = '/unrelated-nas'; row['Config']['Labels'] = {}
        self.assertEqual(m.saved_links(local, [row], [manifest], core, cache), ([], []))

    def test_wrong_repository_and_unrecorded_latest_are_rejected(self):
        local, row, manifest, _ = self.fixture()
        manifest['images'][0]['RepoDigests'] = ['ghcr.io/other/image@sha256:' + 'a' * 64]
        self.assertEqual(m.saved_links(local, [row], [manifest], core, cache)[0], [])
        manifest['images'][0]['RepoDigests'] = ['ghcr.io/example/tracearr:latest']
        self.assertEqual(m.saved_links(local, [row], [manifest], core, cache)[0], [])

    def test_local_compose_build_is_not_mistaken_for_docker_hub_image(self):
        local, row, manifest, _ = self.fixture()
        local['RepoTags'] = ['abr-shelfmark-bridge:latest']
        manifest['containers'][0]['Config']['Image'] = 'abr-shelfmark-bridge:latest'
        manifest['images'][0]['RepoDigests'] = ['abr-shelfmark-bridge@sha256:' + 'a' * 64]
        self.assertEqual(m.saved_links(local, [row], [manifest], core, cache), ([], []))

    def test_docker_hub_tag_and_digest_aliases_are_canonical(self):
        self.assertEqual(m.tag_reference('redis:7-alpine'), 'docker.io/library/redis:7-alpine')
        self.assertEqual(m.tag_reference('docker.io/redis:7-alpine'), 'docker.io/library/redis:7-alpine')
        digest = 'a' * 64
        self.assertEqual(m.digest_reference('redis@sha256:' + digest),
                         m.digest_reference('docker.io/library/redis@sha256:' + digest))
        self.assertIsNone(m.repository('sha256:' + digest))

    def test_tag_recovery_cannot_steal_name_from_another_existing_container(self):
        ref = 'ghcr.io/example/app:latest'
        changes, blocked = m.tag_plan('new', [ref], {ref: ['old']}, {'new', 'old'})
        self.assertEqual(changes, []); self.assertEqual(blocked, [ref])
        changes, blocked = m.tag_plan('new', [ref], {ref: ['old']}, {'new'})
        self.assertEqual(changes, [{'reference': ref, 'beforeImageIds': ['old'], 'afterImageId': 'new'}])
        self.assertEqual(blocked, [])

    def test_pull_must_attach_saved_digest_to_unchanged_current_image(self):
        local, _, _, digest = self.fixture(); repaired = copy.deepcopy(local); repaired['RepoDigests'] = [digest]
        m.verify_registry_link(core, cache, local, digest, repaired, repaired)
        wrong = copy.deepcopy(repaired); wrong['Id'] = 'new-image-version'
        with self.assertRaises(RuntimeError): m.verify_registry_link(core, cache, local, digest, wrong, repaired)
        wrong = copy.deepcopy(repaired); wrong['Config']['Cmd'] = ['modified']
        with self.assertRaises(RuntimeError): m.verify_registry_link(core, cache, local, digest, repaired, wrong)

    def test_docker_hub_digest_alias_is_accepted_after_same_image_pull(self):
        before = image('id', 'redis:7-alpine')
        after = copy.deepcopy(before); after['RepoDigests'] = ['redis@sha256:' + 'a' * 64]
        m.verify_registry_link(core, cache, before, 'docker.io/library/redis@sha256:' + 'a' * 64, after, after)

    def test_mount_order_does_not_look_like_container_restart_but_real_restart_does(self):
        row = container('app', 'image'); row['Mounts'] = [{'Destination': '/b'}, {'Destination': '/a'}]
        changed = copy.deepcopy(row); changed['Mounts'].reverse()
        self.assertEqual(m.containers_fingerprint({'app': row}), m.containers_fingerprint({'app': changed}))
        changed['State']['StartedAt'] = 'restarted'
        self.assertNotEqual(m.containers_fingerprint({'app': row}), m.containers_fingerprint({'app': changed}))

    def test_legacy_manifest_requires_original_checksum_and_stage_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            stage = Path(folder); snapshot = stage / 'snapshot'; snapshot.mkdir()
            document = {'format': 'sawdoctor-support-export-v1', 'sourceHost': '192.168.0.29',
                        'createdUtc': 'original', 'images': [], 'containers': []}
            body = json.dumps(document).encode(); (snapshot / 'manifest.json').write_bytes(body)
            (snapshot / 'SHA256SUMS').write_text(m.sha(body) + '  ./manifest.json\n')
            marker = {'archiveSha256': 'a' * 64, 'createdUtc': 'original'}
            (stage / 'staged.json').write_text(json.dumps(marker))
            native = types.SimpleNamespace(read=lambda path: path.read_bytes())
            with patch.object(m, 'SUPPORT', stage):
                self.assertEqual(m.support_manifest(native, core), document)
                (snapshot / 'manifest.json').write_bytes(body + b' ')
                with self.assertRaisesRegex(RuntimeError, 'original verified snapshot'):
                    m.support_manifest(native, core)

    def test_distinct_saved_digests_remain_ambiguous_but_aliases_do_not(self):
        local, row, manifest, digest = self.fixture()
        manifest['images'][0]['RepoDigests'].append(digest.replace('a' * 64, 'b' * 64))
        self.assertEqual(len(m.saved_links(local, [row], [manifest], core, cache)[0]), 2)
        self.assertEqual(m.repository('registry-1.docker.io/redis:7'), 'docker.io/library/redis')

    def test_worker_repairs_lost_digest_and_core_name_while_retaining_old_image(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); work = root / 'work'; work.mkdir()
            local, tracearr, manifest, digest = self.fixture()
            radarr_digest = 'lscr.io/linuxserver/radarr@sha256:' + 'b' * 64
            current_id, old_id = 'sha256:' + 'd' * 64, 'sha256:' + 'e' * 64
            current_radarr = image(current_id, digest=radarr_digest, layer='radarr-layer')
            old_radarr = image(old_id, 'lscr.io/linuxserver/radarr:latest', layer='old-layer')
            source_radarr = copy.deepcopy(current_radarr); source_radarr['Id'] = 'source-radarr'
            manifest['images'].append(source_radarr)
            manifest['containers'].append(container('radarr', 'source-radarr', 'lscr.io/linuxserver/radarr:latest'))
            running = {'tracearr-nas': tracearr, 'radarr-nas': container('radarr-nas', current_id)}
            original_running = copy.deepcopy(running)
            images = {row['Id']: row for row in [local, current_radarr, old_radarr]}
            calls = []
            main_path = root / 'main.json'; main_path.write_text(json.dumps({'phase': 'awaiting-acceptance', 'proof': {'cutoverId': 'current'}}))
            def atomic(path, value, **kwargs):
                path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
            def run(*args, **kwargs):
                calls.append(args)
                if args[:2] == ('docker', 'info'): return str(root)
                if args[:3] == ('docker', 'image', 'inspect'):
                    ref = args[3]
                    found = images.get(ref) or next(value for value in images.values() if ref in value['RepoDigests'])
                    return json.dumps([found])
                if args[:3] == ('docker', 'image', 'tag'):
                    identity, ref = args[3:]
                    for item in images.values(): item['RepoTags'] = [tag for tag in item['RepoTags'] if m.tag_reference(tag) != m.tag_reference(ref)]
                    images[identity]['RepoTags'].append(ref); return ''
                raise AssertionError('Unexpected command: ' + repr(args))
            def pull(_, name, ref, platform, destination):
                calls.append(('docker', 'image', 'pull', ref))
                self.assertEqual(ref, digest); self.assertEqual(platform, 'linux/amd64')
                images[local['Id']]['RepoDigests'].append(ref)
            fake_cache = types.SimpleNamespace(inventory=lambda _: copy.deepcopy(images), same_image=cache.same_image, pull=pull)
            native = types.SimpleNamespace(
                lock=lambda _: contextlib.nullcontext(), BACKUP_LOCK=root / 'lock', STATE=main_path,
                approved=lambda _: {'dockmonDatabase': str(root / 'dockmon.db')}, read=lambda path: path.read_bytes(),
                held=lambda _: None, helpers=lambda: {'core': core, 'cache': fake_cache},
                dockmon_notify=lambda _: {'automatic': 0}, catalog=lambda: copy.deepcopy(running), atomic=atomic, run=run)
            starter = types.SimpleNamespace(NATIVE_SHA='pinned', PLAN_SHA='plan', load_module=lambda *a: native,
                                            frozen_manifest=lambda *a: (None, manifest, None))
            with patch.multiple(m, BASE=root, WORK=work, STATE=work / 'state.json'), \
                 patch.object(m, 'load', return_value=starter), patch.object(m, 'support_manifest', return_value=None), \
                 patch.object(m, 'skip_setting', return_value=False), \
                 patch.object(m.shutil, 'disk_usage', return_value=types.SimpleNamespace(free=50 * 1024**3)):
                m.worker()
            self.assertEqual(running, original_running)
            self.assertIn(old_id, images)
            self.assertEqual(images[current_id]['RepoTags'], ['lscr.io/linuxserver/radarr:latest'])
            self.assertEqual(images[old_id]['RepoTags'], [])
            record = json.loads((work / 'state.json').read_text())
            self.assertEqual(record['phase'], 'complete')
            self.assertEqual(record['applicationsRestarted'], 0)
            self.assertEqual(record['applicationVersionsChanged'], 0)
            self.assertEqual(record['originalTagBindings']['lscr.io/linuxserver/radarr:latest'], [old_id])
            self.assertTrue(all(call[:3] in [('docker', 'image', 'pull'), ('docker', 'image', 'inspect'),
                                           ('docker', 'image', 'tag')] or call[:2] == ('docker', 'info') for call in calls))


if __name__ == '__main__': unittest.main()
