import copy
import importlib.util
import io
from pathlib import Path
import tarfile
import unittest
from unittest.mock import patch, Mock

PATH = Path(__file__).resolve().parents[1] / 'scripts/resume-nas-npm-certificate-renewal.py'
spec = importlib.util.spec_from_file_location('npm_renewal', PATH)
npm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(npm)


def model():
    return {'name': 'npm-nas', 'services': {'npm': {'container_name': 'npm-nas', 'image': 'jc21/nginx-proxy-manager:latest',
            'environment': {'TZ': 'Europe/London'}, 'volumes': [
                {'type': 'bind', 'source': 'current-data', 'target': '/data'},
                {'type': 'bind', 'source': 'current-certs', 'target': '/etc/letsencrypt'},
                {'type': 'bind', 'source': str(npm.GUARD), 'target': npm.MODULE, 'read_only': True}]}}}


def runtime(name='npm-nas', identity='1' * 64, created=False):
    return {'Id': identity, 'Name': '/' + name, 'Image': npm.IMAGE,
            'State': {'Status': 'created' if created else 'running', 'Running': not created},
            'Config': {'Hostname': identity[:12], 'Env': ['TZ=Europe/London'], 'Image': 'jc21/nginx-proxy-manager:latest',
                       'Labels': {'com.docker.compose.project': name, 'user-policy': 'keep'}},
            'HostConfig': {'Binds': ['input-syntax'], 'Dns': None, 'DnsOptions': None, 'DnsSearch': None,
                           'PortBindings': {'443/tcp': [{'HostIp': '192.168.0.220', 'HostPort': '10443'}]}},
            'Mounts': [{'Type': 'bind', 'Source': 'current-data', 'Destination': '/data', 'RW': True, 'Propagation': 'rprivate'},
                       {'Type': 'bind', 'Source': 'current-certs', 'Destination': '/etc/letsencrypt', 'RW': True, 'Propagation': 'rprivate'}],
            'NetworkSettings': {'Networks': {'npm-nas_default': {'NetworkID': '' if created else 'stable-network',
                'Aliases': [name, 'npm'], 'IPAMConfig': None, 'Links': None, 'DriverOpts': None}}}}


class NpmRenewalHandoverTests(unittest.TestCase):
    def test_candidate_removes_only_reviewed_module_mount(self):
        before = model()
        after = npm.candidate_model(before)
        expected = copy.deepcopy(before)
        expected['services']['npm']['volumes'].pop()
        self.assertEqual(after, expected)
        self.assertEqual(len(before['services']['npm']['volumes']), 3)

    def test_foreign_guard_extra_service_or_storage_refused(self):
        for kind in ('source', 'extra-service', 'storage'):
            data = model()
            if kind == 'source':
                data['services']['npm']['volumes'][-1]['source'] = 'unreviewed'
            elif kind == 'extra-service':
                data['services']['other'] = {}
            else:
                data['services']['npm']['volumes'].append({'target': '/unexpected'})
            with self.assertRaises(RuntimeError):
                npm.candidate_model(data)

    def test_unstarted_probe_allows_only_unassigned_endpoint_id(self):
        before = runtime()
        probe = runtime('npm-renewal-probe', '2' * 64, created=True)
        probe['HostConfig']['Dns'] = []
        npm.verify_runtime(before, probe, unstarted=True)

    def test_running_replacement_cannot_change_network_id(self):
        before = runtime()
        after = runtime(identity='2' * 64)
        after['NetworkSettings']['Networks']['npm-nas_default']['NetworkID'] = 'other-network'
        with self.assertRaises(RuntimeError):
            npm.verify_runtime(before, after)

    def test_ports_environment_storage_and_policy_changes_refused(self):
        for kind in ('port', 'environment', 'storage', 'policy'):
            before, after = runtime(), runtime(identity='2' * 64)
            if kind == 'port':
                after['HostConfig']['PortBindings']['443/tcp'][0]['HostPort'] = '443'
            elif kind == 'environment':
                after['Config']['Env'] = ['TZ=changed']
            elif kind == 'storage':
                after['Mounts'][0]['Source'] = 'empty-new-data'
            else:
                after['Config']['Labels']['user-policy'] = 'changed'
            with self.assertRaises(RuntimeError):
                npm.verify_runtime(before, after)

    def test_stock_module_rejects_retained_hold(self):
        source = b"Let's Encrypt Renewal Timer initialized; setInterval(internalCertificate.processExpiringHosts); renew: async (access, data)"
        npm.verify_stock(source)
        with self.assertRaises(RuntimeError):
            npm.verify_stock(source + b' NAS_NPM_TRIAL_CERT_HOLD')

    def test_stock_file_reads_one_regular_member_without_extracting_paths(self):
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode='w') as archive:
            info = tarfile.TarInfo('../../certificate.js')
            info.size = 4
            archive.addfile(info, io.BytesIO(b'code'))
        with patch.object(npm, 'run', return_value=payload.getvalue()):
            self.assertEqual(npm.stock_file(None, 'owned-probe', npm.MODULE), b'code')

    def test_duplicate_environment_name_refused(self):
        with self.assertRaises(RuntimeError):
            npm.env(['NAME=first', 'NAME=second'])

    def test_unstarted_probe_references_existing_network_without_adopting_it(self):
        candidate = npm.candidate_model(model())
        candidate['networks'] = {'default': {'name': 'npm-nas_default', 'ipam': {}}}
        probe = npm.unstarted_model(candidate, 'unique-probe')
        self.assertEqual(probe['networks'], {'default': {'name': 'npm-nas_default', 'external': True}})
        self.assertEqual(candidate['networks']['default'], {'name': 'npm-nas_default', 'ipam': {}})
        self.assertEqual(probe['services']['npm']['volumes'], candidate['services']['npm']['volumes'])

    def test_environment_mismatch_reports_names_without_secret_values(self):
        before, after = runtime(), runtime(identity='2' * 64)
        after['Config']['Env'] = ['PRIVATE_KEY=SECRET-VALUE']
        with self.assertRaises(RuntimeError) as raised:
            npm.verify_runtime(before, after)
        self.assertIn('PRIVATE_KEY', str(raised.exception))
        self.assertNotIn('SECRET-VALUE', str(raised.exception))

    def test_proxy_preflight_checks_accepted_local_owner_not_unrelated_media_mounts(self):
        native, host, backup = Mock(), Mock(), Mock()
        native.FORMAT = 'current-format'
        native.read.side_effect = [b'{"phase":"awaiting-acceptance","proof":{"cutoverId":"current"}}',
                                   b'{"format":"current-format","cutoverId":"current"}',
                                   b'{"phase":"complete","cutoverId":"current"}']
        host.status.return_value = {'ActiveState': 'inactive'}
        native.catalog.return_value = {'npm-nas': {'Image': npm.IMAGE}}
        main, rows = npm.local_proxy_preflight(host, backup, native)
        native.held.assert_called_once_with({'cutoverId': 'current'})
        native.helpers.assert_not_called()
        backup.preflight.assert_not_called()
        self.assertIn('npm-nas', rows)


if __name__ == '__main__':
    unittest.main()
