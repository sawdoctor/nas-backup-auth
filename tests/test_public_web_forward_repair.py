"""Only approved web targets may change; conflicts/unknown replies never retry."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

path = Path(__file__).resolve().parents[1] / 'scripts/repair-nas-public-web-forwards.py'
spec = importlib.util.spec_from_file_location('forward_repair', path)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
before = {443: {'faultCode': 714}, 80: {'faultCode': 714}}


def name(tag): return tag.rsplit('}', 1)[-1]


class WebForwardRepair(unittest.TestCase):
    def host_queries(self, args, **kwargs):
        if args[:4] == ['ip', '-j', '-4', 'route']:
            return '[{"gateway":"192.168.0.1"}]'
        return 'inet 192.168.0.220/24'

    def guarded_main(self, result, state_exists=False):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder) / 'state.json'
            if state_exists: state.write_text('{}')
            with patch.dict(m.__dict__, {'APPLY_APPROVED_WEB_FORWARDS': True}), \
                 patch.object(m.os, 'geteuid', return_value=0), patch.object(Path, 'is_mount', return_value=True), \
                 patch.object(m.subprocess, 'check_output', side_effect=self.host_queries), \
                 patch.object(m, 'STATE', state), patch.object(m, 'npm_preflight', return_value=Path('/unused')), \
                 patch.object(m, 'public_probe', return_value=result), patch.object(m, 'reader') as gateway:
                try:
                    m.main()
                finally:
                    gateway.assert_not_called()

    def reader(self, response=None):
        if response is None:
            response = ET.fromstring('<e:Envelope xmlns:e="http://schemas.xmlsoap.org/soap/envelope/"><e:Body>'
                                     '<u:AddPortMappingResponse xmlns:u="' + m.SERVICE + '"/></e:Body></e:Envelope>')
        return types.SimpleNamespace(local_name=name, fetch=lambda *args: response)

    def test_only_two_preapproved_public_web_destinations_are_sent(self):
        helper = self.reader(); requests = []
        real = helper.fetch
        def collect(*args): requests.append(args); return real(*args)
        helper.fetch = collect
        history = []; record = {}
        m.apply_pair(helper, 'http://192.168.0.1/control', copy.deepcopy(before), record,
                     lambda value: history.append(copy.deepcopy(value)))
        targets = []
        for url, body, headers in requests:
            root = ET.fromstring(body)
            fields = {name(e.tag): e.text or '' for e in root.iter() if not list(e)}
            self.assertEqual(fields['NewInternalClient'], '192.168.0.220')
            self.assertEqual(fields['NewProtocol'], 'TCP')
            self.assertEqual(fields['NewRemoteHost'], '')
            self.assertEqual(fields['NewEnabled'], '1')
            self.assertEqual(fields['NewLeaseDuration'], '0')
            self.assertEqual(headers['SOAPAction'], '"' + m.SERVICE + '#AddPortMapping"')
            targets.append((int(fields['NewExternalPort']), int(fields['NewInternalPort'])))
        self.assertEqual(targets, [(443, 10443), (80, 10080)])
        self.assertEqual(history[0]['phase'], 'requesting-443')
        self.assertEqual(history[-1]['acceptedPorts'], [443, 80])

    def test_no_other_public_or_admin_port_can_be_written(self):
        for port in (22, 81, 32400, 48222, 48223, 10081, 8443):
            with self.subTest(port=port), self.assertRaises(RuntimeError):
                m.reapply(self.reader(), 'http://192.168.0.1/control', port)

    def test_different_existing_client_is_retained_before_any_write(self):
        rows = copy.deepcopy(before)
        rows[443] = {'NewInternalClient': '192.168.0.29', 'NewInternalPort': '443'}
        with patch.object(m, 'reapply') as write, self.assertRaises(RuntimeError):
            m.apply_pair(self.reader(), 'http://192.168.0.1/control', rows, {}, lambda _: None)
        write.assert_not_called()

    def test_unknown_reader_fault_is_not_treated_as_missing(self):
        rows = copy.deepcopy(before); rows[80] = {'faultCode': 606}
        with patch.object(m, 'reapply') as write, self.assertRaises(RuntimeError):
            m.apply_pair(self.reader(), 'http://192.168.0.1/control', rows, {}, lambda _: None)
        write.assert_not_called()

    def test_conflict_718_does_not_delete_retry_or_write_second_port(self):
        response = ET.fromstring('<Envelope><Body><Fault><detail><UPnPError><errorCode>718</errorCode></UPnPError></detail></Fault></Body></Envelope>')
        helper = self.reader(response); calls = []
        original = helper.fetch
        helper.fetch = lambda *args: (calls.append(args), original(*args))[1]
        record = {}; history = []
        with self.assertRaisesRegex(RuntimeError, 'conflict 718'):
            m.apply_pair(helper, 'http://192.168.0.1/control', copy.deepcopy(before), record,
                         lambda value: history.append(copy.deepcopy(value)))
        self.assertEqual(len(calls), 1)
        self.assertEqual(history[0]['phase'], 'requesting-443')
        self.assertEqual(history[-1]['phase'], 'stopped-443')

    def test_request_timeout_is_recorded_without_retry(self):
        helper = self.reader(); calls = []
        def lost(*args): calls.append(args); raise TimeoutError()
        helper.fetch = lost
        record = {}; history = []
        with self.assertRaisesRegex(RuntimeError, 'without retry'):
            m.apply_pair(helper, 'http://192.168.0.1/control', copy.deepcopy(before), record,
                         lambda value: history.append(copy.deepcopy(value)))
        self.assertEqual(len(calls), 1)
        self.assertEqual(history[-1]['phase'], 'stopped-443')
        self.assertNotIn('acceptedPorts', record)

    def test_journal_failure_prevents_router_rpc(self):
        helper = self.reader(); calls = []
        helper.fetch = lambda *args: calls.append(args)
        def fail(_): raise OSError('disk full')
        with self.assertRaises(OSError):
            m.apply_pair(helper, 'http://192.168.0.1/control', copy.deepcopy(before), {}, fail)
        self.assertEqual(calls, [])

    def test_inconclusive_soap_reply_is_not_claimed_success(self):
        with self.assertRaisesRegex(RuntimeError, 'inconclusive'):
            m.reapply(self.reader(ET.fromstring('<Envelope/>')), 'http://192.168.0.1/control', 443)

    def test_cf_waf_response_without_origin_log_does_not_verify_delivery(self):
        with patch.object(m, 'curl', return_value={'exit': 0, 'http': 403}), patch.object(m, 'logged', return_value=False):
            self.assertFalse(m.public_probe(Path('/unused'))['verified'])

    def test_log_and_http_response_are_both_required(self):
        with patch.object(m, 'curl', return_value={'exit': 0, 'http': 307}), patch.object(m, 'logged', return_value=True):
            self.assertTrue(m.public_probe(Path('/unused'))['verified'])
        with patch.object(m, 'curl', return_value={'exit': 0, 'http': 522}), patch.object(m, 'logged', return_value=True):
            self.assertFalse(m.public_probe(Path('/unused'))['verified'])

    def test_nonce_only_used_in_public_request_and_matched_in_log(self):
        with patch.object(m, 'curl', return_value={'exit': 0, 'http': 307}) as request, patch.object(m, 'logged', return_value=True) as log:
            m.public_probe(Path('/unused'))
        nonce = log.call_args.args[1]
        self.assertIn(nonce, request.call_args.args[0])
        self.assertTrue(request.call_args.args[0].startswith('https://request.sawdoctor.uk/?'))

    def test_actual_log_read_is_bounded_and_never_returns_contents(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'proxy-host-3_access.log').write_text('private-user-and-headers\nGET /?unique-token\n')
            self.assertIs(m.logged(root, 'unique-token'), True)
            self.assertIs(m.logged(root, 'not-a-request'), False)

    def test_apply_flag_is_required_before_any_host_query(self):
        with patch.object(m.subprocess, 'check_output') as query, self.assertRaisesRegex(RuntimeError, 'apply flag'):
            m.main()
        query.assert_not_called()

    def test_already_working_public_path_prevents_any_gateway_write(self):
        self.guarded_main({'exit': 0, 'http': 307, 'seenInNasNpmLog': True, 'verified': True})

    def test_waf_response_is_not_treated_as_a_reason_to_reapply_router_rules(self):
        with self.assertRaisesRegex(RuntimeError, 'not the observed'):
            self.guarded_main({'exit': 0, 'http': 403, 'seenInNasNpmLog': False, 'verified': False})

    def test_origin_log_evidence_prevents_router_write_even_for_app_error(self):
        with self.assertRaisesRegex(RuntimeError, 'reached NAS NPM'):
            self.guarded_main({'exit': 0, 'http': 503, 'seenInNasNpmLog': True, 'verified': False})

    def test_existing_interrupted_operation_is_not_repeated(self):
        with self.assertRaisesRegex(RuntimeError, 'earlier router repair record'):
            self.guarded_main({'exit': 0, 'http': 522, 'seenInNasNpmLog': False, 'verified': False}, state_exists=True)

    def test_local_proxy_preflight_requires_exact_existing_admin_binding(self):
        row = {'Name': '/npm-nas', 'State': {'Running': True}, 'Mounts': [],
               'HostConfig': {'PortBindings': {'81/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '10081'}]}}}
        with patch.object(m.subprocess, 'check_output', return_value=json.dumps([row])), self.assertRaisesRegex(RuntimeError, 'accepted NAS-only'):
            m.npm_preflight()


if __name__ == '__main__': unittest.main()
