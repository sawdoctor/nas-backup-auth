"""Gateway audit stays read-only and cannot follow discovery outside router."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

path = Path(__file__).resolve().parents[1] / 'scripts/read-nas-router-web-mappings.py'
spec = importlib.util.spec_from_file_location('router_read', path)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
SERVICE = 'urn:schemas-upnp-org:service:WANIPConnection:1'


class RouterRead(unittest.TestCase):
    def test_discovery_can_only_contact_the_existing_gateway(self):
        for value in ('http://192.168.0.29/control', 'http://example.org/', 'http://192.168.0.1@example.org/',
                      'http://user:pass@192.168.0.1/', 'file:///etc/passwd', 'http://192.168.0.1/#secret'):
            with self.subTest(value=value), self.assertRaises((RuntimeError, ValueError)):
                m.router_url(value)
        self.assertEqual(m.router_url('http://192.168.0.1:5000/root.xml'), 'http://192.168.0.1:5000/root.xml')

    def test_discovery_service_resolves_router_control_urls(self):
        body = ('<root xmlns="urn:schemas-upnp-org:device-1-0"><URLBase>http://192.168.0.1:5000/</URLBase>'
                '<device><serviceList><service><serviceType>' + SERVICE + '</serviceType>'
                '<controlURL>/ctl/IPConn</controlURL></service></serviceList></device></root>').encode()
        self.assertEqual(m.service_locations(body, 'http://192.168.0.1/root.xml'), {(SERVICE, 'http://192.168.0.1:5000/ctl/IPConn')})

    def test_foreign_control_url_is_not_followed(self):
        body = ('<root><service><serviceType>' + SERVICE + '</serviceType><controlURL>http://example.org/control</controlURL></service></root>').encode()
        with self.assertRaises(RuntimeError):
            m.service_locations(body, 'http://192.168.0.1/root.xml')

    def test_xml_entities_and_redirects_are_rejected(self):
        for body in (b'<!DOCTYPE r [<!ENTITY x "x">]><r>&x;</r>', b'x' * (m.LIMIT + 1)):
            with self.assertRaises(RuntimeError):
                m.xml(body)
        with self.assertRaises(RuntimeError):
            m.NoRedirect().redirect_request(None, None, 302, '', {}, 'http://example.org/')

    def test_fixed_read_action_builds_standard_soap_and_no_write(self):
        reply = ET.fromstring('<Envelope><Body><Response><NewInternalClient>192.168.0.29</NewInternalClient>'
                              '<NewInternalPort>443</NewInternalPort><NewEnabled>1</NewEnabled></Response></Body></Envelope>')
        with patch.object(m, 'fetch', return_value=reply) as request:
            row = m.soap(SERVICE, 'http://192.168.0.1/ctl/IPConn', 'GetSpecificPortMappingEntry', 443)
        self.assertEqual(row['NewInternalClient'], '192.168.0.29')
        _, data, headers = request.call_args.args
        envelope = ET.fromstring(data)
        self.assertEqual(envelope.attrib['{http://schemas.xmlsoap.org/soap/envelope/}encodingStyle'], 'http://schemas.xmlsoap.org/soap/encoding/')
        values = {m.local_name(e.tag): e.text or '' for e in envelope.iter() if not list(e)}
        self.assertEqual(values, {'NewRemoteHost': '', 'NewExternalPort': '443', 'NewProtocol': 'TCP'})
        self.assertEqual(headers['SOAPAction'], '"' + SERVICE + '#GetSpecificPortMappingEntry"')

    def test_router_changes_and_unrelated_ports_cannot_be_invoked(self):
        with patch.object(m, 'fetch') as request:
            for action in ('AddPortMapping', 'DeletePortMapping', 'ForceTermination', 'SetConnectionType'):
                with self.subTest(action=action), self.assertRaises(RuntimeError):
                    m.soap(SERVICE, 'http://192.168.0.1/ctl', action, 443)
            with self.assertRaises(RuntimeError):
                m.soap(SERVICE, 'http://192.168.0.1/ctl', 'GetSpecificPortMappingEntry', 22)
            request.assert_not_called()

    def test_missing_mapping_fault_is_reported_without_guessing(self):
        reply = ET.fromstring('<Envelope><Body><Fault><detail><UPnPError><errorCode>714</errorCode></UPnPError></detail></Fault></Body></Envelope>')
        with patch.object(m, 'fetch', return_value=reply):
            self.assertEqual(m.soap(SERVICE, 'http://192.168.0.1/ctl', 'GetSpecificPortMappingEntry', 80), {'faultCode': 714})


if __name__ == '__main__':
    unittest.main()
