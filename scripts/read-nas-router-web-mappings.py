#!/usr/bin/env python3
"""Read the existing gateway's UPnP WAN address and three TCP mappings.

No router login, install, port-map write, discovery-service enable, firewall
change or application action. Only the already configured LAN gateway may be
contacted. Unavailable UPnP does not establish that GUI rules are absent.
"""
import ipaddress
import json
import re
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

NAS = '192.168.0.220'
GATEWAY = '192.168.0.1'
SERVICES = {f'urn:schemas-upnp-org:service:{name}:{version}'
            for name, version in [('WANIPConnection', 1), ('WANIPConnection', 2), ('WANPPPConnection', 1)]}
READ_ACTIONS = {'GetExternalIPAddress', 'GetSpecificPortMappingEntry'}
LIMIT = 128 * 1024


def router_url(value):
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme not in ('http', 'https') or parsed.hostname != GATEWAY
            or parsed.username is not None or parsed.password is not None
            or parsed.fragment or any(ord(c) < 33 or ord(c) > 126 for c in value)):
        raise RuntimeError('A discovery URL did not identify this LAN gateway; it was not contacted.')
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise RuntimeError('Invalid gateway service port.')
    return value


def xml(body):
    if len(body) > LIMIT or b'<!DOCTYPE' in body.upper() or b'<!ENTITY' in body.upper():
        raise RuntimeError('An oversized or unsupported gateway XML response was rejected.')
    return ET.fromstring(body)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError('Gateway redirect was not followed.')


def fetch(url, data=None, headers=None):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(router_url(url), data=data, headers=headers or {})
    try:
        response = opener.open(request, timeout=2)
    except urllib.error.HTTPError as error:
        if error.code != 500:
            raise RuntimeError('Gateway read request returned HTTP ' + str(error.code)) from None
        response = error
    with response:
        body = response.read(LIMIT + 1)
    return xml(body)


def local_name(tag):
    return tag.rsplit('}', 1)[-1]


def service_locations(body, location):
    root = xml(body)
    base = next((e.text.strip() for e in root.iter() if local_name(e.tag) == 'URLBase' and e.text), location)
    router_url(base)
    result = set()
    for element in root.iter():
        if local_name(element.tag) != 'service':
            continue
        row = {local_name(child.tag): (child.text or '').strip() for child in element}
        if row.get('serviceType') in SERVICES and row.get('controlURL'):
            result.add((row['serviceType'], router_url(urllib.parse.urljoin(base, row['controlURL']))))
    return result


def discover():
    locations = set()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as connection:
        connection.bind((NAS, 0))
        connection.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(NAS))
        connection.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        connection.settimeout(.3)
        for target in ('urn:schemas-upnp-org:device:InternetGatewayDevice:1', 'upnp:rootdevice'):
            message = ('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
                       'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ' + target + '\r\n\r\n').encode('ascii')
            connection.sendto(message, ('239.255.255.250', 1900))
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                body, peer = connection.recvfrom(8192)
            except socket.timeout:
                continue
            if peer[0] != GATEWAY:
                continue
            for line in body.decode('ascii', errors='replace').split('\r\n'):
                name, colon, value = line.partition(':')
                if colon and name.lower() == 'location':
                    locations.add(router_url(value.strip()))
        return sorted(locations)[:2]


def soap(service, url, action, external_port=None):
    if service not in SERVICES or action not in READ_ACTIONS:
        raise RuntimeError('Only the two fixed router read actions are allowed.')
    namespace = 'http://schemas.xmlsoap.org/soap/envelope/'
    envelope = ET.Element('{' + namespace + '}Envelope', {'{' + namespace + '}encodingStyle': 'http://schemas.xmlsoap.org/soap/encoding/'})
    body = ET.SubElement(envelope, '{' + namespace + '}Body')
    operation = ET.SubElement(body, '{' + service + '}' + action)
    if action == 'GetSpecificPortMappingEntry':
        if external_port not in (80, 443, 32400):
            raise RuntimeError('Only existing website and Plex TCP mappings may be read.')
        for name, value in [('NewRemoteHost', ''), ('NewExternalPort', str(external_port)), ('NewProtocol', 'TCP')]:
            ET.SubElement(operation, name).text = value
    response = fetch(url, ET.tostring(envelope, encoding='utf-8', xml_declaration=True),
                     {'Content-Type': 'text/xml; charset="utf-8"', 'SOAPAction': '"' + service + '#' + action + '"'})
    fault = next((e.text for e in response.iter() if local_name(e.tag) == 'errorCode'), None)
    if fault is not None:
        return {'faultCode': int(fault) if re.fullmatch(r'[0-9]{1,5}', fault) else 'unavailable'}
    return {local_name(e.tag): e.text or '' for e in response.iter() if not list(e)}


def main():
    route = json.loads(subprocess.check_output(['ip', '-j', '-4', 'route', 'get', '1.1.1.1'], text=True, timeout=5))[0]
    addresses = subprocess.check_output(['ip', '-4', 'addr', 'show'], text=True, timeout=5)
    if 'inet ' + NAS + '/' not in addresses or route.get('gateway') != GATEWAY:
        raise RuntimeError('Run on the NAS with its existing 192.168.0.1 gateway.')
    services = set()
    for location in discover():
        # Fetch only gateway-advertised metadata, never guess private endpoints.
        response = fetch(location)
        services.update(service_locations(ET.tostring(response), location))
    if not services:
        print('Gateway did not expose a readable UPnP WAN service. No setting was changed; do not enable UPnP for this check.')
        return
    for service, url in sorted(services, reverse=True)[:2]:
        print('Gateway service: ' + service, flush=True)
        address = soap(service, url, 'GetExternalIPAddress')
        if 'NewExternalIPAddress' in address:
            observed = str(ipaddress.IPv4Address(address['NewExternalIPAddress']))
            print('Gateway WAN IPv4: ' + observed + '; expected existing DNS origin: 82.30.213.121', flush=True)
        else:
            print('WAN address query unavailable: ' + str(address.get('faultCode', 'no value')), flush=True)
        for port in (80, 443, 32400):
            row = soap(service, url, 'GetSpecificPortMappingEntry', port)
            if 'faultCode' in row:
                print(f'TCP {port}: mapping query fault {row["faultCode"]} (714 means not exposed in this service)', flush=True)
                continue
            target = str(ipaddress.IPv4Address(row['NewInternalClient']))
            internal = int(row['NewInternalPort'])
            if not 1 <= internal <= 65535:
                raise RuntimeError('The reported internal port was invalid.')
            enabled = row.get('NewEnabled', '').lower() in ('1', 'true', 'yes')
            lease = row.get('NewLeaseDuration', '')
            lease = int(lease) if re.fullmatch(r'[0-9]{1,10}', lease) else 'unknown'
            print(f'TCP {port} -> {target}:{internal}; enabled={enabled}; lease={lease}', flush=True)
    print('Router services can omit GUI-managed rules; an absent entry is not proof that the router has no static rule.')
    print('READ-ONLY COMPLETE. No mapping added, removed or changed; no UPnP setting enabled.')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        raise SystemExit('STOP: ' + (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__))
