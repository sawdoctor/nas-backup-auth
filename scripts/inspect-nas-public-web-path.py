#!/usr/bin/env python3
"""Read-only NPM forwarding inspection and bounded TCP-header observation.

No service, firewall, certificate, database or router change. Only connection
metadata is printed; application payloads, credentials and headers are not.
"""
from collections import Counter
import json
import os
import socket
import struct
import subprocess
import time

NAS = '192.168.0.220'
PORTS = {10080, 10443}


def say(value):
    print(value, flush=True)


def query(*args):
    result = subprocess.run(args, text=True, capture_output=True, timeout=15)
    if result.returncode:
        return 'Query unavailable: ' + ' '.join(args[:4])
    return result.stdout.strip()


def packet(frame):
    if len(frame) < 14:
        return None
    offset = 14
    protocol = struct.unpack('!H', frame[12:14])[0]
    while protocol in (0x8100, 0x88a8):
        if len(frame) < offset + 4:
            return None
        protocol = struct.unpack('!H', frame[offset + 2:offset + 4])[0]
        offset += 4
    if protocol != 0x0800 or len(frame) < offset + 20:
        return None
    header = (frame[offset] & 15) * 4
    if frame[offset] >> 4 != 4 or header < 20 or frame[offset + 9] != 6:
        return None
    if struct.unpack('!H', frame[offset + 6:offset + 8])[0] & 0x1fff:
        return None
    if len(frame) < offset + header + 14:
        return None
    source = socket.inet_ntoa(frame[offset + 12:offset + 16])
    destination = socket.inet_ntoa(frame[offset + 16:offset + 20])
    sport, dport = struct.unpack('!HH', frame[offset + header:offset + header + 4])
    if not ((destination == NAS and dport in PORTS) or (source == NAS and sport in PORTS)):
        return None
    flags = frame[offset + header + 13]
    if not flags & (2 | 4):
        return None
    shown = '+'.join(name for bit, name in ((2, 'SYN'), (16, 'ACK'), (4, 'RST')) if flags & bit)
    return source, sport, destination, dport, shown


def main():
    if os.geteuid() != 0 or 'inet ' + NAS + '/' not in query('ip', '-4', 'addr', 'show'):
        raise RuntimeError('Run with sudo on the NAS.')
    route = json.loads(query('ip', '-j', '-4', 'route', 'get', '1.1.1.1'))[0]
    device = route['dev']
    say('NAS outgoing route: interface=' + device + '; gateway=' + route.get('gateway', '(direct)'))
    row = json.loads(query('docker', 'inspect', 'npm-nas'))[0]
    say('NPM state=' + row['State']['Status'] + '; published ports=' + json.dumps(row['HostConfig']['PortBindings'], sort_keys=True))
    networks = row['NetworkSettings']['Networks']
    addresses = {value.get('IPAddress') for value in networks.values()}
    for name, value in networks.items():
        say('NPM network=' + name + '; IP=' + value.get('IPAddress', '') + '; gateway=' + value.get('Gateway', ''))
    for chain in ('DOCKER-FORWARD', 'DOCKER-BRIDGE', 'DOCKER-CT', 'DOCKER-INTERNAL'):
        say('Firewall ' + chain + ':\n' + query('iptables', '-w', '5', '-S', chain))
    rules = query('iptables', '-w', '5', '-S', 'DOCKER').splitlines()
    selected = [line for line in rules if line.startswith('-N ') or ' DROP' in line
                or any(address and address in line for address in addresses)]
    say('Docker accept/drop rules relevant to NPM:\n' + '\n'.join(selected))
    say('Stopped NAS containers:\n' + query('docker', 'ps', '-a', '--filter', 'status=exited', '--filter', 'status=created',
                                         '--format', '{{.Names}}: {{.Status}}'))
    observations = Counter()
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    capture.bind((device, 0))
    capture.settimeout(1)
    say('Observing only incoming/outgoing NPM TCP handshake metadata for 24 seconds; sending one public Seerr request...')
    probe = subprocess.Popen(['curl', '--disable', '--noproxy', '*', '--silent', '--show-error',
                              '--connect-timeout', '4', '--max-time', '22', '--output', '/dev/null',
                              '--write-out', 'Public Seerr HTTP=%{http_code}\n',
                              'https://request.sawdoctor.uk/?nas_path_check=' + str(int(time.time()))],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 24
        while time.monotonic() < deadline:
            try:
                frame = capture.recv(128)
            except socket.timeout:
                continue
            item = packet(frame)
            if item is not None:
                observations[item] += 1
        try:
            output, error = probe.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            probe.kill()
            output, error = probe.communicate(timeout=5)
        say(output.strip() or 'Public HTTP result unavailable.')
        say('Public request curl exit=' + str(probe.returncode))
        for (source, sport, destination, dport, flags), count in observations.most_common(20):
            say(f'TCP {source}:{sport} -> {destination}:{dport} {flags}; observed={count}')
        incoming = sum(count for item, count in observations.items() if item[2] == NAS and 'SYN' in item[4])
        outgoing = sum(count for item, count in observations.items() if item[0] == NAS and 'SYN' in item[4])
        say('Observed NPM incoming SYN packets=' + str(incoming) + '; outgoing SYN packets=' + str(outgoing))
        if not observations:
            say('No matching IPv4 NPM handshakes reached this NAS interface during the public request. Check origin/routing before editing apps.')
        say('READ-ONLY PUBLIC WEB PATH CHECK COMPLETE. No service, firewall, certificate or data change.')
    finally:
        capture.close()
        if probe.poll() is None:
            probe.kill()
            probe.communicate(timeout=5)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('STOP: ' + (str(error) if isinstance(error, RuntimeError)
                                   else 'Read-only public-path inspection failed (' + type(error).__name__ + ').'))
