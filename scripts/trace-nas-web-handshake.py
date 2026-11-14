#!/usr/bin/env python3
"""Bounded read-only web handshake trace, with a capture positive control.

Observe all interfaces and both translated/untranslated web ports. Print only
TCP connection metadata, never application contents. Change no host settings.
"""
from collections import Counter
import ipaddress
import json
import os
import socket
import struct
import subprocess
import time

NAS = '192.168.0.220'
PORTS = {80, 443, 10080, 10443}


def packet(frame):
    if len(frame) < 14:
        return None
    kind, offset = struct.unpack('!H', frame[12:14])[0], 14
    while kind in (0x8100, 0x88a8):
        if len(frame) < offset + 4:
            return None
        kind, offset = struct.unpack('!H', frame[offset + 2:offset + 4])[0], offset + 4
    if kind == 0x0800:
        if len(frame) < offset + 20 or frame[offset] >> 4 != 4:
            return None
        size = (frame[offset] & 15) * 4
        if size < 20 or frame[offset + 9] != 6 or struct.unpack('!H', frame[offset + 6:offset + 8])[0] & 0x1fff:
            return None
        source = socket.inet_ntoa(frame[offset + 12:offset + 16])
        destination = socket.inet_ntoa(frame[offset + 16:offset + 20])
        tcp = offset + size
    elif kind == 0x86dd:
        if len(frame) < offset + 40 or frame[offset] >> 4 != 6 or frame[offset + 6] != 6:
            return None
        source = socket.inet_ntop(socket.AF_INET6, frame[offset + 8:offset + 24])
        destination = socket.inet_ntop(socket.AF_INET6, frame[offset + 24:offset + 40])
        tcp = offset + 40
    else:
        return None
    if len(frame) < tcp + 14:
        return None
    sport, dport = struct.unpack('!HH', frame[tcp:tcp + 4])
    flags = frame[tcp + 13]
    if not ({sport, dport} & PORTS) or not flags & 6:
        return None
    return source, sport, destination, dport, flags & 0x16


def main():
    addresses = json.loads(subprocess.check_output(['ip', '-j', 'addr', 'show'], text=True, timeout=10))
    local = {a['local'] for row in addresses for a in row.get('addr_info', [])}
    if os.geteuid() != 0 or NAS not in local:
        raise RuntimeError('Run with sudo on the NAS.')
    print('NAS interfaces: ' + '; '.join(row['ifname'] + '=' + ','.join(a['local'] for a in row.get('addr_info', []) if a['family'] == 'inet')
                                       for row in addresses if any(a['local'] == NAS for a in row.get('addr_info', []))), flush=True)
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    # Keep ETH_P_ALL and every interface; do not restrict to the outgoing NIC.
    capture.settimeout(.4)
    counts = Counter()
    print('Tracing web connection headers on all interfaces for 24 seconds...', flush=True)
    probe = subprocess.Popen(['curl', '--disable', '--noproxy', '*', '-4', '-sS', '--connect-timeout', '4', '--max-time', '22',
                              '--output', '/dev/null', '--write-out', 'Public Seerr HTTP=%{http_code}',
                              'https://request.sawdoctor.uk/?nas_trace=' + str(time.time_ns())],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        end = time.monotonic() + 24
        while time.monotonic() < end:
            try:
                body, address = capture.recvfrom(192)
            except socket.timeout:
                continue
            item = packet(body)
            if item is not None:
                counts[(address[0], *item)] += 1
        if probe.poll() is None:
            probe.kill()
        output, _ = probe.communicate(timeout=5)
        print(output or 'Public request did not finish.', flush=True)
        # The HTTPS request must produce an observable external SYN/SYN+ACK.
        outgoing = sum(n for (_, src, _, dst, dp, flags), n in counts.items()
                       if src in local and not ipaddress.ip_address(dst).is_private and dp == 443 and flags == 2)
        replies = sum(n for (_, src, sp, dst, _, flags), n in counts.items()
                      if dst in local and not ipaddress.ip_address(src).is_private and sp == 443 and flags == 18)
        print(f'CAPTURE CONTROL: outgoing HTTPS SYN={outgoing}; returned SYN+ACK={replies}; '
              + ('PASS' if outgoing and replies else 'NOT PROVEN'), flush=True)
        incoming = [(key, n) for key, n in counts.items() if key[3] == NAS and key[4] in PORTS and key[5] == 2]
        if incoming:
            print('WEB CONNECTION ATTEMPTS REACHING NAS:', flush=True)
            for (device, src, sp, dst, dp, flags), n in sorted(incoming):
                print(f'{device}: {src}:{sp} -> {dst}:{dp} SYN x{n}', flush=True)
        elif outgoing and replies:
            print('No IPv4 SYN to NAS web ports on ANY interface during this request.', flush=True)
        for (device, src, sp, dst, dp, flags), n in counts.most_common(28):
            label = '+'.join(name for bit, name in ((2, 'SYN'), (16, 'ACK'), (4, 'RST')) if flags & bit)
            print(f'{device}: {src}:{sp} -> {dst}:{dp} {label} x{n}', flush=True)
        print('READ-ONLY COMPLETE: no service, firewall, router, certificate or database change.', flush=True)
    finally:
        capture.close()
        if probe.poll() is None:
            probe.kill()
            probe.communicate(timeout=5)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        raise SystemExit('STOP: ' + (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__))
