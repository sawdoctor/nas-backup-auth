#!/usr/bin/env python3
"""Reapply only the approved NAS web forwards through the existing Hub service.

Checks public delivery BEFORE any router write. Never enables UPnP, deletes a
mapping, changes another target/port, starts a container or alters certificates.
A missing UPnP read entry is not treated as proof a GUI rule is absent. Router
conflicts/errors stop the operation; there is no delete-and-retry fallback.
"""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import types
import urllib.request
import uuid
import xml.etree.ElementTree as ET

APP = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6')
WORK = APP / 'compose/npm-restore/public-forward-refresh'
STATE = WORK / 'state.json'
FORMAT = 'sawdoctor-existing-web-forward-refresh-v1'
NAS = '192.168.0.220'
WAN = '82.30.213.121'
TARGETS = {443: 10443, 80: 10080}
SERVICE = 'urn:schemas-upnp-org:service:WANIPConnection:1'
READER_URL = 'https://raw.githubusercontent.com/sawdoctor/nas-backup-auth/1d7b231756ae8a2bb212a3d2f93ea9eec51a2202/scripts/read-nas-router-web-mappings.py'
READER_SHA = '1899912040c0005db03c663650733cb821c0c6f1004a51619d74cf45ee95d2e3'


def say(value):
    print(value, flush=True)


def safe(path):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise RuntimeError('An unexpected symbolic operation path was retained.')


def save(record):
    safe(WORK); safe(STATE)
    if not WORK.exists():
        WORK.mkdir(mode=0o700)
    descriptor, temporary = tempfile.mkstemp(dir=WORK)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(record, stream, indent=2)
            stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, STATE)
        directory = os.open(WORK, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def reader():
    with urllib.request.urlopen(READER_URL, timeout=20) as response:
        source = response.read(64 * 1024)
    if hashlib.sha256(source).hexdigest() != READER_SHA:
        raise RuntimeError('The pinned gateway reader failed its integrity check.')
    module = types.ModuleType('pinned_gateway_reader')
    exec(compile(source, READER_URL, 'exec'), module.__dict__)
    return module


def curl(url, connect_to=None):
    args = ['curl', '--disable', '--noproxy', '*', '-4', '--silent', '--show-error',
            '--connect-timeout', '4', '--max-time', '22' if connect_to is None else '5',
            '--output', '/dev/null', '--write-out', '%{http_code}']
    if connect_to:
        args += ['--connect-to', connect_to]
    result = subprocess.run([*args, url], capture_output=True, text=True, timeout=26)
    return {'exit': result.returncode, 'http': int(result.stdout) if result.stdout.isdigit() else 0}


def npm_preflight():
    row = json.loads(subprocess.check_output(['docker', 'inspect', 'npm-nas'], text=True, timeout=15))[0]
    expected = {key: [{'HostIp': NAS, 'HostPort': str(port)}]
                for key, port in [('80/tcp', 10080), ('443/tcp', 10443), ('81/tcp', 10081)]}
    if row['Name'] != '/npm-nas' or not row['State']['Running'] or row['HostConfig']['PortBindings'] != expected:
        raise RuntimeError('NPM is not running with its accepted NAS-only 10080/10081/10443 bindings.')
    roots = [m['Source'] for m in row['Mounts'] if m['Destination'] == '/data' and m['Type'] == 'bind']
    if roots != [str(APP / 'appdata/npm/data')]:
        raise RuntimeError('The accepted NPM data/log binding differs; no router change made.')
    log_root = Path(roots[0]) / 'logs'; safe(log_root)
    for scheme, port in [('http', 10080), ('https', 10443)]:
        result = curl(scheme + '://request.sawdoctor.uk/',
                      'request.sawdoctor.uk:' + ('443' if scheme == 'https' else '80') + ':' + NAS + ':' + str(port))
        if result['exit'] or not 200 <= result['http'] < 400:
            raise RuntimeError('The local NAS Seerr proxy is not ready on ' + scheme + '; no router change made.')
    return log_root


def logged(log_root, nonce):
    safe(log_root)
    files = sorted(log_root.glob('proxy-host-*_access.log'))
    if not files or len(files) > 100:
        return False
    for path in files:
        safe(path)
        with path.open('rb') as stream:
            stream.seek(0, os.SEEK_END)
            stream.seek(max(0, stream.tell() - 256 * 1024))
            if nonce.encode('ascii') in stream.read(256 * 1024):
                return True
    return False


def public_probe(log_root):
    nonce = 'sawdoctor-forward-' + uuid.uuid4().hex
    # This token is used ONLY in the public request, never in a local test.
    result = curl('https://request.sawdoctor.uk/?sawdoctor_forward_probe=' + nonce)
    result['seenInNasNpmLog'] = logged(log_root, nonce)
    result['verified'] = not result['exit'] and 200 <= result['http'] < 500 and result['seenInNasNpmLog']
    return result


def check_before(before):
    if set(before) != set(TARGETS):
        raise RuntimeError('The two fixed web mapping records are required.')
    for external, row in before.items():
        if 'faultCode' in row:
            if row['faultCode'] != 714:
                raise RuntimeError('The Hub did not permit reading a web mapping; no router write made.')
            continue  # Not exposed in this API, NOT assumed absent.
        if row.get('NewInternalClient') != NAS or str(row.get('NewInternalPort')) != str(TARGETS[external]):
            raise RuntimeError('The Hub reports a different existing web destination; it was retained for review.')


def reapply(helper, url, external):
    if external not in TARGETS:
        raise RuntimeError('Only the two already-approved website forwards may be reapplied.')
    namespace = 'http://schemas.xmlsoap.org/soap/envelope/'
    root = ET.Element('{' + namespace + '}Envelope',
                      {'{' + namespace + '}encodingStyle': 'http://schemas.xmlsoap.org/soap/encoding/'})
    body = ET.SubElement(root, '{' + namespace + '}Body')
    action = ET.SubElement(body, '{' + SERVICE + '}AddPortMapping')
    values = [('NewRemoteHost', ''), ('NewExternalPort', str(external)), ('NewProtocol', 'TCP'),
              ('NewInternalPort', str(TARGETS[external])), ('NewInternalClient', NAS), ('NewEnabled', '1'),
              ('NewPortMappingDescription', 'sawdoctor-npm-existing-web'), ('NewLeaseDuration', '0')]
    for key, value in values:
        ET.SubElement(action, key).text = value
    response = helper.fetch(url, ET.tostring(root, encoding='utf-8', xml_declaration=True),
                            {'Content-Type': 'text/xml; charset="utf-8"', 'SOAPAction': '"' + SERVICE + '#AddPortMapping"'})
    fault = next((e.text for e in response.iter() if helper.local_name(e.tag) == 'errorCode'), None)
    if fault is not None:
        if fault == '718':
            raise RuntimeError('Hub reports mapping conflict 718 on TCP ' + str(external) + '. Nothing will be deleted or retried.')
        raise RuntimeError('Hub refused TCP ' + str(external) + ' with fault ' + (fault if fault.isdigit() else 'unavailable') + '.')
    if not any(e.tag == '{' + SERVICE + '}AddPortMappingResponse' for e in response.iter()):
        raise RuntimeError('The Hub write response is inconclusive; no retry or deletion will be attempted.')


def apply_pair(helper, url, before, record, persist=save):
    check_before(before)
    for external, internal in TARGETS.items():
        record['phase'] = 'requesting-' + str(external)
        persist(record)  # Durable intent precedes any router RPC.
        say(f'Reapplying only TCP {external} -> {NAS}:{internal}...')
        try:
            reapply(helper, url, external)
        except Exception as error:
            record['phase'] = 'stopped-' + str(external)
            record['responseUnconfirmed'] = True
            persist(record)
            if isinstance(error, RuntimeError):
                raise
            raise RuntimeError('Gateway request failed or timed out; result retained without retry.') from None
        record.setdefault('acceptedPorts', []).append(external)
        record['phase'] = 'accepted-' + str(external)
        persist(record)


def main():
    if globals().get('APPLY_APPROVED_WEB_FORWARDS') is not True:
        raise RuntimeError('This applies the approved website forwards; the explicit apply flag is required.')
    if os.geteuid() != 0 or not APP.is_mount():
        raise RuntimeError('Run with sudo on the NAS with the application SSD mounted.')
    addresses = subprocess.check_output(['ip', '-4', 'addr', 'show'], text=True, timeout=5)
    route = json.loads(subprocess.check_output(['ip', '-j', '-4', 'route', 'get', '1.1.1.1'], text=True, timeout=5))[0]
    if 'inet ' + NAS + '/' not in addresses or route.get('gateway') != '192.168.0.1':
        raise RuntimeError('The expected NAS address/gateway differs; no router change made.')
    safe(WORK); safe(STATE)
    log_root = npm_preflight()
    say('Checking current public delivery before any router write...')
    first = public_probe(log_root)
    say('Before: HTTP=' + str(first['http']) + '; unique request seen in NAS NPM log=' + str(first['seenInNasNpmLog']))
    if first['verified']:
        say('PUBLIC REQUEST ALREADY REACHES NAS NPM. No router mapping changed. Check the browser/app result next.')
        return
    if first['seenInNasNpmLog']:
        raise RuntimeError('The public request reached NAS NPM; its HTTP result needs an app/proxy review, not a router write.')
    if first['exit'] or first['http'] not in (521, 522, 523):
        raise RuntimeError('This is not the observed Cloudflare origin-connect failure; no router write made.')
    if STATE.exists():
        raise RuntimeError('An earlier router repair record exists. This run only checked delivery; no mapping was reapplied.')
    helper = reader()
    services = set()
    for location in helper.discover():
        services.update(helper.service_locations(ET.tostring(helper.fetch(location)), location))
    candidates = [(kind, url) for kind, url in services if kind == SERVICE]
    if len(candidates) != 1:
        raise RuntimeError('The previously observed Hub WAN service is unavailable or ambiguous; no setting changed.')
    kind, url = candidates[0]
    wan = helper.soap(kind, url, 'GetExternalIPAddress')
    if wan.get('NewExternalIPAddress') != WAN:
        raise RuntimeError('The Hub public address differs from the existing DNS origin; no router write made.')
    before = {port: helper.soap(kind, url, 'GetSpecificPortMappingEntry', port) for port in TARGETS}
    check_before(before)
    record = {'format': FORMAT, 'createdUtc': dt.datetime.now(dt.timezone.utc).isoformat(), 'phase': 'planned',
              'wan': WAN, 'gateway': '192.168.0.1', 'before': before, 'targets': TARGETS, 'initialProbe': first}
    save(record)
    apply_pair(helper, url, before, record)
    say('Hub accepted both existing web targets. Verifying an actual public request in NAS NPM logs...')
    result = public_probe(log_root)
    record['publicProbe'] = result
    record['phase'] = 'public-delivery-verified' if result['verified'] else 'public-delivery-unresolved'
    save(record)
    say('After: HTTP=' + str(result['http']) + '; unique request seen in NAS NPM log=' + str(result['seenInNasNpmLog']))
    say('Small operation record: ' + str(STATE))
    if not result['verified']:
        raise RuntimeError('The approved targets were accepted, but public delivery is still unverified. No further changes made.')
    say('PUBLIC SEERR REQUEST REACHED NAS NPM. Confirm one website on mobile data; other stopped applications remain separate work.')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        raise SystemExit('STOP: ' + (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__))
