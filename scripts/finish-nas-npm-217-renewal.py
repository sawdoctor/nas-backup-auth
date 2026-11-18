#!/usr/bin/env python3
"""Finish the pinned NPM handover against the reviewed actual 2.17.0 module."""
import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import socket
import sqlite3
import ssl
import sys
import time

WORK = Path('/srv/dev-disk-by-uuid-e5af079d-1bbd-4ad2-a94b-5a6dbaf8b4d6/compose/production-cutover/npm-renewal-handover')
ORIGINAL = WORK / 'worker.py'
ORIGINAL_SHA = '1348d0c2e23b6967d385bc50217ba7fa1ece56b2e686d7a314be363ee9ac7ce5'
OOM = WORK / 'worker-with-oom-defaults.py'
OOM_SHA = 'de276d9ffb8fd895ef58bd9b9828c8125abca30f24d9c3d3f70244560ae172da'
REVIEW = WORK / 'private-current-stock-module.json'
REVIEW_SHA = '3304486ed3e590a335199c78602469d4fe5850aeefd5922e9bc61483fc64fcb7'
STOCK_SHA = '4a5f1a06aa28af7a0a7eebad7dba7f35d4c1b395cdee5a88bf8ce4a392e15855'
SELF = WORK / 'worker-current-217.py'
UNIT = 'nas-production-npm-renewal-current.service'
OUTCOME_REMOTE = 'gdrive:nas-backups/openmediavault/migration-review/nas-npm-renewal-outcome-20261118.txt'


def require(value, message):
    if not value:
        raise RuntimeError(message)


def load(path, expected, name):
    require(not any(p.is_symlink() for p in (path, *path.parents))
            and hashlib.sha256(path.read_bytes()).hexdigest() == expected,
            'A retained pinned NPM handover input changed; no proxy update requested.')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verified_review():
    require(not any(p.is_symlink() for p in (REVIEW, *REVIEW.parents)), 'The current-image source review path is symbolic.')
    data = REVIEW.read_bytes()
    require(hashlib.sha256(data).hexdigest() == REVIEW_SHA, 'The native current-image source review changed.')
    review = json.loads(data)
    require(review.get('format') == 'sawdoctor-current-npm-stock-module-review-v1'
            and review.get('package', {}).get('version') == '2.17.0'
            and review.get('package', {}).get('type') == 'module'
            and review.get('modulePath') == '/app/internal/certificate.js'
            and review.get('moduleSha256') == STOCK_SHA
            and hashlib.sha256(review['moduleSource'].encode()).hexdigest() == STOCK_SHA,
            'The reviewed package/version/stock module identity differs.')
    return review


def verify_stock(source):
    require(hashlib.sha256(source).hexdigest() == STOCK_SHA,
            'The current image certificate module differs from the exact reviewed NPM 2.17.0 file.')
    print('NPM 2.17.0 STOCK MODULE VERIFIED: exact native/official source hash; optional renewal options and batch reload reviewed.', flush=True)


def configure(module, oom, review):
    require(review['image'] == module.IMAGE, 'The reviewed stock code belongs to a different current image.')
    oom.configure(module)
    module.verify_stock = verify_stock
    module.SELF = SELF
    module.UNIT = UNIT
    return module


def names_for_certificates(database, wanted):
    connection = sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=5)
    try:
        connection.execute('PRAGMA query_only=ON')
        result = {}
        for cert, text in connection.execute(
                'SELECT certificate_id,domain_names FROM proxy_host WHERE is_deleted=0 AND enabled=1 AND certificate_id>0'):
            if cert not in wanted:
                continue
            for name in json.loads(text):
                if re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', name) and '.' in name:
                    result.setdefault(cert, set()).add(name)
        return {key: sorted(value) for key, value in result.items()}
    finally:
        connection.close()


def served_tls(name):
    try:
        context = ssl.create_default_context()
        with socket.create_connection(('192.168.0.220', 10443), timeout=5) as connection:
            with context.wrap_socket(connection, server_hostname=name) as tls:
                certificate = tls.getpeercert()
        return {'domain': name, 'verified': True, 'expires': certificate['notAfter']}
    except ssl.SSLCertVerificationError as error:
        return {'domain': name, 'verified': False, 'reason': 'certificate verification failed',
                'verificationCode': error.verify_code}
    except (ssl.SSLError, OSError):
        return {'domain': name, 'verified': False, 'reason': 'TLS connection unavailable'}


def file_checks(module, native, certificates):
    result = []
    root = module.APP / 'appdata/npm/letsencrypt'
    now = dt.datetime.now(dt.timezone.utc).timestamp()
    for cert in certificates:
        path = (root / ('live/npm-' + str(cert['id'])) / 'fullchain.pem').resolve()
        check = {'id': cert['id'], 'databaseExpired': cert['expired'], 'actualFileCurrent': False}
        if path.is_relative_to(root.resolve()) and path.is_file():
            output = module.run(native, 'openssl', 'x509', '-in', str(path), '-noout', '-enddate').decode().strip()
            if output.startswith('notAfter='):
                expiry = output.split('=', 1)[1]
                check.update(actualFileExpires=expiry, actualFileCurrent=ssl.cert_time_to_seconds(expiry) > now)
        result.append(check)
    return result


def final_observation(module):
    host, boot, backup, native = module.controllers()
    with native.lock(module.BASE / '.run.lock'):
        record = json.loads(native.read(module.STATE))
        require(record.get('phase') == 'complete' and record.get('image') == module.IMAGE,
                'The current NPM handover did not reach its completed-owner record.')
        names = names_for_certificates(module.DATABASE, set(record.get('originalExpiredIds', [])))
        print('OBSERVING NPM 2.17 BATCH RELOAD AND PREVIOUSLY EXPIRED ROUTE TLS...', flush=True)
        deadline = time.monotonic() + 300
        while True:
            text = module.logs(native, record['startedUtc'])
            certificates = module.certificate_status()
            served = [dict(certificateId=identity, **served_tls(name)) for identity, values in names.items() for name in values]
            batch_complete = 'Completed SSL cert renew process' in text
            if (batch_complete and all(c['verified'] for c in served)) or time.monotonic() >= deadline:
                break
            # A finished failed renewal needs diagnosis, not another forced attempt.
            if batch_complete and any(c['expired'] for c in certificates):
                break
            print('Stock NPM renewal/reload still progressing; no additional Certbot command started.', flush=True)
            time.sleep(15)
        files = file_checks(module, native, certificates)
        missing_names = sorted(set(record.get('originalExpiredIds', [])) - set(names))
        accepted = (batch_complete and not any(c['expired'] for c in certificates)
                    and all(c['actualFileCurrent'] for c in files)
                    and all(c['verified'] for c in served) and not missing_names
                    and 'Certificate renewed but nginx could not be reloaded:' not in text)
        outcome = {'format': 'sawdoctor-npm-217-renewal-observation-v1', 'renewalOwnerActive': True,
                   'nativePackageVersion': '2.17.0', 'reviewSha256': REVIEW_SHA, 'moduleSha256': STOCK_SHA,
                   'normalBatchComplete': batch_complete, 'activeCertificateFiles': files,
                   'originalExpiredRouteTls': served, 'originalExpiredIdsWithoutConcreteHostname': missing_names,
                   'activeExpiredCertificates': [c for c in certificates if c['expired']],
                   'accepted': accepted, 'sourceRemainsFrozen': record.get('sourceFrozen') is True}
        native.atomic(WORK / 'current-217-outcome.json', outcome)
        if not accepted:
            payload = json.dumps({'outcome': outcome, 'privateRenewalLog': text}, sort_keys=True).encode()
            private = WORK / 'private-current-renewal-result.json'
            native.atomic(private, payload)
            try:
                native.run('rclone', '--config', '/root/.config/rclone/rclone.conf', 'copyto', str(private), OUTCOME_REMOTE,
                           '--tpslimit', '2', '--retries', '2', '--contimeout', '10s', '--timeout', '45s', timeout=120)
                print('PRIVATE NPM RENEWAL OUTCOME READY: ' + hashlib.sha256(payload).hexdigest(), flush=True)
            except Exception:
                print('Private renewal outcome retained locally; diagnostic upload unavailable.', flush=True)
        print('NPM 2.17 FINAL RESULT: ' + json.dumps(outcome, sort_keys=True), flush=True)
        if accepted:
            print('NPM RENEWAL ACCEPTED. Current certificate files and previously expired route TLS verified after the normal batch.', flush=True)
        else:
            print('NPM RENEWAL OWNER RESTORED; CERTIFICATE FOLLOW-UP REMAINS. Current certificates and running proxy retained.', flush=True)


def main():
    review = verified_review()
    module = load(ORIGINAL, ORIGINAL_SHA, 'npm_217_pinned_handover')
    oom = load(OOM, OOM_SHA, 'npm_217_pinned_oom')
    configure(module, oom, review)
    module.INSTALL_SOURCE = globals().get('INSTALL_SOURCE')
    module.RESUME_APPROVED_NPM_RENEWAL = globals().get('RESUME_APPROVED_NPM_RENEWAL')
    module.main()
    if sys.argv[1:] == ['--worker']:
        final_observation(module)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        message = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        print('STOP: ' + message + ' Current certificates, data and source freeze retained.', flush=True)
        raise SystemExit(1)
