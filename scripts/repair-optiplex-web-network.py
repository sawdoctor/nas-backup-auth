#!/usr/bin/env python3
"""Restore two source Docker endpoints to their recorded pre-snapshot addresses."""
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.request

SIGNATURE = 'Sawdoctor restore source web-network addresses v1'
BASE = Path('/var/lib/sawdoctor-migration-standby')
WORKER = Path('/run/nas-source-web-repair.py')
STANDBY = Path('/usr/local/sbin/nas-migration-standby')
KNOWN_WORKERS = {
    '4bbae1be9f366f092bc326e1b32324635257613695ba42ab2074bf01d3374818',
    'c026006d872a6a7605926fae3f246810cb2c26f6ba305d0ee0fe662f3099c0c3',
}
NETWORK = 'web-network'
PAIRS = (('nzbdav', 'wizarr', '172.21.0.2'),
         ('usenet-ultimate', 'kometa', '172.21.0.4'))


def say(text):
    print(text, flush=True)


def atomic(path, text):
    if path.is_symlink():
        raise RuntimeError('An unexpected symbolic repair file was retained.')
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(text); stream.flush(); os.fsync(stream.fileno())
        os.chmod(temporary, 0o600 if path.parent == BASE else 0o700)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)


def run(*args, timeout=120, allowed=(0,)):
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    if result.returncode not in allowed:
        if BASE.is_dir():atomic(BASE/'web-network-repair-error.log',result.stdout+'\n'+result.stderr)
        raise RuntimeError('A repair command failed; details are in the private web-network-repair-error.log.')
    return result.stdout


def inspect(*names):
    return {row['Name'].lstrip('/'):row for row in json.loads(run('docker','inspect',*names))}


def plex_check():
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open('http://127.0.0.1:32400/identity',timeout=10) as response:
        if response.status != 200:raise RuntimeError('The local Plex identity check did not return HTTP 200.')


def owners(network):
    return {str(ipaddress.ip_interface(value['IPv4Address']).ip):identity
            for identity,value in (network.get('Containers') or {}).items() if value.get('IPv4Address')}


def preflight(catalog,current,network):
    if network['Name'] != NETWORK or network.get('Driver') != 'bridge' or network.get('Scope') != 'local':
        raise RuntimeError('The reviewed local web-network differs.')
    allocated=owners(network); plan=[]
    ranges=[ipaddress.ip_network(item['Subnet']) for item in network['IPAM']['Config'] if item.get('Subnet')]
    for holder,target,fixed in PAIRS:
        for name in (holder,target):
            if (catalog[name]['Id'] != current[name]['Id'] or catalog[name]['Image'] != current[name]['Image']):
                raise RuntimeError('A recorded source container identity changed: '+name)
        original=catalog[holder]['NetworkSettings']['Networks'][NETWORK]
        connection=current[holder]['NetworkSettings']['Networks'][NETWORK]
        target_connection=current[target]['NetworkSettings']['Networks'][NETWORK]
        target_original=catalog[target]['NetworkSettings']['Networks'][NETWORK]
        if any(item['NetworkID'] != network['Id'] for item in (original,connection,target_connection,target_original)):
            raise RuntimeError('A recorded source Docker network identity changed.')
        if ((target_connection.get('IPAMConfig') or {}).get('IPv4Address') != fixed
            or (target_original.get('IPAMConfig') or {}).get('IPv4Address') != fixed):
            raise RuntimeError('A fixed Wizarr/Kometa address differs from the recorded setup.')
        saved=str(ipaddress.ip_address(original['IPAddress']))
        if saved in {'172.21.0.2','172.21.0.4'} or not any(ipaddress.ip_address(saved) in subnet for subnet in ranges):
            raise RuntimeError('The saved source address needs review: '+holder)
        if allocated.get(saved) not in (None,current[holder]['Id']):
            raise RuntimeError('The saved '+holder+' address '+saved+' is currently occupied; no connections were changed.')
        media=current[holder]['NetworkSettings']['Networks'].get('media-core',{})
        if not current[holder]['State']['Running'] or not media.get('EndpointID') or not media.get('IPAddress'):
            raise RuntimeError(holder+' must retain its active media-core connection.')
        if connection.get('IPAddress') not in (fixed,saved) or not connection.get('EndpointID'):
            raise RuntimeError('The live source web address differs from the two reviewed cases: '+holder)
        for settings in (original,connection):
            if (settings.get('Links') or settings.get('DriverOpts') or settings.get('GlobalIPv6Address')
                or (settings.get('IPAMConfig') or {}).get('LinkLocalIPs')
                or (settings.get('IPAMConfig') or {}).get('IPv6Address')):
                raise RuntimeError('Additional endpoint options require review; no connections were changed.')
        if allocated.get(fixed) not in (None,current[holder]['Id'],current[target]['Id']):
            raise RuntimeError('A different container holds the fixed address; no connections were changed.')
        plan.append({'holder':holder,'target':target,'fixed':fixed,'saved':saved,
                     'id':current[holder]['Id'],'before':connection,'original':original})
    return plan


def connect(item,address,settings):
    args=['docker','network','connect','--ip',address]
    for alias in sorted(set(settings.get('Aliases') or [])):
        args+=['--alias',alias]
    if settings.get('GwPriority'):args+=['--gw-priority',str(settings['GwPriority'])]
    run(*args,NETWORK,item['id'])


def move(item):
    live=inspect(item['holder'])[item['holder']]
    connection=live['NetworkSettings']['Networks'].get(NETWORK,{})
    if connection.get('IPAddress') == item['saved']:
        say(item['holder']+': saved web address already restored.');return
    run('docker','network','disconnect',NETWORK,item['id'])
    try:
        connect(item,item['saved'],item['original'])
    except Exception:
        # Wizarr/Kometa have not been started yet, so the old address is still free.
        try:connect(item,item['before']['IPAddress'],item['before'])
        except Exception:say('Web endpoint rollback also failed for '+item['holder']+'; its media-core attachment was retained.')
        raise
    updated=inspect(item['holder'])[item['holder']]
    if (not updated['State']['Running'] or updated['NetworkSettings']['Networks'][NETWORK]['IPAddress'] != item['saved']
        or updated['NetworkSettings']['Networks']['media-core']['EndpointID'] != live['NetworkSettings']['Networks']['media-core']['EndpointID']):
        raise RuntimeError('A source endpoint verification failed; the private recovery record was retained.')
    say(item['holder']+': original web-network address restored to '+item['saved']+'.')


def repair():
    if STANDBY.is_symlink() or hashlib.sha256(STANDBY.read_bytes()).hexdigest() not in KNOWN_WORKERS:
        raise RuntimeError('The installed standby helper differs from the two reviewed versions.')
    state=run('systemctl','show','nas-migration-standby.service','-p','ActiveState','--value').strip()
    if state not in ('inactive','failed'):
        raise RuntimeError('The snapshot must be inactive before this repair.')
    run('systemctl','disable','--now','nas-migration-standby.timer')
    with (BASE/'.run.lock').open('a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise RuntimeError('A source snapshot operation is still running.')
        catalog=json.loads((BASE/'catalog.json').read_text())
        names=[name for holder,target,fixed in PAIRS for name in (holder,target)]
        current=inspect(*names);network=json.loads(run('docker','network','inspect',NETWORK))[0]
        plan=preflight(catalog,current,network)
        plex_check()
        record=BASE/'web-network-recovery.json'
        if not record.exists():atomic(record,json.dumps({'format':SIGNATURE,'plan':plan},indent=2)+'\n')
        for item in plan:move(item)
        failures=[]
        for holder,target,fixed in PAIRS:
            try:run('docker','start',current[target]['Id']);say(target+': started.')
            except RuntimeError:failures.append(target);say(target+': restart failed; continuing other recovery attempts.')
        if failures:raise RuntimeError('A targeted restart still needs review: '+', '.join(failures))
        updated=inspect(*names)
        for holder,target,fixed in PAIRS:
            if not updated[target]['State']['Running'] or updated[target]['NetworkSettings']['Networks'][NETWORK]['IPAddress'] != fixed:
                raise RuntimeError('A restored fixed address did not match its original owner.')
        say('Finishing the saved source recovery and restoring its original timers...')
        run(str(STANDBY),'resume-source',timeout=600)
        plex_check()
        if (BASE/'resume.json').exists() or (BASE/'paused-timers.json').exists():
            raise RuntimeError('Pending source recovery records remain; the nightly snapshot stays disabled.')
        say('SOURCE RECOVERY COMPLETE. Wizarr and Kometa are running at their original fixed addresses.')
        say('Plex HTTP: 200. Original recovery records cleared and source timers restored.')
        say('The new migration standby timer remains disabled pending a successful overnight snapshot test.')


def main():
    os.umask(0o077)
    if os.geteuid()!=0 or 'inet 192.168.0.29/' not in run('ip','-4','addr','show'):
        raise RuntimeError('Run with sudo on the OptiPlex at 192.168.0.29.')
    if BASE.is_symlink() or not BASE.is_dir():raise RuntimeError('The private source snapshot state directory is required.')
    if sys.argv[1:]==['repair']:repair();return
    if sys.argv[1:]:raise RuntimeError('Unknown source repair operation.')
    if run('systemctl','is-active','nas-source-web-repair.service',allowed=(0,3,4)).strip() in ('active','activating'):
        say('The source web repair is already running.');return
    source=globals().get('INSTALL_SOURCE')
    if not source:raise RuntimeError('Use the complete provided source repair command.')
    if WORKER.exists() and (WORKER.is_symlink() or SIGNATURE not in WORKER.read_text()):
        raise RuntimeError('An unrelated runtime repair file was retained.')
    atomic(WORKER,source)
    run('systemctl','reset-failed','nas-source-web-repair.service',allowed=(0,1))
    run('systemd-run','--unit=nas-source-web-repair','--collect',
        '--description=Restore original OptiPlex web-network addresses and pending apps',
        '/usr/bin/python3','-u',str(WORKER),'repair')
    say('Source web-network repair started in the background. Closing SSH is safe.')
    say('Check: sudo journalctl -u nas-source-web-repair.service -n 25 --no-pager -o cat')


if __name__=='__main__':
    try:main()
    except RuntimeError as error:raise SystemExit('STOP: '+str(error))
    except Exception as error:raise SystemExit('STOP: Source web repair could not finish ('+type(error).__name__+'); private details were withheld.')
