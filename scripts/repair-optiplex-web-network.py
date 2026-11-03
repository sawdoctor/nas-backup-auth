#!/usr/bin/env python3
"""Restore the recorded source web-network map, resolving address chains safely."""
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
PEERS = ('nzbdav', 'usenet-ultimate', 'shelfmark-ebooks', 'prowlarr')
NAMES = PEERS + ('wizarr', 'kometa', 'npm-app-1')


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
    allocated=owners(network); plan=[]; saved_addresses=set()
    ranges=[ipaddress.ip_network(item['Subnet']) for item in network['IPAM']['Config'] if item.get('Subnet')]
    reviewed_ids={current[name]['Id'] for name in NAMES}
    if not set(allocated.values()) <= reviewed_ids:
        raise RuntimeError('An unreviewed container is attached to web-network; no connections were changed.')
    for name in NAMES:
        if catalog[name]['Id'] != current[name]['Id'] or catalog[name]['Image'] != current[name]['Image']:
            raise RuntimeError('A recorded source container identity changed: '+name)
        original=catalog[name]['NetworkSettings']['Networks'][NETWORK]
        connection=current[name]['NetworkSettings']['Networks'][NETWORK]
        if any(item['NetworkID'] != network['Id'] for item in (original,connection)):
            raise RuntimeError('A recorded source Docker network identity changed.')
        saved=str(ipaddress.ip_address(original['IPAddress']))
        if saved in saved_addresses or not any(ipaddress.ip_address(saved) in subnet for subnet in ranges):
            raise RuntimeError('The saved source address map needs review: '+name)
        saved_addresses.add(saved)
        for settings in (original,connection):
            if (settings.get('Links') or settings.get('DriverOpts') or settings.get('GlobalIPv6Address')
                or (settings.get('IPAMConfig') or {}).get('LinkLocalIPs')
                or (settings.get('IPAMConfig') or {}).get('IPv6Address')):
                raise RuntimeError('Additional endpoint options require review for '+name+'; no connections were changed.')
        if name=='npm-app-1':
            if not current[name]['State']['Running'] or connection.get('IPAddress')!=saved:
                raise RuntimeError('The live NPM endpoint differs; this repair will not move NPM.')
            continue
        if name in ('wizarr','kometa'):
            fixed='172.21.0.2' if name=='wizarr' else '172.21.0.4'
            if saved!=fixed or any((item.get('IPAMConfig') or {}).get('IPv4Address')!=fixed for item in (original,connection)):
                raise RuntimeError('A fixed Wizarr/Kometa address differs from the recorded setup.')
            if current[name]['State']['Running'] and connection.get('IPAddress')!=fixed:
                raise RuntimeError('A running Wizarr/Kometa endpoint differs; no connections were changed.')
            continue
        media=current[name]['NetworkSettings']['Networks'].get('media-core',{})
        if name in ('nzbdav','usenet-ultimate') and (not media.get('EndpointID') or not media.get('IPAddress')):
            raise RuntimeError(name+' must retain its active media-core connection.')
        if not current[name]['State']['Running'] or not connection.get('EndpointID') or not connection.get('IPAddress'):
            raise RuntimeError('A reviewed source peer is not connected and running: '+name)
        plan.append({'holder':name,'saved':saved,'id':current[name]['Id'],
                     'before':connection,'original':original})
    return plan


def plan_moves(entries,network):
    """Plan address chains and cycles completely before changing any endpoint."""
    allocated=owners(network).copy()
    current={item['holder']:item['before']['IPAddress'] for item in entries}
    pending={item['holder']:item for item in entries if current[item['holder']]!=item['saved']}
    reserved=set(allocated)|{item['saved'] for item in entries}|{'172.21.0.2','172.21.0.4'}
    for config in network['IPAM']['Config']:
        reserved.update((config.get('AuxiliaryAddresses') or {}).values())
        if config.get('Gateway'):reserved.add(config['Gateway'])
    steps=[]
    while pending:
        ready=next((name for name,item in pending.items() if item['saved'] not in allocated),None)
        if ready is None:
            ready=next(iter(pending));destination=None
            for config in network['IPAM']['Config']:
                subnet=ipaddress.ip_network(config['Subnet'])
                if subnet.version!=4:continue
                for offset in range(1,min(1024,subnet.num_addresses-1)):
                    candidate=str(subnet.broadcast_address-offset)
                    if candidate not in reserved and candidate not in allocated:
                        destination=candidate;break
                if destination:break
            if not destination:raise RuntimeError('No temporary address is available to resolve the recorded address cycle.')
            reserved.add(destination)
        else:
            destination=pending[ready]['saved']
        item=pending[ready];source=current[ready]
        steps.append(dict(item,source=source,destination=destination))
        allocated.pop(source);allocated[destination]=item['id'];current[ready]=destination
        if destination==item['saved']:del pending[ready]
        if len(steps)>2*len(entries):raise RuntimeError('The recorded address graph could not be resolved safely.')
    return steps


def connect(item,address,settings):
    args=['docker','network','connect','--ip',address]
    for alias in sorted(set(settings.get('Aliases') or [])):
        args+=['--alias',alias]
    if settings.get('GwPriority'):args+=['--gw-priority',str(settings['GwPriority'])]
    run(*args,NETWORK,item['id'])


def move(item):
    live=inspect(item['holder'])[item['holder']]
    connection=live['NetworkSettings']['Networks'].get(NETWORK,{})
    if live['Id']!=item['id'] or not live['State']['Running'] or connection.get('IPAddress')!=item['source']:
        raise RuntimeError('A planned source endpoint changed before its move.')
    allocated=owners(json.loads(run('docker','network','inspect',NETWORK))[0])
    if item['destination'] in allocated:raise RuntimeError('A planned destination became occupied; remaining connections were retained.')
    run('docker','network','disconnect',NETWORK,item['id'])
    try:
        connect(item,item['destination'],item['original'])
    except Exception:
        try:connect(item,item['source'],connection)
        except Exception:say('Web endpoint rollback also failed for '+item['holder']+'; its media-core attachment was retained.')
        raise
    updated=inspect(item['holder'])[item['holder']]
    others={name:settings.get('EndpointID') for name,settings in live['NetworkSettings']['Networks'].items() if name!=NETWORK}
    if (not updated['State']['Running'] or updated['NetworkSettings']['Networks'][NETWORK]['IPAddress'] != item['destination']
        or any(updated['NetworkSettings']['Networks'].get(name,{}).get('EndpointID')!=identity for name,identity in others.items())):
        raise RuntimeError('A source endpoint verification failed; the private recovery record was retained.')
    say(item['holder']+': web-network '+item['source']+' -> '+item['destination']+'.')


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
        names=NAMES
        current=inspect(*names);network=json.loads(run('docker','network','inspect',NETWORK))[0]
        for name in names:
            original=catalog[name]['NetworkSettings']['Networks'][NETWORK].get('IPAddress')
            live=current[name]['NetworkSettings']['Networks'][NETWORK].get('IPAddress') or 'disconnected'
            say(name+': current '+live+', recorded '+str(original)+'.')
        plan=preflight(catalog,current,network)
        steps=plan_moves(plan,network)
        plex_check()
        record=BASE/'web-network-recovery.json'
        if not record.exists():atomic(record,json.dumps({'format':SIGNATURE,'plan':plan,'steps':steps},indent=2)+'\n')
        say('Restoring the saved source web-network map: '+str(len(steps))+' endpoint moves.')
        for item in steps:move(item)
        failures=[]
        for holder,target,fixed in PAIRS:
            try:run('docker','start',current[target]['Id']);say(target+': started.')
            except RuntimeError:failures.append(target);say(target+': restart failed; continuing other recovery attempts.')
        if failures:raise RuntimeError('A targeted restart still needs review: '+', '.join(failures))
        updated=inspect(*names)
        for item in plan:
            if updated[item['holder']]['NetworkSettings']['Networks'][NETWORK]['IPAddress']!=item['saved']:
                raise RuntimeError('An original peer address was not restored.')
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
