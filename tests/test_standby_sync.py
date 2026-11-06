import contextlib
import copy
import datetime as dt
import importlib.util
import io
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch, Mock

ROOT=Path(__file__).resolve().parents[1]
REPO=ROOT if (ROOT/'scripts/install-migration-standby-sync.py').is_file() else ROOT/'nas-backup-auth'
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
s=load('standby_sync',REPO/'scripts/install-migration-standby-sync.py')
engine_path=REPO/'scripts/export-optiplex-plex-npm.py'
stage=load('standby_stage_fixture',REPO/'scripts/stage-optiplex-plex-npm-on-nas.py')


def row(name,running=True):
    return {'Name':'/'+name,'Id':name+'-unchanged-id','Image':name+'-image',
            'State':{'Running':running},'Config':{'Labels':{}},'Mounts':[]}


class StandbyTests(unittest.TestCase):
    def test_pinned_existing_workers_load_from_extensionless_installed_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            for original, expected, name in (
                (engine_path, s.SOURCE_SHA, 'source'),
                (REPO/'scripts/stage-optiplex-plex-npm-on-nas.py', s.NAS_SHA, 'nas'),
            ):
                installed=Path(directory)/('nas-'+name+'-worker')
                shutil.copy2(original,installed)
                worker=s.module(installed,expected,'standby_extensionless_'+name)
                self.assertTrue(callable(worker.main))
                installed.write_text(installed.read_text()+'\n# altered fixture\n')
                with self.assertRaisesRegex(RuntimeError,'checksum'):
                    s.module(installed,expected,'standby_extensionless_altered_'+name)

    def cold_fixture(self,directory,fail=False,include_plex=True):
        base=Path(directory); names=('plex','npm-app-1','sonarr','nzbdav','tracearr-db','glances','torbox-media-center')
        current={name:row(name) for name in names}; original=copy.deepcopy(current); calls=[]
        copied=[]
        helper=load('standby_source_fixture_'+str(id(current)),engine_path)
        def run(*args,**kwargs):
            calls.append(args)
            if args[:2]==('systemctl','is-active'):return 'active\n'
            if args[:2]==('systemctl','show'):return 'inactive\n'
            if args[:2] in (('systemctl','start'),('systemctl','stop')):return ''
            if args[:2]==('docker','stop'):
                current[next(name for name,value in current.items() if value['Id']==args[-1])]['State']['Running']=False;return ''
            if args[:2]==('docker','start'):
                current[next(name for name,value in current.items() if value['Id']==args[-1])]['State']['Running']=True;return ''
            if args[:2]==('docker','inspect'):
                return json.dumps([value for value in current.values() if args[-1] in (value['Name'].lstrip('/'),value['Id'])])
            if args[0]==str(helper.SAFE_START):current['plex']['State']['Running']=True;return ''
            raise AssertionError('Unexpected source command '+repr(args))
        def copy_roots(work,roots,live=False):
            self.assertFalse(live)
            excluded=s.LIVE_STATIC | (set() if include_plex else {'plex'})
            self.assertTrue(all(not value['State']['Running'] for name,value in current.items() if name not in excluded))
            if not include_plex:self.assertTrue(current['plex']['State']['Running'])
            self.assertTrue(all(current[name]['State']['Running'] for name in s.LIVE_STATIC))
            copied.append(True)
            if fail:raise RuntimeError('copy failure fixture')
        with patch.multiple(s,SOURCE_BASE=base,APP_NAMES=names),patch.object(s,'module',return_value=helper), \
             patch.object(s,'inspect_source',side_effect=lambda:copy.deepcopy(current)),patch.object(s,'copy_roots',side_effect=copy_roots), \
             patch.object(s,'snapshot_npm_database'),patch.object(s,'validate_source_networks'):
            roots={'npm-letsencrypt':{}}
            if include_plex:roots['plex-config']={}
            e=s.source_engine(original,roots)
            e.BACKUP_LOCK=base/'backup.lock'; e.BACKUP_MARKER=base/'backup-active';e.run=run
            with contextlib.redirect_stdout(io.StringIO()):
                if fail:
                    with self.assertRaisesRegex(RuntimeError,'copy failure'):e.cold_copy(base,original)
                else:e.cold_copy(base,original)
        return base,current,original,calls,copied

    def test_cohort_stops_all_data_writers_together_and_keeps_fuse_provider_running(self):
        with tempfile.TemporaryDirectory() as directory:
            base,current,original,calls,copied=self.cold_fixture(directory)
            self.assertTrue(copied);self.assertEqual(current,original)
            self.assertFalse((base/'resume.json').exists());self.assertFalse((base/'backup-active').exists())
            stops=[a[-1] for a in calls if a[:2]==('docker','stop')]
            self.assertNotIn(current['torbox-media-center']['Id'],stops)
            self.assertNotIn(current['glances']['Id'],stops)
            self.assertNotIn(current['npm-app-1']['Id'],stops)
            starts=[a[-1] for a in calls if a[:2]==('docker','start')]
            self.assertLess(starts.index(current['tracearr-db']['Id']),starts.index(current['sonarr']['Id']))
            self.assertIn(('systemctl','start','plex-daily-backup.timer'),calls)

    def test_failed_cold_copy_restores_all_original_source_containers_and_timer(self):
        with tempfile.TemporaryDirectory() as directory:
            base,current,original,calls,copied=self.cold_fixture(directory,fail=True)
            self.assertEqual(current,original)
            self.assertFalse((base/'resume.json').exists())
            self.assertFalse((base/'backup-active').exists())
            self.assertIn(('systemctl','start','plex-daily-backup.timer'),calls)

    def test_lean_snapshot_keeps_plex_running_while_other_writers_are_consistently_copied(self):
        with tempfile.TemporaryDirectory() as directory:
            base,current,original,calls,copied=self.cold_fixture(directory,include_plex=False)
            self.assertTrue(copied);self.assertEqual(current,original)
            stopped=[a[-1] for a in calls if a[:2]==('docker','stop')]
            self.assertNotIn(current['plex']['Id'],stopped)
            self.assertIn(current['sonarr']['Id'],stopped)
            self.assertIn(current['nzbdav']['Id'],stopped)

    def test_source_reader_adds_only_fixed_read_routes_and_retains_existing_routes(self):
        original='#!/bin/sh\ncase "${SSH_ORIGINAL_COMMAND-}" in\n core) exec /bin/cat /old/core ;;\n *) exit 1 ;;\nesac\n'
        result=s.reader_text(original)
        self.assertTrue(result.endswith(original.split('\n',1)[1]))
        self.assertEqual(s.reader_text(result),result)
        self.assertIn('standby-ready)',result)
        self.assertNotIn('eval ',result)
        subprocess.run(['sh','-n'],input=result,text=True,check=True)
        with self.assertRaises(RuntimeError):s.reader_text('#!/bin/bash\nunknown\n')

    def test_metadata_rejects_stale_invalid_and_future_snapshots(self):
        now=dt.datetime(2026,11,3,23,tzinfo=dt.timezone.utc)
        value={'format':s.FORMAT,'createdUtc':'20261103T223000Z','sha256':'a'*64,'archiveBytes':10,'unpackedBytes':20}
        self.assertTrue(s.valid_metadata(value,now))
        self.assertFalse(s.valid_metadata(dict(value,createdUtc='20261102T223000Z'),now))
        self.assertFalse(s.valid_metadata(dict(value,createdUtc='20261104T223000Z'),now))
        for change in ({'archiveBytes':True},{'unpackedBytes':-1},{'sha256':'../escape'}):
            with self.assertRaises(RuntimeError):s.valid_metadata(dict(value,**change),now)

    def archive_fixture(self,root):
        source=root/'source';source.mkdir()
        data=source/'data/library';data.mkdir(parents=True)
        (data/'movie link.mkv').symlink_to('/mnt/nzbdav/.ids/fixture')
        (data/'settings.json').write_text('private fixture application settings')
        stamp=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        manifest={'format':s.FORMAT,'scope':'standby-only','sourceHost':'192.168.0.29',
                  'createdUtc':stamp,'containers':[{'Name':'/'+name} for name in s.APP_NAMES]}
        (source/'manifest.json').write_text(json.dumps(manifest))
        checks=[]
        for path in sorted(source.rglob('*')):
            if path.is_file() and not path.is_symlink():
                checks.append(subprocess.check_output(['sha256sum','./'+str(path.relative_to(source))],cwd=source,text=True))
        (source/'SHA256SUMS').write_text(''.join(checks))
        archive=root/'archive.tar.zst'
        subprocess.run(['tar','-I','zstd','-cpf',str(archive),'-C',str(source),'.'],check=True)
        metadata={'format':s.FORMAT,'createdUtc':stamp,'sha256':s.digest(archive),
                  'archiveBytes':archive.stat().st_size,'unpackedBytes':stage.validate_tar(archive)+4096}
        return archive,metadata

    def receiver(self,root,archive,metadata):
        ssd=root/'ssd';ssd.mkdir(exist_ok=True);base=ssd/'migration/nightly-standby';base.mkdir(parents=True,exist_ok=True)
        live=ssd/'appdata/silo/config.json';live.parent.mkdir(parents=True,exist_ok=True);live.write_text('NAS-only user and playback state')
        key=root/'transfer-key';key.touch()
        helper=types.SimpleNamespace(KEY=key,HOST_KEY='fixture-host-key\n',
            ssh_base=lambda known:['fixture-ssh'],small_read=lambda command:json.dumps(metadata),validate_tar=stage.validate_tar)
        real_popen=subprocess.Popen;calls=[]
        def popen(command,*args,**kwargs):
            calls.append(command)
            if command[0]=='fixture-ssh':command=['cat',str(archive)]
            return real_popen(command,*args,**kwargs)
        context=contextlib.ExitStack()
        context.enter_context(patch.multiple(s,SSD=ssd,NAS_BASE=base,BASE=base))
        context.enter_context(patch.object(Path,'is_mount',side_effect=None,return_value=True))
        context.enter_context(patch.object(s,'module',return_value=helper))
        context.enter_context(patch.object(s.subprocess,'Popen',side_effect=popen))
        context.enter_context(contextlib.redirect_stdout(io.StringIO()))
        return context,base,live,calls

    def test_real_archive_transfer_extract_and_checksum_preserve_all_live_nas_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);archive,metadata=self.archive_fixture(root)
            context,base,live,calls=self.receiver(root,archive,metadata)
            with context:s.receive_nas()
            target=base/'snapshots'/metadata['createdUtc']
            self.assertEqual((target/'data/library/settings.json').read_text(),'private fixture application settings')
            self.assertTrue((target/'data/library/movie link.mkv').is_symlink())
            self.assertEqual(live.read_text(),'NAS-only user and playback state')
            self.assertEqual(json.loads((base/'current.json').read_text())['snapshot'],str(target))
            self.assertFalse((base/'export.tar.zst.part').exists())
            self.assertFalse(any(command[0] in ('docker','systemctl') for command in calls))

    def test_checksum_mismatch_does_not_activate_or_modify_live_apps(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);archive,metadata=self.archive_fixture(root);metadata['sha256']='0'*64
            context,base,live,calls=self.receiver(root,archive,metadata)
            with context:
                with self.assertRaisesRegex(RuntimeError,'SHA256'):s.receive_nas()
            self.assertEqual(live.read_text(),'NAS-only user and playback state')
            self.assertFalse((base/'current.json').exists())
            self.assertEqual(list((base/'snapshots').iterdir()),[])

    def test_verified_snapshot_reuse_repairs_index_after_interruption_and_removes_transfer_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);archive,metadata=self.archive_fixture(root)
            context,base,live,calls=self.receiver(root,archive,metadata)
            target=base/'snapshots'/metadata['createdUtc'];target.mkdir(parents=True)
            (target/'_VERIFIED.json').write_text(json.dumps(metadata))
            shutil.copy2(archive,base/'export.tar.zst.part')
            with context:s.receive_nas()
            self.assertTrue((base/'current.json').is_file())
            self.assertFalse((base/'export.tar.zst.part').exists())
            self.assertFalse(any(command[0]=='fixture-ssh' for command in calls))

    def test_pruning_retains_current_previous_and_unowned_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for stamp in ('20261030T010000Z','20261031T010000Z','20261101T010000Z','20261102T010000Z'):
                path=root/stamp;path.mkdir();(path/'_VERIFIED.json').write_text(json.dumps({'format':s.FORMAT}))
            unowned=root/'20261001T010000Z';unowned.mkdir();(unowned/'preserve').write_text('not ours')
            link=root/'symlink';link.symlink_to(unowned,target_is_directory=True)
            s.prune_snapshots(root,root/'20261102T010000Z')
            self.assertFalse((root/'20261030T010000Z').exists());self.assertFalse((root/'20261031T010000Z').exists())
            self.assertTrue((root/'20261101T010000Z').exists());self.assertTrue((root/'20261102T010000Z').exists())
            self.assertTrue((unowned/'preserve').is_file());self.assertTrue(link.is_symlink())

    def test_scope_excludes_unwanted_containers_and_keeps_images_manual(self):
        for name in ('rdtclient-books','jellyfin','fail2ban-ui','dockhand','buildx_buildkit_usenet-ultimate-builder0'):
            self.assertNotIn(name,s.APP_NAMES)
        source=s.unit_texts('source');nas=s.unit_texts('nas')
        self.assertIn('00:30:00 Europe/London',source['nas-migration-standby.timer'])
        self.assertIn('01:15:00 Europe/London',nas['nas-migration-standby.timer'])
        self.assertIn('Persistent=false',source['nas-migration-standby.timer'])
        self.assertIn('Persistent=true',nas['nas-migration-standby.timer'])
        self.assertNotIn('resume-source',nas['nas-migration-standby.service'])
        self.assertNotIn('nzbdav-rclone.service',source['nas-migration-standby-resume.service'])
        self.assertIn('OnFailure=nas-migration-standby-retry.service',source['nas-migration-standby.service'])
        self.assertIn('Restart=on-failure',source['nas-migration-standby-retry.service'])
        self.assertNotIn('retry.service',str(nas))
        self.assertNotIn('pull',str(nas))

    def test_pause_window_uses_uk_time_in_winter_and_summer(self):
        cases={
            '2026-11-03T00:29:59+00:00':False,
            '2026-11-03T00:30:00+00:00':True,
            '2026-11-03T02:29:59+00:00':True,
            '2026-11-03T02:30:00+00:00':False,
            '2026-11-03T13:00:00+00:00':False,
            '2026-07-02T23:45:00+00:00':True,
            '2026-07-03T01:30:00+00:00':False,
        }
        for value,expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(s.nighttime_pause_allowed(dt.datetime.fromisoformat(value)),expected)

    def test_source_outside_window_recovers_pending_apps_then_skips_without_inspection_or_copy(self):
        with patch.object(s,'source_resume') as resume,patch.object(s,'nighttime_pause_allowed',return_value=False), \
             patch.object(s,'inspect_source') as inspect,patch.object(s,'copy_roots') as copying, \
             contextlib.redirect_stdout(io.StringIO()):
            s.snapshot_source()
        resume.assert_called_once();inspect.assert_not_called();copying.assert_not_called()

    def test_window_guard_checks_each_stop_but_allows_recovery_starts(self):
        helper=load('standby_guard_fixture',engine_path)
        catalog={name:row(name) for name in s.APP_NAMES};calls=[]
        with patch.object(s,'module',return_value=helper), \
             patch.object(s,'run',side_effect=lambda *args,**kwargs:calls.append(args) or ''), \
             patch.object(s,'nighttime_pause_allowed',return_value=False):
            engine=s.source_engine(catalog,{})
            with self.assertRaisesRegex(RuntimeError,'window has closed'):
                engine.run('docker','stop','--timeout','60','fixture-id')
            engine.run('docker','start','fixture-id')
        self.assertEqual(calls,[('docker','start','fixture-id')])

    def test_existing_install_changes_schedule_without_starting_or_stopping_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);units=root/'units';units.mkdir();base=root/'state';base.mkdir()
            (units/'nas-migration-standby.service').write_text('# '+s.SIGNATURE+'\n')
            reader=root/'reader';reader.write_text('#!/bin/sh\ncase "${SSH_ORIGINAL_COMMAND-}" in\n *) exit 1 ;;\nesac\n')
            helper=types.SimpleNamespace(check_authorization=lambda:None);calls=[]
            with patch.multiple(s,ROLE='source',BASE=base,OUTPUT=root/'output',READER=reader,UNITS=units), \
                 patch.object(s,'module',return_value=helper),patch.object(s,'data_roots',return_value={}), \
                 patch.object(s,'inspect_source',return_value={}),patch.object(s.os,'chown'), \
                 patch.object(s,'validate_source_networks'), \
                 patch.object(s.shutil,'which',return_value='/fixture/existing-tool'), \
                 patch.object(s.pwd,'getpwnam',return_value=types.SimpleNamespace(pw_uid=1000,pw_gid=1000)), \
                 patch.object(s,'run',side_effect=lambda *args,**kwargs:calls.append(args) or ''), \
                 contextlib.redirect_stdout(io.StringIO()):
                s.install('fixture')
            self.assertNotIn(('systemctl','start','--no-block','nas-migration-standby.service'),calls)
            self.assertFalse(any(a[0]=='systemctl' and any(x in a for x in ('stop','restart')) for a in calls))
            self.assertIn('Persistent=false',(units/'nas-migration-standby.timer').read_text())

    def test_repaired_source_web_map_requires_all_paused_addresses_to_remain_pinned(self):
        catalog={name:dict(row(name),NetworkSettings={'Networks':{'web-network':{
            'NetworkID':'unchanged-web-network','EndpointID':'endpoint-'+name,'IPAddress':address,
            'IPAMConfig':None if name=='npm-app-1' else {'IPv4Address':address}}}})
            for name,address in s.SOURCE_WEB_ADDRESSES.items()}
        s.validate_source_networks(catalog)
        for name in ('nzbdav','usenet-ultimate','shelfmark-ebooks','prowlarr','wizarr','kometa'):
            changed=copy.deepcopy(catalog);changed[name]['NetworkSettings']['Networks']['web-network']['IPAMConfig']=None
            with self.subTest(name=name),self.assertRaisesRegex(RuntimeError,'no longer pinned'):
                s.validate_source_networks(changed)
        changed=copy.deepcopy(catalog);changed['nzbdav']['NetworkSettings']['Networks']['web-network']['IPAddress']='172.21.0.2'
        with self.assertRaisesRegex(RuntimeError,'map changed'):s.validate_source_networks(changed)

    def recovery_fixture(self,base,failures):
        names=('plex','wizarr','sonarr','kometa','nzbdav','tracearr-db','tracearr-redis')
        catalog={name:row(name) for name in names};current=copy.deepcopy(catalog);calls=[]
        for name,address in (('wizarr','172.21.0.2'),('kometa','172.21.0.4')):
            settings={'Networks':{'web-network':{'NetworkID':'web-id','IPAMConfig':{'IPv4Address':address}}}}
            catalog[name]['NetworkSettings']=copy.deepcopy(settings);current[name]['NetworkSettings']=copy.deepcopy(settings)
        for value in current.values():value['State']['Running']=False
        helper=load('standby_recovery_fixture_'+str(id(catalog)),engine_path)
        with patch.multiple(s,SOURCE_BASE=base,APP_NAMES=names),patch.object(s,'module',return_value=helper):
            engine=s.source_engine(catalog)
        engine.BACKUP_LOCK=base/'backup.lock';engine.BACKUP_MARKER=base/'backup-active';engine.BACKUP_MARKER.touch()
        state={'format':s.FORMAT,'containers':[{'name':name,'id':value['Id']} for name,value in catalog.items()],
               'ownsMarker':True,'restoreBackupTimer':True}
        engine.record(state)
        def run(*args,**kwargs):
            calls.append(args)
            if args[:2]==('docker','inspect'):
                return json.dumps([value for name,value in current.items() if args[-1] in (name,value['Id'])])
            if args[:2]==('docker','start'):
                name=next(name for name,value in current.items() if value['Id']==args[-1])
                if name in failures:raise RuntimeError('mock restart failure')
                current[name]['State']['Running']=True;return ''
            if args[0]==str(engine.SAFE_START):
                self.assertTrue(current['nzbdav']['State']['Running'])
                current['plex']['State']['Running']=True;return ''
            if args==('systemctl','start',engine.BACKUP_TIMER):return ''
            raise AssertionError('Unexpected recovery command '+repr(args))
        engine.run=run
        return engine,current,calls

    def test_failed_app_cannot_block_plex_other_apps_or_original_backup_timer(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);failures={'wizarr'};engine,current,calls=self.recovery_fixture(base,failures)
            with contextlib.redirect_stdout(io.StringIO()),patch.object(s.signal,'alarm') as alarm:
                with self.assertRaisesRegex(RuntimeError,'pending retries: wizarr'):engine.resume()
            self.assertTrue(current['plex']['State']['Running'])
            self.assertTrue(all(value['State']['Running'] for name,value in current.items() if name!='wizarr'))
            pending=json.loads(engine.STATE.read_text())
            self.assertEqual([item['name'] for item in pending['containers']],['wizarr'])
            self.assertFalse(pending['ownsMarker']);self.assertFalse(pending['restoreBackupTimer'])
            self.assertFalse(engine.BACKUP_MARKER.exists())
            self.assertIn(('systemctl','start',engine.BACKUP_TIMER),calls)
            starts=[a[-1] for a in calls if a[:2]==('docker','start')]
            self.assertLess(starts.index('kometa-unchanged-id'),starts.index('sonarr-unchanged-id'))
            alarm.assert_called_with(0)
            failures.clear();before=len(calls)
            with contextlib.redirect_stdout(io.StringIO()):engine.resume()
            self.assertFalse(engine.STATE.exists())
            self.assertEqual([a[-1] for a in calls[before:] if a[:2]==('docker','start')],['wizarr-unchanged-id'])

    def test_auxiliary_timers_are_restored_even_when_one_client_recovery_fails(self):
        helper=types.SimpleNamespace(resume=Mock(side_effect=RuntimeError('pending app')))
        with patch.object(s,'source_engine',return_value=helper),patch.object(s,'restore_aux') as aux:
            with self.assertRaisesRegex(RuntimeError,'pending app'):s.source_resume()
        aux.assert_called_once()

    def test_recovery_command_error_does_not_overwrite_snapshot_command_error(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);copy_error=base/'private-error.log';copy_error.write_text('original cold-copy error')
            response=types.SimpleNamespace(returncode=1,stdout='',stderr='mock networking error')
            with patch.multiple(s,BASE=base),patch.object(s.subprocess,'run',return_value=response):
                with self.assertRaises(RuntimeError):
                    s.run('docker','start','mock-id',error_log='source-recovery-command-error.log')
            self.assertEqual(copy_error.read_text(),'original cold-copy error')
            self.assertIn('mock networking error',(base/'source-recovery-command-error.log').read_text())

    def test_source_aux_recovery_restores_only_previously_active_timers(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);path=root/'paused-timers.json';selected=['media-mount-guard.timer','abs-user-provisioner.timer']
            path.write_text(json.dumps(selected));calls=[]
            with patch.multiple(s,SOURCE_BASE=root),patch.object(s,'run',side_effect=lambda *a,**k:calls.append(a) or ''):
                s.restore_aux()
            self.assertEqual(calls,[('systemctl','start',name) for name in selected]);self.assertFalse(path.exists())

    def test_online_npm_backup_includes_committed_wal_without_stopping_live_proxy(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'npm-live';source.mkdir();work=root/'work'
            target=work/'data/npm-data/database.sqlite';target.parent.mkdir(parents=True)
            live=sqlite3.connect(source/'database.sqlite');live.execute('PRAGMA journal_mode=WAL')
            live.execute('CREATE TABLE fixture(value TEXT)');live.execute('INSERT INTO fixture VALUES("committed live value")');live.commit()
            before=(source/'database.sqlite').read_bytes();before_wal=(source/'database.sqlite-wal').read_bytes()
            target.write_bytes(b'old staging database');Path(str(target)+'-wal').write_bytes(b'old staging wal')
            with patch.multiple(s,ROOTS={'npm-data':str(source)}):s.snapshot_npm_database(work)
            with sqlite3.connect(target) as copied:
                self.assertEqual(copied.execute('SELECT value FROM fixture').fetchall(),[('committed live value',)])
                self.assertEqual(copied.execute('PRAGMA journal_mode').fetchone()[0],'delete')
            self.assertEqual((source/'database.sqlite').read_bytes(),before)
            self.assertEqual((source/'database.sqlite-wal').read_bytes(),before_wal)
            self.assertFalse(Path(str(target)+'-wal').exists())
            live.close()

    def test_retention_keeps_last_full_snapshot_alongside_two_newer_lean_snapshots(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            stamps=('20261101T010000Z','20261102T010000Z','20261103T010000Z','20261104T010000Z','20261105T010000Z')
            for stamp in stamps:
                path=root/stamp;path.mkdir();(path/'_VERIFIED.json').write_text(json.dumps({'format':s.FORMAT}))
            for stamp in stamps[:2]:(root/stamp/'data/plex-config').mkdir(parents=True)
            s.prune_snapshots(root,root/stamps[-1])
            self.assertEqual({p.name for p in root.iterdir()},set((stamps[1],stamps[3],stamps[4])))

    def test_lean_database_checks_verify_npm_without_accessing_plex(self):
        with tempfile.TemporaryDirectory() as directory:
            work=Path(directory);database=work/'data/npm-data/database.sqlite';database.parent.mkdir(parents=True)
            with sqlite3.connect(database) as db:db.execute('CREATE TABLE fixture(value TEXT)')
            engine=types.SimpleNamespace(verify=Mock(side_effect=AssertionError('Plex must not be read')))
            with contextlib.redirect_stdout(io.StringIO()):s.verify_databases(work,engine)
            engine.verify.assert_not_called()

    def external_backup_fixture(self,root,rows,result='success'):
        helper=root/'plex-daily-backup.sh';helper.write_text('reviewed fixture backup worker')
        calls=[]
        def run(*args,**kwargs):
            calls.append(args)
            if args[0]=='systemctl':return result+'\n'
            if args[:4]==('sudo','-u','sawdoctor','rclone'):return json.dumps(rows)
            raise AssertionError(args)
        stack=contextlib.ExitStack()
        stack.enter_context(patch.multiple(s,PLEX_BACKUP_HELPER=helper,PLEX_BACKUP_SHA=s.digest(helper)))
        stack.enter_context(patch.object(s,'run',side_effect=run))
        return stack,helper,calls

    def test_recent_completed_cloud_backup_is_recorded_without_downloading_its_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            rows=[{'Name':'plex-config-2026-11-06-0430.tar.gz','Size':12*1024**3,'IsDir':False},
                  {'Name':'.plex-config-2026-11-07-0430.tar.gz.partial','Size':1,'IsDir':False}]
            stack,helper,calls=self.external_backup_fixture(Path(directory),rows)
            with stack:record=s.external_plex_backup(dt.datetime(2026,11,7,0,30,tzinfo=dt.timezone.utc))
            self.assertEqual(record['remote'],'gdrive:plex-backups/plex-config-2026-11-06-0430.tar.gz')
            self.assertTrue(any('lsjson' in call for call in calls))
            self.assertFalse(any('copy' in call or 'copyto' in call for call in calls))

    def test_stale_partial_empty_or_future_cloud_archives_cannot_replace_plex_snapshot(self):
        now=dt.datetime(2026,11,7,0,30,tzinfo=dt.timezone.utc)
        rows=[{'Name':'plex-config-2026-11-05-0430.tar.gz','Size':12,'IsDir':False},
              {'Name':'.plex-config-2026-11-06-0430.tar.gz.partial','Size':12,'IsDir':False},
              {'Name':'plex-config-2026-11-06-0430.tar.gz','Size':0,'IsDir':False},
              {'Name':'plex-config-2026-11-07-0430.tar.gz','Size':12,'IsDir':False}]
        with tempfile.TemporaryDirectory() as directory:
            stack,helper,calls=self.external_backup_fixture(Path(directory),rows)
            with stack,self.assertRaisesRegex(RuntimeError,'No completed Plex'):s.external_plex_backup(now)

    def test_failed_or_changed_normal_backup_blocks_lean_snapshot_before_pausing(self):
        with tempfile.TemporaryDirectory() as directory:
            stack,helper,calls=self.external_backup_fixture(Path(directory),[],result='exit-code')
            with stack,self.assertRaisesRegex(RuntimeError,'did not succeed'):s.external_plex_backup()
            self.assertFalse(any('lsjson' in call for call in calls))
        with tempfile.TemporaryDirectory() as directory:
            stack,helper,calls=self.external_backup_fixture(Path(directory),[])
            helper.write_text('changed backup helper')
            with stack,self.assertRaisesRegex(RuntimeError,'helper changed'):s.external_plex_backup()
            self.assertEqual(calls,[])


if __name__=='__main__':unittest.main()
