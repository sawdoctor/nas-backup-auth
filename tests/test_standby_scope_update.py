import ast
import contextlib
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
REPO=ROOT if (ROOT/'scripts/update-migration-standby-scope.py').is_file() else ROOT/'nas-backup-auth'
spec=importlib.util.spec_from_file_location('scope_update',REPO/'scripts/update-migration-standby-scope.py')
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
NEW=(REPO/'scripts/install-migration-standby-sync.py').read_bytes()


class ScopeTests(unittest.TestCase):
    def original_fixture(self):
        value=NEW.decode().replace(s.NEW_PRUNE,s.OLD_PRUNE,1)
        self.assertNotEqual(value,NEW.decode())
        return value.encode()

    def functions(self,value):
        text=value.decode()
        return {node.name:ast.dump(node,include_attributes=False) for node in ast.parse(text).body
                if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef))}

    def test_nas_patch_changes_only_the_retention_function_and_is_repeatable(self):
        before=self.original_fixture();after=s.nas_patch(before)
        self.assertEqual(after.decode().replace(s.NEW_PRUNE,s.OLD_PRUNE,1),before.decode())
        changed={name for name,value in self.functions(before).items() if self.functions(after)[name]!=value}
        self.assertEqual(changed,{'prune_snapshots'})
        self.assertEqual(s.nas_patch(after),after)

    def test_changed_nas_identity_or_retention_is_retained(self):
        original=self.original_fixture()
        for changed in (original.replace(b"'sawdoctor-migration-standby-v1'",b"'unrelated-format'",1),
                        original.replace(s.OLD_PRUNE.encode(),s.OLD_PRUNE.replace('[:-2]','[:-1]').encode(),1)):
            with self.subTest(changed_identity=changed!=original),self.assertRaises(RuntimeError):s.nas_patch(changed)

    def test_source_replacement_is_pinned_and_unrelated_source_is_rejected(self):
        self.assertEqual(hashlib.sha256(NEW).hexdigest(),s.SOURCE_AFTER_SHA)
        self.assertEqual(s.source_candidate(NEW),NEW)
        with self.assertRaisesRegex(RuntimeError,'differs'):s.source_candidate(b'unrelated worker')

    def install_fixture(self,root,original):
        worker=root/'worker';worker.write_bytes(original);worker.chmod(0o700)
        helper=root/'helper';helper.write_bytes(b'reviewed helper fixture')
        base=root/'state';base.mkdir();calls=[]
        stack=contextlib.ExitStack()
        stack.enter_context(patch.multiple(s,WORKER=worker,NAS_HELPER=helper,
            NAS_HELPER_SHA=s.sha(helper.read_bytes()),PLEX_BACKUP=helper,PLEX_BACKUP_SHA=s.sha(helper.read_bytes())))
        stack.enter_context(patch.object(s,'inactive',side_effect=lambda unit:calls.append(unit)))
        stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        return stack,worker,helper,base,calls

    def test_nas_installer_retains_original_worker_modes_units_and_appdata(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);before=self.original_fixture();after=s.nas_patch(before)
            stack,worker,helper,base,calls=self.install_fixture(root,before)
            live=root/'live-app.sqlite';live.write_bytes(b'live data')
            unit=root/'standby.timer';unit.write_bytes(b'original timer')
            with stack:s.install_locked('nas',base,before,after)
            self.assertEqual(worker.read_bytes(),after)
            self.assertEqual(worker.stat().st_mode & 0o777,0o700)
            self.assertEqual((base/'scope-change/worker.before').read_bytes(),before)
            self.assertEqual(live.read_bytes(),b'live data');self.assertEqual(unit.read_bytes(),b'original timer')
            self.assertEqual(calls,['nas-migration-standby.service','nas-migration-standby-install.service'])

    def test_busy_service_or_changed_worker_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            before=self.original_fixture();after=s.nas_patch(before)
            stack,worker,helper,base,calls=self.install_fixture(Path(directory),before)
            with stack,patch.object(s,'inactive',side_effect=RuntimeError('busy')):
                with self.assertRaisesRegex(RuntimeError,'busy'):s.install_locked('nas',base,before,after)
            self.assertEqual(worker.read_bytes(),before)
            self.assertFalse((base/'scope-change').exists())

    def test_source_recovery_record_blocks_scope_change(self):
        with tempfile.TemporaryDirectory() as directory:
            stack,worker,helper,base,calls=self.install_fixture(Path(directory),b'old worker')
            (base/'resume.json').write_text('pending original recovery state')
            with stack,self.assertRaisesRegex(RuntimeError,'recovery is pending'):
                s.install_locked('source',base,b'old worker',b'new worker')
            self.assertEqual(worker.read_bytes(),b'old worker')
            self.assertEqual((base/'resume.json').read_text(),'pending original recovery state')

    def test_completed_update_is_repeatable_without_changing_original_recovery_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            before=self.original_fixture();after=s.nas_patch(before)
            stack,worker,helper,base,calls=self.install_fixture(Path(directory),before)
            with stack:
                s.install_locked('nas',base,before,after)
                saved=(base/'scope-change/worker.before').read_bytes()
                s.install_locked('nas',base,after,after)
            self.assertEqual(worker.read_bytes(),after)
            self.assertEqual((base/'scope-change/worker.before').read_bytes(),saved)

    def test_different_existing_recovery_copy_blocks_update(self):
        with tempfile.TemporaryDirectory() as directory:
            before=self.original_fixture();after=s.nas_patch(before)
            stack,worker,helper,base,calls=self.install_fixture(Path(directory),before)
            folder=base/'scope-change';folder.mkdir();(folder/'worker.before').write_bytes(b'other recovery copy')
            with stack,self.assertRaisesRegex(RuntimeError,'different previous-worker'):
                s.install_locked('nas',base,before,after)
            self.assertEqual(worker.read_bytes(),before)


if __name__=='__main__':unittest.main()
