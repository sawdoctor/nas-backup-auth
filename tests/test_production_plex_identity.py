"""Plex API identity is processed; raw and processed must match frozen source."""
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('plex_identity_finish',Path(__file__).resolve().parents[1]/'scripts/finish-nas-plex-identity.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class PlexIdentity(unittest.TestCase):
    def setUp(self):
        self.raw='a-raw-source-machine-guid';self.processed='b'*40
        self.prefs=('<Preferences MachineIdentifier="'+self.raw+'" ProcessedMachineIdentifier="'+self.processed+'" PlexOnlineToken="private-token"/>').encode()
        self.evidence=m.identity_fields(self.prefs)
        self.proof={'identitySha256':m.sha(self.raw.encode())}

    def test_processed_api_identity_passes_when_it_is_not_the_raw_identifier(self):
        api=('<MediaContainer machineIdentifier="'+self.processed+'"/>').encode()
        m.validate_identity(self.prefs,self.evidence,self.proof,api)
        self.assertNotEqual(self.raw,self.processed)

    def test_raw_identifier_is_not_accepted_as_the_api_processed_identifier(self):
        api=('<MediaContainer machineIdentifier="'+self.raw+'"/>').encode()
        with self.assertRaisesRegex(RuntimeError,'API processed'):m.validate_identity(self.prefs,self.evidence,self.proof,api)

    def test_new_or_regenerated_processed_identity_cannot_pass_against_frozen_evidence(self):
        changed=self.prefs.replace(self.processed.encode(),b'c'*40)
        with self.assertRaisesRegex(RuntimeError,'Stored Plex identifiers'):m.validate_identity(changed,self.evidence,self.proof)
        with self.assertRaisesRegex(RuntimeError,'API processed'):
            m.validate_identity(self.prefs,self.evidence,self.proof,b'<MediaContainer machineIdentifier="cccccccccccccccccccccccccccccccccccccccc"/>')

    def test_changed_raw_identity_cannot_pass_even_with_original_processed_api_identity(self):
        changed=self.prefs.replace(self.raw.encode(),b'new-server')
        with self.assertRaisesRegex(RuntimeError,'Stored Plex identifiers'):m.validate_identity(changed,self.evidence,self.proof)

    def test_source_hold_identity_is_an_independent_required_binding(self):
        with self.assertRaises(RuntimeError):m.validate_identity(self.prefs,self.evidence,{'identitySha256':'0'*64})

    def test_missing_processed_identifier_is_not_generated_or_accepted(self):
        with self.assertRaisesRegex(RuntimeError,'incomplete'):m.identity_fields(b'<Preferences MachineIdentifier="raw"/>')

    def frozen_archive(self, root, body):
        relative='data/plex-config/Library/Application Support/Plex Media Server/Preferences.xml'
        raw=root/'incoming';raw.mkdir()
        (raw/'SHA256SUMS').write_text(m.sha(self.prefs)+'  ./'+relative+'\n')
        archive=root/'migration/production-handover/frozen/example/export.tar.zst'
        archive.parent.mkdir(parents=True)
        with tarfile.open(archive,'w') as stream:
            member=tarfile.TarInfo('./'+relative);member.size=len(body)
            stream.addfile(member,io.BytesIO(body))
        def parse(line):
            digest,name=line.rstrip('\n').split('  ',1)
            return name.removeprefix('./'),digest
        native=types.SimpleNamespace(PREFS=Path(relative.removeprefix('data/plex-config/')),
            helpers=lambda:{'core':types.SimpleNamespace(parse_checksum=parse)},
            safe=lambda path:None,read=lambda path:path.read_bytes(),
            atomic=lambda path,value:path.write_text(json.dumps(value)))
        state={'raw':str(raw),'proof':dict(self.proof,cutoverId='example',archiveBytes=archive.stat().st_size)}
        return native,state,archive

    def test_original_frozen_preferences_supply_processed_identity_without_extracting_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);native,state,archive=self.frozen_archive(root,self.prefs)
            popen=subprocess.Popen
            with patch.object(m,'BACKUP',root),patch.object(m,'EVIDENCE',root/'evidence.json'),patch.object(m,'say'), \
                    patch.object(m.subprocess,'Popen',side_effect=lambda *args,**kwargs:popen(['cat',str(archive)],**kwargs)):
                evidence=m.source_preferences(native,state)
            self.assertEqual(evidence['processedSha256'],self.evidence['processedSha256'])
            self.assertEqual(list((root/'incoming').iterdir()),[root/'incoming/SHA256SUMS'])
            self.assertNotIn('private-token',(root/'evidence.json').read_text())

    def test_wrong_archive_preferences_fail_before_identity_evidence_is_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);native,state,archive=self.frozen_archive(root,self.prefs.replace(b'b'*40,b'c'*40))
            popen=subprocess.Popen
            with patch.object(m,'BACKUP',root),patch.object(m,'EVIDENCE',root/'evidence.json'),patch.object(m,'say'), \
                    patch.object(m.subprocess,'Popen',side_effect=lambda *args,**kwargs:popen(['cat',str(archive)],**kwargs)):
                with self.assertRaisesRegex(RuntimeError,'verified checksum'):m.source_preferences(native,state)
            self.assertFalse((root/'evidence.json').exists())


if __name__=='__main__':unittest.main()
