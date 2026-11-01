import hashlib
import json
import sys
import tempfile
import unittest
import zipfile
from collections import Counter
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from collect_soc_event_sources import pinned_path,lfs_pointer
from prepare_soc_event_candidates import blocks,sanitize,members,prepare,REVIEWED_TRANSFER_SOURCES
from collect_defensive_sources import select_path


class AcquisitionTests(unittest.TestCase):
    def test_pins_data_reference_not_arbitrary_host(self):
        self.assertEqual(pinned_path('https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/x.zip','OTRF/Security-Datasets'),'datasets/x.zip')
        self.assertIsNone(pinned_path('https://attacker.invalid/datasets/x.zip','OTRF/Security-Datasets'))
        self.assertIsNone(pinned_path('https://raw.githubusercontent.com/OTHER/repo/master/datasets/x.zip','OTRF/Security-Datasets'))
        with self.assertRaises(ValueError):pinned_path('/datasets/../credentials','OTRF/Security-Datasets')

    def test_lfs_pinned_hash_and_invalid_pointer(self):
        h='a'*64
        self.assertEqual(lfs_pointer(('version https://git-lfs.github.com/spec/v1\noid sha256:'+h+'\nsize 42\n').encode()),{'sha256':h,'bytes':42})
        self.assertIsNone(lfs_pointer(b'normal log'))
        with self.assertRaises(ValueError):lfs_pointer(b'version https://git-lfs.github.com/spec/v1\nbad')

    def test_metadata_selector_does_not_collect_source_commands(self):
        self.assertTrue(select_path('splunk_attack','datasets/a.yml'))
        self.assertFalse(select_path('splunk_attack','bin/replay.py'))
        self.assertFalse(select_path('otrf','datasets/a.ps1'))
        self.assertTrue(select_path('cti_realm','domains/cti_realm/tasks/cti_realm_50/cti_realm_50.yaml'))


class CleaningTests(unittest.TestCase):
    def test_ambiguous_license_is_not_a_transferred_source(self):
        self.assertNotIn('otrf',REVIEWED_TRANSFER_SOURCES)
        self.assertIn('splunk_attack',REVIEWED_TRANSFER_SOURCES)

    def test_labels_and_credentials_not_observations(self):
        c=Counter();v=sanitize({'event':'audit','IncidentGrade':'TruePositive','nested':{'password':'secret'},'msg':'api_key=abc action=read'},c)
        self.assertNotIn('IncidentGrade',v);self.assertEqual(v['nested']['password'],'[REDACTED]');self.assertNotIn('abc',v['msg'])
        self.assertEqual(c['annotation_fields'],1)

    def test_complete_jsonl_coordinates(self):
        b=blocks(b'{"event":1}\n\n{"event":2}\n',Counter())
        self.assertEqual([x['locator']['line']for x in b],[1,3]);self.assertEqual(len(b),2)

    def test_multiline_text_is_not_falsely_called_events(self):
        s='<Event>\n  text\n</Event>\n';b=blocks(s.encode(),Counter())
        self.assertEqual(b[0]['format'],'text_block_not_event');self.assertEqual(b[0]['observation'],s)

    def test_never_silently_truncate_large_or_bad_records(self):
        with self.assertRaises(ValueError):blocks(json.dumps({'message':'x'*13000}).encode(),Counter())
        with self.assertRaises(ValueError):blocks(b'{"a":1}\nBROKEN\n',Counter())

    def test_zip_traversal_and_duplicate_rejected(self):
        with tempfile.TemporaryDirectory()as d:
            p=Path(d)/'a.zip'
            with zipfile.ZipFile(p,'w')as z:z.writestr('../a.log','x')
            with self.assertRaises(ValueError):members(p)

    def test_only_text_members(self):
        with tempfile.TemporaryDirectory()as d:
            p=Path(d)/'a.zip'
            with zipfile.ZipFile(p,'w')as z:z.writestr('input.pcap',b'\x00\x01')
            with self.assertRaisesRegex(ValueError,'no_supported_text_members'):members(p)

    def test_shared_provider_and_file_stay_one_partition(self):
        with tempfile.TemporaryDirectory()as d:
            root=Path(d)/'source';root.mkdir();out=Path(d)/'clean';data=b'{"event":"shared"}\n';h=hashlib.sha256(data).hexdigest()
            cases=[{'id':x,'provider_id':'same','source':'splunk_attack','files':['x.log']}for x in ['a','b']]
            (root/'event-plan.json').write_text(json.dumps({'cases':cases,'held':[]}))
            (root/'x.log').write_bytes(data)
            (root/'event-acquisition.json').write_text(json.dumps({'files':[{'source':'splunk_attack','path':'x.log','stored_path':'x.log','sha256':h,'bytes':len(data),'case_ids':['a','b']}],'errors':[],'bytes':len(data)}))
            for k in ['splunk_attack','otrf']:
                p=root/'raw'/k;p.mkdir(parents=True);(p/'LICENSE').write_text('fixture')
            r=prepare(root,out)
            self.assertEqual(r['known_file_identity_components'],1);self.assertEqual(sum(r['observation_blocks'].values()),1)
            cs=[json.loads(x)for x in (out/'case-lineage.jsonl').read_text().splitlines()]
            self.assertEqual(cs[0]['partition'],cs[1]['partition']);self.assertFalse(r['ready_for_gpu_training'])


if __name__=='__main__':unittest.main()
