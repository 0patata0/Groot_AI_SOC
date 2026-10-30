import contextlib
import csv
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from audit_beth_splits import BASE, EXTRA, audit


class BethSplitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def row(self, **changes):
        row = {k:'0' for k in BASE | EXTRA}
        row.update(timestamp='1.000001',hostName='fixture-host',args='[]',sus='0',evil='0')
        row.update(changes)
        return row

    def source(self, part, rows, *, extra=False, columns=None, text=None):
        columns = columns or sorted(BASE | (EXTRA if extra else set())) + ['sus','evil']
        if text is None:
            s = io.StringIO(newline='')
            w = csv.writer(s)
            w.writerow(columns)
            for row in rows:
                w.writerow([row[k] for k in columns])
            text = s.getvalue()
        path = self.root / (part+'.zip')
        raw = text.encode()
        with zipfile.ZipFile(path,'w',zipfile.ZIP_DEFLATED) as z:
            z.writestr(part+'.csv',raw)
        with zipfile.ZipFile(path) as z:
            crc = z.infolist()[0].CRC
        return {'partition':part,'file':path.name,'format':'zip','member':part+'.csv',
                'download_bytes':path.stat().st_size,'download_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                'raw_bytes':len(raw),'provider_crc32':crc}

    def run_audit(self, *items):
        with contextlib.redirect_stdout(io.StringIO()):
            return audit({'schema':1,'source':'BETH','version':3,'files':list(items)},self.root,self.root)

    def test_labels_do_not_hide_overlap_or_conflicts(self):
        a = self.source('train',[self.row(),self.row()])
        b = self.source('test',[self.row(evil='1',sus='1')])
        r = self.run_audit(a,b)
        p = r['pairs'][0]['full_features']
        self.assertEqual((p['unique_shared_signatures'],p['left_rows'],p['right_rows'],
                          p['matched_multiplicity'],p['conflicting_label_signatures']),(1,2,1,1,1))
        self.assertEqual(r['files']['train']['within_file']['full_features']['repeated_rows_beyond_first'],1)
        self.assertEqual(list(self.root.glob('beth-digests-*')),[])

    def test_projection_is_not_full_feature_equality(self):
        a = self.source('train',[self.row(threadId='10'),self.row(threadId='11')],extra=True)
        b = self.source('reference',[self.row()])
        r = self.run_audit(a,b)
        self.assertEqual(r['pairs'][0]['full_features']['unique_shared_signatures'],0)
        self.assertEqual(r['pairs'][0]['shared_projection']['left_rows'],2)
        self.assertEqual(r['files']['train']['projection_omits'],sorted(EXTRA))

    def test_empty_and_zero_stay_distinct_and_quoted_rows_parse(self):
        a = self.source('train',[self.row(args='a,b\nc',returnValue='')])
        b = self.source('validation',[self.row(args='a,b\nc',returnValue='0')])
        r = self.run_audit(a,b)
        self.assertEqual(r['pairs'][0]['shared_projection']['unique_shared_signatures'],0)
        self.assertEqual(r['files']['train']['empty_fields'],{'returnValue':1})

    def test_hash_tampering_rejected(self):
        a = self.source('train',[self.row()]); b = self.source('test',[self.row()])
        a['download_sha256'] = '0'*64
        with self.assertRaisesRegex(ValueError,'hash/size'):
            self.run_audit(a,b)

    def test_duplicate_columns_and_short_rows_rejected(self):
        b = self.source('test',[self.row()])
        a = self.source('train',[self.row()],columns=sorted(BASE)+['sus','evil','evil'])
        with self.assertRaisesRegex(ValueError,'Duplicate CSV'):
            self.run_audit(a,b)
        a = self.source('train',[],text=','.join(sorted(BASE)+['sus','evil'])+'\n0,1\n')
        with self.assertRaisesRegex(ValueError,'row width'):
            self.run_audit(a,b)
        self.assertEqual(list(self.root.glob('beth-digests-*')),[])

    def test_invalid_labels_and_times_rejected(self):
        b = self.source('test',[self.row()])
        for changes in ({'sus':'2'},{'timestamp':'NaN'},{'timestamp':'-1'},{'hostName':''}):
            a = self.source('train',[self.row(**changes)])
            with self.assertRaises(ValueError):
                self.run_audit(a,b)

    def test_empty_csv_and_duplicate_partitions_rejected(self):
        a = self.source('train',[]); b = self.source('test',[self.row()])
        with self.assertRaisesRegex(ValueError,'Empty or incomplete'):
            self.run_audit(a,b)
        with self.assertRaisesRegex(ValueError,'partitions'):
            self.run_audit(b,b)

    def test_zip_crc_and_extra_members_rejected(self):
        a = self.source('train',[self.row()]); b = self.source('test',[self.row()])
        a['provider_crc32'] ^= 1
        with self.assertRaisesRegex(ValueError,'CRC metadata'):
            self.run_audit(a,b)
        a = self.source('train',[self.row()])
        path = self.root/a['file']
        with zipfile.ZipFile(path,'a') as z:
            z.writestr('../unwanted','never extracted')
        a.update(download_bytes=path.stat().st_size,download_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        with self.assertRaisesRegex(ValueError,'Unexpected ZIP'):
            self.run_audit(a,b)
        self.assertFalse((self.root.parent/'unwanted').exists())

    def test_output_exists_refused_before_input_access(self):
        output = self.root/'report.json';output.write_text('preserve')
        script = Path(__file__).resolve().parents[1]/'audit_beth_splits.py'
        result = subprocess.run([sys.executable,'-B',str(script),'--manifest','absent',
                                 '--directory',str(self.root),'--scratch',str(self.root),
                                 '--output',str(output)],capture_output=True,text=True)
        self.assertEqual(result.returncode,2)
        self.assertIn('Output already exists',result.stderr)
        self.assertEqual(output.read_text(),'preserve')


if __name__ == '__main__':
    unittest.main()
