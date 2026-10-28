import hashlib,io,json,tempfile,unittest,zipfile
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from acquire_institutional import verified_copy,retain_members
class AcquisitionTests(unittest.TestCase):
 def test_full_source_must_match_length_and_published_checksum(self):
  data=b'fixed institution fixture'
  with tempfile.TemporaryDirectory() as d:
   r=verified_copy(io.BytesIO(data),Path(d)/'ok',len(data),hashlib.md5(data).hexdigest());self.assertTrue(r['whole_archive_checksum_verified'])
   with self.assertRaisesRegex(ValueError,'mismatch'):verified_copy(io.BytesIO(data),Path(d)/'bad',len(data),'0'*32)
 def test_larger_than_manifest_is_refused(self):
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaisesRegex(ValueError,'larger'):verified_copy(io.BytesIO(b'abcd'),Path(d)/'bad',2,'0'*32)
 def test_only_explicit_raw_label_pairs_are_retained(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);p=root/'archive.zip'
   with zipfile.ZipFile(p,'w') as z:
    for n in ('gather/attacker_0/logs/attacks.log','gather/intranet_server/logs/audit/audit.log','labels/intranet_server/logs/audit/audit.log'):z.writestr(n,'fixture\n')
    z.writestr('../../escape','bad');z.writestr('unrequested-big.bin','not needed')
   receipts=retain_members(p,root/'selected');self.assertEqual(len(receipts),3);self.assertTrue(all(x['zip_crc_verified'] for x in receipts));self.assertFalse((root/'escape').exists());self.assertFalse((root/'selected/unrequested-big.bin').exists())
if __name__=='__main__':unittest.main()
