"""Network-free range, integrity and archive-change rejection tests."""
import io,unittest,zipfile
from unittest.mock import patch
from remote_zip import RemoteZip
class Response(io.BytesIO):
 status=206
 def __init__(self,data,start,end,total,etag='same'):
  super().__init__(data);self.headers={'Content-Range':f'bytes {start}-{end}/{total}','ETag':etag}
class RangeTests(unittest.TestCase):
 def fixture(self):
  h=io.BytesIO()
  with zipfile.ZipFile(h,'w',zipfile.ZIP_DEFLATED) as z:z.writestr('labels/auth.log','fixed fixture\n'*50)
  return h.getvalue()
 def reader(self,data,wrong_status=False,changed=False):
  calls=[]
  def open_(req,timeout):
   a,b=map(int,req.headers['Range'][6:].split('-'));r=Response(data[a:b+1],a,b,len(data),'changed' if changed and calls else 'same');calls.append((a,b));r.status=200 if wrong_status else 206;return r
  return RemoteZip('https://example.test/public.zip',len(data),opener=open_,chunk=64,max_transfer=2048)
 def test_reads_zip_and_verifies_member_crc_without_whole_download_claim(self):
  data=self.fixture();r=self.reader(data)
  with zipfile.ZipFile(r) as z:self.assertEqual(z.read('labels/auth.log'),b'fixed fixture\n'*50)
  self.assertLessEqual(r.transferred,len(data))
 def test_ignored_range_never_triggers_full_download(self):
  with self.assertRaisesRegex(ValueError,'ignored'):self.reader(self.fixture(),wrong_status=True).read(1)
 def test_etag_change_is_rejected(self):
  r=self.reader(self.fixture(),changed=True);r.read(1);r.seek(64)
  with self.assertRaisesRegex(ValueError,'changed'):r.read(1)
 def test_partial_reads_are_assembled_without_accepting_truncated_content(self):
  data=self.fixture()
  class Partial(Response):
   def read(self,n=-1):return super().read(min(n,7))
  def opener(req,timeout):
   a,b=map(int,req.headers['Range'][6:].split('-'));return Partial(data[a:b+1],a,b,len(data))
  r=RemoteZip('https://example.test/public.zip',len(data),opener=opener,chunk=64,max_transfer=2048)
  with zipfile.ZipFile(r) as z:self.assertEqual(z.read('labels/auth.log'),b'fixed fixture\n'*50)
 def test_truncated_transfer_retries_same_range_and_never_uses_partial_bytes(self):
  data=self.fixture();attempts=[]
  def opener(req,timeout):
   a,b=map(int,req.headers['Range'][6:].split('-'));attempts.append((a,b));return Response(data[a:a+3] if len(attempts)==1 else data[a:b+1],a,b,len(data))
  r=RemoteZip('https://example.test/public.zip',len(data),opener=opener,chunk=64,max_transfer=2048)
  with patch('remote_zip.time.sleep'):self.assertEqual(r.read(16),data[:16])
  self.assertEqual(attempts[0],attempts[1]);self.assertEqual(r.transferred,67)
 def test_budget_and_invalid_seek_are_rejected(self):
  r=self.reader(self.fixture());r.max_transfer=2
  with self.assertRaisesRegex(ValueError,'budget'):r.read(1)
  with self.assertRaisesRegex(ValueError,'seek'):r.seek(-1)
if __name__=='__main__':unittest.main()
