import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
def load(name):
 s=importlib.util.spec_from_file_location(name,ROOT/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
P=load('pcap_source_candidates');A=load('verified_archive')

class FlowTests(unittest.TestCase):
 def row(self,**kw):
  r=dict(zip(P.FIELDS,['2011/08/15 16:43:26.000000','0.1','tcp','147.32.84.165','1234',' ->','147.32.80.9','53','CON','0','0','2','200','100','flow=From-Botnet-V46-TCP-CC1-HTTP-Not-Encrypted']));r.update(kw);return r
 def test_unknown_not_benign(self):
  for label in ['flow=Background','flow=To-Botnet-V1','flow=To-Normal-V1']:
   self.assertNotEqual(P.category(label),'provider_normal_origin');self.assertNotEqual(P.category(label),'provider_botnet_origin')
 def test_uncertain_server(self):
  self.assertEqual(P.category('flow=From-Normal-V46-UDP-CVUT-DNS-Server'),'provider_normal_server_low_confidence')
 def test_direction_unspecified(self):
  self.assertEqual(P.category('flow=Normal-V46-HTTP-windowsupdate'),'provider_normal_activity_direction_unspecified')
 def test_non_ip_protocols(self):
  self.assertIsNone(P.validate_row(self.row(Proto='arp')))
  for proto in ['arp','rarp','ipx/spx']:
   self.assertIsNone(P.validate_row(self.row(Proto=proto,SrcAddr='00:15:17:2c:e5:2d',DstAddr='ff:ff:ff:ff:ff:ff')))
 def test_bad_numbers(self):
  for bad in ['NaN','Infinity','-1','abc']:
   self.assertIsNotNone(P.validate_row(self.row(Dur=bad)))
  self.assertIsNotNone(P.validate_row(self.row(SrcBytes='201')))
 def test_no_label_address_or_name_in_input(self):
  o,r=P.transformed('ctu13-05',2,self.row());s=json.dumps(o)
  for v in ['147.32.','Botnet','Normal','CC1','Virut','Label']:
   self.assertNotIn(v,s)
  self.assertEqual(r['category'],'provider_botnet_origin');self.assertEqual(r['source_line'],2)
  self.assertEqual(o['source_timezone'],'unverified');self.assertNotIn('+09:',o['observed_at_source'])
 def test_pseudonyms_preserve_cross_case_links(self):
  a,_=P.transformed('ctu13-05',2,self.row());b,_=P.transformed('ctu13-11',3,self.row())
  self.assertEqual(a['source_endpoint'],b['source_endpoint']);self.assertNotEqual(a['id'],b['id'])
 def test_label_changes_do_not_change_observation(self):
  a,_=P.transformed('ctu13-05',2,self.row());b,_=P.transformed('ctu13-05',2,self.row(Label='flow=Background'))
  self.assertEqual(a,b)

class ArchiveTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.d=Path(self.t.name)
 def pack(self):
  p=self.d/'input';p.write_bytes(b'unchanged bytes\x00\xff');out=self.d/'cleaned.tar.gz'
  r=A.build(out,{'datasets/test/file':p},'cleaned');return out,r
 def test_lossless_and_fresh_destination(self):
  out,r=self.pack();A.verify_extract(out,r,self.d/'restore')
  self.assertEqual((self.d/'restore/datasets/test/file').read_bytes(),b'unchanged bytes\x00\xff')
  with self.assertRaises(ValueError):A.verify_extract(out,r,self.d/'restore')
 def test_tamper(self):
  out,r=self.pack();out.write_bytes(out.read_bytes()+b'changed')
  with self.assertRaises(ValueError):A.verify_extract(out,r,self.d/'restore')
 def test_unsafe_names(self):
  for name in ['/absolute','../escape','a/../b','a//b','./a','a\\b','']:
   with self.assertRaises(ValueError):A.safe_name(name)
 def test_extra_member(self):
  out,r=self.pack();r['members'].append('extra')
  with self.assertRaises(ValueError):A.verify_extract(out,r,self.d/'restore')
 def test_symlink_source(self):
  p=self.d/'file';p.write_text('x');s=self.d/'link';s.symlink_to(p)
  with self.assertRaises(ValueError):A.build(self.d/'x.gz',{'data':s},'cleaned')
 def test_malicious_member_types_and_duplicates(self):
  for kind in ['symlink','hardlink','device','duplicate']:
   out=self.d/(kind+'.gz')
   with tarfile.open(out,'w:gz') as tar:
    m=tarfile.TarInfo('data')
    if kind=='symlink':m.type=tarfile.SYMTYPE;m.linkname='/tmp/outside'
    if kind=='hardlink':m.type=tarfile.LNKTYPE;m.linkname='../outside'
    if kind=='device':m.type=tarfile.CHRTYPE
    tar.addfile(m)
    if kind=='duplicate':tar.addfile(m)
   r={'sha256':A.digest(out),'members':['data'],'manifest_sha256':'unused','kind':'cleaned'}
   with self.assertRaises(ValueError):A.verify_extract(out,r,self.d/(kind+'-restore'))

if __name__=='__main__':unittest.main()
