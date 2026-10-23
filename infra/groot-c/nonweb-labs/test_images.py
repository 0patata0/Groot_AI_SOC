#!/usr/bin/env python3
"""Offline unit contracts. Native build/service checks are separate evidence."""
import importlib.util
import json
import lzma
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parent
def load(name):
 spec=importlib.util.spec_from_file_location('nonweb_test_'+name,ROOT/(name+'.py'))
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
p=load('prepare');i=load('images')

class Preparation(unittest.TestCase):
 def test_debian_versions(self):
  for a,b in [('1.0~rc1','1.0'),('5:5.0.7-2','5:5.0.7-2ubuntu0.1'),('1.0-9','1.0-10'),('1:9','2:1'),('1.0','1.0+1')]:
   self.assertLess(p.version_compare(a,b),0);self.assertGreater(p.version_compare(b,a),0)
  self.assertEqual(p.version_compare('1.001-0','1.1'),0)
 def test_control_duplicate(self):
  with self.assertRaisesRegex(ValueError,'duplicate'):p.control('Package: a\nPackage: b')
 def test_xz_concatenated(self):
  self.assertEqual(p.unpack_xz(lzma.compress(b'a')+b'\0'*4+lzma.compress(b'')+lzma.compress(b'b')),b'ab')
 def test_xz_invalid(self):
  for raw in (lzma.compress(b'a')[:-1],lzma.compress(b'a')+b'\0',lzma.compress(b'a')+b'bad'):
   with self.assertRaises((ValueError,lzma.LZMAError)):p.unpack_xz(raw)
 def test_dependency_expression(self):
  self.assertEqual(p.parse_dependency('libc6:any (>= 2.31)'),('libc6','>=','2.31'))
  with self.assertRaises(ValueError):p.parse_dependency('libc6;touch /tmp/x')
 def test_closure_pins(self):
  rows=[{'Package':'redis','Version':'1','Depends':'lib (>= 2) | other'}, {'Package':'redis','Version':'2'}, {'Package':'lib','Version':'2'}, {'Package':'lib','Version':'3'}]
  result=p.resolve({(r['Package'],r['Version']):r for r in rows},['redis'],{'redis':'1'})
  self.assertEqual([(r['Package'],r['Version']) for r in result],[('lib','3'),('redis','1')])
 def test_virtual_dependency(self):
  row={'Package':'real','Version':'1','Provides':'virtual (= 2)'}
  self.assertEqual(p.resolve({('real','1'):row},['virtual (>= 2)']),[row])
 def test_unsatisfied_closed(self):
  with self.assertRaisesRegex(ValueError,'unsatisfied'):p.resolve({},['not-present'])
 def test_input_symlink_and_hardlink(self):
  with tempfile.TemporaryDirectory() as work:
   path=Path(work)/'file';path.write_bytes(b'x');alias=Path(work)/'link';alias.symlink_to(path)
   with self.assertRaises(ValueError):p.read(alias)
   alias.unlink();alias.hardlink_to(path)
   with self.assertRaises(ValueError):p.read(path)
 def test_signature_failure(self):
  with mock.patch.object(p.subprocess,'run',return_value=subprocess.CompletedProcess([],1,b'',b'failure')):
   with self.assertRaisesRegex(ValueError,'signature_invalid'):p.verify_signature('/usr/bin/gpgv',b'key',b'signed')
 def test_signature_missing_validsig(self):
  with mock.patch.object(p.subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'GOODSIG',b'')):
   with self.assertRaisesRegex(ValueError,'signature_invalid'):p.verify_signature('/usr/bin/gpgv',b'key',b'signed',b'body')
 def test_historical_armored_key_conversion(self):
  def run(command,**kwargs):
   key=Path(command[command.index('--keyring')+1]).read_bytes()
   self.assertEqual(key,b'public-key-packet')
   return subprocess.CompletedProcess(command,0,b'[GNUPG:] VALIDSIG fingerprint\n',b'')
  armor=b'-----BEGIN PGP PUBLIC KEY BLOCK-----\n\ncHVibGljLWtleS1wYWNrZXQ=\n=crc1\n-----END PGP PUBLIC KEY BLOCK-----\n'
  with mock.patch.object(p.subprocess,'run',side_effect=run):p.verify_signature('/usr/bin/gpgv',armor,b'signature',b'data')
 def test_signed_index_hash_rejection(self):
  source={'ubuntu_suites':['focal'],'ubuntu_components':['main']}
  with tempfile.TemporaryDirectory() as work:
   root=Path(work);(root/'focal-main-Packages.xz').write_bytes(lzma.compress(b''))
   release='Origin: Ubuntu\nSuite: focal\nCodename: focal\nSHA256:\n '+('a'*64)+' 1 main/binary-amd64/Packages.xz\n'
   with self.assertRaisesRegex(ValueError,'signed_index_hash'):p.indexes(root,source,{'focal':release})
 def test_exact_sources(self):
  source=json.loads((ROOT/'sources.json').read_text())
  self.assertEqual(source['redis']['package_version'],'5:5.0.7-2')
  self.assertEqual(source['samba']['version'],'4.6.3')
  self.assertRegex(source['base_image'],r'^ubuntu@sha256:[0-9a-f]{64}$')

class Images(unittest.TestCase):
 def test_no_tags_for_export(self):
  source=(ROOT/'images.py').read_text()
  self.assertIn("['image','save','--output',str(target),row['image_id']]",source)
  self.assertIn("'--network=none'",source)
 def test_fixed_id(self):
  with self.assertRaisesRegex(ValueError,'fixed_image'):i.config('redis:latest')
 def test_anonymous_volumes_rejected(self):
  ident='sha256:'+'a'*64
  row={'Id':ident,'Os':'linux','Architecture':'amd64','Config':{'Volumes':{'/data':{}}}}
  with mock.patch.object(i,'docker',return_value=json.dumps([row]).encode()):
   with self.assertRaisesRegex(ValueError,'volumes'):i.config(ident)
 def test_wrong_platform_rejected(self):
  ident='sha256:'+'a'*64
  row={'Id':ident,'Os':'linux','Architecture':'arm64','Config':{}}
  with mock.patch.object(i,'docker',return_value=json.dumps([row]).encode()):
   with self.assertRaisesRegex(ValueError,'identity'):i.config(ident)
 def test_untrusted_output_parent(self):
  with tempfile.TemporaryDirectory() as work:
   with self.assertRaisesRegex(ValueError,'root_owned_path'):i.trusted_directory(Path(work))
 def test_terminal_tag_and_uid(self):
  lib=(ROOT/'terminal-lib.sh').read_text()
  for uid,tag,success in [(10001,'a'*64,True),(0,'a'*64,False),(10001,'a'*63,False),(10001,'A'*64,False),(10001,'x;touch /tmp/x',False)]:
   command=lib+'\nid(){ printf "%s\\n" '+str(uid)+'; }; terminal_input "$1"'
   run=subprocess.run(['/bin/sh','-c',command,'test',tag],capture_output=True)
   self.assertEqual(run.returncode==0,success)
 def test_terminal_signal_membership(self):
  lib=(ROOT/'terminal-lib.sh').read_text()
  for row,sid,start,success in [('41 40 123','40','123',True),('40 40 123','40','123',True),
                               ('40 99 123','40','123',False),('41 40 124','40','123',False),
                               ('41 140 123','40','123',False),('41 40 1234','40','123',False),
                               ('','40','123',False)]:
   command=lib+'\nterminal_proc(){ printf "%s\\n" "$ROW"; }; terminal_member 41 "$1" "$2"'
   run=subprocess.run(['/bin/sh','-c',command,'test',sid,start],capture_output=True,env={'ROW':row})
   self.assertEqual(run.returncode==0,success)
 def test_shell_syntax(self):
  for file in [*ROOT.glob('terminal-*.sh'),*ROOT.glob('redis/*.sh'),*ROOT.glob('samba/*.sh')]:
   self.assertEqual(subprocess.run(['/bin/sh','-n',str(file)],capture_output=True).returncode,0)

if __name__=='__main__':unittest.main()
