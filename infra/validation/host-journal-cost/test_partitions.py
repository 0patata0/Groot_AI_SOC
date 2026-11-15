"""Every native-selected source is merged; scope, fd safety and changes fail closed."""
from pathlib import Path
import copy,importlib.util,json,os,stat,sys,types,unittest
from unittest.mock import patch
ROOT=Path(os.environ['SOC_PARTITION_ROOT']).resolve();BASE=Path(os.environ['SOC_PARTITION_BASE']).resolve();sys.path.insert(0,str(ROOT/'infra/mcp'))
from test_diagnostic_journal_native import FakeReader,event
from test_diagnostic_journal import d,h,j,args,NOW

def load(name,root):
 spec=importlib.util.spec_from_file_location(name,root/'infra/mcp/diagnostic_journal_native.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);m.core=d;m.journal=j;return m
n=load('partition_candidate',ROOT);old=load('partition_parent',BASE)

class Reader(FakeReader):
 def __init__(self,rows,close=None):super().__init__(copy.deepcopy(rows));self.cleanup=close;self.close_count=0
 def add_match(self,**fields):
  if 'PRIORITY' in fields and self.priorities is None:self.priorities=[]
  super().add_match(**fields)
 def close(self):
  self.close_count+=1
  if self.cleanup:self.cleanup();self.cleanup=None
  super().close()

class World:
 def __init__(self,parts,*,change=None,existing=None,ambiguous=False):
  self.parts=parts;self.change=change;self.existing=existing or {};self.active=dict(self.existing);self.fd_data={};self.opens=0;self.next_fd=10;self.readers=[];self.ambiguous=ambiguous
 def snapshot(self):return dict(self.active)
 def __call__(self,*,system_only=False,source_fd=None):
  if source_fd is not None:
   reader=Reader(self.fd_data[source_fd]);self.readers.append(reader);return reader
  parts=self.change if self.change is not None and self.opens else self.parts;self.opens+=1;owned=[]
  for identity,rows in parts:
   fd=self.next_fd;self.next_fd+=1;owned.append(fd);self.fd_data[fd]=rows
   if not self.ambiguous:self.active[fd]=identity
  rows=sorted([r for _,values in parts for r in values],key=lambda r:r['stamp'],reverse=True)
  def close():
   for fd in owned:self.active.pop(fd,None)
  reader=Reader(rows,close);self.readers.append(reader);return reader

class Partitions(unittest.TestCase):
 def setUp(self):
  for k,v in (('_history',h),('_journal',j)):
   c=patch.object(d,k,v);c.start();self.addCleanup(c.stop)
 def group(self,world,limit=5):
  with patch.object(n,'journal_fds',side_effect=world.snapshot):
   return n.host_text_group((NOW-3600)*1000000,NOW*1000000,limit,range(4,7),n.fixed_literals(),world)
 def test_every_partition_contributes_actual_rows(self):
  w=World([((1,i),[event(at=NOW-100-i,priority=b'6',unit='source'+str(i)+'.service',cursor=str(i))]) for i in range(4)])
  rows,more=self.group(w);self.assertEqual({x['source_units'][0] for x in rows},{'source'+str(i)+'.service' for i in range(4)});self.assertFalse(more);self.assertEqual(w.active,{});self.assertTrue(all(x.close_count==1 for x in w.readers))
 def test_global_tail_and_has_more_not_per_file_tail(self):
  parts=[((1,i),[event(at=NOW-100-i*10-z,priority=b'6',cursor=str(i)+'-'+str(z)) for z in range(10)]) for i in range(3)]
  rows,more=self.group(World(parts),3);self.assertEqual(len(rows),4);self.assertTrue(more)
  self.assertEqual({r['at_kst'] for r in rows},{h.shown((NOW-100-z)*1000000) for z in range(4)})
 def test_dedup_uses_exact_cursor_and_conflict_is_not_hidden(self):
  a=event(priority=b'6');w=World([((1,1),[a]),((1,2),[copy.deepcopy(a)])]);rows,more=self.group(w);self.assertEqual(len(rows),1);self.assertFalse(more)
  b=copy.deepcopy(a);b['fields']['MESSAGE']=b'RuntimeError: different'
  w=World([((1,1),[a]),((1,2),[b])])
  with self.assertRaisesRegex(ValueError,'journal_cursor_conflict'):self.group(w)
  self.assertEqual(w.active,{})
 def test_conflict_is_detected_even_after_old_row_trimmed(self):
  a=event(at=NOW-900,priority=b'6',cursor='old');b=copy.deepcopy(a);b['fields']['MESSAGE']=b'RuntimeError: changed'
  parts=[((1,1),[a]),((1,2),[event(at=NOW-100-i,priority=b'6',cursor=str(i)) for i in range(5)]),((1,3),[b])]
  with self.assertRaisesRegex(ValueError,'journal_cursor_conflict'):self.group(World(parts),2)
 def test_rotation_or_vacuum_is_unavailable_not_zero(self):
  a=event(priority=b'6');w=World([((1,1),[a])],change=[((1,2),[a])])
  with self.assertRaisesRegex(ValueError,'generation_changed'):self.group(w)
  self.assertEqual(w.active,{})
 def test_missing_source_fd_before_read_is_rejected(self):
  w=World([((1,1),[event(priority=b'6')])]);calls=[0]
  def snapshot():
   calls[0]+=1
   if calls[0]>=3:return {}
   return w.snapshot()
  with patch.object(n,'journal_fds',side_effect=snapshot),self.assertRaisesRegex(ValueError,'source_changed'):
   n.host_text_group((NOW-3600)*1000000,NOW*1000000,5,range(4,7),n.fixed_literals(),w)
  self.assertEqual(w.active,{})
 def test_capacity_bound_never_trims_unread_sources(self):
  w=World([((1,1),[]),((1,2),[])])
  with patch.object(n,'MAX_HOST_JOURNAL_FILES',1),self.assertRaisesRegex(ValueError,'source_bound'):self.group(w)
  self.assertEqual(w.active,{})
 def test_embedded_ambiguous_fd_source_keeps_original_full_reader(self):
  w=World([((1,1),[event(priority=b'6')])],existing={5:(2,2)})
  rows,more=self.group(w);self.assertEqual(len(rows),1);self.assertFalse(more);self.assertEqual(w.active,{5:(2,2)});self.assertEqual(w.opens,1)
 def test_non_fd_test_reader_and_empty_source_keep_original_behavior(self):
  for rows in ([],[event(priority=b'6')]):
   w=World([((1,1),rows)],ambiguous=True);result,_=self.group(w);self.assertEqual(len(result),len(rows));self.assertEqual(w.opens,1)
 def test_masking_and_priority_predicate_unchanged(self):
  rows=[event(priority=b'6',message=b'RuntimeError token=DO_NOT_EXPORT',cursor='a'),event(priority=b'7',cursor='debug'),event(priority=b'6',message=b'ordinary',cursor='normal')]
  out,_=self.group(World([((1,1),rows)]));self.assertEqual(len(out),1);self.assertNotIn(b'DO_NOT_EXPORT',d.encode(out))
 def test_whole_worker_packet_matches_original_single_source_oracle(self):
  rows=[event(at=NOW-100-i,priority=str(i%8).encode(),message=b'RuntimeError' if i%2 else b'normal',cursor=str(i)) for i in range(90)];parts=[((1,1),rows[:30]),((1,2),rows[30:60]),((1,3),rows[60:])];world=World(parts)
  value=dict(args(),target='b:systemd',limit=5)
  def one(**kw):return Reader(rows)
  parent=old.worker({'value':value,'host':'b'},now=NOW,factory=one)
  with patch.object(n,'journal_fds',side_effect=world.snapshot):candidate=n.worker({'value':value,'host':'b'},now=NOW,factory=world)
  self.assertEqual(candidate,parent);n.checked_packet(d.encode(candidate),value,'b',NOW);self.assertEqual(world.active,{})
 def test_new_fd_identity_and_slot_reuse_are_distinguished(self):
  self.assertEqual(n.opened_since({3:(1,1)},{3:(1,2),4:(1,1)}),{3:(1,2),4:(1,1)})
 def test_factory_fd_clone_requires_root_safe_system_journal(self):
  seen=[];binding=types.SimpleNamespace(__version__='235',LOCAL_ONLY=1,SYSTEM_ONLY=4,Reader=lambda **kw:seen.append(kw));meta=types.SimpleNamespace(st_mode=stat.S_IFREG|0o640,st_uid=0,st_nlink=1)
  with patch.dict(sys.modules,{'systemd':types.SimpleNamespace(journal=binding)}),patch.object(n.os,'fstat',return_value=meta),patch.object(n.os,'readlink',return_value='/var/log/journal/local/system.journal'):
   n.reader_factory(system_only=True,source_fd=31)
   for kw in ({'source_fd':31},{'system_only':True,'source_fd':2},{'system_only':True,'source_fd':'31'}):
    with self.assertRaises(ValueError):n.reader_factory(**kw)
  self.assertEqual(seen,[{'flags':0,'files':['/proc/self/fd/31']}])
 def test_unsafe_fd_paths_modes_owner_and_links_do_not_create_reader(self):
  binding=types.SimpleNamespace(__version__='235',LOCAL_ONLY=1,SYSTEM_ONLY=4,Reader=lambda **kw:self.fail('unsafe reader opened'))
  for path,mode,uid,links in [('/tmp/system.journal',0o640,0,1),('/var/log/journal/local/user.journal',0o640,0,1),('/var/log/journal/local/system.journal',0o660,0,1),('/var/log/journal/local/system.journal',0o640,1000,1),('/var/log/journal/local/system.journal',0o640,0,2)]:
   meta=types.SimpleNamespace(st_mode=stat.S_IFREG|mode,st_uid=uid,st_nlink=links)
   with patch.dict(sys.modules,{'systemd':types.SimpleNamespace(journal=binding)}),patch.object(n.os,'fstat',return_value=meta),patch.object(n.os,'readlink',return_value=path),self.assertRaises(ValueError):n.reader_factory(system_only=True,source_fd=31)
 def test_worker_input_cannot_choose_private_fd_or_files(self):
  for extra in ({'source_fd':31},{'files':['/etc/shadow']},{'source_paths':['/var/log/journal']}):
   value=dict(args(),target='b:systemd',**extra)
   with patch.object(n,'journal_fds',side_effect=AssertionError('reached source')),self.assertRaises(ValueError):n.worker({'value':value,'host':'b'},now=NOW)
  with self.assertRaises(ValueError):n.worker({'value':dict(args(),target='b:systemd'),'host':'b','source_fd':31},now=NOW)
 def test_fd_inventory_skips_only_closed_and_non_journal_descriptors(self):
  def meta(fd):
   if fd==19:raise OSError(9,'closed')
   return types.SimpleNamespace(st_mode=stat.S_IFREG,st_dev=1,st_ino=fd)
  with patch.object(n.os,'listdir',return_value=['17','18','19']),patch.object(n.os,'fstat',side_effect=meta),patch.object(n.os,'readlink',side_effect=lambda path:'/var/log/journal/local/system.journal' if path.endswith('/17') else '/tmp/unrelated'):
   self.assertEqual(n.journal_fds(),{17:(1,17)})

if __name__=='__main__':unittest.main()
