"""Only owned fence/unit files in a private fixture; no systemd calls."""
import importlib.util
import os
from pathlib import Path
import unittest

HERE=Path(__file__).parent
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
fixture=load('control_source_fixture','test_release_files.py')
m=load('release_controls_tested','release_controls.py')


class ControlFiles(unittest.TestCase):
    setUp=fixture.SourceTransaction.setUp
    prepare=fixture.SourceTransaction.prepare

    def controls(self,host='b'):
        fs=self.prepare(host);(self.root/'etc/mcp/system-diagnostics').mkdir(parents=True,exist_ok=True)
        return m.Files(fs,'c'*64)

    def test_split_collection_consumer_and_mcp_fences_are_persistent(self):
        ctl=self.controls()
        for kind in ('collection','consumer','mcp'):
            self.assertFalse(ctl.fenced(kind));self.assertTrue(ctl.fence(kind));self.assertTrue(ctl.fenced(kind));self.assertFalse(ctl.fence(kind))
        self.assertEqual(ctl.unfence('collection'),True);self.assertFalse(ctl.fenced('collection'))
        self.assertTrue(ctl.fenced('consumer'));self.assertTrue(ctl.fenced('mcp'))

    def test_foreign_fence_is_not_adopted_or_deleted(self):
        ctl=self.controls();p=ctl.path(m.CONSUMERS);p.write_bytes(b'other operation');p.chmod(0o600)
        for action in (ctl.fence,ctl.unfence,ctl.fenced):
            with self.assertRaisesRegex(ValueError,'foreign_control_file'):action('consumer')
        self.assertEqual(p.read_bytes(),b'other operation')

    def test_unknown_kind_cannot_select_paths(self):
        ctl=self.controls()
        for action in (ctl.fence,ctl.unfence,ctl.fenced):
            with self.assertRaisesRegex(ValueError,'fence_kind'):action('/etc/shadow')

    def test_mcp_fence_only_exists_on_b(self):
        ctl=self.controls('a')
        with self.assertRaisesRegex(ValueError,'fence_kind'):ctl.fence('mcp')

    def test_documents_are_create_only_idempotent_and_exactly_removable(self):
        ctl=self.controls();count=ctl.install();self.assertEqual(count,len(ctl.docs));self.assertEqual(ctl.install(),0)
        for path,raw in ctl.docs.items():self.assertEqual(ctl.path(path).read_bytes(),raw)
        self.assertEqual(ctl.remove_documents(),count);self.assertEqual(ctl.remove_documents(),0)

    def test_existing_foreign_document_prevents_all_new_writes(self):
        ctl=self.controls();p=ctl.path(m.UNIT_DIR/m.WATCH);p.write_bytes(b'other watchdog');p.chmod(0o644)
        with self.assertRaisesRegex(ValueError,'foreign_control_file'):ctl.install()
        self.assertEqual(list((self.root/'etc/systemd/system').glob('capstone-journal-release*')),[p])

    def test_changed_document_is_not_deleted(self):
        ctl=self.controls();ctl.install();p=ctl.path(m.UNIT_DIR/m.WATCH);p.write_bytes(b'operator edited');before={q:q.read_bytes()for q in ctl.path(m.UNIT_DIR/m.TIMER).parent.rglob('*')if q.is_file()}
        with self.assertRaisesRegex(ValueError,'foreign_control_file'):ctl.remove_documents()
        self.assertEqual(before,{q:q.read_bytes()for q in before})

    def test_other_dropins_and_security_unit_files_are_untouched(self):
        ctl=self.controls();p=self.root/'etc/systemd/system/capstone-system-diagnostics.service.d/30-inventory-netlink.conf';p.parent.mkdir();p.write_bytes(b'original inventory dropin')
        ctl.install();ctl.remove_documents();self.assertEqual(p.read_bytes(),b'original inventory dropin')
        self.assertFalse(any('vector'in str(p)or'wazuh'in str(p)or'suricata'in str(p)for p in ctl.docs))

    def test_symlink_file_or_parent_never_followed(self):
        ctl=self.controls();p=ctl.path(m.UNIT_DIR/m.WATCH);other=self.root/'victim';other.write_bytes(b'keep');p.symlink_to(other)
        with self.assertRaises(OSError):ctl.install()
        self.assertEqual(other.read_bytes(),b'keep')
        p.unlink();folder=ctl.path(next(p for p in ctl.docs if p.name==m.DROPIN)).parent;folder.symlink_to(other.parent,target_is_directory=True)
        with self.assertRaises(OSError):ctl.install()

    def test_hardlink_or_fifo_is_not_overwritten(self):
        ctl=self.controls();p=ctl.path(m.UNIT_DIR/m.WATCH);os.mkfifo(p)
        with self.assertRaisesRegex(ValueError,'unsafe_file'):ctl.install()
        p.unlink();p.write_bytes(b'keep');p.chmod(0o644);os.link(p,p.with_name('alias'))
        with self.assertRaisesRegex(ValueError,'unsafe_file'):ctl.install()

    def test_raw_create_or_remove_cannot_bypass_approved_document_bytes(self):
        ctl=self.controls();path=m.UNIT_DIR/m.WATCH
        with self.assertRaisesRegex(ValueError,'control_payload_not_in_plan'):ctl.create(path,b'unapproved executable',mode=0o644)
        with self.assertRaisesRegex(ValueError,'control_payload_not_in_plan'):ctl.remove(path,b'unapproved',mode=0o644)
        with self.assertRaisesRegex(ValueError,'control_path_scope'):ctl.path(Path('/etc/shadow'))

    def test_dropin_contract_is_release_bound_and_fence_groups_separate(self):
        a=m.documents('a','a'*32,'b'*64);other=m.documents('a','c'*32,'b'*64)
        for path,raw in a.items():
            if path.name!=m.DROPIN:continue
            self.assertIn(b'a'*32,raw);self.assertNotEqual(raw,other[path])
            expected=m.CONSUMERS if 'soc-observe'in str(path)else m.COLLECTION;self.assertIn(str(expected).encode(),raw)

    def test_helper_limits_boot_schedule_and_no_new_tcp_listener(self):
        docs=m.documents('b','a'*32,'b'*64);status=docs[m.UNIT_DIR/m.STATUS].decode();watch=docs[m.UNIT_DIR/m.WATCH].decode();timer=docs[m.UNIT_DIR/m.TIMER].decode()
        self.assertIn('RestrictAddressFamilies=AF_UNIX\n',status);self.assertIn('MemoryMax=96M',status);self.assertNotIn('AF_INET',status)
        self.assertIn('OnBootSec=5s',timer);self.assertIn('OnUnitInactiveSec=10s',timer)
        self.assertIn('MemoryMax=256M',watch);self.assertIn('TimeoutStartSec=330s',watch);self.assertIn('--operation recover',watch)
        self.assertNotIn('AF_INET6',watch);self.assertNotIn('/bin/sh',watch)

    def test_control_renderer_rejects_escape_and_unapproved_host(self):
        for args in (('d','a'*32,'b'*64),('a','../../escape','b'*64),('a','a'*32,'not a digest')):
            with self.assertRaises(ValueError):m.documents(*args)


if __name__=='__main__':unittest.main()
