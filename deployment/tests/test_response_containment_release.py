"""No nft/approval/network operations: exact ownership and parent-state tests."""
import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

spec=importlib.util.spec_from_file_location('response_release_under_test',Path(__file__).resolve().parents[1]/'soc_agent_block.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.rid='a'*32
        self.record={'ip':'192.168.16.233','owned_deadline':1800000000,'status':'kept'}
        self.before={'comment':'contain:'+self.rid+':1800000000'}
        self.service=SimpleNamespace(_load=mock.Mock(side_effect=lambda rid:copy.deepcopy(self.record)),_save=mock.Mock())
        self.c=SimpleNamespace(ContainmentService=mock.Mock(return_value=self.service),digest=lambda v:'b'*64)
        self.b=SimpleNamespace(owned=mock.Mock(return_value=True),release=mock.Mock(return_value={'element':None}))
    def call(self):m.release_owned_containment('engine',self.c,self.b,'192.168.16.233',self.before)
    def test_kept_parent_is_released_and_persisted(self):
        self.call();self.service._load.assert_called_once_with(self.rid)
        saved=self.service._save.call_args.args[0]
        self.assertEqual(saved['status'],'released');self.assertEqual(saved['owned_deadline'],1800000000)
        self.b.release.assert_called_once()
    def test_unknown_tags_never_delete(self):
        for tag in ('manual','response:x','contain:bad:1800000000'):
            self.before['comment']=tag
            with self.assertRaises(ValueError):self.call()
        self.b.release.assert_not_called()
    def test_ip_deadline_state_or_ownership_changes_never_delete(self):
        for change in ({'ip':'192.168.16.234'},{'owned_deadline':1799999999},{'status':'released'}):
            original=self.record.copy();self.record.update(change)
            with self.assertRaises(ValueError):self.call()
            self.record=original
        self.b.owned.return_value=False
        with self.assertRaises(ValueError):self.call()
        self.b.release.assert_not_called()
    def test_failed_readback_never_saves_success(self):
        self.b.release.return_value={'element':self.before}
        with self.assertRaises(ValueError):self.call()
        self.service._save.assert_not_called()

if __name__=='__main__':unittest.main()
