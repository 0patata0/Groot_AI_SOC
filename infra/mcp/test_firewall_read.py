"""Firewall reads must preserve base policies, all rules and paging boundaries."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('fw_response', Path(__file__).with_name('response-mcp.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


def fixture():
    objects = [{'table': {'family':'inet','name':'test'}},
               {'chain': {'family':'inet','table':'test','name':'input','hook':'input','prio':0,'policy':'drop'}},
               {'rule': {'family':'inet','table':'test','chain':'input','handle':8,'expr':[{'accept':None}]}},
               {'set': {'family':'inet','table':'test','name':'protected','type':'ipv4_addr','elem':['192.0.2.1']}}]
    return {'schema':1,'target':'a:firewall','observed_at_kst':'2026-10-29T15:00:00+09:00',
            'sha256':'a'*64,'counts':{k:1 for k in ('table','chain','rule','set')},'objects':objects,
            'coverage_warnings':[]}


class FirewallRead(unittest.TestCase):
    def read(self, args):
        r=m.call_tool('get_firewall_rules',args)
        self.assertFalse(r['isError'],r)
        return json.loads(r['content'][0]['text'])

    def test_complete_native_objects_policies_and_set_elements_preserved(self):
        with tempfile.TemporaryDirectory() as t, patch.object(m,'_fw_cache',return_value=Path(t)), patch.object(m,'_fw_capture',return_value=fixture()), patch.object(m,'request_approval') as approval, patch.object(m,'run_agent_block') as mutate:
            result=self.read({})
        self.assertTrue(result['complete']);self.assertEqual(result['total_objects'],4)
        self.assertEqual(result['objects'],fixture()['objects']);approval.assert_not_called();mutate.assert_not_called()

    def test_fixed_command_numeric_no_shell_and_failure_not_empty(self):
        def command(argv, **kw):
            self.assertEqual(argv,['/usr/sbin/nft','-j','-a','-n','list','ruleset'])
            self.assertNotIn('shell',kw)
            kw['stdout'].write(json.dumps({'nftables':fixture()['objects']}).encode())
            return type('P',(),{'returncode':0})()
        with patch.object(m.subprocess,'run',side_effect=command):
            self.assertEqual(m._fw_capture()['counts']['rule'],1)
        with patch.object(m,'_fw_cache'), patch.object(m,'_fw_capture',side_effect=ValueError('nft unavailable')):
            result=m.firewall_rules({})
        self.assertTrue(result['isError']);self.assertIn('미완료',result['content'][0]['text'])

    def test_no_command_path_or_filter_injection(self):
        for args in ({'command':'flush ruleset'},{'snapshot':'../../etc/shadow'}, {'offset':True}, {'limit':0}, {'limit':201}, {'offset':1}, {'offset':-1}, []):
            with patch.object(m,'_fw_capture') as read:
                self.assertTrue(m.firewall_rules(args)['isError'],args)
                read.assert_not_called()

    def test_snapshot_pages_survive_separate_calls_and_expired_or_symlink_refused(self):
        with tempfile.TemporaryDirectory() as t, patch.object(m,'_fw_cache',return_value=Path(t)), patch.object(m,'_fw_capture',side_effect=lambda:fixture()) as capture:
            first=self.read({'limit':2})
            # Mac test is unprivileged; production insists on root-owned cache.
            with patch.object(m.os,'fstat',side_effect=lambda fd:type('S',(),{'st_uid':0,'st_mode':0o100600,'st_mtime':m.time.time()})()):
                last=self.read({'snapshot':first['snapshot'],'offset':2})
            self.assertFalse(first['complete']);self.assertEqual(first['next_offset'],2)
            self.assertTrue(last['complete']);self.assertEqual(last['sha256'],first['sha256']);self.assertEqual(capture.call_count,1)
            (Path(t)/('b'*32)).symlink_to('/etc/passwd')
            self.assertTrue(m.firewall_rules({'snapshot':'b'*32})['isError'])
            with patch.object(m.time,'time',return_value=10**12):
                self.assertTrue(m.firewall_rules({'snapshot':first['snapshot']})['isError'])

    def test_byte_budget_requires_next_page_and_oversized_object_fails(self):
        with tempfile.TemporaryDirectory() as t, patch.object(m,'_fw_cache',return_value=Path(t)), patch.object(m,'_fw_capture',side_effect=lambda:fixture()), patch.object(m,'FW_PAGE_BYTES',100):
            p=self.read({});self.assertFalse(p['complete']);self.assertIsNotNone(p['next_offset'])
        with tempfile.TemporaryDirectory() as t, patch.object(m,'_fw_cache',return_value=Path(t)), patch.object(m,'_fw_capture',side_effect=lambda:fixture()), patch.object(m,'FW_PAGE_BYTES',1):
            self.assertTrue(m.firewall_rules({})['isError'])


if __name__=='__main__':unittest.main()
