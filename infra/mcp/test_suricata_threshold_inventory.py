import copy
import contextlib
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import security_rule_inventory as inv
import rule_change_executor as parser

POLICY=b'suppress gen_id 1, sig_id 2001219, track by_src, ip 192.168.16.231/32\n'
STAMP='2026-11-07T02:45:32Z'


class Engine:
    def __init__(self):
        self.info={'Id':'a'*64,'State':{'StartedAt':STAMP},'Config':{'Cmd':['-S','/rules/all.rules','--set','threshold-file=/rules/threshold.in']},
                   'Mounts':[{'Source':'/fixed/rules','Destination':'/rules','RW':False}]}
        self.policy=POLICY;self.commands=[];self.inspect_reads=0;self.changed=None;self.remote_sha=None
        self.runner=SimpleNamespace(call=self.run)
    def spec(self,target):
        if target!='a:suricata-local':raise parser.RuleChangeError('wrong target')
        return {'mount_source':'/fixed/rules','container':'suricata','path':'/fixed/rules/local.rules','et_path':'/fixed/rules/et.rules'}
    def locked(self):return contextlib.nullcontext()
    def _inspect(self,spec):return {'container_id':'a'*64,'started_at':STAMP,'running':True}
    def run(self,args):
        self.commands.append(args)
        if args==[parser.DOCKER,'inspect','suricata']:
            self.inspect_reads+=1
            info=self.changed if self.changed and self.inspect_reads%2==0 else self.info
            return json.dumps([info]).encode()
        if args==[parser.DOCKER,'exec','a'*64,'sha256sum','/rules/threshold.in']:
            return ((self.remote_sha or inv.digest(self.policy))+'  /rules/threshold.in\n').encode()
        raise AssertionError(args)


class ThresholdTests(unittest.TestCase):
    def read(self,engine=None,reader=None):
        engine=engine or Engine()
        def fixed(path,limit):
            self.assertEqual(path,'/fixed/rules/threshold.in');self.assertEqual(limit,65536)
            return engine.policy,SimpleNamespace()
        with patch.object(parser,'_read_regular',side_effect=reader or fixed):return inv.suricata_thresholds(engine,parser)

    def test_current_exact_selection_and_host_container_bytes(self):
        engine=Engine();out=self.read(engine)
        self.assertEqual(out['status'],'observed');self.assertTrue(out['configuration_selected'])
        self.assertFalse(out['runtime_load_verified']);self.assertEqual(out['sha256'],hashlib.sha256(POLICY).hexdigest())
        self.assertEqual(out['entries'][0]['parameters']['track'],'by_src')
        self.assertEqual(out['entries'][0]['address_networks'],['192.168.16.231/32'])
        self.assertTrue(out['observed_at_kst'].endswith('+09:00'))
        self.assertEqual(len(engine.commands),3)

    def test_all_kinds_lists_variables_and_continuations_preserved(self):
        raw=(b'# heading\nsuppress gen_id 0, sig_id 0\n'
             b'suppress gen_id 1, sig_id 42, track by_either, ip [192.0.2.0/24, 2001:db8::/32]\n'
             b'suppress gen_id 1, sig_id 43, track by_dst, ip $HOME_NET\n'
             b'threshold gen_id 1, sig_id 44, type both, \\\n track by_src, count 5, seconds 120\n'
             b'event_filter gen_id 1, sig_id 45, type limit, track by_flow, count 2, seconds 10\n'
             b'rate_filter gen_id 1, sig_id 46, track by_rule, count 10, seconds 60, new_action drop, timeout 300\n')
        rows,warnings=inv.threshold_statements(raw);self.assertFalse(warnings);self.assertEqual(len(rows),6)
        self.assertEqual(rows[1]['address_networks'],['192.0.2.0/24','2001:db8::/32'])
        self.assertFalse(rows[2]['address_resolution_complete']);self.assertEqual(rows[2]['address_variables'],['$HOME_NET'])
        self.assertEqual(rows[3]['line'],5);self.assertEqual(rows[3]['parameters']['count'],'5')
        self.assertEqual(rows[5]['meaning'],'rule_action_rate_control')

    def test_unknown_invalid_duplicate_or_incomplete_lines_not_silently_zero(self):
        for raw in (b'unknown anything', b'suppress gen_id 1, sig_id 42, track by_src',
                    b'suppress gen_id 1, sig_id 42, ip 192.0.2.1',
                    b'suppress gen_id 1, sig_id 42, sig_id 43',
                    b'suppress gen_id 1, sig_id 42, track by_src, ip garbage',
                    b'threshold gen_id 0, sig_id 42, type both, track by_src, count 1, seconds 10',
                    b'suppress gen_id 1, sig_id 42 \\',
                    b'rate_filter gen_id 1, sig_id 46, track by_rule, count 10, seconds 60, new_action sdrop, timeout 300'):
            with self.subTest(raw=raw):
                rows,warnings=inv.threshold_statements(raw);self.assertEqual(len(rows),1);self.assertFalse(rows[0]['parsed']);self.assertTrue(warnings)
                engine=Engine();engine.policy=raw;self.assertEqual(self.read(engine)['status'],'partial')

    def test_empty_file_is_only_empty_selected_file(self):
        engine=Engine();engine.policy=b'# comments only\n';out=self.read(engine)
        self.assertEqual(out['status'],'observed');self.assertEqual(out['statement_count'],0)
        self.assertFalse(out['runtime_load_verified'])

    def test_untrusted_or_ambiguous_selection_never_reads_arbitrary_path(self):
        for command in ([],['--set','threshold-file=/etc/shadow'],['--set','threshold-file=/rules/../secret'],
                        ['--set','threshold-file=/rules/threshold.in','--set','threshold-file=/rules/threshold.in'],
                        ['--set','threshold-file=/rules/threshold.in','--set=threshold-file=/other'],[None]):
            engine=Engine();engine.info['Config']['Cmd']=command
            with patch.object(parser,'_read_regular') as read:
                out=inv.suricata_thresholds(engine,parser)
            self.assertEqual(out['status'],'unavailable');read.assert_not_called()

    def test_changed_bytes_config_container_and_missing_file_remain_unknown(self):
        engine=Engine();engine.remote_sha='0'*64;self.assertEqual(self.read(engine)['status'],'unavailable')
        for part,value in [('Id','b'*64),('Config',{'Cmd':['different']}),('State',{'StartedAt':'2026-11-07T02:46:32Z'})]:
            engine=Engine();engine.changed={**engine.info,part:value};self.assertEqual(self.read(engine)['status'],'unavailable')
        replies=iter([(POLICY,None),(POLICY+b'# drift',None)])
        self.assertEqual(self.read(reader=lambda *args:next(replies))['status'],'unavailable')
        def missing(*args):raise FileNotFoundError()
        self.assertEqual(self.read(reader=missing)['status'],'unavailable')

    def test_size_encoding_and_statement_limits(self):
        for raw in (b'x'*65537,b'\xff',b'suppress gen_id 1, sig_id 42\n'*513):
            engine=Engine();engine.policy=raw;out=self.read(engine)
            self.assertEqual(out['status'],'unavailable');self.assertNotIn('entries',out)

    def test_threshold_change_invalidates_rule_inventory_page_snapshot(self):
        engine=Engine();et=b'alert tcp any any -> any any (msg:"fixture"; sid:42; rev:1;)\n';custom=b''
        engine._snapshot=lambda spec:(custom,None,{'et_sha256':inv.digest(et),'all_sha256':inv.digest(et)})
        engine._inspect=lambda spec:{'container_id':'a'*64,'started_at':STAMP,'running':True}
        def fixed(path,limit):return (et if path.endswith('et.rules') else engine.policy),None
        service=SimpleNamespace(ServiceActionService=lambda engine:SimpleNamespace(_rule_engine_evidence=lambda runtime:{'status':'unavailable'}))
        with patch.object(parser,'_read_regular',side_effect=fixed),patch.object(parser,'_load_extension',return_value=service):
            first=inv.inventory(engine,parser,{'target':'a:suricata'})
            self.assertEqual(first['status'],'complete');self.assertEqual(first['runtime']['threshold_configuration']['status'],'observed')
            engine.policy=POLICY.replace(b'231',b'232')
            with self.assertRaisesRegex(ValueError,'snapshot_changed'):
                inv.inventory(engine,parser,{'target':'a:suricata','snapshot_id':first['snapshot_id']})


if __name__=='__main__':unittest.main()
