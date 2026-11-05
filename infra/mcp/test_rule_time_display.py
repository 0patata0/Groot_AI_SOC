import copy
from datetime import datetime
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import json

spec=importlib.util.spec_from_file_location('rule_time_view',Path(__file__).with_name('rule_change_mcp.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class RuleTimeDisplayTests(unittest.TestCase):
    def test_registration_and_application_confirmation_are_labelled_kst_without_plan_change(self):
        original={'kind':'containment','workflow_created_at':1793707800,'initial_apply_observed_at':1793707802,
                  'temporary_expires_at':1793708400,'payload':{'plan_sha256':'a'*64}}
        before=copy.deepcopy(original);result=m.with_time_display(original)
        times={r['source_field']:r['kst'] for r in result['time_display']['values']}
        self.assertEqual(times['workflow_created_at'],'2026-11-03T21:10:00+09:00')
        self.assertEqual(times['initial_apply_observed_at'],'2026-11-03T21:10:02+09:00')
        self.assertEqual(original,before)
        self.assertEqual({k:v for k,v in result.items() if k!='time_display'},before)
    def test_operation_epochs_and_live_remaining_preserve_original_receipt(self):
        now = datetime.fromisoformat('2026-11-03T21:12:00+09:00')
        end = int(datetime.fromisoformat('2026-11-03T21:20:18+09:00').timestamp())
        original = {'kind':'containment', 'target':'a:incident-ip', 'request_id':'a'*32,
                    'temporary_expires_at':end, 'owned_deadline':end, 'live_owned_deadline':end,
                    'live_observed_at':int(now.timestamp()), 'live_block_state':'owned',
                    'live_remaining_seconds':497, 'closed_at':None,
                    'payload':{'expires_at':end, 'plan_sha256':'b'*64}}
        saved = copy.deepcopy(original); answer = m.with_time_display(original, now)
        self.assertEqual({k:v for k,v in answer.items() if k!='time_display'}, saved)
        self.assertEqual(original, saved)
        self.assertEqual(answer['time_display']['containment']['owned_deadline_kst'],
                         '2026-11-03T21:20:18+09:00')
        self.assertEqual(answer['time_display']['containment']['remaining_seconds_at_observation'], 498)
        self.assertEqual(answer['live_remaining_seconds'],497)  # Actual kernel rounding is retained.

    def test_unknown_or_foreign_live_block_never_gets_active_deadline_summary(self):
        for state in ('absent','unavailable','foreign'):
            value = m.with_time_display({'kind':'containment','target':'a:incident-ip',
                'live_block_state':state,'owned_deadline':1793708418,
                'live_owned_deadline':None,'live_observed_at':1793707920})
            self.assertNotIn('containment',value['time_display'])
        for invalid in (True,float('nan'),float('inf'),'1793708418'):
            value = m.with_time_display({'owned_deadline':invalid})
            self.assertEqual(value['time_display']['values'],[])

    def test_status_and_containment_calls_use_same_display_for_both_mcp_roles(self):
        original={'kind':'containment','target':'a:incident-ip','owned_deadline':1793708418}
        for readonly in (True,False):
            for operation in ('get','service-get','status','operation-status','contain-ip'):
                proc=SimpleNamespace(returncode=0,stdout=json.dumps(original).encode())
                with patch.object(m.subprocess,'run',return_value=proc) as call:
                    result=m._call_helper({'operation':operation},readonly=readonly)
                value=json.loads(result['content'][0]['text'])
                self.assertEqual(value['owned_deadline'],original['owned_deadline'])
                self.assertIn('time_display',value)
                self.assertEqual('--read-only' in call.call_args.args[0],readonly)

    def test_kst_and_elapsed_are_added_without_changing_approval_observation(self):
        original={'target':'a:suricata','observation':{'started_at':'2026-10-24T15:55:11Z','running':True},
                  'base_state_sha256':'a'*64,'content':'literal log 2026-10-24T15:55:11Z'}
        saved=copy.deepcopy(original)
        result=m.with_time_display(original,datetime.fromisoformat('2026-10-25T01:05:11+09:00'))
        self.assertEqual(original,saved)
        self.assertEqual({k:v for k,v in result.items() if k!='time_display'},saved)
        self.assertEqual(result['time_display']['values'],[{'source_field':'observation.started_at',
            'kst':'2026-10-25T00:55:11+09:00','seconds_until_rendered_at':600,'elapsed_display':'0일 0시간 10분 0초'}])

    def test_naive_invalid_values_and_negative_elapsed_are_not_invented(self):
        result=m.with_time_display({'observation':{'started_at':'2026-10-24T15:55:11',
                                                  'observed_at':True,'last_reload':'bad'}},
                                   datetime.fromisoformat('2026-10-25T01:05:11+09:00'))
        self.assertEqual(result['time_display']['values'],[])
        result=m.with_time_display({'runtime':{'started_at':'2026-10-25T01:15:11+09:00'}},
                                   datetime.fromisoformat('2026-10-25T01:05:11+09:00'))
        self.assertEqual(result['time_display']['values'][0]['seconds_until_rendered_at'],-600)


if __name__=='__main__': unittest.main()
