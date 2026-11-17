"""Timeouts keep actual reads without approving, retrying or inventing results."""
import copy
import json
import tempfile
import types
import unittest
from unittest.mock import patch

import soc_management_controller as controller
import soc_management_run as gate


class InterruptedEvidence(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.store=controller.Store(self.tmp.name,clock=lambda:1794890000)
        self.addCleanup(self.store.close)
        with self.store.db:cid=self.store.new_case('timeout-evidence')
        case=self.store.db.execute('select * from cases where id=?',(cid,)).fetchone()
        self.trace=controller.Trace(self.store,case,self.store.start(case))
        self.trace.accept({'type':'system','subtype':'init','session_id':'timeout-session'})

    def read(self,error=False):
        name='mcp__security_events__search_suricata_alerts'
        args={'source_ip':'192.0.2.7','since_kst':'2026-11-17T12:00:00+09:00',
              'until_kst':'2026-11-17T12:01:00+09:00','limit':10}
        payload={'source':'suricata','source_scope':'wazuh_indexed_alerts','returned_count':1,
                 'indexed_window_total_count':None,'requested_since_kst':args['since_kst'],
                 'requested_until_kst':args['until_kst'],'alerts':[{'timestamp':'2026-11-17T12:00:30+09:00',
                 'source_ip':'192.0.2.7','destination_ip':'198.51.100.20','signature_id':2058076,'agent':'sensor-a'}]}
        self.trace.accept({'type':'tool_use','name':name,'input':args})
        self.trace.accept({'type':'tool_result','name':name,'output':json.dumps(payload),'is_error':error})

    def report(self):
        return self.store.db.execute('select * from report_outbox').fetchone()

    def test_timeout_keeps_received_read_and_unknown_state(self):
        self.read();result=self.trace.finish(124)
        self.assertFalse(result['completed']);self.assertEqual(result['text'],'')
        row=self.report();self.assertEqual(row['state'],'outcome_unknown')
        for text in ('model_subprocess_timeout_requires_review','중단 전 확보한 조회 근거',
                     '192.0.2.7','198.51.100.20','2058076','전체 건수 미확인'):
            self.assertIn(text,row['text'])
        self.assertNotIn('MANAGEMENT_STATUS: resolved',row['text'])
        case=self.store.db.execute('select * from cases').fetchone()
        self.assertEqual(case['final_text'],row['text'])
        self.assertIsNone(self.store.next_case())
        self.assertEqual(self.store.db.execute('select count(*) from runs').fetchone()[0],1)

    def test_failed_read_does_not_become_evidence(self):
        self.read(error=True);self.trace.finish(124)
        text=self.report()['text']
        self.assertIn('오류 반환',text)
        self.assertNotIn('192.0.2.7',text)
        self.assertNotIn('중단 전 확보한 조회 근거',text)

    def test_inflight_write_is_unknown_and_never_repeated(self):
        self.trace.accept({'type':'tool_use','name':'mcp__rule_write_a__propose_rule_edit',
                           'input':{'target':'a:modsecurity-custom'}})
        self.trace.finish(124)
        text=self.report()['text'];self.assertIn('결과 미확인',text)
        self.assertNotIn('적용 완료',text);self.assertIsNone(self.store.next_case())
        self.assertEqual(self.store.db.execute('select completed from tool_calls').fetchone()[0],0)

    def test_read_fact_bound_is_visible_instead_of_a_false_complete_report(self):
        self.trace.completed_read_fact_bytes=128*1024
        self.read();self.trace.finish(124)
        self.assertIn('일부 근거는 이 표에 없으며',self.report()['text'])

    def test_automatic_prompt_has_one_policy_copy_and_exact_evidence(self):
        case=dict(self.trace.case,incident_read_at='2026-11-17T12:02:00+09:00')
        evidence=self.store.context(case['id']);base='UNIQUE_AUTOMATIC_POLICY_ANCHOR'
        text=controller.prompt_for(base,case,evidence)
        self.assertEqual(text.count(base),1)
        content=text.split('\nUNTRUSTED_EVIDENCE_JSON\n',1)[1].split('\nTRUSTED_CURRENT_REQUEST_JSON\n',1)
        self.assertEqual(json.loads(content[0]),evidence['events'])
        self.assertEqual(json.loads(content[1])['request'],'현재 수신 사건 조사·위험 판단·대응·검증')

    def test_explicit_chat_request_is_preserved_verbatim(self):
        request='FW와 systemd를 구분해서 현재 조회해줘'
        case=dict(self.trace.case,chat_request=request,incident_read_at='2026-11-17T12:02:00+09:00')
        text=controller.prompt_for('base-policy',case,self.store.context(case['id']))
        self.assertEqual(json.loads(text.split('\nTRUSTED_CURRENT_REQUEST_JSON\n',1)[1])['request'],request)

    def reopen(self):
        self.store.close()
        self.store=controller.Store(self.tmp.name,clock=lambda:1794890001)
        self.addCleanup(self.store.close)

    def test_abrupt_controller_exit_recovers_durable_reads_without_rerunning(self):
        self.read()
        self.assertIn('192.0.2.7',self.store.meta('read_checkpoint/'+self.trace.run_id))
        # No Trace.finish: reproduce the service supervisor killing its controller.
        self.reopen();self.store.recover();self.store.recover()
        text=self.report()['text']
        self.assertIn('interrupted_run_requires_review',text)
        self.assertIn('중단 전 확보한 조회 근거',text)
        for value in ('192.0.2.7','198.51.100.20','2058076','현재 상태·위험 해소·승인을 증명하지 않습니다'):
            self.assertIn(value,text)
        self.assertEqual(self.report()['state'],'outcome_unknown')
        self.assertIsNone(self.store.next_case())
        self.assertEqual(self.store.db.execute('select count(*) from report_outbox').fetchone()[0],1)
        self.assertEqual(self.store.db.execute('select count(*) from runs').fetchone()[0],1)
        self.assertEqual(self.store.db.execute('select count(*) from tool_calls').fetchone()[0],1)
        self.assertEqual(self.store.db.execute('select final_text from cases').fetchone()[0],text)

    def test_pending_write_after_checkpoint_remains_unknown_on_recovery(self):
        self.read()
        self.trace.accept({'type':'tool_use','name':'mcp__rule_write_a__propose_rule_edit',
                           'input':{'target':'a:modsecurity-custom'}})
        self.reopen();self.store.recover()
        text=self.report()['text']
        self.assertIn('192.0.2.7',text);self.assertIn('결과 미확인',text)
        self.assertNotIn('적용 완료',text);self.assertIsNone(self.store.next_case())
        self.assertEqual(self.store.db.execute('select completed from tool_calls where is_write=1').fetchone()[0],0)

    def test_corrupt_or_cross_run_checkpoint_is_not_restored_as_evidence(self):
        self.read();key='read_checkpoint/'+self.trace.run_id
        original=json.loads(self.store.meta(key))
        for value in ('{bad-json',json.dumps(dict(original,run_id='f'*32)),
                      json.dumps(dict(original,facts_sha256='0'*64)),
                      json.dumps(dict(original,through_ordinal=999))):
            with self.subTest(value=value):
                with self.store.db:self.store.set_meta(key,value)
                text=self.store.interrupted_report(self.trace.run_id,self.trace.case['id'],
                                                  'interrupted_run_requires_review')
                self.assertIn('무결성·실행 결속',text)
                self.assertNotIn('192.0.2.7',text)
                self.assertIn('조회 응답 수신',text)

    def test_failed_read_does_not_create_a_success_checkpoint(self):
        self.read(error=True)
        self.assertEqual(self.store.meta('read_checkpoint/'+self.trace.run_id,''),'')
        self.reopen();self.store.recover()
        self.assertIn('오류 반환',self.report()['text'])
        self.assertNotIn('192.0.2.7',self.report()['text'])

    def test_fact_limit_is_durable_after_abrupt_exit(self):
        self.trace.completed_read_fact_bytes=128*1024
        self.read();self.reopen();self.store.recover()
        self.assertIn('일부 근거는 이 표에 없으며',self.report()['text'])

    def test_checkpoint_does_not_leak_into_another_run(self):
        self.read();self.trace.finish(124)
        old=self.report()['text']
        self.store.review(self.trace.case['id'],'읽기 전용 후속 검토')
        case=self.store.next_case();run=self.store.start(case)
        self.store.recover()
        text=self.store.db.execute('select text from report_outbox where run_id=?',(run,)).fetchone()[0]
        self.assertIn('192.0.2.7',old);self.assertNotIn('192.0.2.7',text)

    def test_new_block_observation_invalidates_old_list_even_at_fact_limit(self):
        name='mcp__resp__list_blocks'
        def read(blocks):
            self.trace.accept({'type':'tool_use','name':name,'input':{}})
            self.trace.accept({'type':'tool_result','name':name,'output':json.dumps({'blocks':blocks})})
        read(['192.0.2.77'])
        self.assertIn('192.0.2.77',json.dumps(self.trace.completed_read_facts))
        self.trace.completed_read_fact_bytes=128*1024
        read([]);self.reopen();self.store.recover()
        text=self.report()['text']
        self.assertNotIn('192.0.2.77',text)
        self.assertIn('일부 근거는 이 표에 없으며',text)


class ReadSelectionProfile(unittest.TestCase):
    def setUp(self):
        self.name='mcp__security_events__search_suricata_alerts'
        self.agent=types.SimpleNamespace(provider='custom',model='soc-qwen36:35b-balanced-q4km-20261108',
            base_url='http://10.200.10.10:11435/v1',valid_tool_names={self.name})
        self.request={'model':self.agent.model,'reasoning_effort':'medium','max_tokens':4096,
            'messages':[{'role':'user','content':'실제 사건의 근거를 조회한다'}],
            'tools':[{'type':'function','function':{'name':self.name,'parameters':{'type':'object'}}}],
            'tool_choice':'required','extra_body':{}}

    def test_forced_registered_read_is_fast_and_input_is_unchanged(self):
        before=copy.deepcopy(self.request)
        with patch.dict('os.environ',{'CAPSTONE_MANAGEMENT_MODE':'manage'}):
            result=gate.management_reasoning(self.request,self.agent)
        self.assertEqual(self.request,before)
        self.assertEqual(result['reasoning_effort'],'none');self.assertEqual(result['max_tokens'],2048)
        for key in ('tools','tool_choice','messages'):self.assertEqual(result[key],before[key])

    def test_auto_mixed_unknown_and_overridden_choices_keep_judgment_reasoning(self):
        with patch.dict('os.environ',{'CAPSTONE_MANAGEMENT_MODE':'manage'}):
            for change in ({'tool_choice':'auto'},
                {'tools':self.request['tools']+[{'type':'function','function':{'name':'mcp__rule_write_a__temporarily_contain_ip'}}]},
                {'tools':[{'type':'function','function':{'name':'mcp__unknown__read'}}]},
                {'extra_body':{'tools':self.request['tools']}}):
                with self.subTest(change=change):
                    result=gate.management_reasoning({**self.request,**change},self.agent)
                    self.assertEqual(result['reasoning_effort'],'medium')


if __name__=='__main__':unittest.main()
