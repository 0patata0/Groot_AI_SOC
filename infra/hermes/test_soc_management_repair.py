"""Bound one literal repair while preserving assessment, tools and authority."""
import copy
import contextlib
import io
import json
import os
import types
import unittest
from unittest.mock import patch
import soc_management_run as m

class Agent:
    provider='custom'
    model='qwen3.6:35b'
    base_url='http://10.200.10.10:11435/v1'
    _current_turn_id='current'
    _interrupt_requested=False
    def _build_api_kwargs(self):
        return copy.deepcopy(self.request)

class LiteralRepair(unittest.TestCase):
    def setUp(self):
        self.agent=Agent()
        self.agent.request={'model':'qwen3.6:35b','reasoning_effort':'medium','max_tokens':6144,
            'messages':[{'role':'user','content':'실제 사건 영향과 대응 경과를 검토해줘'}],
            'tools':[{'type':'function','function':{'name':'mcp__rule_a__get_operation_status'}}],
            'tool_choice':'auto','extra_body':{}}
        self.env=patch.dict(os.environ,{'CAPSTONE_MANAGEMENT_MODE':'verify','CAPSTONE_MANAGEMENT_REVIEW':'1','CAPSTONE_OPERATOR_REVIEW':'1'})
        self.env.start();self.addCleanup(self.env.stop)

    def test_only_one_literal_build_is_fast_and_assessment_is_restored(self):
        original=copy.deepcopy(self.agent.request)
        self.assertEqual(m.management_reasoning(self.agent._build_api_kwargs(),self.agent)['reasoning_effort'],'medium')
        self.assertTrue(m.arm_literal_repair(self.agent,'current',['containment_deadline_clock_mismatch']))
        with contextlib.redirect_stderr(io.StringIO()) as out:result=self.agent._build_api_kwargs()
        self.assertEqual(result['reasoning_effort'],'none');self.assertEqual(result['max_tokens'],2048)
        for k in ('messages','tools','tool_choice'):self.assertEqual(result[k],original[k])
        self.assertIn('management_literal_repair_profile',out.getvalue())
        self.assertEqual(self.agent._build_api_kwargs(),original)
        self.assertEqual(self.agent.request,original)
        self.assertNotIn('_build_api_kwargs',self.agent.__dict__)

    def test_unknown_risk_missing_evidence_and_writes_do_not_arm(self):
        for issues in ([],['unobserved_event_source:suricata'],['incident_impact_verification_missing'],['sample_zero_presented_as_absence','unknown_issue']):
            self.assertFalse(m.arm_literal_repair(self.agent,'current',issues))
        with patch.dict(os.environ,{'CAPSTONE_MANAGEMENT_MODE':'manage'}):
            self.assertFalse(m.arm_literal_repair(self.agent,'current',['sample_zero_presented_as_absence']))
        self.assertNotIn('_build_api_kwargs',self.agent.__dict__)

    def test_new_turn_or_interrupt_cancels_pending_profile(self):
        for key,value in (('_current_turn_id','new'),('_interrupt_requested',True)):
            a=Agent();a.request=copy.deepcopy(self.agent.request)
            self.assertTrue(m.arm_literal_repair(a,'current',['unknown_window_total_claimed']))
            setattr(a,key,value)
            self.assertEqual(a._build_api_kwargs(),a.request)
            self.assertNotIn('_build_api_kwargs',a.__dict__)
            self.assertNotIn('_capstone_grounding_restore',a.__dict__)

    def test_unrecognized_model_or_route_retains_original_request(self):
        for key,value in (('provider','other'),('model','another-model'),('base_url','https://other.invalid/v1')):
            a=Agent();a.request=copy.deepcopy(self.agent.request);setattr(a,key,value)
            m.arm_literal_repair(a,'current',['containment_time_role_mismatch'])
            self.assertEqual(a._build_api_kwargs(),a.request)

    def test_existing_builder_is_restored_and_mode_is_checked_at_use(self):
        original=lambda:copy.deepcopy(self.agent.request)
        self.agent._build_api_kwargs=original
        m.arm_literal_repair(self.agent,'current',['missing_or_invalid_management_status'])
        with patch.dict(os.environ,{'CAPSTONE_MANAGEMENT_MODE':'manage'}):
            self.assertEqual(self.agent._build_api_kwargs()['reasoning_effort'],'medium')
        self.assertIs(self.agent._build_api_kwargs,original)

    def test_final_response_retry_uses_fast_profile_without_forcing_another_read(self):
        import test_soc_management_grounding as g
        fixture=g.Grounding();fixture.setUp()
        fixture.completed.append('get_operation_status')
        fixture.kw['assistant_message'].content='잘못된 기한 표기입니다.\nMANAGEMENT_STATUS: needs_review'
        with patch.object(g.wrapper,'evidence_claim_violations',return_value=['containment_deadline_clock_mismatch']):
            verdict=fixture.call(fixture.agent,**fixture.kw)
        self.assertEqual(verdict.action,'continue')
        with contextlib.redirect_stderr(io.StringIO()):result=fixture.agent._build_api_kwargs()
        self.assertEqual(result['reasoning_effort'],'none');self.assertEqual(result['max_tokens'],2048)
        self.assertEqual(result['tool_choice'],'auto')
        self.assertIn('containment_deadline_clock_mismatch',fixture.kw['messages'][-1]['content'])
        self.assertIs(fixture.agent._build_api_kwargs,fixture.builder)

    def test_unknown_citation_is_rewritten_without_inventing_or_requiring_a_read(self):
        good='mcp__security_events__search_suricata_alerts'
        typo='mcp__security_events::search_suricata_alerts'
        catalog=[{'type':'function','function':{'name':good}}]
        text='INCIDENT_DISPOSITION: '+json.dumps({'assessment':'unresolved',
            'basis':'실제 센서 표본을 확인했지만 전체 침해 영향은 아직 미확인입니다.',
            'evidence_tools':[good,typo]})+'\nMANAGEMENT_STATUS: needs_review'
        self.assertTrue(m.citation_name_repair(text,[good],catalog))
        self.assertEqual(m.evidence_claim_violations(text,[],[good]),['unobserved_disposition_tools'])
        import test_soc_management_grounding as g
        fixture=g.Grounding();fixture.setUp();fixture.completed.append(good)
        fixture.kw['assistant_message'].content=text
        callback=m.grounding_wrapper(lambda agent,**kw:'original',
            types.SimpleNamespace(FinalResponseVerdict=types.SimpleNamespace),
            lambda rows,row:rows.append(row),lambda rows,user:0,
            fixture.completed,successful_reads=[good])
        verdict=callback(fixture.agent,**fixture.kw)
        self.assertEqual(verdict.action,'continue')
        with contextlib.redirect_stderr(io.StringIO()):request=fixture.agent._build_api_kwargs()
        self.assertEqual(request['tool_choice'],'auto')
        self.assertEqual(request['reasoning_effort'],'none')
        self.assertIn('unobserved_disposition_tools',fixture.kw['messages'][-1]['content'])
        self.assertIn(typo,text)  # No automatic name correction or fabricated receipt.

    def test_registered_unread_or_resolved_citation_retains_normal_evidence_retry(self):
        good='mcp__security_events__search_suricata_alerts'
        missing='mcp__security_events__search_modsecurity_alerts'
        catalog=[{'type':'function','function':{'name':n}} for n in (good,missing)]
        def report(assessment,names):
            return 'INCIDENT_DISPOSITION: '+json.dumps({'assessment':assessment,
                'basis':'실제 센서 표본을 확인했지만 전체 침해 영향은 아직 미확인입니다.',
                'evidence_tools':names})+'\nMANAGEMENT_STATUS: needs_review'
        for text in (report('unresolved',[good,missing]),report('benign',[good,'misspelled']),
                     report('unresolved',['misspelled']),report('unresolved',[good,good,'misspelled'])):
            self.assertFalse(m.citation_name_repair(text,[good],catalog))

    def test_model_citation_hint_uses_only_successful_permitted_names_without_mutation(self):
        good='mcp__security_events__search_suricata_alerts'
        request={'messages':[{'role':'system','content':'관제 지시'}, {'role':'tool','content':'untrusted'}]}
        before=copy.deepcopy(request)
        shown=m.completed_citation_request(request,[good,good,'arbitrary','mcp__rule_write_a__propose_rule_edit'])
        self.assertEqual(request,before)
        self.assertEqual(shown['messages'][0]['content'].count(good),1)
        self.assertNotIn('arbitrary',shown['messages'][0]['content'])
        self.assertNotIn('propose_rule_edit',shown['messages'][0]['content'])
        self.assertEqual(shown['messages'][1],before['messages'][1])
        with patch.dict(os.environ,{'CAPSTONE_MANAGEMENT_MODE':'manage'}):
            self.assertIs(m.completed_citation_request(request,[good]),request)
        self.assertIs(m.completed_citation_request(request,[]),request)

    def test_complete_web_review_uses_lower_thinking_without_changing_tools_or_judgment(self):
        reads=['mcp__security_events__'+n for n in ('get_web_service_target','search_wazuh_alerts','search_web_access')]
        before=copy.deepcopy(self.agent.request)
        with patch.dict(os.environ,{'CAPSTONE_WEB_IMPACT_REVIEW':'1'}), contextlib.redirect_stderr(io.StringIO()):
            result=m.completed_web_review_request(before,self.agent,reads,requirements_complete=True)
        self.assertEqual(result['reasoning_effort'],'none');self.assertEqual(result['max_tokens'],3072)
        self.assertEqual(before,self.agent.request)
        for key in ('tools','tool_choice','messages'):self.assertEqual(result[key],before[key])

    def test_incomplete_unrelated_write_or_other_model_review_keeps_original_profile(self):
        reads=['mcp__security_events__'+n for n in ('get_web_service_target','search_wazuh_alerts','search_web_access')]
        request=self.agent.request
        with patch.dict(os.environ,{'CAPSTONE_WEB_IMPACT_REVIEW':'1'}):
            self.assertIs(m.completed_web_review_request(request,self.agent,reads),request)
            self.assertIs(m.completed_web_review_request(request,self.agent,reads[:-1],requirements_complete=True),request)
            for key in ('CAPSTONE_WEB_IMPACT_REVIEW','CAPSTONE_OPERATOR_REVIEW','CAPSTONE_MANAGEMENT_REVIEW'):
                with patch.dict(os.environ,{key:'0'}):
                    self.assertIs(m.completed_web_review_request(request,self.agent,reads,requirements_complete=True),request)
            with patch.dict(os.environ,{'CAPSTONE_MANAGEMENT_MODE':'manage'}):
                self.assertIs(m.completed_web_review_request(request,self.agent,reads,requirements_complete=True),request)
            self.agent.model='unverified-model'
            self.assertIs(m.completed_web_review_request(request,self.agent,reads,requirements_complete=True),request)

    def test_model_more_evidence_choice_reenters_real_read_selection_with_existing_budget(self):
        import test_soc_management_grounding as g
        f=g.Grounding();f.setUp();f.completed.append('get_operation_status')
        f.agent._capstone_more_evidence_turn=f.agent._current_turn_id
        f.agent._capstone_full_review_turn=f.agent._current_turn_id
        f.agent._capstone_inquiry_receipts=1
        f.kw['assistant_message'].content='추가 근거를 실제 조회하겠습니다.'
        verdict=f.call(f.agent,**f.kw)
        self.assertEqual(verdict.action,'continue')
        self.assertEqual(f.agent._build_api_kwargs()['tool_choice'],'required')
        self.assertIn('model_requested_additional_evidence',f.kw['messages'][-1]['content'])
        self.assertIsNone(f.agent._capstone_more_evidence_turn)
        self.assertEqual(f.agent._capstone_full_review_turn,f.agent._current_turn_id)

    def test_additional_inquiry_requires_real_progress_and_keeps_original_budget(self):
        import test_soc_management_grounding as g
        f=g.Grounding();f.setUp();f.completed.append('get_operation_status')
        f.kw['assistant_message'].content='추가 근거를 실제 조회하겠습니다.'
        def arm(count):
            f.agent._capstone_more_evidence_turn=f.agent._current_turn_id
            f.agent._capstone_inquiry_receipts=count
        arm(1);first=f.call(f.agent,**f.kw);self.assertEqual(first.action,'continue')
        f.kw['codex_ack_continuations']=1
        arm(1);self.assertEqual(f.call(f.agent,**f.kw),'original')
        arm(2);second=f.call(f.agent,**f.kw);self.assertEqual(second.action,'continue')
        f.kw['codex_ack_continuations']=2
        arm(3);third=f.call(f.agent,**f.kw);self.assertEqual(third.action,'continue')
        f.kw['codex_ack_continuations']=3
        arm(4);self.assertEqual(f.call(f.agent,**f.kw),'original')
        self.assertEqual(f.agent._capstone_inquiry_retries,(f.agent._current_turn_id,(1,2,3)))

if __name__=='__main__':unittest.main()
