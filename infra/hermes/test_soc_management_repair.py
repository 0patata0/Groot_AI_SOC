"""Bound one literal repair while preserving assessment, tools and authority."""
import copy
import contextlib
import io
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

if __name__=='__main__':unittest.main()
