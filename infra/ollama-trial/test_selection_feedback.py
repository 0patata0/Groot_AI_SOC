"""Regression for observed truncated plans and invented agent IDs."""
import hashlib
import importlib.util
import json
import types
import unittest
import harness as h

HOST='mcp__security_events__search_wazuh_alerts'
Q='2026-11-04 DVWA 사건의 실제 영향과 종결 가능 여부를 조사해줘'

def schemas():
    return {HOST:{'type':'object','properties':{'agent_id':{'type':'string'},'limit':{'type':'integer'}},'additionalProperties':False}}

def receipt(name,data):
    raw=json.dumps(data)
    return {'server':'security-events','name':name,'arguments':{},'result':raw,'result_sha256':hashlib.sha256(raw.encode()).hexdigest(),'is_error':False}

class SelectionFeedback(unittest.TestCase):
    def test_small_batch_keeps_global_budget_separate(self):
        for budget in (1,3,4,12,32):
            self.assertEqual(h.selection_schema(schemas(),budget)['properties']['calls']['maxItems'],min(4,budget))

    def test_unknown_agent_not_guessed_from_ip_date_or_rule_id(self):
        for question in (Q,Q+' 출발지192.0.2.123',Q+' 규칙 ID 123'):
            self.assertNotIn('agent_id',h.refine_read_schemas(question,schemas(),[])[HOST]['properties'])
        self.assertIn('agent_id',schemas()[HOST]['properties'])

    def test_user_scope_is_allowed_without_treating_it_as_observed(self):
        narrowed=h.refine_read_schemas(Q+' agent_id=127',schemas(),[])
        self.assertEqual(narrowed[HOST]['properties']['agent_id']['enum'],['127'])
        self.assertTrue(h.incident_evidence_gap(Q,[]))

    def test_only_verified_registration_can_extend_scope(self):
        for agent in ('017','129'):
            call=receipt('get_web_service_target',{'source':'c_apache_access_snapshot','agent':{'id':agent,'name':'backend'}})
            self.assertEqual(h.refine_read_schemas(Q,schemas(),[call])[HOST]['properties']['agent_id']['enum'],[agent])
            call['result']+=' '
            self.assertNotIn('agent_id',h.refine_read_schemas(Q,schemas(),[call])[HOST]['properties'])

    def test_verified_inventory_does_not_make_up_missing_agents(self):
        call=receipt('get_wazuh_agents',{'result':'Agent ID: 023\nName: backend\nIP: 192.0.2.21\nStatus: active\n'})
        call['server']='wazuh-ro'
        self.assertEqual(h.refine_read_schemas(Q,schemas(),[call])[HOST]['properties']['agent_id']['enum'],['023'])
        call['is_error']=True
        self.assertNotIn('agent_id',h.refine_read_schemas(Q,schemas(),[call])[HOST]['properties'])

    @unittest.skipUnless(importlib.util.find_spec('jsonschema'),'installed validator only')
    def test_real_validator_rejects_oversized_batch_and_unobserved_agent(self):
        from jsonschema import ValidationError
        narrowed=h.refine_read_schemas(Q+' agent_id=127',schemas(),[])
        schema=h.selection_schema(narrowed,32)
        with self.assertRaises(ValidationError):
            h.validated_selection({'calls':[{'tool':HOST,'arguments':{'agent_id':'999'}}]},schema)
        with self.assertRaises(ValidationError):
            h.validated_selection({'calls':[{'tool':HOST,'arguments':{'agent_id':'127','limit':i}} for i in range(1,6)]},schema)

    def test_failed_incident_report_retains_backend_evidence_and_limits_in_table(self):
        call=receipt('search_web_access',{'source':'c_apache_access_snapshot','target':'c:example',
            'returned_count':0,'retained_index_match_count':0,'actual_request_total_count':None,
            'coverage':{'rows_truncated':True}})
        answer=h.fallback(Q,[call])
        self.assertIn('| 확인 항목 | 조회 결과 | 근거·범위 |',answer)
        self.assertIn('c:example 웹 근거',answer)
        self.assertIn('보관 행 상한으로 잘림',answer)
        self.assertIn('검증 미완료',answer)
        self.assertNotIn('MANAGEMENT_STATUS:',answer)

    def test_inventory_is_navigation_and_cannot_complete_incident(self):
        scope=h.incident_selection_scope(Q,[])
        self.assertIn('mcp__wazuh_ro__get_wazuh_agents',scope)
        self.assertIn('mcp__security_events__get_web_service_target',scope)
        self.assertTrue(h.incident_evidence_gap(Q,[receipt('get_web_service_target',{'agent':{'id':'017'}})]))

    def test_feedback_contains_structure_without_model_argument_content(self):
        plan={'calls':[{'tool':HOST,'arguments':{'secret':'DO-NOT-ECHO'}},{'tool':HOST}]}
        error=types.SimpleNamespace(validator='required',absolute_path=('calls',1))
        feedback=h.selection_error_feedback(error,plan,h.selection_schema(schemas(),32))
        self.assertEqual(feedback['missing_arguments_at'],[1])
        self.assertEqual(feedback['path'],['calls',1])
        self.assertEqual(feedback['selected_calls'],2)
        self.assertNotIn('DO-NOT-ECHO',json.dumps(feedback))

if __name__=='__main__':unittest.main()
