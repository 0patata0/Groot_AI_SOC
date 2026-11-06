"""Shared native/SDK bundle evidence; no model, SSH or dispatch."""
from pathlib import Path
import copy
import hashlib
import json
import sys
import unittest
sys.path.insert(0,str(Path(__file__).parents[1]/'hermes'))
import test_soc_management_bundle as f
import harness as h

QUESTION='이 실제 사건의 침해 영향과 현재 c:apache 상태를 조사하고 종결 가능한지 보고해줘'

def call(value=None,params=None):
    raw=json.dumps(f.fixture() if value is None else value,ensure_ascii=False)
    return {'server':'security-events','name':'collect_incident_evidence','arguments':f.args() if params is None else params,
        'result':raw,'result_sha256':hashlib.sha256(raw.encode()).hexdigest(),'is_error':False}

def decision(names=(f.w.BUNDLE_TOOL,)):
    return 'INCIDENT_DISPOSITION: '+json.dumps({'assessment':'remediated','basis':'실제 조회한 사건 구간과 백엔드 자료를 비교하고 판단 근거를 제시합니다.','evidence_tools':list(names)},ensure_ascii=False)

class SharedBundle(unittest.TestCase):
    def test_sdk_model_view_does_not_modify_audit_or_original_grounding_facts(self):
        from test_soc_management_web_view import evidence
        def reader(name,params):
            value=f.read(name,params)
            if name=='search_web_access':value.update(evidence())
            return value
        original=call(f.fixture(reader=reader));before=copy.deepcopy(original)
        facts=h.facts_for([original]);shown=h.model_view('security-events','collect_incident_evidence',original['result'])
        self.assertLess(len(shown),len(original['result'])*.9)
        self.assertEqual(original,before);self.assertEqual(h.facts_for([original]),facts)
        self.assertFalse(h.incident_evidence_gap(QUESTION,[original]))

    def test_component_view_keeps_actual_wire_calls_and_parent_identity(self):
        calls=[call()];before=copy.deepcopy(calls);view=h.evidence_reads(calls)
        self.assertEqual(calls,before);self.assertEqual(len(view.wire_calls),1);self.assertEqual(len(view),5)
        self.assertEqual(len(view.component_origins),5);self.assertIs(h.evidence_reads(view),view)
        self.assertFalse(h.incident_evidence_gap(QUESTION,calls))
        self.assertTrue(h.diagnostic_observations(calls)['c:apache'])
        self.assertTrue(all(x['bundle_component']['transport_tool']==f.w.BUNDLE_TOOL for x in h.facts_for(calls)))

    def test_malformed_bundle_cannot_supply_scope_facts_or_recovery(self):
        value=f.fixture();value['components'][0]['arguments']['source_ip']='192.0.2.99'
        calls=[call(value)];self.assertEqual(h.facts_for(calls),[])
        self.assertTrue(h.incident_evidence_gap(QUESTION,calls))
        self.assertIn('incident_bundle_provenance_invalid',h.violations(QUESTION,'서비스 정상화 확인',calls))

    def test_citation_names_remain_actual_wire_names_not_component_aliases(self):
        calls=[call()]
        self.assertEqual(h.incident_completion_issues(QUESTION,decision(),calls),[])
        fake=('mcp__security_events__search_modsecurity_alerts','mcp__security_events__search_wazuh_alerts')
        self.assertIn('incident_disposition_evidence_missing',h.incident_completion_issues(QUESTION,decision(fake),calls))

    def test_unrelated_actual_host_read_cannot_be_claimed_through_bundle_citation(self):
        params=f.args();params.pop('web_context');value=f.fixture(params)
        host=f.read('search_wazuh_alerts',{'agent_id':'017',**f.WINDOW});raw=json.dumps(host)
        separate={'server':'security-events','name':'search_wazuh_alerts','arguments':{'agent_id':'017',**f.WINDOW},
            'result':raw,'result_sha256':hashlib.sha256(raw.encode()).hexdigest(),'is_error':False}
        calls=[call(value,params),separate]
        self.assertIn('incident_impact_verification_missing',h.incident_completion_issues(QUESTION,decision(),calls))
        self.assertEqual(h.incident_completion_issues(QUESTION,decision((f.w.BUNDLE_TOOL,'mcp__security_events__search_wazuh_alerts')),calls),[])

    def test_failed_last_diagnostic_invalidates_an_earlier_success(self):
        def fail(name,args):
            if name=='get_system_diagnostics':raise OSError('private message')
            return f.read(name,args)
        calls=[call(),call(f.fixture(reader=fail))]
        self.assertIsNone(h.diagnostic_observations(calls)['c:apache'])
        self.assertNotIn('private message',json.dumps(calls))

    def test_followup_prompt_and_agent_schema_use_bound_components(self):
        calls=[call()]
        prompt=h.incident_observation_prompt(QUESTION,calls)
        self.assertIn('bundle_component',prompt)
        self.assertIn(f.w.BUNDLE_TOOL,prompt)
        schema={'mcp__security_events__search_wazuh_alerts':{
            'type':'object','properties':{'agent_id':{'type':'string'}},'additionalProperties':False}}
        refined=h.refine_read_schemas(QUESTION,schema,calls)
        self.assertEqual(refined['mcp__security_events__search_wazuh_alerts']['properties']['agent_id']['enum'],['017'])
        malformed=f.fixture();malformed['components'][0]['arguments']['source_ip']='192.0.2.99'
        refined=h.refine_read_schemas(QUESTION,schema,[call(malformed)])
        self.assertNotIn('agent_id',refined['mcp__security_events__search_wazuh_alerts']['properties'])
