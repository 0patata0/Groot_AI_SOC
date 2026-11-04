"""Actual receipt/citation boundaries shared with Native; no model or dispatch."""
from datetime import datetime
import copy
import hashlib
import json
import unittest
import harness as h

QUESTION='실제 탐지 사건의 침해 영향과 종결 가능 여부를 조사해줘'
WAF='mcp__security_events__search_modsecurity_alerts'
HOST='mcp__security_events__search_wazuh_alerts'
AT='2026-11-04T14:48:02+09:00'
IP='192.0.2.40'

def call(server,name,args,data,error=False):
    raw=json.dumps(data)
    return {'server':server,'name':name,'arguments':args,'result':raw,'result_sha256':hashlib.sha256(raw.encode()).hexdigest(),'is_error':error}

def sensor():
    return call('security-events','search_modsecurity_alerts',{},
        {'source':'modsecurity','source_scope':'wazuh_indexed_alerts','alerts':[{'timestamp':AT,'source_ip':IP,'wazuh_rule_id':'100102'}]})

def host(**changes):
    args={'agent_id':'002','since_kst':'2026-11-04T14:48:00+09:00','until_kst':'2026-11-04T14:49:00+09:00'};args.update(changes)
    return call('security-events','search_wazuh_alerts',args,{'source':'wazuh','source_scope':'wazuh_indexed_alerts',
        'requested_since_kst':'2026-11-04T14:48:00+09:00','requested_until_kst':'2026-11-04T14:49:00+09:00','alerts':[]})

def status(ip=IP,reference='request_id'):
    return call('rule-a','get_operation_status',{'target':'a:incident-ip','request_id':'a'*32},
        {'target':'a:incident-ip','ip':ip,reference:'a'*32,'status':'expired'})

def decision(assessment='remediated',tools=(WAF,HOST)):
    return '실제 조회 범위와 미확인 사항을 구분한 보고입니다.\nINCIDENT_DISPOSITION: '+json.dumps({
        'assessment':assessment,'basis':'실제 도구 반환 근거와 남은 확인 범위를 별도로 검토한 판단입니다.','evidence_tools':list(tools)},ensure_ascii=False)

class Completion(unittest.TestCase):
    def test_remediated_sensor_requires_agent_time_receipt_and_real_citation(self):
        calls=[sensor(),host()];before=copy.deepcopy(calls)
        self.assertEqual(h.incident_completion_issues(QUESTION,decision(),calls),[])
        self.assertEqual(calls,before)
        self.assertIn('incident_disposition_evidence_missing',h.incident_completion_issues(QUESTION,decision(),[sensor()]))
        self.assertIn('incident_impact_verification_missing',h.incident_completion_issues(QUESTION,decision(tools=(WAF,)),[sensor()]))
        self.assertIn('incident_impact_verification_missing',h.incident_completion_issues(QUESTION,decision(tools=(WAF,)),calls))

    def test_each_filtered_or_wrong_window_query_fails_the_shared_contract(self):
        for args in ({'source_ip':IP},{'wazuh_rule_id':'100102'},{'agent_id':'x'},{'since_kst':'2026-11-04T15:00:00+09:00'}):
            with self.subTest(args=args):self.assertIn('incident_impact_verification_missing',h.incident_completion_issues(QUESTION,decision(),[sensor(),host(**args)]))

    def test_wrong_agent_rows_and_tampered_result_are_not_receipts(self):
        c=host();data=json.loads(c['result']);data['alerts']=[{'agent_id':'003','timestamp':AT}];c=call(c['server'],c['name'],c['arguments'],data)
        self.assertIn('incident_impact_verification_missing',h.incident_completion_issues(QUESTION,decision(),[sensor(),c]))
        c=host();c['result_sha256']='0'*64
        self.assertIn('incident_disposition_evidence_missing',h.incident_completion_issues(QUESTION,decision(),[sensor(),c]))
        self.assertFalse(h.facts_for([c]))

    def test_returned_host_rows_must_match_the_claimed_window_and_count(self):
        for extra in ({'alerts':[{'agent_id':'002','timestamp':'2026-11-04T15:00:00+09:00'}]},
                      {'alerts':[{'agent_id':'002'}]},{'returned_count':1},{'returned_count':True}):
            c=host();data=json.loads(c['result']);data.update(extra);c=call(c['server'],c['name'],c['arguments'],data)
            with self.subTest(extra=extra):self.assertIn('incident_impact_verification_missing',h.incident_completion_issues(QUESTION,decision(),[sensor(),c]))

    def test_benign_without_response_and_unresolved_do_not_force_external_asset(self):
        self.assertEqual(h.incident_completion_issues(QUESTION,decision('benign',(WAF,)),[sensor()]),[])
        self.assertEqual(h.incident_completion_issues(QUESTION,decision('unresolved',(WAF,)),[sensor()]),[])

    def test_benign_with_related_status_requires_impact_for_both_id_spellings(self):
        for field in ('request_id','proposal_id'):
            with self.subTest(field=field):
                calls=[sensor(),status(reference=field)]
                self.assertIn('incident_impact_verification_missing',h.incident_completion_issues(QUESTION,decision('benign',(WAF,)),calls))
                self.assertEqual(h.incident_completion_issues(QUESTION,decision('benign'),calls+[host()]),[])
        self.assertEqual(h.incident_completion_issues(QUESTION,decision('benign',(WAF,)),[sensor(),status(ip='192.0.2.41')]),[])

    def test_missing_duplicate_or_unobserved_decisions_are_not_silent_success(self):
        self.assertIn('incident_disposition_missing',h.incident_completion_issues(QUESTION,'사건은 정상으로 종결합니다.',[sensor()]))
        malformed='INCIDENT_DISPOSITION: {"assessment":"benign","assessment":"unresolved"}'
        self.assertIn('incident_disposition_invalid',h.incident_completion_issues(QUESTION,malformed,[sensor()]))
        self.assertIn('incident_disposition_missing',h.incident_completion_issues(QUESTION,decision()+'\n'+decision(),[sensor(),host()]))

    def test_zero_or_failed_event_read_cannot_support_benign_or_fake_citation(self):
        c=sensor();data=json.loads(c['result']);data['alerts']=[];c=call(c['server'],c['name'],{},data)
        self.assertIn('incident_event_verification_missing',h.incident_completion_issues(QUESTION,decision('benign',(WAF,)),[c]))
        self.assertEqual(h.incident_completion_issues(QUESTION,decision('unresolved',(WAF,)),[c]),[])
        c['is_error']=True
        self.assertIn('incident_disposition_evidence_missing',h.incident_completion_issues(QUESTION,decision('unresolved',(WAF,)),[c]))

    def test_malformed_time_source_or_identity_cannot_support_positive_decision(self):
        for field,value in (('timestamp',None),('source_ip',None),('source','suricata')):
            c=sensor();d=json.loads(c['result'])
            if field=='source':d[field]=value
            else:d['alerts'][0][field]=value
            c=call(c['server'],c['name'],{},d)
            with self.subTest(field=field):self.assertIn('incident_event_verification_missing',h.incident_completion_issues(QUESTION,decision('benign',(WAF,)),[c]))

    def test_plain_lookup_and_change_are_not_reclassified_as_incident_closure(self):
        for question in ('DVWA 접근 기록 보여줘','WAF 룰 수정안을 작성해줘'):
            self.assertEqual(h.incident_completion_issues(question,'조회 결과입니다.',[sensor()]),[])

    def test_public_output_hides_internal_metadata_only_after_audit(self):
        text=decision('unresolved',(WAF,))+'\nMANAGEMENT_STATUS: needs_review'
        public=h.footer_free(text);self.assertNotIn('INCIDENT_DISPOSITION',public);self.assertNotIn('MANAGEMENT_STATUS',public)
        self.assertIn('실제 조회',public);self.assertEqual(h.incident_completion_issues(QUESTION,text,[sensor()]),[])

if __name__=='__main__':unittest.main()
