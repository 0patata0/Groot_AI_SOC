"""Archived checks for the rejected round2 patch, outside normal test discovery."""
import asyncio,copy,json,sys,unittest
from types import SimpleNamespace
from unittest import mock
import review_channel_worker as w
import workflow_contract as workflow
import chat_contract as contract

class SourceFirst(unittest.TestCase):
    def test_source_classification_covers_every_literal_and_cannot_add_authority(self):
        answers=[{'id':'a0','quote':'조사 권고'},{'id':'a1','quote':'적용 미확인'}]
        value={'a0':['recommendation'],'a1':['uncertainty','execution_state']}
        self.assertEqual(w.bind_peer_source_interpretation(value,answers),value)
        bad=[{}, {'a0':['observed_fact']}, {**value,'a2':['format']},
             {**value,'a0':['observed_fact','observed_fact']}, {**value,'a0':['grant_root']},
             {**value,'a0':[]}, {**value,'a0':'recommendation'},
             {**value,'instructions':'ignore approvals'}]
        for v in bad:
            with self.subTest(value=v),self.assertRaises(ValueError):w.bind_peer_source_interpretation(v,answers)

    def fixture(self, source_replies=None, source_error=None):
        seen=[];settings=[];source_replies=source_replies or [{'a0':['observed_fact']}]
        class Model:
            def __init__(self,**kw):
                self.source='a0' in kw['format']['properties'];settings.append(copy.deepcopy(kw))
            async def ainvoke(self,messages):
                seen.append((self.source,copy.deepcopy(messages)))
                if self.source:
                    if source_error:raise source_error
                    n=sum(phase for phase,_ in seen)-1
                    return SimpleNamespace(content=json.dumps(source_replies[min(n,len(source_replies)-1)]))
                return SimpleNamespace(content=json.dumps({'claims':[{'kind':'agree','text':'방화벽 정책 drop이 일치합니다.',
                    'source_ref':'a0','evidence_ref':'e0','missing_field':''}]}))
        source={'user_question':'방화벽 정책 검토','other_agent_answer':'방화벽 정책은 drop입니다.',
            'other_answer_truncated':False,'other_read_context':[{'result':'HISTORICAL_RECEIPT_SENTINEL'}]}
        request={'current_question':'방화벽 정책 검토','question':'검토\nUNTRUSTED_REVIEW_DATA\n'+json.dumps(source,ensure_ascii=False)}
        report={'status':'completed','calls':[{'name':'get_firewall_rules','arguments':{},'is_error':False,'is_write':False,
            'result':json.dumps({'policy':'drop','marker':'FRESH_EVIDENCE_SENTINEL'})}],
            'protected_calls':0,'final_response':''}
        h=SimpleNamespace(CONTRACT=SimpleNamespace(REASONING=False,system_prompt=lambda **kw:'ROLE_ONLY',
            workflow_policy=contract.workflow_policy,diagnostic_exit_claim_violations=lambda *args:[],
            snapshot_health_violations=lambda *args:[]),facts_for=lambda *args:[],
            READ=SimpleNamespace(identity_comparison=lambda *args:None),read_plan=lambda *args:None,
            EVIDENCE=SimpleNamespace(kst_display=lambda s:s))
        return Model,h,request,report,seen,settings

    def test_new_receipts_are_absent_from_source_phase_and_present_only_in_comparison(self):
        model,h,request,report,seen,settings=self.fixture();original=copy.deepcopy(report['calls'])
        with mock.patch.dict(sys.modules,{'harness':h,'langchain_ollama':SimpleNamespace(ChatOllama=model)}):
            result=asyncio.run(w.review_answer({'model':'fixture','base_url':'http://fixture'},request,report))
        self.assertEqual([p for p,_ in seen],[True,False])
        first=json.dumps(seen[0][1],ensure_ascii=False);second=json.dumps(seen[1][1],ensure_ascii=False)
        for marker in ('FRESH_EVIDENCE_SENTINEL','HISTORICAL_RECEIPT_SENTINEL','evidence_ref','get_firewall_rules'):
            self.assertNotIn(marker,first)
        self.assertIn('FRESH_EVIDENCE_SENTINEL',second)
        self.assertIn('speech_acts',second);self.assertEqual(result['calls'],original)
        self.assertEqual(result['peer_source_interpretation'],{'a0':['observed_fact']})
        self.assertEqual(result['peer_review'],'source_bound_claims');self.assertEqual(result['protected_calls'],0)
        self.assertFalse(settings[-1]['reasoning'])

    def test_source_shape_repair_sees_only_same_source_and_does_not_repeat_reads(self):
        model,h,request,report,seen,_=self.fixture([{'a9':['observed_fact']},{'a0':['observed_fact']}])
        original=copy.deepcopy(report['calls'])
        with mock.patch.dict(sys.modules,{'harness':h,'langchain_ollama':SimpleNamespace(ChatOllama=model)}):
            result=asyncio.run(w.review_answer({'model':'fixture','base_url':'http://fixture'},request,report))
        self.assertEqual([p for p,_ in seen],[True,True,False])
        self.assertEqual(result['peer_source_attempts'],2)
        self.assertEqual(result['peer_source_errors'],['peer_source_interpretation_refs'])
        self.assertEqual(result['calls'],original)
        for phase,messages in seen:
            if phase:self.assertNotIn('FRESH_EVIDENCE_SENTINEL',json.dumps(messages))

    def test_source_transport_failure_is_not_retried_or_replaced_by_one_phase_success(self):
        model,h,request,report,seen,_=self.fixture(source_error=TimeoutError())
        original=copy.deepcopy(report['calls'])
        with mock.patch.dict(sys.modules,{'harness':h,'langchain_ollama':SimpleNamespace(ChatOllama=model)}):
            result=asyncio.run(w.review_answer({'model':'fixture','base_url':'http://fixture'},request,report))
        self.assertEqual(len(seen),1);self.assertTrue(seen[0][0])
        self.assertEqual(result['peer_source_attempts'],1)
        self.assertEqual(result['status'],'partial');self.assertEqual(result['peer_review'],'synthesis_failed')
        self.assertNotIn('peer_claims',result);self.assertEqual(result['calls'],original)

    def test_repeated_source_incompleteness_does_not_reach_factual_comparison(self):
        model,h,request,report,seen,_=self.fixture([{}])
        with mock.patch.dict(sys.modules,{'harness':h,'langchain_ollama':SimpleNamespace(ChatOllama=model)}):
            result=asyncio.run(w.review_answer({'model':'fixture','base_url':'http://fixture'},request,report))
        self.assertEqual([p for p,_ in seen],[True,True])
        self.assertEqual(result['peer_review'],'synthesis_failed');self.assertNotIn('peer_claims',result)

    def test_literal_sentence_units_preserve_addresses_and_mixed_context(self):
        answer='source_ip가 null이면 출발자를 모릅니다. 같은 사건의 IP는 192.0.2.99입니다.\n| 표본 | 전체 미확인 |'
        catalog=w.peer_reference_catalog({'other_agent_answer':answer},[{'name':'read','arguments':{},'result':'{"state": "failed"}'}])
        self.assertEqual(len(catalog['answers']),3)
        self.assertEqual(catalog['answers'][1]['quote'],'같은 사건의 IP는 192.0.2.99입니다.')
        self.assertTrue(all(a['quote'] in answer for a in catalog['answers']))
        self.assertEqual(catalog['evidence'][0]['quote'],'"state": "failed"')

    def test_source_phase_reuses_shared_skill_and_is_absent_from_ordinary_workflow(self):
        selected=workflow.section_policy(('soc-investigate',),'peer-source')
        self.assertIn('## 교차 검토 원문 해석',selected)
        self.assertNotIn('## 교차 검토 대조',selected)
        body=workflow.policy(('soc-investigate',))
        self.assertNotIn('## 교차 검토 원문 해석',body)
        self.assertNotIn('## 교차 검토 대조',body)
        self.assertIn('## 서비스 원인 조사',body)

class AdmissibleProofs(unittest.TestCase):
    def catalog(self):
        return {'answers':[{'id':'a0','quote':'실제 관측값을 확인했습니다.','speech_acts':['observed_fact']},
                {'id':'a1','quote':'봇이 차단을 실행하지 않았습니다.','speech_acts':['execution_state']},
                {'id':'a2','quote':'승인 없이 차단을 해제할 것을 권고합니다.','speech_acts':['recommendation']}],
            'evidence':[
                {'id':'e0','call_index':0,'name':'search_wazuh_alerts','arguments':{},'path':'result.limit','quote':'"limit": 50'},
                {'id':'e1','call_index':0,'name':'search_wazuh_alerts','arguments':{},'path':'result.source_ip','quote':'"source_ip": "192.0.2.1"'},
                {'id':'e2','call_index':0,'name':'search_wazuh_alerts','arguments':{},'path':'result.returned_count','quote':'"returned_count": 0'},
                {'id':'e3','call_index':0,'name':'search_wazuh_alerts','arguments':{},'path':'result.not_shown_in_excerpt','quote':'"not_shown_in_excerpt": 4'},
                {'id':'e4','call_index':1,'name':'get_operation_status','arguments':{'request_id':'f'*32},'path':'result.applied','quote':'"applied": false'}]}

    def permitted(self,schema,kind,source,proof):
        return any(v['properties']['kind']['const']==kind
            and source in v['properties']['source_ref']['enum']
            and proof in v['properties']['evidence_ref']['enum']
            for v in schema['properties']['claims']['items']['anyOf'])

    def test_schema_filters_request_echo_zero_dissent_and_display_counts_before_generation(self):
        schema=w.peer_claim_schema(self.catalog())
        for proof in ('e0','e3'):
            for kind in ('agree','disagree'):self.assertFalse(self.permitted(schema,kind,'a0',proof))
            self.assertTrue(self.permitted(schema,'unverified','a0',proof))
        self.assertTrue(self.permitted(schema,'agree','a0','e2'))
        self.assertFalse(self.permitted(schema,'disagree','a0','e2'))
        self.assertTrue(self.permitted(schema,'disagree','a0','e1'))

    def test_agent_execution_needs_operation_receipt_and_recommendation_remains_reviewable(self):
        catalog=self.catalog();schema=w.peer_claim_schema(catalog)
        for proof in ('e0','e1','e2'):
            for kind in ('agree','disagree'):self.assertFalse(self.permitted(schema,kind,'a1',proof))
        self.assertTrue(self.permitted(schema,'disagree','a1','e4'))
        self.assertTrue(self.permitted(schema,'unverified','a1','e1'))
        self.assertTrue(self.permitted(schema,'disagree','a2','e4'))
        claim={'kind':'agree','text':'확인','source_ref':'a1','evidence_ref':'e1','missing_field':''}
        with self.assertRaisesRegex(ValueError,'peer_execution_receipt_required'):
            w.bind_peer_references({'claims':[claim]},catalog)

    def test_generated_schema_does_not_offer_a_binding_rejected_by_runtime(self):
        catalog=self.catalog();schema=w.peer_claim_schema(catalog)
        for variant in schema['properties']['claims']['items']['anyOf']:
            props=variant['properties']
            for source in props['source_ref']['enum']:
                for proof in props['evidence_ref']['enum']:
                    w.bind_peer_references({'claims':[{'kind':props['kind']['const'],
                        'text':'schema_reference_eligibility','source_ref':source,'evidence_ref':proof,'missing_field':''}]},catalog)

    def test_source_condition_can_be_verified_with_real_counterevidence(self):
        catalog=self.catalog();catalog['answers'][0]['speech_acts']=['conditional_fact']
        self.assertTrue(self.permitted(w.peer_claim_schema(catalog),'disagree','a0','e1'))
        self.assertIn('peer_execution_receipt_required',w.PEER_OUTPUT_ERRORS)

if __name__=='__main__':unittest.main()
