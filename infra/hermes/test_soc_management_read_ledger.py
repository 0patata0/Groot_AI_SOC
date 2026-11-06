"""Actual-dispatch provenance and supplied identifiers; no network or writes."""
import copy
import hashlib
import importlib.util
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from unittest.mock import patch
import unittest

from test_soc_management_run import wrapper as w, Harness, controller
from test_soc_management_selection import agent, request, NAME

ENV={'CAPSTONE_MANAGEMENT_MODE':'verify','CAPSTONE_MANAGEMENT_REVIEW':'1',
     'CAPSTONE_WEB_IMPACT_REVIEW':'1','CAPSTONE_OPERATOR_REVIEW':'1'}
REFS=[{'proposal_id':'a'*32,'target':'a:incident-ip'},
      {'proposal_id':'b'*32,'target':'b:wazuh-local-rules'}]
def context(refs=None,complete=True,reason='현재 차단과 웹 영향 확인'):
    return {'case_id':'c'*32,'operator_reason':reason,'mode':'verify','purpose':'후속 조사',
            'evidence_scope':{'status_references':REFS if refs is None else refs,'status_references_complete':complete}}
def activate(ctx):
    return patch.dict(w.os.environ,{**ENV,'CAPSTONE_REVIEW_CONTEXT_JSON':json.dumps(ctx)},clear=True)
def schema(name):
    key='proposal_id' if name.endswith('change_status') else 'request_id'
    return {'type':'object','additionalProperties':False,'required':[key],
            'properties':{key:{'type':'string','pattern':'^[0-9a-f]{32}$'}}}

class SuppliedReferences(unittest.TestCase):
    def test_exact_ids_are_typed_and_literal_operator_id_is_preserved(self):
        with activate(context(reason='추가로 '+ 'd'*32 +' 조회')):
            self.assertEqual(w.review_status_ids(NAME),['a'*32,'d'*32])
            self.assertEqual(w.review_status_ids('mcp__rule_b__get_rule_change_status'),['b'*32,'d'*32])
            self.assertEqual(w.review_status_ids('mcp__rule_a__get_rule_change_status'),['d'*32])
            self.assertIsNone(w.review_status_ids('mcp__resp__list_blocks'))

    def test_malformed_incomplete_legacy_and_wrong_mode_preserve_ordinary_schema(self):
        for refs,complete in [(None,False),([{'proposal_id':'bad','target':'a:incident-ip'}],True),('bad',True)]:
            with activate(context(refs,complete)):
                self.assertIsNone(w.review_status_ids(NAME))
                self.assertEqual(w.known_status_selection_schema(NAME,schema(NAME),[]),schema(NAME))
        with activate(context()),patch.dict(w.os.environ,{'CAPSTONE_MANAGEMENT_MODE':'manage'}):
            self.assertIsNone(w.review_status_ids(NAME))

    def test_untrusted_log_ids_do_not_become_status_input(self):
        ctx=context();ctx['evidence_scope']['log_text']='request_id='+ 'd'*32
        with activate(ctx):self.assertEqual(w.review_status_ids(NAME),['a'*32])

    def test_same_id_can_have_two_explicit_types_without_cross_host_guessing(self):
        refs=[REFS[0],{'proposal_id':'a'*32,'target':'b:wazuh-local-rules'}]
        with activate(context(refs)):
            self.assertEqual(w.review_status_ids(NAME),['a'*32])
            self.assertEqual(w.review_status_ids('mcp__rule_b__get_rule_change_status'),['a'*32])
            self.assertEqual(w.review_status_ids('mcp__rule_b__get_operation_status'),[])

    @unittest.skipUnless(importlib.util.find_spec('jsonschema'),'existing server jsonschema required')
    def test_mutated_identifier_is_rejected_and_source_schema_is_immutable(self):
        from jsonschema import Draft202012Validator
        source=schema(NAME);original=copy.deepcopy(source)
        with activate(context()):selected=w.known_status_selection_schema(NAME,source,REFS)
        self.assertEqual(source,original);self.assertEqual(selected['properties']['request_id']['type'],'string')
        validator=Draft202012Validator(selected)
        for value in ('a'*31+'f','b'*32,{},None):self.assertFalse(validator.is_valid({'request_id':value}))
        self.assertTrue(validator.is_valid({'request_id':'a'*32}))

    def test_root_includes_later_references_and_marks_truncation(self):
        at=controller.datetime.now(w.KST)
        ctx={'events':[],'sensor_references':[('suricata','192.0.2.20',at.timestamp()-120,'100110')],
             'sensor_references_complete':True,'evidence_truncated':False,'later_proposals_truncated':False,
             'proposals':[{'id':'a'*32,'target':'a:incident-ip'}],
             'later_proposals':[{'id':'b'*32,'target':'b:wazuh-local-rules'}]}
        from unittest.mock import Mock
        store=Mock();store.context.return_value=ctx
        value=controller.verification_case(store,{'id':'c'*32,'mode':'verify','session_id':None},at)
        self.assertEqual(value['compact_review_evidence_scope']['status_references'],REFS)
        self.assertTrue(value['compact_review_evidence_scope']['status_references_complete'])
        ctx['later_proposals_truncated']=True
        self.assertFalse(controller.verification_case(store,{'id':'c'*32,'mode':'verify'},at)
                         ['compact_review_evidence_scope']['status_references_complete'])

class CompletedDispatches(unittest.TestCase):
    def test_exact_arguments_hash_and_kst_do_not_claim_success(self):
        args={'request_id':'a'*32};raw='{"state":"unknown"}'
        row=w.read_ledger_entry(NAME,args,raw)
        self.assertEqual(row['arguments'],args);self.assertEqual(row['result_sha256'],hashlib.sha256(raw.encode()).hexdigest())
        self.assertEqual(row['result_state'],'returned');self.assertTrue(row['completed_at_kst'].endswith('+09:00'))
        args['request_id']='changed';self.assertEqual(row['arguments']['request_id'],'a'*32)
        self.assertNotIn('healthy',row);self.assertNotIn('success',row)

    def test_nested_and_outer_errors_are_not_discarded(self):
        for value in ({'error':'unavailable'},{'result':'{}','isError':True},
                      {'result':'{"error":"missing"}'},{'is_error':True}):
            self.assertEqual(w.read_ledger_entry(NAME,{},value)['result_state'],'error')

    def test_unsupported_oversize_ambiguous_and_nonfinite_data_is_not_fabricated(self):
        for raw in ('plain text','{"error":true,"error":false}','{"value":NaN}',
                    {'result':'{"value":Infinity}'},'x'*(w.MAX_EVENT_AUDIT_BYTES+1)):
            self.assertIsNone(w.read_ledger_entry(NAME,{},raw))
        self.assertIsNone(w.read_ledger_entry(NAME,{'v':float('nan')},'{}'))
        self.assertIsNone(w.read_ledger_entry(NAME,{'v':'x'*8193},'{}'))
        self.assertIsNone(w.read_ledger_entry('mcp__resp__unblock_ip',{},'{}'))
        self.assertIsNone(w.read_ledger_entry('terminal',{},'{}'))

    def test_view_is_copy_and_missing_or_overflow_is_not_empty_success(self):
        row=w.read_ledger_entry(NAME,{},'{}');rows=[row]
        view=w.read_ledger_view(rows);view['rows'][0]['arguments']['new']=1
        self.assertEqual(rows,[row]);self.assertEqual(row['arguments'],{})
        self.assertIsNone(w.read_ledger_view(None));self.assertIsNone(w.read_ledger_view([row]*129))
        self.assertIsNone(w.read_ledger_view([dict(row,result_state='healthy')]))
        self.assertEqual(w.read_ledger_view([])['count'],0)

    def capture(self,h):
        with patch.object(w,'completed_web_review_request',side_effect=lambda r,*a,**kw:dict(r,ledger_test=True)):
            agent=h.AIAgent();agent._build_api_kwargs()
            return agent._capstone_management_report['read_ledger']

    def test_parallel_same_name_completions_bind_their_own_arguments(self):
        h=Harness();h.registry.dispatch=lambda name,args,**kw:json.dumps({'echo':args['request_id']})
        def check(h):
            with ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(lambda i:h.registry.dispatch(NAME,{'request_id':f'{i:032x}'}),range(8)))
            rows=self.capture(h);self.assertEqual(len(rows),8)
            for row in rows:
                raw=json.dumps({'echo':row['arguments']['request_id']})
                self.assertEqual(row['result_sha256'],hashlib.sha256(raw.encode()).hexdigest())
            self.assertEqual(h.wire_calls,[]) # dispatch metadata alone is not wire proof
        h.run(check,'verify')

    def test_errors_are_recorded_but_exceptions_and_prevalidation_refusals_are_not(self):
        h=Harness();h.registry.dispatch=lambda name,args,**kw:'{"error":"unavailable"}'
        def check(h):
            h.registry.dispatch(NAME,{'request_id':'a'*32})
            with patch.object(w,'known_status_input_rejection',return_value={'error':'mismatch'}):
                h.registry.dispatch(NAME,{'request_id':'b'*32})
            rows=self.capture(h);self.assertEqual(len(rows),1);self.assertEqual(rows[0]['result_state'],'error')
        h.run(check,'verify')
        h=Harness()
        def fail(*a,**kw):raise RuntimeError('native failure')
        h.registry.dispatch=fail
        def check_failed(h):
            with self.assertRaisesRegex(RuntimeError,'native failure'):h.registry.dispatch(NAME,{'request_id':'a'*32})
            self.assertEqual(self.capture(h),[])
        h.run(check_failed,'verify')

    def test_overflow_or_unparseable_completion_marks_ledger_unavailable(self):
        for raw,count in [('{}',129),('not json',1)]:
            h=Harness();h.registry.dispatch=lambda *a,**kw:raw
            def check(h):
                for _ in range(count):h.registry.dispatch(NAME,{'request_id':'a'*32})
                self.assertIsNone(self.capture(h))
            h.run(check,'verify')

@unittest.skipUnless(importlib.util.find_spec('jsonschema'),'existing server jsonschema required')
class ReportLedger(unittest.TestCase):
    def prepare(self):
        a=agent();r=request();r['tool_choice']='auto';r['tools'][0]['function']['parameters']=schema(NAME)
        snap={'turn':a._current_turn_id,'reads':[NAME],'facts':[{'kind':'blocks','count':0}],
              'receipts':[{'tool':NAME,'output':'{"state":"unknown"}','is_error':False}],
              'read_ledger':[w.read_ledger_entry(NAME,{'request_id':'a'*32},'{"state":"unknown"}')]}
        return a,r,snap

    def test_model_gets_ledger_and_full_receipts_without_losing_tool_capability(self):
        a,r,snap=self.prepare();other='mcp__rule_b__get_operation_status';a.valid_tool_names.add(other)
        r['tools'].append({'type':'function','function':{'name':other,'parameters':schema(other)}})
        before=copy.deepcopy((r,snap))
        with activate(context()):wire=w.management_report_request(r,a,snap)
        value=json.loads(wire['messages'][-1]['content'])
        self.assertEqual(value['completed_read_ledger']['rows'],snap['read_ledger'])
        self.assertEqual(value['untrusted_current_receipts'][0]['output'],{'state':'unknown'})
        self.assertIn(other,value['available_read_tools']);self.assertEqual(value['reference_bound_status_reads'][other],[])
        self.assertIn(other,a.valid_tool_names);self.assertIn(other,a._capstone_management_selection['catalog'])
        self.assertEqual((r,snap),before)

    def test_missing_ledger_is_not_claimed_complete_and_no_ids_still_allows_report(self):
        from jsonschema import Draft202012Validator
        a,r,snap=self.prepare();snap['read_ledger']=None
        with activate(context([])):wire=w.management_report_request(r,a,snap)
        value=json.loads(wire['messages'][-1]['content'])
        self.assertIsNone(value['completed_read_ledger'])
        schema_out=wire['response_format']['json_schema']['schema'];Draft202012Validator.check_schema(schema_out)
        self.assertEqual(len(schema_out['anyOf']),1);self.assertNotIn('$defs',schema_out)
        self.assertIn(NAME,a._capstone_management_selection['catalog'])

    def test_pending_query_without_identifier_fails_before_provider_not_invalid_schema(self):
        a,r,_=self.prepare();r['tool_choice']='required'
        with activate(context([])),patch.object(w,'indexed_read_request',return_value=None):
            with self.assertRaisesRegex(RuntimeError,'status_reference_missing'):
                w.management_read_request(r,a,pending=True)

    def test_complete_receipt_citations_are_fixed_not_repaired_by_fabrication(self):
        from jsonschema import Draft202012Validator
        a,r,snap=self.prepare();other='mcp__resp__list_blocks';a.valid_tool_names.add(other)
        r['tools'].append({'type':'function','function':{'name':other,'parameters':{'type':'object'}}})
        snap['reads'].append(other);snap['receipts'].append({'tool':other,'output':'{}','is_error':False})
        with activate(context()):wire=w.management_report_request(r,a,snap)
        prop=wire['response_format']['json_schema']['schema']['anyOf'][1]['properties']['report']['properties']['evidence_indexes']
        v=Draft202012Validator(prop);self.assertTrue(v.is_valid([0,1]))
        for value in ([0,0],[0],[0,1,2],[1,0]):self.assertFalse(v.is_valid(value))
        self.assertEqual(prop['const'],list(range(len(snap['reads']))))
        self.assertEqual(len(a._capstone_management_selection['catalog']),2)

class CollectionEvidence(unittest.TestCase):
    def setUp(self):
        self.facts=[{'kind':'web_service','logging_continuity_verified':False},
                    {'kind':'web_access','logging_continuity_verified':False,
                     'returned_count':1,'coverage':{'files_unavailable':0}}]

    def test_unverified_continuity_does_not_prove_outage_or_need_for_recovery(self):
        for text in ('사건 당시 접근 로그 및 서비스 호출 기록의 불연속성으로 영향 확인 불가.',
                     '파일 로그 수집이 복구되면 백엔드 응답을 대조한다.',
                     '접근 로그 수집 장애로 추가 조사가 필요하다.'):
            self.assertIn('web_continuity_unverified_is_not_outage',w.web_evidence_violations(text,self.facts))

    def test_unverified_and_conditional_claims_remain_available(self):
        for text in ('로그 연속성은 미검증이며 추가 확인이 필요하다.',
                     '로그 불연속성은 미확인이다.',
                     '로그 수집 장애가 확인되면 복구한다.',
                     '로그 수집 중단 여부를 확인한다.',
                     '로그 불연속성으로 단정하지 않는다.',
                     '> 파일 로그 수집이 복구되면 확인한다.',
                     '```\n로그 기록 불연속성\n```'):
            self.assertNotIn('web_continuity_unverified_is_not_outage',w.web_evidence_violations(text,self.facts))

    def test_missing_files_or_verified_continuity_are_not_this_narrow_check(self):
        for change in ('missing','verified'):
            facts=copy.deepcopy(self.facts)
            if change=='missing':facts[1]['coverage']['files_unavailable']=1
            else:facts[1]['logging_continuity_verified']=True
            self.assertNotIn('web_continuity_unverified_is_not_outage',
                             w.web_evidence_violations('로그 수집 장애로 기록 불연속성 확인.',facts))
