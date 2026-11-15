"""Same-turn read-attempt provenance and outcome counterexamples; no network."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(os.environ.get('SOC_ATTEMPT_ROOT', Path(__file__).resolve().parents[3])).resolve()
sys.path[:0] = [str(ROOT/'infra/hermes'), str(ROOT/'infra/ollama-trial')]
import soc_management_run as gate
WAZUH = 'mcp__security_events__search_wazuh_alerts'
SURI = 'mcp__security_events__search_suricata_alerts'
DIAG = 'mcp__system_diagnostics__get_system_diagnostics'


def receipt(tool=WAZUH, data=None, *, raw=None, phase='returned', flag=False, arguments=None):
    if raw is None:raw = json.dumps(data if data is not None else {'returned_count': 0})
    return {'tool':tool, 'arguments':arguments or {}, 'output':raw,
            'result_sha256':hashlib.sha256(raw.encode()).hexdigest(), 'phase':phase, 'is_error':flag}


def check(text, records=(), complete=True):
    return gate.read_attempt_claim_violations(text, gate.read_attempt_view(list(records), complete=complete))


class AttemptView(unittest.TestCase):
    def test_empty_is_complete_and_not_a_success(self):
        self.assertEqual(gate.read_attempt_view([]), {'complete':True, 'rows':[]})

    def test_returned_empty_sample_is_not_a_security_verdict(self):
        view=gate.read_attempt_view([receipt()]);self.assertTrue(view['complete'])
        self.assertEqual(view['rows'][0]['outcome'], 'returned')
        self.assertFalse({'healthy','benign','resolved','approval'} & set(view['rows'][0]))

    def test_protocol_and_payload_errors_are_preserved(self):
        for r in (receipt(flag=True), receipt(data={'error':'invalid_arguments'}),
                  receipt(data={'result':json.dumps({'error':'backend_timeout'})})):
            with self.subTest(r=r):
                view=gate.read_attempt_view([r]);self.assertTrue(view['complete'])
                self.assertEqual(view['rows'][0]['outcome'], 'reported_error')

    def test_opaque_response_is_kept_without_keyword_error_guessing(self):
        for text in ('historical error: 3 cases', 'plain tool text', ''):
            view=gate.read_attempt_view([receipt(raw=text)])
            self.assertTrue(view['complete']);self.assertEqual(view['rows'][0]['outcome'],'returned')

    def test_real_transport_error_has_no_synthetic_server_result(self):
        view=gate.read_attempt_view([{'tool':WAZUH,'arguments':{},'phase':'transport_error',
            'error_type':'TimeoutError','output':None,'result_sha256':None}])
        self.assertTrue(view['complete']);self.assertEqual(view['rows'][0]['outcome'],'transport_error')
        self.assertIsNone(view['rows'][0]['result_sha256'])
        self.assertFalse(gate.read_attempt_view([{'tool':WAZUH,'arguments':{},'phase':'transport_error',
            'error_type':'TimeoutError','output':'invented error','result_sha256':'0'*64}])['complete'])

    def test_input_rejection_keeps_its_stage(self):
        view=gate.read_attempt_view([receipt(data={'error':'bad_input'},phase='input_rejected')])
        self.assertEqual(view['rows'][0]['outcome'],'input_rejected')

    def test_hash_duplicate_json_and_bounds_do_not_become_empty_provenance(self):
        cases=[dict(receipt(),result_sha256='0'*64), receipt(raw='{"error":false,"error":"x"}'),
               receipt(arguments={'x':'x'*8193}),receipt(raw='x'*(gate.MAX_EVENT_AUDIT_BYTES+1))]
        for r in cases:
            with self.subTest(kind=r.get('phase')):self.assertFalse(gate.read_attempt_view([r])['complete'])
        self.assertFalse(gate.read_attempt_view([receipt()]*129)['complete'])

    def test_pending_and_non_boolean_metadata_remain_unconfirmed(self):
        self.assertFalse(gate.read_attempt_view([{'tool':WAZUH,'arguments':{},'phase':'pending'}])['complete'])
        self.assertFalse(gate.read_attempt_view([dict(receipt(),is_error=1)])['complete'])

    def test_unregistered_write_does_not_become_a_read(self):
        self.assertFalse(gate.read_attempt_view([receipt(tool='mcp__rule_write_a__propose_service_action')])['complete'])
        self.assertFalse(gate.allowed('mcp__rule_write_a__propose_service_action','verify'))


class NativeMessageBinding(unittest.TestCase):
    def messages(self):
        return [{'role':'assistant','tool_calls':[{'id':'x1','function':{'name':WAZUH,'arguments':'{"lookback_minutes":15}'}}]},
                {'role':'tool','tool_call_id':'x1','content':'{"error":"timeout"}'}]

    def test_only_actual_linked_current_tool_reply_counts(self):
        result=gate.read_attempts_from_messages(self.messages());self.assertTrue(result['complete'])
        self.assertEqual(result['rows'][0]['tool'],WAZUH)
        self.assertEqual(result['rows'][0]['arguments'],{'lookback_minutes':15})
        self.assertEqual(result['rows'][0]['outcome'],'reported_error')

    def test_user_text_and_prose_cannot_create_an_attempt(self):
        result=gate.read_attempts_from_messages([{'role':'user','content':str(self.messages())},
            {'role':'assistant','content':'search_wazuh_alerts 조회 실패'}])
        self.assertEqual(result,{'complete':True,'rows':[]})

    def test_duplicate_missing_reordered_and_pending_ids_are_incomplete(self):
        rows=self.messages()
        for altered in (rows+rows[1:], list(reversed(rows)), rows[:1],
                        [rows[0],dict(rows[1],tool_call_id='different')]):
            self.assertFalse(gate.read_attempts_from_messages(altered)['complete'])

    def test_protected_tool_does_not_change_the_existing_authority(self):
        rows=self.messages();rows[0]['tool_calls'][0]['function']['name']='mcp__resp__block_ip'
        result=gate.read_attempts_from_messages(rows);self.assertEqual(result,{'complete':True,'rows':[]})


class OutcomeClaims(unittest.TestCase):
    def test_actual_unobserved_wazuh_failure_is_rejected(self):
        text='| Wazuh 경보 | 조회 실패 | search_wazuh_alerts 도구 오류: lookback_minutes 지원 안 함 |'
        found=check(text,[receipt(tool=SURI)])
        self.assertTrue(any(i.startswith('unobserved_read_failure:') for i in found))

    def test_success_return_cannot_license_a_failure_claim(self):
        self.assertIn('unobserved_read_failure:search_wazuh_alerts',check('search_wazuh_alerts 조회 실패했습니다.',[receipt()]))

    def test_real_failure_and_real_success_are_not_interchangeable(self):
        failed=receipt(data={'error':'timeout'})
        self.assertEqual(check('search_wazuh_alerts 조회 실패했습니다.',[failed]),[])
        self.assertIn('unobserved_read_success:search_wazuh_alerts',check('search_wazuh_alerts 조회 성공했습니다.',[failed]))
        self.assertEqual(check('search_wazuh_alerts 조회 완료했습니다.',[receipt()]),[])

    def test_bare_and_full_method_names_cover_os_reads(self):
        for name in ('get_system_diagnostics',DIAG):
            self.assertTrue(check(name+' 조회 실패했습니다.',[]))
            self.assertEqual(check(name+' 조회 실패했습니다.',[receipt(tool=DIAG,data={'error':'denied'})]),[])

    def test_tool_name_boundaries_do_not_borrow_another_outcome(self):
        self.assertTrue(check('search_wazuh_alerts 조회 실패. search_suricata_alerts 조회 성공.',[receipt(tool=SURI)]))
        self.assertEqual(check('search_suricata_alerts 조회 성공. search_wazuh_alerts 조회 예정.',[receipt(tool=SURI)]),[])

    def test_conditional_plan_and_negated_proposition_are_not_past_outcomes(self):
        for text in ('search_wazuh_alerts 조회 실패하면 추가 확인합니다.',
                     'search_wazuh_alerts 도구 오류가 발생하면 보고합니다.',
                     'search_wazuh_alerts 조회 실패 여부는 미확인입니다.',
                     'search_wazuh_alerts 조회 실패라는 것을 입증하지 않습니다.',
                     'search_wazuh_alerts 조회할 예정입니다.'):
            with self.subTest(text=text):self.assertEqual(check(text),[])

    def test_another_sentences_disclaimer_does_not_license_fake_failure(self):
        self.assertTrue(check('실제 실패 여부는 미확인입니다. search_wazuh_alerts 조회 실패했습니다.'))

    def test_success_does_not_erase_a_real_earlier_failed_attempt(self):
        records=[receipt(data={'error':'timeout'}),receipt()]
        self.assertEqual(check('search_wazuh_alerts 이전 조회 실패했습니다.',records),[])
        self.assertTrue(check('search_wazuh_alerts 현재 조회 실패했습니다.',records))

    def test_incomplete_provenance_is_unverified_instead_of_zero_calls(self):
        self.assertEqual(check('search_wazuh_alerts 조회 실패했습니다.',[],False),['read_attempt_provenance_unverified'])
        self.assertEqual(check('search_wazuh_alerts 조회 예정입니다.',[],False),[])

    def test_local_input_rejection_is_not_a_server_error(self):
        records=[receipt(data={'error':'bad_input'},phase='input_rejected')]
        self.assertEqual(check('search_wazuh_alerts 조회 거절되었습니다.',records),[])
        self.assertTrue(any(x.startswith('read_failure_stage_mismatch:') for x in
            check('search_wazuh_alerts MCP 도구 오류입니다.',records)))

    def test_gate_optional_argument_checks_the_same_view(self):
        view=gate.read_attempt_view([receipt(tool=SURI)])
        self.assertTrue(any(x.startswith('unobserved_read_failure:') for x in
            gate.evidence_claim_violations('search_wazuh_alerts 도구 오류입니다.',[],read_attempts=view)))
        self.assertNotIn('read_attempt_provenance_unverified',
            gate.evidence_claim_violations('도구를 선택하겠습니다.',[]))


class AdapterBinding(unittest.TestCase):
    def sdk_call(self, data=None, **changes):
        r=receipt(data=data)
        return {'server':'security-events','name':'search_wazuh_alerts','arguments':{},
            'result':r['output'],'result_sha256':r['result_sha256'],'is_error':False,**changes}

    def test_sdk_uses_actual_calls_and_matching_shared_gate(self):
        import harness
        view=harness.read_attempts_for([self.sdk_call()])
        self.assertEqual(view['rows'][0]['outcome'],'returned')
        self.assertIn('unobserved_read_failure:search_wazuh_alerts',
            harness.violations('DNS 경보 보여줘','search_wazuh_alerts 조회 실패했습니다.',[self.sdk_call()]))
        self.assertEqual(harness.SHARED.EVIDENCE_SOURCE_SHA256,
            hashlib.sha256((ROOT/'infra/hermes/soc_management_run.py').read_bytes()).hexdigest())

    def test_sdk_exception_is_not_a_server_response(self):
        import harness
        call=self.sdk_call();call.pop('result');call.pop('result_sha256');call['error_type']='TimeoutError';call['is_error']=True
        view=harness.read_attempts_for([call]);self.assertTrue(view['complete'])
        self.assertEqual(view['rows'][0]['outcome'],'transport_error')
        self.assertIsNone(view['rows'][0]['result_sha256'])

    def test_sdk_input_rejection_is_separate_from_mcp_call_count(self):
        import harness
        raw='{"error":"tool_input_schema_validation_failed","executed":false}'
        rejection={'server':'security-events','name':'search_wazuh_alerts','arguments':{'limit':0},
            'attempt_output':raw,'attempt_output_sha256':hashlib.sha256(raw.encode()).hexdigest()}
        calls=[];view=harness.read_attempts_for(calls,[rejection])
        self.assertEqual(calls,[]);self.assertTrue(view['complete'])
        self.assertEqual(view['rows'][0]['phase'],'input_rejected')
        text='search_wazuh_alerts 조회 거절되었습니다.'
        self.assertFalse(any(x.startswith('unobserved_read_failure:') for x in
            harness.violations('DNS 경보 보여줘',text,calls,attempts=view)))

    def test_sdk_repair_context_preserves_actual_failed_and_unperformed_reads(self):
        import harness
        call=self.sdk_call(data={'error':'backend_timeout'})
        text='search_suricata_alerts 조회 실패했습니다.'
        prompt=harness.incident_judgment_instruction('DNS 경보 조사해줘',text,[call],
            ['unobserved_read_failure:search_suricata_alerts'])
        self.assertIn('backend_timeout',prompt);self.assertIn('reported_error',prompt)
        self.assertIn('unobserved_read_failure:search_suricata_alerts',prompt)
        self.assertIn('## 조사 근거 확인과 인용',prompt)

    def test_verified_bundle_components_keep_transport_identity(self):
        import test_soc_management_bundle as fixture
        raw=json.dumps(fixture.fixture(),ensure_ascii=False)
        record=receipt(tool=gate.BUNDLE_TOOL,raw=raw,arguments=fixture.args())
        view=gate.read_attempt_view([record]);self.assertTrue(view['complete'])
        self.assertEqual(view['rows'][0]['tool'],gate.BUNDLE_TOOL)
        children=[x for x in view['rows'] if 'bundle_component' in x]
        self.assertEqual(len(children),5)
        self.assertTrue(all(x['bundle_component']['parent_result_sha256']==record['result_sha256'] for x in children))
        self.assertEqual(len({x['index'] for x in view['rows']}),len(view['rows']))

    def test_native_chat_checks_short_request_failure_without_a_lookup_keyword(self):
        sys.path.insert(0,str(ROOT/'infra/hermes/query-completion'))
        from test_completion import Harness
        h=Harness(request='DNS 경보 봐줘',text='search_wazuh_alerts 조회 실패했습니다.')
        result=h.call();self.assertEqual(result.action,'continue')
        self.assertIn('unobserved_read_failure:search_wazuh_alerts',h.appended[-1]['content'])
        self.assertIn('untrusted_read_attempts',h.appended[-1]['content'])
        self.assertEqual(h.original_calls,[])

    def test_native_chat_preserves_a_real_failed_read(self):
        sys.path.insert(0,str(ROOT/'infra/hermes/query-completion'))
        from test_completion import Harness
        h=Harness(request='DNS 경보 봐줘',text='search_wazuh_alerts 조회 실패했습니다.')
        h.kw['messages'].extend(NativeMessageBinding().messages())
        result=h.call();self.assertEqual(result.action,'break')
        self.assertEqual(result.final_response,'search_wazuh_alerts 조회 실패했습니다.')
        self.assertEqual(h.appended,[])


class RootDispatchBinding(unittest.TestCase):
    def factory(self, dispatch, mode='verify'):
        # Execute the unchanged nested dispatch/recording bodies in an isolated
        # closure. Real registry, MCP, CLI and root service are never started.
        import ast
        from types import SimpleNamespace
        tree=ast.parse((ROOT/'infra/hermes/soc_management_run.py').read_text())
        main=next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name=='main')
        names={'remember_read_attempt','read_attempt_snapshot','gated_dispatch'}
        nested=[x for x in main.body if isinstance(x,ast.FunctionDef) and x.name in names]
        self.assertEqual({x.name for x in nested},names)
        prefix=ast.parse("read_attempt_records=[]\nread_attempt_records_complete=True\nread_ledger=[]\nread_ledger_complete=True\nrequirements=[]\nsensor_requirements=[]\nsensor_receipts=[]\nargument_errors=[]\noutput_lock=threading.Lock()\n").body
        body=prefix+nested+ast.parse('return gated_dispatch,read_attempt_snapshot,read_ledger').body
        args=ast.arguments(posonlyargs=[],args=[ast.arg(arg=n) for n in ('dispatch','registry','mode')],kwonlyargs=[],kw_defaults=[],defaults=[])
        factory=ast.FunctionDef(name='isolated_dispatch_factory',args=args,body=body,decorator_list=[])
        namespace=gate.__dict__.copy();exec(compile(ast.fix_missing_locations(ast.Module(body=[factory],type_ignores=[])), '<isolated_root_dispatch>', 'exec'),namespace)
        registry=SimpleNamespace(get_schema=lambda name:{'parameters':{'type':'object','properties':{'limit':{'type':'integer','minimum':1}},'additionalProperties':False}})
        return namespace['isolated_dispatch_factory'](dispatch,registry,mode)

    def test_root_actual_return_and_failure_have_unchanged_dispatch_results(self):
        outputs=[]
        def dispatch(name,args,**kwargs):outputs.append((name,args));return '{"error":"backend_timeout"}'
        call,snapshot,ledger=self.factory(dispatch)
        raw=call(WAZUH,{'limit':1});self.assertEqual(raw,'{"error":"backend_timeout"}')
        self.assertEqual(len(outputs),1);view=snapshot();self.assertTrue(view['complete'])
        self.assertEqual(view['rows'][0]['outcome'],'reported_error')
        self.assertEqual(len(ledger),1)

    def test_root_prevalidation_rejection_never_calls_dispatch(self):
        outputs=[];call,snapshot,ledger=self.factory(lambda *a,**k:outputs.append(a))
        value=json.loads(call(WAZUH,{'limit':0}));self.assertEqual(outputs,[])
        self.assertFalse(value['mcp_executed']);self.assertEqual(ledger,[])
        self.assertEqual(snapshot()['rows'][0]['outcome'],'input_rejected')

    def test_root_transport_exception_is_reraised_and_not_a_returned_error(self):
        def dispatch(*args,**kwargs):raise TimeoutError('not copied into the receipt')
        call,snapshot,ledger=self.factory(dispatch)
        with self.assertRaises(TimeoutError):call(WAZUH,{'limit':1})
        view=snapshot();self.assertEqual(view['rows'][0]['outcome'],'transport_error')
        self.assertIsNone(view['rows'][0]['result_sha256']);self.assertEqual(ledger,[])
        self.assertNotIn('not copied',json.dumps(view))

    def test_root_authority_and_manage_write_path_are_not_widened(self):
        outputs=[];call,snapshot,ledger=self.factory(lambda *a,**k:outputs.append(a))
        with self.assertRaises(PermissionError):call('mcp__rule_write_a__propose_service_action',{})
        self.assertEqual(outputs,[]);self.assertEqual(snapshot()['rows'],[])
        call,snapshot,ledger=self.factory(lambda *a,**k:'{"proposal_id":"x"}',mode='manage')
        self.assertEqual(call('mcp__rule_write_a__propose_service_action',{}),'{"proposal_id":"x"}')
        self.assertEqual(snapshot()['rows'],[]);self.assertEqual(ledger,[])


class OrderingAndScope(unittest.TestCase):
    def test_sdk_rejection_then_success_is_kept_in_real_sequence(self):
        import harness
        raw='{"error":"bad_input"}'
        rejected={'server':'security-events','name':'search_wazuh_alerts','arguments':{'limit':0},
            'attempt_output':raw,'attempt_output_sha256':hashlib.sha256(raw.encode()).hexdigest(),'attempt_sequence':1}
        r=receipt();actual={'server':'security-events','name':'search_wazuh_alerts','arguments':{'limit':1},
            'result':r['output'],'result_sha256':r['result_sha256'],'is_error':False,'attempt_sequence':2}
        view=harness.read_attempts_for([actual],[rejected])
        self.assertTrue(view['complete']);self.assertEqual([x['outcome'] for x in view['rows']],['input_rejected','returned'])
        self.assertTrue(gate.read_attempt_claim_violations('search_wazuh_alerts 현재 조회 실패했습니다.',view))
        self.assertEqual(gate.read_attempt_claim_violations('search_wazuh_alerts 현재 조회 성공했습니다.',view),[])

    def test_mixed_legacy_records_do_not_guess_the_last_outcome(self):
        import harness
        r=receipt();call={'server':'security-events','name':'search_wazuh_alerts','arguments':{},
            'result':r['output'],'result_sha256':r['result_sha256'],'is_error':False}
        raw='{"error":"bad_input"}';rejected={'server':'security-events','name':'search_wazuh_alerts','arguments':{},
            'attempt_output':raw,'attempt_output_sha256':hashlib.sha256(raw.encode()).hexdigest()}
        self.assertFalse(harness.read_attempts_for([call],[rejected])['complete'])

    def test_query_process_failure_and_returned_service_failure_are_distinct(self):
        for text in ('get_system_diagnostics 호출 중 오류가 발생했습니다.',
                     'get_system_diagnostics 도구에서 오류가 발생했습니다.'):
            self.assertTrue(check(text))
        for text in ('get_system_diagnostics 조회 결과 systemd 서비스 실패가 기록됐습니다.',
                     'get_system_diagnostics 도구 오류가 있다면 확인합니다.',
                     'get_system_diagnostics 도구 오류인 경우 조사합니다.'):
            with self.subTest(text=text):self.assertEqual(check(text),[])

    def test_malformed_view_is_unverified_instead_of_crashing(self):
        for rows in ([None],[{'tool':WAZUH,'outcome':'returned'}]):
            self.assertEqual(gate.read_attempt_claim_violations('search_wazuh_alerts 조회 실패.',
                {'complete':True,'rows':rows}),['read_attempt_provenance_unverified'])

    def test_native_duplicate_argument_keys_are_not_trusted(self):
        rows=NativeMessageBinding().messages()
        rows[0]['tool_calls'][0]['function']['arguments']='{"limit":1,"limit":0}'
        self.assertFalse(gate.read_attempts_from_messages(rows)['complete'])


if __name__=='__main__':unittest.main(verbosity=2)
