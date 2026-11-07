"""Fresh chat reads select actual MCP calls before drafting factual answers."""
import copy
import importlib.util
import json
import hashlib
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import soc_management_controller as c
import soc_management_run as w
from test_soc_management_selection import agent, request, DEPS

NAME='mcp__system_diagnostics__get_system_diagnostics'


class ChatRead(unittest.TestCase):
    def test_inline_gate_without_file_uses_installed_harness_path(self):
        sentinel=object();module=SimpleNamespace(load_harness=lambda:sentinel)
        spec=SimpleNamespace(loader=SimpleNamespace(exec_module=lambda m:None))
        saved=w.__dict__.pop('__file__');w.chat_lookup_harness.cache_clear()
        try:
            with patch.object(w.importlib.util,'spec_from_file_location',return_value=spec) as load,\
                 patch.object(w.importlib.util,'module_from_spec',return_value=module):
                self.assertIs(w.chat_lookup_harness(),sentinel)
                self.assertEqual(load.call_args.args[1],Path('/opt/data/plugins/groot-query-completion/alignment.py'))
        finally:
            w.__dict__['__file__']=saved;w.chat_lookup_harness.cache_clear()

    def setUp(self):
        self.context={'request':'지금 A B C systemd 상태 조회해줘',
            'background':'이전 답변은 현재 상태의 근거가 아니다.',
            'tools':[NAME], 'requested_at_kst':'2026-11-06T17:55:00+09:00'}
        self.env={'CAPSTONE_MANAGEMENT_MODE':'verify',
            'CAPSTONE_CHAT_READ_JSON':json.dumps(self.context,ensure_ascii=False)}
        self.tool={'type':'function','function':{'name':NAME,'parameters':{
            'type':'object','additionalProperties':False,'required':['target'],
            'properties':{'target':{'type':'string','enum':['a:systemd','b:systemd','c:systemd']}}}}}

    def test_metadata_is_out_of_band_and_wrong_mode_or_malformed_is_rejected(self):
        with patch.dict(w.os.environ,{},clear=True):self.assertIsNone(w.chat_read_context())
        for changes in ({'CAPSTONE_MANAGEMENT_MODE':'manage'},
                        {'CAPSTONE_CHAT_READ_JSON':'{"request":1,"request":2}'},
                        {'CAPSTONE_CHAT_READ_JSON':'x'*32769}):
            with patch.dict(w.os.environ,dict(self.env,**changes),clear=True):
                with self.assertRaisesRegex(RuntimeError,'chat_read_context_invalid'):w.chat_read_context()
        for changes in ({'tools':['terminal']},{'tools':[NAME,NAME]}, {'tools':[]},
                        {'requested_at_kst':'2026-11-06T08:55:00Z'},{'request':''}):
            env=dict(self.env,CAPSTONE_CHAT_READ_JSON=json.dumps(dict(self.context,**changes)))
            with patch.dict(w.os.environ,env,clear=True):
                with self.assertRaisesRegex(RuntimeError,'chat_read_context_invalid'):w.chat_read_context()

    def test_first_request_is_scoped_and_later_reads_keep_normal_catalog(self):
        other={'type':'function','function':{'name':'mcp__resp__list_blocks','parameters':{'type':'object'}}}
        r={'tools':[self.tool,other]};before=copy.deepcopy(r)
        with patch.dict(w.os.environ,self.env,clear=True):
            out=w.initial_review_read(r,[])
            self.assertEqual([t['function']['name'] for t in out['tools']],[NAME])
            self.assertEqual(out['tool_choice'],'required')
            self.assertIs(w.initial_review_read(r,['get_system_diagnostics']),r)
            with self.assertRaisesRegex(RuntimeError,'chat_read_tools_unavailable'):
                w.initial_review_read({'tools':[other]},[])
        self.assertEqual(r,before)

    def test_mixed_inquiry_keeps_all_registered_reads_but_no_write(self):
        env=dict(self.env,CAPSTONE_CHAT_READ_JSON=json.dumps(dict(self.context,tools=None)))
        r={'tools':[self.tool,{'type':'function','function':{'name':'mcp__rule_write_a__propose_service_action'}}]}
        with patch.dict(w.os.environ,env,clear=True):
            self.assertEqual(len(w.initial_review_read(r,[])['tools']),1)

    @unittest.skipUnless(importlib.util.find_spec('jsonschema'),'server jsonschema required')
    def test_selector_keeps_nonce_scope_background_and_retry_error_context(self):
        a=agent();a.valid_tool_names={NAME}
        r=request();r['tools']=[self.tool];r['messages']=[{'role':'user','content':'native original'}]
        before=copy.deepcopy(r)
        with patch.dict(w.os.environ,self.env,clear=True):
            out=w.management_read_request(r,a,pending=True)
            self.assertEqual(out['max_tokens'],1024)
            self.assertEqual(json.loads(out['messages'][1]['content']),self.context)
            self.assertNotIn('tools',out)
            self.assertEqual(a._capstone_management_selection['catalog'][NAME],self.tool['function']['parameters'])
            self.assertEqual(a._capstone_management_selection['turn'],a._current_turn_id)
            retry=copy.deepcopy(r);retry['messages'].append({'role':'tool','content':'real argument error'})
            out=w.management_read_request(retry,a,pending=True)
            self.assertIn({'role':'tool','content':'real argument error'},out['messages'])
        self.assertEqual(r,before)

    def test_read_selection_does_not_lower_subsequent_investigation_reasoning(self):
        with patch.dict(w.os.environ,self.env,clear=True):
            self.assertEqual(w.management_reasoning(request(),agent(),required_read_phase=True)['reasoning_effort'],'none')
            self.assertEqual(w.management_reasoning(request(),agent())['reasoning_effort'],'medium')

    def test_only_fresh_readonly_chat_lead_receives_root_metadata(self):
        case={'mode':'verify','chat_task':'lead','run_count':0,'session_id':None,
              'chat_request':self.context['request'],'chat_background':self.context['background']}
        command=c.command_for(case)
        raw=next(x.split('=',1)[1] for x in command if x.startswith('CAPSTONE_CHAT_READ_JSON='))
        payload=json.loads(raw);self.assertEqual(payload['request'],case['chat_request'])
        self.assertEqual(payload['background'],case['chat_background']);self.assertIsNone(payload['tools'])
        self.assertNotIn('CAPSTONE_MANAGEMENT_REVIEW=1',command)
        for changes in ({'mode':'manage'},{'chat_task':'peer'},{'run_count':1},
                        {'session_id':'valid-session'},{'operator_review':True}):
            command=c.command_for(dict(case,**changes))
            self.assertFalse(any(x.startswith('CAPSTONE_CHAT_READ_JSON=') for x in command))

    def test_oversized_root_context_is_refused(self):
        with self.assertRaisesRegex(c.ControllerError,'chat_read_context_invalid'):
            c.command_for({'mode':'verify','chat_task':'lead','run_count':0,'session_id':None,
                           'chat_request':'x'*6001})

    @unittest.skipUnless(DEPS,'existing server jsonschema/OpenAI dependencies required')
    def test_pipeline_lookup_selection_cannot_add_unrelated_targets_or_time_filters(self):
        from jsonschema import Draft202012Validator
        a=agent();a.valid_tool_names={NAME};r=request();tool=copy.deepcopy(self.tool)
        tool['function']['parameters']['properties']['target']['enum']+=['b:management-pipeline','b:management']
        r['tools']=[tool];before=copy.deepcopy(r)
        env=dict(self.env,CAPSTONE_CHAT_READ_JSON=json.dumps(dict(self.context,request='관제 조사 대기 상태 확인해줘')))
        with patch.dict(w.os.environ,env,clear=True):out=w.management_read_request(r,a,pending=True)
        schema=out['response_format']['json_schema']['schema'];nonce=a._capstone_management_selection['nonce']
        def valid(args):return Draft202012Validator(schema).is_valid({'request_nonce':nonce,'calls':[{'tool':NAME,'arguments':args}]})
        self.assertTrue(valid({'target':'b:management-pipeline'}))
        self.assertEqual(schema['properties']['calls']['maxItems'],1)
        for args in ({'target':'b:management'},{'target':'a:systemd'},
                     {'target':'b:management-pipeline','lookback_minutes':90}):self.assertFalse(valid(args))
        self.assertEqual(r,before)
        # A schema-rejected model draft must not widen the next attempt.
        with patch.dict(w.os.environ,env,clear=True):retry=w.management_read_request(r,a,pending=True)
        self.assertEqual(retry['response_format']['json_schema']['schema']['properties']['calls'],schema['properties']['calls'])
        a=agent();a.valid_tool_names={NAME};r['tools']=[self.tool]
        with patch.dict(w.os.environ,env,clear=True):
            with self.assertRaisesRegex(RuntimeError,'chat_pipeline_target_unregistered'):
                w.management_read_request(r,a,pending=True)

    @unittest.skipUnless(DEPS,'existing server jsonschema/OpenAI dependencies required')
    def test_ids_policy_native_selection_rejects_unasked_waf_on_first_and_retry(self):
        from jsonschema import Draft202012Validator
        name='mcp__rule_a__get_service_action_target'
        tool={'type':'function','function':{'name':name,'parameters':{
            'type':'object','additionalProperties':False,'required':['target'],
            'properties':{'target':{'type':'string','enum':['a:waf','a:suricata']}}}}}
        for question in ('IDS 관리자 예외 보여줘','IDS 예외?'):
            a=agent();a.valid_tool_names={name};r=request();r['tools']=[tool];before=copy.deepcopy(r)
            env=dict(self.env,CAPSTONE_CHAT_READ_JSON=json.dumps(dict(self.context,tools=[name],request=question)))
            with patch.dict(w.os.environ,env,clear=True):
                for _ in range(2):
                    out=w.management_read_request(r,a,pending=True);lease=a._capstone_management_selection
                    schema=out['response_format']['json_schema']['schema'];validator=Draft202012Validator(schema)
                    def value(target):return {'request_nonce':lease['nonce'],'calls':[{'tool':name,'arguments':{'target':target}}]}
                    self.assertTrue(validator.is_valid(value('a:suricata')))
                    self.assertFalse(validator.is_valid(value('a:waf')))
                    self.assertEqual(schema['properties']['calls']['maxItems'],1)
                    self.assertEqual(lease['catalog'][name]['properties']['target']['enum'],['a:suricata'])
            self.assertEqual(r,before)
        r['tools']=[copy.deepcopy(tool)]
        r['tools'][0]['function']['parameters']['properties']['target']['enum']=['a:waf']
        with patch.dict(w.os.environ,env,clear=True):
            with self.assertRaisesRegex(RuntimeError,'chat_ids_policy_target_unregistered'):
                w.management_read_request(r,a,pending=True)

    @unittest.skipUnless(DEPS,'existing server jsonschema/OpenAI dependencies required')
    def test_three_hosts_remain_required_and_current_duplicates_are_coalesced(self):
        from openai.types.chat import ChatCompletion
        a=agent();a.valid_tool_names={NAME};r=request();r['tools']=[self.tool]
        with patch.dict(w.os.environ,self.env,clear=True):
            w.management_read_request(r,a,pending=True)
            lease=a._capstone_management_selection
            calls=[{'tool':NAME,'arguments':{'target':h+':systemd'}} for h in 'abc']
            def response(rows):
                return ChatCompletion(id='test',model=a.model,created=0,object='chat.completion',
                    choices=[{'index':0,'finish_reason':'stop','message':{'role':'assistant','content':
                        json.dumps({'request_nonce':lease['nonce'],'calls':rows})}}])
            out,count=w.management_selection_response(response(calls),lease,a)
            self.assertEqual(count,3);self.assertEqual(len(out.choices[0].message.tool_calls),3)
            out,count=w.management_selection_response(response(calls+[calls[0]]),lease,a)
            self.assertEqual(count,3)
            self.assertEqual(lease['catalog'][NAME],self.tool['function']['parameters'])

    @unittest.skipUnless(DEPS,'existing server jsonschema/OpenAI dependencies required')
    def test_current_service_native_lease_excludes_unasked_hosts_and_keeps_retry_scope(self):
        from jsonschema import Draft202012Validator
        a=agent();a.valid_tool_names={NAME};r=request();tool=copy.deepcopy(self.tool)
        props=tool['function']['parameters']['properties']
        props['target']['enum']+=['b:management']
        props['limit']={'type':'integer','minimum':1,'maximum':50,'default':20}
        props['lookback_minutes']={'type':'integer','minimum':1,'maximum':1440,'default':15}
        r['tools']=[tool];before=copy.deepcopy(r)
        for names in ([NAME],None):
            env=dict(self.env,CAPSTONE_CHAT_READ_JSON=json.dumps(dict(self.context,tools=names,
                request='B 서버 capstone-management.service의 지금 실행 상태와 시작 설정 알려줘.')))
            with patch.dict(w.os.environ,env,clear=True):
                for _ in range(2):
                    out=w.management_read_request(r,a,pending=True);lease=a._capstone_management_selection
                    schema=out['response_format']['json_schema']['schema']
                    self.assertTrue(lease['current_diagnostic'])
                    self.assertEqual(schema['properties']['calls']['maxItems'],1)
                    self.assertEqual(lease['catalog'][NAME]['properties']['target']['enum'],['b:management'])
                    for target in ('a:systemd','c:systemd'):
                        self.assertFalse(Draft202012Validator(schema).is_valid({'request_nonce':lease['nonce'],
                            'calls':[{'tool':NAME,'arguments':{'target':target}}]}))
        self.assertEqual(r,before)

    @unittest.skipUnless(DEPS,'existing server jsonschema/OpenAI dependencies required')
    def test_current_native_defaults_deduplicate_without_weakening_nonce_or_arguments(self):
        from openai.types.chat import ChatCompletion
        a=agent();a.valid_tool_names={NAME};r=request();tool=copy.deepcopy(self.tool)
        props=tool['function']['parameters']['properties'];props['target']['enum']+=['b:management']
        props['limit']={'type':'integer','minimum':1,'maximum':50,'default':20}
        props['lookback_minutes']={'type':'integer','minimum':1,'maximum':1440,'default':15}
        r['tools']=[tool]
        env=dict(self.env,CAPSTONE_CHAT_READ_JSON=json.dumps(dict(self.context,
            request='B 서버 capstone-management.service 현재 상태?')))
        with patch.dict(w.os.environ,env,clear=True):w.management_read_request(r,a,pending=True)
        lease=a._capstone_management_selection
        def response(rows,nonce=lease['nonce']):
            return ChatCompletion(id='test',model=a.model,created=0,object='chat.completion',
                choices=[{'index':0,'finish_reason':'stop','message':{'role':'assistant','content':
                    json.dumps({'request_nonce':nonce,'calls':rows})}}])
        first={'tool':NAME,'arguments':{'target':'b:management'}}
        same={'tool':NAME,'arguments':{'target':'b:management','limit':20,'lookback_minutes':15}}
        out,count=w.management_selection_response(response([first,same]),lease,a)
        self.assertEqual(count,1)
        self.assertEqual(json.loads(out.choices[0].message.tool_calls[0].function.arguments),first['arguments'])
        for invalid in ({'tool':NAME,'arguments':{'target':'a:systemd'}},
                        {'tool':NAME,'arguments':{'target':'b:management','limit':51}}):
            with self.assertRaises(Exception):w.management_selection_response(response([first,same,invalid]),lease,a)
        with self.assertRaises(Exception):w.management_selection_response(response([first],nonce='old'),lease,a)

    @unittest.skipUnless(DEPS,'existing server jsonschema/OpenAI dependencies required')
    def test_temporal_service_request_does_not_receive_current_only_lease(self):
        a=agent();a.valid_tool_names={NAME};r=request();r['tools']=[self.tool]
        env=dict(self.env,CAPSTONE_CHAT_READ_JSON=json.dumps(dict(self.context,
            request='B 서버 capstone-management.service 지금 상태 두 번 비교해줘')))
        with patch.dict(w.os.environ,env,clear=True):out=w.management_read_request(r,a,pending=True)
        self.assertNotIn('current_diagnostic',a._capstone_management_selection)
        self.assertEqual(out['response_format']['json_schema']['schema']['properties']['calls']['maxItems'],4)

    @unittest.skipUnless(DEPS,'existing server jsonschema/OpenAI dependencies required')
    def test_registered_time_schema_projection_rejects_systemd_history_and_matches_native(self):
        from jsonschema import Draft202012Validator
        spec=importlib.util.spec_from_file_location('chat_diagnostics_schema',Path(__file__).parents[1]/'mcp/system-diagnostics-mcp.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        # Read the actual registry schema, including compiler normalization.
        core_spec=importlib.util.spec_from_file_location('chat_diagnostics_core',Path(__file__).parents[1]/'mcp/system_diagnostics.py')
        core=importlib.util.module_from_spec(core_spec);core_spec.loader.exec_module(core)
        module._library=core
        schema=next(t['inputSchema'] for t in module.tools() if t['name']=='get_system_diagnostics')
        schema=w.tool_input_schema(NAME,schema)
        projected=w.chat_read_schema(NAME,schema)
        self.assertIn('anyOf',projected)
        native=Draft202012Validator(schema);grammar=Draft202012Validator(projected)
        for target in ('a:systemd','b:systemd','c:systemd','b:management','c:apache','invalid'):
            for times in ({},{'lookback_minutes':10},{'since_kst':'2026-11-06T00:00:00+09:00'},
                          {'until_kst':'2026-11-06T01:00:00+09:00'},
                          {'since_kst':'2026-11-06T00:00:00+09:00','until_kst':'2026-11-06T01:00:00+09:00'},
                          {'since_kst':'2026-11-06T00:00:00+09:00','until_kst':'2026-11-06T01:00:00+09:00','lookback_minutes':10}):
                for journal in ({},{'view':'journal'},{'journal_scope':'all'},
                                {'view':'journal','journal_scope':'all'},
                                {'view':'journal','journal_scope':'errors'},
                                {'view':'summary'},{'view':'journal','journal_scope':'unknown'}):
                    args=dict(target=target,**times,**journal)
                    self.assertEqual(native.is_valid(args),grammar.is_valid(args),args)
        unknown=copy.deepcopy(schema);unknown['allOf'].append({'required':['limit']})
        self.assertIs(w.chat_read_schema(NAME,unknown),unknown)
        self.assertIs(w.chat_read_schema('other',schema),schema)


class LiteralLookup(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('chat_literal_harness',Path(__file__).parents[1]/'ollama-trial/harness.py')
        self.h=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.h)
        self.context={'request':'지금 A B C systemd 상태 보여줘','background':'',
            'tools':[NAME],'requested_at_kst':'2026-11-06T18:15:00+09:00'}
        self.ledger=[];self.receipts=[];self.facts=[]
        for h in 'abc':
            args={'target':h+':systemd'}
            payload={'schema':1,'target':args['target'],'kind':'runtime','status':'ok','codes':[],
                'metrics':{'failed_units_total':0,'returned_units':0,'unit_list_truncated':False},
                'observed_at_kst':'2026-11-06T18:15:00+09:00','age_seconds':10,'untrusted_evidence':True}
            raw=json.dumps({'result':json.dumps(payload)})
            self.ledger.append(w.read_ledger_entry(NAME,args,raw))
            self.receipts.append({'tool':NAME,'output':raw,'is_error':False})
            self.facts+=w.observation_facts('get_system_diagnostics',SimpleNamespace(isError=False,
                content=[SimpleNamespace(text=raw)]),args)

    def test_complete_current_receipts_render_existing_table_with_no_health_claim(self):
        text=w.literal_chat_lookup(self.context,self.ledger,self.receipts,self.h)
        self.assertEqual(text.count('현재 로드된 failed unit 0개'),3)
        self.assertIn('전체 공격 탐지·대응 성공을 뜻하지',text)
        self.assertEqual(w.evidence_claim_violations(text,self.facts,{NAME}),[])

    def test_missing_error_mismatched_or_duplicate_receipts_cannot_complete(self):
        for mutate in ('missing','error','sha','duplicate','unavailable'):
            rows=copy.deepcopy(self.ledger);receipts=copy.deepcopy(self.receipts)
            if mutate=='missing':rows.pop();receipts.pop()
            if mutate=='error':receipts[-1]['is_error']=True
            if mutate=='sha':rows[-1]['result_sha256']='0'*64
            if mutate=='duplicate':receipts[-1]=copy.deepcopy(receipts[0])
            if mutate=='unavailable':
                raw=json.dumps({'target':'c:systemd','status':'unavailable'})
                receipts[-1]['output']=raw;rows[-1]['result_sha256']=hashlib.sha256(raw.encode()).hexdigest()
            with self.subTest(mutate=mutate):self.assertIsNone(w.literal_chat_lookup(self.context,rows,receipts,self.h))

    def test_current_investigation_queue_metric_completes_with_exact_receipt(self):
        ctx=dict(self.context,request='지금 관제 조사 대기 상태 확인해줘')
        args={'target':'b:management-pipeline'}
        data={'schema':1,'target':args['target'],'host':'b','kind':'runtime','status':'degraded',
            'codes':['case_review_required'],'mutation_performed':False,'age_seconds':1,
            'observed_at_kst':'2026-11-06T18:15:00+09:00','metrics':{'pending_reports':2,
                'running_cases':1,'overdue_cases':0,'review_required_cases':7}}
        raw=json.dumps({'result':json.dumps(data)});ledger=[w.read_ledger_entry(NAME,args,raw)]
        receipts=[{'tool':NAME,'output':raw,'is_error':False}]
        text=w.literal_chat_lookup(ctx,ledger,receipts,self.h)
        self.assertIn('보고 전송 2건 / 실행 중 1건',text)
        self.assertIn('검토 상태 사건 | 7건',text)
        self.assertIn('공격 확정·실행 실패 건수 아님',text)
        self.assertIsNone(w.literal_chat_lookup(ctx,ledger,self.receipts[:1],self.h))
        self.assertIsNone(w.literal_chat_lookup(dict(ctx,request='어제 관제 조사가 밀린 원인 분석해줘'),ledger,receipts,self.h))

    def test_history_judgment_change_and_unscoped_requests_keep_native_reasoning(self):
        for question in ('오늘 systemd 실패 경보가 반복됐는데 지금도 장애인지 조회해줘',
                         'A systemd 왜 실패했어?','A systemd 위험 판단해줘','systemd 서비스를 재시작해줘'):
            ctx=dict(self.context,request=question)
            self.assertIsNone(w.literal_chat_lookup(ctx,self.ledger,self.receipts,self.h))
        self.assertIsNone(w.literal_chat_lookup(dict(self.context,tools=None),self.ledger,self.receipts,self.h))

    def test_native_iteration_completion_requires_current_turn_and_no_interrupt(self):
        a=agent();a._capstone_chat_selection_turn=a._current_turn_id
        original=lambda agent,**kw:'ordinary';callback=lambda:'verified table'
        wrapped=w.chat_lookup_iteration_wrapper(original,callback)
        env={'CAPSTONE_MANAGEMENT_MODE':'verify','CAPSTONE_CHAT_READ_JSON':json.dumps(self.context)}
        with patch.dict(w.os.environ,env,clear=True):
            out=wrapped(a);self.assertEqual(out.action,'break');self.assertEqual(out.final_response,'verified table')
            a._interrupt_requested=True;self.assertEqual(wrapped(a),'ordinary')
            a._interrupt_requested=False;a._current_turn_id='new';self.assertEqual(wrapped(a),'ordinary')
        with patch.dict(w.os.environ,{},clear=True):self.assertEqual(wrapped(a),'ordinary')

    @unittest.skipUnless(Path('/opt/hermes/agent/conversation_loop.py').exists(),'installed Native phase required')
    def test_native_phase_keeps_actual_model_count_and_passes_response_to_finalizer(self):
        from agent import conversation_loop as loop
        a=agent();a._capstone_chat_selection_turn=a._current_turn_id
        wrapped=w.chat_lookup_iteration_wrapper(loop.begin_iteration,lambda:'verified table')
        state=SimpleNamespace(messages=[],conversation_history=[],original_user_message='request',
            api_call_count=1,interrupted=False,_turn_exit_reason='unknown',final_response=None)
        env={'CAPSTONE_MANAGEMENT_MODE':'verify','CAPSTONE_CHAT_READ_JSON':json.dumps(self.context)}
        with patch.dict(w.os.environ,env,clear=True):
            out=loop._run_phase(wrapped,a,state)
        self.assertEqual(out.action,'break');self.assertEqual(state.api_call_count,1)
        self.assertEqual(state.final_response,'verified table')
        self.assertEqual(state._turn_exit_reason,'text_response(verified_chat_lookup)')


if __name__=='__main__':unittest.main()
