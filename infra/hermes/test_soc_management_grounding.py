"""Bounded native-loop retry: model selects a read; no action/argument synthesis."""
import copy
import json
import types
import unittest
from unittest.mock import patch
from test_soc_management_run import wrapper, definition, READ_NAMES, WRITE_NAMES, Harness


class Grounding(unittest.TestCase):
    def sensor_plan(self):
        return [{'tool':'mcp__security_events__search_modsecurity_alerts','arguments':{
            'source_ip':'192.0.2.60','since_kst':'2026-11-04T14:48:00+09:00',
            'until_kst':'2026-11-04T19:00:00+09:00','limit':50}}]

    def sensor_catalog(self):
        request=copy.deepcopy(self.request)
        for t in request['tools']:
            if t['function']['name'] in wrapper.SENSOR_SEARCH_TOOLS:
                t['function']['parameters']={'type':'object','properties':{
                    **{k:{'type':'string'} for k in ('source_ip','since_kst','until_kst','lookback_minutes')},
                    'limit':{'type':'integer','minimum':1,'maximum':50}}}
        return request

    def test_verify_requires_actual_sensor_window_after_status_read(self):
        plan=self.sensor_plan();original=self.sensor_catalog();before=copy.deepcopy(original)
        with patch.dict(wrapper.os.environ,{'CAPSTONE_MANAGEMENT_MODE':'verify','CAPSTONE_MANAGEMENT_REVIEW':'0'}):
            narrowed=wrapper.initial_review_read(original,['get_operation_status'],sensor_requirements=plan)
            self.assertEqual(narrowed['tool_choice'],'required')
            self.assertEqual([t['function']['name'] for t in narrowed['tools']],[plan[0]['tool']])
            args=narrowed['tools'][0]['function']['parameters']
            self.assertEqual(args['type'],'object');self.assertNotIn('anyOf',args)
            self.assertEqual(args['properties']['source_ip']['enum'],['192.0.2.60'])
            self.assertNotIn('lookback_minutes',args['properties'])
            self.assertNotIn('arguments',narrowed)
            self.assertEqual(original,before)
            receipt={'tool':plan[0]['tool'],'source_ip':'192.0.2.60',
                     'since':wrapper.parse_instant(plan[0]['arguments']['since_kst']),
                     'until':wrapper.parse_instant(plan[0]['arguments']['until_kst'])}
            self.assertIs(wrapper.initial_review_read(original,['read'],sensor_requirements=plan,sensor_receipts=[receipt]),original)
            for bad in (dict(receipt,source_ip='192.0.2.61'),dict(receipt,tool='mcp__rule_a__get_operation_status'),
                        dict(receipt,until=wrapper.parse_instant('2026-11-04T14:49:00+09:00'))):
                self.assertTrue(wrapper.missing_sensor_reads(plan,[bad]))
        with patch.dict(wrapper.os.environ,{'CAPSTONE_MANAGEMENT_MODE':'manage'}):
            self.assertIs(wrapper.initial_review_read(original,[],sensor_requirements=plan),original)

    def test_original_window_is_offered_before_recurrence_for_the_same_tool(self):
        first=self.sensor_plan()[0]
        second={'tool':first['tool'],'arguments':dict(first['arguments'],
            since_kst='2026-11-04T14:48:02.598000+09:00',until_kst='2026-11-04T20:00:00+09:00')}
        first={'tool':first['tool'],'arguments':dict(first['arguments'],until_kst='2026-11-04T14:48:59.999999+09:00')}
        plan=[first,second];catalog=self.sensor_catalog()
        with patch.dict(wrapper.os.environ,{'CAPSTONE_MANAGEMENT_MODE':'verify'}):
            request=wrapper.initial_review_read(catalog,['get_operation_status'],sensor_requirements=plan)
            params=request['tools'][0]['function']['parameters']
            self.assertEqual(params['properties']['since_kst']['enum'],[first['arguments']['since_kst']])
            self.assertEqual(params['properties']['until_kst']['enum'],[first['arguments']['until_kst']])
            receipt={'tool':first['tool'],'source_ip':first['arguments']['source_ip'],
                'since':wrapper.parse_instant(first['arguments']['since_kst']),
                'until':wrapper.parse_instant(first['arguments']['until_kst'])}
            request=wrapper.initial_review_read(catalog,['search_modsecurity_alerts'],
                sensor_requirements=plan,sensor_receipts=[receipt])
            params=request['tools'][0]['function']['parameters']
            self.assertEqual(params['properties']['since_kst']['enum'],[second['arguments']['since_kst']])
            self.assertEqual(params['properties']['until_kst']['enum'],[second['arguments']['until_kst']])

    def test_required_scope_rejects_fraction_truncation_before_dispatch_without_repair(self):
        plan=self.sensor_plan();args=plan[0]['arguments'];args['until_kst']='2026-11-04T19:00:00.598000+09:00'
        bad=dict(args,until_kst='2026-11-04T19:00:00+09:00');before=copy.deepcopy(bad)
        with patch.dict(wrapper.os.environ,{'CAPSTONE_MANAGEMENT_MODE':'verify'}):
            rejection=wrapper.required_sensor_input_rejection(plan[0]['tool'],bad,plan,[])
            self.assertEqual(rejection['error'],'required_sensor_scope_mismatch')
            self.assertFalse(rejection['executed']);self.assertFalse(rejection['mcp_executed'])
            self.assertEqual(rejection['required_read'],plan[0]);self.assertEqual(bad,before)
            self.assertTrue(wrapper.argument_error(rejection))
            self.assertIsNone(wrapper.required_sensor_input_rejection(plan[0]['tool'],args,plan,[]))
            tool=wrapper.initial_review_read(self.sensor_catalog(),[],sensor_requirements=plan)['tools'][0]
            self.assertIn(args['until_kst'],tool['function']['description'])

    def test_scope_guard_is_limited_to_pending_authenticated_sensor_reads(self):
        plan=self.sensor_plan();name=plan[0]['tool'];args=plan[0]['arguments']
        receipt={'tool':name,'source_ip':args['source_ip'],
            'since':wrapper.parse_instant(args['since_kst']),'until':wrapper.parse_instant(args['until_kst'])}
        with patch.dict(wrapper.os.environ,{'CAPSTONE_MANAGEMENT_MODE':'verify'}):
            for bad in (dict(args,source_ip='192.0.2.61'),dict(args,limit=1),dict(args,agent_id='001')):
                self.assertIsNotNone(wrapper.required_sensor_input_rejection(name,bad,plan,[]))
            self.assertIsNone(wrapper.required_sensor_input_rejection(name,{},plan,[receipt]))
            self.assertIsNone(wrapper.required_sensor_input_rejection('mcp__resp__list_blocks',{},plan,[]))
            self.assertIsNone(wrapper.required_sensor_input_rejection(name,{},[],[]))
        with patch.dict(wrapper.os.environ,{'CAPSTONE_MANAGEMENT_MODE':'manage'}):
            self.assertIsNone(wrapper.required_sensor_input_rejection(name,{},plan,[]))

    @unittest.skipUnless(__import__("importlib.util").util.find_spec("jsonschema"), "server jsonschema required")
    def test_native_dispatch_enforces_scope_without_mcp_execution_or_input_rewrite(self):
        plan=self.sensor_plan();args=plan[0]['arguments'];args['until_kst']='2026-11-04T19:00:00.598000+09:00'
        bad=dict(args,until_kst='2026-11-04T19:00:00+09:00')
        h=Harness(self.sensor_catalog()['tools'])
        def check(h):
            denied=json.loads(h.registry.dispatch(plan[0]['tool'],bad))
            self.assertEqual(denied['error'],'required_sensor_scope_mismatch')
            self.assertEqual(h.dispatches,[]);self.assertEqual(h.wire_calls,[])
            self.assertEqual(h.registry.dispatch(plan[0]['tool'],args),{'ok':True})
            self.assertEqual(h.dispatches[0][1],args)
        with patch.object(wrapper,'sensor_read_requirements',return_value=plan):h.run(check,'verify')

    def required_retry(self,plan,receipts,status=(),statuses=()):
        return wrapper.grounding_wrapper(lambda agent,**kw:'original',
            types.SimpleNamespace(FinalResponseVerdict=types.SimpleNamespace),lambda rows,row:rows.append(row),
            lambda rows,user:0,self.completed,sensor_requirements=plan,sensor_receipts=receipts,
            status_requirements=status,status_receipts=statuses)

    def test_partial_success_cannot_end_before_missing_required_window_and_retry_is_bounded(self):
        plan=self.sensor_plan();receipts=[];self.completed.append('get_operation_status')
        self.kw['assistant_message'].content='표본을 확인했습니다.\nMANAGEMENT_STATUS: monitor'
        call=self.required_retry(plan,receipts)
        with patch.dict(wrapper.os.environ,{'CAPSTONE_MANAGEMENT_MODE':'verify'}):
            verdict=call(self.agent,**self.kw);self.assertEqual(verdict.action,'continue')
            self.assertIn('필수 조회 영수증',self.kw['messages'][-1]['content'])
            self.assertIn(plan[0]['arguments']['since_kst'],self.kw['messages'][-1]['content'])
            request=self.agent._build_api_kwargs()
            self.assertEqual([x['function']['name'] for x in request['tools']],[plan[0]['tool']])
            self.assertEqual(request['reasoning_effort'],'none');self.assertNotIn('arguments',request)
            # No SDK/wire dispatch is performed by the retry adapter.
            self.assertEqual(self.completed,['get_operation_status'])
            self.kw['codex_ack_continuations']=1
            self.assertEqual(call(self.agent,**self.kw),'original')

    def test_fresh_matching_receipt_allows_completion_and_manage_is_unchanged(self):
        plan=self.sensor_plan();a=plan[0]['arguments'];receipts=[]
        self.completed.append('search_modsecurity_alerts')
        self.kw['assistant_message'].content='표본을 확인했습니다.\nMANAGEMENT_STATUS: monitor'
        call=self.required_retry(plan,receipts)
        with patch.dict(wrapper.os.environ,{'CAPSTONE_MANAGEMENT_MODE':'manage'}):
            self.assertEqual(call(self.agent,**self.kw),'original')
        receipts.append({'tool':plan[0]['tool'],'source_ip':a['source_ip'],
            'since':wrapper.parse_instant(a['since_kst']),'until':wrapper.parse_instant(a['until_kst'])})
        with patch.dict(wrapper.os.environ,{'CAPSTONE_MANAGEMENT_MODE':'verify'}):
            self.assertEqual(call(self.agent,**self.kw),'original')

    def test_required_status_retry_cannot_be_satisfied_by_an_unrelated_health_read(self):
        self.completed.append('get_system_diagnostics')
        self.kw['assistant_message'].content='서비스 확인.\nMANAGEMENT_STATUS: monitor'
        req=[{'proposal_id':'a'*32,'target':'a:incident-ip'}]
        call=self.required_retry(self.sensor_plan(),[],status=req)
        with patch.dict(wrapper.os.environ,{'CAPSTONE_MANAGEMENT_MODE':'verify'}):
            verdict=call(self.agent,**self.kw);self.assertEqual(verdict.action,'continue')
            request=self.agent._build_api_kwargs()
            self.assertEqual([x['function']['name'] for x in request['tools']],['mcp__rule_a__get_operation_status'])
            self.assertIn('status_reads',self.kw['messages'][-1]['content'])
            self.assertIn('"arguments": {"request_id": "'+ 'a'*32+'"}',self.kw['messages'][-1]['content'])

    def test_automatic_verify_requires_shared_status_before_sensors_without_operator_flag(self):
        req=[{'proposal_id':'a'*32,'target':'a:incident-ip'},
             {'proposal_id':'b'*32,'target':'a:incident-ip'}]
        request=self.sensor_catalog();before=copy.deepcopy(request)
        with patch.dict(wrapper.os.environ,{'CAPSTONE_MANAGEMENT_MODE':'verify','CAPSTONE_MANAGEMENT_REVIEW':'0'}):
            first=wrapper.initial_review_read(request,['prior_sensor'],req,[],self.sensor_plan(),[])
            self.assertEqual(first['tool_choice'],'required')
            self.assertEqual(len(first['tools']),1)
            f=first['tools'][0]['function'];self.assertEqual(f['name'],'mcp__rule_a__get_operation_status')
            self.assertEqual(f['parameters']['properties'],{'request_id':{'type':'string','enum':['a'*32]}})
            self.assertFalse(f['parameters']['additionalProperties'])
            receipt={'kind':'proposal_status','proposal_id':'a'*32,'target':'a:incident-ip'}
            second=wrapper.initial_review_read(request,['get_operation_status'],req,[receipt])
            self.assertEqual(second['tools'][0]['function']['parameters']['properties']['request_id']['enum'],['b'*32])
            wrong=dict(receipt,target='a:waf')
            again=wrapper.initial_review_read(request,[],req,[wrong])
            self.assertEqual(again['tools'][0]['function']['parameters']['properties']['request_id']['enum'],['a'*32])
            self.assertEqual(request,before)
            with self.assertRaisesRegex(RuntimeError,'status_read_schema_unavailable'):
                bad=copy.deepcopy(request);bad['tools']=[definition('mcp__rule_a__get_operation_status')]
                wrapper.initial_review_read(bad,[],req,[])

    def test_required_retry_still_preserves_interrupt_iteration_and_readonly_boundaries(self):
        self.completed.append('get_operation_status');call=self.required_retry(self.sensor_plan(),[])
        with patch.dict(wrapper.os.environ,{'CAPSTONE_MANAGEMENT_MODE':'verify'}):
            self.agent._interrupt_requested=True;self.assertEqual(call(self.agent,**self.kw),'original')
            self.agent._interrupt_requested=False;self.kw['api_call_count']=11
            self.assertEqual(call(self.agent,**self.kw),'original')
            self.kw['api_call_count']=1;self.agent.tools=[definition(WRITE_NAMES[0])]
            self.assertEqual(call(self.agent,**self.kw),'original')

    def test_sensor_requirements_cannot_add_authority_and_missing_catalog_is_error(self):
        plan=self.sensor_plan();self.assertEqual(wrapper.sensor_read_requirements(json.dumps(plan)),plan)
        for bad in ([],[dict(plan[0],tool=WRITE_NAMES[0])],[dict(plan[0],command='sudo')],
                    [{'tool':plan[0]['tool'],'arguments':dict(plan[0]['arguments'],limit=True)}],
                    [{'tool':plan[0]['tool'],'arguments':dict(plan[0]['arguments'],until_kst='2026-11-06T19:00:00+09:00')}],
                    [{'tool':plan[0]['tool'],'arguments':dict(plan[0]['arguments'],since_kst='2026-11-04T14:48:00')}],
                    [{'tool':plan[0]['tool'],'arguments':dict(plan[0]['arguments'],source_ip='$(id)')} ]):
            with self.subTest(bad=bad),self.assertRaises(RuntimeError):wrapper.sensor_read_requirements(json.dumps(bad))
        with patch.dict(wrapper.os.environ,{'CAPSTONE_MANAGEMENT_MODE':'verify'}):
            with self.assertRaisesRegex(RuntimeError,'sensor_read_tools_unavailable'):
                wrapper.initial_review_read({'tools':[]},[],sensor_requirements=plan)

    def test_sensor_receipts_require_real_matching_scope_not_log_claims(self):
        plan=self.sensor_plan();a=plan[0]['arguments'];d={'source':'modsecurity','source_scope':'wazuh_indexed_alerts',
            'requested_since_kst':a['since_kst'],'requested_until_kst':a['until_kst'],'alerts':[],'returned_count':0}
        result=types.SimpleNamespace(is_error=False,content=[types.SimpleNamespace(text=json.dumps(d))])
        receipt=wrapper.sensor_read_receipt('search_modsecurity_alerts',a,result)
        self.assertEqual(wrapper.missing_sensor_reads(plan,[receipt]),[])
        result.is_error=True;self.assertIsNone(wrapper.sensor_read_receipt('search_modsecurity_alerts',a,result));result.is_error=False
        for change in ({'source':'suricata'},{'source_scope':'assistant_text'},{'error':'timeout'}):
            result.content[0].text=json.dumps({**d,**change})
            self.assertIsNone(wrapper.sensor_read_receipt('search_modsecurity_alerts',a,result))

    def test_native_wire_receipt_releases_only_its_completed_sensor_requirement(self):
        from test_soc_management_run import Harness
        plan=self.sensor_plan();a=plan[0]['arguments'];h=Harness(tools=self.sensor_catalog()['tools'])
        def check(h):
            import asyncio
            agent=h.AIAgent();before=agent._build_api_kwargs()
            self.assertEqual(before['tool_choice'],'required')
            self.assertEqual([t['function']['name'] for t in before['tools']],[plan[0]['tool']])
            data={'source':'modsecurity','source_scope':'wazuh_indexed_alerts','requested_since_kst':a['since_kst'],
                  'requested_until_kst':a['until_kst'],'alerts':[],'returned_count':0}
            client=h.ClientSession(content=[types.SimpleNamespace(text=json.dumps(data))])
            asyncio.run(client.call_tool('search_modsecurity_alerts',a))
            after=agent._build_api_kwargs()
            self.assertNotIn('tool_choice',after)
            self.assertIn('mcp__rule_a__get_operation_status',[t['function']['name'] for t in after['tools']])
            self.assertFalse(set(t['function']['name'] for t in after['tools'])&set(WRITE_NAMES))
        with patch.object(wrapper,'sensor_read_requirements',return_value=plan):h.run(check,'verify')

    def test_required_read_phase_is_low_only_until_real_receipt_and_cannot_fake_completion(self):
        from test_soc_management_run import Harness
        plan=self.sensor_plan();a=plan[0]['arguments']
        for complete in (False,True):
            with self.subTest(complete=complete):
                h=Harness(tools=self.sensor_catalog()['tools'])
                def check(h):
                    import asyncio
                    wrapper.os.environ.update(CAPSTONE_MANAGEMENT_REVIEW='1',CAPSTONE_OPERATOR_REVIEW='1')
                    agent=h.AIAgent();agent.provider='custom';agent.model='qwen3.6:35b';agent.base_url='http://10.200.10.10:11435/v1'
                    h.api_kwargs={'model':'qwen3.6:35b','tools':h.initial_tools}
                    request=agent._build_api_kwargs();self.assertEqual(request['reasoning_effort'],'none');self.assertEqual(request['max_tokens'],2048)
                    data={'source':'modsecurity','source_scope':'wazuh_indexed_alerts','requested_since_kst':a['since_kst'],
                          'requested_until_kst':a['until_kst'],'alerts':[],'returned_count':0}
                    if complete:
                        client=h.ClientSession(content=[types.SimpleNamespace(text=json.dumps(data))]);asyncio.run(client.call_tool('search_modsecurity_alerts',a))
                        request=agent._build_api_kwargs();self.assertEqual(request['reasoning_effort'],'medium');self.assertEqual(request['max_tokens'],6144)
                    else:
                        asyncio.run(h.ClientSession().call_tool('get_operation_status',{'request_id':'a'*32}))
                    h.Emitter().emit_result({'final_response':'허용된 요청의 확인 결과입니다.\nMANAGEMENT_STATUS: resolved'})
                with patch.object(wrapper,'sensor_read_requirements',return_value=plan):h.run(check,'verify')
                self.assertIn('MANAGEMENT_STATUS: '+('resolved' if complete else 'needs_review'),h.emissions[0][0]['final_response'])

    def test_response_read_scope_survives_native_filter_and_never_offers_writes(self):
        names = ['mcp__resp__get_firewall_rules', 'mcp__resp__list_blocks']
        request = {**self.request, 'tools':[definition(n) for n in names + WRITE_NAMES]}
        env = {'CAPSTONE_MANAGEMENT_REVIEW':'1','CAPSTONE_MANAGEMENT_MODE':'verify'}
        for selected in ('get_firewall_rules', 'list_blocks'):
            with self.subTest(selected=selected), patch.dict(wrapper.os.environ,
                    {**env, 'CAPSTONE_FAST_READ_TOOL':selected}):
                result = wrapper.initial_review_read(request, [])
                self.assertEqual([t['function']['name'] for t in result['tools']], ['mcp__resp__'+selected])
                self.assertEqual(result['tool_choice'], 'required')
                self.assertNotIn('arguments', result)
                # The native adapter can already have narrowed to that tool.
                self.assertEqual(wrapper.initial_review_read(result, [])['tools'], result['tools'])
                self.assertIs(wrapper.initial_review_read(request, [selected]), request)
                with self.assertRaisesRegex(RuntimeError, 'fast_read_tool_unavailable'):
                    wrapper.initial_review_read({**request,'tools':[]}, [])
        with patch.dict(wrapper.os.environ, {**env,'CAPSTONE_FAST_READ_TOOL':'block_ip'}):
            with self.assertRaisesRegex(RuntimeError, 'fast_read_tool_invalid'):
                wrapper.initial_review_read(request, [])

    def test_proposal_review_requires_exact_fresh_status_before_other_queries(self):
        requirements=[{'proposal_id':'a'*32,'target':'b:wazuh-local-rules'}]
        with patch.dict(wrapper.os.environ, {'CAPSTONE_MANAGEMENT_REVIEW':'1','CAPSTONE_MANAGEMENT_MODE':'verify'}):
            request=wrapper.initial_review_read(self.request,['unrelated_health'],requirements,[])
            self.assertEqual([t['function']['name'] for t in request['tools']],['mcp__rule_b__get_rule_change_status'])
            self.assertEqual(request['tool_choice'],'required')
            self.assertNotIn('arguments',request)
            receipt={'kind':'proposal_status','proposal_id':'b'*32,'target':'b:wazuh-local-rules'}
            self.assertEqual(wrapper.initial_review_read(self.request,['read'],requirements,[receipt])['tool_choice'],'required')
            receipt['proposal_id']='a'*32
            self.assertIs(wrapper.initial_review_read(self.request,['read'],requirements,[receipt]),self.request)
            receipt['target']='a:suricata-local'
            self.assertEqual(wrapper.initial_review_read(self.request,['read'],requirements,[receipt])['tool_choice'],'required')
        with patch.dict(wrapper.os.environ, {'CAPSTONE_MANAGEMENT_REVIEW':'1','CAPSTONE_MANAGEMENT_MODE':'manage'}):
            self.assertIs(wrapper.initial_review_read(self.request,[],requirements,[]),self.request)

    def test_status_requirements_are_out_of_band_validated_and_missing_tools_fail(self):
        req=[{'proposal_id':'a'*32,'target':'a:chatproxy'}]
        self.assertEqual(wrapper.status_read_requirements(json.dumps(req)),req)
        for invalid in ('{}','[]',json.dumps([{'proposal_id':'a'*32,'target':'arbitrary:root'}]),
                        json.dumps([{'proposal_id':'a'*32,'target':'a:waf','command':'sudo'}])):
            with self.subTest(invalid=invalid),self.assertRaises(RuntimeError):wrapper.status_read_requirements(invalid)
        with patch.dict(wrapper.os.environ, {'CAPSTONE_MANAGEMENT_REVIEW':'1','CAPSTONE_MANAGEMENT_MODE':'verify'}):
            request={**self.request,'tools':[]}
            with self.assertRaisesRegex(RuntimeError,'tools_unavailable'):wrapper.initial_review_read(request,[],req,[])

    def test_readonly_review_requires_model_selected_read_before_answer(self):
        with patch.dict(wrapper.os.environ, {'CAPSTONE_MANAGEMENT_REVIEW':'1','CAPSTONE_MANAGEMENT_MODE':'verify'}):
            request = wrapper.initial_review_read(self.request, [])
            self.assertEqual(request['tool_choice'], 'required')
            self.assertEqual({t['function']['name'] for t in request['tools']}, set(READ_NAMES))
            self.assertIs(wrapper.initial_review_read(self.request, ['actual_read']), self.request)
        with patch.dict(wrapper.os.environ, {'CAPSTONE_MANAGEMENT_REVIEW':'1','CAPSTONE_MANAGEMENT_MODE':'manage'}):
            self.assertIs(wrapper.initial_review_read(self.request, []), self.request)

    def setUp(self):
        self.completed=[];self.original_calls=[]
        self.tools=[definition(n) for n in READ_NAMES+WRITE_NAMES+['terminal']]
        for t in self.tools:
            name=t['function']['name']
            if name.endswith(('__get_rule_change_status','__get_operation_status')):
                key='proposal_id' if name.endswith('__get_rule_change_status') else 'request_id'
                t['function']['parameters']={'type':'object','properties':{key:{'type':'string'}}}
        self.request={'model':'qwen3.6:35b','tools':self.tools,'tool_choice':'auto',
                      'reasoning_effort':'none','extra_body':{'think':False}}
        self.builder=lambda:copy.deepcopy(self.request)
        self.agent=types.SimpleNamespace(_build_api_kwargs=self.builder,tools=self.tools,
            api_mode='chat_completions',provider='custom',model='qwen3.6:35b',
            base_url='http://211.170.162.111:11434/v1',_current_turn_id='turn-a',
            _interrupt_requested=False,max_iterations=12,iteration_budget=types.SimpleNamespace(remaining=8),
            _emit_pending_fallback_notice=lambda:None,_clear_status_buffer=lambda:None,
            _build_assistant_message=lambda msg,reason:{'role':'assistant','content':msg.content})
        self.kw=dict(assistant_message=types.SimpleNamespace(content='조회하겠습니다.',tool_calls=None),
            finish_reason='stop',messages=[{'role':'user','content':'최근 보안 이벤트를 확인해줘'}],
            user_message='최근 보안 이벤트를 확인해줘',api_call_count=1,codex_ack_continuations=0,
            active_system_prompt='policy',_turn_exit_reason=None,_preflight_compression_blocked=False,
            truncated_response_parts=[],length_continue_retries=0,_pending_verification_response=None,
            _pending_verification_response_previewed=False)
        def original(agent,**kw):self.original_calls.append(kw);return 'original'
        self.call=wrapper.grounding_wrapper(original,types.SimpleNamespace(FinalResponseVerdict=types.SimpleNamespace),
            lambda rows,row:rows.append(row),lambda rows,user:0,self.completed)

    def test_zero_calls_retry_offers_reads_once_without_selecting_tool_or_arguments(self):
        verdict=self.call(self.agent,**self.kw);self.assertEqual(verdict.action,'continue')
        self.assertEqual(verdict.codex_ack_continuations,1)
        request=self.agent._build_api_kwargs()
        self.assertEqual(request['tool_choice'],'required')
        self.assertEqual({t['function']['name'] for t in request['tools']},set(READ_NAMES))
        self.assertNotIn('arguments',request);self.assertEqual(request['reasoning_effort'],'medium')
        self.assertNotIn('think',request['extra_body'])
        self.assertIs(self.agent._build_api_kwargs,self.builder)
        next_request=self.agent._build_api_kwargs()
        self.assertEqual(next_request['reasoning_effort'],'none');self.assertFalse(next_request['extra_body']['think'])
        self.assertEqual(self.call(self.agent,**self.kw),'original')

    def test_actual_read_or_native_pending_tool_does_not_force_more_calls(self):
        self.completed.append('search_suricata_alerts')
        self.kw['assistant_message'].content='반환 표본을 확인했습니다.\nMANAGEMENT_STATUS: monitor'
        self.assertEqual(self.call(self.agent,**self.kw),'original')
        self.completed.clear();self.kw['assistant_message'].tool_calls=[{'name':'native-selected'}]
        self.assertEqual(self.call(self.agent,**self.kw),'original')

    def test_interrupt_budget_pending_verification_and_turn_limits_preserved(self):
        cases=[('kw','api_call_count',11),('kw','codex_ack_continuations',1),
               ('kw','_pending_verification_response','pending'),('agent','_interrupt_requested',True)]
        for where,key,value in cases:
            with self.subTest(key=key):
                if where=='kw':old=self.kw[key];self.kw[key]=value
                else:old=getattr(self.agent,key);setattr(self.agent,key,value)
                self.assertEqual(self.call(self.agent,**self.kw),'original')
                if where=='kw':self.kw[key]=old
                else:setattr(self.agent,key,old)
        self.agent.iteration_budget.remaining=1
        self.assertEqual(self.call(self.agent,**self.kw),'original')

    def test_reanchor_cannot_point_at_another_user_message(self):
        self.kw['messages']=[{'role':'user','content':'old unrelated request'}]
        self.assertEqual(self.call(self.agent,**self.kw),'original')
        self.assertIs(self.agent._build_api_kwargs,self.builder)

    def test_no_read_tools_or_other_api_cannot_arm_retry(self):
        self.agent.tools=[definition(WRITE_NAMES[0])]
        self.assertEqual(self.call(self.agent,**self.kw),'original')
        self.agent.tools=self.tools;self.agent.api_mode='responses'
        self.assertEqual(self.call(self.agent,**self.kw),'original')

    def test_new_turn_cancels_required_request_without_changing_original_builder(self):
        self.call(self.agent,**self.kw);self.agent._current_turn_id='replacement'
        self.assertEqual(self.agent._build_api_kwargs()['tool_choice'],'auto')
        self.assertIs(self.agent._build_api_kwargs,self.builder)

    def test_other_provider_keeps_its_reasoning_settings(self):
        self.agent.base_url='https://other.example/v1'
        self.call(self.agent,**self.kw)
        request=self.agent._build_api_kwargs()
        self.assertEqual(request['reasoning_effort'],'none');self.assertFalse(request['extra_body']['think'])

    def test_management_thinking_is_scoped_to_verified_route_and_model(self):
        request=wrapper.management_reasoning(copy.deepcopy(self.request),self.agent)
        self.assertNotIn('think',request['extra_body']);self.assertEqual(request['reasoning_effort'],'medium')
        self.assertFalse(self.request['extra_body']['think'])
        self.agent.model='another-model'
        self.assertEqual(wrapper.management_reasoning(self.request,self.agent),self.request)

    def test_thor_transport_preserves_management_and_readonly_profiles(self):
        self.agent.base_url='http://10.200.10.10:11435/v1'
        with patch.dict(wrapper.os.environ, {'CAPSTONE_MANAGEMENT_REVIEW':'1','CAPSTONE_MANAGEMENT_MODE':'manage','CAPSTONE_OPERATOR_REVIEW':'0'}):
            request=wrapper.management_reasoning(copy.deepcopy(self.request),self.agent)
            self.assertEqual(request['reasoning_effort'],'medium')
            self.assertNotIn('think',request['extra_body'])
        with patch.dict(wrapper.os.environ, {'CAPSTONE_MANAGEMENT_REVIEW':'1','CAPSTONE_MANAGEMENT_MODE':'verify','CAPSTONE_OPERATOR_REVIEW':'0'}):
            request=wrapper.management_reasoning(copy.deepcopy(self.request),self.agent)
            self.assertEqual(request['reasoning_effort'],'none')
            self.assertEqual(request['max_tokens'],2048)

    def test_operator_case_review_keeps_reasoning_budget_separate_from_chat(self):
        with patch.dict(wrapper.os.environ, {'CAPSTONE_MANAGEMENT_REVIEW':'1','CAPSTONE_MANAGEMENT_MODE':'verify','CAPSTONE_OPERATOR_REVIEW':'1'}):
            request=wrapper.management_reasoning(copy.deepcopy(self.request),self.agent)
            self.assertEqual(request['reasoning_effort'],'medium')
            self.assertEqual(request['max_tokens'],6144)
            self.assertNotIn('think',request['extra_body'])

    def test_unrecognized_native_source_refuses_before_installing_hook(self):
        with patch.object(wrapper.Path,'read_bytes',side_effect=OSError),self.assertRaisesRegex(RuntimeError,'source_changed'):
            wrapper.install_grounding_retry([])

    def test_explicit_readonly_review_uses_bounded_nonreasoning_profile(self):
        with patch.dict(wrapper.os.environ, {'CAPSTONE_MANAGEMENT_REVIEW': '1', 'CAPSTONE_MANAGEMENT_MODE': 'verify'}):
            request=wrapper.management_reasoning(copy.deepcopy(self.request),self.agent)
            self.assertEqual(request['reasoning_effort'],'none')
            self.assertEqual(request['max_tokens'],2048)
        with patch.dict(wrapper.os.environ, {'CAPSTONE_MANAGEMENT_REVIEW': '1', 'CAPSTONE_MANAGEMENT_MODE': 'manage'}):
            self.assertEqual(wrapper.management_reasoning(copy.deepcopy(self.request),self.agent)['reasoning_effort'],'medium')


    def test_missing_sensor_citation_retry_cannot_repeat_only_operation_status(self):
        missing='mcp__security_events__search_modsecurity_alerts'
        old='mcp__rule_a__get_operation_status'
        text='INCIDENT_DISPOSITION: '+json.dumps({'evidence_tools':[old,missing]})
        names=wrapper.missing_cited_sensor_reads(text,{old})
        self.assertEqual(names,{missing})
        self.assertTrue(wrapper.arm_grounding_read(self.agent,'turn-a',names))
        request=self.agent._build_api_kwargs()
        self.assertEqual([x['function']['name'] for x in request['tools']],[missing])
        self.assertEqual(request['tool_choice'],'required')
        self.assertNotIn('arguments',request)
        self.assertIs(self.agent._build_api_kwargs,self.builder)
        self.assertFalse(wrapper.missing_cited_sensor_reads(text,{old,missing}))

    def test_missing_citations_never_add_write_or_unregistered_tools(self):
        text='INCIDENT_DISPOSITION: '+json.dumps({'evidence_tools':['terminal',WRITE_NAMES[0],'mcp__unknown__search_modsecurity_alerts']})
        self.assertEqual(wrapper.missing_cited_sensor_reads(text,set()),set())
        self.assertFalse(wrapper.arm_grounding_read(self.agent,'turn-a',{WRITE_NAMES[0]}))
        self.assertFalse(wrapper.arm_grounding_read(self.agent,'turn-a',{'unregistered'}))
        self.assertIs(self.agent._build_api_kwargs,self.builder)

if __name__=='__main__':unittest.main()
