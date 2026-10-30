"""Exercise the real runtime repair loop with SDK boundaries replaced, no network."""
import asyncio
import hashlib
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runtime


class PreparationLoop(unittest.TestCase):
    def execute(self, *, submit_on=0, narrow_repair=False, bad_input=False, question=None, correct_preflight=False, repeat_preflight=False, read_incident=False, incident_drafts=None, incident_read_error=False):
        calls, prompts = [], []
        self.selector_prompts=[];self.agent_system_prompts=[]
        selector_prompts=self.selector_prompts;agent_system_prompts=self.agent_system_prompts
        self.protected_starts = []
        content = '# heading\nbody\n'
        sha = hashlib.sha256(content.encode()).hexdigest()
        available = {'rule-a':['get_rule_change_target'], 'rule-write-a':['propose_rule_edit']}
        if read_incident:
            available['security-events']=['search_modsecurity_alerts']
        class Connector:
            def __init__(self, server): self.server = server
            async def list_tools(self):
                return [types.SimpleNamespace(name=name,description='fixture',inputSchema={
                    'type':'object','properties':{'target':{'type':'string'}}}) for name in available[self.server]]
            async def call_tool(self, name, arguments, **kw):
                calls.append(name)
                if incident_read_error and name=='search_modsecurity_alerts' and len(calls)==1:
                    return types.SimpleNamespace(isError=True,content=[types.SimpleNamespace(type='text',text=json.dumps({'error':'until_kst must be in the past 90 days'}))])
                data = ({'target':'a:modsecurity-custom','content':content,'sha256':sha}
                        if name=='get_rule_change_target' else
                        {'source':'modsecurity','returned_count':0,'alerts':[],
                         'requested_since_kst':'2026-10-30T12:00:00+09:00','requested_until_kst':'2026-10-30T12:01:00+09:00'}
                        if name=='search_modsecurity_alerts' else
                        {'target':'a:modsecurity-custom','proposal_id':'1'*32,'before_sha256':sha,
                         'after_sha256':hashlib.sha256(content.replace(arguments['edits'][0]['old_text'],arguments['edits'][0]['new_text']).encode()).hexdigest(),
                         'status':'pending','review_posted':True})
                return types.SimpleNamespace(isError=False,content=[types.SimpleNamespace(type='text',text=json.dumps(data))])
        class Client:
            def __init__(self, **kw): pass
            def get_all_active_sessions(self):
                return {server:types.SimpleNamespace(connector=Connector(server)) for server in available}
            async def close_all_sessions(self): pass
        class Tool:
            def __init__(self, **kw): self.__dict__.update(kw)
            async def ainvoke(self, args): return await self.coroutine(**args)
        class LLM:
            def __init__(self, **kw): self.callbacks=kw.get('callbacks',[])
            def with_structured_output(self, *a, **kw):
                if read_incident:
                    async def select(messages):
                        selector_prompts.append(messages)
                        return {'calls':[{'tool':'mcp__security_events__search_modsecurity_alerts',
                            'arguments':{'target':'bad-year' if incident_read_error and len(selector_prompts)==1 else 'fixture'}}]}
                    return types.SimpleNamespace(ainvoke=select)
                raise AssertionError('write preparation was narrowed to read-only selection')
        class Agent:
            def __init__(self, client, **kw):
                self.client=client;self.llm=kw['llm'];agent_system_prompts.append(kw['system_prompt'])
            async def initialize(self): await self.adapter.create_all(self.client)
            async def run(self, prompt):
                prompts.append(prompt);tools={t.name:t for t in self.adapter.tools}
                if read_incident:
                    if incident_drafts:
                        return incident_drafts[min(len(prompts)-1,len(incident_drafts)-1)]
                    return 'WAF 반환 표본 0건. 구간 전체와 사건 영향·위험은 미확인이며 추가 조사가 필요합니다.'
                if len(prompts)==1:
                    if bad_input:
                        refused = json.loads(await tools['mcp__rule_a__get_rule_change_target'].ainvoke({}))
                        assert refused['executed'] is False
                        assert refused['error']=='tool_input_schema_validation_failed'
                    await tools['mcp__rule_a__get_rule_change_target'].ainvoke({'target':'a:modsecurity-custom'})
                if repeat_preflight:
                    for i in range(4):
                        for callback in self.llm.callbacks:
                            await callback.on_chat_model_start({},[],run_id=str(i))
                        await tools['mcp__rule_write_a__propose_rule_edit'].ainvoke({
                            'target':'a:modsecurity-custom','base_sha256':sha,
                            'edits':[{'old_text':'body\n','new_text':'body\n\n# AUDIT-NOTE\n'}],
                            'reason':'requested comment'})
                elif correct_preflight:
                    await tools['mcp__rule_write_a__propose_rule_edit'].ainvoke({
                        'target':'a:modsecurity-custom','base_sha256':sha,
                        'edits':[{'old_text':'body\n','new_text':'body\n'+ ('\n' if len(prompts)==1 else '')+'# AUDIT-NOTE\n'}],
                        'reason':'requested comment'})
                elif len(prompts)==submit_on:
                    await tools['mcp__rule_write_a__propose_rule_edit'].ainvoke({
                        'target':'a:modsecurity-custom','base_sha256':sha,
                        'edits':[{'old_text':'# heading\n','new_text':'# new\n# heading\n'}],'reason':'requested comment'})
                return 'ModSecurity 파일을 확인했습니다. 변경안은 준비하지 못했습니다.'
        class ValidationError(Exception):
            validator='required'
        class Validator:
            def __init__(self,*a):pass
            @staticmethod
            def check_schema(*a):pass
            def validate(self,args):
                if read_incident and 'calls' in args:
                    return
                if 'target' not in args:raise ValidationError('missing target')
        definitions={
            'mcp_use':{'MCPClient':Client,'MCPAgent':Agent},
            'mcp_use.agents.adapters.langchain_adapter':{'LangChainAdapter':object},
            'langchain_ollama':{'ChatOllama':LLM},
            'langchain_core.tools':{'StructuredTool':Tool},
            'langchain_core.callbacks':{'AsyncCallbackHandler':object},
            'jsonschema':{'Draft202012Validator':Validator,'ValidationError':ValidationError}}
        modules={}
        for name,attrs in definitions.items():
            module=types.ModuleType(name);module.__dict__.update(attrs);modules[name]=module
        original_scope=runtime.harness.tool_scope
        def scope(question, observed=None):
            return {'mcp__rule_a__get_rule_change_target'} if narrow_repair and observed else original_scope(question,observed)
        with patch.dict(sys.modules,modules), patch.object(runtime,'capabilities',return_value=available), \
             patch.object(runtime,'filter_catalog',side_effect=lambda server,tools,mode:tools), \
             patch.object(runtime.harness,'tool_scope',side_effect=scope):
            pool = types.SimpleNamespace(borrow=AsyncMock(side_effect=AssertionError('write request entered read pool')))
            report=asyncio.run(runtime.run({'model':'qwen3.6:35b','base_url':'http://fixture.invalid',
                'access_mode':'hermes-parity','mcpServers':{s:{} for s in available}},
                {'question':question or 'WAF 파일 선두에 주석 변경안을 만들어줘. 실제 적용하지 말고 승인 카드까지만 준비해줘.'},
                connection_pool=None if read_incident else pool,on_protected_start=lambda:self.protected_starts.append(True)))
            pool.borrow.assert_not_awaited()
        self.assertNotEqual(report['status'],'failed',report)
        return report,prompts,calls

    def test_incident_selection_executes_model_choice_then_returns_evidence_for_judgment(self):
        report,prompts,calls=self.execute(question='DVWA 공격이었나? 탐지 규칙과 근거를 조사하고 위험을 판단해줘.',read_incident=True)
        self.assertEqual(len(prompts),1)
        self.assertIn('<untrusted_tool_observations>',prompts[0])
        self.assertIn('search_modsecurity_alerts',prompts[0])
        self.assertIn('2026-10-30T12:00:00+09:00',prompts[0])
        self.assertEqual(calls,['search_modsecurity_alerts'])
        self.assertEqual(report['protected_calls'],0)
        self.assertEqual(report.get('remaining_issues',[]),[])
        self.assertIn('추가 조사가 필요',report['final_response'])
        self.assertEqual(report['calls'][0]['via'],'structured_read_selection')

    def test_real_failed_read_feedback_and_clock_reach_next_selector(self):
        report,prompts,calls=self.execute(question='DVWA 사건 조사하고 위험 판단해줘',read_incident=True,incident_read_error=True)
        self.assertEqual(calls,['search_modsecurity_alerts']*2)
        self.assertEqual(len(self.selector_prompts),2)
        self.assertNotIn('<untrusted_failed_reads>',self.selector_prompts[0][1][1])
        feedback=self.selector_prompts[1][1][1]
        self.assertIn('<untrusted_failed_reads>',feedback)
        self.assertIn('until_kst must be in the past 90 days',feedback)
        self.assertIn('bad-year',feedback)
        for messages in self.selector_prompts:
            self.assertIn(report['turn_clock'],messages[0][1])
            self.assertIn(report['at_kst'],messages[0][1])
        self.assertIn(report['turn_clock'],self.agent_system_prompts[0])
        self.assertEqual(len(prompts),1)
        self.assertEqual(report['protected_calls'],0)
        self.assertEqual(report['status'],'completed')

    def test_incident_factual_repair_keeps_failed_draft_without_repeating_reads(self):
        failed='WAF 경보는 0건입니다.'
        fixed='WAF 반환 표본 0건. 실제 공격 여부와 영향은 미확인이고 추가 조사가 필요합니다.'
        report,prompts,calls=self.execute(question='DVWA 공격인지 근거와 대응 필요성을 조사해줘.',
            read_incident=True,incident_drafts=[failed,fixed])
        self.assertEqual(report['status'],'completed')
        self.assertEqual(report['final_response'],fixed)
        self.assertEqual(calls,['search_modsecurity_alerts'])
        self.assertEqual(len(prompts),2)
        self.assertIn('<untrusted_tool_observations>',prompts[-1])
        self.assertIn(failed,prompts[-1])
        self.assertEqual(report['judgment_audit'][0]['draft'],failed)
        self.assertIn('sample_zero_presented_as_absence',report['judgment_audit'][0]['issues'])
        self.assertEqual(report['judgment_audit'][-1]['issues'],[])

    def test_incident_exhausted_factual_repairs_remain_partial_with_audit(self):
        failed='WAF 경보는 0건입니다.'
        report,prompts,calls=self.execute(question='DVWA 공격인지 근거와 대응 필요성을 조사해줘.',
            read_incident=True,incident_drafts=[failed])
        self.assertEqual(report['status'],'partial')
        self.assertEqual(len(prompts),2)
        self.assertEqual(calls,['search_modsecurity_alerts'])
        self.assertEqual(report['protected_calls'],0)
        self.assertEqual(len(report['judgment_audit']),2)
        self.assertEqual(report['stop_reason'],'repeated_unchanged_judgment')
        self.assertNotIn(failed,report['final_response'])

    def test_incident_environment_refusal_is_repaired_without_an_action(self):
        failed='사설 주소이므로 대응이 불필요합니다.'
        fixed='WAF 반환 표본 0건. 승인 여부와 실제 영향은 미확인이고 추가 조사가 필요합니다.'
        report,prompts,calls=self.execute(question='DVWA 공격인지 근거와 대응 필요성을 조사해줘.',
            read_incident=True,incident_drafts=[failed,fixed])
        self.assertEqual(report['final_response'],fixed)
        self.assertIn('environment_used_as_authorization',report['judgment_audit'][0]['issues'])
        self.assertEqual(calls,['search_modsecurity_alerts'])
        self.assertEqual(report['protected_calls'],0)

    def test_stalled_model_receives_exactly_one_preparation_continuation(self):
        report,prompts,calls=self.execute()
        self.assertEqual(len(prompts),2)
        self.assertEqual(report['write_preparation_attempts'],1)
        self.assertEqual(calls,['get_rule_change_target'])
        self.assertFalse(report['write_progress']['complete'])

    def test_preparation_retains_model_selected_write_tools(self):
        report,prompts,calls=self.execute(submit_on=2,narrow_repair=True)
        self.assertEqual(len(prompts),2)
        self.assertEqual(calls,['get_rule_change_target','propose_rule_edit'])
        self.assertTrue(report['write_progress']['complete'])

    def test_requested_candidate_is_write_preparation_not_completed_read_only(self):
        q='WAF 파일 끝에 주석 한 줄을 덧붙이는 검토용 후보와 승인 카드를 준비해줘. 실제 적용은 하지마.'
        report,prompts,calls=self.execute(question=q)
        self.assertEqual(report['status'],'partial')
        self.assertEqual(report['write_preparation_attempts'],1)
        self.assertFalse(report['write_progress']['complete'])
        self.assertFalse(runtime.harness.READ.wants_write('기존 승인 카드와 후보를 보여줘'))
        report,prompts,calls=self.execute(question=q,submit_on=2)
        self.assertTrue(report['write_progress']['complete'])
        self.assertEqual(calls,['get_rule_change_target','propose_rule_edit'])

    def test_a_protected_attempt_is_not_repeated_by_preparation(self):
        report,prompts,calls=self.execute(submit_on=1)
        self.assertEqual(len(prompts),1)
        self.assertNotIn('write_preparation_attempts',report)
        self.assertEqual(calls.count('propose_rule_edit'),1)

    def test_mismatched_literal_comment_is_partial_without_protected_retry(self):
        q='WAF 맨 끝에 # AUDIT-NOTE 주석 한 줄을 추가하는 승인안을 만들어줘. 기존 내용은 유지해줘.'
        report,prompts,calls=self.execute(question=q,submit_on=1)
        self.assertEqual(report['status'],'partial')
        self.assertEqual(report['proposal_input_rejections'][0]['rejection']['error'],'proposal_preflight_scope_mismatch')
        self.assertIn('편집 검증 거절',report['final_response'])
        self.assertEqual(len(prompts),2)
        self.assertEqual(calls,['get_rule_change_target'])
        self.assertEqual(report['protected_calls'],0)
        self.assertEqual(self.protected_starts,[])

    def test_model_corrects_local_scope_error_before_exactly_one_submission(self):
        q='WAF 맨 끝에 # AUDIT-NOTE 주석 한 줄을 추가하는 승인안을 만들어줘. 기존 내용은 유지해줘.'
        report,prompts,calls=self.execute(question=q,correct_preflight=True)
        self.assertEqual(report['status'],'completed')
        self.assertEqual(len(prompts),2)
        self.assertEqual(calls,['get_rule_change_target','propose_rule_edit'])
        self.assertEqual(report['protected_calls'],1)
        self.assertEqual(self.protected_starts,[True])
        self.assertEqual(len(report['proposal_input_rejections']),1)
        self.assertEqual(report['write_progress']['scope_checks'][0]['status'],'match')
        self.assertIn('이전 편집 검증 거절',report['final_response'])

    def test_repeated_local_failures_stop_before_another_model_or_protected_call(self):
        q='WAF 맨 끝에 # AUDIT-NOTE 주석 한 줄을 추가하는 승인안을 만들어줘. 기존 내용은 유지해줘.'
        report,prompts,calls=self.execute(question=q,repeat_preflight=True)
        self.assertEqual(report['status'],'partial')
        self.assertEqual(report['stop_reason'],'repeated_local_proposal_failure')
        self.assertEqual(len(report['proposal_input_rejections']),3)
        self.assertEqual(calls,['get_rule_change_target']);self.assertEqual(self.protected_starts,[])
        self.assertIn('빈 줄 1개',report['final_response']);self.assertIn('3회',report['final_response'])

    def test_preserve_mode_proposal_uses_one_model_continuation(self):
        q='WAF 파일 끝에 주석 한 줄을 추가하는 승인안을 만들어줘. 기존 내용과 모드는 유지하고, 원복 방법도 알려줘.'
        report,prompts,calls=self.execute(question=q,submit_on=2)
        self.assertEqual(report['write_preparation_attempts'],1)
        self.assertEqual(calls,['get_rule_change_target','propose_rule_edit'])
        self.assertEqual(len(prompts),2)
        self.assertTrue(report['write_progress']['complete'])
        report,prompts,calls=self.execute(question=q,submit_on=1)
        self.assertEqual(len(prompts),1)
        self.assertNotIn('write_preparation_attempts',report)

    def test_schema_refusal_does_not_call_mcp_and_model_can_correct_it(self):
        report,prompts,calls=self.execute(submit_on=1,bad_input=True)
        self.assertEqual(calls,['get_rule_change_target','propose_rule_edit'])
        self.assertEqual(report['protected_calls'],1)
        self.assertEqual(len(report['input_rejections']),1)
        self.assertFalse(report['input_rejections'][0]['executed'])
        self.assertTrue(report['write_progress']['complete'])


if __name__=='__main__':unittest.main()
