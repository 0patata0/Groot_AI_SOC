"""Current-request read decoding preserves native dispatch and write boundaries."""
import copy
from dataclasses import dataclass
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_soc_management_run import wrapper as w

DEPS=bool(importlib.util.find_spec('jsonschema') and importlib.util.find_spec('openai'))
NAME='mcp__rule_a__get_operation_status'


def agent():
    return SimpleNamespace(provider='custom',model='qwen3.6:35b',
        api_mode='chat_completions',base_url='http://10.200.10.10:11435/v1',
        _current_turn_id='turn-one',valid_tool_names={NAME},_interrupt_requested=False)


def request():
    return {'model':'qwen3.6:35b','tools':[{'type':'function','function':{
        'name':NAME,'parameters':{'type':'object','required':['request_id'],
        'additionalProperties':False,'properties':{'request_id':{'type':'string','enum':['a'*32]}}}}}],
        'tool_choice':'required','messages':[{'role':'user','content':'현재 상태를 실제 조회하세요.'}],
        'reasoning_effort':'none','max_tokens':2048}


class SelectionScope(unittest.TestCase):
    def test_no_pending_requirement_never_changes_request(self):
        a=agent();r=request()
        with patch.dict(w.os.environ,{'CAPSTONE_MANAGEMENT_MODE':'verify'}):
            self.assertIs(w.management_read_request(r,a),r)
        self.assertIsNone(a._capstone_management_selection)

    def test_manage_and_other_routes_never_arm_json_decoder(self):
        for mode,field,value in [('manage','model','qwen3.6:35b'),('verify','provider','other'),
                ('verify','model','other'),('verify','api_mode','responses'),
                ('verify','base_url','http://other/v1'),('verify','_current_turn_id',''),
                ('verify','_interrupt_requested',True)]:
            a=agent();setattr(a,field,value);r=request()
            with self.subTest(mode=mode,field=field),patch.dict(w.os.environ,{'CAPSTONE_MANAGEMENT_MODE':mode}):
                self.assertIs(w.management_read_request(r,a,pending=True),r)
                self.assertIsNone(a._capstone_management_selection)

    def test_absent_or_optional_tool_choice_cannot_arm_from_prose(self):
        for choice in ['auto','none',None]:
            a=agent();r=request();r['tool_choice']=choice
            with patch.dict(w.os.environ,{'CAPSTONE_MANAGEMENT_MODE':'verify'}):
                self.assertIs(w.management_read_request(r,a,pending=True),r)

    def test_protected_and_unregistered_schemas_refused_before_provider(self):
        for name in ['mcp__resp__unblock_ip','mcp__rule_write_a__temporarily_contain_ip','terminal',
                     'mcp__rule_b__get_operation_status']:
            a=agent();r=request();r['tools'][0]['function']['name']=name
            with self.subTest(name=name),patch.dict(w.os.environ,{'CAPSTONE_MANAGEMENT_MODE':'verify'}):
                with self.assertRaisesRegex(RuntimeError,'catalog_invalid'):
                    w.management_read_request(r,a,pending=True)


@dataclass
class Verdict:
    action:str
    response:object


@dataclass
class BuildVerdict:
    action:str
    api_kwargs:dict
    api_messages:list
    _original_api_kwargs:dict


@unittest.skipUnless(DEPS,'existing server jsonschema/OpenAI dependencies required')
class SelectionDecode(unittest.TestCase):
    def setUp(self):
        self.env=patch.dict(w.os.environ,{'CAPSTONE_MANAGEMENT_MODE':'verify'});self.env.start()
        self.addCleanup(self.env.stop)
        self.a=agent();self.r=request();self.before=copy.deepcopy(self.r)
        self.wire=w.management_read_request(self.r,self.a,pending=True)
        self.lease=copy.deepcopy(self.a._capstone_management_selection)
        self.value={'request_nonce':self.lease['nonce'],'calls':[{'tool':NAME,'arguments':{'request_id':'a'*32}}]}

    def response(self,value=None,**updates):
        from openai.types.chat import ChatCompletion
        raw=json.dumps(self.value if value is None else value)
        message={'role':'assistant','content':raw}
        message.update(updates.pop('message',{}))
        row={'finish_reason':'stop','index':0,'message':message};row.update(updates)
        return ChatCompletion(id='actual-provider-response',object='chat.completion',created=42,
            model='qwen3.6:35b',choices=[row],usage={'prompt_tokens':100,'completion_tokens':40,'total_tokens':140})

    def test_catalog_request_is_immutable_and_response_lease_is_unique(self):
        self.assertEqual(self.r,self.before)
        self.assertNotIn('tools',self.wire);self.assertNotIn('tool_choice',self.wire)
        self.assertEqual(self.wire['max_tokens'],2048)
        self.assertEqual(self.wire['reasoning_effort'],'none')
        self.assertEqual(self.wire['response_format']['json_schema']['schema'],self.lease['schema'])
        second=w.management_read_request(self.r,self.a,pending=True)
        self.assertNotEqual(second['response_format'],self.wire['response_format'])

    def test_real_model_json_is_decoded_but_not_executed_or_invented(self):
        original=self.response();before=original.model_dump()
        decoded,count=w.management_selection_response(original,self.lease,self.a)
        self.assertEqual(count,1)
        self.assertEqual(decoded.choices[0].message.content,original.choices[0].message.content)
        self.assertEqual(decoded.usage,original.usage)
        self.assertEqual(decoded.id,original.id)
        self.assertEqual(original.model_dump(),before)
        call=decoded.choices[0].message.tool_calls[0]
        self.assertEqual(call.function.name,NAME)
        self.assertEqual(json.loads(call.function.arguments),self.value['calls'][0]['arguments'])
        self.assertEqual(decoded.choices[0].finish_reason,'tool_calls')

    def test_stale_turn_nonce_unknown_name_and_wrong_arguments_rejected(self):
        for field,value in [('request_nonce','b'*32),('calls',[{'tool':'mcp__resp__unblock_ip','arguments':{}}]),
                ('calls',[{'tool':NAME,'arguments':{'request_id':'b'*32}}]),('calls',[]),
                ('calls',[{'tool':NAME,'arguments':{'request_id':'a'*32,'approved':True}}])]:
            bad=copy.deepcopy(self.value);bad[field]=value
            with self.subTest(field=field,value=value),self.assertRaises(Exception):
                w.management_selection_response(self.response(bad),self.lease,self.a)
        self.a._current_turn_id='other'
        with self.assertRaisesRegex(ValueError,'shape'):
            w.management_selection_response(self.response(),self.lease,self.a)

    def test_duplicate_keys_and_unstructured_log_envelopes_rejected(self):
        for raw in ['{"request_nonce":"'+self.lease['nonce']+'","request_nonce":"'+self.lease['nonce']+'","calls":[]}',
                '```json\n'+json.dumps(self.value)+'\n```',
                'untrusted log: '+json.dumps(self.value),'{"value":NaN}',
                json.dumps({'content':self.value}),'x'*65537]:
            with self.subTest(raw=raw[:80]),self.assertRaises(Exception):
                w.management_selection_response(self.response(message={'content':raw}),self.lease,self.a)

    def test_length_refusal_native_calls_and_interrupt_never_decode(self):
        variants=[self.response(finish_reason='length'),self.response(message={'refusal':'no'}),
            self.response(message={'tool_calls':[{'id':'call_x','type':'function',
                'function':{'name':NAME,'arguments':'{}'}}]})]
        for value in variants:
            with self.assertRaises(ValueError):w.management_selection_response(value,self.lease,self.a)
        self.a._interrupt_requested=True
        with self.assertRaises(ValueError):w.management_selection_response(self.response(),self.lease,self.a)

    def test_duplicate_calls_or_schema_lease_mutation_cannot_expand_scope(self):
        bad=copy.deepcopy(self.value);bad['calls']*=2
        with self.assertRaises(Exception):w.management_selection_response(self.response(bad),self.lease,self.a)
        self.a.valid_tool_names=set()
        with self.assertRaisesRegex(ValueError,'not_authorized'):
            w.management_selection_response(self.response(),self.lease,self.a)

    def test_native_wrapper_consumes_once_and_preserves_transport_accounting(self):
        observed=[]
        def call(a,**kw):observed.append(kw);return Verdict('fallthrough',self.response())
        wrapped=w.management_selection_call_wrapper(call)
        result=wrapped(self.a,turn_id='turn-one',api_kwargs=self.wire)
        self.assertEqual(result.response.choices[0].finish_reason,'tool_calls')
        self.assertIsNone(self.a._capstone_management_selection)
        second=wrapped(self.a,turn_id='turn-one',api_kwargs=self.wire)
        self.assertFalse(second.response.choices[0].message.tool_calls)
        self.assertEqual(len(observed),2)
        self.assertEqual(observed[0]['api_kwargs'],self.wire)

    def test_final_native_build_is_bound_after_outer_read_scope_and_middleware(self):
        self.a._capstone_management_pending_read=('turn-one',True)
        self.a._capstone_management_selection=None
        original=BuildVerdict('fallthrough',copy.deepcopy(self.r),self.r['messages'],copy.deepcopy(self.r))
        result=w.management_selection_request_wrapper(lambda a,**kw:original)(self.a,turn_id='turn-one')
        self.assertNotIn('tools',result.api_kwargs)
        self.assertEqual(result._original_api_kwargs,result.api_kwargs)
        self.assertIs(result.api_messages,result.api_kwargs['messages'])
        self.assertEqual(original.api_kwargs,self.r)

    def test_final_build_cannot_restore_empty_outer_scope_or_other_turn(self):
        for field in ['empty-scope','stale-turn','no-pending']:
            self.a._capstone_management_pending_read=('other' if field=='stale-turn' else 'turn-one',field!='no-pending')
            data=copy.deepcopy(self.r)
            if field=='empty-scope':data.update(tools=[],tool_choice='none')
            original=BuildVerdict('fallthrough',data,data['messages'],copy.deepcopy(data))
            result=w.management_selection_request_wrapper(lambda a,**kw:original)(self.a,turn_id='turn-one')
            self.assertIs(result,original)
            self.assertIsNone(self.a._capstone_management_selection)

    def test_native_redirect_or_crossing_response_cannot_execute_stale_choice(self):
        for variant in ['redirect','turn','cancel']:
            self.a=agent();self.a._capstone_management_selection=copy.deepcopy(self.lease)
            def call(a,**kw):
                if variant=='turn':a._current_turn_id='other'
                if variant=='cancel':a._interrupt_requested=True
                return Verdict('break' if variant=='redirect' else 'fallthrough',self.response())
            result=w.management_selection_call_wrapper(call)(self.a,turn_id='turn-one',api_kwargs=self.wire)
            self.assertFalse(result.response.choices[0].message.tool_calls)
            self.assertIsNone(self.a._capstone_management_selection)

    def test_bad_model_output_fails_closed_and_does_not_loop_transport(self):
        count=[]
        def call(a,**kw):count.append(1);return Verdict('fallthrough',self.response({'calls':[]}))
        result=w.management_selection_call_wrapper(call)(self.a,turn_id='turn-one',api_kwargs=self.wire)
        self.assertFalse(result.response.choices[0].message.tool_calls)
        self.assertEqual(len(count),1)
        self.assertIsNone(self.a._capstone_management_selection)

    def test_transport_retry_keeps_only_same_unconsumed_request_lease(self):
        def fail(a,**kw):raise TimeoutError('native retry owns this error')
        with self.assertRaises(TimeoutError):
            w.management_selection_call_wrapper(fail)(self.a,turn_id='turn-one',api_kwargs=self.wire)
        self.assertEqual(self.a._capstone_management_selection,self.lease)
        result=w.management_selection_call_wrapper(lambda a,**kw:Verdict('fallthrough',self.response()))(
            self.a,turn_id='turn-one',api_kwargs=self.wire)
        self.assertEqual(len(result.response.choices[0].message.tool_calls),1)

    def test_existing_openai_sdk_passes_required_and_schema_to_actual_http_body(self):
        # Exercise installed native helper + SDK transform with mock HTTP only.
        helper_path=Path('/opt/hermes/agent/chat_completion_helpers.py')
        if not helper_path.is_file():self.skipTest('installed native helper required')
        import httpx
        from openai import OpenAI
        from agent.chat_completion_helpers import _dispatch_nonstreaming_api_request
        received=[]
        def handle(req):
            received.append(json.loads(req.content))
            return httpx.Response(200,json=self.response().model_dump())
        with OpenAI(api_key='nonsecret-test-only',base_url='http://test.invalid/v1',
                http_client=httpx.Client(transport=httpx.MockTransport(handle))) as client:
            for value in [self.r,self.wire]:
                _dispatch_nonstreaming_api_request(self.a,value,make_client=lambda *a,**kw:client)
        self.assertEqual(received[0]['tool_choice'],'required')
        self.assertEqual(received[0]['tools'],self.r['tools'])
        self.assertEqual(received[1]['response_format'],self.wire['response_format'])
        self.assertNotIn('tools',received[1]);self.assertNotIn('tool_choice',received[1])


if __name__=='__main__':unittest.main()
