"""Read-input admission and real protocol-error identity, never protected retry."""
import asyncio
import copy
import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch
import soc_management_run as gate
from test_soc_management_run import Harness, definition

MANAGER='mcp__wazuh_ro__search_wazuh_manager_logs'
SCHEMA={'type':'object','properties':{'level':{'type':'string'},'limit':{'type':'integer'},
    'tag':{'type':'string'},'search_term':{'type':'string'},'offset':{'type':'integer'}},'required':['level']}
HAS_VALIDATOR=importlib.util.find_spec('jsonschema') is not None

class InputContract(unittest.TestCase):
    def test_normalization_does_not_modify_catalog_or_add_arguments(self):
        original=copy.deepcopy(SCHEMA);out=gate.tool_input_schema(MANAGER,SCHEMA)
        self.assertEqual(SCHEMA,original)
        self.assertEqual(set(out['properties']),set(SCHEMA['properties']))
        self.assertEqual(out['properties']['level']['enum'],['critical','debug','debug2','error','info','warning'])
        self.assertFalse(out['additionalProperties'])

    def test_absent_schema_is_not_executed_or_normal(self):
        rejection=gate.tool_input_rejection(MANAGER,{},None)
        self.assertEqual(rejection['error'],'tool_input_schema_unavailable')
        self.assertFalse(rejection['mcp_executed'])

    def test_protected_inputs_remain_owned_by_existing_approval_path(self):
        self.assertIsNone(gate.tool_input_rejection('mcp__rule_write_a__propose_rule_edit',{},SCHEMA))

    @unittest.skipUnless(HAS_VALIDATOR,'installed validator only')
    def test_missing_numeric_and_unsupported_manager_arguments_are_rejected(self):
        for args in ({},{'level':'3'},{'level':'info','since_kst':'2026-01-01T00:00:00+09:00'},
                     {'level':'warning','limit':'30'}):
            before=copy.deepcopy(args);error=gate.tool_input_rejection(MANAGER,args,SCHEMA)
            self.assertEqual(error['error'],'tool_input_schema_validation_failed')
            self.assertFalse(error['executed']);self.assertEqual(args,before)
        for level in gate.tool_input_schema(MANAGER,SCHEMA)['properties']['level']['enum']:
            self.assertIsNone(gate.tool_input_rejection(MANAGER,{'level':level,'limit':3},SCHEMA))

    @unittest.skipUnless(HAS_VALIDATOR,'installed validator only')
    def test_wrong_server_target_and_extra_diagnostic_argument(self):
        schema={'type':'object','properties':{'target':{'type':'string','enum':['b:wazuh-local-rules']}},
                'required':['target'],'additionalProperties':False}
        self.assertIsNotNone(gate.tool_input_rejection('mcp__rule_b__get_rule_change_target',{'target':'a:waf'},schema))
        schema['properties']['target']['enum']=['soc:coverage']
        self.assertIsNotNone(gate.tool_input_rejection('mcp__system_diagnostics__get_system_diagnostics',
            {'target':'soc:coverage','requested_at_kst':'2026-01-01T00:00:00+09:00'},schema))

    @unittest.skipUnless(HAS_VALIDATOR,'installed validator only')
    def test_management_dispatch_rejects_then_corrects_without_first_dispatch(self):
        tool=definition(MANAGER);tool['function']['parameters']=copy.deepcopy(SCHEMA)
        def check(h):
            denied=json.loads(h.registry.dispatch(MANAGER,{'level':'3'}))
            self.assertFalse(denied['mcp_executed']);self.assertFalse(h.dispatches)
            self.assertEqual(h.registry.dispatch(MANAGER,{'level':'warning'}),{'ok':True})
        h=Harness(tools=[tool]);h.run(check)
        self.assertEqual(h.dispatches,[(MANAGER,{'level':'warning'}, {})])

    @unittest.skipUnless(HAS_VALIDATOR,'installed validator only')
    def test_chat_hook_checks_final_plugin_arguments_and_preserves_existing_block(self):
        path=Path(__file__).parent/'query-completion/alignment.py'
        spec=importlib.util.spec_from_file_location('native_input_pretool_test',path);a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
        tool=definition(MANAGER);tool['function']['parameters']=SCHEMA
        agent=types.SimpleNamespace(platform='mattermost',model='qwen3.6:35b',provider='custom',api_mode='chat_completions',tools=[tool])
        ref=types.SimpleNamespace(name=MANAGER,args={'level':'3'},call_id='call-test')
        h=types.SimpleNamespace(EVIDENCE=gate)
        blocked,args=a.proposal_input_wrapper(lambda *_:(None,ref.args),h,'test')(agent,ref)
        self.assertFalse(json.loads(blocked)['mcp_executed']);self.assertEqual(args,{'level':'3'})
        corrected={'level':'warning'}
        self.assertEqual(a.proposal_input_wrapper(lambda *_:(None,corrected),h,'test')(agent,ref),(None,corrected))
        self.assertEqual(a.proposal_input_wrapper(lambda *_:('existing block',ref.args),h,'test')(agent,ref),('existing block',ref.args))

class ProtocolBoundary(unittest.TestCase):
    def setUp(self):
        class McpError(Exception):
            def __init__(self,code):self.error=types.SimpleNamespace(code=code,message='server invalid params')
        self.error_type=McpError
        self.modules={'mcp.shared.exceptions':types.SimpleNamespace(McpError=McpError),
                      'mcp.types':types.SimpleNamespace(CallToolResult=lambda **kw:types.SimpleNamespace(**kw),
                                                       TextContent=lambda **kw:types.SimpleNamespace(**kw))}

    def test_only_actual_invalid_params_is_an_application_response(self):
        with patch.dict(sys.modules,self.modules):
            result=gate.read_protocol_error_result('search_wazuh_manager_logs',self.error_type(-32602))
            body=json.loads(result.content[0].text)
            self.assertTrue(result.isError);self.assertTrue(body['server_responded'])
            self.assertFalse(body['executed']);self.assertEqual(body['mcp_protocol_code'],-32602)
            self.assertIsNone(gate.read_protocol_error_result('search_wazuh_manager_logs',self.error_type(-32603)))
            self.assertIsNone(gate.read_protocol_error_result('search_wazuh_manager_logs',RuntimeError('network')))
            self.assertIsNone(gate.read_protocol_error_result('propose_rule_edit',self.error_type(-32602)))

    def test_installed_rust_error_spelling_requires_no_sdk_result_constructor(self):
        modules={**self.modules,'mcp.shared.exceptions':types.SimpleNamespace(MCPError=self.error_type),
                 'mcp.types':types.SimpleNamespace()}
        with patch.dict(sys.modules,modules):
            result=gate.read_protocol_error_result('search_wazuh_manager_logs',self.error_type(-32602))
            self.assertTrue(result.isError);self.assertTrue(result.is_error)
            self.assertEqual(json.loads(result.content[0].text)['mcp_protocol_code'],-32602)

    def test_native_result_hook_converts_read_error_once_and_propagates_write(self):
        path=Path(__file__).parent/'query-completion/alignment.py'
        spec=importlib.util.spec_from_file_location('native_input_alignment_test',path);a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
        calls=[]
        async def original(server,server_name,name,args):calls.append(name);raise self.error_type(-32602)
        wrapped=a.vulnerability_result_wrapper(original,None,'test',gate)
        with patch.dict(sys.modules,self.modules):
            result=asyncio.run(wrapped(None,'wazuh-ro','search_wazuh_manager_logs',{}))
            self.assertTrue(result.isError)
            with self.assertRaises(self.error_type):asyncio.run(wrapped(None,'rule-write-a','propose_rule_edit',{}))
        self.assertEqual(calls,['search_wazuh_manager_logs','propose_rule_edit'])

if __name__=='__main__':unittest.main()
