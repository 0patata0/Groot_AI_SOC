"""Transport boundaries for complete rule proposals and bounded helper results."""
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('rule_change_mcp', Path(__file__).with_name('rule_change_mcp.py'))
mcp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mcp)


class RuleChangeTransportTests(unittest.TestCase):
    def test_complete_128k_candidate_with_json_escaping_is_sent(self):
        content = '# "\\' * 32767 + '\n'
        self.assertLessEqual(len(content.encode()), 128 * 1024)
        payload = {'operation': 'propose', 'target': 'a:modsecurity-custom',
                   'base_sha256': '0' * 64, 'candidate_content': content, 'reason': '검증'}
        result = subprocess.CompletedProcess([], 0, b'{"status":"pending"}', b'')
        with patch.object(mcp.subprocess, 'run', return_value=result) as run:
            answer = mcp._call_helper(payload)
        self.assertFalse(answer['isError'])
        self.assertEqual(json.loads(run.call_args.kwargs['input'])['candidate_content'], content)
        self.assertEqual(run.call_args.kwargs['timeout'], 360)

    def test_full_large_diff_survives_helper_and_mcp_json_wrapping(self):
        diff = ('-기존 "값"\\\n+새로운 "값"\\\n' * 9000)
        data = {'status': 'pending', 'diff': diff, 'limits': {'max_diff_utf8_bytes': 512 * 1024}}
        raw = json.dumps(data, ensure_ascii=False).encode()
        self.assertGreater(len(raw), 256 * 1024)
        with patch.object(mcp.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, raw, b'')):
            reply = mcp.handle({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {
                'name': 'propose_rule_change', 'arguments': {'target': 'a:modsecurity-custom',
                    'base_sha256': '0' * 64, 'candidate_content': 'SecRuleEngine DetectionOnly\n', 'reason': '크기 검증'}}})
        decoded = json.loads(json.dumps(reply, ensure_ascii=False))
        self.assertEqual(json.loads(decoded['result']['content'][0]['text'])['diff'], diff)
        self.assertFalse(decoded['result']['isError'])

    def test_input_over_cap_never_executes_helper(self):
        with patch.object(mcp.subprocess, 'run') as run:
            result = mcp._call_helper({'operation': 'propose', 'candidate_content': 'x' * mcp.MAX_INPUT})
        self.assertTrue(result['isError'])
        run.assert_not_called()

    def test_output_over_cap_is_rejected_without_truncation(self):
        with patch.object(mcp.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'x' * (mcp.MAX_OUTPUT + 1), b'')):
            result = mcp._call_helper({'operation': 'get'})
        self.assertTrue(result['isError'])
        self.assertIn('response too large', result['content'][0]['text'])

    def test_read_timeout_and_helper_failures_stay_bounded(self):
        with patch.object(mcp.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, b'{"error":"rejected"}', b'')) as run:
            result = mcp._call_helper({'operation': 'get'})
        self.assertEqual(run.call_args.kwargs['timeout'], 45)
        self.assertTrue(result['isError'])
        with patch.object(mcp.subprocess, 'run', side_effect=subprocess.TimeoutExpired('helper', 360)):
            self.assertTrue(mcp._call_helper({'operation': 'propose'})['isError'])

    def test_tool_instructs_complete_candidate_and_one_approval(self):
        tool = next(x for x in mcp.TOOLS if x['name'] == 'propose_rule_change')
        self.assertIn('128 KiB', tool['description'])
        self.assertIn('single approval', tool['description'])
        self.assertFalse(tool['inputSchema']['additionalProperties'])

    def test_operation_tools_dispatch_exact_fields_and_reject_extra_commands(self):
        cases = [
            ('propose_rule_edit', 'propose-edit', {'target':'a:modsecurity-custom', 'base_sha256':'a'*64,
                'edits':[{'old_text':'# existing\n', 'new_text':'# updated\n'}], 'reason':'localized change'}),
            ('get_service_action_target', 'service-get', {'target': 'a:waf'}),
            ('propose_service_action', 'service-propose', {'target':'a:waf', 'action':'reload', 'base_state_sha256':'a'*64, 'reason':'verify'}),
            ('temporarily_contain_ip', 'contain-ip', {'ip':'8.9.10.11', 'reason':'verified attack'}),
            ('get_operation_status', 'operation-status', {'request_id':'a'*32}),
        ]
        for name, op, args in cases:
            msg = {'id':1,'method':'tools/call','params':{'name':name,'arguments':args}}
            with patch.object(mcp, '_call_helper', return_value=mcp._result({'ok':True})) as call:
                self.assertFalse(mcp.handle(msg)['result']['isError'])
                call.assert_called_once_with({'operation':op, **args})
            msg['params']['arguments'] = {**args, 'command':'arbitrary command'}
            with patch.object(mcp, '_call_helper') as call:
                self.assertTrue(mcp.handle(msg)['result']['isError'])
                call.assert_not_called()

    def test_operation_schemas_expose_no_arbitrary_install_or_container_tool(self):
        self.assertEqual(len(mcp.TOOLS), 8)
        for tool in mcp.TOOLS:
            self.assertFalse(tool['inputSchema']['additionalProperties'])
        tool = next(t for t in mcp.TOOLS if t['name']=='propose_service_action')
        self.assertEqual(tool['inputSchema']['properties']['target']['enum'], mcp.SERVICE_TARGETS)
        self.assertEqual(tool['inputSchema']['properties']['action']['enum'], ['restart','reload'])

    def test_exact_edit_schema_and_validation_timeout(self):
        tool = next(t for t in mcp.TOOLS if t['name'] == 'propose_rule_edit')
        schema = tool['inputSchema']['properties']['edits']
        self.assertEqual((schema['minItems'], schema['maxItems']), (1, 16))
        self.assertFalse(schema['items']['additionalProperties'])
        self.assertEqual(set(schema['items']['required']), {'old_text', 'new_text'})
        self.assertEqual(schema['items']['properties']['old_text']['minLength'], 1)
        self.assertIn('original', tool['description'])
        payload = {'operation':'propose-edit', 'target':'a:modsecurity-custom', 'base_sha256':'a'*64,
                   'edits':[{'old_text':'# before\n','new_text':'# after\n'}], 'reason':'review'}
        with patch.object(mcp.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'{"status":"pending","review_posted":true}', b'')) as run:
            reply = mcp._call_helper(payload)
        self.assertFalse(reply['isError'])
        self.assertEqual(run.call_args.kwargs['timeout'], 360)
        self.assertEqual(json.loads(run.call_args.kwargs['input']), payload)

    def test_edit_tool_cannot_accept_whole_candidate_or_command(self):
        base = {'target':'a:modsecurity-custom', 'base_sha256':'a'*64,
                'edits':[{'old_text':'before','new_text':'after'}], 'reason':'review'}
        for extra in ({'candidate_content':'full file'}, {'command':'id'}, {'path':'/tmp/file'}):
            with self.subTest(extra=extra), patch.object(mcp, '_call_helper') as call:
                result = mcp.handle({'id':1,'method':'tools/call','params':{
                    'name':'propose_rule_edit','arguments':{**base, **extra}}})
                self.assertTrue(result['result']['isError'])
                call.assert_not_called()


if __name__ == '__main__':
    unittest.main()
