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
            access = 'read' if name in mcp.READ_TOOLS else 'write'
            msg = {'id':1,'method':'tools/call','params':{'name':name,'arguments':args}}
            with patch.object(mcp, '_call_helper', return_value=mcp._result({'ok':True})) as call:
                self.assertFalse(mcp.handle(msg, access)['result']['isError'])
                call.assert_called_once_with({'operation':op, **args}, readonly=(access == 'read'))
            msg['params']['arguments'] = {**args, 'command':'arbitrary command'}
            with patch.object(mcp, '_call_helper') as call:
                self.assertTrue(mcp.handle(msg, access)['result']['isError'])
                call.assert_not_called()

    def test_harness_check_status_is_read_only_on_siem_host_only(self):
        read_b = {t['name'] for t in mcp.tool_list('read', 'b')}
        self.assertIn('get_harness_check_status', read_b)
        for access, host in (('read', 'a'), ('write', 'a'), ('write', 'b')):
            self.assertNotIn('get_harness_check_status', {t['name'] for t in mcp.tool_list(access, host)})
        self.assertIn('get_harness_check_status', mcp.READ_TOOLS)
        tool = next(t for t in mcp.TOOLS if t['name'] == 'get_harness_check_status')
        self.assertTrue(tool['annotations']['readOnlyHint'])
        self.assertFalse(tool['annotations']['destructiveHint'])
        self.assertFalse(tool['inputSchema']['additionalProperties'])
        self.assertEqual(tool['inputSchema']['properties'], {})
        self.assertIn('approval', tool['description'])

    def test_harness_check_status_dispatches_fixed_read_operation(self):
        msg = {'id': 1, 'method': 'tools/call',
               'params': {'name': 'get_harness_check_status', 'arguments': {}}}
        with patch.object(mcp, '_call_helper', return_value=mcp._result({'scope': 'structural checks', 'status': 'passed'})) as call:
            reply = mcp.handle(msg, 'read', 'b')
        self.assertFalse(reply['result']['isError'])
        call.assert_called_once_with({'operation': 'harness-status'}, readonly=True)
        # Any argument is rejected before the helper runs.
        msg['params']['arguments'] = {'origin': 'all'}
        with patch.object(mcp, '_call_helper') as call:
            self.assertTrue(mcp.handle(msg, 'read', 'b')['result']['isError'])
            call.assert_not_called()
        # The write MCP never advertises or dispatches this read tool.
        msg['params']['arguments'] = {}
        self.assertEqual(mcp.handle(msg, 'write', 'b')['error']['code'], -32602)

    def test_request_harness_check_is_write_tool_on_siem_host_only(self):
        write_b = {t['name'] for t in mcp.tool_list('write', 'b')}
        self.assertIn('request_harness_check', write_b)
        for access, host in (('read', 'b'), ('read', 'a'), ('write', 'a')):
            self.assertNotIn('request_harness_check', {t['name'] for t in mcp.tool_list(access, host)})
        self.assertNotIn('request_harness_check', mcp.READ_TOOLS)
        tool = next(t for t in mcp.TOOLS if t['name'] == 'request_harness_check')
        self.assertFalse(tool['annotations']['readOnlyHint'])
        self.assertFalse(tool['annotations']['destructiveHint'])
        self.assertFalse(tool['inputSchema']['additionalProperties'])
        self.assertEqual(set(tool['inputSchema']['required']), {'reason'})
        self.assertIn('approv', tool['description'].lower())

    def test_request_harness_check_dispatches_exact_fields(self):
        msg = {'id': 1, 'method': 'tools/call',
               'params': {'name': 'request_harness_check', 'arguments': {'reason': '분기 점검 요청'}}}
        with patch.object(mcp, '_call_helper', return_value=mcp._result({'status': 'posting'})) as call:
            reply = mcp.handle(msg, 'write', 'b')
        self.assertFalse(reply['result']['isError'])
        call.assert_called_once_with({'operation': 'harness-check-request', 'reason': '분기 점검 요청'}, readonly=False)
        # Extra/arbitrary fields are rejected before the helper runs.
        for extra in ({'command': 'id'}, {'unit': 'x.service'}):
            with patch.object(mcp, '_call_helper') as call:
                msg['params']['arguments'] = {'reason': 'x', **extra}
                self.assertTrue(mcp.handle(msg, 'write', 'b')['result']['isError'])
                call.assert_not_called()
        # The read MCP never advertises or dispatches this write tool.
        msg['params']['arguments'] = {'reason': 'x'}
        self.assertEqual(mcp.handle(msg, 'read', 'b')['error']['code'], -32602)

    def test_harness_check_request_uses_card_posting_timeout(self):
        with patch.object(mcp.subprocess, 'run',
                          return_value=subprocess.CompletedProcess([], 0, b'{"status":"posting"}', b'')) as run:
            mcp._call_helper({'operation': 'harness-check-request', 'reason': 'x'})
        self.assertEqual(run.call_args.kwargs['timeout'], 360)

    def test_harness_review_tools_are_write_tools_on_siem_host_only(self):
        write_b = {t['name'] for t in mcp.tool_list('write', 'b')}
        for name in ('request_harness_skill_resync', 'acknowledge_harness_finding'):
            self.assertIn(name, write_b)
            self.assertNotIn(name, mcp.READ_TOOLS)
            for access, host in (('read', 'b'), ('write', 'a')):
                self.assertNotIn(name, {t['name'] for t in mcp.tool_list(access, host)})
        resync = next(t for t in mcp.TOOLS if t['name'] == 'request_harness_skill_resync')
        self.assertTrue(resync['annotations']['destructiveHint'])
        self.assertEqual(resync['inputSchema']['properties']['skill']['enum'],
                         ['soc-output', 'soc-query', 'soc-investigate', 'soc-change', 'soc-recover'])
        self.assertEqual(set(resync['inputSchema']['required']),
                         {'skill', 'source_surface', 'target_surface', 'report_sha256', 'reason'})

    def test_harness_review_tools_dispatch_exact_operations(self):
        resync_args = {'skill': 'soc-query', 'source_surface': 'management', 'target_surface': 'sdk',
                       'report_sha256': 'a' * 64, 'reason': '교차본 드리프트 정본 재동기화'}
        ack_args = {'draft_kind': 'review_structural_findings', 'reference': 'soc-change',
                    'report_sha256': 'b' * 64, 'reason': '확인 기록'}
        for name, op, args in (('request_harness_skill_resync', 'harness-review-resync', resync_args),
                               ('acknowledge_harness_finding', 'harness-review-ack', ack_args)):
            msg = {'id': 1, 'method': 'tools/call', 'params': {'name': name, 'arguments': args}}
            with patch.object(mcp, '_call_helper', return_value=mcp._result({'status': 'posting'})) as call:
                self.assertFalse(mcp.handle(msg, 'write', 'b')['result']['isError'])
                call.assert_called_once_with({'operation': op, **args}, readonly=False)
            # extra/arbitrary field rejected before the helper runs
            with patch.object(mcp, '_call_helper') as call:
                msg['params']['arguments'] = {**args, 'path': '/etc/evil'}
                self.assertTrue(mcp.handle(msg, 'write', 'b')['result']['isError'])
                call.assert_not_called()
            # not advertised on the read MCP
            msg['params']['arguments'] = args
            self.assertEqual(mcp.handle(msg, 'read', 'b')['error']['code'], -32602)

    def test_operation_schemas_expose_no_arbitrary_install_or_container_tool(self):
        self.assertEqual(len(mcp.TOOLS), 13)
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
