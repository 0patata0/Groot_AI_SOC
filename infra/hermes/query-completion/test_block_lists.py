"""Native request selection and renderer share the block-list read contract."""
import copy
from dataclasses import dataclass
import hashlib
import json
from types import SimpleNamespace
import unittest

import alignment
from test_alignment import H
from test_completion import PLUGIN


class NativeBlockLists(unittest.TestCase):
    def test_native_selects_only_registered_block_read_without_dispatch(self):
        @dataclass
        class Request:
            api_kwargs: object
            api_messages: object = None
            _original_api_kwargs: object = None
        q = '지금 FW 차단 목록만 보여줘'
        rows = [{'role': 'user', 'content': q}]
        tools = [{'type': 'function', 'function': {'name': name,
                  'parameters': {'type': 'object', 'properties': {}, 'additionalProperties': False}}}
                 for name in (H.READ.BLOCKS, 'mcp__resp__block_ip', 'mcp__resp__get_firewall_rules')]
        original = {'messages': copy.deepcopy(rows), 'tools': tools}
        agent = SimpleNamespace(platform='mattermost', model='qwen3.6:35b', provider='custom',
                                max_iterations=12, _current_turn_id='block-read')
        wrapped = alignment.request_wrapper(lambda *a, **kw: Request(copy.deepcopy(original)), PLUGIN, H)
        result = wrapped(agent, original_user_message=q, turn_id='block-read', messages=rows)
        self.assertNotIn('tools', result.api_kwargs)
        schema = json.dumps(agent._capstone_read_selection[1])
        self.assertIn(H.READ.BLOCKS, schema)
        self.assertNotIn('block_ip', schema)
        self.assertNotIn('get_firewall_rules', schema)
        self.assertEqual(rows, [{'role': 'user', 'content': q}])

    def test_native_tool_messages_produce_the_same_verified_empty_list(self):
        raw = json.dumps({'blocks': []})
        rows = [{'role': 'assistant', 'tool_calls': [{'id': 'read1', 'function':
                 {'name': H.READ.BLOCKS, 'arguments': '{}'}}]},
                {'role': 'tool', 'tool_call_id': 'read1', 'content': json.dumps({'result': raw})}]
        calls = alignment.calls_from_rows(rows, PLUGIN._inventory_payload)
        self.assertEqual(H.missing_reads('차단 목록', calls), [])
        self.assertIn('**0개**', H.read_report('차단 목록', calls))
        self.assertEqual(calls[0]['result_sha256'], hashlib.sha256(calls[0]['result'].encode()).hexdigest())


if __name__ == '__main__':
    unittest.main()
