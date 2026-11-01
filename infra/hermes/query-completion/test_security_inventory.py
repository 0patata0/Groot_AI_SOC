"""Native transport must retain full-device conditions and reject stale scope."""
import importlib.util
import json
from pathlib import Path
import unittest
import sys
import alignment
from test_completion import PLUGIN
from test_inventory_render import native_wrap

path=Path(__file__).resolve().parents[2]/'ollama-trial/test_security_inventory.py'
sys.path.insert(0,str(path.parent))
spec=importlib.util.spec_from_file_location('full_inventory_fixtures',path)
fixtures=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixtures)
H=alignment.load_harness()


def rows(call):
    name='mcp__'+call['server'].replace('-','_')+'__'+call['name']
    return [{'role':'assistant','tool_calls':[{'id':'read-full','type':'function','function':{
                 'name':name,'arguments':json.dumps(call['arguments'])}}]},
            {'role':'tool','tool_call_id':'read-full','content':native_wrap(json.dumps({'result':call['result']}),name)}]


class NativeFullInventory(unittest.TestCase):
    def test_native_reformat_reuses_bound_details_and_keeps_id(self):
        previous='Wazuh ID 5712 조건 보여줘';current='룰 각각 표로 보여줘'
        call=fixtures.fixture(view='details',rule_id='5712',total=1)
        messages=[{'role':'user','content':previous},*rows(call),{'role':'assistant','content':'untrusted paraphrase'},
                  {'role':'user','content':current}]
        resolved=alignment.resolve_rule_history(current,messages,len(messages)-1,PLUGIN,H)
        self.assertEqual(H.security_inventory_request(resolved)['rule_id'],'5712')
        report=alignment.prior_read_report(resolved,messages,len(messages)-1,PLUGIN,H)
        self.assertIn('| 5712 |',report);self.assertIn('새 조회 없음',report)
        messages[2]['content']='tampered tool body'
        self.assertIsNone(alignment.prior_read_report(resolved,messages,len(messages)-1,PLUGIN,H))

    def test_native_request_builder_returns_table_locally_without_read_selection(self):
        from types import SimpleNamespace
        from dataclasses import dataclass
        @dataclass
        class Request:
            api_kwargs:object
        previous='WAF 커스텀 룰 상세 조회';current='룰 각각 표로 보여줘'
        messages=[{'role':'user','content':previous},*rows(fixtures.fixture(target='a:waf',origin='custom',view='details')),
                  {'role':'user','content':current}]
        agent=SimpleNamespace(platform='mattermost',model='qwen3.6:35b',provider='custom',max_iterations=12,_current_turn_id='a')
        wrap=alignment.request_wrapper(lambda *a,**k:Request({'messages':messages,'tools':[]}),PLUGIN,H)
        wrap(agent,original_user_message=current,turn_id='a',messages=messages)
        self.assertIn('| 5712 |',agent._capstone_query_completion_local_format[1])
        self.assertIsNone(agent._capstone_read_selection)

    def test_native_wrapped_vendor_correlation_is_identical_to_sdk_evidence(self):
        call=fixtures.fixture(view='details',rule_id='5712',total=1)
        native=alignment.calls_from_rows(rows(call),PLUGIN._inventory_payload)
        question='Wazuh ID 5712 조건 보여줘'
        self.assertEqual(H.missing_reads(question,native),[])
        self.assertEqual(H.read_report(question,native),fixtures.H.read_report(question,[call]))

    def test_native_custom_subset_does_not_satisfy_full_device_request(self):
        call=fixtures.fixture(origin='custom')
        native=alignment.calls_from_rows(rows(call),PLUGIN._inventory_payload)
        self.assertEqual(H.missing_reads('Wazuh 룰',native),['b:wazuh'])
        self.assertEqual(H.missing_reads('Wazuh 커스텀 룰',native),[])


if __name__=='__main__':unittest.main()
