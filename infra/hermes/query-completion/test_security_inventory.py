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
