"""Native receipt projection and followups retain the same selected FW scope."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

import alignment
from test_completion import PLUGIN
from test_security_inventory import rows

path=Path(__file__).resolve().parents[2]/'ollama-trial/test_firewall_scope.py'
sys.path.insert(0,str(path.parent))
spec=importlib.util.spec_from_file_location('selected_fw_fixtures',path)
fixtures=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixtures)
H=alignment.load_harness()


class NativeFirewallScope(unittest.TestCase):
    def test_wrapped_native_and_sdk_selected_tables_are_identical(self):
        call=fixtures.snapshot();native=alignment.calls_from_rows(rows(call),PLUGIN._inventory_payload)
        for question in ('FW input만 보여줘','FW output 룰','FW mapped 체인 룰'):
            self.assertEqual(H.missing_reads(question,native),[])
            self.assertEqual(H.read_report(question,native),fixtures.h.read_report(question,[call]))

    def test_same_human_history_retains_hook_when_reformatting(self):
        previous='FW input 룰 보여줘';current='각각 표로 보여줘';call=fixtures.snapshot()
        messages=[{'role':'user','content':previous},*rows(call),{'role':'user','content':current}]
        resolved=alignment.resolve_rule_history(current,messages,len(messages)-1,PLUGIN,H)
        self.assertEqual(H.firewall_request(resolved)['firewall_display_scope']['hooks'],['input'])
        report=alignment.prior_read_report(resolved,messages,len(messages)-1,PLUGIN,H)
        self.assertIn('새 조회 없음',report);self.assertNotIn('| 80 |',report)

    def test_tampered_receipt_cannot_be_used_for_a_selected_view(self):
        call=fixtures.snapshot();messages=rows(call);messages[-1]['content']='tampered tool body'
        native=alignment.calls_from_rows(messages,PLUGIN._inventory_payload)
        self.assertTrue(H.missing_reads('FW input만',native))
        self.assertIn('미완료',H.read_report('FW input만',native))


if __name__=='__main__':unittest.main()
