import json
import unittest
from datetime import datetime,timezone
from unittest.mock import patch
from test_security_events_mcp import module as M


class HistoricalWazuh(unittest.TestCase):
    def test_exact_window_rule_and_agent_filters_without_custom_query(self):
        args=M.validate_args('wazuh',{'since_kst':'2026-10-31T12:56:11+09:00','until_kst':'2026-10-31T13:56:11+09:00','wazuh_rule_id':'40704','agent_id':'001'})
        query=M.build_query('wazuh',args,datetime(2026,10,31,6,tzinfo=timezone.utc))
        text=json.dumps(query)
        self.assertIn('40704',text);self.assertIn('agent.id',text);self.assertNotIn('rule.groups',text)
        for bad in ({'query':{}},{'command':'restart'},{'agent_id':'../root'},{'wazuh_rule_id':'*'}):
            with self.assertRaises(ValueError):M.validate_args('wazuh',bad)

    def test_unit_and_exit_are_projected_without_raw_log_or_command(self):
        value=M.summarize_wazuh({'timestamp':'2026-10-31T04:55:47Z','rule':{'id':'40704','description':'Service exited','level':5},
            'agent':{'id':'001','name':'host'},'full_log':'systemd[1]: example.service: Main process exited, code=exited, status=1/FAILURE secret_token=DO_NOT_EXPORT'})
        self.assertEqual(value['service_units'],['example.service']);self.assertEqual(value['exit_status']['status'],'1')
        self.assertEqual(value['timestamp'],'2026-10-31T13:55:47+09:00');self.assertNotIn('DO_NOT_EXPORT',json.dumps(value))
        self.assertFalse(value['raw_log_returned'])

    def test_empty_sample_is_not_a_total_or_recovery_claim(self):
        with patch.object(M,'indexer_search',return_value={'hits':{'hits':[]}}):
            value=M.search('wazuh',{'limit':10})
        self.assertEqual(value['source'],'wazuh');self.assertEqual(value['returned_count'],0)
        self.assertIsNone(value['indexed_window_total_count']);self.assertTrue(value['untrusted_evidence'])

if __name__=='__main__':unittest.main()
