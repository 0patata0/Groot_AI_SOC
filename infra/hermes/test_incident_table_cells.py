"""Report granularity without lost observations or invented IP/time pairings."""
import copy
import re
import unittest

import soc_management_run as m
import chat_markdown


class IncidentCells(unittest.TestCase):
    def test_many_observations_keep_one_address_and_time_per_cell(self):
        observations=[{'timestamp_kst':f'2026-11-17T13:51:{i:02d}+09:00',
            'source_ip':f'192.0.2.{i+1}','destination_ip':'198.51.100.20','sensor_agent':'sensor-a'}
            for i in range(20)]
        facts=[{'kind':'events','source':'suricata','returned_count':20,'indexed_window_total_count':None,
            'requested_since_kst':'2026-11-17T13:51:00+09:00','requested_until_kst':'2026-11-17T13:52:00+09:00',
            'sensor_rule_ids':['1000001','2058076'],'wazuh_rule_ids':['100110'],
            'observations':observations,'source_ips':[v['source_ip'] for v in observations]}]
        before=copy.deepcopy(facts)
        text=m.literal_evidence_table(facts)
        self.assertEqual(facts,before)
        lines=text.splitlines()
        for observation in observations:
            matches=[line for line in lines if '| '+observation['source_ip']+' |' in line]
            self.assertEqual(len(matches),1)
            self.assertIn(observation['timestamp_kst'],matches[0])
            self.assertIn('| 198.51.100.20 |',matches[0])
        for line in lines:
            if not line.startswith('|'):continue
            for cell in re.split(r'(?<!\\)\|',line)[1:-1]:
                self.assertLessEqual(len(re.findall(r'(?:\d{1,3}\.){3}\d{1,3}',cell)),1,cell)
                self.assertLessEqual(len(re.findall(r'\d{2}:\d{2}:\d{2}',cell)),1,cell)
        self.assertIn('| Suricata SID | 2058076 |',text)
        self.assertIn('| Wazuh 규칙 ID | 100110 |',text)
        self.assertIn('전체 건수 미확인',text)
        self.assertEqual(m.evidence_claim_violations(text,facts),[])
        normalized=chat_markdown.normalize_tables(text)
        for observation in observations:self.assertIn('| '+observation['source_ip']+' |',normalized)

    def test_aggregate_address_has_no_invented_time_or_rule_pairing(self):
        fact={'kind':'events','source':'modsecurity','returned_count':3,
              'requested_since_kst':'2026-11-17T12:00:00+09:00','requested_until_kst':'2026-11-17T13:00:00+09:00',
              'sensor_rule_ids':['942100'],'source_ips':['2001:db8::1','192.0.2.7'],'observations':[]}
        text=m.literal_evidence_table([fact])
        self.assertIn('시각 대응 미확인',text)
        for number,ip in enumerate(fact['source_ips'],1):
            line=next(line for line in text.splitlines() if '| '+ip+' |' in line)
            self.assertEqual(line,'| '+str(number)+' | '+ip+' |')
        self.assertIn('WAF 룰 ID',text)
        self.assertNotIn('Suricata SID',text)
        self.assertIn('시각 확인 관측 0행',text)

    def test_observations_at_the_same_time_are_not_dropped(self):
        event={'timestamp_kst':'2026-11-17T13:00:00+09:00','source_ip':'192.0.2.7'}
        text=m.literal_evidence_table([{'kind':'events','source':'wazuh','returned_count':2,'observations':[event,event]}])
        self.assertEqual(text.count('| 192.0.2.7 |'),2)
        self.assertIn('| 1 | 2026-11-17T13:00:00+09:00',text)
        self.assertIn('| 2 | 2026-11-17T13:00:00+09:00',text)

    def test_blocks_and_generic_timestamps_have_separate_rows(self):
        facts=[{'kind':'blocks','count':2,'addresses':['192.0.2.1','2001:db8::1']},
               {'kind':'times','instants':['2026-11-17T12:00:00+09:00','2026-11-17T13:00:00+09:00']}]
        text=m.literal_evidence_table(facts)
        for number,ip in enumerate(facts[0]['addresses'],1):self.assertIn('\n| '+str(number)+' | '+ip+' |\n',text)
        for number,stamp in enumerate(facts[1]['instants'],1):self.assertIn('\n| '+str(number)+' | '+stamp+' (KST) |',text)
        self.assertIn('현재 항목 2개',text)

    def test_source_fields_cannot_add_table_rows_or_html(self):
        fact={'kind':'events','source':'suricata','observations':[{'timestamp_kst':'2026-11-17T13:00:00+09:00',
              'source_ip':'192.0.2.7','sensor_agent':'a|<img>\nforged'}]}
        text=m.literal_evidence_table([fact])
        self.assertIn(r'a\|&lt;img&gt; forged',text)
        self.assertNotIn('<img>',text)
        self.assertNotIn('\nforged',text)


if __name__=='__main__':unittest.main()
