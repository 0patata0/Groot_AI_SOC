import io
import json
import unittest
from inspect_dedale_network import alert_fields, host_transport_tuple, inspect_alerts, inspect_host_records


class NetworkEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.row = {'@timestamp': 1734912021587, 'timestamp': 1734912021587,
                    'timestamp8601': 1734912021587, 'host': '192.0.2.1',
                    'program': 'suricata', 'priority': 30, 'severity': 6,
                    'message': '[1:1234:5] Fixture [Classification: Misc activity] [Priority: 2] {TCP} 192.0.2.2:80 -> 192.0.2.3:12345\n'}
    def encoded(self, row):return json.dumps(row).encode()+b'\n'
    def test_no_timestamp_unit_guess_and_observer_not_target(self):
        p=alert_fields(self.row)
        self.assertIsNone(p['timestamp_kst']);self.assertEqual(p['sensor_ip'],'192.0.2.1')
        self.assertEqual(p['destination_ip'],'192.0.2.3');self.assertEqual(p['alert_priority'],2)
    def test_explicit_clock_contract_converts_exact_milliseconds_to_kst(self):
        p=alert_fields(self.row,timestamp_unit='epoch-ms')
        self.assertEqual(p['timestamp_kst'],'2024-12-23T09:00:21.587000+09:00')
    def test_conflicting_boolean_and_unknown_time_contract_rejected(self):
        for row in [{**self.row,'timestamp':1},{**self.row,'@timestamp':True}]:
            with self.assertRaises(ValueError):alert_fields(row)
        with self.assertRaises(ValueError):alert_fields(self.row,timestamp_unit='guess')
    def test_ipv6_endpoints_supported(self):
        row={**self.row,'message':self.row['message'].replace('192.0.2.2:80','[2001:db8::2]:80').replace('192.0.2.3:12345','2001:db8::3:12345')}
        p=alert_fields(row);self.assertEqual(p['source_ip'],'2001:db8::2');self.assertEqual(p['destination_port'],12345)
    def test_invalid_ports_and_hidden_second_line_rejected(self):
        for value in [self.row['message'].replace(':12345',':65536'),self.row['message']+'another event',self.row['message'].replace('192.0.2.2','999.0.2.2')]:
            with self.assertRaises(ValueError):alert_fields({**self.row,'message':value})
    def test_dns_answer_is_not_transport_connection(self):
        with self.assertRaises(ValueError):host_transport_tuple({'network':{'protocol':'dns'},'dns':{'answers':[{'data':'192.0.2.3'}]}})
    def test_partial_endpoint_or_wildcard_cannot_form_connection(self):
        for v in [{'source':{'ip':'192.0.2.2'}},{'source':{'ip':'192.0.2.2','port':2},'destination':{'ip':'0.0.0.0','port':22}}]:
            with self.assertRaises(ValueError):host_transport_tuple({'network':{'transport':'tcp'},**v})
    def test_complete_explicit_host_tuple(self):
        v={'network':{'transport':'TCP'},'source':{'ip':'192.0.2.2','port':'42'},'destination':{'ip':'192.0.2.3','port':22}}
        self.assertEqual(host_transport_tuple(v),('tcp','192.0.2.2',42,'192.0.2.3',22))
    def test_same_sid_time_different_sensors_are_retained(self):
        rows=[self.row,{**self.row,'host':'192.0.2.9'}]
        r=inspect_alerts(map(self.encoded,rows))
        self.assertEqual(r['counts']['records'],2);self.assertEqual(len(r['sensor_counts']),2)
        self.assertEqual(r['confirmed_host_incident_links'],0)
    def test_regression_and_exact_raw_sha_preserved(self):
        later={**self.row,**{k:1734912021588 for k in ['@timestamp','timestamp','timestamp8601']}}
        lines=[self.encoded(later),self.encoded(self.row)];r=inspect_alerts(lines)
        self.assertEqual(r['counts']['time_regressions'],1);self.assertEqual(r['bytes'],sum(map(len,lines)))
    def test_host_inventory_does_not_expand_label_scope_to_all_logs(self):
        row={'event':{'module':'sysmon','code':'22','action':'Dns query (rule: DnsQuery)'},'network':{'protocol':'dns'},'host':{'name':'fixture'}}
        r=inspect_host_records([self.encoded(row)],source='labels')
        self.assertEqual(r['counts']['dns_event'],1);self.assertEqual(r['counts']['sysmon_event_3'],0)
        self.assertEqual(r['counts']['complete_explicit_ecs_transport_tuple'],0)
    def test_malformed_alert_fails_instead_of_silent_omission(self):
        with self.assertRaises(ValueError):inspect_alerts([self.encoded({**self.row,'message':'bad'})])


if __name__=='__main__':unittest.main()
