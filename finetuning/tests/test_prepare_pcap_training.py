import json,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from prepare_pcap_training import summarize,port

class PcapPreparationTests(unittest.TestCase):
 def test_port_encodings(self):
  self.assertEqual(port('53'),53);self.assertEqual(port('0x35'),53);self.assertIsNone(port(''))
 def test_flow_is_not_query_or_packet_count(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'obs.jsonl'
   values=[{'id':'1','protocol':'udp','source_port_raw':'53','destination_port_raw':'3000','packets':5,'bytes':100,'observed_at_source':'2011-08-15T12:00:00'},
           {'id':'2','protocol':'tcp','source_port_raw':'4000','destination_port_raw':'53','packets':7,'bytes':200,'observed_at_source':'2011-08-15T12:01:00'},
           {'id':'3','protocol':'icmp','source_port_raw':'53','destination_port_raw':'53','packets':13,'bytes':500,'observed_at_source':'2011-08-15T12:02:00'}]
   path.write_text(''.join(json.dumps(x)+'\n' for x in values));r=summarize(path)
   self.assertEqual(r['flow_records'],3);self.assertEqual(r['packet_count_bidirectional'],25)
   self.assertEqual(r['port53_tcp_udp_flow_records'],2);self.assertEqual(r['icmp_family_flow_records'],1)
   self.assertEqual(r['first_to_last_flow_start_span_seconds'],120);self.assertEqual(r['highest_packet_flow']['id'],'3')
   self.assertEqual(r['clock_timezone'],'unverified')
 def test_duplicate_identifier_refused(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'obs';r={'id':'x','protocol':'udp','source_port_raw':'53','destination_port_raw':'3000','packets':5,'bytes':100,'observed_at_source':'2011-08-15T12:00:00'}
   p.write_text((json.dumps(r)+'\n')*2)
   with self.assertRaises(ValueError):summarize(p)

if __name__=='__main__':unittest.main()
