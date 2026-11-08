import copy,importlib.util,json,sys,unittest
from pathlib import Path
from unittest.mock import patch,Mock
spec=importlib.util.spec_from_file_location('policy_soc_test',Path(__file__).with_name('soc_bot.py'));bot=importlib.util.module_from_spec(spec);spec.loader.exec_module(bot)

def receipt():
 return {'schema':1,'changes':[{'name':'관리 SSH SYN 오탐 예외','signature_id':2001219,'source_ip':'192.168.16.231','destination_ip':'192.168.16.230','destination_port':22,'effective_at':'2026-11-07T11:45:46+09:00','evidence_sha256':'a'*64}]}

def fakepath():
 p=Mock();p.exists.return_value=True;p.is_symlink.return_value=False;p.is_file.return_value=True;p.stat.return_value=Mock(st_uid=0,st_mode=0o640,st_size=600);p.read_text.return_value=json.dumps(receipt());return p

def response(before=4,after=0):return {'timed_out':False,'_shards':{'failed':0},'aggregations':{'periods':{'buckets':{'before':{'doc_count':before},'after':{'doc_count':after}}}}}

class PolicyReportTests(unittest.TestCase):
 def test_exact_flow_and_time_boundary_no_original_query_filter(self):
  with patch.object(bot,'Path',return_value=fakepath()),patch.object(bot,'idx_search',return_value=response())as search:
   text=bot.policy_change_report(60)
  q=search.call_args.args[1];terms=q['query']['bool']['filter'];self.assertIn({'term':{'data.src_ip':'192.168.16.231'}},terms);self.assertIn({'term':{'data.dest_ip':'192.168.16.230'}},terms);self.assertIn({'term':{'data.dest_port':'22'}},terms);self.assertIn({'term':{'data.alert.signature_id':'2001219'}},terms)
  self.assertEqual(set(q['aggs']['periods']['filters']['filters']['before']['range']['timestamp']),{'lt'});self.assertEqual(set(q['aggs']['periods']['filters']['filters']['after']['range']['timestamp']),{'gte'})
  self.assertIn('| 4 | 0 |',text);self.assertIn('과거 기록',text);self.assertNotIn('```',text)
 def test_new_alerts_are_never_hidden(self):
  with patch.object(bot,'Path',return_value=fakepath()),patch.object(bot,'idx_search',return_value=response(4,2)):
   self.assertIn('| 4 | 2 |',bot.policy_change_report(60))
 def test_zero_zero_comparison_is_omitted_but_matching_history_stays_visible(self):
  with patch.object(bot,'Path',return_value=fakepath()),patch.object(bot,'idx_search',return_value=response(0,0)):
   self.assertEqual(bot.policy_change_report(60),'')
  with patch.object(bot,'Path',return_value=fakepath()),patch.object(bot,'idx_search',return_value=response(0,2)):
   self.assertIn('| 0 | 2 |',bot.policy_change_report(60))
 def test_failed_or_partial_query_not_zero(self):
  for value in ({'timed_out':True},{'_shards':{'failed':1}},response(4,-1),response(4,False),{}):
   with self.subTest(value=value),patch.object(bot,'Path',return_value=fakepath()),patch.object(bot,'idx_search',return_value=value):
    self.assertIn('조회 실패',bot.policy_change_report(60))
 def test_invalid_policy_refused(self):
  for field,value in [('source_ip','0.0.0.0/0'),('destination_port',True),('effective_at','2026-11-07T02:45:46'),('evidence_sha256','bad'),('signature_id',True)]:
   r=receipt();r['changes'][0][field]=value
   with self.subTest(field=field),self.assertRaises((ValueError,TypeError)):bot.report_policy_changes(r)
 def test_unsafe_file_refused(self):
  for field,value in [('st_uid',1000),('st_mode',0o666),('st_size',9000)]:
   p=fakepath();setattr(p.stat.return_value,field,value)
   with patch.object(bot,'Path',return_value=p),patch.object(bot,'idx_search')as search:
    self.assertIn('조회 실패',bot.policy_change_report(60));search.assert_not_called()
 def test_initial_missing_or_empty_policy_unchanged(self):
  p=fakepath();p.exists.return_value=False
  with patch.object(bot,'Path',return_value=p):self.assertEqual(bot.policy_change_report(60),'')
  p=fakepath();p.read_text.return_value='{"schema":1,"changes":[]}'
  with patch.object(bot,'Path',return_value=p):self.assertEqual(bot.policy_change_report(60),'')
 def test_card_keeps_original_counts_and_adds_context(self):
  agg={'total':4,'rules':[('ET SCAN Potential SSH Scan',4)],'src':[],'agent':[]}
  with patch.object(bot,'agg_alerts',return_value=(agg,None)),patch.object(bot,'recent_alerts',return_value=([],None)),patch.object(bot,'action_report',return_value='history'),patch.object(bot,'policy_change_report',return_value='POLICY_NOTE'):
   text=bot.build_report(60)['attachments'][0]['text']
  self.assertIn('**4건**',text);self.assertIn('POLICY_NOTE',text);self.assertIn('ET SCAN Potential SSH Scan',text)
 def test_recent_alert_table_has_description_and_observed_source_not_attacker(self):
  agg={'total':1,'rules':[],'src':[('192.0.2.1',1)],'agent':[]}
  rows=[{'ts':'2026-11-08 12:00 KST','id':'31533','level':10,'desc':'POST | frequency','agent':'web','srcip':'192.0.2.1'}]
  with patch.object(bot,'agg_alerts',return_value=(agg,None)),patch.object(bot,'recent_alerts',return_value=(rows,None)),patch.object(bot,'action_report',return_value='history'),patch.object(bot,'policy_change_report',return_value=''):
   text=bot.build_report(60)['attachments'][0]['text']
  self.assertIn('Wazuh ID/레벨 | 경보 내용',text);self.assertIn('POST \\| frequency',text)
  self.assertIn('프록시·NAT',text);self.assertIn('실제 요청자와 다를 수',text)
  self.assertNotIn('공격자 IP',text)
if __name__=='__main__':unittest.main()
