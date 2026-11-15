"""Read intent counterexamples and source-receipt scope regression tests."""
from pathlib import Path
import copy,hashlib,importlib.util,json,os,sys,unittest
from unittest.mock import patch
ROOT=Path(os.environ['SOC_INTENT_ROOT']);sys.path.insert(0,str(ROOT/'infra/ollama-trial'));import harness as h
sys.path.insert(0,str(ROOT/'infra/ollama-trial'));from test_event_lookup import receipt,Clock
class Intent(unittest.TestCase):
 def setUp(self):
  self.clock=patch.object(h,'datetime',Clock);self.clock.start();self.addCleanup(self.clock.stop)
 def test_conversational_verbs_across_sensors(self):
  for device,source in [('WAF','modsecurity'),('IDS','suricata'),('Wazuh','wazuh')]:
   for verb in ['봐줘','봐 줄래','볼래','확인해 줄래','조회해 주세요','정리 부탁해','보여 주실래']:
    with self.subTest(device=device,verb=verb):self.assertEqual(h.event_lookup_scope(device+' 경보 좀 '+verb),{'mcp__security_events__search_'+source+'_alerts'})
 def test_verb_removal_keeps_objects_and_negation(self):
  for text in ['조회하지마','보지마','확인하지마','봐야해','조회 실패했다','download','restart','showcase']:
   self.assertEqual(h.CONTRACT.read_action_remainder(text),text)
 def test_dns_selects_alerts_never_rule_files(self):
  for q in ['DNS 경보 좀 봐줘','DNS 로그 확인해 줄래','최근 30분 DNS 경보 볼래','Suricata DNS 로그 봐줘']:
   with self.subTest(q=q):
    self.assertEqual(h.tool_scope(q),{'mcp__security_events__search_suricata_alerts'});self.assertTrue(h.structured_read(q));self.assertEqual(h.workflow_names(q),('soc-query',))
 def test_unknown_constraints_and_mixed_tasks_not_silently_erased(self):
  for q in ['DNS 경보 192.0.2.1만 봐줘','DNS 경보 목적지 1.1.1.1 봐줘','DNS 경보 오늘 말고 어제 봐줘','DNS 경보 삭제해줘','DNS 경보 왜 그런지 조사해줘','DNS 경보 위험한지 판단해줘','WAF DNS 경보 봐줘','Wazuh DNS 로그 봐줘','DNS 경보 전체 봐줘','DNS 경보 100건 봐줘','DNS 경보 보지마','DNS 경보 아니면 HTTP 경보 봐줘','xDNS 경보 봐줘']:
   with self.subTest(q=q):self.assertIsNone(h.event_lookup_scope(q))
 def test_os_log_request_is_not_current_diagnostic(self):
  q='B systemd 오류 로그 좀 봐줘'
  self.assertTrue(h.diagnostic_history_request(q));self.assertIsNone(h.diagnostic_request(q));self.assertIsNone(h.event_lookup_scope(q))
 def test_dns_proof_is_question_or_sensor_label_not_port_or_guess(self):
  rows=[{'signature':'ET DNS Query','n':1},{'dns_questions':[{'name':'example.test','type':'A'}],'n':2},{'destination_port':'53','n':3},{'signature':'DNSSECx','n':4},{'dns_questions':[{}],'n':5}]
  before=copy.deepcopy(rows);self.assertEqual([x['n'] for x in h.event_topic_rows('dns',rows)],[1,2]);self.assertEqual(rows,before)
 def test_non_dns_topic_does_not_filter_other_reports(self):
  rows=[{'signature':'http'},{'signature':'dns'}];self.assertEqual(h.event_topic_rows(None,rows),rows);self.assertIsNone(h.event_topic('IDS 로그 좀 봐줘'))
 def test_topic_schema_has_only_actual_catalog_fields(self):
  name='mcp__security_events__search_suricata_alerts';s={name:{'type':'object','properties':{'lookback_minutes':{'type':'integer','minimum':1,'maximum':1440},'limit':{'type':'integer','maximum':50},'signature_id':{'type':'string'}}}}
  before=copy.deepcopy(s);got=h.refine_read_schemas('최근 30분 DNS 경보 봐줘',s,[])
  self.assertEqual(got[name]['properties']['lookback_minutes']['enum'],[30]);self.assertNotIn('dns',str(got));self.assertNotIn('signature_id',got[name]['properties']);self.assertEqual(s,before)
 def test_topic_render_separates_returned_sample_and_displayed_matches(self):
  c=receipt('suricata',returned_count=3,alerts=[{'timestamp':'2026-11-08T12:59:00+09:00','signature':'ET DNS Query','signature_id':'1'},{'timestamp':'2026-11-08T12:59:00+09:00','signature':'ET HTTP','signature_id':'2'},{'timestamp':'2026-11-08T12:59:00+09:00','signature':'ET SSH','signature_id':'3'}]);before=copy.deepcopy(c)
  text=h.lookup_report('오늘 DNS 경보 봐줘',[c]);self.assertIn('전체 반환 표본 3건 중 DNS 관련 1건',text);self.assertIn('ET DNS Query',text);self.assertNotIn('ET HTTP',text);self.assertNotIn('ET SSH',text);self.assertIn('전체 DNS 경보 수 조회 아님',text);self.assertEqual(c,before)
 def test_topic_empty_subset_does_not_claim_absence(self):
  c=receipt('suricata');text=h.lookup_report('오늘 DNS 경보 봐줘',[c]);self.assertIn('전체 반환 표본 1건 중 DNS 관련 0건',text);self.assertIn('표본에서 DNS 관련 행 없음',text);self.assertIn('전체 경보·공격 부재의 증거가 아님',text)
 def test_zero_actual_sample_has_no_synthetic_rows(self):
  c=receipt('suricata',returned_count=0,alerts=[]);text=h.lookup_report('오늘 DNS 경보 봐줘',[c]);self.assertIn('전체 반환 표본 0건 중 DNS 관련 0건',text);self.assertNotIn('ET DNS',text)
 def test_failed_or_tampered_receipt_cannot_complete(self):
  c=receipt('suricata');c['result_sha256']='0'*64
  self.assertTrue(h.missing_reads('오늘 DNS 경보 봐줘',[c]));self.assertIn('미완료',h.lookup_report('오늘 DNS 경보 봐줘',[c]))
 def test_no_calls_cannot_complete(self):
  self.assertTrue(h.missing_reads('DNS 경보 봐줘',[]));self.assertIn('current_state_requires_actual_read',h.violations('DNS 경보 봐줘','이제 조회하겠습니다.',[]))
 def test_failed_read_not_repeated(self):
  name='mcp__security_events__search_suricata_alerts';s={name:{'type':'object','properties':{'lookback_minutes':{'type':'integer'}}}}
  self.assertEqual(h.refine_read_schemas('DNS 경보 봐줘',s,[dict(receipt('suricata'),is_error=True)]),{})
 def test_explicit_count_bound_stays_exact(self):
  self.assertEqual(h._event_lookup_request('IDS 경보 7건 봐줘')[1],7)
 def test_non_topic_existing_waf_block_report_unchanged(self):
  self.assertEqual(h.lookup_report('오늘 WAF 차단 로그 보여줘',[receipt()]),h.event_report('오늘 WAF 차단 로그 보여줘',[receipt()]))
if __name__=='__main__':unittest.main(verbosity=2)
