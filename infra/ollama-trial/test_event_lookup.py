"""Plain listings retain real reads, scope and the shared table on every path."""
import copy
from datetime import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import harness as h

NOW = datetime.fromisoformat('2026-11-08T13:00:00+09:00')
class Clock(datetime):
    @classmethod
    def now(cls, tz=None): return NOW.astimezone(tz) if tz else NOW.replace(tzinfo=None)


def receipt(source='modsecurity', **changes):
    start='2026-11-08T00:00:00+09:00';end='2026-11-08T12:59:30+09:00'
    data={'source':source,'applied_filters':{},'window_mode':'explicit_bounds',
          'requested_since_kst':start,'requested_until_kst':end,'returned_count':1,
          'limit':50,'scan_capped':False,'alerts':[{'timestamp':end,'http_status':403,
              'engine':'Enabled','request_path':'/fixture','method':'GET','waf_rule_ids':['123'],
              'waf_rule_matches':[{'rule_id':'123','description':'fixture'}]}]}
    data.update(changes)
    raw=json.dumps(data)
    return {'server':'security-events','name':'search_'+source+'_alerts',
            'arguments':{'since_kst':start,'until_kst':end,'limit':50},'result':raw,
            'result_sha256':hashlib.sha256(raw.encode()).hexdigest(),'is_error':False,'is_write':False}


class EventLookup(unittest.TestCase):
    def setUp(self):
        self.clock=patch.object(h,'datetime',Clock);self.clock.start();self.addCleanup(self.clock.stop)

    def test_aliases_select_actual_event_search_without_write_capabilities(self):
        for q,sources in [('오늘 WAF 차단 로그 보여줘',('modsecurity',)),
                          ('최근 IDS 경보 보여줘',('suricata',)),
                          ('IPS 로그 조회',('suricata',)),
                          ('금일 Wazuh 이벤트 목록',('wazuh',)),
                          ('WAF IDS Wazuh 보안 로그 조회',('modsecurity','suricata','wazuh'))]:
            with self.subTest(q=q):
                expected={'mcp__security_events__search_'+s+'_alerts' for s in sources}
                self.assertEqual(h.event_lookup_scope(q),expected)
                self.assertTrue(h.structured_read(q));self.assertEqual(h.tool_scope(q),expected)
                self.assertTrue(all(h.EVIDENCE.allowed(n,'verify') for n in expected))
                self.assertEqual(h.workflow_names(q),('soc-query',))

    def test_mixed_judgment_changes_unknown_filters_and_peer_are_not_plain_reads(self):
        for q in ('WAF 로그 보고 원인 조사해줘','WAF 차단 로그 보여주고 IP 해제해줘',
                  'WAF 경보가 공격인지 판단해줘','IDS 경보 보고 영향 범위 확인해줘',
                  'Wazuh 경보 서로 검증해줘','WAF 로그 192.0.2.1만 보여줘',
                  '오늘 WAF 경보와 지금 서버 상태 비교해줘','WAF 로그 지난주 것 보여줘',
                  'WAF 룰 보여줘','로그 조회해줘'):
            with self.subTest(q=q): self.assertIsNone(h.event_lookup_scope(q))

    def test_short_alert_queries_use_indexed_wazuh_and_exact_count(self):
        for q,count in (('최근 올라온 경보 10개 보여줄래',10),('경보 7건 보여줘',7),
                        ('최근 이벤트 3개 조회해줘',3),('Wazuh 경보10개만 보여줘',10)):
            with self.subTest(q=q):
                scope={'mcp__security_events__search_wazuh_alerts'}
                self.assertEqual(h.event_lookup_scope(q),scope)
                self.assertEqual(h._event_lookup_request(q)[1],count)
                self.assertTrue(h.structured_read(q))
                self.assertEqual(h.workflow_names(q),('soc-query',))
        for q in ('경보 전체 보여줘','경보 100개 보여줘','경보 0건 보여줘',
                  '경보 -5건 보여줘','경보 10건 중 3개 보여줘','경보 30분 10개 보여줘',
                  '경보 10개 원인 알려줘','WAF IDS 경보 10개 보여줘',
                  '192.0.2.1 경보 10개 보여줘','룰 조회해줘','로그 10개 보여줘'):
            with self.subTest(q=q):self.assertIsNone(h.event_lookup_scope(q))

    def test_exact_requested_count_binds_schema_and_receipt(self):
        q='최근 올라온 경보 10개 보여줄래';name='mcp__security_events__search_wazuh_alerts'
        schema={name:{'type':'object','properties':{'lookback_minutes':{'type':'integer'},
                    'limit':{'type':'integer','minimum':1,'maximum':50}},'required':[]}}
        got=h.refine_read_schemas(q,schema,[])[name]
        self.assertEqual(got['properties']['limit']['enum'],[10])
        self.assertEqual(set(got['required']),{'lookback_minutes','limit'})
        for change in ({'maximum':5},{'enum':[20,50]},{'type':'string'}):
            bad=copy.deepcopy(schema);bad[name]['properties']['limit'].update(change)
            with self.subTest(change=change):self.assertEqual(h.refine_read_schemas(q,bad,[]),{})
        good=receipt('wazuh',limit=10);good['arguments']['limit']=10
        self.assertEqual(h.event_lookup_missing(q,[good]),[])  # Fewer real rows is valid.
        report=h.lookup_report(q,[good]);self.assertIn('반환 표본 1건',report)
        self.assertIn('**Wazuh**',report);self.assertNotIn('미기록',report)
        bad=receipt('wazuh',limit=20);bad['arguments']['limit']=20
        self.assertTrue(h.event_lookup_missing(q,[bad]))
        del good['arguments']['limit']
        self.assertTrue(h.event_lookup_missing(q,[good]))

    def test_today_requires_midnight_and_fresh_actual_window(self):
        q='오늘 WAF 차단 로그 보여줘';good=receipt()
        self.assertEqual(h.missing_reads(q,[good]),[])
        for changed in (receipt(requested_since_kst='2026-11-08T12:00:00+09:00'),
                        receipt(requested_until_kst='2026-11-08T10:00:00+09:00'),
                        receipt(requested_until_kst='2026-11-08T14:00:00+09:00')):
            with self.subTest(changed=changed['result']):self.assertTrue(h.missing_reads(q,[changed]))

    def test_sensor_alerts_cannot_complete_requests_for_unattested_block_actions(self):
        for q in ('IDS 차단 로그 보여줘','IPS 차단 경보 조회','Wazuh 차단 이벤트 목록',
                  'WAF IDS 차단 로그 보여줘'):
            with self.subTest(q=q):
                self.assertIsNone(h.event_lookup_scope(q))
                self.assertIsNone(h.event_lookup_missing(q,[receipt('suricata')]))
        self.assertTrue(h.event_lookup_scope('WAF 차단 로그 보여줘'))

    def test_malformed_rows_and_unmatched_requested_limit_remain_incomplete(self):
        q='오늘 WAF 차단 로그 보여줘'
        for bad in (receipt(alerts=[None]),receipt(alerts=['not an event']),
                    receipt(limit=10),dict(receipt(),arguments={**receipt()['arguments'],'limit':True})):
            with self.subTest(bad=bad):self.assertTrue(h.missing_reads(q,[bad]))

    def test_filled_recent_sample_is_complete_but_never_an_exhaustive_window(self):
        q='최근 Wazuh 경보 보여줘'
        c=receipt('wazuh',limit=1,scanned=1,scan_capped=True)
        c['arguments']['limit']=1
        self.assertEqual(h.missing_reads(q,[c]),[])
        text=h.lookup_report(q,[c])
        self.assertIn('조회 한도 도달',text)
        self.assertIn('추가 경보 존재 여부/구간 전체 건수 미확인',text)
        self.assertIn('IP 정보 없음',text)
        self.assertEqual(text.count('로컬 접속을 뜻하지 않습니다.'),1)
        self.assertNotIn('부분 조회·미완료',text)
        for changes in ({'scanned':2},{'scanned':True},{'returned_count':0,'alerts':[]}):
            bad=receipt('wazuh',limit=1,scanned=1,scan_capped=True)
            bad['arguments']['limit']=1
            data=json.loads(bad['result']);data.update(changes);bad['result']=json.dumps(data)
            bad['result_sha256']=hashlib.sha256(bad['result'].encode()).hexdigest()
            with self.subTest(changes=changes):self.assertTrue(h.missing_reads(q,[bad]))

    def test_bad_receipts_and_incomplete_results_never_complete(self):
        q='오늘 WAF 로그 보여줘';good=receipt()
        cases=[dict(good,is_error=True),dict(good,is_write=True),dict(good,result_sha256='0'*64),
               dict(good,arguments={**good['arguments'],'rule_id':'999'}),
               receipt(source='suricata'),receipt(returned_count=True),receipt(returned_count=2),
               receipt(limit=0),receipt(scan_capped=True),receipt(applied_filters={'source_ip':'192.0.2.1'}),
               receipt(alerts=[{'timestamp':'2026-11-07T12:00:00+09:00'}])]
        for bad in cases:
            with self.subTest(bad=bad):self.assertTrue(h.missing_reads(q,[bad]))
        self.assertTrue(h.missing_reads(q,[good,dict(good,is_error=True)]))
        self.assertIn('미완료',h.lookup_report(q,[dict(good,is_error=True)]))

    def test_block_log_not_inferred_from_detectiononly_or_app_status(self):
        for code,mode in ((200,'Enabled'),(403,'DetectionOnly'),(403,None),(403,'On')):
            c=receipt(alerts=[{'timestamp':'2026-11-08T12:59:00+09:00','http_status':code,'engine':mode}])
            self.assertTrue(h.missing_reads('오늘 WAF 차단로그 보여줘',[c]))
        self.assertIn('HTTP 상태',h.event_report('오늘 WAF 차단로그 보여줘',[receipt()]))

    def test_zero_is_sample_zero_and_each_requested_device_is_required(self):
        q='오늘 WAF IDS 로그 보여줘';w=receipt(returned_count=0,alerts=[])
        self.assertTrue(h.missing_reads(q,[w]))
        self.assertEqual(h.missing_reads(q,[w,receipt('suricata')]),[])
        text=h.lookup_report(q,[w,receipt('suricata')])
        self.assertIn('반환 표본 없음',text);self.assertIn('전체 경보·공격 부재의 증거가 아님',text)

    def test_unqueried_fallback_keeps_table_without_unrelated_block_policy(self):
        text=h.action_fallback('오늘 WAF 차단 로그 보여줘',[])
        self.assertIn('| 조회 상태 |',text);self.assertIn('미완료',text)
        self.assertNotIn('block_ip',text);self.assertNotIn('현재 차단 목록',text)

    def test_model_selection_schema_preserves_catalog_bounds_and_drops_unrequested_filters(self):
        name='mcp__security_events__search_modsecurity_alerts'
        schema={name:{'type':'object','properties':{
            'since_kst':{'type':'string'},'until_kst':{'type':'string'},
            'lookback_minutes':{'type':'integer','maximum':1440},'limit':{'type':'integer','maximum':50},
            'rule_id':{'type':'string'},'source_ip':{'type':'string'}}}}
        original=copy.deepcopy(schema)
        selected=h.refine_read_schemas('오늘 WAF 로그 보여줘',schema,[])
        self.assertEqual(schema,original)
        self.assertEqual(set(selected[name]['properties']),{'since_kst','until_kst','limit'})
        self.assertEqual(set(selected[name]['required']),{'since_kst','until_kst'})
        self.assertEqual(selected[name]['properties']['limit']['maximum'],50)
        self.assertEqual(h.refine_read_schemas('오늘 WAF 로그 보여줘',schema,[dict(receipt(),is_error=True)]),{})

    def test_native_worker_and_all_adapters_share_literal_order(self):
        path=Path(__file__).resolve().parents[1]/'hermes/review_channel_worker.py'
        spec=importlib.util.spec_from_file_location('_event_worker',path)
        worker=importlib.util.module_from_spec(spec);spec.loader.exec_module(worker)
        q='오늘 WAF 차단 로그 보여줘'
        self.assertEqual(worker.lookup_read_scope(h,q,'lead'),h.event_lookup_scope(q))
        self.assertIsNone(worker.lookup_read_scope(h,q,'peer'))
        self.assertEqual(h.lookup_report(q,[receipt()]),h.event_report(q,[receipt()]))

    def test_recent_listing_cannot_select_a_future_absolute_window(self):
        name='mcp__security_events__search_wazuh_alerts'
        schema={name:{'type':'object','properties':{
            'since_kst':{'type':'string'},'until_kst':{'type':'string'},
            'lookback_minutes':{'type':'integer','minimum':1,'maximum':1440},
            'limit':{'type':'integer','minimum':1,'maximum':50}}}}
        selected=h.refine_read_schemas('Wazuh 최근 경보를 표로 보여줘',schema,[])[name]
        self.assertEqual(set(selected['properties']),{'lookback_minutes','limit'})
        self.assertEqual(selected['properties']['lookback_minutes']['enum'],[60])
        self.assertEqual(selected['required'],['lookback_minutes'])
        self.assertFalse(selected['additionalProperties'])
        for changes in ({'maximum':30},{'enum':[5,10]}, {'type':'string'}):
            bad=copy.deepcopy(schema)
            bad[name]['properties']['lookback_minutes'].update(changes)
            self.assertEqual(h.refine_read_schemas('최근 Wazuh 로그 보여줘',bad,[]),{})
        required=copy.deepcopy(schema);required[name]['required']=['since_kst']
        self.assertEqual(h.refine_read_schemas('최근 Wazuh 로그 보여줘',required,[]),{})


if __name__ == '__main__':unittest.main()
