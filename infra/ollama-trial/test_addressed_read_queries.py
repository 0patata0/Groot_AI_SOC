"""Transport addressing cannot change read scope or authorize a larger window."""
import copy
from datetime import datetime,timedelta
import hashlib,json,re,unittest
from unittest.mock import patch

import harness as h

NOW=datetime.fromisoformat('2026-11-17T20:30:00+09:00')
class Clock(datetime):
    @classmethod
    def now(cls,tz=None):return NOW.astimezone(tz) if tz else NOW.replace(tzinfo=None)

def call(source='modsecurity',minutes=60,limit=3,empty=False):
    end=NOW-timedelta(seconds=10);start=end-timedelta(minutes=minutes)
    rows=[] if empty else [{'timestamp':end.isoformat(),'source_ip':'192.0.2.7',
        'http_status':403,'engine':'Enabled','method':'GET','request_path':'/fixture',
        'waf_rule_ids':['123'],'waf_rule_matches':[{'rule_id':'123','description':'fixture'}],
        'signature_id':123,'signature':'fixture','agent':'fixture-a','wazuh_rule_id':'100102'}]
    data={'source':source,'applied_filters':{},'window_mode':'lookback',
        'requested_since_kst':start.isoformat(),'requested_until_kst':end.isoformat(),
        'returned_count':len(rows),'limit':limit,'scan_capped':False,'alerts':rows}
    raw=json.dumps(data)
    return {'server':'security-events','name':'search_'+source+'_alerts',
        'arguments':{'lookback_minutes':minutes,'limit':limit},'result':raw,
        'result_sha256':hashlib.sha256(raw.encode()).hexdigest(),'is_error':False,'is_write':False}

class AddressedQueries(unittest.TestCase):
    def test_leading_bot_address_preserves_read_classification_across_targets(self):
        questions=('최근 WAF 차단 경보 3건만 표로 보여줘','최근 IDS 경보 3건 보여줘',
            '최근 Wazuh 경보 3건 보여줘','최근 경보 3건 보여줘','FW 룰 보여줘',
            'WAF 룰 보여줘','B systemd 상태 보여줘','B 도커 컨테이너 자원 보여줘',
            '지금 임시차단 목록 보여줘','룰 조회해줘','최근 30분 IDS 경보 보여줘')
        for q in questions:
            for prefix in ('@hermes ','@ollama ','[socadmin] @hermes: ','@OLLAMA, '):
                with self.subTest(question=q,prefix=prefix):
                    original=prefix+q
                    self.assertEqual(h.normalized(original),h.normalized(q))
                    self.assertEqual(h.event_lookup_scope(original),h.event_lookup_scope(q))
                    self.assertEqual(h.tool_scope(original),h.tool_scope(q))
                    self.assertEqual(original,prefix+q)

    def test_unknown_multiple_quoted_and_embedded_addresses_remain_data(self):
        for q in ('@hermes-other WAF 경보 보여줘','@hermes.example WAF 경보 보여줘',
                  '@other WAF 경보 보여줘','@hermes @ollama WAF 경보 보여줘',
                  '"@hermes" WAF 경보 보여줘','user@hermes WAF 경보 보여줘',
                  'https://example.test/@hermes WAF 경보 보여줘',
                  '[WAF] @hermes 경보 보여줘'):
            self.assertEqual(h.CONTRACT.normalize_query_text(q),q)

    def test_investigation_filters_and_write_intent_do_not_become_plain_listings(self):
        for q in ('WAF 경보 원인 조사해줘','IDS 경보가 공격인지 판단해줘',
                  'WAF 경보 192.0.2.8만 보여줘','WAF 경보 보여주고 IP 차단해줘'):
            for prefix in ('','@hermes ','@ollama '):
                self.assertIsNone(h.event_lookup_scope(prefix+q))
        self.assertTrue(h.READ.wants_write(h.normalized('@hermes 192.0.2.8 차단해줘')))
        self.assertFalse(h.structured_read('@hermes WAF 경보 보여주고 IP 차단해줘'))

    def test_model_request_text_and_supplied_time_are_not_rewritten(self):
        original='@hermes 2026-11-17T20:30:00+09:00 시각을 보여줘'
        self.assertEqual(h.SHARED.current_request_text(original),original)
        self.assertIn('2026-11-17T20:30:00+09:00',h.normalized(original))
        self.assertEqual(h.CONTRACT.normalize_query_text('@hermes'),'')

class EventWindows(unittest.TestCase):
    def setUp(self):
        clock=patch.object(h,'datetime',Clock);clock.start();self.addCleanup(clock.stop)

    def test_default_window_does_not_expand_to_fill_requested_count(self):
        for source,label in (('modsecurity','WAF'),('suricata','IDS'),('wazuh','Wazuh')):
            q='@hermes 최근 '+label+' 경보 3건 보여줘'
            empty=call(source,empty=True)
            self.assertEqual(h.event_lookup_missing(q,[empty]),[])
            self.assertTrue(h.event_lookup_missing(q,[call(source,minutes=480)]))
            self.assertTrue(h.event_lookup_missing(q,[call(source,minutes=30)]))
            report=h.lookup_report(q,[empty])
            self.assertIn('전체 경보·공격 부재의 증거가 아님',report)
            self.assertIn('반환 표본 0건',report)

    def test_explicit_window_and_today_keep_their_own_bounds(self):
        q='@hermes 최근 30분 IDS 경보 3건 보여줘'
        self.assertEqual(h.event_lookup_missing(q,[call('suricata',minutes=30)]),[])
        self.assertTrue(h.event_lookup_missing(q,[call('suricata')]))
        row=call();data=json.loads(row['result']);data['requested_since_kst']=NOW.replace(hour=0,minute=0,second=0,microsecond=0).isoformat();data['window_mode']='explicit_bounds'
        row['arguments']={'since_kst':data['requested_since_kst'],'until_kst':data['requested_until_kst'],'limit':3}
        row['result']=json.dumps(data);row['result_sha256']=hashlib.sha256(row['result'].encode()).hexdigest()
        self.assertEqual(h.event_lookup_missing('@hermes 오늘 WAF 차단 경보 3건 보여줘',[row]),[])

    def test_schema_default_is_equal_for_plain_and_addressed_queries(self):
        name='mcp__security_events__search_modsecurity_alerts'
        schemas={name:{'type':'object','properties':{
            'lookback_minutes':{'type':'integer','minimum':1,'maximum':1440},
            'limit':{'type':'integer','minimum':1,'maximum':50}},'required':[]}}
        before=copy.deepcopy(schemas)
        for q,minutes in (('최근 WAF 경보 3건 보여줘',60),('최근 30분 WAF 경보 3건 보여줘',30)):
            plain=h.refine_read_schemas(q,schemas,[])
            self.assertEqual(plain,h.refine_read_schemas('@hermes '+q,schemas,[]))
            self.assertEqual(plain[name]['properties']['lookback_minutes']['enum'],[minutes])
        self.assertEqual(schemas,before)

    def assert_one_time_per_cell(self,text):
        for line in text.splitlines():
            if line.startswith('|'):
                for cell in re.split(r'(?<!\\)\|',line)[1:-1]:
                    self.assertLessEqual(len(re.findall(r'\d\d:\d\d:\d\d',cell)),1,cell)

    def test_each_sensor_window_keeps_bounds_in_separate_cells(self):
        for source,label in (('modsecurity','WAF'),('suricata','IDS'),('wazuh','Wazuh')):
            for empty in (True,False):
                row=call(source,empty=empty);original=copy.deepcopy(row)
                text=h.event_report('@hermes 최근 '+label+' 경보 3건 보여줘',[row])
                self.assertIn('| 조회 시작(KST) | 조회 종료(KST) | 반환 상태 |',text)
                self.assert_one_time_per_cell(text)
                data=json.loads(row['result'])
                self.assertIn(data['requested_since_kst'],text);self.assertIn(data['requested_until_kst'],text)
                self.assertEqual(row,original)

    def test_wazuh_legacy_summary_times_are_sample_bounds_not_query_bounds(self):
        name='mcp__wazuh_ro__get_wazuh_alert_summary'
        raw=json.dumps({'result':'Alert ID: fixture-a\nTime: 2026-11-17T20:00:00+09:00\nAgent: A\nRule ID: 100102\n\nAlert ID: fixture-b\nTime: 2026-11-17T20:20:00+09:00\nAgent: B\nRule ID: 100103\n'})
        row={'server':'wazuh-ro','name':'get_wazuh_alert_summary','arguments':{},'result':raw,
             'result_sha256':hashlib.sha256(raw.encode()).hexdigest(),'is_error':False}
        with patch.object(h,'tool_scope',return_value={name}):text=h.event_report('Wazuh 경보 요약 보여줘',[row])
        self.assertIn('표본 첫 시각(KST)',text);self.assertIn('표본 마지막 시각(KST)',text)
        self.assertIn('절대 구간/전체 건수 조회 아님',text);self.assert_one_time_per_cell(text)

    def test_backend_window_rows_and_all_returned_values_are_preserved(self):
        data={'target':'c:dvwa','source':'c_apache_access_snapshot','mutation_performed':False,
            'actual_request_total_count':None,'records':[],'returned_count':0,'coverage':{},
            'requested_since_kst':'2026-11-17T19:30:00+09:00',
            'requested_until_kst':'2026-11-17T20:30:00+09:00','observed_at_kst':'2026-11-17T20:30:00+09:00'}
        raw=json.dumps(data);row={'server':'security-events','name':'search_web_access',
             'arguments':{'target':'c:dvwa'},'result':raw,'result_sha256':hashlib.sha256(raw.encode()).hexdigest()}
        text=h.READ.web_access_report({'target':'c:dvwa','lookback_minutes':60},[row])
        self.assertIn('| 조회 시작(KST) |',text);self.assertIn('| 조회 종료(KST) |',text)
        self.assertIn('실제 전체 요청 수 미확인',text);self.assert_one_time_per_cell(text)

if __name__=='__main__':unittest.main()
