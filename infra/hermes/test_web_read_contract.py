"""Short web lookups retain scope without incident classification or prefetch."""
import copy
import hashlib
import json
import re
import unittest
import read_contract as r

TIME=re.compile(r'20\d\d-[^ ]+\+09:00')
QUESTION='DVWA 접근 기록 좀 보여줘'

def call():
    data={'source':'c_apache_access_snapshot','target':'c:dvwa','mutation_performed':False,
        'actual_request_total_count':None,'returned_count':1,'records':[{
            'timestamp_kst':'2026-11-04T17:58:00+09:00','source_ip':'192.0.2.20','method':'GET','path':'/dvwa/a|b','status':200}],
        'coverage':{'rows_truncated':True},'requested_since_kst':'2026-11-04T17:00:00+09:00',
        'requested_until_kst':'2026-11-04T18:00:00+09:00','observed_at_kst':'2026-11-04T17:59:00+09:00'}
    raw=json.dumps(data)
    return {'server':'security-events','name':'search_web_access','arguments':{'target':'c:dvwa','lookback_minutes':60},
        'is_error':False,'result':raw,'result_sha256':hashlib.sha256(raw.encode()).hexdigest()}

class PlainReads(unittest.TestCase):
    def test_short_aliases_share_one_actual_read_scope(self):
        for text in (QUESTION,'dvwa 백엔드 요청 기록 보여줘','c:lab-java 접근 로그 조회','c:lab-httpd49 접근 기록 보여줘'):
            with self.subTest(text=text):
                p=r.plan(text,TIME);self.assertEqual(p['kind'],'web_access')
                self.assertEqual(r.scope(p),{'mcp__security_events__search_web_access'})
                self.assertIn('서버가 KST 구간을 계산',r.guidance(p))

    def test_investigation_write_explicit_time_or_mixed_devices_are_not_shortcut(self):
        for text in ('DVWA 공격 접근 로그 조사해줘','DVWA 접근 로그 왜 이상하지?','DVWA 접근 기록과 WAF 룰 보여줘',
                     'DVWA 접근 로그 삭제해줘','DVWA 어제 접근 기록 보여줘','DVWA 24시간 접근 로그 조회','DVWA와 c:lab-java 접근 기록 보여줘',
                     'DVWA랑 Log4Shell 접근 기록 보여줘','DVWA와 다른 서비스 접근 기록 보여줘','칼리에서 DVWA 접근 기록 조회'):
            with self.subTest(text=text):
                p=r.plan(text,TIME);self.assertTrue(p is None or p['kind']!='web_access')

    def test_no_actual_correct_receipt_remains_missing(self):
        p=r.plan(QUESTION,TIME);self.assertTrue(r.missing(p,[],None))
        valid=call();self.assertEqual(r.missing(p,[valid],None),[])
        for patch in ({'is_error':True},{'result_sha256':'0'*64},{'server':'rule-a'},{'arguments':{'target':'c:lab-java'}}):
            with self.subTest(patch=patch):self.assertTrue(r.missing(p,[dict(valid,**patch)],None))

    def test_old_or_wrong_interval_and_malformed_records_do_not_satisfy_lookup(self):
        p=r.plan(QUESTION,TIME)
        for patch in ({'requested_since_kst':'2026-11-03T18:00:00+09:00'},
                      {'observed_at_kst':'2026-11-05T18:00:00+09:00'},{'records':[{}]},
                      {'source':'wazuh'},{'returned_count':0}):
            c=call();d=json.loads(c['result']);d.update(patch);c['result']=json.dumps(d);c['result_sha256']=hashlib.sha256(c['result'].encode()).hexdigest()
            with self.subTest(patch=patch):self.assertTrue(r.missing(p,[c],None))

    def test_same_receipt_renders_table_preserves_scope_and_does_not_classify_incident(self):
        p=r.plan(QUESTION,TIME);c=call();before=copy.deepcopy(c);text=r.report(p,[c],None)
        self.assertEqual(before,c);self.assertIn('| KST 시각 |',text);self.assertIn('/dvwa/a\\|b',text)
        self.assertIn('보관 행 상한으로 잘림',text);self.assertIn('실제 전체 요청 수 미확인',text)
        self.assertNotIn('INCIDENT_DISPOSITION',text);self.assertNotIn('```',text)

if __name__=='__main__':unittest.main()
