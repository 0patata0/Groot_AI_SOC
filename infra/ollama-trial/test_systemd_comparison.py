"""Factual history/current lookup must not become a recovery verdict."""
import copy
from datetime import datetime, timedelta
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

sys.path.insert(0,str(Path(__file__).parent))
import harness as h

QUESTION='오늘 systemd 오류랑 현재 상태 비교해줘. 설정은 바꾸지 마.'


def receipt(server,name,args,data):
    raw=json.dumps(data,ensure_ascii=False)
    return dict(server=server,name=name,arguments=args,result=raw,
        result_sha256=hashlib.sha256(raw.encode()).hexdigest(),is_error=False,is_write=False)


def replace_data(call, **values):
    return receipt(call['server'],call['name'],call['arguments'],dict(json.loads(call['result']),**values))


class SystemdComparison(unittest.TestCase):
    def setUp(self):
        self.at=datetime.now(h.EVIDENCE.KST)
        self.start=self.at.replace(hour=0,minute=0,second=0,microsecond=0).isoformat()
        self.until=self.at.isoformat();self.calls=[]
        for host in 'abc':
            target=host+':systemd'
            self.calls.append(receipt('system-diagnostics','get_system_diagnostics',{'target':target},
                dict(schema=1,target=target,host=host,kind='runtime',status='ok',age_seconds=5,
                    observed_at_kst=(self.at-timedelta(seconds=5)).isoformat(),
                    lookback_scope='latest_snapshot_only_not_requested_history',
                    metrics=dict(failed_units_total=0,returned_units=0,unit_list_truncated=False))))
        row=dict(timestamp=self.until,agent='collector-only',agent_id='007',program_name='systemd',
                 service_units=['example.service'],wazuh_rule_id='40704',exit_status={'code':'exited','status':'1','label':'FAILURE'})
        args=dict(since_kst=self.start,until_kst=self.until,program_name='systemd',limit=10)
        self.calls.append(receipt('security-events','search_wazuh_alerts',args,
            dict(source='wazuh',source_scope='wazuh_indexed_alerts',window_mode='explicit_bounds',
                 requested_since_kst=self.start,requested_until_kst=self.until,
                 applied_filters={'program_name':'systemd'},alerts=[row,copy.deepcopy(row)],returned_count=2,
                 limit=10,scan_capped=False,indexed_window_total_count=None)))

    def test_variants_remain_lookups_and_need_both_tools(self):
        for q in (QUESTION,'금일 systemd 실패 이력과 지금 상태를 대조해서 표로 보여줘',
                  '현재 상태와 오늘 systemd 경보를 비교해 줘','@hermes '+QUESTION,'@ollama '+QUESTION):
            self.assertTrue(h.systemd_comparison_request(q),q)
            self.assertTrue(h.structured_read(q));self.assertEqual(h.tool_scope(q),set(h.SYSTEMD_COMPARE_TOOLS))
        self.assertEqual(h.missing_reads(QUESTION,[]),['a:systemd','b:systemd','c:systemd','오늘 systemd 경보: 정확한 KST 구간·필터·반환 근거'])

    def test_judgment_protection_and_specific_scopes_stay_with_model(self):
        for extra in (' 원인도 조사해',' 왜 그런가',' 위험 판단해',' 복구됐어?', ' 정상인가?',
                      ' 재시작해',' A 서버만',' a:systemd만',' 10시부터',' 1시간만',
                      ' 특정 룰만',' Vector도',' B 제외',' 전부 빠짐없이',' 예시를 설명해'):
            self.assertFalse(h.systemd_comparison_request(QUESTION+extra),extra)
        self.assertFalse(h.systemd_comparison_request('"오늘 systemd 오류랑 현재 상태 비교해줘" 번역'))
        for extra in (' 그리고 FW도 조회해',' SSH 상태도',' 디스크 용량도',' 백업 상태도',' 미등록컴포넌트도 확인해'):
            self.assertFalse(h.systemd_comparison_request(QUESTION+extra),extra)

    def test_ledger_and_literals_preserve_scope_without_host_or_recovery_claim(self):
        before=copy.deepcopy(self.calls)
        report=h.systemd_comparison_report(QUESTION,self.calls,self.until)
        self.assertIn('반환 표본 2건',report);self.assertIn('collector-only / 007',report)
        self.assertIn('example.service | 40704 | exited/1/FAILURE | 2 |',report)
        self.assertIn('현재 복구 여부는 미확인',report)
        self.assertEqual(report.count('| a:systemd |'),1);self.assertEqual(report.count('| c:systemd |'),1)
        self.assertEqual(h.missing_reads(QUESTION,self.calls),[])
        self.assertEqual(self.calls,before)
        rows=copy.deepcopy(self.calls);rows[-1]['arguments'].pop('limit')
        self.assertIsNotNone(h.systemd_comparison_report('@hermes '+QUESTION,rows,self.until))

    def test_missing_failed_tampered_wrong_tool_host_stale_never_complete(self):
        cases=[]
        cases.append(self.calls[:-1]);cases.append(self.calls[1:])
        for mutation in ({'is_error':True},{'result_sha256':'0'*64},{'server':'other'}):
            rows=copy.deepcopy(self.calls);rows[0].update(mutation);cases.append(rows)
        for change in ({'host':'b'},{'status':'unavailable'},{'publisher_stale':True},
                       {'observed_at_kst':(self.at-timedelta(minutes=4)).isoformat()},
                       {'metrics':{'failed_units_total':False,'returned_units':0,'unit_list_truncated':False}}):
            rows=copy.deepcopy(self.calls);rows[0]=replace_data(rows[0],**change);cases.append(rows)
        rows=copy.deepcopy(self.calls);rows.append(dict(rows[0],is_error=True));cases.append(rows)
        for rows in cases:self.assertIsNone(h.systemd_comparison_report(QUESTION,rows,self.until))

    def test_events_exact_window_filters_and_row_count_are_required(self):
        for change in ({'returned_count':0},{'applied_filters':{'program_name':'systemd','agent_id':'001'}},
                       {'requested_since_kst':(self.at-timedelta(hours=1)).isoformat()},
                       {'requested_until_kst':(self.at-timedelta(seconds=1)).isoformat()},
                       {'source':'suricata'},{'window_mode':'lookback'}):
            rows=copy.deepcopy(self.calls);rows[-1]=replace_data(rows[-1],**change)
            self.assertIsNone(h.systemd_comparison_report(QUESTION,rows,self.until),change)
        rows=copy.deepcopy(self.calls);rows[-1]['arguments']['agent_id']='001'
        self.assertIsNone(h.systemd_comparison_report(QUESTION,rows,self.until))
        rows=copy.deepcopy(self.calls);rows.append(dict(rows[-1],is_error=True))
        self.assertIsNone(h.systemd_comparison_report(QUESTION,rows,self.until))

    def test_zero_sample_and_nonzero_current_failures_are_not_hidden(self):
        rows=copy.deepcopy(self.calls);rows[-1]=replace_data(rows[-1],returned_count=0,alerts=[])
        rows[0]=replace_data(rows[0],status='degraded',metrics=dict(failed_units_total=1,returned_units=1,
            unit_list_truncated=False,failed_unit_0='new-failure.service'))
        report=h.systemd_comparison_report(QUESTION,rows,self.until)
        self.assertIn('반환 표본 0건',report);self.assertIn('전체 경보 부재를 뜻하지',report)
        self.assertIn('| a:systemd | 1 | new-failure.service',report)

    def test_native_bound_receipts_complete_without_extra_model_and_pass_guard(self):
        w=h.EVIDENCE;ledger=[];receipts=[];facts=[]
        for c in self.calls:
            name='mcp__'+c['server'].replace('-','_')+'__'+c['name']
            raw=json.dumps({'result':c['result']})
            ledger.append(w.read_ledger_entry(name,c['arguments'],raw))
            receipts.append({'tool':name,'output':raw,'is_error':False})
            facts+=w.observation_facts(c['name'],SimpleNamespace(isError=False,
                content=[SimpleNamespace(text=raw)]),c['arguments'])
        context=dict(request=QUESTION,background='',tools=sorted(h.SYSTEMD_COMPARE_TOOLS),requested_at_kst=self.until)
        result=w.literal_chat_lookup(context,ledger,receipts,h)
        self.assertIsNotNone(result);self.assertIn('MANAGEMENT_STATUS: resolved',result)
        self.assertEqual(w.evidence_claim_violations(result,facts,set(h.SYSTEMD_COMPARE_TOOLS)),[])
        self.assertIsNone(w.literal_chat_lookup(context,ledger[:-1],receipts[:-1],h))

    def test_review_worker_both_scopes_and_peer_boundary(self):
        path=Path(__file__).parents[1]/'hermes/review_channel_worker.py'
        spec=importlib.util.spec_from_file_location('comparison_worker',path)
        worker=importlib.util.module_from_spec(spec);spec.loader.exec_module(worker)
        self.assertEqual(worker.lookup_read_scope(h,QUESTION,'lead'),h.SYSTEMD_COMPARE_TOOLS)
        self.assertIsNone(worker.lookup_read_scope(h,QUESTION,'peer'))
        self.assertEqual(worker.diagnostic_read_targets(h,QUESTION),[])

    def test_actual_narrowed_diagnostic_schema_has_no_impossible_empty_enum(self):
        root=Path(__file__).parents[1]/'mcp'
        def load(name,path):
            spec=importlib.util.spec_from_file_location(name,path)
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
        m=load('comparison_diagnostic_mcp',root/'system-diagnostics-mcp.py')
        m._library=load('comparison_diagnostic_core',root/'system_diagnostics.py')
        alias='mcp__system_diagnostics__get_system_diagnostics'
        schema=next(t['inputSchema'] for t in m.tools() if t['name']=='get_system_diagnostics')
        schema=h.EVIDENCE.tool_input_schema(alias,schema)
        refined=h.refine_read_schemas(QUESTION,{alias:schema},[])
        selected=h.selection_schema(refined,4)
        def walk(value):
            if isinstance(value,dict):
                if 'enum' in value:self.assertTrue(value['enum'])
                for item in value.values():walk(item)
            elif isinstance(value,list):
                for item in value:walk(item)
        walk(selected)
        result=h.EVIDENCE.chat_read_schema(alias,refined[alias])
        self.assertNotIn('since_kst',result['properties'])
        self.assertEqual(result['properties']['target']['enum'],['a:systemd','b:systemd','c:systemd'])


if __name__=='__main__':unittest.main()
