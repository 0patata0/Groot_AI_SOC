"""Fresh SOC scope, intact evidence and typed same-subject followups."""
import copy
import hashlib
import json
import unittest
from datetime import datetime,timedelta
import harness as h

Q='지금 관제 현황 알려줘'

def seal(name,data,args=None):
    server,tool=name.removeprefix('mcp__').split('__')
    raw=json.dumps(data)
    return dict(server=server.replace('_','-'),name=tool,arguments=args if args is not None else h.SOC_OVERVIEW_CALLS[name],
        result=raw,result_sha256=hashlib.sha256(raw.encode()).hexdigest(),is_error=False,is_write=False)

def calls():
    now=datetime.now(h.EVIDENCE.KST);stamp=now.isoformat()
    rows={host+':collection':dict(status='ok',observed_at_kst=stamp,kind='runtime',codes=[]) for host in 'abc'}
    rows['b:management-pipeline']=dict(schema=1,kind='runtime',host='b',target='b:management-pipeline',status='degraded',
        observed_at_kst=stamp,mutation_performed=False,codes=['case_review_required'],metrics=dict(pending_reports=1,
        running_cases=2,overdue_cases=3,review_required_cases=4))
    return [seal('mcp__system_diagnostics__get_system_diagnostics',dict(schema=1,kind='coverage',target='soc:coverage',
        targets=rows,hosts={host:'observed' for host in 'abc'},total_targets=4,counts=dict(ok=3,degraded=1,unavailable=0,not_installed=0),mutation_performed=False)),
        seal('mcp__security_events__search_wazuh_alerts',dict(source='wazuh',applied_filters={},alerts=[],returned_count=0,
            limit=5,scan_capped=False,scanned=0,requested_since_kst=(now-timedelta(hours=1)).isoformat(),requested_until_kst=stamp)),
        seal('mcp__resp__list_blocks',dict(blocks=['192.0.2.9']))]

class Overview(unittest.TestCase):
    def test_aliases_are_new_overview_and_history_or_actions_keep_their_scope(self):
        for q in (Q,'관제 현황 알려줄래','관제 상황 보여줘','현재 SOC 상태?','전체 관제 현황 표로 보여주세요'):
            self.assertTrue(h.soc_overview_request(q),q)
            self.assertEqual(h.tool_scope(q),set(h.SOC_OVERVIEW_CALLS))
            self.assertTrue(h.structured_read(q));self.assertTrue(h.missing_reads(q,[]))
            self.assertEqual(h.resolve_short_read(q,['도커 컨테이너 자원 보여줘']),q)
            self.assertEqual(h.read_background('old unverified docker table',q),'')
        for q in ('어제 관제 현황 보여줘','관제 상태가 왜 이상해?','관제 현황 확인하고 차단해줘',
                  '관제 현황 조회하지 마','관제 처리 대기 현황 보여줘','A 서버 관제 현황 보여줘'):
            self.assertFalse(h.soc_overview_request(q),q)

    def test_complete_receipts_render_metrics_and_do_not_reuse_docker(self):
        c=calls();before=copy.deepcopy(c)
        self.assertEqual(h.missing_reads(Q,c),[])
        text=h.lookup_report(Q,c)
        for word in ('보고 전송 대기','검토 필요','동적 IP 차단','수집·서비스','경보','192.0.2.9'):self.assertIn(word,text)
        self.assertNotIn('Docker',text);self.assertEqual(c,before)

    def test_missing_failed_wrong_hash_stale_receipts_never_complete(self):
        original=calls()
        for i in range(3):
            self.assertTrue(h.missing_reads(Q,original[:i]+original[i+1:]))
            bad=copy.deepcopy(original);bad[i]['is_error']=True
            self.assertTrue(h.missing_reads(Q,bad))
            bad=copy.deepcopy(original);bad[i]['result_sha256']='0'*64
            self.assertTrue(h.missing_reads(Q,bad))
        bad=copy.deepcopy(original);data=json.loads(bad[0]['result'])
        data['targets']['a:collection']['observed_at_kst']=(datetime.now(h.EVIDENCE.KST)-timedelta(hours=1)).isoformat()
        bad[0]=seal('mcp__system_diagnostics__get_system_diagnostics',data)
        self.assertTrue(h.missing_reads(Q,bad))
        self.assertTrue(h.missing_reads(Q,original,['a:missing',*json.loads(original[0]['result'])['targets']]))

    def test_schema_does_not_invent_tools_or_repeat_failed_reads(self):
        schemas={name:dict(type='object',properties={k:dict(type='string' if isinstance(v,str) else 'integer') for k,v in args.items()},
            required=list(args),additionalProperties=False) for name,args in h.SOC_OVERVIEW_CALLS.items()}
        narrowed=h.refine_read_schemas(Q,schemas,[])
        self.assertEqual(set(narrowed),set(schemas))
        plan={'calls':[dict(tool=n,arguments=a) for n,a in h.SOC_OVERVIEW_CALLS.items()]}
        schema=h.selection_schema(narrowed,32,question=Q)
        self.assertEqual(h.validated_selection(plan,schema)[0],plan)
        self.assertEqual(h.refine_read_schemas(Q,schemas,[dict(c,is_error=True) for c in calls()]),{})
        self.assertEqual(h.refine_read_schemas(Q,{},[]),{})

    def test_docker_followups_preserve_host_object_and_chain(self):
        history=['B 서버 hermes 컨테이너 상세 보여줘']
        for q,view in [('메모리는?','container_stats'),('로그도','container_logs')]:
            resolved=h.resolve_short_read(q,history);req=h.host_inventory_request(resolved)[0]
            self.assertEqual((req['host'],req['container'],req['view']),('b','hermes',view));history.append(q)
        self.assertEqual(h.host_inventory_request(h.resolve_short_read('메모리는?',['C 서버 도커 목록 보여줘']))[0]['host'],'c')

    def test_existing_device_detail_paths_use_same_resolver_and_keep_filters(self):
        for prior,target in [('WAF 커스텀 룰 조회','a:waf'),('IDS 기본 룰 조회','a:suricata'),
                             ('Wazuh ID 5712 조건 보여줘','b:wazuh')]:
            for follow in ('좀 더 자세하게 보고싶은데','상세조회한거 표로 보여줄래'):
                resolved=h.resolve_short_read(follow,[prior]);plan=h.security_inventory_request(resolved)
                self.assertEqual(plan['targets'],[target]);self.assertEqual(plan['view'],'details')
                if '5712' in prior:self.assertEqual(plan['rule_id'],'5712')
                if '커스텀' in prior:self.assertEqual(plan['origin'],'custom')
                if '기본' in prior:self.assertEqual(plan['origin'],'builtin')
        req=h.host_inventory_request(h.resolve_short_read('메모리는?',['C 서버 디스크 상태 보여줘']))[0]
        self.assertEqual((req['host'],req['view']),('c','resources'))

    def test_systemd_followups_keep_arbitrary_unit_not_container_or_host_ram(self):
        for unit in ('ssh.service','apache2.service','capstone-vector.service','example-worker@blue.service'):
            history=['A 서버 '+unit+' 상태 보여줘']
            resolved=h.resolve_short_read('메모리는?',history);req=h.host_inventory_request(resolved)[0]
            self.assertEqual((req['host'],req['unit'],req['view']),('a',unit,'service_details'))
            logs=h.resolve_short_read('로그도',history+['메모리는?'])
            self.assertEqual(logs,'A 서버 '+unit+' 로그 보여줘');self.assertNotIn('컨테이너',logs)
        self.assertEqual(h.resolve_short_read('로그도',['B 서버 hermes 컨테이너 상세 보여줘','다른 이야기']),'로그도')
        self.assertEqual(h.resolve_short_read('로그 삭제해줘',['A 서버 ssh.service 상태 보여줘']),'로그 삭제해줘')

if __name__=='__main__':unittest.main()
