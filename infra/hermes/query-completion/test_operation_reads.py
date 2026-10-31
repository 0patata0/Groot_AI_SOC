"""Operation reads and engine counters preserve unknown and historical scope."""
import copy
import hashlib
import json
import unittest
from test_expanded_reads import H, call


class OperationReads(unittest.TestCase):
    rid='c7'*16

    def test_service_and_containment_requests_choose_the_right_host_and_tool(self):
        for device,target in [('WAF','a:waf'),('IDS','a:suricata'),('채팅 프록시','a:chatproxy'),('Wazuh Manager','b:wazuh-manager'),('Wazuh 대시보드','b:wazuh-dashboard'),
                              ('Vector','a:vector'),('A 서버 Wazuh 에이전트','a:wazuh-agent'),('B 서버 wazuh-agent','b:wazuh-agent')]:
            q=device+' 재시작 요청 '+self.rid+' 처리됐어?'
            p=H.read_plan(q);self.assertEqual((p['kind'],p['target']),('operation',target))
            self.assertEqual(H.tool_scope(q),{'mcp__rule_'+target[0]+'__get_operation_status'})
        q='임시차단 요청 '+self.rid+' 지금도 차단 중이야?'
        self.assertEqual(H.read_plan(q)['target'],'a:incident-ip')
        self.assertIsNone(H.read_plan('WAF 요청 '+self.rid+' 재시작해줘'))
        self.assertIsNone(H.read_plan('WAF와 IDS 재시작 요청 '+self.rid+' 상태 알려줘'))
        self.assertIsNone(H.read_plan('Wazuh 에이전트 재시작 요청 '+self.rid+' 상태 알려줘'))

    def test_failed_operation_read_stays_unknown_and_is_not_replayed(self):
        q='WAF 재시작 요청 '+self.rid+' 처리됐어?'
        c=call('get_operation_status',{'error':'operation request is missing or ambiguous'},{'request_id':self.rid},server='rule-a')
        c['is_error']=True
        self.assertTrue(H.missing_reads(q,[c]))
        out=H.read_report(q,[c]);self.assertIn('조회가 미완료',out);self.assertIn('원인인지 확인되지 않았습니다',out)
        alias='mcp__rule_a__get_operation_status';schemas={alias:{'properties':{'request_id':{'type':'string'}},'required':['request_id']}}
        self.assertEqual(H.refine_read_schemas(q,schemas,[])[alias]['properties']['request_id']['enum'],[self.rid])
        self.assertEqual(H.refine_read_schemas(q,schemas,[c]),{})
        c['result_sha256']='0'*64
        self.assertTrue(H.refine_read_schemas(q,schemas,[c]))

    def test_current_service_does_not_prove_old_action_and_hash_is_required(self):
        q='Wazuh Manager 재시작 요청 '+self.rid+' 결과와 현재 상태 알려줘'
        p=H.read_plan(q);self.assertIn('mcp__rule_b__get_operation_status',H.tool_scope(q))
        status=call('get_operation_status',{'request_id':self.rid,'target':p['target'],'status':'failed','result':'verification failed','result_posted':False,'after_observation_sha256':'f'*64},{'request_id':self.rid},server='rule-b')
        obs={'running':True,'health':'healthy'};sha=hashlib.sha256(json.dumps(obs,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()
        current=call('get_service_action_target',{'target':p['target'],'observation':obs,'base_state_sha256':sha},{'target':p['target']},server='rule-b')
        self.assertFalse(H.missing_reads(q,[status,current]))
        out=H.read_report(q,[status,current]);self.assertIn('failed',out);self.assertIn('승인·성공 증명이 아닙니다',out)
        bad=call('get_service_action_target',{'target':p['target'],'observation':obs,'base_state_sha256':'0'*64},{'target':p['target']},server='rule-b')
        self.assertIn(p['target'],H.missing_reads(q,[status,bad]))

    def test_containment_workflow_deadline_is_not_live_nft_state(self):
        q='임시차단 요청 '+self.rid+' 지금도 차단 중이야?'
        for state in ('owned','absent','foreign','unavailable'):
            d={'request_id':self.rid,'target':'a:incident-ip','status':'expired','result_posted':True,'owned_deadline':1000,'live_observed_at':1100,'live_block_state':state,'live_remaining_seconds':20 if state=='owned' else None}
            c=call('get_operation_status',d,{'request_id':self.rid},server='rule-a')
            out=H.read_report(q,[c]);self.assertIn('| 현재 상태 | '+state+' |',out);self.assertIn('+09:00',out)
            self.assertIn('과거 기한만으로 현재 차단 여부를 계산하지 않습니다',out)
            self.assertFalse(H.missing_reads(q,[c]))
        wrong=call('get_operation_status',{**d,'target':'b:wazuh-manager'},{'request_id':self.rid},server='rule-a')
        self.assertTrue(H.missing_reads(q,[wrong]))

    def test_engine_counter_scope_and_unavailable_are_preserved(self):
        q='IDS 엔진에 실제 적재된 룰 수와 로딩 실패 수 알려줘'
        data={'target':'a:suricata','observation':{'running':True,'container_id':'a'*64},
              'rule_engine_evidence':{'status':'observed','scope':'single_tenant_engine_counters','container_id':'a'*64,
              'rules_loaded':321,'rules_failed':2,'rules_skipped':1,'last_reload_kst':'2026-10-25T19:21:12+09:00','observed_at_kst':'2026-10-30T21:27:00+09:00'}}
        def output(d):return H.service_report(q,[call('get_service_action_target',d,{'target':'a:suricata'},server='rule-a')])
        out=output(data);self.assertIn('| 321 | 2 | 1 |',out);self.assertIn('개별 SID 엔진 적재는 미확인',out)
        for key,value in [('status','unavailable'),('rules_loaded',True),('container_id','b'*64),('last_reload_kst','unknown')]:
            changed=copy.deepcopy(data);changed['rule_engine_evidence'][key]=value;out=output(changed)
            self.assertIn('엔진 적재 통계는 조회 불가',out);self.assertNotIn('| 321 |',out)


if __name__ == '__main__':unittest.main()
