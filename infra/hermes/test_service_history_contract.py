"""Registered service scope, evidence completeness and fail-closed navigation."""
import copy
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module
c=load('service_contract',ROOT/'infra/hermes/chat_contract.py')
d=load('service_core',ROOT/'infra/mcp/system_diagnostics.py')
m=load('service_mcp',ROOT/'infra/mcp/system-diagnostics-mcp.py');m._library=d
w=load('service_native',ROOT/'infra/hermes/soc_management_run.py')
NAME='mcp__system_diagnostics__get_system_diagnostics'

def catalog():
    return {'tools':[{'function':{'name':NAME,'parameters':m.tools()[0]['inputSchema']}}]}

class ServiceHistory(unittest.TestCase):
    def setUp(self):
        self.now=datetime.now(timezone(timedelta(hours=9)))
        self.at=self.now.isoformat()
        self.question='오늘 B 서버 capstone-management.service 실패 원인이 뭐고, 지금도 문제인지 확인해줘. 설정은 바꾸지 마.'
        self.plan=c.service_history_plan(catalog(),self.question,self.at)
        self.assertIsNotNone(self.plan)

    def rows(self):
        rows=[]
        for option in self.plan['requirements']:
            args=option['arguments'];target=args['target']
            data={'schema':1,'target':target,'host':target[0],'unit':self.plan['units'][target],
                  'mutation_performed':False,'observed_at_kst':self.at}
            if 'since_kst' in args:
                data.update(kind='journal_history',history_coverage={'status':'partial_or_unavailable'},has_more=False,
                            requested_since_kst=args['since_kst'],requested_until_kst=args['until_kst'])
            else:data.update(status='observed',properties={'ActiveState':'failed','Result':'exit-code'})
            rows.append({**copy.deepcopy(option),'is_error':False,'data':data})
        return rows

    def test_every_registered_history_target_and_terminal_punctuation(self):
        targets={k:v for k,v in d.TARGETS.items() if isinstance(v,str)}
        self.assertEqual(len(targets),25)
        for target,unit in targets.items():
            with self.subTest(target=target):
                for q in (f'오늘 {target} 오류와 현재 상태 확인',f'오늘 {target[0].upper()} 서버 {unit}. 실패와 지금 상태 확인'):
                    plan=c.service_history_plan(catalog(),q,self.at)
                    self.assertEqual(plan['units'],{target:unit})
                    self.assertEqual([x['arguments']['target'] for x in plan['requirements']],[target,target])

    def test_today_yesterday_and_exact_intervals(self):
        history=self.plan['requirements'][1]['arguments']
        self.assertEqual(history['since_kst'],self.now.replace(hour=0,minute=0,second=0,microsecond=0).isoformat())
        self.assertEqual(history['until_kst'],self.at)
        yesterday=c.service_history_plan(catalog(),'어제 c:apache 오류 조회',self.at)['requirements'][0]['arguments']
        self.assertEqual(datetime.fromisoformat(yesterday['until_kst'])+timedelta(microseconds=1),self.now.replace(hour=0,minute=0,second=0,microsecond=0))
        start=(self.now-timedelta(hours=1)).isoformat()
        plan=c.service_history_plan(catalog(),f'{start} ~ {self.at} c:apache 오류 조회',self.at)
        self.assertEqual(plan['requirements'][0]['arguments'],{'target':'c:apache','since_kst':start,'until_kst':self.at})

    def test_ambiguous_negative_unregistered_and_mixed_time_not_guessed(self):
        for q in ('오늘 vector.service 오류 확인','오늘 A 서버 capstone-management.service 실패와 현재 확인',
                  '오늘 b:management 오류 조회하지 마','오늘 b:management 오류 예시 설명',
                  '오늘 b:unknown 오류 확인','오늘 192.168.16.231 b:management 오류 확인',
                  '오늘과 어제 b:management 오류 확인','최근 b:management 오류 확인',
                  '오늘 3시부터 b:management 오류 확인','오늘 b:management 말고 c:apache 오류 확인',
                  '오늘 A 서버 B 서버 vector.service 실패 확인','오늘 soc:coverage 오류 확인'):
            with self.subTest(q=q):self.assertIsNone(c.service_history_plan(catalog(),q,self.at))

    def test_catalog_drift_and_timestamp_invalid_fail_closed(self):
        for change in ('history','mapping','duplicate'):
            req=catalog();schema=req['tools'][0]['function']['parameters']
            if change=='history':schema['allOf'][-1]['then']['properties']['target']['enum'].pop()
            elif change=='mapping':schema['properties']['target']['description']='b:management=unknown.service'
            else:req['tools'].append(copy.deepcopy(req['tools'][0]))
            self.assertIsNone(c.service_history_plan(req,self.question,self.at))
        for at in ('bad','2026-11-06T12:00:00Z','2026-11-06T12:00:00'):
            self.assertIsNone(c.service_history_plan(catalog(),self.question,at))

    def test_mixed_attack_request_keeps_security_evidence_requirement(self):
        self.assertFalse(c.service_history_plan(catalog(),self.question+' 공격 영향도 확인',self.at)['only_service'])

    def test_no_read_and_partial_read_remain_pending(self):
        state=c.service_history_state(self.plan,[],self.now)
        self.assertEqual(state['pending'],self.plan['requirements']);self.assertEqual(len(state['incomplete']),2)
        state=c.service_history_state(self.plan,self.rows()[:1],self.now)
        self.assertEqual(state['pending'],self.plan['requirements'][1:]);self.assertEqual(len(state['incomplete']),1)

    def test_actual_failed_attempt_stops_reselection_but_never_completes(self):
        rows=self.rows();rows[1].update(is_error=True,data={'error':'unavailable'})
        state=c.service_history_state(self.plan,rows,self.now)
        self.assertEqual(state['pending'],[]);self.assertEqual(state['incomplete'],['b:management:history:unavailable'])

    def test_read_coverage_does_not_require_health_or_full_journal(self):
        rows=self.rows();rows[0]['arguments']['lookback_minutes']=15;rows[1]['arguments']['limit']=20
        self.assertEqual(c.service_history_state(self.plan,rows,self.now),{'pending':[],'incomplete':[]})
        self.assertEqual(rows[0]['data']['properties']['ActiveState'],'failed')
        self.assertEqual(rows[1]['data']['history_coverage']['status'],'partial_or_unavailable')

    def test_wrong_unit_period_host_mutation_stale_and_malformed_not_complete(self):
        for change in ('unit','host','period','mutation','stale','future','publisher','shape','schema','kind'):
            rows=self.rows();data=rows[1]['data']
            if change=='unit':data['unit']='different.service'
            if change=='host':data['host']='a'
            if change=='period':data['requested_since_kst']=self.at
            if change=='mutation':data['mutation_performed']=True
            if change=='stale':data['observed_at_kst']=(self.now-timedelta(seconds=181)).isoformat()
            if change=='future':data['observed_at_kst']=(self.now+timedelta(seconds=6)).isoformat()
            if change=='publisher':data['publisher_stale']=True
            if change=='shape':data['history_coverage']=[]
            if change=='schema':data['schema']=True
            if change=='kind':data['kind']='current'
            with self.subTest(change=change):self.assertTrue(c.service_history_state(self.plan,rows,self.now)['incomplete'])

    def test_wrong_arguments_cannot_end_required_attempts(self):
        for key,value in [('target','c:apache'),('since_kst',self.at),('until_kst',self.at[:-6]+'+00:00'),('lookback_minutes',15)]:
            rows=self.rows();rows[1]['arguments'][key]=value
            with self.subTest(key=key):self.assertEqual(c.service_history_state(self.plan,rows,self.now)['pending'],self.plan['requirements'][1:])

    def test_bounded_service_read_uses_low_reasoning_not_risk_or_write(self):
        from types import SimpleNamespace
        agent=SimpleNamespace(provider='custom',model='qwen3.6:35b',base_url='http://10.200.10.10:11435/v1')
        for suffix,effort in (('', 'none'),(' 공격 영향도 판단', 'medium'),(' 위험과 대응 판단','medium'),(' 재시작 승인 요청','medium'),(' 복구 여부와 종결 판단','medium')):
            context={'request':self.question+suffix,'background':'','tools':[NAME],'requested_at_kst':self.at}
            with patch.dict(w.os.environ,{'CAPSTONE_MANAGEMENT_MODE':'verify','CAPSTONE_CHAT_READ_JSON':json.dumps(context)},clear=True):
                result=w.management_reasoning(dict(catalog(),model='qwen3.6:35b'),agent)
                self.assertEqual(result['reasoning_effort'],effort)
        with patch.dict(w.os.environ,{},clear=True):
            self.assertEqual(w.management_reasoning(dict(catalog(),model='qwen3.6:35b'),agent)['reasoning_effort'],'medium')

    def test_native_provider_shaping_keeps_registered_service_reasoning_scope(self):
        from types import SimpleNamespace
        req=catalog();native=copy.deepcopy(req);native['tools'][0]['function']['parameters'].pop('allOf')
        full=req['tools'][0]['function']['parameters']
        agent=SimpleNamespace(provider='custom',model='qwen3.6:35b',base_url='http://10.200.10.10:11435/v1',
            _current_turn_id='current',_capstone_registered_read_conditions=('current',{NAME:full}))
        context={'request':self.question,'background':'','tools':[NAME],'requested_at_kst':self.at}
        with patch.dict(w.os.environ,{'CAPSTONE_MANAGEMENT_MODE':'verify','CAPSTONE_CHAT_READ_JSON':json.dumps(context)},clear=True):
            self.assertEqual(w.management_reasoning(dict(native,model='qwen3.6:35b'),agent)['reasoning_effort'],'none')
            agent._capstone_registered_read_conditions=('old',{NAME:full})
            self.assertEqual(w.management_reasoning(dict(native,model='qwen3.6:35b'),agent)['reasoning_effort'],'medium')
            agent._capstone_registered_read_conditions=('current',{NAME:full})
            self.assertEqual(w.management_reasoning({'tools':[],'model':'qwen3.6:35b'},agent)['reasoning_effort'],'medium')

    def test_immutable_inline_gate_without_file_loads_fixed_contract(self):
        original=w.__file__;w.diagnostic_contract.cache_clear()
        del w.__file__
        try:
            with patch.object(w,'Path',side_effect=lambda path: ROOT/'infra/hermes/soc_management_run.py' if path=='/opt/data/management-code/run.py' else Path(path)):
                self.assertEqual(w.diagnostic_contract().VERSION,c.VERSION)
        finally:
            w.__file__=original;w.diagnostic_contract.cache_clear()

    def test_native_only_root_current_question_and_verify_mode(self):
        context={'request':self.question,'background':'','tools':[NAME],'requested_at_kst':self.at}
        env={'CAPSTONE_MANAGEMENT_MODE':'verify','CAPSTONE_CHAT_READ_JSON':json.dumps(context)}
        with patch.dict(w.os.environ,env,clear=True):
            self.assertEqual(w.operator_diagnostic_options(catalog()),self.plan['requirements'])
            self.assertEqual(w.operator_diagnostic_options(catalog(),self.rows()),[])
            self.assertEqual(w.chat_diagnostic_state(catalog(),self.rows())['incomplete'],[])
        with patch.dict(w.os.environ,{},clear=True):self.assertEqual(w.operator_diagnostic_options(catalog()),[])
        with patch.dict(w.os.environ,dict(env,CAPSTONE_MANAGEMENT_MODE='apply'),clear=True):
            with self.assertRaisesRegex(RuntimeError,'chat_read_context_invalid'):w.operator_diagnostic_options(catalog())

if __name__=='__main__':unittest.main()
