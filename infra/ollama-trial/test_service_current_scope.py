"""Current-only service lookup uses the catalog and preserves other scopes."""
from datetime import datetime
import unittest

import harness as h
from test_service_identity_scope import NAME, AT, catalog, snapshot


class ServiceCurrentScope(unittest.TestCase):
    def plan(self, question, request=None):
        return h.CONTRACT.service_history_plan(request or catalog(),question,AT)

    def test_registered_names_and_units_need_only_current_reads(self):
        for question,target in (
                ('A 서버 인증서 감시 상태 보여줘','a:certificate-monitor'),
                ('A 서버 저장소 감시 서비스 상태 알려줘','a:storage-monitor'),
                ('B 서버 도커 현재 상태 보여줘','b:docker'),
                ('C 서버 apache2.service 상태 확인해줘','c:apache'),
                ('a:certificate-monitor 지금 상태 표로 보여줘','a:certificate-monitor')):
            with self.subTest(question=question):
                self.assertIsNone(h.read_plan(question),'service status must not preselect Wazuh agent identity')
                plan=self.plan(question)
                self.assertIsNotNone(plan)
                self.assertTrue(plan['current_only'])
                self.assertEqual(plan['requirements'],[{'tool':NAME,'arguments':{'target':target}}])
                self.assertFalse(plan['initial_window'])
                self.assertIsNone(plan['initial_history_window_minutes'])
                self.assertTrue(h.CONTRACT.service_lookup_scope(plan,question))

    def test_shared_service_name_asks_host_instead_of_choosing_one(self):
        question='Docker 상태 보여줘'
        self.assertIsNone(self.plan(question))
        notice=h.CONTRACT.service_scope_notice(catalog(),question)
        self.assertIn('어느 대상의 상태',notice)
        self.assertIn('a:docker',notice)
        self.assertIn('b:docker',notice)
        self.assertIn('c:docker',notice)
        self.assertIn('아직 조회하지 않았습니다',notice)
        self.assertNotIn('로그·이력',notice)

    def test_current_receipt_does_not_require_history_or_claim_a_user_period(self):
        question='A 서버 인증서 감시 서비스 현재 상태 보여줘'
        plan=self.plan(question)
        self.assertIsNotNone(plan)
        receipts=h.service_history_receipts([snapshot()])
        context=h.CONTRACT.service_report_context(catalog(),question,AT,receipts,now=datetime.fromisoformat(AT))
        self.assertIsNotNone(context)
        self.assertTrue(context['lookup_only'])
        self.assertEqual(context['history_window_origin'],'current_observation_only')
        self.assertEqual(context['requested_service_scope']['history_windows'],[])
        self.assertEqual(h.CONTRACT.service_lookup_note(context),'')

    def test_failed_wrong_host_or_stale_snapshot_never_completes(self):
        question='A 서버 인증서 감시 상태 보여줘'
        self.assertIsNotNone(self.plan(question))
        for kind in ('failed','wrong','stale','missing'):
            receipts=h.service_history_receipts([snapshot()])
            if kind=='failed':receipts[0]['is_error']=True
            elif kind=='wrong':receipts[0]['data']['host']='b'
            elif kind=='stale':receipts[0]['data']['observed_at_kst']='2000-01-01T00:00:00+09:00'
            else:receipts=[]
            with self.subTest(kind=kind):
                self.assertIsNone(h.CONTRACT.service_report_context(catalog(),question,AT,receipts,now=datetime.fromisoformat(AT)))

    def test_companions_are_taken_from_actual_schema_and_kept_in_scope(self):
        request=catalog();schema=request['tools'][0]['function']['parameters']
        declared=schema['properties']['target'].get('x-capstone-current-companions',{})
        question='B 서버 관리 서비스 현재 상태 보여줘'
        plan=self.plan(question,request)
        self.assertIsNotNone(plan)
        expected={'b:management',*declared.get('b:management',[])}
        self.assertEqual({r['arguments']['target']for r in plan['requirements']},expected)
        self.assertTrue(all(set(r['arguments'])=={'target'}for r in plan['requirements']))

    def test_previous_historical_and_cause_requests_keep_their_required_reads(self):
        for question in ('A 서버 인증서 감시 현재 상태와 최근 실행 결과 보여줘',
                         'A 서버 인증서 감시 최근 30분 오류와 현재 상태 보여줘',
                         'A 서버 인증서 감시 실패 원인과 현재 상태 확인해줘'):
            with self.subTest(question=question):
                plan=self.plan(question)
                self.assertIsNotNone(plan)
                self.assertFalse(plan.get('current_only',False))
                self.assertTrue(any('since_kst'in r['arguments']for r in plan['requirements']))

    def test_temporal_resampling_mutation_and_health_judgment_are_not_current_only(self):
        for suffix in ('어제 상태 보여줘','지난 30분 상태 보여줘','내일 상태 보여줘',
                       '아까 상태 보여줘','두 번 상태 확인해줘','다시 상태 확인해줘',
                       '이전 상태와 현재 상태 비교해줘','현재 상태가 정상인지 판단해줘',
                       '현재 상태와 다른 서버 영향도 알려줘','재시작하고 상태 보여줘',
                       '현재 상태 보여주는 문장 번역해줘','현재 상태를 도구 없이 알려줘',
                       '현재 상태를 조회하지 마','상태와 적용 룰 보여줘'):
            with self.subTest(suffix=suffix):
                plan=self.plan('A 서버 인증서 감시 '+suffix)
                self.assertFalse(plan and plan.get('current_only'))

    def test_transport_actor_is_not_a_period_or_a_target(self):
        for prefix in ('[socadmin] ','[operator.42] ','@hermes '):
            with self.subTest(prefix=prefix):
                plan=self.plan(prefix+'A 서버 저장소 감시 상태 보여줘')
                self.assertIsNotNone(plan)
                self.assertEqual(plan['requirements'],[{'tool':NAME,'arguments':{'target':'a:storage-monitor'}}])

    def test_unknown_and_conflicting_targets_never_fall_back_to_another_host(self):
        for question in ('D 서버 Docker 현재 상태 보여줘','A 서버 b:docker 상태 보여줘',
                         'A 서버 처음 보는 감시 서비스 현재 상태 보여줘'):
            with self.subTest(question=question):self.assertIsNone(self.plan(question))

    def test_unfamiliar_object_name_never_becomes_host_agent_identity(self):
        for noun in ('새 관측 대상','인증서 감시','저장소 감시','기타 장치'):
            with self.subTest(noun=noun):
                self.assertIsNone(h.read_plan('A 서버 '+noun+' 상태 보여줘'))
        request=catalog();labels=request['tools'][0]['function']['parameters']['properties']['target']['x-capstone-service-labels']
        labels['a:storage-monitor'].append('신규 장치 관측')
        question='A 서버 신규 장치 관측 상태 보여줘'
        self.assertIsNone(h.read_plan(question))
        self.assertEqual(self.plan(question,request)['requirements'],[{'tool':NAME,'arguments':{'target':'a:storage-monitor'}}])

    def test_plain_host_identity_keeps_korean_particles_after_id(self):
        for question in ('보안 서버 ID와 연결 상태 보여줘','서비스 서버의 ID를 표로 보여줘',
                         'B 호스트 ID와 상태','A 서버의 현재 연결 상태 확인해줘'):
            with self.subTest(question=question):self.assertEqual(h.read_plan(question)['kind'],'agent_identity')

    def test_agent_identity_and_engine_rule_scope_remain_distinct(self):
        question='서비스 서버 에이전트 ID와 현재 연결 상태 보여줘'
        self.assertIsNone(self.plan(question))
        self.assertEqual(h.read_plan(question)['kind'],'agent_identity')
        for question in ('A 서버 IDS 적용 룰과 현재 상태 보여줘',
                         'A 서버 Suricata 모드와 현재 상태 보여줘',
                         'A 서버 WAF 차단 룰과 현재 상태 보여줘'):
            with self.subTest(question=question):
                plan=self.plan(question)
                self.assertFalse(plan and plan.get('current_only'))

    def test_host_reply_preserves_service_and_gets_fresh_current_reads(self):
        for old,reply,target in (
                ('Docker 상태 보여줘','C 서버','c:docker'),
                ('B 서버 Docker 현재 상태 보여줘','C 서버','c:docker'),
                ('b:docker 상태 보여줘','A 서버','a:docker')):
            with self.subTest(old=old):
                question=h.resolve_short_read(reply,[old])
                plan=self.plan(question)
                self.assertIsNotNone(plan)
                self.assertEqual(plan['requirements'],[{'tool':NAME,'arguments':{'target':target}}])
        question=h.resolve_short_read('상태 보여줘',['Docker 상태 보여줘','C 서버'])
        self.assertEqual(self.plan(question)['requirements'],[{'tool':NAME,'arguments':{'target':'c:docker'}}])

    def test_host_reply_keeps_the_requested_historical_window(self):
        question=h.resolve_short_read('B 서버',['Docker 최근 30분 오류와 현재 상태 보여줘'])
        plan=self.plan(question)
        self.assertIsNotNone(plan)
        self.assertEqual(set(plan['units']),{'b:docker'})
        self.assertFalse(plan['current_only'])
        args=next(r['arguments']for r in plan['requirements']if 'since_kst'in r['arguments'])
        self.assertEqual((datetime.fromisoformat(args['until_kst'])-datetime.fromisoformat(args['since_kst'])).total_seconds(),1800)

    def test_host_reply_never_inherits_a_write_topic_or_unchecked_history(self):
        for prior in ([],[{'author':'another','text':'Docker 상태 보여줘'}],
                      ['B 서버 Docker 재시작해줘'],['FW 룰 보여줘'],
                      ['Docker 상태 보여줘','논문 요약해줘']):
            with self.subTest(prior=prior):self.assertEqual(h.resolve_short_read('C 서버',prior),'C 서버')
        self.assertEqual(h.resolve_short_read('C 서버 자원 사용량 보여줘',['Docker 상태 보여줘']),
                         'C 서버 자원 사용량 보여줘')


if __name__=='__main__':unittest.main()
