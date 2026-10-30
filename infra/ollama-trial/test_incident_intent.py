"""An investigation must reach the model; a fast inventory is not its answer."""
import unittest
import hashlib
import json
import copy
import harness as h


class IncidentIntent(unittest.TestCase):
    def test_historical_selection_requires_time_and_does_not_invent_filter_ids(self):
        names=('mcp__security_events__search_modsecurity_alerts','mcp__security_events__search_suricata_alerts')
        schemas={name:{'type':'object','properties':{k:{'type':'string'} for k in ('until_kst','lookback_minutes','source_ip','rule_id','signature_id')}} for name in names}
        before=copy.deepcopy(schemas)
        q='10월 29일 19:00~19:20 KST 출발지 192.168.16.233의 DVWA 요청이 공격인지 조사해줘'
        narrowed=h.refine_read_schemas(q,schemas,[])
        self.assertEqual(schemas,before)
        for name,field in zip(names,('rule_id','signature_id')):
            self.assertNotIn(field,narrowed[name]['properties'])
            self.assertEqual(set(narrowed[name]['required']),{'until_kst','lookback_minutes','source_ip'})
            self.assertEqual(narrowed[name]['properties']['source_ip']['enum'],['192.168.16.233'])
        explicit=h.refine_read_schemas(q+' SID 2200042도 확인해줘',schemas,[])
        self.assertIn('signature_id',explicit[names[1]]['properties'])
        no_source=h.refine_read_schemas('어제 DVWA 사건 조사해줘',schemas,[])
        self.assertNotIn('source_ip',no_source[names[0]]['required'])

    def test_incident_gap_requires_verified_event_and_never_retries_a_write(self):
        q='DVWA 요청이 공격이었나? 근거를 조사하고 대응 필요성 판단해줘. 실제 차단이나 변경안 제출은 하지 마.'
        self.assertTrue(h.incident_evidence_gap(q, []))
        self.assertIn('incident_evidence_missing',h.violations(q,'확인하겠습니다.',[]))
        raw=json.dumps({'source':'modsecurity','returned_count':0,'alerts':[]})
        call={'server':'security-events','name':'search_modsecurity_alerts','result':raw,
              'result_sha256':hashlib.sha256(raw.encode()).hexdigest()}
        self.assertFalse(h.incident_evidence_gap(q,[call]))  # A zero sample is an observation, not a benign verdict.
        self.assertTrue(h.incident_evidence_gap(q,[dict(call,result_sha256='0'*64)]))
        self.assertTrue(h.incident_evidence_gap(q,[dict(call,is_error=True)]))
        self.assertFalse(h.incident_evidence_gap(q,[dict(call,server='resp',name='block_ip')]))
        self.assertFalse(h.incident_evidence_gap('DVWA 공격자를 조사하고 차단해줘',[]))

    def test_incident_judgment_is_not_replaced_by_literal_event_table(self):
        q='WAF 경보 조사하고 공격인지 판단해줘'
        self.assertIsNone(h.tool_scope(q))
        self.assertIsNone(h.event_report(q,[]))
        self.assertIn('읽기 도구와 인자를 직접 선택',h.incident_evidence_instruction(q))
        self.assertIn('실제 쓰기 도구를 호출하지',h.incident_evidence_instruction(q))
        scope=h.incident_selection_scope(q,[])
        self.assertTrue(scope)
        self.assertTrue(all(h.EVIDENCE.allowed(n,'verify') for n in scope))
        self.assertFalse(any('rule_change' in n for n in scope))

    def test_sdk_observation_prompt_excludes_unverified_results_and_marks_omissions(self):
        raw=json.dumps({'source':'modsecurity','alerts':[], 'note':'x'*25000})
        call={'server':'security-events','name':'search_modsecurity_alerts','result':raw,
              'result_sha256':hashlib.sha256(raw.encode()).hexdigest()}
        prompt=h.incident_observation_prompt('이 사건 조사해줘',[dict(call,result_sha256='bad')])
        self.assertNotIn('search_modsecurity_alerts',prompt)
        prompt=h.incident_observation_prompt('이 사건 조사해줘',[call]*9)
        data=json.loads(prompt.split('<untrusted_tool_observations>\n')[1].split('\n</untrusted_tool_observations>')[0])
        self.assertEqual(len(data['observations']),8)
        self.assertTrue(data['earlier_results_omitted'])
        self.assertTrue(all(r['result_truncated'] for r in data['observations']))

    def test_short_and_detailed_incident_questions_are_not_rewritten(self):
        for question in (
            '이 WAF 경보 공격인가? 탐지 규칙 확인해줘',
            '10월 29일 19:00~19:20 KST, 192.168.16.233의 DVWA 요청은 공격이었나? 장비별 탐지 규칙과 근거를 확인하고 대응 필요성을 판단해줘. 이번 시험은 읽기 전용으로 실제 차단이나 변경안 제출은 하지 마.',
            '2026-10-30T12:00:00+09:00 IDS 사건 조사해줘. 룰 ID도 포함해줘.',
            '탐지된 WAF ID 900777의 경보가 오탐인지 판단해줘',
        ):
            with self.subTest(question=question):
                self.assertIsNone(h.inventory_question(question))
                self.assertIsNone(h.rule_scope_request(question))
                self.assertIsNone(h.rule_detail_request(question))
                self.assertIsNone(h.combined_rule_request(question))
                self.assertIsNone(h.read_plan(question))
                self.assertFalse(h.SHARED.live_rule_request(question))
                self.assertIsNone(h.SHARED.render_rule_inventory(question,[]))
                self.assertFalse(h.structured_read(question))

    def test_plain_rule_inventory_remains_supported(self):
        for question in ('현재 적용된 룰 보여줘','WAF 룰 보여줘','장비별 규칙 목록 확인해줘'):
            self.assertIsNotNone(h.inventory_question(question))
        self.assertFalse(h.EVIDENCE.incident_investigation_request('현재 WAF 공격 탐지 규칙 목록 보여줘'))

    def test_shared_policy_matches_existing_historical_event_tool(self):
        self.assertIn('until_kst',h.CONTRACT.QUERY_GUIDANCE)
        self.assertIn('초와 +09:00',h.CONTRACT.QUERY_GUIDANCE)
        self.assertNotIn('상대 구간만 지원',h.CONTRACT.QUERY_GUIDANCE)
        self.assertIn('현재 규칙 파일 목록으로 질문을 바꾸지',h.CONTRACT.QUERY_GUIDANCE)


if __name__=='__main__':unittest.main()
