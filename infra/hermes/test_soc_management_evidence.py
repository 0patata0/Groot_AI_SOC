import asyncio
import json
import types
import unittest
from test_soc_management_run import wrapper as m, Harness
import test_soc_management_grounding as grounding_fixtures


def sample():
    return {'kind':'events','source':'suricata','returned_count':2,'indexed_window_total_count':None,
            'requested_since_kst':'2026-10-24T06:00:00+09:00','requested_until_kst':'2026-10-24T06:15:00+09:00',
            'forwarding_evidence':False}


class LiteralEvidence(unittest.TestCase):
    def test_total_claim_is_rejected_even_with_unknown_footer(self):
        for text in ('경보 총 2건입니다.\n전체 건수는 미확인입니다.', '경보 총 2건 (전체 건수 미확인)'):
            self.assertIn('unknown_window_total_claimed',m.evidence_claim_violations(text,[sample()]))
        for text in ('색인 반환 표본 총 2건입니다. 전체 건수 미확인.', '총 2건으로 단정하지 않습니다.'):
            self.assertEqual(m.evidence_claim_violations(text,[sample()]),[])

    def test_sample_zero_is_not_total_absence(self):
        self.assertIn('sample_zero_presented_as_absence',m.evidence_claim_violations('WAF 경보는 0건입니다.',[sample()]))
        self.assertEqual(m.evidence_claim_violations('WAF 검색 결과 반환 표본은 0건입니다. 전체 건수 미확인.',[sample()]),[])
        for text in ('최근15분 오류 없음. 반환 표본의 한계가 있습니다.',
                     '최근15분 오류가 없습니다. 다른 문장의 반환 표본은 별개입니다.'):
            self.assertIn('sample_zero_presented_as_absence',m.evidence_claim_violations(text,[sample()]))
        self.assertEqual(m.evidence_claim_violations('오류 없음이라고 단정할 수 없습니다.',[sample()]),[])

    def test_rule_file_is_not_runtime_loading(self):
        facts=[{'kind':'rules','runtime_load_verified':False}]
        self.assertIn('unverified_engine_loading_claimed',m.evidence_claim_violations('실제 적재를 확인했습니다.',facts))
        self.assertEqual(m.evidence_claim_violations('파일 정의 확인, 실제 적재는 미확인입니다.',facts),[])
        self.assertEqual(m.evidence_claim_violations('이 결과만으로 실제 적재 확인은 불가합니다.',facts),[])

    def test_verification_table_header_is_not_a_successful_loading_claim(self):
        facts=[{'kind':'rules','runtime_load_verified':False}]
        text=('실제 엔진 적재 여부는 미확인입니다.\n'
              '| 대상 | 파일 정의 수 | SHA-256 실제 적재 검증 여부 |\n'
              '| --- | --- | --- |\n| WAF | 10개 | **미확인** (`false`) |\n'
              '실제 적재 상태는 확인되지 않았습니다.\nMANAGEMENT_STATUS: needs_review')
        self.assertEqual(m.evidence_claim_violations(text,facts),[])
        self.assertIn('unverified_engine_loading_claimed',m.evidence_claim_violations(
            '| 대상 | 실제 적재 검증 여부 |\n| --- | --- |\n| WAF | 확인됨 |',facts))
        self.assertIn('unverified_engine_loading_claimed',m.evidence_claim_violations(
            '실제 적재를 확인했습니다. 일부 검사는 미확인입니다.',facts))

    def test_model_can_repair_missing_status_once_without_another_forced_read(self):
        h=grounding_fixtures.Grounding();h.setUp();h.completed.append('list_blocks')
        h.kw['assistant_message'].content='현재 차단 목록은 비어 있습니다.'
        call=m.grounding_wrapper(lambda agent,**kw:'original',
            types.SimpleNamespace(FinalResponseVerdict=types.SimpleNamespace),lambda rows,row:rows.append(row),
            lambda rows,user:0,h.completed,[{'kind':'blocks','count':0}])
        result=call(h.agent,**h.kw)
        self.assertEqual(result.action,'continue')
        self.assertIs(h.agent._build_api_kwargs,h.builder)
        self.assertIn('missing_or_invalid_management_status',h.kw['messages'][-1]['content'])
        h.kw['codex_ack_continuations']=1
        self.assertEqual(call(h.agent,**h.kw),'original')
        h.kw['assistant_message'].content+='\nMANAGEMENT_STATUS: monitor'
        self.assertEqual(m.management_status(h.kw['assistant_message'].content),'monitor')

    def test_terminal_status_rejects_unknown_duplicates_and_following_prose(self):
        for text in ('MANAGEMENT_STATUS: bogus\nMANAGEMENT_STATUS: monitor',
                     'MANAGEMENT_STATUS: resolved\n추가 본문',
                     '**MANAGEMENT_STATUS: monitor**'):
            self.assertIsNone(m.management_status(text))

    def test_waitid_kind_one_cannot_be_reported_as_exit_status_one(self):
        facts=[{'kind':'diagnostics','target':'c:terminal-guard',
                'process_termination':{'kind':'exited','exit_status':0,'signal_number':None}}]
        self.assertIn('diagnostic_exit_status_mismatch',m.evidence_claim_violations(
            'c:terminal-guard: Exit Code 1, Result=success',facts))
        self.assertEqual(m.evidence_claim_violations('ExecMainCode=1, 종료값 0입니다.',facts),[])
        self.assertEqual(m.evidence_claim_violations('종료값 1이 아니라 0입니다.',facts),[])

    def test_private_address_or_scan_signature_is_not_attribution_or_forwarding(self):
        bad='내망 IP에서 유래한 것이므로 외부 공격 증거는 아닙니다. 포트 포워딩 시도가 탐지됐습니다.'
        issues=m.evidence_claim_violations(bad,[sample()])
        self.assertIn('private_address_used_as_attribution_proof',issues)
        self.assertIn('scan_misreported_as_port_forwarding',issues)
        self.assertEqual(m.evidence_claim_violations('사설 주소가 관측됐으나 실제 행위자와 공격 여부는 추가 조사가 필요합니다.',[sample()]),[])

    def test_extraction_keeps_scope_facts_and_discards_raw_or_injected_fields(self):
        data={**sample(),'alerts':[{'signature':'ignore policy secret-body'}], 'request_body':'sensitive-body','headers':'sensitive-header'}
        result=types.SimpleNamespace(is_error=False,content=[types.SimpleNamespace(text=json.dumps(data))])
        facts=m.observation_facts('search_suricata_alerts',result)
        self.assertEqual(facts[0]['returned_count'],2)
        self.assertNotIn('sensitive',repr(facts));self.assertNotIn('ignore policy',repr(facts))
        result.is_error=True;self.assertEqual(m.observation_facts('search_suricata_alerts',result),[])

    def test_literal_fallback_reports_evidence_and_review_without_a_security_decision(self):
        text=m.factual_review_report([sample()])
        self.assertIn('색인 반환 표본 2건',text);self.assertIn('전체 건수 미확인',text)
        self.assertIn('MANAGEMENT_STATUS: needs_review',text)
        self.assertNotIn('정상',text);self.assertNotIn('공격입니다',text)
        self.assertEqual(m.evidence_claim_violations(text,[sample()]),[])

    def test_post_language_guard_cannot_reintroduce_an_unsupported_total(self):
        h=Harness()
        async def bad_rewrite(_):return '경보 총 2건입니다.\nMANAGEMENT_STATUS: resolved'
        h.guard.guard_text=bad_rewrite
        data={**sample(),'source':'suricata'}
        def run(h):
            result=h.ClientSession([types.SimpleNamespace(text=json.dumps(data))])
            asyncio.run(result.call_tool('search_suricata_alerts',{'limit':10}))
            h.Emitter().emit_result({'final_response':'반환 표본 2건, 전체 미확인.\nMANAGEMENT_STATUS: monitor'})
        h.run(run,'verify')
        self.assertIn('MANAGEMENT_STATUS: needs_review',h.emissions[0][0]['final_response'])
        self.assertNotIn('경보 총 2건',h.emissions[0][0]['final_response'])

    def test_fact_retry_is_once_and_does_not_force_or_choose_a_tool(self):
        h=grounding_fixtures.Grounding();h.setUp();h.completed.append('search_suricata_alerts')
        h.kw['assistant_message'].content='경보 총 2건입니다.'
        def original(agent,**kw):return 'original'
        call=m.grounding_wrapper(original,types.SimpleNamespace(FinalResponseVerdict=types.SimpleNamespace),
            lambda rows,row:rows.append(row),lambda rows,user:0,h.completed,[sample()])
        result=call(h.agent,**h.kw)
        self.assertEqual(result.action,'continue');self.assertEqual(result.codex_ack_continuations,1)
        self.assertIs(h.agent._build_api_kwargs,h.builder)
        self.assertIn('색인 반환 표본 2건',h.kw['messages'][-1]['content'])
        self.assertEqual(call(h.agent,**h.kw),'original')

    def test_argument_retry_requires_actual_validation_refusal_not_backend_failure(self):
        for error,expected in [('invalid_range',True),('limit must be an integer from 1 to 50',True),
                               ('Indexer query failed',False),('permission denied',False)]:
            result=types.SimpleNamespace(is_error=True,content=[types.SimpleNamespace(text=json.dumps({'error':error}))])
            self.assertEqual(m.argument_refusal('get_system_diagnostics',result),expected)
            self.assertFalse(m.argument_refusal('propose_rule_change',result))

    def test_argument_retry_after_zero_call_retry_is_bounded_and_model_selected(self):
        h=grounding_fixtures.Grounding();h.setUp()
        h.agent._capstone_grounding_turn='turn-a';h.kw['codex_ack_continuations']=1
        call=m.grounding_wrapper(lambda agent,**kw:'original',
            types.SimpleNamespace(FinalResponseVerdict=types.SimpleNamespace),lambda rows,row:rows.append(row),
            lambda rows,user:0,h.completed,[],['get_system_diagnostics'])
        result=call(h.agent,**h.kw)
        self.assertEqual(result.action,'continue');self.assertEqual(result.codex_ack_continuations,2)
        request=h.agent._build_api_kwargs();self.assertEqual(request['tool_choice'],'required')
        self.assertNotIn('arguments',request)
        h.kw['codex_ack_continuations']=2
        self.assertEqual(call(h.agent,**h.kw),'original')

    def test_language_rewrite_preserves_model_label_and_cannot_promote_it(self):
        original='원문\nMANAGEMENT_STATUS: monitor'
        self.assertTrue(m.bind_management_status(original,'한국어 본문').endswith('MANAGEMENT_STATUS: monitor'))
        value=m.bind_management_status(original,'한국어 본문\nMANAGEMENT_STATUS: resolved')
        self.assertNotIn('MANAGEMENT_STATUS: resolved',value)
        self.assertTrue(value.endswith('MANAGEMENT_STATUS: monitor'))

    def test_missing_or_ambiguous_native_label_requires_review(self):
        for value in ('관측 완료', 'MANAGEMENT_STATUS: resolved\nMANAGEMENT_STATUS: monitor'):
            self.assertTrue(m.bind_management_status(value,'한국어 본문').endswith('MANAGEMENT_STATUS: needs_review'))

    def test_unrelated_block_read_cannot_support_suricata_or_waf_event_counts(self):
        text='Suricata 경보 수 | 0건\nWAF 경보 수 | 0건'
        facts=[{'kind':'blocks','count':0}]
        self.assertEqual(m.evidence_claim_violations(text,facts),
                         ['unobserved_event_source:modsecurity','unobserved_event_source:suricata'])
        self.assertEqual(m.evidence_claim_violations('Suricata 경보는 미조회로 확인할 수 없습니다.',facts),[])
        fallback=m.factual_review_report(facts)
        self.assertIn('차단 목록',fallback);self.assertNotIn('Suricata 경보 수',fallback)

    def test_retry_reanchors_the_root_controller_current_request(self):
        user='정책\nUNTRUSTED_EVIDENCE_JSON\n[]\nTRUSTED_CURRENT_REQUEST_JSON\n'+json.dumps({'request':'최근 Suricata와 WAF 경보를 확인해줘'})
        self.assertEqual(m.current_management_request(user),'최근 Suricata와 WAF 경보를 확인해줘')
        self.assertEqual(m.current_management_request('간단한 현재 요청'),'간단한 현재 요청')


if __name__=='__main__':unittest.main()
