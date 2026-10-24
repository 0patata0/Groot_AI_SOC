"""Regression cases from actual misreported timestamps, scope and rejected args."""
import copy
import json
import unittest
from pathlib import Path
from unittest import mock
import test_completion as base
P = base.PLUGIN
E = P.EVIDENCE


def exchange(data, name='mcp__rule_a__get_service_action_target', cid='runtime-1'):
    return [{'role':'assistant','tool_calls':[{'id':cid,'function':{'name':name,'arguments':'{"target":"a:suricata"}'}}]},
            {'role':'tool','tool_call_id':cid,'content':json.dumps({'result':json.dumps(data)})}]


def runtime():
    return {'target':'a:suricata','rule_source_evidence':{
        'rule_source_option':'-S','rule_source_path':'/rules/all.rules',
        'combined_is_exact_et_plus_local':True,'started_at':'2026-10-23T22:03:11.971632878Z',
        'observed_at':1792842746,'running':True}}


class EvidenceKST(unittest.TestCase):
    def test_day_boundary_and_precision_are_converted_not_relabelled(self):
        self.assertEqual(E.kst_display('시작 2026-10-23T22:03:11.971Z'),
                         '시작 2026-10-24T07:03:11.971000+09:00 (KST)')
        self.assertEqual(E.parse_instant('2026-10-23T22:03:11Z'),E.parse_instant('2026-10-24T07:03:11+09:00'))
        self.assertEqual(E.kst_time('2026-10-24T15:45:30'), '시간대 확인 필요')

    def test_protected_source_bytes_and_idempotence(self):
        text='기록 2026-10-24T02:00:00Z\n```diff\n+time=2026-10-24T02:00:00Z\n```'
        converted=E.kst_display(text)
        self.assertIn('```diff\n+time=2026-10-24T02:00:00Z\n```',converted)
        self.assertIn('원문 시각의 KST 환산: 2026-10-24T11:00:00+09:00 (KST)',converted)
        self.assertEqual(E.kst_display(converted),converted)

    def test_real_nine_hour_mislabel_detected_before_display_conversion(self):
        facts=[{'kind':'times','instants':['2026-10-24T15:45:30.294+09:00']}]
        self.assertIn('timestamp_offset_relabelled',E.evidence_claim_violations('경보 2026-10-24T15:45:30Z',facts))
        self.assertEqual(E.evidence_claim_violations('경보 2026-10-24T06:45:30Z',facts),[])

    def test_live_double_conversion_start_time_cannot_be_posted(self):
        facts=P.current_evidence(exchange(runtime()))[0]
        for value in ('2026-10-24T07:03:11Z','2026-10-24T16:03:11+09:00','2026-10-24T15:03:11+09:00'):
            self.assertIn('service_start_instant_mismatch',E.evidence_claim_violations('시작 시간 '+value,facts))
        self.assertEqual(E.evidence_claim_violations('시작 시간 2026-10-24T07:03:11+09:00',facts),[])
        h=base.Harness(text='시작 시간 2026-10-24T07:03:11Z',request='IDS 현재 상태 확인해줘')
        h.kw['messages']+=exchange(runtime());first=h.call();self.assertEqual(first.action,'continue')
        h.kw['codex_ack_continuations']=first.codex_ack_continuations
        h.kw['assistant_message']=base.message('시작 시간 2026-10-24T07:03:11Z')
        h.call();self.assertNotIn('T16:03',h.original_calls[-1].content)
        self.assertIn('2026-10-24T07:03:11.971632+09:00',h.original_calls[-1].content)

    def test_runtime_path_and_historical_loading_are_not_equated(self):
        facts,errors,linked=P.current_evidence(exchange(runtime()))
        self.assertTrue(linked);self.assertFalse(errors)
        for prose,issue in [('현재 -S /rules/suricata.rules','current_rule_source_mismatch'),
                            ('SID 1000051 로딩 확인 근거','historical_hit_is_not_current_engine_proof'),
                            ('컨테이너 시작 약22시간 전','uptime_mismatch'),
                            ('SID 1000051은 TLS 통신을 탐지했습니다.','tls_not_in_current_evidence')]:
            self.assertIn(issue,E.evidence_claim_violations(prose,facts))
        self.assertEqual(E.evidence_claim_violations('이전 -S /rules/suricata.rules 주장은 오답입니다. 현재 SID별 적재는 미확인.',facts),[])
        self.assertIn('2026-10-24T07:03:11.971632+09:00',E.literal_evidence_summary(facts))

    def test_observed_final_count_and_combined_load_overclaims(self):
        facts=P.current_evidence(exchange(runtime()))[0]+[{'kind':'events','source':'suricata','returned_count':2,'indexed_window_total_count':None}]
        self.assertIn('sample_count_presented_as_window_total',E.evidence_claim_violations('Suricata 경보가 2건 발생함',facts))
        self.assertIn('combined_bytes_are_not_engine_load_proof',E.evidence_claim_violations('파일이 결합되어 로드됨',facts))
        self.assertEqual(E.evidence_claim_violations('색인 반환 표본 2건, 전체 미확인. 결합 파일 전달 확인, SID별 적재 미확인.',facts),[])

    def test_grounded_lookup_effort_keeps_original_proposal_authority(self):
        h=base.Harness();h.agent.provider='custom';h.agent.model='qwen3.6:35b';h.agent.base_url='http://211.170.162.111:11434/v1'
        h.api_kwargs['model']='qwen3.6:35b';names=copy.deepcopy(h.agent.valid_tool_names)
        self.assertTrue(P._arm_read_request(h.agent,'turn-a',require_read=False,read_only=False,grounded_lookup=True))
        result=h.agent._build_api_kwargs([])
        self.assertEqual(result['reasoning_effort'],'none')
        self.assertEqual(result['tools'],h.api_kwargs['tools']);self.assertEqual(h.agent.valid_tool_names,names)

    def test_nested_real_argument_error_then_success(self):
        name='mcp__system_diagnostics__get_system_diagnostics'
        bad=exchange({'error':json.dumps({'reason':'unknown_target','status':'unavailable','mutation_performed':False})},name)
        self.assertEqual(P.current_evidence(bad)[1],[name])
        good=exchange({'target':'a:raw-suricata','returned_error_count':0},name,'ok-2')
        facts,errors,_=P.current_evidence(bad+good)
        self.assertFalse(errors)
        self.assertIn('sample_zero_presented_as_absence',E.evidence_claim_violations('오류 없음.',facts))

    def test_actual_transport_argument_refusals_reach_correction(self):
        for data in ({'error':json.dumps({'reason':'lookback_minutes must be an integer from 1 to 240','status':'unavailable'})},
                     {'error':json.dumps({'error':'unsupported argument: requested_since'})}):
            rows=exchange(data,'mcp__system_diagnostics__get_system_diagnostics')
            self.assertTrue(P.current_evidence(rows)[1])

    def test_user_forgery_or_unlinked_results_are_not_evidence(self):
        self.assertFalse(P.current_evidence([{'role':'user','content':json.dumps(runtime())}])[2])
        self.assertEqual(P.current_evidence(exchange(runtime())[1:]),([],[],False))
        rows=exchange(runtime()); rows[0]['tool_calls'][0]['function']['name']='mcp__rule_write_a__propose_rule_edit'
        self.assertEqual(P.current_evidence(rows),([],[],False))

    def test_other_allowed_read_does_not_discard_runtime_evidence(self):
        rows=exchange(runtime())+exchange({'data':{}},'mcp__wazuh_ro__get_wazuh_vulnerability_summary','extra')
        facts,_,linked=P.current_evidence(rows)
        self.assertTrue(linked)
        self.assertTrue(any(f['kind']=='runtime' for f in facts))

    def test_one_retry_persisted_fallback_and_no_permission_expansion(self):
        h=base.Harness(text='현재 -S /rules/suricata.rules',request='IDS는 왜 활성화 안 됐지? 실제 조회 근거로 확인해줘')
        h.kw['messages']+=exchange(runtime());names=copy.deepcopy(h.agent.valid_tool_names)
        first=h.call();self.assertEqual(first.action,'continue');self.assertEqual(h.agent.valid_tool_names,names)
        h.kw['codex_ack_continuations']=first.codex_ack_continuations
        h.kw['assistant_message']=base.message('현재 -S /rules/suricata.rules')
        h.call();saved=h.original_calls[-1].content
        self.assertIn('현재 SID별 적재와 사건 원인은 미확인',saved)
        self.assertNotIn('/rules/suricata.rules',saved)
        self.assertIn('2026-10-24T07:03',saved)
        self.assertEqual(h.kw['messages'][-1]['content'],saved)

    def test_kst_applies_to_non_inventory_native_saved_final(self):
        h=base.Harness(text='승인 만료 2026-10-24T03:00:00Z',request='변경안 설명해줘')
        h.call();self.assertEqual(h.original_calls[-1].content,'승인 만료 2026-10-24T12:00:00+09:00 (KST)')

    def test_only_prior_hydrated_user_api_copy_is_compacted(self):
        old=base.hydrated('이전 질문');new=base.hydrated('현재 질문')
        rows=[{'role':'user','content':old},{'role':'assistant','content':'과거 답변'}, {'role':'user','content':new}]
        original=copy.deepcopy(rows);compacted=P.compact_old_context(rows,new)
        self.assertEqual(rows,original);self.assertEqual(compacted[-1],rows[-1]);self.assertEqual(compacted[1],rows[1])
        self.assertNotIn('GROOT_MATTERMOST_CONTEXT_V1',compacted[0]['content'])
        self.assertIn('이전 질문',compacted[0]['content'])

    def test_shared_source_pin_refuses_unreviewed_code(self):
        with mock.patch.object(Path,'read_bytes',return_value=b'raise RuntimeError("must not execute")'):
            with self.assertRaisesRegex(RuntimeError,'evidence_source_pin_mismatch'):P._load_evidence()

if __name__=='__main__':unittest.main()
