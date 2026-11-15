"""Claims, uncertainty and future checks stay tied to their own proposition.

Run with SOC_MODALITY_ROOT pointing at an isolated source tree. These cases
are development counterexamples; no model, network or production changes.
"""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(os.environ.get('SOC_MODALITY_ROOT', Path(__file__).resolve().parents[3])).resolve()
sys.path[:0] = [str(ROOT / 'infra/hermes'), str(ROOT / 'infra/ollama-trial')]
import soc_management_run as gate
import chat_contract as contract

ZERO = 'sample_zero_presented_as_absence'
WAF = 'unobserved_event_source:modsecurity'
IDS = 'unobserved_event_source:suricata'
FACTS = [{'kind': 'events', 'source': 'suricata', 'returned_count': 0,
          'indexed_window_total_count': None}]


def issues(text, facts=FACTS):
    return set(gate.evidence_claim_violations(text, facts))


class AttachedModality(unittest.TestCase):
    def test_live_absence_complement_is_not_a_claim_of_absence(self):
        text = ('이는 해당 구간 전체에 경보가 없다는 것을 증명하지 않으며, '
                '수집 또는 색인 지연 가능성을 배제할 수 없습니다.')
        self.assertNotIn(ZERO, issues(text))

    def test_proof_verbs_share_the_same_negation_scope(self):
        for verb in ('증명', '입증', '보장', '단정', '판단', '확정'):
            for ending in ('하지 않습니다', '하지는 않습니다', '하지도 않습니다', '할 수 없습니다', '하지 못했습니다'):
                with self.subTest(verb=verb, ending=ending):
                    self.assertNotIn(ZERO, issues('경보가 없다는 것을 ' + verb + ending + '.'))

    def test_positive_proof_does_not_withdraw_an_absence_claim(self):
        for ending in ('증명했습니다', '입증했습니다', '보장합니다', '단정합니다'):
            with self.subTest(ending=ending):
                self.assertIn(ZERO, issues('경보가 없다는 것을 ' + ending + '.'))

    def test_conditional_is_not_the_current_state(self):
        for text in ('경보가 없다면 다음 구간도 조회합니다.', '경보가 없으면 추가로 확인합니다.',
                     '경보 0건이면 수집 상태를 확인해야 합니다.'):
            with self.subTest(text=text):
                self.assertNotIn(ZERO, issues(text))

    def test_consequences_of_a_real_absence_remain_claims(self):
        for text in ('경보가 없으므로 정상입니다.', '경보가 없어 추가 확인이 필요합니다.',
                     '경보가 없고 정상입니다.', '경보가 없으며 원인은 미상입니다.'):
            with self.subTest(text=text):
                self.assertIn(ZERO, issues(text))

    def test_disclaimer_in_another_sentence_does_not_excuse_an_assertion(self):
        for text in ('경보가 없다는 것을 증명하지 못했습니다. 공격은 없습니다.',
                     '위험은 미확인입니다. 공격 경보가 없었음.',
                     '반환 표본 0건입니다. 경보는 없었습니다.'):
            with self.subTest(text=text):
                self.assertIn(ZERO, issues(text))

    def test_prior_sample_qualifier_is_not_reused_by_another_proposition(self):
        for text in ('반환 표본 0건이며 현재 공격은 없습니다.',
                     '검색 결과 경보 0건이고 전체 공격은 없습니다.',
                     '표본만 확인했지만 실제 공격은 없었습니다.'):
            with self.subTest(text=text):
                self.assertIn(ZERO, issues(text))

    def test_double_negation_does_not_become_an_uncertainty_exemption(self):
        for text in ('경보가 없다는 것을 증명하지 않은 건 아닙니다.',
                     '경보가 없다는 것을 보장할 수 없다는 것은 아닙니다.'):
            with self.subTest(text=text):
                self.assertIn(ZERO, issues(text))

    def test_epistemic_failure_and_finding_nothing_are_different(self):
        for text in ('경보 여부는 판단할 수 없습니다.', '공격 가능성을 배제할 수 없음'):
            self.assertNotIn(ZERO, issues(text))
        for text in ('공격을 발견할 수 없음', '경보를 찾을 수 없었습니다'):
            self.assertIn(ZERO, issues(text))


class SensorBinding(unittest.TestCase):
    def test_live_plan_does_not_borrow_an_earlier_count(self):
        text = ('Suricata 반환 표본 0건입니다. 목적지 DNS 서버와의 상호작용에 대한 '
                '추가적인 WAF 또는 Wazuh 경보 확인이 필요합니다. 위험 해소 근거는 부족합니다.')
        self.assertNotIn(WAF, issues(text))

    def test_table_future_cell_is_not_the_rows_observed_measurement(self):
        text = ('| 대상 | 결과 | 미확인·다음 조치 |\n| --- | --- | --- |\n'
                '| Suricata 경보 | 반환 표본 0건 | WAF 또는 Wazuh 경보 추가 확인 필요 |')
        self.assertNotIn(WAF, issues(text))

    def test_same_sentence_other_subject_does_not_borrow_zero(self):
        self.assertNotIn(WAF, issues('Suricata 경보 반환 표본 0건이며 WAF 경보는 추가 확인이 필요합니다.'))

    def test_an_unread_sources_own_count_is_still_rejected(self):
        for text in ('Suricata 반환 표본 0건, WAF 경보 0건입니다.',
                     '| Suricata 경보 | 0건 | WAF 경보 3건 |',
                     'WAF 경보 0건입니다. 다음 조회가 필요합니다.'):
            with self.subTest(text=text):
                self.assertIn(WAF, issues(text))

    def test_an_earlier_plan_does_not_hide_a_later_actual_count(self):
        for text in ('WAF 경보 추가 확인이 필요하지만 현재 0건입니다.',
                     'WAF 경보 조회 예정이며 이미 3건을 확인했습니다.'):
            with self.subTest(text=text):
                self.assertIn(WAF, issues(text))

    def test_real_absence_and_past_detection_require_the_named_read(self):
        for text in ('WAF 경보가 없었습니다.', 'WAF 탐지 없음.', 'WAF 스캔 0건 확인했습니다.',
                     'WAF 경보를 확인했습니다.', 'ModSecurity 이벤트를 관측했습니다.'):
            with self.subTest(text=text):
                self.assertIn(WAF, issues(text))

    def test_configuration_statement_is_separate_from_event_count(self):
        self.assertNotIn(WAF, issues('WAF 탐지 모드와 규칙 설정은 변경 없음.'))
        self.assertIn(WAF, issues('WAF 탐지 모드는 유지, 경보는 0건입니다.'))

    def test_shared_predicate_requires_both_sources(self):
        for text in ('WAF와 IDS 경보 0건입니다.', 'ModSecurity/Suricata 경보가 없었습니다.'):
            with self.subTest(text=text):
                self.assertIn(WAF, issues(text))
                self.assertIn(IDS, issues(text, []))

    def test_citation_spelling_is_not_a_sensor_mention(self):
        for text in ('sensor_rule_ids 비어 있음', 'waf_action 필드 이벤트 10건',
                     'mcp__security_events__search_suricata_alerts'):
            with self.subTest(text=text):
                self.assertNotIn(WAF, issues(text, []))
                self.assertNotIn(IDS, issues(text, []))

    def test_future_counted_read_is_not_a_completed_query(self):
        for text in ('WAF 경보 3건을 조회할 예정입니다.', 'WAF 경보 3건을 확인해야 합니다.',
                     'WAF 경보 3건이면 추가 조사합니다.'):
            with self.subTest(text=text):
                self.assertNotIn(WAF, issues(text))
        self.assertIn(WAF, issues('WAF 경보 3건을 조회했습니다. 추가 확인 예정입니다.'))

    def test_never_read_and_no_events_are_different(self):
        for text in ('WAF 경보는 미조회이며 건수를 알 수 없습니다.',
                     'WAF 경보 확인 근거가 없습니다.', 'WAF 경보가 없다는 것을 입증하지 못했습니다.'):
            self.assertNotIn(WAF, issues(text))
        self.assertIn(WAF, issues('WAF 경보가 없습니다. 조회 근거는 미확인입니다.'))


class CommonContract(unittest.TestCase):
    def completed_sample(self):
        raw = json.dumps({'source': 'suricata', 'returned_count': 0,
            'indexed_window_total_count': None, 'alerts': []})
        return {'server': 'security-events', 'name': 'search_suricata_alerts',
                'arguments': {'lookback_minutes': 15, 'limit': 50}, 'result': raw,
                'result_sha256': hashlib.sha256(raw.encode()).hexdigest(), 'is_error': False}

    def report(self):
        return ('반환 표본 0건이며 전체 건수와 위험은 미확인입니다.\nINCIDENT_DISPOSITION: ' +
            json.dumps({'assessment': 'unresolved', 'basis': '현재 반환 표본이 0건이며 전체 건수와 실제 위험은 아직 미확인입니다.',
                'evidence_tools': ['mcp__security_events__search_suricata_alerts']}, ensure_ascii=False))

    def test_optional_status_is_validated_without_selecting_its_value(self):
        import harness
        q = 'DNS 경보 조사해줘'
        body = self.report()
        for status in (None, 'needs_review', 'monitor', 'awaiting_approval'):
            text = body if status is None else body + '\nMANAGEMENT_STATUS: ' + status
            with self.subTest(status=status):
                self.assertNotIn('invalid_management_status_format', harness.violations(q, text, [self.completed_sample()]))
        self.assertIn('invalid_management_status_format', harness.violations(q,
            body + '\nMANAGEMENT_STATUS: unresolved', [self.completed_sample()]))

    def test_chat_repair_reuses_disposition_skill_without_a_wrong_nonce_phase(self):
        import harness
        instruction = harness.incident_judgment_instruction('DNS 경보 조사해줘',
            self.report() + '\nMANAGEMENT_STATUS: unresolved', [self.completed_sample()], ['invalid_management_status_format'])
        self.assertIn('## 판단 메타데이터 형식', instruction)
        self.assertIn('status_format_problem', instruction)
        self.assertNotIn('request_nonce', instruction)
        self.assertNotIn('## 관리 상태 형식 정정', instruction)

    def test_first_named_sensor_does_not_expand_before_its_read(self):
        import harness
        for sensor, tool in (('WAF', 'modsecurity'), ('IDS', 'suricata'), ('Wazuh', 'wazuh')):
            q = sensor + ' 최근 경보 조사해줘. 대응이 필요한지 근거와 한계를 같이 알려줘.'
            with self.subTest(sensor=sensor):
                self.assertEqual(harness.incident_selection_scope(q, []),
                    {'mcp__security_events__search_' + tool + '_alerts'})
        self.assertEqual(harness.incident_selection_scope('WAF와 IDS 경보 조사해줘', []),
            {'mcp__security_events__search_modsecurity_alerts', 'mcp__security_events__search_suricata_alerts'})

    def test_first_scope_keeps_reference_mixed_and_later_reads(self):
        import harness
        from unittest.mock import patch
        q = 'WAF 최근 경보 조사해줘'
        with patch.object(harness, 'incident_evidence_gap', return_value=True):
            self.assertIn('mcp__security_events__get_web_service_target',
                harness.incident_selection_scope(q, [self.completed_sample()]))
            self.assertIn('mcp__security_events__get_web_service_target',
                harness.incident_selection_scope('WAF 경보와 systemd 상태를 조사해줘', []))
            with patch.object(harness, 'card_evidence_gaps', return_value=['suricata']):
                self.assertEqual(harness.incident_selection_scope(q, [], reference={'kind': 'evidence'}),
                    {harness.EVIDENCE.BUNDLE_TOOL, 'mcp__security_events__search_suricata_alerts'})
        self.assertIsNone(harness.incident_selection_scope('WAF 규칙 목록 보여줘', []))

    def test_diagnostic_compatibility_uses_the_public_modality(self):
        for text in ('이라는 것을 증명하지 않습니다.', '이면 추가 조사합니다.'):
            with self.subTest(text=text):
                self.assertTrue(contract._claim_is_unasserted(text))
        for text in ('입니다.', '이며 현재 정상입니다.', '없습니다.'):
            self.assertFalse(contract._claim_is_unasserted(text))
        self.assertEqual(contract.claim_modality('를 조회할 예정입니다.'), 'planned_check')
        self.assertFalse(contract._claim_is_unasserted('를 조회할 예정입니다.'))

    def test_finite_sentence_boundary_stops_uncertainty_scope(self):
        for text in ('입니다. 확인이 필요합니다.', '이며 추가 확인이 필요합니다.', '입니다; 판단할 수 없습니다.'):
            self.assertFalse(contract._claim_is_unasserted(text))

    def test_native_and_sdk_read_the_same_pinned_gate(self):
        import harness
        import hashlib
        expected = hashlib.sha256((ROOT / 'infra/hermes/soc_management_run.py').read_bytes()).hexdigest()
        self.assertEqual(harness.SHARED.EVIDENCE_SOURCE_SHA256, expected)
        for text in ('WAF 경보 0건입니다.', 'Suricata 경보가 없다는 것을 증명하지 않습니다.'):
            self.assertEqual(harness.EVIDENCE.evidence_claim_violations(text, FACTS),
                             gate.evidence_claim_violations(text, FACTS))

    def test_no_privilege_or_disposition_is_synthesized(self):
        self.assertFalse(gate.allowed('mcp__resp__block_ip', 'verify'))
        self.assertFalse(gate.allowed('mcp__rule_write_b__propose_service_action', 'verify'))
        self.assertEqual(gate.parse_incident_disposition('경보는 미확인입니다.', set())[1],
                         'incident_disposition_missing')


if __name__ == '__main__':
    unittest.main(verbosity=2)
