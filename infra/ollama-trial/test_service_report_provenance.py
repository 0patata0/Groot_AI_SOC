"""Proof boundaries shared by both chat paths; no model/network operations."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import harness as h

c = h.CONTRACT
GOOD = '2030-01-02T01:20:22+09:00'
QUERY = '2030-01-02T01:20:35+09:00'

def facts():
    return [{'kind': 'diagnostics', 'target': 'b:backup', 'unit': 'backup.service',
             'diagnostic_mode': 'snapshot', 'observed_at_kst': GOOD,
             'properties': {'Type': 'oneshot', 'ActiveState': 'inactive', 'SubState': 'dead', 'Result': 'success'},
             'process_termination': {'kind': 'exited', 'exit_status': 0, 'signal_number': None},
             'requested_window_total_count': None},
            {'kind': 'diagnostics', 'target': 'b:backup', 'unit': 'backup.service',
             'diagnostic_mode': 'journal_excerpt', 'observed_at_kst': QUERY,
             'journal_valid': True, 'journal_scope': 'all', 'journal_returned_entries': 7,
             'journal_has_more': False, 'journal_response_size_limited': False,
             'requested_window_total_count': None}]

class Provenance(unittest.TestCase):
    def test_earlier_error_sample_sentence_cannot_change_current_exit_statement(self):
        for text in ('조회 구간의 반환 오류 표본은0건(전체 건수 미확인)입니다. 현재 b:backup 프로세스는 정상 종료했습니다.',
                     '조회 구간의 반환 오류 표본은0건(전체 건수 미확인)입니다. b:backup 상태는 Type=oneshot입니다. 애플리케이션 로그는 정상 종료로 관측됩니다.'):
            with self.subTest(text=text):
                self.assertNotIn('diagnostic_snapshot_is_not_functional_health', c.snapshot_health_violations(text, facts()))
                self.assertNotIn('web_snapshot_is_not_application_health', c.snapshot_health_violations(text, facts()))

    def test_historical_exit_same_proposition_remains_unverified(self):
        self.assertTrue(c.snapshot_health_violations('당시 b:backup 프로세스는 정상 종료했습니다.', facts()))

    def test_positive_current_function_health_remains_rejected(self):
        for suffix in ('정상 작동 중입니다.', '정상 운영 중입니다.', '정상입니다.'):
            with self.subTest(suffix=suffix):
                self.assertTrue(c.snapshot_health_violations('b:backup 서비스는 ' + suffix, facts()))

    def test_direct_negative_health_predicate_with_running_particle_is_allowed(self):
        for action in ('작동', '동작', '운영', '가동'):
            with self.subTest(action=action):
                text = '현재 inactive 상태는 서비스의 정상 ' + action + ' 중임을 의미하지 않습니다.'
                self.assertFalse(c.snapshot_health_violations(text, facts()))

    def test_double_negative_and_independent_positive_health_still_fail(self):
        for text in ('서비스가 정상 작동 중임을 의미하지 않는 것은 아닙니다.',
                     '이 관측은 서비스가 정상 작동 중임을 의미하지 않습니다. 서비스는 정상 작동 중입니다.'):
            with self.subTest(text=text):
                self.assertTrue(c.snapshot_health_violations(text, facts()))

    def test_current_property_clock_cannot_use_journal_query_clock(self):
        for text in ('서비스 상태: ActiveState=inactive, SubState=dead(관측 시각 ' + QUERY + ').',
                     '수집 시각(' + QUERY + ') 기준 b:backup 상태는 Type=oneshot, ActiveState=inactive입니다.'):
            with self.subTest(text=text):
                self.assertIn('diagnostic_property_observation_time_mismatch', c.diagnostic_property_claim_violations(text, facts()))

    def test_snapshot_clock_supports_both_positions_and_minute_precision(self):
        for text in ('b:backup ActiveState=inactive(관측 시각 ' + GOOD + ').',
                     '관측 ' + GOOD + ' 기준 b:backup Type=oneshot입니다.',
                     'b:backup ActiveState=inactive(관측 시각 2030-01-02 01:20 KST).'):
            with self.subTest(text=text):
                self.assertNotIn('diagnostic_property_observation_time_mismatch', c.diagnostic_property_claim_violations(text, facts()))

    def test_explicit_second_precision_cannot_round_into_another_second(self):
        rows = facts()
        rows[0]['observed_at_kst'] = '2030-01-02T01:20:22.900000+09:00'
        text = 'b:backup Type=oneshot(관측 시각 2030-01-02T01:20:23+09:00).'
        self.assertIn('diagnostic_property_observation_time_mismatch', c.diagnostic_property_claim_violations(text, rows))

    def test_fractional_precision_is_compared_at_its_declared_digits(self):
        rows = facts()
        rows[0]['observed_at_kst'] = '2030-01-02T01:20:22.123456+09:00'
        self.assertNotIn('diagnostic_property_observation_time_mismatch', c.diagnostic_property_claim_violations(
            'b:backup Type=oneshot(관측 시각 2030-01-02T01:20:22.123+09:00).', rows))
        self.assertIn('diagnostic_property_observation_time_mismatch', c.diagnostic_property_claim_violations(
            'b:backup Type=oneshot(관측 시각 2030-01-02T01:20:22.124+09:00).', rows))

    def test_other_subjects_snapshot_cannot_supply_the_clock(self):
        rows = facts()
        other = copy.deepcopy(rows[0]);other.update(target='c:cache', unit='cache.service', observed_at_kst=QUERY)
        rows.append(other)
        self.assertIn('diagnostic_property_observation_time_mismatch', c.diagnostic_property_claim_violations(
            'b:backup ActiveState=inactive(관측 시각 ' + QUERY + ').', rows))

    def test_one_matching_subject_cannot_license_a_shared_clock_for_two_subjects(self):
        rows = facts()
        other = copy.deepcopy(rows[0]);other.update(target='c:cache', unit='cache.service', observed_at_kst=QUERY)
        rows.append(other)
        self.assertIn('diagnostic_property_observation_time_mismatch', c.diagnostic_property_claim_violations(
            'b:backup와 c:cache Type=oneshot(관측 시각 ' + GOOD + ').', rows))
        self.assertNotIn('diagnostic_property_observation_time_mismatch', c.diagnostic_property_claim_violations(
            'b:backup Type=oneshot(관측 시각 ' + GOOD + '). c:cache Type=oneshot(관측 시각 ' + QUERY + ').', rows))

    def test_separate_journal_and_execution_clocks_are_not_current_property_claims(self):
        for text in ('b:backup ActiveState=inactive. journal 관측 시각 ' + QUERY + '의 반환은7행입니다.',
                     'b:backup Result=success. 메시지의 실행 시각은2030-01-01T04:20:11+09:00입니다.'):
            with self.subTest(text=text):
                self.assertNotIn('diagnostic_property_observation_time_mismatch', c.diagnostic_property_claim_violations(text, facts()))

    def test_returned_count_is_not_a_verified_truncation_limit(self):
        for text in ('journal_scope=all의 반환 표본이 7건으로 제한되어 있어 전체 이력은 미확인입니다.',
                     'b:backup 반환 로그는7행에서 잘렸습니다.'):
            with self.subTest(text=text):
                self.assertIn('diagnostic_journal_return_count_is_not_truncation', c.snapshot_health_violations(text, facts()))

    def test_actual_more_or_size_limit_and_literal_count_scope_are_preserved(self):
        for changes in ({'journal_has_more': True}, {'journal_has_more': True, 'journal_response_size_limited': True}):
            rows = facts();rows[1].update(changes)
            self.assertNotIn('diagnostic_journal_return_count_is_not_truncation', c.snapshot_health_violations(
                '반환 표본이7행으로 제한되어 있습니다.', rows))
        self.assertNotIn('diagnostic_journal_return_count_is_not_truncation', c.snapshot_health_violations(
            '반환 표본은7행이고 요청 한도는50행입니다. 보존 전체는 미확인입니다.', facts()))
        for text in ('반환 표본이7행으로 제한되었다고 단정할 수 없습니다.',
                     '반환 표본이7행으로 제한되지 않았습니다.',
                     '반환 표본이7행으로 제한되었다면 더 조회해야 합니다.'):
            with self.subTest(text=text):
                self.assertNotIn('diagnostic_journal_return_count_is_not_truncation', c.snapshot_health_violations(text, facts()))
        self.assertIn('diagnostic_journal_return_count_is_not_truncation', c.snapshot_health_violations(
            '반환 표본이7행으로 제한되지 않은 것은 아닙니다.', facts()))

    def test_repair_feedback_points_to_the_wrong_property_clock_sentence(self):
        text = '원인은 미확인입니다. b:backup ActiveState=inactive(관측 시각 ' + QUERY + ').'
        rows = c.rejected_claim_sentences(text, facts(), ['diagnostic_property_observation_time_mismatch'])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['sentence'], text.split('. ', 1)[1])

    def test_later_disclaimer_cannot_qualify_a_finite_absence_claim(self):
        for text in ('요청 기간 내 오류가 없었으나 전체 기간의 정상을 보장하지 않습니다.',
                     '표본을 조회했지만 전체 기간 내 오류가 없었습니다.',
                     '오류가 없었습니다. 추가 원인은 미확인입니다.'):
            with self.subTest(text=text):
                self.assertIn('sample_zero_presented_as_absence', c.snapshot_health_violations(text, facts()))

    def test_returned_sample_absence_and_explicit_uncertainty_remain_distinct(self):
        for text in ('반환 오류 표본은 없었으나 전체 기간의 부재는 미확인입니다.',
                     '오류가 없었는지는 미확인입니다.', '오류가 없었다고 단정할 수 없습니다.',
                     '오류 없음(반환 표본 기준), 보존 전체는 미확인입니다.'):
            with self.subTest(text=text):
                self.assertNotIn('sample_zero_presented_as_absence', c.snapshot_health_violations(text, facts()))

    def test_limited_sample_cannot_hide_independent_absence_after_a_join(self):
        text = '반환 오류 표본은 없었으나 전체 기간의 오류가 없었습니다.'
        self.assertIn('sample_zero_presented_as_absence', c.snapshot_health_violations(text, facts()))

    def test_initial_cause_scope_is_explicit_without_rewriting_the_model_report(self):
        context = {'lookup_only': False, 'history_window_origin': 'initial_recent_sample_not_incident_time',
                   'initial_history_window_minutes': 1440}
        model = '**판단**\n원인은 미확인입니다.\nMANAGEMENT_STATUS: needs_review'
        rendered = c.service_lookup_text(model, context)
        self.assertIn('초기 확인 범위', rendered)
        self.assertIn('사용자가 지정한 사건 시각이 아닙니다', rendered)
        self.assertIn('추가 조회의 범위는 아래 실제 근거', rendered)
        self.assertNotIn('구간 밖의 과거 실행·실패는 미확인', rendered)
        self.assertTrue(rendered.endswith(model))
        self.assertEqual(rendered.count('MANAGEMENT_STATUS:'), 1)

    def test_explicit_period_current_only_and_invalid_default_have_no_sample_note(self):
        for context in ({'history_window_origin': 'user_specified_period', 'initial_history_window_minutes': 1440},
                        {'history_window_origin': 'current_observation_only', 'initial_history_window_minutes': None},
                        {'history_window_origin': 'initial_recent_sample_not_incident_time', 'initial_history_window_minutes': True}):
            with self.subTest(context=context):
                self.assertEqual(c.service_lookup_text('unchanged', context), 'unchanged')

    def test_complete_evidence_guard_allows_attached_absence_disclaimer(self):
        for text in ('요청 구간 내 오류 메시지가 없음을 의미하지 않습니다.',
                     '공격이 없다는 뜻이 아닙니다.',
                     '오류가 없었다고 단정할 수 없습니다.'):
            with self.subTest(text=text):
                self.assertNotIn('sample_zero_presented_as_absence',
                    h.EVIDENCE.evidence_claim_violations(text, facts()))

    def test_complete_evidence_guard_retains_independent_and_double_negative_absence(self):
        for text in ('요청 구간 내 오류 메시지가 없음을 의미하지 않는 것은 아닙니다.',
                     '오류가 없음을 의미하지 않습니다. 공격이 없습니다.',
                     '반환 오류 표본은 없었으나 전체 기간의 오류가 없었습니다.'):
            with self.subTest(text=text):
                self.assertIn('sample_zero_presented_as_absence',
                    h.EVIDENCE.evidence_claim_violations(text, facts()))

    def boundary_facts(self):
        rows=facts();rows[1].update(requested_since_kst='2030-01-01T01:20:35+09:00',
                                  requested_until_kst=QUERY)
        return rows

    def test_returned_event_time_cannot_become_a_journal_query_endpoint(self):
        for text in ('journal_scope=all 조회(2030-01-02T00:12:01 이전): 실행 기록 확인.',
                     'journal_scope=all 조회: 2030-01-01T03:00 이후 기록을 확인했습니다.'):
            with self.subTest(text=text):
                self.assertIn('diagnostic_period_coverage_unverified',
                    c.diagnostic_period_claim_violations(text,self.boundary_facts()))

    def test_actual_journal_endpoint_and_separate_event_sample_are_preserved(self):
        for text in ('journal_scope=all 조회(2030-01-02T01:20:35 이전): 반환 표본입니다.',
                     'journal_scope=all 조회: 2030-01-01T01:20부터 반환 표본을 확인했습니다.',
                     'journal_scope=all 반환 표본은2030-01-02T00:12:01 이전 기록입니다.'):
            with self.subTest(text=text):
                self.assertNotIn('diagnostic_period_coverage_unverified',
                    c.diagnostic_period_claim_violations(text,self.boundary_facts()))

    def test_query_boundary_uncertainty_does_not_license_a_double_negative(self):
        prefix='journal_scope=all 조회(2030-01-02T00:12:01 이전'
        self.assertNotIn('diagnostic_period_coverage_unverified',c.diagnostic_period_claim_violations(
            prefix+'인지는 미확인입니다.',self.boundary_facts()))
        self.assertIn('diagnostic_period_coverage_unverified',c.diagnostic_period_claim_violations(
            prefix+'임을 의미하지 않는 것은 아닙니다.',self.boundary_facts()))


if __name__ == '__main__':
    unittest.main()
