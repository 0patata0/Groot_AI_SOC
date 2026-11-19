"""Equivalent property syntax and bounded occurrence claims, without I/O."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
import harness as h
c=h.CONTRACT

def facts():
    return [{'kind':'diagnostics','target':'b:backup','unit':'backup.service',
        'diagnostic_mode':'snapshot','observed_at_kst':'2030-01-02T03:04:05+09:00',
        'properties':{'Type':'oneshot','ActiveState':'inactive','SubState':'dead','UnitFileState':'static'},
        'requested_window_total_count':None}]

class ClaimForms(unittest.TestCase):
    def test_labelled_enablement_enum_is_checked_as_a_property(self):
        for label in ('자동 시작 설정(enabled)','자동시작 설정은 enabled',
                      '부팅 시 자동 실행 설정(enabled)','자동 시작(enabled-runtime)'):
            with self.subTest(label=label):
                self.assertIn('diagnostic_property_value_mismatch',
                    c.diagnostic_property_claim_violations('b:backup '+label+' 상태를 유지합니다.',facts()))

    def test_static_is_not_rewritten_to_disabled_or_enabled(self):
        self.assertFalse(c.diagnostic_property_claim_violations('b:backup 자동 시작 설정(static)으로 관측했습니다.',facts()))
        self.assertIn('diagnostic_property_value_mismatch',
            c.diagnostic_property_claim_violations('b:backup 자동 시작 설정(disabled)입니다.',facts()))

    def test_unknown_field_and_another_subject_cannot_license_enablement(self):
        rows=facts();rows[0]['properties'].pop('UnitFileState')
        self.assertIn('diagnostic_property_value_unverified',
            c.diagnostic_property_claim_violations('b:backup 자동 시작 설정(enabled)입니다.',rows))
        rows=facts();other=copy.deepcopy(rows[0]);other['target']='c:cache';other['unit']='cache.service'
        other['properties']['UnitFileState']='enabled';rows.append(other)
        self.assertIn('diagnostic_property_value_mismatch',
            c.diagnostic_property_claim_violations('b:backup 자동 시작 설정(enabled)입니다.',rows))

    def test_actual_matching_enablement_and_unrelated_enabled_word_remain_valid(self):
        rows=facts();rows[0]['properties']['UnitFileState']='enabled'
        self.assertFalse(c.diagnostic_property_claim_violations('b:backup 자동 시작 설정(enabled)입니다.',rows))
        self.assertFalse(c.diagnostic_property_claim_violations('보고 정책의 표 출력 옵션은 enabled입니다.',facts()))

    def test_korean_particle_does_not_hide_a_property_or_split_another_identifier(self):
        self.assertIn('diagnostic_property_value_mismatch',
            c.diagnostic_property_claim_violations('현재UnitFileState=enabled입니다.',facts()))
        self.assertFalse(c.diagnostic_property_claim_violations('다른 식별자 SomeUnitFileState=enabled입니다.',facts()))

    def test_attached_uncertainty_denial_and_double_negation_are_separate(self):
        for suffix in ('인지 미확인입니다.','을 의미하지 않습니다.','임을 의미하지 않습니다.'):
            with self.subTest(suffix=suffix):
                self.assertNotIn('diagnostic_property_value_mismatch',
                    c.diagnostic_property_claim_violations('자동 시작 설정(enabled)'+suffix,facts()))
        self.assertIn('diagnostic_property_value_mismatch',c.diagnostic_property_claim_violations(
            '자동 시작 설정(enabled)임을 의미하지 않는 것은 아닙니다.',facts()))

    def test_history_and_current_enablement_are_not_mixed(self):
        rows=facts();old=copy.deepcopy(rows[0]);old['diagnostic_mode']='journal_history'
        old['properties']['UnitFileState']='enabled';rows.append(old)
        self.assertNotIn('diagnostic_property_value_mismatch',c.diagnostic_property_claim_violations(
            '과거 b:backup 자동 시작 설정(enabled)이었습니다.',rows))
        self.assertIn('diagnostic_property_value_mismatch',c.diagnostic_property_claim_violations(
            '현재 b:backup 자동 시작 설정(enabled)입니다.',rows))

    def test_labelled_property_uses_its_own_observation_clock(self):
        self.assertNotIn('diagnostic_property_observation_time_mismatch',c.diagnostic_property_claim_violations(
            'b:backup 자동 시작 설정(static), 관측 시각 2030-01-02T03:04:05+09:00.',facts()))
        self.assertIn('diagnostic_property_observation_time_mismatch',c.diagnostic_property_claim_violations(
            'b:backup 자동 시작 설정(static), 관측 시각 2030-01-02T03:04:15+09:00.',facts()))

    def test_universal_occurrence_is_not_proved_by_a_sample(self):
        for text in ('매 실행마다 status=ok를 반환했습니다.','각 기동은 실패했습니다.',
                     '모든 주기는 정상 완료되었습니다.'):
            with self.subTest(text=text):
                self.assertIn('diagnostic_period_coverage_unverified',c.diagnostic_period_claim_violations(text,facts()))

    def test_bounded_sample_and_explicit_unknown_do_not_claim_all_occurrences(self):
        for text in ('반환 JSON 표본의 각 실행은 status=ok로 기록돼 있습니다.',
                     '매 실행마다 정상인지 미확인입니다.',
                     '매 실행마다 정상 종료 여부는 미확인입니다.',
                     '매 실행마다 정상임을 보장하지 않습니다.'):
            with self.subTest(text=text):
                self.assertNotIn('diagnostic_period_coverage_unverified',c.diagnostic_period_claim_violations(text,facts()))

    def test_sample_elsewhere_and_double_negative_cannot_excuse_universal_claim(self):
        for text in ('반환 표본은50건이고 매 실행마다 정상으로 종료됐습니다.',
                     '매 실행마다 정상임을 보장하지 않는 것은 아닙니다.'):
            with self.subTest(text=text):
                self.assertIn('diagnostic_period_coverage_unverified',c.diagnostic_period_claim_violations(text,facts()))

    def test_last_resort_removes_only_the_false_enum_sentence_without_replacing_judgment(self):
        review={'assessment':'unresolved','status':'needs_review',
                'basis':'실패 원인은 현재 제공된 조회 근거에서 확인하지 못했습니다.',
                'current_observation':'b:backup 자동 시작 설정(enabled)입니다. 현재 Type=oneshot입니다.',
                'limitations':['전체 기능과 과거 원인은 미확인입니다.'],'next_steps':[],
                'evidence_tools':['mcp__system_diagnostics__get_system_diagnostics']}
        original=copy.deepcopy(review)
        revised,count=c.prune_rejected_review(review,facts(),['diagnostic_property_value_mismatch'])
        self.assertIsNotNone(revised)
        self.assertEqual(count,1)
        self.assertEqual(review,original)
        self.assertNotIn('enabled',revised['current_observation'])
        self.assertEqual(revised['assessment'],review['assessment'])
        self.assertEqual(revised['status'],review['status'])
        self.assertEqual(revised['basis'],review['basis'])
        self.assertFalse(c.diagnostic_property_claim_violations(revised['current_observation'],facts()))

if __name__=='__main__':unittest.main()
