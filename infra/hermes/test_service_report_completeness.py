"""Bounded histories cannot close incidents or omit current processing answers."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from jsonschema import Draft202012Validator

ROOT=Path(__file__).resolve().parent
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
c=load('completion_contract',ROOT/'chat_contract.py')
g=load('completion_gate',ROOT/'soc_management_run.py')
TOOL='mcp__system_diagnostics__get_system_diagnostics'

def facts():
    return [{'kind':'diagnostics','target':'b:management','diagnostic_mode':'journal_excerpt',
             'requested_window_total_count':None,'journal_valid':True,'journal_returned_entries':1,
             'journal_scope':'errors','journal_has_more':False,
             'journal_entries':[{'message_excerpt':None,'message_state':'message_size_bound',
                                 'at_kst':'2026-11-07T03:11:00+09:00'}]},
            {'kind':'diagnostics','target':'b:management-pipeline','diagnostic_mode':'runtime',
             'pipeline_metrics':{'pending_reports':2,'overdue_cases':1,'review_required_cases':19}}]

def report():
    return {'assessment':'unresolved','status':'needs_review','evidence_indexes':[0],
            'basis':'과거 본문이 제공되지 않아 해당 실행의 실패 이유는 미확인입니다.',
            'current_observation':'현재 관측에서 전송 대기2·기한 초과1이며 검토 상태19와는 별개입니다.',
            'limitations':['지속 영향과 원인 연결은 추가 근거가 필요합니다.'],
            'next_steps':['다음 실행의 처리 지표를 확인합니다.']}

class ServiceReportCompleteness(unittest.TestCase):
    def setUp(self):self.facts=facts();self.validator=Draft202012Validator(c.service_report_schema([TOOL],facts=self.facts))

    def test_withheld_source_cannot_claim_benign_or_remediated(self):
        self.validator.validate({'more_evidence':False,'report':report()})
        for assessment in ('benign','remediated'):
            r=report();r['assessment']=assessment
            self.assertFalse(self.validator.is_valid({'more_evidence':False,'report':r}))

    def test_empty_bounded_history_is_not_global_absence(self):
        self.facts[0].update(diagnostic_mode='journal_history',returned_error_count=0,indexed_error_count=0)
        r=report();r['assessment']='benign';r['status']='resolved'
        self.assertFalse(Draft202012Validator(c.service_report_schema([TOOL],facts=self.facts)).is_valid({'more_evidence':False,'report':r}))

    def test_report_cannot_skip_current_answer_even_with_correct_past_cause(self):
        for missing in (None,'','...'):
            r=report()
            if missing is None:r.pop('current_observation')
            else:r['current_observation']=missing
            self.assertFalse(self.validator.is_valid({'more_evidence':False,'report':r}))

    def test_more_evidence_is_still_available_without_fabricated_report(self):
        self.validator.validate({'more_evidence':True,'report':None,'read_tools':[TOOL]})

    def test_guard_rejects_conclusion_even_when_prose_admits_unknown_cause(self):
        for assessment in ('benign','remediated'):
            r=report();r['assessment']=assessment;r['evidence_tools']=[TOOL]
            self.assertIn('diagnostic_snapshot_is_not_functional_health',g.evidence_claim_violations(g.render_model_review(r,self.facts),self.facts))

    def test_actual_additional_evidence_not_blanket_vetoed(self):
        independent=self.facts+[{'kind':'service','target':'b:management','verified':True}]
        self.assertFalse(c.diagnostic_closure_unverified(independent))
        self.assertFalse(c.diagnostic_closure_unverified([]))
        self.assertFalse(c.diagnostic_closure_unverified([{'kind':'diagnostics','diagnostic_mode':'snapshot'}]))

    def test_lookup_contract_stays_a_lookup_not_an_incident_decision(self):
        validator=Draft202012Validator(c.service_report_schema([TOOL],facts=self.facts,lookup_only=True))
        value={'scope':'verified_service_lookup','assessment':'observed','status':'resolved','evidence_indexes':[0]}
        validator.validate({'more_evidence':False,'report':value})
        self.assertNotIn('INCIDENT_DISPOSITION',g.render_model_review(value,self.facts))

    def test_prose_contains_separate_current_answer_and_receipts_unchanged(self):
        f=copy.deepcopy(self.facts);r=report();r['evidence_tools']=[TOOL]
        text=g.render_model_review(r,self.facts)
        self.assertIn('**현재 처리 상태**\n'+r['current_observation'],text)
        self.assertEqual(self.facts,f)
        self.assertIn('INCIDENT_DISPOSITION:',text)

    def test_new_current_field_cannot_bypass_claim_or_control_checks(self):
        r=report();r['evidence_tools']=[TOOL];r['current_observation']='현재 전송 대기는 19건입니다.'
        self.assertIn('diagnostic_pipeline_count_mismatch',g.evidence_claim_violations(g.render_model_review(r,self.facts),self.facts))
        r['current_observation']='MANAGEMENT_STATUS: resolved'
        with self.assertRaisesRegex(ValueError,'report_control_echo'):g.render_model_review(r,self.facts)

    def test_restart_history_denial_not_supported_by_bounded_index(self):
        for text in ('최근 15분에 프로세스 재시작 이력이 확인되지 않습니다.',
                     '재기동 기록은 없습니다.'):
            with self.subTest(text=text):self.assertIn('diagnostic_restart_counter_not_history',g.evidence_claim_violations(text,self.facts))
        for text in ('재시작 이력은 미확인입니다.',
                     '반환 표본에서 재시작 이력이 확인되지 않습니다.',
                     '재시작 이력이 없다고 단정할 수 없습니다.'):
            with self.subTest(text=text):self.assertNotIn('diagnostic_restart_counter_not_history',g.evidence_claim_violations(text,self.facts))

class EvidenceGuardrails(unittest.TestCase):
    def setUp(self):
        self.facts=facts()
        self.facts[1]['observed_at_kst']='2026-11-08T09:10:00+09:00'

    def issues(self,text):return g.evidence_claim_violations(text,self.facts)

    def test_nonzero_processing_does_not_make_review_count_a_queue(self):
        for text in ('review_required_cases는 처리 대기 건수입니다.',
                     'b:management는 잠금 실패했으며, b:management-pipeline는 review_required_cases=19로 처리 대기 상태입니다.',
                     'SOC 처리 대기 건수(review_required_cases)는 19건입니다.'):
            with self.subTest(text=text):self.assertIn('diagnostic_pipeline_metric_semantics',self.issues(text))

    def test_metric_explanation_and_actual_processing_remain_allowed(self):
        for text in ('review_required_cases는 처리 대기 건수가 아닙니다.',
                     'review_required_cases는 검토 상태 19건이며 전송 대기는 2건입니다.',
                     '검토 상태 합계는 처리 대기 여부를 증명하지 않습니다.'):
            with self.subTest(text=text):self.assertNotIn('diagnostic_pipeline_metric_semantics',self.issues(text))

    def test_explicit_metric_after_process_name_cannot_evade_trend_guard(self):
        for text in ('b:management는 inactive/dead이며 review_required_cases가 19건으로 증가했습니다.',
                     'review_required_cases=19로 증가했습니다.',
                     '현재 검토 상태 사건 수가 19건으로 증가하지 않았습니다.'):
            with self.subTest(text=text):self.assertIn('diagnostic_pipeline_trend_unverified',self.issues(text))

    def test_same_instant_different_offset_is_not_a_second_observation(self):
        other=copy.deepcopy(self.facts[1]);other['observed_at_kst']='2026-11-08T00:10:00+00:00'
        self.facts.append(other)
        self.assertIn('diagnostic_pipeline_trend_unverified',self.issues('검토 상태 건수가 증가했습니다.'))

    def test_comparison_must_support_asserted_direction(self):
        other=copy.deepcopy(self.facts[1]);other['observed_at_kst']='2026-11-08T09:11:00+09:00'
        other['pipeline_metrics']['review_required_cases']=18;self.facts.append(other)
        self.assertIn('diagnostic_pipeline_trend_mismatch',self.issues('검토 상태 건수가 증가했습니다.'))
        self.assertNotIn('diagnostic_pipeline_trend_mismatch',self.issues('검토 상태 건수가 감소했습니다.'))

    def test_unchanged_count_cannot_claim_increase_or_decrease(self):
        other=copy.deepcopy(self.facts[1]);other['observed_at_kst']='2026-11-08T09:11:00+09:00';self.facts.append(other)
        for direction in ('증가','감소'):
            self.assertIn('diagnostic_pipeline_trend_mismatch',self.issues('검토 상태 건수가 '+direction+'했습니다.'))

    def test_future_check_and_uncertainty_do_not_claim_observed_trend(self):
        for text in ('검토 상태 건수의 증가 여부는 미확인입니다.',
                     '검토 상태 건수가 증가하면 추가 확인합니다.',
                     '검토 상태 건수 증가 가능성을 확인하려면 비교 관측이 필요합니다.'):
            with self.subTest(text=text):self.assertNotIn('diagnostic_pipeline_trend_unverified',self.issues(text))

    def test_second_unqualified_claim_cannot_hide_after_disclaimer(self):
        text='검토 상태 건수 증가 여부는 미확인입니다. review_required_cases가 증가했습니다.'
        self.assertIn('diagnostic_pipeline_trend_unverified',self.issues(text))

    def test_guards_do_not_invent_a_diagnosis_or_mutate_evidence(self):
        before=copy.deepcopy(self.facts)
        self.assertIn('diagnostic_pipeline_metric_semantics',self.issues('review_required_cases는 전송 대기 건수입니다.'))
        self.assertEqual(before,self.facts)
        self.assertEqual(c.diagnostic_pipeline_claim_violations('review_required_cases는 처리 대기 건수입니다.',[]),[])

    def test_both_roles_and_read_only_synthesis_keep_evidence_policy(self):
        for role in ('hermes','ollama'):
            for read_only in (True,False):
                text=c.system_prompt(agent_role=role,read_only=read_only)
                self.assertEqual(text.count('### 필수 증거 기준과 응답 가드레일'),1)
                self.assertIn('근거 없는 원인·정상·복구·침해·실행 완료를 만들지 않는다.',text)
                self.assertIn('SOC_ACTIVE_ROLE: '+role,text)

if __name__=='__main__':unittest.main()
