"""Observed lifecycle roles, missing history and report/audit separation."""
import copy
import json
import unittest
import soc_management_run as m
from test_soc_management_operation_time import receipt

def timeline(verified=False):
    return receipt(workflow_created_at=1793707800,
        initial_apply_observed_at=1793707803 if verified else None,
        initial_apply_observation_sha256='d'*64 if verified else None)

class Timeline(unittest.TestCase):
    def test_unrecorded_application_is_not_expiry_registration_or_ttl_subtraction(self):
        facts=[m.containment_clock(timeline())]
        for text in ('최초 차단 시각 `21:20:18+09:00`',
                     '최초 적용 확인 시간: 2026-11-03T21:10:00+09:00',
                     '| 최초 차단 시각 21:20:18 | 나머지는 미확인 |'):
            self.assertIn('containment_initial_application_time_unverified',m.evidence_claim_violations(text,facts))
        for text in ('요청 등록 시각 21:10:00, 최초 적용 확인 시각 미확인',
                     '만료시각: 21:20:18', '최초 차단 시각 21:20:18은 잘못된 표기입니다.',
                     '예시: 최초 차단 시각 21:20:18', '> 최초 차단 시각 21:20:18',
                     '```log\n최초 차단 시각 21:20:18\n```'):
            self.assertEqual(m.containment_time_violations(text,facts),[],text)

    def test_recorded_application_confirmation_and_registration_cannot_be_swapped(self):
        facts=[m.containment_clock(timeline(True))]
        self.assertEqual(m.containment_time_violations('요청 등록 시각 21:10:00; 최초 적용 확인 시각 21:10:03',facts),[])
        for text in ('요청 등록 시각 21:10:03','최초 적용 확인 시각 21:10:00',
                     '최초 적용 확인 시각 2026-11-04T21:10:03+09:00'):
            self.assertIn('containment_time_role_mismatch',m.containment_time_violations(text,facts))
        self.assertIn('containment_time_role_requires_kst',m.containment_time_violations('최초 적용 확인 시각 21:10:03+00:00',facts))

    def test_multiple_requests_require_identity(self):
        facts=[m.containment_clock(timeline()),m.containment_clock({**timeline(True),'request_id':'c'*32})]
        self.assertEqual(m.containment_time_violations('최초 적용 확인 시각 21:10:03',facts),[])
        self.assertIn('containment_initial_application_time_unverified',m.containment_time_violations('a'*32+' 최초 적용 확인 시각 21:10:03',facts))

    def test_unverified_or_inconsistent_confirmation_does_not_become_a_fact(self):
        for changes in ({'initial_apply_observation_sha256':None},{'initial_apply_observed_at':1793707799},
                        {'initial_apply_observed_at':True}):
            fact=m.containment_clock({**timeline(True),**changes})
            self.assertFalse(fact['initial_apply_time_verified'])
            self.assertNotIn('initial_apply_observed_at',fact['times'])

    def test_model_projection_and_table_keep_unknown_without_editing_audit(self):
        original=timeline();before=copy.deepcopy(original);raw=json.dumps({'result':json.dumps(original)})
        view=json.loads(json.loads(m.operation_time_view(raw))['result'])
        self.assertEqual(view['workflow_created_at_kst'],'2026-11-03T21:10:00+09:00')
        self.assertIsNone(view['initial_apply_observed_at_kst'])
        self.assertFalse(view['containment_time_semantics']['initial_apply_time_verified'])
        self.assertEqual(original,before)
        table=m.factual_review_report([m.containment_clock(original)])
        self.assertIn('요청 등록',table);self.assertIn('최초 적용 확인 시각 미기록·미확인',table)
        self.assertNotIn('역산한 실제 차단',table)
        self.assertEqual(m.evidence_claim_violations(table,[m.containment_clock(original)]),[])

if __name__=='__main__':unittest.main()
