"""Source tampering, missing evidence and harmful certainty regressions."""
from copy import deepcopy
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from refine_v4_observation_targets import (ads_answer, lds_answer, kev_answer, verify_lds,
                                         audit_field, audit_time, explicit_kst, sha, verify_kev)


class TargetTests(unittest.TestCase):
    def ads(self):
        a = {'timestamp_kst': '2022-01-01T09:00:00+09:00', 'source_id': 'a', 'agent_id': '1',
             'rule_id': '10', 'level': 10, 'description': 'sensor text', 'groups': ['attack'],
             'mitre_ids': ['T1055'], 'phase_window': 'normal'}
        b = {**a, 'source_id': 'b', 'level': 5, 'mitre_ids': []}
        return {'archive_case_id': 'case', 'evidence': [a, b]}

    def test_equal_timestamp_is_not_ordered(self):
        answer, facts = ads_answer(self.ads())
        self.assertTrue(facts['equal_displayed_time'])
        self.assertIn('선후관계를 정할 수 없습니다', answer)
        self.assertIn('입력의 나열 순서', answer)

    def test_actual_order_does_not_imply_common_actor(self):
        p = self.ads();p['evidence'][1]['timestamp_kst'] = '2022-01-01T09:00:01+09:00'
        answer, facts = ads_answer(p)
        self.assertFalse(facts['equal_displayed_time'])
        self.assertIn('같은 행위자', answer)
        self.assertIn('증명하지는 않습니다', answer)

    def test_sensor_technique_and_normal_context_scopes_preserved(self):
        answer, _ = ads_answer(self.ads())
        for text in ('T1055', 'mitre_ids=[]', '경보 주석', 'normal', '전체 정상 판정을 뜻하지'):
            self.assertIn(text, answer)

    def test_reverse_order_and_naive_time_rejected(self):
        p = self.ads();p['evidence'][1]['timestamp_kst'] = '2022-01-01T08:59:00+09:00'
        with self.assertRaises(ValueError): ads_answer(p)
        with self.assertRaises(ValueError): explicit_kst('2022-01-01T00:00:00')

    def test_real_timezone_conversion_and_precision(self):
        self.assertEqual(explicit_kst('2022-01-01T00:00:00.1234Z'), '2022-01-01T09:00:00.123400+09:00')
        self.assertEqual(explicit_kst('2022-01-01T09:00:00+09:00'), '2022-01-01T09:00:00+09:00')
        self.assertEqual(audit_time('msg=audit(1640995200.027:7)')[0], '2022-01-01T09:00:00.027000+09:00')

    def test_audit_missing_is_not_zero_and_duplicates_refused(self):
        self.assertIsNone(audit_field('uid=0', 'auid'))
        self.assertEqual(audit_field('uid=0', 'uid'), '0')
        self.assertEqual(audit_field('acct="name with space"', 'acct'), 'name with space')
        with self.assertRaises(ValueError): audit_field('res=success res=failed', 'res')

    def lds(self, labelled=False):
        raw = b'type=USER_AUTH msg=audit(1640995200.027:7): pid=12 uid=0 auid=4294967295 msg=\'acct="operator" exe="/bin/su" res=success\'\n'
        item = {'line': 1, 'labels': ['step'], 'rules': {'step': ['rule']}}
        labels = (json.dumps(item)+'\n').encode() if labelled else b''
        obs = {'evidence_id': 'env:audit:1', 'raw_line': raw.decode().rstrip('\n'),
               'raw_line_sha256': sha(raw), 'observed_at_kst': '2022-01-01T09:00:00.027000+09:00',
               'provider_line_labels': item['labels'] if labelled else [],
               'provider_rules': item['rules'] if labelled else {}}
        ref = {'source_line': 1, 'source_file_sha256': sha(raw), 'source_line_sha256': sha(raw),
               'label_file_sha256': sha(labels), 'label_line': 1 if labelled else None,
               'label_line_sha256': sha(labels) if labelled else None}
        c = {'messages': [{}, {'content': 'prompt\n'+json.dumps(obs)}], 'review': {'source_rows': [ref]}}
        return raw, labels, obs, c

    def test_unlabelled_does_not_become_security_clearance(self):
        raw, labels, obs, case = self.lds()
        self.assertEqual(verify_lds(raw, labels, [case])['candidate_rows'], 1)
        answer, facts = lds_answer(obs)
        self.assertIn('독립적으로 입증한 것은 아닙니다', answer)
        self.assertIn('전체 공격 성공', answer)
        self.assertEqual(facts['audit_fields']['uid'], '0')
        self.assertIsNone(facts['audit_fields']['addr'])

    def test_exact_provider_label_binding(self):
        raw, labels, obs, case = self.lds(True)
        self.assertEqual(verify_lds(raw, labels, [case])['provider_labelled_rows'], 1)
        case['review']['source_rows'][0]['label_line'] = 2
        with self.assertRaises(ValueError): verify_lds(raw, labels, [case])

    def test_changed_source_or_label_bytes_fail(self):
        raw, labels, obs, case = self.lds(True)
        for a,b in [(raw.replace(b'uid=0', b'uid=1'), labels), (raw, labels.replace(b'step', b'other'))]:
            with self.assertRaises(ValueError): verify_lds(a, b, [case])

    def test_duplicate_provider_label_cannot_hide_conflict(self):
        raw, labels, _, case = self.lds(True)
        with self.assertRaises(ValueError): verify_lds(raw, labels+labels, [case])

    def kev(self):
        return {'cveID': 'CVE-2000-0001', 'catalog_version': 'historical', 'vendorProject': 'vendor',
                'product': 'product', 'vulnerabilityName': 'issue', 'shortDescription': 'specific effect',
                'dateAdded': '2020-01-01', 'dueDate': '2020-01-02', 'cwes': ['CWE-1'],
                'knownRansomwareCampaignUse': 'Unknown', 'forensicTriage': 'Yes',
                'requiredAction': 'Preserve evidence before updates.', 'notes': 'https://example.org/reference'}

    def test_required_action_and_forensic_requirement_not_omitted(self):
        p = self.kev();answer, facts = kev_answer(p)
        for text in (p['requiredAction'], p['notes'], p['shortDescription'], 'forensicTriage=Yes', '우선 확인사항'):
            self.assertIn(text, answer)
        self.assertEqual(facts['forensicTriage'], 'Yes')

    def test_no_and_unknown_not_broadened_to_no_risk(self):
        p = self.kev();p['forensicTriage'] = 'No';answer,_ = kev_answer(p)
        self.assertIn('불필요하다는 결론은 아닙니다', answer)
        self.assertIn('사용되지 않았다는 증거가 아닙니다', answer)
        self.assertIn('우리 조직의 확정 기한으로 자동 적용하지', answer)

    def test_unknown_forensic_flag_not_coerced_to_no(self):
        p = self.kev();p['forensicTriage'] = None
        with self.assertRaises(ValueError): kev_answer(p)

    def test_mutated_official_document_refused(self):
        with self.assertRaises(ValueError): verify_kev(b'{"vulnerabilities":[]}', [])


if __name__ == '__main__': unittest.main()
