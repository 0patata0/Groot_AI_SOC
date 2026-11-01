import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from prepare_operator_sources import (canonical, sha, regression_answer, regression_examples,
    entity_answer, entity_request, project_entities, cloud_identity, cloud_timeline_answer, markdown_sections)


class SourceProofTests(unittest.TestCase):
    def test_negative_wazuh_oracle_is_not_a_benign_verdict(self):
        row={'source':'wazuh','target':{'predicate':'expected_tuple_does_not_match','rule_id':'4805','level':'0','decoder':'sonicwall'},
             'source_url':'https://example.invalid/pinned/fixture','source_locator':{'ordinal':1}}
        answer=regression_answer(row)
        self.assertIn('일치하지 않을',answer)
        self.assertIn('무해 판정이 아닙니다',answer)
        self.assertIn('엔진을 재실행하지 않았습니다',answer)

    def test_unknown_crs_oracle_is_held(self):
        row={'source':'crs','target':{'stage_assertions':[{'log':{'expect_ids':[901234],'custom_matcher':'anything'}}]}}
        with self.assertRaisesRegex(ValueError,'Unreviewed'):regression_answer(row)

    def test_zero_redactions_do_not_drop_every_fixture(self):
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp);(root/'review').mkdir();(root/'raw/wazuh').mkdir(parents=True)
            original=b'example provider fixture\n';(root/'raw/wazuh/test.ini').write_bytes(original)
            target={'predicate':'expected_tuple_matches','rule_id':'4805','level':'0','decoder':'sonicwall'}
            r={'id':'fixture-one','source':'wazuh','source_path':'test.ini','source_sha256':sha(original),
               'provisional_partition':'training_candidate','static_status':'linked','reasons':[],
               'target':target,'target_sha256':sha(canonical(target).encode()),'input':{'log':'ordinary event'},
               'source_url':'https://example.invalid/test.ini','source_commit':'a'*40,'source_locator':{'ordinal':1},'split_group':'one'}
            file=root/'review/regression-records.jsonl';file.write_text(canonical(r)+'\n')
            examples,held=regression_examples(root)
            self.assertEqual((len(examples),len(held)),(1,0))
            r['input']['log']='password=fixture-value'
            file.write_text(canonical(r)+'\n')
            examples,held=regression_examples(root)
            self.assertEqual(len(examples),0)
            self.assertEqual(held[0]['reason'],'redaction_would_change_provider_test')
            r['provisional_partition']='reserved_evaluation';file.write_text(canonical(r)+'\n')
            self.assertEqual(regression_examples(root),([],[]))

    def test_entity_proof_requires_named_alert_exact_type_and_unique_value(self):
        question='According to the alert "Cloud control-plane activity", what IP address was recorded?'
        alerts=[{'AlertName':'Cloud control-plane activity','Entities':[{'Type':'ip','Address':'203.0.113.61'}]}]
        self.assertIsNotNone(entity_answer(question,'203.0.113.61',alerts))
        self.assertIsNone(entity_answer(question,'203.0.113.6',alerts))
        self.assertIsNone(entity_answer('What IP address was recorded?','203.0.113.61',alerts))
        different=copy.deepcopy(alerts);different[0]['Entities'][0]['Type']='account'
        self.assertIsNone(entity_answer(question,'203.0.113.61',different))
        ambiguous=copy.deepcopy(alerts);ambiguous[0]['Entities'].append({'Type':'ip','Address':'203.0.113.62'})
        self.assertIsNone(entity_answer(question,'203.0.113.61',ambiguous))

    def test_causal_and_role_specific_answers_do_not_pass_entity_lookup(self):
        for q in ['What was the first IP address?', 'What IP address was responsible for the attack?',
                  'What was the destination IP address?', 'How was the URL used?']:
            with self.subTest(q=q):self.assertIsNone(entity_request(q))

    def test_retrospective_verdicts_are_excluded_from_entity_input(self):
        value=[{'Type':'ip','Address':'203.0.113.61','Roles':['Attacker'],'LastVerdict':'Malicious',
                'ThreatAnalysisSummary':[{'Verdict':'Malicious'}]}]
        self.assertEqual(project_entities(value),[{'Type':'ip','Address':'203.0.113.61'}])

    def test_timeline_requires_explicit_zone_and_preserves_error_scope(self):
        obs={'userIdentity':{'arn':'arn:example:user/test'},'recipientAccountId':'example-account',
             'sourceIPAddress':'203.0.113.61','eventTime':'2025-06-10T20:30:00Z','eventID':'e1',
             'eventName':'ReadObject','eventSource':'example.service','errorCode':'AccessDenied'}
        self.assertIsNotNone(cloud_identity(obs))
        answer=cloud_timeline_answer([{'observation':obs}],19)
        self.assertIn('2025-06-11T05:30:00+09:00',answer)
        self.assertIn('AccessDenied',answer)
        self.assertIn('19개 중 제공된 1개',answer)
        self.assertIn('침해 성공을 증명하지 않습니다',answer)
        obs['eventTime']='2025-06-10T20:30:00'
        with self.assertRaises(ValueError):cloud_identity(obs)

    def test_duplicate_guide_sections_cannot_hide_a_risk(self):
        with self.assertRaises(ValueError):markdown_sections('## Risks\none\n## Risks\ntwo\n')


if __name__=='__main__':unittest.main()
