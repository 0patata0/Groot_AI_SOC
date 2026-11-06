"""Service lifecycle guidance reaches shared model inputs, not only SOUL sync."""
import unittest
import harness
import importlib.util
import json
import hashlib
from pathlib import Path

class ServiceSemantics(unittest.TestCase):
    def test_unit_name_causal_questions_receive_shared_lifecycle_guidance(self):
        for question in ('어제 B 서버 capstone-management.service 실패 원인이 뭐고, 지금도 문제인지 확인해줘. 설정은 바꾸지 마.',
                         '오늘 C 서버 apache2.service 실패 원인이 뭐야?',
                         'systemd 오류 왜 생겼어?'):
            with self.subTest(question=question):
                value=harness.guidance(question)
                self.assertEqual(value.count(harness.CONTRACT.SERVICE_STATE_GUIDANCE),1)
                self.assertIn('Type=oneshot',value)
                self.assertIn('raw_messages_returned=false',value)

    def test_unrelated_firewall_read_does_not_receive_service_guidance(self):
        self.assertNotIn(harness.CONTRACT.SERVICE_STATE_GUIDANCE,harness.guidance('fw 룰 보여줘'))

    def test_peer_own_claims_cannot_turn_successful_oneshot_into_failure(self):
        path=Path(__file__).resolve().parents[1]/'hermes/review_channel_worker.py'
        spec=importlib.util.spec_from_file_location('semantic_peer',path);worker=importlib.util.module_from_spec(spec);spec.loader.exec_module(worker)
        raw=json.dumps({'schema':1,'target':'c:vector','unit':'vector.service',
            'properties':{'Type':'oneshot','ActiveState':'inactive','SubState':'dead','Result':'success'},
            'process_termination':{'kind':'exited','exit_status':0,'signal_number':None}})
        calls=[{'server':'system-diagnostics','name':'get_system_diagnostics','arguments':{'target':'c:vector'},
                'result':raw,'result_sha256':hashlib.sha256(raw.encode()).hexdigest(),'is_error':False,'is_write':False}]
        with self.assertRaisesRegex(ValueError,'peer_diagnostic_claim_mismatch'):
            worker.validate_diagnostic_peer_claims(harness,'현재 c:vector는 inactive/dead이므로 여전히 실패한 상태입니다.',calls)
        worker.validate_diagnostic_peer_claims(harness,'현재 c:vector는 Type=oneshot, Result=success입니다. 지속 장애 여부는 미확인입니다.',calls)

if __name__=='__main__':unittest.main()
