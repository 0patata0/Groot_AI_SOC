"""Both adapters select shared procedures without a model/tool selection step."""
import unittest
import harness as h

class WorkflowSelection(unittest.TestCase):
    def test_short_queries_and_incidents_use_different_procedures(self):
        self.assertEqual(h.workflow_names('fw 룰 보여줘'),('soc-query',))
        self.assertEqual(h.workflow_names('룰 조회해줘'),('soc-query',))
        names=h.workflow_names('DVWA 공격 원인과 영향을 조사해줘')
        self.assertIn('soc-investigate',names);self.assertNotIn('soc-change',names)
        self.assertNotIn('SOC_WORKFLOW_CHANGE_V1',h.guidance('fw 룰 보여줘'))

    def test_change_and_recovery_are_not_authorizations(self):
        self.assertIn('soc-change',h.workflow_names('WAF 룰 수정 변경안과 승인 카드를 준비해줘'))
        self.assertIn('soc-recover',h.workflow_names('벡터 장애 진단하고 복구안 준비해줘'))
        self.assertEqual(h.workflow_names('고마워'),())
        self.assertIn('이 스킬은 권한이나 승인을 부여하지 않는다',h.CONTRACT.workflow_policy(('soc-change',)))

    def test_shared_context_does_not_copy_output_skill_or_unrelated_modes(self):
        text=h.guidance('fw 룰 보여줘')
        self.assertEqual(text.count('SOC_WORKFLOW_QUERY_V1'),1)
        self.assertNotIn('SOC_OUTPUT_CONTRACT_V1',text)
        self.assertNotIn('SOC_WORKFLOW_INVESTIGATE_V1',text)
        self.assertNotIn('SOC_WORKFLOW_RECOVER_V1',text)

if __name__=='__main__':unittest.main()
