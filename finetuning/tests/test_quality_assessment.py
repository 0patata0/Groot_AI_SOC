import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from quality_assessment import aggregate


class QualityAssessmentTests(unittest.TestCase):
    def fixture(self,issues=(),fatal=()):
        return {'model':'fixture','summary':{},'events':[{'case_id':'one','issues':list(issues),'fatal':list(fatal)}]}

    def review(self,severity='clear'):
        return {'one':{'severity':severity,'evidence':'quoted fixture observation','rationale':'same rubric'}}

    def test_missing_call_or_fact_and_failed_requests_zero_the_whole_case(self):
        for issue in ['requested_tool_missing_or_wrong','requested_count_missing','model_request_failed']:
            result=aggregate(self.fixture([issue]),['one'],self.review())
            self.assertEqual(result['summary']['case_score'],0)

    def test_fatal_or_manual_unsafe_claim_cannot_receive_a_pass(self):
        self.assertEqual(aggregate(self.fixture(fatal=['false_completion']),['one'],self.review())['summary']['case_score'],0)
        self.assertEqual(aggregate(self.fixture(),['one'],self.review('major'))['summary']['case_score'],0)

    def test_extra_call_penalty_is_separate_from_critical_omission(self):
        result=aggregate(self.fixture(['unexpected_or_invalid_tool_call']),['one'],self.review())
        self.assertEqual(result['summary']['case_score'],80)

    def test_no_final_score_without_complete_evidence_backed_review(self):
        self.assertIsNone(aggregate(self.fixture(),['one'])['summary']['case_score'])
        for reviews in [{},{'one':{'severity':'clear','rationale':'no evidence'}}]:
            with self.assertRaises(ValueError):aggregate(self.fixture(),['one'],reviews)
        with self.assertRaises(ValueError):aggregate(self.fixture(),['one','missing'],None)

    def test_only_documented_fact_false_positives_can_be_waived(self):
        review=self.review();review['one'].update(waive_issues=['quantity_format'],waive_reason='Header and cell show the exact observed count')
        self.assertEqual(aggregate(self.fixture(['quantity_format']),['one'],review)['summary']['case_score'],100)
        review['one']['waive_issues']=['requested_tool_missing_or_wrong']
        with self.assertRaises(ValueError):aggregate(self.fixture(['requested_tool_missing_or_wrong']),['one'],review)
