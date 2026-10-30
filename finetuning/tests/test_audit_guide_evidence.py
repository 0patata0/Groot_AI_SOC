import csv
import io
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import audit_guide_evidence as A


class TestBoundary(unittest.TestCase):
    def test_missing_triage_can_support_action_review_but_never_benign_target(self):
        group={'rows':1,'grades':{'':1},'actions':{'ContainAccount':1},
               'granular_actions':{'account disabled':1},'action_pair_missing_rows':0}
        index,summary=A.task_indexes({('1','2'):group},set())
        self.assertEqual(index['triage_cases'],[])
        self.assertEqual(len(index['action_cases']),1)
        self.assertEqual(index['action_cases'][0]['grades'],{'':1})
        self.assertEqual(summary['action_cases_without_triage'],1)
        self.assertEqual(summary['unique_source_eligible_incidents'],1)
        index,summary=A.task_indexes({('1','2'):group},{('1','2')})
        self.assertEqual(summary['unique_source_eligible_incidents'],0)

    def test_incomplete_action_pair_does_not_erase_valid_triage(self):
        group={'rows':2,'grades':{'TruePositive':2},'actions':{'ContainAccount':1,'':1},
               'granular_actions':{'':2},'action_pair_missing_rows':1}
        index,summary=A.task_indexes({('1','2'):group},set())
        self.assertEqual(len(index['triage_cases']),1)
        self.assertEqual(index['action_cases'],[])
        self.assertEqual(summary['action_exclusion_reasons'],{'incomplete_action_label_pair':1})

    def test_only_exact_org_incident_pair_is_overlap(self):
        buf=io.StringIO(newline='');writer=csv.writer(buf)
        writer.writerow(A.G.COLUMNS+['Usage'])
        for org,incident,grade in [('1','5','TruePositive'),('2','5','FalsePositive'),('1','5','')]:
            record={'OrgId':org,'IncidentId':incident,'IncidentGrade':grade}
            writer.writerow([record.get(k,'')for k in A.G.COLUMNS]+['Public'])
        buf.seek(0);result=A.scan_test(buf,{('1','5')})
        self.assertEqual(result['overlap_incidents'],1)
        self.assertEqual(result['overlap_rows'],2)
        self.assertEqual(result['test_records'],3)
        self.assertEqual(result['test_organizations'],2)
        self.assertEqual(result['overlap_keys'],[{'org_id':'1','incident_id':'5','test_rows':2}])
        self.assertNotIn('TruePositive',str(result))

    def test_missing_usage_column_rejected(self):
        buf=io.StringIO();csv.writer(buf).writerow(A.G.COLUMNS);buf.seek(0)
        with self.assertRaisesRegex(ValueError,'schema'):A.scan_test(buf,set())


if __name__=='__main__':unittest.main()
