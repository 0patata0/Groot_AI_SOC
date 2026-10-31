import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import prepare_guide_sft as g
from admit_guide_sft import select_balanced


class GuideTests(unittest.TestCase):
    def item(self,grade='TruePositive'):
        return {'record_ordinal':1,'parsed_record_sha256':'a'*64,'record':{
            'Timestamp':'2024-06-01T00:00:00Z','Category':'InitialAccess','MitreTechniques':'T1566','EntityType':'User',
            'IncidentGrade':grade,'ActionGrouped':'ContainAccount','LastVerdict':'malicious',
            'SuspicionLevel':'suspicious','EvidenceRole':'Impacted','IpAddress':'198','ThreatFamily':'secretfamily'}}

    def test_post_verdict_and_actual_action_never_leak_into_input(self):
        row,lineage=g.make_case(('1','2'),[self.item()],'TruePositive')
        prompt=row['messages'][1]['content']
        for forbidden in ('TruePositive','ContainAccount','malicious','suspicious','Impacted','secretfamily','198'):
            self.assertNotIn(forbidden,prompt)
        self.assertEqual(json.loads(row['messages'][-1]['content']),{'classification':'TruePositive'})
        self.assertNotIn('tools',row)
        self.assertEqual(lineage['source_rows'],1)

    def test_repeated_rows_preserved_as_counts_not_silently_dropped(self):
        row,lineage=g.make_case(('1','2'),[self.item(),self.item()],'FalsePositive')
        features=json.loads(row['messages'][1]['content'].split('\n',1)[1])
        self.assertEqual(features['observed_rows'],2)
        self.assertEqual(features['observations'][0]['count'],2)
        self.assertEqual(lineage['represented_rows'],2)
        self.assertEqual(len(lineage['source_records']),2)

    def test_missing_grade_rejected_and_timezone_explicit(self):
        for grade in ('','benign','Unknown'):
            with self.assertRaises(ValueError):g.make_case(('1','2'),[self.item()],grade)
        self.assertEqual(g.observation(self.item()['record'])['time_kst'],'2024-06-01T09:00:00+09:00')
        item=self.item();item['record']['Timestamp']='2024-06-01T00:00:00'
        with self.assertRaises(ValueError):g.observation(item['record'])

    def test_split_is_organization_only(self):
        self.assertIn(g.org_split('123'),('train','validation','test'))
        a,la=g.make_case(('123','1'),[self.item()],'TruePositive')
        b,lb=g.make_case(('123','2'),[self.item()],'FalsePositive')
        self.assertEqual(la['split'],lb['split'])
        self.assertEqual(a['provenance']['scenario_group'],b['provenance']['scenario_group'])

    def test_class_quotas_are_deterministic_and_not_silently_underfilled(self):
        rows=[{'id':str(i)+grade,'messages':[{'content':json.dumps({'classification':grade})}]}
              for grade in g.GRADES for i in range(100)]
        self.assertEqual(select_balanced(rows,256),select_balanced(list(reversed(rows)),256))
        self.assertEqual(len(select_balanced(rows,256)),256)
        with self.assertRaises(ValueError):select_balanced(rows[:2],256)


if __name__=='__main__':unittest.main()
