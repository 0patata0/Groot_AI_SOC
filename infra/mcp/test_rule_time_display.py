import copy
from datetime import datetime
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('rule_time_view',Path(__file__).with_name('rule_change_mcp.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class RuleTimeDisplayTests(unittest.TestCase):
    def test_kst_and_elapsed_are_added_without_changing_approval_observation(self):
        original={'target':'a:suricata','observation':{'started_at':'2026-10-24T15:55:11Z','running':True},
                  'base_state_sha256':'a'*64,'content':'literal log 2026-10-24T15:55:11Z'}
        saved=copy.deepcopy(original)
        result=m.with_time_display(original,datetime.fromisoformat('2026-10-25T01:05:11+09:00'))
        self.assertEqual(original,saved)
        self.assertEqual({k:v for k,v in result.items() if k!='time_display'},saved)
        self.assertEqual(result['time_display']['values'],[{'source_field':'observation.started_at',
            'kst':'2026-10-25T00:55:11+09:00','seconds_until_rendered_at':600,'elapsed_display':'0일 0시간 10분 0초'}])

    def test_naive_invalid_values_and_negative_elapsed_are_not_invented(self):
        result=m.with_time_display({'observation':{'started_at':'2026-10-24T15:55:11',
                                                  'observed_at':True,'last_reload':'bad'}},
                                   datetime.fromisoformat('2026-10-25T01:05:11+09:00'))
        self.assertEqual(result['time_display']['values'],[])
        result=m.with_time_display({'runtime':{'started_at':'2026-10-25T01:15:11+09:00'}},
                                   datetime.fromisoformat('2026-10-25T01:05:11+09:00'))
        self.assertEqual(result['time_display']['values'][0]['seconds_until_rendered_at'],-600)


if __name__=='__main__': unittest.main()
