import copy
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from prepare_operator_contract_eval import cases
from operator_rollout import replay, valid_arguments
from soc_dataset import validate_case

CATALOG=json.loads((Path(__file__).resolve().parents[1]/'mcp_contract.20261107.json').read_text())


class ContractEvalTests(unittest.TestCase):
    def test_every_fixture_is_current_schema_valid_and_reference_replay_complete(self):
        fixtures=cases('validation',CATALOG)+cases('test',CATALOG)
        self.assertEqual(len(fixtures),32)
        for case in fixtures:
            with self.subTest(case=case['id']):
                self.assertFalse(case['training_included']);validate_case(case,CATALOG)
                responses=iter(copy.deepcopy([m for m in case['messages'][case['prompt_messages_count']:]if m['role']=='assistant']))
                result=replay(case,CATALOG,lambda m,t:next(responses))
                self.assertEqual(result['issues'],[]);self.assertTrue(result['semantic_review_required'])

    def test_short_followup_receives_context_but_never_reference_tool_observation(self):
        case=next(c for c in cases('validation',CATALOG)if c['review']['workflow']=='short_followup')
        seen=[]
        def omit(messages,tools):
            seen.append(messages);return {'role':'assistant','content':'확인했습니다.'}
        result=replay(case,CATALOG,omit)
        self.assertEqual(len(seen[0]),4)
        self.assertFalse(any(m['role']=='tool'for m in seen[0]))
        self.assertIn('required_call_omitted',result['issues'])

    def test_event_and_diagnostic_time_guards_are_not_dropped(self):
        for name in ('mcp__system_diagnostics__get_system_diagnostics','mcp__security_events__search_suricata_alerts'):
            entry=next(t for t in CATALOG['tools']if t['name']==name)
            initial={'target':'b:systemd'}if 'diagnostics' in name else {}
            self.assertTrue(valid_arguments(name,initial,entry))
            self.assertFalse(valid_arguments(name,{**initial,'since_kst':'2026-11-06T01:00:00+09:00'},entry))
            self.assertFalse(valid_arguments(name,{**initial,'since_kst':'2026-11-06T01:00:00+09:00',
                'until_kst':'2026-11-06T02:00:00+09:00','lookback_minutes':60},entry))
            changed=copy.deepcopy(entry);changed['parameters']['allOf'].append({'const':'unknown'})
            self.assertFalse(valid_arguments(name,initial,changed))


if __name__=='__main__':unittest.main()
