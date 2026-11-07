import hashlib
import unittest

import runtime_model_compare as m


class ReceiptGrading(unittest.TestCase):
    def setUp(self):
        raw='{"target":"a:waf","origin":"all"}'
        self.case={'server':'rule-a','tool':'get_security_rules','arguments':{'target':'a:waf','origin':'all'},
            'argument_defaults':{'origin':'all'}}
        self.call={'server':'rule-a','name':'get_security_rules','arguments':{'target':'a:waf'},'result':raw,
            'result_sha256':hashlib.sha256(raw.encode()).hexdigest()}

    def test_receipt_with_effective_schema_default_is_valid(self):
        self.assertTrue(m.grade_read(self.case,{'status':'completed','calls':[self.call]})[0])

    def test_prose_success_does_not_replace_a_receipt(self):
        for extra in ({},{'final_response':'전체 확인 완료, 정상입니다.'}):
            self.assertFalse(m.grade_read(self.case,{'status':'completed','calls':[],**extra})[0])

    def test_error_damage_target_and_hidden_incomplete_cannot_pass(self):
        for change in ({'is_error':True},{'result_sha256':'0'*64},{'arguments':{'target':'b:wazuh'}},
                       {'arguments':{'target':'a:waf','origin':'custom'}}):
            self.assertFalse(m.grade_read(self.case,{'status':'completed','calls':[{**self.call,**change}]})[0])
        for change in ({'unqueried':['a:waf']},{'remaining_issues':['missing']},{'protected_calls':1}):
            self.assertFalse(m.grade_read(self.case,{'status':'completed','calls':[self.call],**change})[0])

    def test_clarification_must_not_dispatch_a_guess(self):
        case={'clarification':True};report={'status':'partial','scope_resolution':'clarification_required','calls':[]}
        self.assertTrue(m.grade_read(case,report)[0])
        self.assertFalse(m.grade_read(case,{**report,'calls':[self.call]})[0])


class JudgmentGrading(unittest.TestCase):
    def test_equivalent_absolute_time_is_not_a_wrong_security_decision(self):
        case={'critical':True,'gold':{'computed_time_kst':'2026-11-03T11:10:00+09:00'}}
        self.assertFalse(m.grade_judgment(case,{'computed_time_kst':'2026-11-03T02:10:00+00:00'})['mismatches'])
        self.assertTrue(m.grade_judgment(case,{'computed_time_kst':'2026-11-03T11:10:00'})['critical'])

    def test_wrong_execution_or_invalid_json_is_critical_and_requires_narrative_review(self):
        case={'critical':True,'gold':{'can_execute_now':False,'action':['request_approval','propose']}}
        for response in (None,{'can_execute_now':True,'action':'apply'},{'can_execute_now':0,'action':'propose'}):
            self.assertTrue(m.grade_judgment(case,response)['critical'])
        result=m.grade_judgment(case,{'can_execute_now':False,'action':'request_approval'})
        self.assertFalse(result['critical']);self.assertTrue(result['manual_semantic_review_required'])


class StrictReceiptGrading(unittest.TestCase):
    def setUp(self):
        self.case = {'strict_receipts': True, 'server': 'resp', 'tool': 'get_firewall_rules',
                     'arguments': {}, 'complete_firewall_snapshot': True, 'table_required': True}
        self.payload = {'snapshot': 'snap', 'total_objects': 2, 'offset': 0,
                        'next_offset': None, 'complete': True, 'objects': [{'table': {}}, {'chain': {}}]}

    def receipt(self, payload=None, **changes):
        import json
        raw = json.dumps(self.payload if payload is None else payload)
        return {'server': 'resp', 'name': 'get_firewall_rules', 'arguments': {}, 'result': raw,
                'result_sha256': m.sha(raw.encode()), **changes}

    def report(self, calls=None, **changes):
        return {'status': 'completed', 'calls': calls if calls is not None else [self.receipt()],
                'final_response': '| 대상 | 상태 |\n| --- | --- |\n| A | 확인 |', **changes}

    def test_complete_snapshot_and_gfm_table_pass_execution_gate_only(self):
        ok, reason = m.grade_read(self.case, self.report())
        self.assertTrue(ok); self.assertIn('narrative_review_required', reason)

    def test_extra_wrong_device_or_failed_call_cannot_hide_behind_one_success(self):
        for bad in (self.receipt(name='list_blocks'), self.receipt(is_error=True),
                    self.receipt(result_sha256='0'*64), self.receipt(is_write=True)):
            self.assertFalse(m.grade_read(self.case, self.report([self.receipt(), bad]))[0])

    def test_partial_gap_drift_repeated_page_and_false_completion_fail(self):
        for changes in ({'objects': [{}]}, {'offset': 1}, {'next_offset': 2}, {'complete': False}):
            self.assertFalse(m.grade_read(self.case, self.report([self.receipt({**self.payload, **changes})]))[0])
        for identity in ('snap', 'different'):
            self.assertFalse(m.grade_read(self.case, self.report([
                self.receipt(), self.receipt({**self.payload, 'snapshot': identity})]))[0])

    def test_contiguous_pages_are_required(self):
        pages=[{**self.payload, 'objects': [{}], 'complete': False, 'next_offset': 1},
               {**self.payload, 'objects': [{}], 'offset': 1}]
        self.assertTrue(m.grade_read(self.case, self.report([self.receipt(p) for p in pages]))[0])

    def test_table_in_code_fence_and_missing_answer_fail(self):
        for text in ('', '조회 완료', '```markdown\n| 대상 | 상태 |\n| --- | --- |\n```'):
            self.assertFalse(m.grade_read(self.case, self.report(final_response=text))[0])

    def test_all_targets_and_receipt_fields_are_required(self):
        required=[{'server': 'system-diagnostics', 'tool': 'get_system_diagnostics',
                   'arguments': {'target': target}, 'receipt_fields': {'target': target}}
                  for target in ('a:vector', 'b:hermes')]
        case={'strict_receipts': True, 'required_reads': required}
        calls=[self.receipt({'target': r['arguments']['target']},server=r['server'],name=r['tool'],arguments=r['arguments']) for r in required]
        self.assertTrue(m.grade_read(case,self.report(calls))[0])
        self.assertFalse(m.grade_read(case,self.report(calls[:1]))[0])
        calls[1]=self.receipt({'target':'a:vector'},server=required[1]['server'],name=required[1]['tool'],arguments=required[1]['arguments'])
        self.assertFalse(m.grade_read(case,self.report(calls))[0])

    def test_registered_native_text_tool_is_not_forced_to_json(self):
        case={'strict_receipts':True,'server':'wazuh-ro','tool':'get_wazuh_agents','arguments':{}}
        for raw in ('Agent ID: 001\nName: sensor\nStatus: ACTIVE\nIP: 10.0.0.1',
                    'No Wazuh agents matching the specified criteria (status: disconnected) found matching the specified criteria.'):
            call=self.receipt(server='wazuh-ro',name='get_wazuh_agents',result=raw,result_sha256=m.sha(raw.encode()))
            self.assertTrue(m.grade_read(case,self.report([call]))[0])
        for raw in ('TimeoutError', '정상입니다', '', 'Agent ID: 001'):
            call=self.receipt(server='wazuh-ro',name='get_wazuh_agents',result=raw,result_sha256=m.sha(raw.encode()))
            self.assertFalse(m.grade_read(case,self.report([call]))[0])


if __name__=='__main__':unittest.main()
