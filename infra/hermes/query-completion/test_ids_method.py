"""Application capability questions must neither list rules nor authorize writes."""
import copy
import unittest
from test_expanded_reads import H, call

NAME='mcp__rule_a__get_service_action_target'
QUESTION='IDS 룰 바꾸면 무중단으로 적용돼? 실제 도구로 확인해줘. 변경이나 재시작은 하지 마.'


def receipt(**change):
    data={'target':'a:suricata','observation':{'running':True,'container_id':'a'*64},
          'allowed_actions':['restart'],'impact':'Passive IDS detection pauses during restart',
          'rule_source_evidence':{'observed_at':1794000000,'rule_source_option':'-S',
              'rule_source_path':'/rules/all.rules','combined_is_exact_et_plus_local':True}}
    data.update(change)
    return call('get_service_action_target',data,{'target':'a:suricata'},server='rule-a')


class IdsMethodTests(unittest.TestCase):
    def test_sdk_selection_retains_registered_target_until_verified(self):
        schema={'type':'object','properties':{'target':{'type':'string',
            'enum':['a:suricata','a:waf']}},'required':['target'],'additionalProperties':False}
        original=copy.deepcopy(schema)
        for q in (QUESTION,'IDS 재시작 없이 룰 바꿀 수 있어? 확인만 해줘.'):
            with self.subTest(q=q):
                narrowed=H.refine_read_schemas(q,{NAME:schema},[])
                self.assertEqual(narrowed[NAME]['properties']['target']['enum'],['a:suricata'])
                self.assertEqual(narrowed[NAME]['required'],['target'])
                self.assertEqual(H.refine_read_schemas(q,{NAME:schema},[receipt()]),{})
                self.assertEqual(H.refine_read_schemas(q,{},[]),{})
        self.assertEqual(schema,original)

    def test_short_paraphrases_select_service_capability_not_inventory(self):
        for q in (QUESTION,'IDS 재시작해야 해?','Suricata 룰 반영 방법 알려줘',
                  '수리카타 무중단 가능?','IDS 재시작 없이 룰 바꿀 수 있어?',
                  'IDS 룰 적용하는 방식 알려줘','Suricata hot reload 돼?'):
            with self.subTest(q=q):
                self.assertTrue(H.ids_change_method_question(q))
                self.assertEqual(H.tool_scope(q),{NAME})
                self.assertIsNone(H.security_inventory_request(q))
                self.assertIsNone(H.inventory_question(q))

    def test_writes_and_concepts_keep_normal_path(self):
        for q in ('IDS 룰 바꾸고 재시작해줘','IDS reload 해줘','IDS 재적재해줘',
                  'IDS 리로드 해줘','IDS 승인안 작성해줘',
                  'IDS 재시작해야 하는지 확인하고 재시작해줘',
                  'IDS hot reload가 무슨 뜻이야? 도구 없이 설명만 해줘'):
            with self.subTest(q=q):
                self.assertFalse(H.ids_change_method_question(q))
                self.assertNotEqual(H.tool_scope(q),{NAME})
        self.assertTrue(H.ids_change_method_question('IDS 재적재 가능한지 확인만 해줘. 재적재하지 마.'))

    def test_verified_current_capability_has_table_impact_and_no_claim_of_apply(self):
        text=H.service_report(QUESTION,[receipt()])
        self.assertIn('재시작만 허용',text);self.assertIn('무중단 적용 경로가 아닙니다',text)
        self.assertIn('| 허용 작업 | restart |',text)
        self.assertIn('| 실행 룰 지정 | -S /rules/all.rules |',text)
        self.assertIn('2026-11-07T06:20:00+09:00',text)
        self.assertIn('Passive IDS detection pauses during restart',text)
        self.assertNotIn('적용 완료',text);self.assertNotIn('```',text)
        self.assertFalse(H.missing_reads(QUESTION,[receipt()]))

    def test_allowed_reload_is_not_evidence_that_reload_succeeded(self):
        text=H.service_report(QUESTION,[receipt(allowed_actions=['reload','restart'])])
        self.assertIn('실제 무중단 적용 성공은 아직 확인하지 않았습니다',text)
        self.assertNotIn('재시작만 허용',text)

    def test_unknown_actions_impact_and_wrong_target_are_incomplete(self):
        for change in ({'allowed_actions':[]},{'allowed_actions':['restart','restart']},
                       {'allowed_actions':['shell']},{'allowed_actions':[{}]},
                       {'impact':None},{'target':'a:waf'},{'observation':None}):
            with self.subTest(change=change):
                self.assertTrue(H.missing_reads(QUESTION,[receipt(**change)]))
                self.assertIsInstance(H.service_report(QUESTION,[receipt(**change)]),str)

    def test_failed_latest_read_and_corrupt_hash_never_reuse_earlier_success(self):
        failed=receipt();failed['is_error']=True
        corrupt=receipt();corrupt['result_sha256']='0'*64
        for later in (failed,corrupt):
            with self.subTest(later=later):
                self.assertTrue(H.missing_reads(QUESTION,[receipt(),later]))
                self.assertNotIn('재시작만 허용',H.service_report(QUESTION,[receipt(),later]))

    def test_invalid_epoch_or_unverified_source_remains_unknown_without_crash(self):
        for stamp in (float('nan'),float('inf'),10**100,True,None):
            row=receipt(rule_source_evidence={'observed_at':stamp,'combined_is_exact_et_plus_local':True})
            text=H.service_report(QUESTION,[row])
            self.assertIn('| 관측 시각 KST | 미확인 |',text)
            self.assertIn('| 실행 룰 지정 | 미확인 |',text)

    def test_compound_inventory_and_method_keeps_both_requirements(self):
        q='IDS 룰 개수와 무중단 적용 가능 여부 확인해줘'
        self.assertEqual(H.tool_scope(q),{NAME,'mcp__rule_a__get_security_rules'})
        self.assertTrue(H.missing_reads(q,[receipt()]))
        out=H.read_report(q,[receipt()])
        self.assertIn('재시작만 허용',out)
        self.assertIn('미조회·검증 실패',out)


if __name__=='__main__':unittest.main()
