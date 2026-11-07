"""Real trial regressions: omitted verbs and unobserved tables are not facts."""
import unittest

import harness as h
from test_block_lists import receipt
from test_firewall_harness import call
from test_security_inventory import fixture


class ReadClaimBoundaries(unittest.TestCase):
    def test_fw_policy_view_is_one_full_fw_read(self):
        for q in ('FW 정책 표로', '방화벽 정책 좀 볼래?', '현재 FW 정책 보여줘'):
            self.assertEqual(h.tool_scope(q), {'mcp__resp__get_firewall_rules'}, q)
            self.assertTrue(h.structured_read(q))
            self.assertTrue(h.missing_reads(q, []))
            self.assertEqual(h.missing_reads(q, [call()]), [])
        for q in ('FW 정책 안전한지 검토해줘', 'FW 정책 수정하고 표로',
                  '어제 FW 정책 표로', 'FW 정책 표로. 조회하지 마',
                  'WAF 정책 표로', 'FW 정책이란 개념 설명해줘'):
            self.assertIsNone(h.firewall_request(q), q)

    def test_noun_table_requests_keep_device_and_ambiguity(self):
        for name, target in (('WAF', 'a:waf'), ('IDS', 'a:suricata'), ('Wazuh', 'b:wazuh')):
            p = h.security_inventory_request(name + ' 룰 첫 3개만 표로')
            self.assertEqual(p['targets'], [target]); self.assertEqual(p['first_limit'], 3)
            self.assertEqual(p['origin'], 'all'); self.assertEqual(p['view'], 'details')
        self.assertIn('어느 장비', h.scope_notice('룰 표로'))
        for q in ('Wazuh 룰 삭제하고 표로', '어제 Wazuh 룰 표로', '도구 없이 Wazuh 룰 표로'):
            self.assertIsNone(h.security_inventory_request(q), q)

    def test_first_count_is_bound_to_registered_arguments_and_receipt(self):
        q='Wazuh 상관분석 룰 첫 3개만 표로'
        p=h.security_inventory_request(q)
        self.assertTrue(p['correlation_only'])
        alias='mcp__rule_b__get_security_rules'
        schema=h.refine_read_schemas(q,{alias:{'type':'object','properties':{}}},[])[alias]
        properties=schema['anyOf'][0]['properties']
        self.assertEqual(properties['limit'], {'enum':[3]})
        self.assertEqual(properties['target'], {'enum':['b:wazuh']})
        self.assertEqual(properties['correlation_only'], {'enum':[True]})
        self.assertEqual(properties['origin'], {'enum':['all']})
        c=fixture(view='details',correlation=True,limit=3)
        self.assertEqual(h.missing_reads(q,[c]),[])
        self.assertIn('| 5712 |',h.read_report(q,[c]))
        wrong=fixture(view='details',correlation=True,limit=20)
        self.assertTrue(h.missing_reads(q,[wrong]))
        for count in (0, 101, 1000, 999999):
            self.assertIsNone(h.security_inventory_request(f'Wazuh 룰 첫 {count}개 표로'))

    def test_temporary_modifier_does_not_change_scope_or_authorize_actions(self):
        for q in ('임시로 차단된 IP 있어?', '현재 임시 차단 목록', 'FW 임시로 막힌 주소 보여줘'):
            self.assertEqual(h.tool_scope(q), {h.READ.BLOCKS}, q)
            self.assertTrue(h.missing_reads(q,[]))
            self.assertEqual(h.missing_reads(q,[receipt()]),[])
        for q in ('임시로 차단된 IP 해제해줘', '어제 임시 차단 목록',
                  'WAF 임시 차단 목록', '임시로 차단된 IP와 WAF 룰 표로',
                  '임시로 차단된 IP 왜 막혔어?'):
            self.assertIsNone(h.READ.block_list_plan(h.normalized(q)), q)

    def test_unobserved_block_table_and_tool_sample_are_rejected(self):
        q='현재 임시 차단 주소 있어?'
        for answer in ('현재 임시 차단 목록입니다.\n| 차단 IP | 남은 시간 |\n| --- | --- |\n| 192.0.2.44 | 100 |',
                       '현재 차단된 IPv4 주소 목록을 확인했습니다.',
                       '네, 현재 임시 차단된 IPv4 주소 목록입니다.\n| IP 주소 | 남은 시간 |\n| --- | --- |\n| 192.0.2.44 | 100 |'):
            self.assertIn('unobserved_block_list_claim',h.action_claim_violations(q,answer,[]))
        for answer in ('get_security_rules(target=b:wazuh) 반환 표본 3건',
                       'get_security_rules(target=b:wazuh) 반환 자료를 확인했습니다.'):
            self.assertIn('unobserved_tool_result_claim',h.action_claim_violations('룰 표로',answer,[]))
        for answer in ('차단 목록은 미확인입니다.', 'get_security_rules를 조회해야 합니다.'):
            self.assertEqual(h.action_claim_violations(q,answer,[]),[])
        self.assertEqual(h.action_claim_violations('예시를 표로 설명해줘',
            '| 차단 IP | 남은 시간 |\n| 192.0.2.44 | 100 |',[]),[])
        self.assertEqual(h.action_claim_violations(q,
            'list_blocks는 별도의 임시 차단 목록입니다. 이번 조회로 규칙을 변경하지 않았습니다.',[]),[])

    def test_only_complete_owned_fw_set_replaces_extra_block_read(self):
        q='FW 정책 보여줘';answer='현재 차단된 IPv4 주소는 없습니다.'
        owned={'set':{'family':'inet','table':'capstone_fw','name':'agent_block','type':'ipv4_addr','elem':[]}}
        c=call(objects=[owned],total_objects=1,counts={'set':1})
        self.assertEqual(h.action_claim_violations(q,answer,[c]),[])
        for bad in (call(), call(objects=[owned],total_objects=2,counts={'set':1},complete=False),
                    call(objects=[{'set':{**owned['set'],'table':'unrelated'}}],total_objects=1,counts={'set':1}),
                    {**c,'result_sha256':'0'*64}):
            self.assertIn('unobserved_block_list_claim',h.action_claim_violations(q,answer,[bad]))


if __name__=='__main__':unittest.main()
