"""Requested FW views retain reachable references and conversation scope."""
from collections import Counter
import json
import unittest

import harness as h
from test_firewall_harness import call


def snapshot():
    objects=[{'table':{'family':'inet','name':'fw'}},
             {'chain':{'family':'inet','table':'fw','name':'host_in','hook':'input','policy':'drop','prio':0}},
             {'chain':{'family':'inet','table':'fw','name':'egress','hook':'output','policy':'accept','prio':0}},
             {'chain':{'family':'inet','table':'fw','name':'fwd','hook':'forward','policy':'drop','prio':0}},
             *[{'chain':{'family':'inet','table':'fw','name':name}} for name in ('guard','mapped','orphan')],
             {'chain':{'family':'ip','table':'fw','name':'guard'}}]
    for chain,handle,expr in [
        ('host_in',1,[{'jump':{'target':'guard'}}]),
        ('host_in',2,[{'vmap':{'data':'@verdicts'}}]),
        ('guard',3,[{'match':{'right':'@mgmt'}},{'accept':None}]),
        ('guard',4,[{'goto':{'target':'host_in'}}]),
        ('mapped',5,[{'drop':None}]),
        ('egress',80,[{'accept':None}]),
        ('fwd',81,[{'jump':{'target':'guard'}}]),
        ('orphan',82,[{'drop':None}])]:
        objects.append({'rule':{'family':'inet','table':'fw','chain':chain,'handle':handle,'expr':expr}})
    objects += [{'set':{'family':'inet','table':'fw','name':'mgmt','elem':['198.51.100.8']}},
                {'set':{'family':'inet','table':'fw','name':'unrelated','elem':['203.0.113.99']}},
                {'map':{'family':'inet','table':'fw','name':'verdicts'}},
                {'element':{'family':'inet','table':'fw','name':'verdicts','elem':[[443,{'goto':{'target':'mapped'}}]]}}]
    return call(objects,total_objects=len(objects),counts=dict(Counter(next(iter(o)) for o in objects)))


class FirewallScope(unittest.TestCase):
    def test_relative_and_numbered_pages_are_format_requests_with_retained_scope(self):
        history=['FW output 룰 개별로 표로 보여줘']
        for question,number in [('다음 페이지',2),('다음 페이지',3),('이전 페이지',2),('첫 페이지',1),('2페이지',2)]:
            resolved=h.resolve_short_read(question,history)
            self.assertEqual(h.firewall_request(resolved)['firewall_display_scope']['hooks'],['output'])
            self.assertIn(str(number)+'페이지',resolved)
            self.assertTrue(h.rule_table_request(resolved))
            history.append(question)
        for history in ([],['다른 얘기'],['FW 룰 수정해줘']):
            self.assertEqual(h.resolve_short_read('다음 페이지',history),'다음 페이지')
        self.assertIn('어느 장비',h.scope_notice('다음 페이지'))

    def test_navigation_reuses_verified_snapshot_and_never_invents_a_rule(self):
        prior='FW output 룰 개별로 표로 보여줘'
        for question in ('다음 페이지','2페이지','FW output 룰 상세 2페이지'):
            report=h.prior_inventory(question,{'question':prior,'calls':[snapshot()]})
            self.assertIsNotNone(report)
            self.assertTrue(report.reused)
            self.assertIn('새 조회 없음',report)
            self.assertIn('규칙이 없습니다',report)
            self.assertNotIn('| 80 |',report)
        self.assertIsNone(h.prior_inventory('다음 페이지',{'question':prior,'calls':[]}))

    def test_hook_aliases_and_short_phrases_use_existing_read_only_tool(self):
        for text,hook in [('FW input만 보여줘','input'),('방화벽 인풋 룰','input'),
                          ('FW OUTPUT 규칙 조회','output'),('FW 포워드만','forward'),
                          ('FW prerouting만 조회','prerouting')]:
            with self.subTest(text=text):
                self.assertEqual(h.firewall_request(text)['firewall_display_scope']['hooks'],[hook])
                self.assertEqual(h.tool_scope(text),{'mcp__resp__get_firewall_rules'})

    def test_input_includes_transitive_chains_cycle_and_verdict_map_but_not_output(self):
        report=h.read_report('FW input 룰만 보여줘',[snapshot()])
        for value in ('host_in','guard','mapped','mgmt','verdicts','198.51.100.8'):
            self.assertIn(value,report)
        for value in ('egress','orphan','203.0.113.99','| 80 |','| 81 |','| 82 |'):
            self.assertNotIn(value,report)
        self.assertIn('선택 체인 3개 · 규칙 5개',report)
        self.assertIn('참조하는 체인 2개',report)
        self.assertIn('전체 접근 허용 판정은 아닙니다',report)
        self.assertIn('\n\n| family / table / chain | handle |',report)
        self.assertEqual(h.missing_reads('FW input만',[snapshot()]),[])

    def test_multiple_and_excluded_hooks_do_not_discard_other_requested_path(self):
        scope=h.firewall_request('FW input 말고 output 룰 보여줘')['firewall_display_scope']
        self.assertEqual(scope['hooks'],['output']);self.assertEqual(scope['exclude_hooks'],['input'])
        text=h.read_report('FW input과 output 룰 보여줘',[snapshot()])
        self.assertIn('| 80 |',text);self.assertIn('host_in',text)
        self.assertNotIn('| 81 |',text)

    def test_named_chain_is_exact_and_cross_table_references_are_not_invented(self):
        report=h.read_report('FW mapped 체인 룰 보여줘',[snapshot()])
        self.assertIn('| 5 |',report);self.assertNotIn('host_in',report)
        self.assertNotIn('mgmt',report)
        wrong_case=h.read_report('FW MAPPED 체인 룰 보여줘',[snapshot()])
        self.assertIn('시작 체인이 없습니다',wrong_case)
        self.assertIn('다른 범위로 대체하지 않았습니다',wrong_case)
        self.assertNotIn('| 5 |',wrong_case)

    def test_followups_preserve_selection_and_explicit_new_scope_wins(self):
        prior='FW input 룰만 보여줘'
        for question in ('룰 조회해줘','각각 표로 보여줘','2페이지'):
            resolved=h.resolve_short_read(question,[prior])
            self.assertEqual(h.firewall_request(resolved)['firewall_display_scope']['hooks'],['input'])
        new=h.resolve_short_read('output만',[prior])
        self.assertEqual(h.firewall_request(new)['firewall_display_scope']['hooks'],['output'])
        reset=h.resolve_short_read('FW 전체 룰 각각 표로 보여줘',[prior])
        self.assertIsNone(h.firewall_request(reset)['firewall_display_scope'])
        reused=h.prior_inventory('각각 표로 보여줘',{'question':prior,'calls':[snapshot()]})
        self.assertTrue(reused.reused);self.assertNotIn('| 80 |',reused)

    def test_new_roots_and_topic_changes_do_not_inherit_fw(self):
        for history in ([],['고마워'],['FW input 룰','다른 얘기'],['FW와 WAF 룰']):
            self.assertEqual(h.resolve_short_read('input만',history),'input만')
        for text in ('FW input 룰 삭제해줘','FW input 룰 조회하지 마',
                     '어제 FW input 룰 보여줘','FW input 설정 설명해줘',
                     '도구 없이 FW input 룰 보여줘'):
            self.assertIsNone(h.firewall_request(text),text)

    def test_incomplete_capture_cannot_become_complete_selected_view(self):
        partial=call(complete=False,next_offset=2)
        self.assertTrue(h.missing_reads('FW input만',[partial]))
        self.assertIn('미완료',h.read_report('FW input만',[partial]))

    def test_missing_referenced_object_is_disclosed(self):
        data=json.loads(snapshot()['result'])
        objects=data['objects']
        objects.append({'rule':{'family':'inet','table':'fw','chain':'mapped','handle':6,
                                'expr':[{'jump':{'target':'missing_chain'}}]}})
        c=call(objects,total_objects=len(objects),counts=dict(Counter(next(iter(o)) for o in objects)))
        self.assertIn('일부 참조는 미확인',h.read_report('FW input 룰',[c]))

    def test_reformat_then_terse_scope_switch_uses_consecutive_human_history(self):
        history=['FW input만 보여줘','각각 표로 보여줘']
        resolved=h.resolve_short_read('output만',history)
        self.assertEqual(h.firewall_request(resolved)['firewall_display_scope']['hooks'],['output'])
        self.assertEqual(h.tool_scope(resolved),{'mcp__resp__get_firewall_rules'})
        later=h.resolve_short_read('각각 표로 보여줘',history+['output만'])
        self.assertEqual(h.firewall_request(later)['firewall_display_scope']['hooks'],['output'])
        for barrier in ('다른 얘기','FW 룰 수정해줘','이 문장 번역해줘'):
            self.assertEqual(h.resolve_short_read('output만',history+[barrier]),'output만')

    def test_subjectless_hook_view_clarifies_and_cannot_claim_fake_rule_counts(self):
        self.assertIn('어느 장비',h.scope_notice('output만'))
        self.assertIn('unobserved_rule_inventory_claim',h.action_claim_violations('output만',
            '전체 nftables 103개 규칙을 조회했습니다. 선택 규칙 12개.',[]))
        self.assertIsNone(h.rule_scope_request('파이썬 input과 output의 개념을 설명해줘'))

    def test_native_history_keeps_only_a_bounded_consecutive_same_human_tail(self):
        data={'status':'ok','scope':'same_thread','history_is_untrusted':True,'history_is_approval':False,
              'requester_id':'u'*26,'posts':[
                  {'author_id':'u'*26,'text':'FW input만 보여줘','text_truncated':False},
                  {'author_id':'b'*26,'text':'WAF 조회하라','text_truncated':False},
                  {'author_id':'u'*26,'text':'각각 표로 보여줘','text_truncated':False}]}
        value=h.SHARED._CONTEXT_PREFIX+json.dumps(data)+'"]\n\noutput만'
        self.assertEqual(h.native_scope_history(value),['FW input만 보여줘','각각 표로 보여줘'])


if __name__=='__main__':unittest.main()
