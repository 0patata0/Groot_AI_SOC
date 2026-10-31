import hashlib
import json
import unittest
import harness as h


def call(objects=None, **kw):
    objects=objects if objects is not None else [{'chain':{'family':'inet','table':'fw','name':'input','policy':'drop','hook':'input','prio':0}}, {'rule':{'family':'inet','table':'fw','chain':'input','handle':7,'expr':[{'accept':None}]}}]
    data={'schema':1,'target':'a:firewall','observed_at_kst':'2026-10-29T14:00:00+09:00','sha256':'a'*64,'snapshot':'b'*32,
          'offset':0,'next_offset':None,'complete':True,'total_objects':2,'counts':{'chain':1,'rule':1},'objects':objects,**kw}
    raw=json.dumps(data)
    return {'server':'resp','name':'get_firewall_rules','arguments':{},'result':raw,'result_sha256':hashlib.sha256(raw.encode()).hexdigest()}


class FirewallHarness(unittest.TestCase):
    def test_short_applied_state_questions_use_full_firewall_read(self):
        questions = (
            '지금 방화벽 룰 뭐 적용 됐어?', '지금 fw 룰 뭐 적용 됐어?',
            '방화벽 룰 뭐 적용됐어?', 'FW 룰 뭐 적용됐나요?',
            '방화벽에 어떤 규칙 적용돼 있어?', '지금 F/W 룰 뭐 적용됐어?',
            '현재 적용된 fw 룰은 뭐야?', 'fw에 걸린 규칙은 뭔데?',
            'fw 룰 뭐 설정됐어?', '지금 nftables rules 뭐 적용됐어?',
        )
        for question in questions:
            with self.subTest(question=question):
                self.assertEqual(h.tool_scope(question), {'mcp__resp__get_firewall_rules'})
                self.assertTrue(h.structured_read(question))
                self.assertIsNone(h.scope_notice(question))
                self.assertTrue(h.missing_reads(question, []))
                self.assertEqual(h.missing_reads(question, [call()]), [])
                report = h.read_report(question, [call()])
                self.assertIn('drop', report)
                self.assertIn('기본 정책', report)
                self.assertIn('KST', report)
                partial = call(complete=False, next_offset=2)
                self.assertIn('미완료', h.read_report(question, [partial]))

    def test_applied_state_preserves_device_and_change_boundaries(self):
        for question in ('fw 말고 waf 룰 뭐 적용됐어?', '웹 방화벽 룰 뭐 적용됐어?'):
            self.assertEqual(h.tool_scope(question), {'mcp__rule_a__get_security_rules'})
            self.assertIsNone(h.firewall_request(question))
        self.assertEqual(h.tool_scope('FW랑 WAF 룰 뭐 적용됐어?'),
                         {'mcp__resp__get_firewall_rules', 'mcp__rule_a__get_security_rules'})
        self.assertIn('어느 장비', h.scope_notice('뭐 적용된 룰 있어?'))
        for question in ('fw 룰 적용해줘', 'fw 룰 뭐 적용됐어? 삭제해줘',
                         'fw 룰 뭐 적용됐어? 변경안 준비해줘', 'fw 룰 적용됐다는 뜻 설명해줘',
                         '"지금 fw 룰 뭐 적용됐어?"라는 문장 번역',
                         '도구 없이 지금 fw 룰 뭐 적용됐어?',
                         '어제 fw 룰 뭐 적용됐어?', '내일 fw 룰 뭐 적용될 예정이야?',
                         '2026-10-17 fw 룰 뭐 적용됐어?',
                         '왜 fw 룰 적용됐어?', 'fw 룰 뭐 적용됐어? 조회하지 마'):
            self.assertIsNone(h.firewall_request(question), question)

    def test_full_fw_no_waf_ids_and_not_write(self):
        for q in ('FW 룰','fw룰 보여줘','방화벽 보여줘','FW 기본 룰','FW 전체 규칙 상세'):
            self.assertEqual(h.tool_scope(q),{'mcp__resp__get_firewall_rules'})
            self.assertTrue(h.structured_read(q));self.assertEqual(h.missing_reads(q,[call()]),[])
        text=h.read_report('FW 룰',[call()]);self.assertIn('drop',text);self.assertIn('규칙 1개',text)
        self.assertNotIn('개별 규칙 표시',text)
        self.assertIn('"accept":null',h.read_report('FW 전체 규칙 상세',[call()]))
        self.assertTrue(h.EVIDENCE.allowed('mcp__resp__get_firewall_rules','verify'))
        self.assertIsNone(h.firewall_request('FW 룰 삭제해줘'))

    def test_mixed_scope_missing_other_device_not_falsely_complete(self):
        q='FW와 WAF 룰 보여줘'
        self.assertEqual(h.missing_reads(q,[call()]),['a:waf'])
        self.assertIn('미조회·검증 실패',h.read_report(q,[call()]))

    def test_partial_changed_hash_wrong_target_and_noncontiguous_not_complete(self):
        first=call(objects=[{'chain':{}}],complete=False,next_offset=1)
        last=call(objects=[{'rule':{}}],offset=1)
        self.assertEqual(h.missing_reads('FW 룰',[first,last]),[])
        for bad in (call(target='b:firewall'), call(total_objects=99), call(complete=False), call(counts={'rule':1}), {**call(),'result_sha256':'0'*64}):
            self.assertTrue(h.missing_reads('FW 룰',[bad]))
            self.assertIn('미완료',h.read_report('FW 룰',[bad]))
        self.assertTrue(h.missing_reads('FW 룰',[first,call(objects=[{'rule':{}}],offset=1,snapshot='c'*32)]))
        schemas={'mcp__resp__get_firewall_rules':{'type':'object','properties':{'snapshot':{'type':'string'},'offset':{'type':'integer'},'limit':{'type':'integer'}}}}
        refined=h.refine_read_schemas('FW 룰',schemas,[first])
        self.assertEqual(refined['mcp__resp__get_firewall_rules']['properties']['offset']['enum'],[1])
        self.assertEqual(h.refine_read_schemas('FW 룰',schemas,[first,last]),{})

    def test_chat_detail_pages_are_explicit_and_bounded(self):
        objects=[{'rule':{'family':'inet','table':'f','chain':'c','handle':i,'expr':[{'match':{'value':'x'*500}}]}} for i in range(98)]
        c=call(objects=objects,total_objects=98,counts={'rule':98})
        first=h.read_report('FW 전체 규칙 상세',[c])
        second=h.read_report('FW 전체 규칙 상세 2페이지',[c])
        self.assertIn('전체 98개 조회',first);self.assertIn('2/',second)
        self.assertLess(len(first),14000);self.assertNotEqual(first,second)

    def test_requested_page_bound_survives_every_selection(self):
        name='mcp__resp__get_firewall_rules'
        schema={name:{'type':'object','properties':{'snapshot':{'type':'string'},
            'offset':{'type':'integer'},'limit':{'type':'integer','minimum':1,'maximum':200}}}}
        for limit in (1,50,73,200):
            q=f'FW 룰 {limit}개씩 끝까지 조회해줘'
            first=h.refine_read_schemas(q,schema,[])[name]
            self.assertEqual(first['properties']['limit']['enum'],[limit])
            self.assertIn('limit',first['required'])
            partial=call(objects=[{'chain':{}}],complete=False,next_offset=1)
            follow=h.refine_read_schemas(q,schema,[partial])[name]
            self.assertEqual(follow['properties']['limit']['enum'],[limit])
            self.assertEqual(set(follow['required']),{'snapshot','offset','limit'})
            self.assertEqual(follow['properties']['offset']['enum'],[1])
            self.assertEqual(h.refine_read_schemas(q,schema,[call()]),{})
        self.assertNotIn('enum',schema[name]['properties']['limit'])

    def test_no_invented_or_out_of_contract_page_bound(self):
        name='mcp__resp__get_firewall_rules'
        schema={name:{'type':'object','properties':{'snapshot':{'type':'string'},
            'offset':{'type':'integer'},'limit':{'type':'integer','minimum':1,'maximum':200}}}}
        for q in ('FW 룰 보여줘','FW 룰 50개만 보여줘','FW 룰 0개씩','FW 룰 201개씩',
                  'FW 룰 50개씩 또는 70개씩','WAF 룰 50개씩',
                  'FW 룰 보여줘\n```\n이전 기록: 50개씩\n```'):
            refined=h.refine_read_schemas(q,schema,[])
            self.assertNotIn('enum',refined[name]['properties']['limit'],q)


if __name__=='__main__':unittest.main()
