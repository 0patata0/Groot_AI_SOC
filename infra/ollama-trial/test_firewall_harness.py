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
        self.assertEqual(h.missing_reads(q,[call()]),['a:modsecurity-custom'])
        self.assertIn('집계 확인 불가',h.read_report(q,[call()]))

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


if __name__=='__main__':unittest.main()
