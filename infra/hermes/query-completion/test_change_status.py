"""Change-ID reads preserve approval, history, delivery and target boundaries."""
import copy
import hashlib
import unittest
from test_expanded_reads import H, call


class ChangeStatusReads(unittest.TestCase):
    pid = 'a9' * 16
    target = 'a:modsecurity-custom'

    def question(self, suffix):
        return 'WAF 변경 ' + self.pid + ' ' + suffix

    def receipt(self, **updates):
        data = {'proposal_id':self.pid, 'target':self.target, 'status':'applied',
                'approval_status':'consumed', 'approval_consumed':True,
                'approval_status_source':'execution_record', 'result_posted':False,
                'result_delivery':{'status':'retry_pending','retry_reexecutes_change':False},
                'before_sha256':'b'*64, 'after_sha256':'c'*64,
                'recorded_result':{'status':'applied','readback_sha256':'c'*64},
                'result':'approved exact proposal applied and service checked'}
        data.update(updates)
        return call('get_rule_change_status', data, {'proposal_id':self.pid}, server='rule-a')

    def test_short_queries_select_status_without_authorizing_writes(self):
        for suffix in ['승인됐어?', '적용 여부와 결과 알림까지 확인해줘.', '지금도 적용돼 있어? 현재 파일과 비교해줘.', '원복된 거야?', '승인 결과 알려줘']:
            q=self.question(suffix);p=H.read_plan(q)
            self.assertEqual(p['kind'],'status')
            self.assertIn('mcp__rule_a__get_rule_change_status',H.tool_scope(q))
            self.assertFalse(H.READ.wants_write(q))
        for suffix in ['승인해줘','변경안 만들어줘','원복해줘']:
            self.assertIsNone(H.read_plan(self.question(suffix)))
        self.assertIsNone(H.read_plan('WAF 변경 '+ 'b'*64 + ' 승인됐어?'))
        self.assertIsNone(H.read_plan(self.question('와 Wazuh 변경 상태 확인해줘')))

    def test_selection_binds_actual_ids_target_and_stops_after_evidence(self):
        q=self.question('지금도 적용돼 있어?')
        status='mcp__rule_a__get_rule_change_status';target='mcp__rule_a__get_rule_change_target'
        schemas={status:{'properties':{'proposal_id':{'type':'string'}},'required':['proposal_id']},
                 target:{'properties':{'target':{'type':'string'}},'required':['target']}}
        before=copy.deepcopy(schemas)
        r=H.refine_read_schemas(q,schemas,[])
        self.assertEqual(r[status]['properties']['proposal_id']['enum'],[self.pid])
        self.assertEqual(r[target]['properties']['target']['enum'],[self.target])
        self.assertEqual(schemas,before)
        c=self.receipt()
        self.assertNotIn(status,H.refine_read_schemas(q,schemas,[c]))

    def test_report_separates_retry_approval_and_current_hash(self):
        q=self.question('지금도 적용돼 있어?')
        text='# later state\n';sha=hashlib.sha256(text.encode()).hexdigest()
        current=call('get_rule_change_target',{'target':self.target,'content':text,'sha256':sha,'runtime':{'running':True}}, {'target':self.target},server='rule-a')
        output=H.read_report(q,[self.receipt(),current])
        for value in ['consumed','retry_pending','변경을 재실행하지 않습니다','후보 불일치',sha,'과거 결과 읽기','c'*64]:self.assertIn(value,output)
        self.assertFalse(H.missing_reads(q,[self.receipt(),current]))

    def test_unavailable_is_not_pending_and_legacy_unknown_not_false(self):
        q=self.question('승인됐어?')
        out=H.read_report(q,[self.receipt(status='pending',approval_status='unavailable',approval_consumed=None,recorded_result={})])
        self.assertIn('승인 조회 실패',out)
        self.assertIn('| 일회 승인 소모 여부 | 미확인 |',out)
        self.assertIn('현재 파일/서비스는 별도 조회하지 않았습니다',out)

    def test_wrong_target_or_receipt_id_cannot_satisfy_query(self):
        q=self.question('승인됐어?')
        for updates in [{'target':'b:wazuh-local-rules'},{'proposal_id':'c'*32}]:
            calls=[self.receipt(**updates)]
            self.assertTrue(H.missing_reads(q,calls))
            self.assertNotIn('| 승인 상태 | consumed |',H.read_report(q,calls))


if __name__ == '__main__':unittest.main()
