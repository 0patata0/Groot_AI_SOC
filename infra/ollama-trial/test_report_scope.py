"""Keep observed IP membership distinct from unknown intervention and mode."""
import copy
import unittest
import harness as h
import test_evidence_report as f

Q='WAF·IDS 경보를 조사하고 현재 IP 임시 차단도 확인해줘.'

def context(addresses=()):
    calls=[f.call(f.MOD),f.call(f.SUR),f.call(f.BLOCK,{'blocks':list(addresses)})]
    return h.evidence_report_context(Q,calls,f.AT,(f.MOD,f.SUR,f.BLOCK)),calls

def review(basis):return {'basis':basis,'limitations':[]}

class ReportScope(unittest.TestCase):
    def test_membership_metadata_is_bound_to_the_current_receipt_and_never_proves_mode(self):
        for ips in ((),('192.0.2.1','192.0.2.2')):
            ctx,calls=context(ips);state=ctx['current_ip_inventory']
            self.assertTrue(state['requested']);self.assertEqual(state['read_state'],'observed')
            self.assertEqual(state['returned_ip_count'],len(ips));self.assertEqual(state['receipt_sha256'],calls[-1]['result_sha256'])
            self.assertIn('not_historical_request_intervention_or_feature_activation',state['scope'])

    def test_unqualified_or_explicit_current_unknown_is_rejected_for_zero_and_nonzero_membership(self):
        for ips in ((),('192.0.2.1',)):
            ctx,_=context(ips);before=copy.deepcopy(ctx)
            for text in ('전체 경보 수·백엔드 영향·차단 상태는 미확인입니다.',
                         '현재 임시 IP 차단 상태는 미확인입니다.',
                         '이번 요청에서 차단 목록은 미확인입니다.',
                         '지금 차단 목록은 아직 확인하지 못했습니다.',
                         '현재 차단 IP는 알 수 없습니다.',
                         '차단 현황이 확인되지 않았습니다.',
                         '전체 건수·영향·차단 상태는 추가 조회 필요'):
                self.assertEqual(h.evidence_report_scope_violations(review(text),ctx),['current_block_inventory_unknown_scope'],text)
            self.assertEqual(ctx,before)

    def test_limits_fields_use_the_same_scope_check(self):
        ctx,_=context();r=review('현재 조회 표본은 제한되어 있으며 실제 침해 영향은 미확인입니다.')
        r['limitations']=['차단 상태는 미확인입니다.']
        self.assertEqual(h.evidence_report_scope_violations(r,ctx),['current_block_inventory_unknown_scope'])

    def test_historical_request_mode_approval_and_impact_unknowns_remain_allowed(self):
        ctx,_=context()
        for text in ('현재 임시 IP 차단 목록은 0개이며 과거 요청 차단 상태는 미확인입니다.',
                     '어제 IP 차단 상태는 미확인입니다.',
                     'WAF의 차단 상태는 미확인입니다.',
                     'HTTP 403으로 실제 차단 상태는 확인할 수 없습니다.',
                     '차단 상태는 미확인(웹 요청 중재)입니다.',
                     '임시 차단 기능의 활성 상태는 미확인입니다.',
                     '차단 유지 승인 상태는 미확인입니다.',
                     '전체 경보 건수와 백엔드 침해 영향은 미확인입니다.'):
            self.assertEqual(h.evidence_report_scope_violations(review(text),ctx),[],text)

    def test_unrequested_or_unconfirmed_membership_is_not_assumed(self):
        ctx,_=context()
        for update in ({'requested':False},{'read_state':'unconfirmed','returned_ip_count':None}):
            before=copy.deepcopy(ctx);before['current_ip_inventory'].update(update)
            self.assertEqual(h.evidence_report_scope_violations(review('차단 상태는 미확인입니다.'),before),[])
        self.assertEqual(h.evidence_report_scope_violations(review('차단 상태는 미확인입니다.'),{}),[])

    def test_later_failure_wrong_hash_or_filtered_list_cannot_supply_known_membership(self):
        _ctx,calls=context()
        for bad in (f.call(f.BLOCK,{'error':'unavailable'},is_error=True),
                    dict(f.call(f.BLOCK),result_sha256='0'*64),f.call(f.BLOCK,arguments={'ip':'192.0.2.1'})):
            self.assertIsNone(h.evidence_report_context(Q,calls+[bad],f.AT,(f.MOD,f.SUR,f.BLOCK)))

    def test_repair_diagnostic_binds_the_observed_count_and_distinct_unknown_scopes(self):
        import json
        ctx,_=context();before=copy.deepcopy(ctx)
        msgs=h.CONTRACT.evidence_report_messages(ctx,agent_role='ollama',feedback={
            'issues':['current_block_inventory_unknown_scope'],
            'untrusted_rejected_report':review('차단 상태는 미확인입니다.')})
        check=json.loads(msgs[1]['content'])['report_validation']['current_inventory_scope_check']
        self.assertEqual(check['observed_current_inventory']['returned_ip_count'],0)
        self.assertEqual(check['observed_current_inventory']['receipt_sha256'],ctx['current_ip_inventory']['receipt_sha256'])
        self.assertEqual(len(check['not_proven_by_current_inventory_ko']),2)
        self.assertEqual(ctx,before)

    def test_explicit_model_scope_resolves_generic_uncertainty_but_never_current_inventory_unknown(self):
        ctx,calls=context();value=review('전체 건수·영향·차단 상태는 추가 조회 필요')
        value.update(unverified_blocking_scope='과거 웹 요청의 차단·거부')
        self.assertEqual(h.evidence_report_scope_violations(value,ctx),[])
        value['basis']='현재 IP 차단 목록은 미확인입니다.'
        self.assertEqual(h.evidence_report_scope_violations(value,ctx),['current_block_inventory_unknown_scope'])
        value.update(basis='실제 사건의 웹 요청 차단 여부와 영향은 현재 자료만으로 미확인입니다.',
            assessment='unresolved',evidence_tools=[f.MOD],status='needs_review',next_steps=[])
        text=h.evidence_report_text(value,calls,ctx)
        self.assertIn('판단문의 미확인 차단 범위: 과거 웹 요청의 차단·거부',text)
        self.assertIn('현재 동적 IP 목록은 별도 조회 관측값',text)

    def test_inventory_schema_requires_named_scope_or_explicit_no_uncertain_blocking_topic(self):
        from jsonschema import Draft202012Validator, ValidationError
        schema=h.CONTRACT.evidence_report_schema([f.MOD,f.BLOCK],[f.MOD,f.BLOCK],inventory_observed=True,
            read_schemas={n:{'type':'object','properties':{}} for n in (f.MOD,f.BLOCK)},direct_reads=0,allow_more=False)
        value={'more_evidence':False,'report':{'assessment':'unresolved','basis':'현재 관측한 목록과 과거 사건의 실제 영향을 구분하며 추가 근거가 필요합니다.',
            'evidence_indexes':[0,1],'limitations':['전체 사건 영향은 미확인입니다.'],'next_steps':[],'status':'needs_review'}}
        with self.assertRaises(ValidationError):Draft202012Validator(schema).validate(value)
        for scope in (None,'과거 웹 요청의 차단·거부','과거 IP 차단 이력','차단 기능의 활성 설정'):
            value['report']['unverified_blocking_scope']=scope;Draft202012Validator(schema).validate(value)
        value['report']['unverified_blocking_scope']='현재 IP 목록'
        with self.assertRaises(ValidationError):Draft202012Validator(schema).validate(value)

    def test_known_policy_annotations_are_display_only_and_cannot_conceal_arbitrary_claims(self):
        value={'basis':'현재 표본으로 침해 영향은 미확인입니다. (SOC_WORKFLOW_INVESTIGATE_V1)',
            'limitations':['HTTP 403은 차단 주체를 증명하지 않습니다. (SOC-environment-policy: 웹 백엔드 근거)',
                           '주장 (SOC-environment-policy: 실제 차단 성공)',
                           '공식 규칙 (CVE-2021-44228)'],
            'evidence_tools':[f.MOD],'machine_field':'SOC_WORKFLOW_INVESTIGATE_V1'}
        before=copy.deepcopy(value);display=h.CONTRACT.report_display(value)
        self.assertEqual(display['basis'],'현재 표본으로 침해 영향은 미확인입니다.')
        self.assertEqual(display['limitations'][0],'HTTP 403은 차단 주체를 증명하지 않습니다.')
        self.assertEqual(display['limitations'][1:],value['limitations'][1:])
        self.assertEqual(display['machine_field'],value['machine_field']);self.assertEqual(value,before)

class ScopeRuntime(unittest.TestCase):
    def execute(self,plans):
        import test_runtime
        fixture=test_runtime.PreparationLoop()
        result,prompts,calls=fixture.execute(question='WAF 경보 조사하고 현재 IP 임시 차단도 확인해줘.',
            read_incident=True,compact_plans=plans,
            selector_plans=[{'calls':[{'tool':f.MOD,'arguments':{'target':'fixture'}},{'tool':f.BLOCK,'arguments':{}}]}],
            read_fixtures={f.BLOCK:({'type':'object','properties':{},'additionalProperties':False},lambda _:{'blocks':[]})})
        return fixture,result,prompts,calls

    def test_unknown_scope_is_corrected_in_the_same_phase_without_another_read(self):
        from test_evidence_runtime import report
        bad=report((0,1),basis='현재 경보 표본만으로 실제 침해 영향과 차단 상태는 미확인입니다.')
        good=report((0,1),basis='현재 임시 IP 차단 목록은 0개이며 과거 요청 차단과 실제 침해 영향은 미확인입니다.')
        bad['report']['unverified_blocking_scope']=None
        good['report']['unverified_blocking_scope']='과거 웹 요청의 차단·거부'
        fixture,result,prompts,calls=self.execute([bad,good])
        self.assertEqual(calls,['search_modsecurity_alerts','list_blocks']);self.assertEqual(prompts,[])
        self.assertEqual(result['evidence_claim_repairs'],1);self.assertEqual(result['protected_calls'],0)
        self.assertFalse(result.get('remaining_issues'));self.assertEqual(result['status'],'partial')
        self.assertIn('current_block_inventory_unknown_scope',result['evidence_report_audit'][0]['issues'])
        self.assertEqual(result['last_evidence_review']['basis'],good['report']['basis'])

    def test_persistent_unknown_does_not_publish_a_fake_judgment_or_repeat_reads(self):
        from test_evidence_runtime import report
        bad=report((0,1),basis='현재 경보 표본만으로 실제 침해 영향과 차단 상태는 미확인입니다.')
        bad['report']['unverified_blocking_scope']=None
        _,result,_,calls=self.execute([bad])
        self.assertEqual(calls,['search_modsecurity_alerts','list_blocks'])
        self.assertEqual(result['stop_reason'],'evidence_report_claim_repair_budget_exhausted')
        self.assertNotIn(bad['report']['basis'],result['final_response']);self.assertEqual(result['protected_calls'],0)

if __name__=='__main__':unittest.main()
