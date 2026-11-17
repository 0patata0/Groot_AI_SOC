"""Requested web investigations use existing, scope-bound reads, not route guesses."""
import copy
import json
from pathlib import Path
import sys
import unittest
from jsonschema import Draft202012Validator, ValidationError
import harness as h
import test_evidence_report as r
sys.path.insert(0,str(next(p for p in Path(__file__).parents if p.name=='infra')/'hermes'))
import test_soc_management_bundle as f

Q='WAF와 IDS 공격 경보를 조사해줘. 웹 요청이 실제 차단됐는지 근거로 구분하고 현재 임시 IP 차단도 확인해줘.'
MOD=r.MOD;BUNDLE=h.EVIDENCE.BUNDLE_TOOL
WEB='mcp__security_events__search_web_access'
TARGET='mcp__security_events__get_web_service_target'

def event(paths=('/dvwa/login.php',),ip=f.IP,window=None):
    args={**(f.WINDOW if window is None else window),'source_ip':ip}
    data=f.read('search_modsecurity_alerts',args)
    data['alerts']=[{**data['alerts'][0],'source_ip':ip,'request_path':p} for p in paths]
    data['returned_count']=len(paths)
    return r.call(MOD,data,arguments=args)

def reader(paths=('/dvwa/login.php',),failure=None):
    def read(name,args):
        if name==failure:raise OSError('private detail')
        data=f.read(name,args)
        if name=='search_modsecurity_alerts':
            data['alerts']=[{**data['alerts'][0],'source_ip':args['source_ip'],'request_path':p} for p in paths]
        if name=='search_web_access':data['records']=[]
        return data
    return read

def bundle(paths=('/dvwa/login.php',),ip=f.IP,window=None,failure=None):
    window=dict(f.WINDOW if window is None else window)
    args={'events':[{'sensor':'modsecurity','arguments':{**window,'source_ip':ip}}],'web_context':window}
    return r.call(BUNDLE,f.fixture(args,reader(paths,failure)),arguments=args)

def initial(paths=('/dvwa/login.php',)):
    return [event(paths),r.call(r.SUR,f.read('search_suricata_alerts',f.WINDOW),arguments=f.WINDOW),r.call(r.BLOCK)]

def decision(assessment='unresolved'):
    return ('INCIDENT_DISPOSITION: '+json.dumps({'assessment':assessment,
        'basis':'실제 조회한 반환 표본과 한계를 구분했으며 사건 영향은 별도 근거로 판단해야 합니다.',
        'evidence_tools':[MOD]},ensure_ascii=False)+'\nMANAGEMENT_STATUS: '+
        ('needs_review' if assessment=='unresolved' else 'resolved'))

class WebScope(unittest.TestCase):
    def test_nominal_waf_block_observation_is_not_proved_by_response_or_other_unknown_clause(self):
        for line in ('WAF 차단 관측은 있으나 백엔드 영향은 미확인입니다.',
                     'WAF 차단 기록이 확인됐습니다. 다른 결과는 판단할 수 없습니다.'):
            self.assertIn('waf_intervention_unverified_by_event_fields',h.incident_field_violations(line,initial()),line)
        for line in ('WAF 차단 관측은 미확인입니다.',
                     'WAF 차단 관측이 있음을 증명하지 않습니다.',
                     'WAF 차단 기록이 있다고 단정할 수 없습니다.'):
            self.assertNotIn('waf_intervention_unverified_by_event_fields',h.incident_field_violations(line,initial()),line)

    def test_nominalized_block_proof_negation_is_not_a_positive_http_outcome(self):
        for line in ('WAF 경보의 HTTP 403은 응답 코드일 뿐 WAF가 요청을 차단했음을 증명하지 않음.',
                     'HTTP 403은 WAF가 요청을 차단했음을 증명하지 않습니다.'):
            self.assertNotIn('http_status_used_as_security_outcome',h.incident_field_violations(line,initial()),line)
        for line in ('HTTP 403은 WAF가 요청을 차단했음을 증명합니다.',
                     'HTTP 403은 WAF가 요청을 차단했음을 증명하지 않는 것은 아닙니다.'):
            self.assertIn('http_status_used_as_security_outcome',h.incident_field_violations(line,initial()),line)

    def test_explicit_request_needs_additional_read_after_initial_sensor_and_inventory_reads(self):
        calls=initial();before=copy.deepcopy(calls)
        state=h.requested_web_evidence(Q,calls)
        self.assertTrue(state['requested']);self.assertEqual(len(state['pending']),1)
        self.assertEqual(state['pending'][0]['source_ip'],f.IP)
        self.assertEqual(h.incident_required_read_gaps(Q,calls),{BUNDLE})
        self.assertIsNone(h.evidence_report_context(Q,calls,r.AT,(MOD,r.SUR,r.BLOCK,BUNDLE)))
        self.assertIn(f.IP,' '.join(h.missing_reads(Q,calls)))
        self.assertEqual(calls,before)

    def test_unrequested_prohibited_quoted_or_write_scope_does_not_add_reads(self):
        for q in ('WAF와 IDS 공격 경보를 조사하고 출발지를 비교해줘.',
                  'WAF 공격 경보 조사. 웹 요청의 실제 차단 근거 확인은 제외해줘.',
                  '"웹 요청이 실제 차단됐는지 조사해줘"라는 예시 말고 WAF 경보만 조사해줘.',
                  Q+' IP 차단해줘.'):
            self.assertFalse(h.requested_web_evidence(q,initial())['requested'],q)

    def test_arguments_remain_paired_by_observed_actor_and_actual_window(self):
        other={**f.WINDOW,'since_kst':'2026-11-05T20:11:00+09:00','until_kst':'2026-11-05T20:11:59+09:00'}
        calls=[event(),event(ip='192.0.2.99',window=other)]
        before=copy.deepcopy(calls);original={BUNDLE:f.b.tool()['inputSchema']}
        narrowed=h.web_evidence_read_schemas(Q,original,calls)
        validator=Draft202012Validator(narrowed[BUNDLE]);branches=narrowed[BUNDLE]['anyOf']
        self.assertEqual(len(branches),2)
        for ip,window in ((f.IP,f.WINDOW),('192.0.2.99',other)):
            args=bundle(ip=ip,window=window)['arguments'];validator.validate(args)
            Draft202012Validator(original[BUNDLE]).validate(args)
            args['events'][0]['arguments']['source_ip']='192.0.2.99' if ip==f.IP else f.IP
            with self.assertRaises(ValidationError):validator.validate(args)
        self.assertEqual(calls,before)
        self.assertNotIn('c:log4shell',json.dumps(narrowed))

    def test_selection_rejects_missing_web_window_changed_period_and_protected_member(self):
        schemas=h.web_evidence_read_schemas(Q,{BUNDLE:f.b.tool()['inputSchema']},initial())
        schema=h.selection_schema(schemas,8,question=Q)
        good={'calls':[{'tool':BUNDLE,'arguments':bundle()['arguments']}]}
        self.assertEqual(h.validated_selection(good,schema)[0],good)
        changes=(lambda p:p['calls'][0]['arguments'].pop('web_context'),
                 lambda p:p['calls'][0]['arguments']['web_context'].update(until_kst='2026-11-05T22:00:00+09:00'),
                 lambda p:p['calls'].append({'tool':'mcp__resp__block_ip','arguments':{'ip':f.IP}}))
        for change in changes:
            bad=copy.deepcopy(good);change(bad)
            with self.assertRaises(ValidationError):h.validated_selection(bad,schema)

    def test_valid_bundle_supplies_attempts_without_mutating_wire_or_proving_routing(self):
        calls=initial()+[bundle()];before=copy.deepcopy(calls)
        state=h.requested_web_evidence(Q,calls);s=state['scopes'][0]
        self.assertFalse(state['pending']);self.assertTrue(s['attempted']);self.assertFalse(s['errors'])
        self.assertEqual({q['target'] for q in s['queries']},{'c:dvwa'})
        self.assertEqual(s['unmapped_path_hints'],[])
        self.assertEqual(calls,before);self.assertNotIn('verified_route',json.dumps(state))
        context=h.evidence_report_context(Q,calls,r.AT,(MOD,r.SUR,r.BLOCK,BUNDLE))
        self.assertIsNotNone(context);self.assertEqual(context['requested_web_evidence'],state)

    def test_configuration_unmapped_path_survives_execution_complete_and_cannot_close_incident(self):
        paths=('/dvwa/login.php','/log4shell/')
        calls=initial(paths)+[bundle(paths)]
        self.assertTrue(json.loads(calls[-1]['result'])['execution_complete'])
        state=h.requested_web_evidence(Q,calls)
        self.assertFalse(state['pending'])
        self.assertEqual(state['scopes'][0]['unmapped_path_hints'],['/log4shell/'])
        self.assertEqual(h.incident_completion_issues(Q,decision(),calls),[])
        self.assertIn('requested_web_impact_scope_unverified',h.incident_completion_issues(Q,decision('remediated'),calls))
        context=h.evidence_report_context(Q,calls,r.AT,(MOD,r.SUR,r.BLOCK,BUNDLE))
        output=h.add_evidence_source_comparison(context,'원문 표와 모델 판단')
        self.assertIn('/log4shell/',output);self.assertIn('설정 대응·접근 근거 미확인',output)
        self.assertIn('증명이 아닙니다',output)
        self.assertEqual(h.add_evidence_source_comparison(context,output),output)

    def test_root_partial_and_invalid_provenance_failures_are_attempts_not_success_or_blind_retry(self):
        for call in (bundle(failure='search_web_access'),r.call(BUNDLE,{'error':'unavailable'},arguments=bundle()['arguments'],is_error=True)):
            calls=initial()+[call];state=h.requested_web_evidence(Q,calls)
            self.assertFalse(state['pending']);self.assertTrue(state['scopes'][0]['errors'])
            self.assertIn('requested_web_impact_scope_unverified',h.incident_completion_issues(Q,decision('benign'),calls))
        bad=bundle();data=json.loads(bad['result']);data['components'][0]['arguments']['source_ip']='192.0.2.99'
        bad=r.call(BUNDLE,data,arguments=bad['arguments'])
        state=h.requested_web_evidence(Q,initial()+[bad])
        self.assertFalse(state['pending']);self.assertIn('web_collection_provenance_invalid',state['scopes'][0]['errors'])

    def test_wrong_hash_actor_or_window_cannot_supply_requested_read_coverage(self):
        for bad in (dict(bundle(),result_sha256='0'*64),bundle(ip='192.0.2.99',failure='search_web_access'),
                    bundle(window={**f.WINDOW,'until_kst':'2026-11-05T22:00:00+09:00'})):
            self.assertTrue(h.requested_web_evidence(Q,initial()+[bad])['pending'])

    def test_same_unfiltered_backend_scope_can_be_reused_without_attributing_records_to_an_actor(self):
        state=h.requested_web_evidence(Q,initial()+[bundle(ip='192.0.2.99')])
        self.assertFalse(state['pending'])
        self.assertEqual({s['source_ip'] for s in state['scopes']},{f.IP,'192.0.2.99'})
        self.assertTrue(all(q['source']=='direct_configuration_and_access_reads' for s in state['scopes'] for q in s['queries']))
        self.assertIn('not_waf_intervention',state['scope'])

    def test_latest_failed_same_bundle_invalidates_prior_success(self):
        good=bundle();bad=r.call(BUNDLE,{'error':'unavailable'},arguments=good['arguments'],is_error=True)
        state=h.requested_web_evidence(Q,initial()+[good,bad]);s=state['scopes'][0]
        self.assertFalse(state['pending']);self.assertFalse(s['queries']);self.assertTrue(s['errors'])

    def test_latest_failed_underlying_query_in_a_different_parent_invalidates_old_success(self):
        args=bundle()['arguments'];args['diagnostics']=[{'target':'c:apache'}]
        bad=r.call(BUNDLE,f.fixture(args,reader(failure='search_web_access')),arguments=args)
        state=h.requested_web_evidence(Q,initial()+[bundle(),bad]);s=state['scopes'][0]
        self.assertFalse(state['pending']);self.assertFalse(s['queries']);self.assertTrue(s['errors'])

    def test_missing_paths_or_valid_event_scope_cannot_become_benign(self):
        calls=initial(())
        self.assertEqual(h.requested_web_evidence(Q,calls)['scopes'],[])
        self.assertIn('requested_web_impact_scope_unverified',h.incident_completion_issues(Q,decision('benign'),calls))
        self.assertIn('범위를 확정하지 못했습니다',h.add_evidence_source_comparison(
            {'question':Q,'derived_sample_source_sets':[],'requested_web_evidence':h.requested_web_evidence(Q,calls)},'본문'))
        wazuh='mcp__security_events__search_wazuh_alerts'
        calls=[r.call(wazuh,{'source':'wazuh','alerts':[]})]
        self.assertIn('requested_web_impact_scope_unverified',h.incident_completion_issues(
            Q,decision('benign').replace(MOD,wazuh),calls))

    def test_direct_config_and_unfiltered_access_reads_can_satisfy_attempt_without_bundle(self):
        args={'target':'c:dvwa',**f.WINDOW};read=reader()
        config=r.call(TARGET,read('get_web_service_target',{'target':'c:dvwa'}),arguments={'target':'c:dvwa'})
        access=r.call(WEB,read('search_web_access',args),arguments=args)
        calls=initial()+[config,access]
        self.assertFalse(h.requested_web_evidence(Q,calls)['pending'])
        changes=(lambda c:c['arguments'].update(source_ip=f.IP),
                 lambda c:c['arguments'].update(until_kst='2026-11-05T22:00:00+09:00'),
                 lambda c:c['arguments'].update(target='c:lab-java'),
                 lambda c:c.update(result_sha256='0'*64))
        for change in changes:
            bad=copy.deepcopy(access);change(bad)
            self.assertTrue(h.requested_web_evidence(Q,initial()+[config,bad])['pending'])

class WebRuntime(unittest.TestCase):
    def test_several_new_read_batches_are_progress_with_existing_total_budgets(self):
        import test_runtime
        from test_evidence_runtime import report
        actors={f.IP:'/dvwa/login.php','192.0.2.99':'/_offline-lab-java/index',
                '192.0.2.199':'/_offline-lab-httpd49/index'}
        base=f.read('search_modsecurity_alerts',f.WINDOW)
        base['alerts']=[{**base['alerts'][0],'source_ip':ip,'request_path':p} for ip,p in actors.items()]
        def collect(args):return f.fixture(args,reader((actors[args['events'][0]['arguments']['source_ip']],)))
        interval={k:{'type':'integer','minimum':1,'maximum':50} if k=='limit' else {'type':'string'} for k in f.WINDOW}
        event_schema={'type':'object','properties':interval,'required':list(interval),'additionalProperties':False}
        fixtures={MOD:(event_schema,lambda _:copy.deepcopy(base)),
            r.SUR:(event_schema,lambda _:f.read('search_suricata_alerts',f.WINDOW)),
            r.BLOCK:({'type':'object','properties':{},'additionalProperties':False},lambda _:{'blocks':[]}),
            BUNDLE:(f.b.tool()['inputSchema'],collect)}
        plans=[{'calls':[{'tool':n,'arguments':{} if n==r.BLOCK else dict(f.WINDOW)} for n in (MOD,r.SUR,r.BLOCK)]}]
        plans.extend({'calls':[{'tool':BUNDLE,'arguments':bundle((path,),ip)['arguments']}]} for ip,path in actors.items())
        fixture=test_runtime.PreparationLoop()
        answer=report((0,1,2,3));answer['report']['unverified_blocking_scope']=None
        result,prompts,calls=fixture.execute(question=Q,read_incident=True,compact_plans=[answer],
            selector_plans=plans,read_fixtures=fixtures)
        self.assertEqual(calls,['search_modsecurity_alerts','search_suricata_alerts','list_blocks']+['collect_incident_evidence']*3)
        self.assertEqual(len(fixture.selector_prompts),4);self.assertEqual(prompts,[])
        self.assertEqual(result['status'],'partial');self.assertEqual(result['protected_calls'],0)
        self.assertFalse(result.get('unqueried'));self.assertFalse(result.get('remaining_issues'))
        self.assertEqual(result['incident_read_batches'],3)
        self.assertFalse(h.requested_web_evidence(Q,result['calls'])['pending'])
        context=json.loads(fixture.compact_prompts[0][1]['content'])
        self.assertEqual(len(context['untrusted_completed_reads']),6)
        self.assertEqual(len(context['requested_web_evidence']['scopes']),3)

if __name__=='__main__':unittest.main()
