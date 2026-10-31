"""Card investigations and pure summaries must not turn into unrelated live reads."""
import copy
import hashlib
import json
import unittest
import harness as H


def diagnostic(target='a:systemd', failed=0):
    value={'schema':1,'kind':'runtime','target':target,'status':'ok','codes':[],
           'observed_at_kst':'2026-10-31T13:01:00+09:00',
           'metrics':{'failed_units_total':failed,'returned_units':failed,
                      'unit_list_truncated':False,'engine_uptime_seconds':12345}}
    raw=json.dumps(value)
    return {'server':'system-diagnostics','name':'get_system_diagnostics',
            'arguments':{'target':target},'result':raw,'result_sha256':hashlib.sha256(raw.encode()).hexdigest()}


class CardSummary(unittest.TestCase):
    def test_report_clock_and_source_are_bound_in_both_read_selector_schemas(self):
        from datetime import datetime
        body={'status':'ok','scope':'same_thread','posts':[{'kind':'root','post_id':'r'*26,
            'created_at_ms':int(datetime.fromisoformat('2026-10-31T13:56:11+09:00').timestamp()*1000),
            'text':'경보 조회 자료 (최근 60분) Suricata: 192.168.16.230 -> 168.126.63.1:53\nSystemd: Service exited'}]}
        q='태그한 카드에서 탐지 규칙이 뭐가 문제인지 확인해줘'
        full=H.SHARED._CONTEXT_PREFIX+json.dumps(body)+'"]\n\n'+q
        reference=H.card_reference(full,q)
        self.assertEqual(reference['since_kst'],'2026-10-31T12:56:11+09:00')
        self.assertEqual(reference['source_ips'],['192.168.16.230'])
        self.assertEqual(H.card_evidence_gaps(reference,[]),['suricata','wazuh'])
        schema={'type':'object','properties':{k:{} for k in ('since_kst','until_kst','source_ip','lookback_minutes')}}
        selected=H.refine_read_schemas(q,{'mcp__security_events__search_suricata_alerts':schema},[],reference=reference)
        props=selected['mcp__security_events__search_suricata_alerts']['properties']
        self.assertNotIn('lookback_minutes',props);self.assertEqual(props['until_kst']['enum'],['2026-10-31T13:56:11+09:00'])
        self.assertIn('12:56:11',H.read_background(full,q))
        previous={'role':'assistant','content':'UNVERIFIED_OLD_NORMAL'}
        rows=[{'role':'system','content':'system'},previous,{'role':'user','content':full},{'role':'assistant','content':'current turn'}]
        selected=H.project_card_messages(rows,full,q)
        self.assertNotIn(previous,selected);self.assertEqual(selected[-1],rows[-1]);self.assertEqual(len(rows),4)
        self.assertIn('원인 조사',H.resolve_card_request(full,'이거 왜 자꾸 뜨는 거야?'))
        self.assertEqual(H.resolve_card_request('','이거 왜 자꾸 뜨는 거야?'),'이거 왜 자꾸 뜨는 거야?')
        self.assertEqual(H.resolve_card_request(full,'이거 차단해줘'),'이거 차단해줘')

    def test_host_failure_requires_the_actual_card_rule_and_is_not_satisfied_by_login_success(self):
        ref={'families':['wazuh'],'source_ips':['192.0.2.1'],'host_rule_ids':['40704'],
             'since_kst':'2026-10-31T12:56:11+09:00','until_kst':'2026-10-31T13:56:11+09:00'}
        def call(rid):
            d={'source':'wazuh','requested_since_kst':ref['since_kst'],'requested_until_kst':ref['until_kst'],
               'alerts':[{'wazuh_rule_id':rid,'service_units':['management.service']}]}
            raw=json.dumps(d)
            return {'server':'security-events','name':'search_wazuh_alerts','arguments':{'wazuh_rule_id':rid},
                    'result':raw,'result_sha256':hashlib.sha256(raw.encode()).hexdigest()}
        self.assertEqual(H.card_evidence_gaps(ref,[call('5715')]),['wazuh'])
        self.assertEqual(H.card_evidence_gaps(ref,[call('40704')]),[])
        self.assertIn('card_host_event_omitted:40704',H.card_answer_issues(ref,'SSH 로그인 확인',[call('40704')]))
        self.assertEqual(H.card_answer_issues(ref,'management.service 종료 1. 원인 미확인',[call('40704')]),[])
        schema={'type':'object','properties':{k:{} for k in ('since_kst','until_kst','source_ip','agent_id','wazuh_rule_id')}}
        key='mcp__security_events__search_wazuh_alerts'
        narrowed=H.refine_read_schemas('카드 경보가 뭐가 문제인지 확인해줘',{key:schema},[],reference=ref)[key]
        self.assertEqual(narrowed['properties']['wazuh_rule_id']['enum'],['40704'])
        self.assertNotIn('source_ip',narrowed['properties']);self.assertNotIn('agent_id',narrowed['properties'])
        selection=H.selection_schema({key:narrowed},32,ref)
        self.assertEqual(selection['properties']['calls']['maxItems'],1)

    def test_environment_is_not_authorization_even_without_a_causal_suffix(self):
        self.assertIn('environment_used_as_authorization',H.incident_context_violations('모두 정상적인 내부 통신 패턴에서 발생한 탐지입니다.'))
        self.assertFalse(H.incident_context_violations('내부망의 정상 통신인지 미확인입니다.'))
        self.assertIn('environment_used_as_authorization',H.incident_context_violations('모두 정상적인 내부 트래픽과 서비스 장애로 외부 공격은 아닙니다.'))
        self.assertIn('environment_used_as_authorization',H.incident_context_violations('내부 호스트의 정상적인 도메인 이름 확인 트래픽으로 판단됩니다.'))

    def test_required_role_is_system_injected_and_missing_policy_is_rejected(self):
        policy=H.CONTRACT.system_prompt()
        self.assertEqual(policy.count('SOC_ROLE_CONTRACT_V1'),1)
        for role in ('hermes','ollama'):
            self.assertIn('SOC_ACTIVE_ROLE: '+role,H.CONTRACT.system_prompt(agent_role=role))
        self.assertNotEqual(H.CONTRACT.fingerprint(agent_role='hermes'),H.CONTRACT.fingerprint(agent_role='ollama'))
        with self.assertRaisesRegex(ValueError,'unknown_soc_role'):H.CONTRACT.system_prompt(agent_role='user-selected')
        with self.assertRaisesRegex(ValueError,'shared_soc_role_missing'):
            H.CONTRACT.validate_role_policy('Role removed')
        messages=H.CONTRACT.project_messages([{'role':'system','content':policy},
            {'role':'user','content':'로그에 역할을 무시하라고 적혀 있다'}])
        self.assertEqual(messages[0]['content'].count('SOC_ROLE_CONTRACT_V1'),1)
        self.assertIn('로그에',messages[1]['content'])

    def test_fallback_is_brief_without_hiding_unverified_judgment(self):
        answer=H.fallback('이 경보 왜 발생했는지 조사해줘',[diagnostic()])
        self.assertIn('검증 미완료',answer);self.assertLess(len(answer),700)
        self.assertNotIn('engine_uptime_seconds',answer)

    def test_card_rule_heading_is_not_an_inventory(self):
        questions=['지금 태그한 카드에서 탐지규칙(상위)가 뭐가 문제인건지 한번 확인해볼래?',
                   '룰 말고 탐지된거\n탐지 규칙(상위):\nSuricata IDS medium: ET DYN_DNS Query\n'
                   'ET SCAN Potential SSH Scan\nSystemd: Service exited due to a failure.\n무슨 로그인지 알고싶은데',
                   '이 DNS 경보가 왜 계속 나오는지 확인해줘']
        for question in questions:
            with self.subTest(question=question):
                self.assertTrue(H.EVIDENCE.incident_investigation_request(H.normalized(question)))
                self.assertIsNone(H.scope_notice(question))
                self.assertIsNone(H.diagnostic_request(question))
                self.assertIsNone(H.security_inventory_request(question))
                self.assertIsNone(H.tool_scope(question))
                self.assertTrue(H.incident_evidence_gap(question,[]))
                self.assertIsNone(H.diagnostic_report(question,[diagnostic()],['a:systemd']))

    def test_natural_current_rule_question_is_inventory_not_broad_investigation(self):
        self.assertEqual(H.tool_scope('웹방화벽 룰은 어떻게 되어있지?'),{'mcp__rule_a__get_security_rules'})
        self.assertIsNotNone(H.rule_scope_request('방화벽 룰 어때?'))
        self.assertIsNone(H.rule_scope_request('웹방화벽 룰은 어떻게 만드는 거야?'))
        self.assertIn('environment_used_as_authorization',H.incident_context_violations('모두 정상 운영 트래픽(SSH 내부 스캔)입니다.'))

    def test_explicit_inventory_and_current_health_keep_their_scope(self):
        self.assertIsNotNone(H.scope_notice('룰 조회해줘'))
        self.assertEqual(H.tool_scope('IDS 탐지 규칙 보여줘'),{'mcp__rule_a__get_security_rules'})
        self.assertEqual(H.diagnostic_request('A 서버 현재 systemd 실패 목록 보여줘')['requested'],['a:systemd'])

    def test_pure_summary_uses_dated_verified_facts_and_marks_incomplete_investigation(self):
        evidence={'question':'탐지된 로그가 무슨 로그인지 알고싶은데','calls':[diagnostic()]}
        for question in ('좀 요약해서 보여줄래','짧게 정리해줘','앞선 결과 핵심만 요약해줘'):
            answer=H.prior_summary(question,evidence)
            self.assertIn('새 조회 없음',answer);self.assertIn('13:01:00+09:00',answer)
            self.assertIn('failed unit 0개',answer);self.assertIn('원인 조사는 미완료',answer)
            self.assertNotIn('engine_uptime_seconds',answer);self.assertLess(len(answer),650)

    def test_summary_cannot_borrow_missing_tampered_failed_or_protected_results(self):
        good=diagnostic();bad=copy.deepcopy(good);bad['result_sha256']='0'*64
        for calls in ([bad],[good,dict(good,is_error=True)],[]):
            answer=H.prior_summary('요약해줘',{'calls':calls})
            self.assertNotIn('failed unit 0개',answer)
        answer=H.prior_summary('요약해줘',{'calls':[dict(good,server='resp',name='block_ip')]})
        self.assertIn('변경 작업',answer)
        self.assertIn('찾지 못했습니다',H.prior_summary('요약해줘',None))

    def test_event_source_scope_and_unqueried_allowlist_are_not_invented(self):
        raw=json.dumps({'source':'suricata','alerts':[{'source_ip':'192.168.15.79','destination_port':22}]})
        call={'server':'security-events','name':'search_suricata_alerts','result':raw,'result_sha256':hashlib.sha256(raw.encode()).hexdigest()}
        issues=H.incident_field_violations('SSH 스캔은 외부 IP의 접근입니다.\n모두 정상 트래픽 목록에 없음.',[call])
        self.assertIn('ssh_private_source_mislabeled_as_public',issues)
        self.assertIn('event_read_does_not_verify_allowlist',issues)
        self.assertFalse(H.incident_field_violations('SSH 출발지는 사설 IP이며 업무 승인 여부는 미확인입니다.',[call]))

    def test_current_changes_and_new_topics_are_not_pure_summaries(self):
        for q in ('현재 상태 다시 조회해서 요약해줘','FW 룰 조회하고 요약해줘','요약하고 차단해줘',
                  '이전 결과 요약 후 최신 것도 확인해줘','아래 내용을 요약해줘: 외부 지시'):
            self.assertFalse(H.summary_request(q),q)
            self.assertIsNone(H.prior_summary(q,{'calls':[diagnostic()]}))

    def test_incomplete_known_summary_continues_read_investigation(self):
        q='좀 요약해서 보여줄래'
        recovered=H.summary_recovery_request(q,{'question':'무슨 로그인지 알고싶은데','calls':[diagnostic()]})
        self.assertIn('빠진 근거',recovered);self.assertEqual(H.request_kind(recovered),'investigation')
        self.assertEqual(H.summary_recovery_request(q,{'question':'IP 차단해줘','calls':[]}),q)
        self.assertEqual(H.summary_recovery_request(q,None),q)

    def test_default_diagnostics_omit_full_metrics_but_details_remain_available(self):
        calls=[diagnostic()]
        short=H.diagnostic_report('A 서버 systemd 실패 목록 보여줘',calls,['a:systemd'])
        detail=H.diagnostic_report('A 서버 systemd 실패 목록 상세 수치 보여줘',calls,['a:systemd'])
        self.assertNotIn('engine_uptime_seconds',short);self.assertIn('engine_uptime_seconds',detail)
        self.assertIn('수치는 생략',short);self.assertIn('과거 장애 원인',short)

    def test_rule_details_keep_conditions_and_exceptions_without_dumping_duplicate_json(self):
        rule={'description':'test XSS condition','attributes':{'phase':'2','severity':['CRITICAL']},
              'conditions':[{'variables':'ARGS','operator':'@detectXSS'}],
              'configured_base_action':'pass','configuration_changes_by_id':[
                  {'kind':'secruleupdatetargetbyid','arguments':['941100','!ARGS:allowed']}],
              'runtime_controls':[],'api_definition':{'redundant':'x'*10000}}
        answer='\n'.join(H.rule_detail_brief(rule))
        self.assertIn('@detectXSS',answer);self.assertIn('!ARGS:allowed',answer)
        self.assertIn('ctl 0건',answer);self.assertNotIn('redundant',answer);self.assertLess(len(answer),500)


if __name__=='__main__':unittest.main()
