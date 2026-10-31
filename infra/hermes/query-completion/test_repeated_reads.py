"""Adversarial scope and evidence regressions from repeated live comparisons."""
import copy
from dataclasses import dataclass
import hashlib
import json
from types import SimpleNamespace
import unittest
try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None
import alignment
from test_alignment import H
from test_completion import PLUGIN
from test_expanded_reads import call
from test_inventory_render import payload, FILES

MULTI = '보안 서버와 서비스 서버의 프로세스와 TCP LISTENING 포트를 각각 최대 3개 조회해줘. 변경·차단·재시작은 하지 마.'
COMBINED = 'WAF·IDS·Wazuh 커스텀 파일 규칙 개수와 IDS가 local.rules를 실제 사용하는지 함께 조회해줘.'
POLICY = '보호된 DGX 차단 요청은 왜 거절하는지 정책 근거만 설명해줘. 조회나 차단 도구는 호출하지 마.'
NAMES = ('groot-sec', 'groot-web')
IDS = ('019', '017')


def identity():
    return call('get_wazuh_agents', '\n'.join(f'Agent ID: {i}\nName: {n}\nStatus: ACTIVE\nIP: 192.0.2.{i[-2:]}\nLast Keep Alive: 2026-10-25T10:00:00Z' for i, n in zip(IDS, NAMES)), {'status': 'active'})


def process(agent, count=3):
    return call('get_wazuh_agent_processes', '\n'.join(f'PID: {i}\nName: p{i}\nState: S\nStart Time: 2026-10-25T10:00:00Z' for i in range(count)), {'agent_id': agent, 'limit': count})


def port(agent, protocol='tcp'):
    return call('get_wazuh_agent_ports', f'Protocol: {protocol}\nLocal: 127.0.0.1:22\nState: listening\nProcess Name: sshd\nPID: 1', {'agent_id': agent, 'protocol': protocol, 'state': 'LISTENING', 'limit': 3})


def schemas():
    return {
        H.READ.AGENTS: {'type':'object','properties':{'status':{'type':'string'},'name':{'type':'string'},'limit':{'type':'integer'}},'required':['status']},
        H.READ.WAZUH+'get_wazuh_agent_processes': {'type':'object','properties':{'agent_id':{'type':'string'},'limit':{'type':'integer'}},'required':['agent_id']},
        H.READ.WAZUH+'get_wazuh_agent_ports': {'type':'object','properties':{'agent_id':{'type':'string'},'limit':{'type':'integer'},'protocol':{'type':'string'},'state':{'type':'string'}},'required':['agent_id']}}


class RepeatedReads(unittest.TestCase):
    def test_subject_predicates_and_distinct_limits_are_bound_without_cross_product(self):
        q='보안 서버에서는 프로세스를 최대 4개, 서비스 서버에서는 TCP ESTABLISHED 포트를 최대 7개 조회해줘.'
        p=H.read_plan(q);a,c=p['plans']
        self.assertEqual((a['agent_name'],a['features'],a['limit']),('groot-sec',['get_wazuh_agent_processes'],4))
        self.assertEqual((c['agent_name'],c['features'],c['limit']),('groot-web',['get_wazuh_agent_ports'],7))
        self.assertEqual(H.READ.port_filters(c),{'protocol':'tcp','state':'ESTABLISHED'})
        selected=H.refine_read_schemas(q,schemas(),[identity()])
        self.assertEqual(selected[H.READ.WAZUH+'get_wazuh_agent_processes']['properties']['agent_id']['enum'],['019'])
        self.assertEqual(selected[H.READ.WAZUH+'get_wazuh_agent_ports']['properties']['agent_id']['enum'],['017'])
        self.assertTrue(H.missing_reads(q,[identity(),process('017',4)]))

    def test_multiple_literal_ids_are_each_required_and_visible(self):
        q='에이전트 ID 041과 ID 087의 프로세스를 각각 최대 3개 조회해줘'
        p=H.read_plan(q);self.assertEqual([x['agent_id'] for x in p['plans']],['041','087'])
        calls=[process('041')]
        self.assertTrue(any('087' in s for s in H.missing_reads(q,calls)))
        self.assertIn('전체 확인 완료가 아닙니다',H.read_report(q,calls))
        self.assertEqual(H.missing_reads(q,calls+[process('087')]),[])

    def test_exclusions_do_not_add_work_or_erase_write_intent(self):
        q='보안 서버 TCP 포트 최대 7개 조회해줘. 서비스 서버는 이번 대상에서 제외해줘.'
        p=H.read_plan(q);self.assertEqual(p['agent_name'],'groot-sec');self.assertNotEqual(p['kind'],'multi')
        q='WAF 규칙 정의 개수와 IDS 규칙 정의 개수를 비교해줘. Wazuh는 이번 조회에서 빼고 표로 보여줘.'
        self.assertEqual(set(H.missing_reads(q,[])),{'a:waf','a:suricata'})
        q='WAF 규칙을 삭제하고 IDS는 제외해줘'
        self.assertTrue(H.READ.wants_write(H.normalized(q)));self.assertIsNone(H.read_plan(q))
        self.assertIn('서비스 서버',H.READ.scope_text('서비스 서버를 제외하지 마.'))

    def test_distribution_tail_does_not_create_second_host_vulnerability_work(self):
        q='서비스 서버 취약점 분포와 보안 서버 로그수집기 Global/Interval 통계를 조회해줘. 취약점 분포는 개수를 제한하지 마.'
        p=H.read_plan(q)
        self.assertEqual([x['features'] for x in p['plans']],[['get_wazuh_vulnerability_summary'],['get_wazuh_log_collector_stats']])

    def test_exact_search_keeps_identity_and_missing_command_visible(self):
        q='보안 서버 프로세스에서 이름에 chronyd가 포함된 항목을 검색해서 최대 3개 PID와 명령줄을 보여줘.'
        p=H.read_plan(q);self.assertEqual(p['search'],'chronyd')
        sc=schemas();sc[H.READ.WAZUH+'get_wazuh_agent_processes']['properties']['search']={'type':'string'}
        selected=H.refine_read_schemas(q,sc,[identity()])[H.READ.WAZUH+'get_wazuh_agent_processes']
        self.assertEqual(selected['properties']['search']['enum'],['chronyd'])
        c=process('019');self.assertTrue(H.missing_reads(q,[identity(),c]))
        c['arguments']['search']='chronyd'
        text=H.read_report(q,[identity(),c]);self.assertIn('명령줄(미제공이면 미확인)',text)

    def test_unknown_name_is_retained_and_can_resolve_from_actual_inventory(self):
        q='이름이 sensor-east인 장비의 UDP 포트를 조회해줘'
        p=H.read_plan(q);self.assertEqual(p['agent_name'],'sensor-east')
        self.assertIsNone(H.READ.target_id(p,[identity()]))
        c=call('get_wazuh_agents','Agent ID: 042\nName: sensor-east\nStatus: ACTIVE\nIP: 192.0.2.42',{'status':'active'})
        self.assertEqual(H.READ.target_id(p,[c]),'042')

    def test_diagnostic_subset_uses_real_catalog_and_never_equates_soc_bot_with_hermes(self):
        q='B 서버의 서비스 진단에서 Hermes와 Wazuh manager 두 대상만 조회해줘'
        targets=['b:soc-bot','b:docker','b:vector']
        wanted,unsupported=H.diagnostic_scope(q,targets)
        self.assertEqual(wanted,[]);self.assertEqual(unsupported,['b:hermes','b:wazuh-manager'])
        self.assertEqual(H.refine_read_schemas(q,{'mcp__system_diagnostics__get_system_diagnostics':{'properties':{'target':{'enum':targets}}}},[],targets),{})
        text=H.diagnostic_report(q,[],targets);self.assertIn('실제 유효 조회 0개',text);self.assertIn('서비스 상태를 확인했다는 뜻이 아닙니다',text)
        wanted,unsupported=H.diagnostic_scope('B 서버의 서비스 진단 중 b:docker만 조회해줘',targets)
        self.assertEqual(wanted,['b:docker']);self.assertEqual(unsupported,[])

    def test_device_specific_filter_and_limit_variants_cannot_be_crossed(self):
        q='보안 서버 TCP LISTENING 포트를 최대 4개, 서비스 서버 UDP 포트를 최대 7개 조회해줘'
        s=H.refine_read_schemas(q,schemas(),[identity()])[H.READ.WAZUH+'get_wazuh_agent_ports']
        self.assertEqual(len(s['anyOf']),2)
        if Draft202012Validator:
            v=Draft202012Validator(s)
            v.validate({'agent_id':'019','protocol':'tcp','state':'LISTENING','limit':4})
            v.validate({'agent_id':'017','protocol':'udp','state':'','limit':7})
            for invalid in [{'agent_id':'019','protocol':'udp','state':'','limit':7},{'agent_id':'017','protocol':'udp','state':'','limit':4}]:
                with self.assertRaises(Exception):v.validate(invalid)

    def test_critical_example_limit_never_truncates_distribution_query(self):
        q='Groot_C 취약점 심각도 분포와 Critical 항목을 최대 3개 조회해줘'
        base={'type':'object','properties':{'agent_id':{'type':'string'},'limit':{'type':'integer'},'severity':{'type':'string'}},'required':['agent_id']}
        summary=H.READ.WAZUH+'get_wazuh_vulnerability_summary';critical=H.READ.WAZUH+'get_wazuh_critical_vulnerabilities'
        selected=H.refine_read_schemas(q,{summary:base,critical:copy.deepcopy(base)},[identity()])
        self.assertEqual(set(selected[summary]['properties']),{'agent_id'})
        self.assertFalse(selected[summary]['additionalProperties'])
        self.assertNotIn('limit',selected[summary]['required'])
        self.assertEqual(selected[critical]['properties']['limit']['maximum'],3)
        self.assertIn('limit',selected[critical]['required'])
        limited=call('get_wazuh_vulnerability_summary','CVE: Unknown\nSeverity: LOW',{'agent_id':'017','limit':1})
        self.assertTrue(any('get_wazuh_vulnerability_summary' in x for x in H.missing_reads(q,[identity(),limited])))
        self.assertNotIn('반환 합계 1건',H.read_report(q,[identity(),limited]))
        if Draft202012Validator:
            with self.assertRaises(Exception):Draft202012Validator(selected[summary]).validate({'agent_id':'017','limit':1})

    def test_udp_does_not_invent_tcp_listening_and_limit_is_required(self):
        q='보안 서버 UDP 포트를 최대 2개 조회해줘'
        selected=H.refine_read_schemas(q,schemas(),[identity()])[H.READ.WAZUH+'get_wazuh_agent_ports']
        self.assertEqual(selected['properties']['protocol']['enum'],['udp'])
        self.assertEqual(selected['properties']['state']['enum'],[''])
        self.assertIn('limit',selected['required'])
        self.assertEqual(selected['properties']['limit']['maximum'],2)
        p=H.read_plan('Groot_C TCP ESTABLISHED 포트를 최대 2개 조회해줘')
        self.assertEqual(H.READ.port_filters(p),{'protocol':'tcp','state':'ESTABLISHED'})

    def test_network_ports_empty_is_ambiguous_even_for_registered_agent(self):
        q='Groot_C UDP 포트 최대 3개 조회해줘'
        c=call('get_wazuh_agent_ports','No network ports for agent 017 matching the specified criteria found matching the specified criteria.',{'agent_id':'017','protocol':'udp','state':'','limit':3})
        self.assertTrue(H.missing_reads(q,[identity(),c]))
        self.assertNotIn(H.READ.WAZUH+'get_wazuh_agent_ports',H.refine_read_schemas(q,schemas(),[identity(),c]))
        text=H.read_report(q,[identity(),c]);self.assertIn('구분할 수 없습니다',text)
        self.assertNotIn('반환 자료 0건',text)

    def test_manager_label_is_verified_against_actual_identity(self):
        q='Wazuh Manager 프로세스를 최대 2개 보여줘'
        p=H.read_plan(q);self.assertEqual(p['agent_name'],'wazuh.manager')
        self.assertEqual(H.READ.verified_ids(p,[identity()]),[])
        c=call('get_wazuh_agents','Agent ID: 007\nName: wazuh.manager\nStatus: ACTIVE\nIP: 127.0.0.1',{'status':'active'})
        self.assertEqual(H.READ.verified_ids(p,[c]),['007'])

    def test_b_host_cannot_be_satisfied_by_manager_container(self):
        manager=call('get_wazuh_agents','Agent ID: 000\nName: wazuh.manager\nStatus: ACTIVE\nIP: 127.0.0.1',{'status':'active'})
        host=call('get_wazuh_agents','Agent ID: 019\nName: groot-siem-host\nStatus: ACTIVE\nIP: 192.0.2.20',{'status':'active'})
        for question in ('B 서버 프로세스를 최대 2개 보여줘', 'Groot_B 취약점 요약을 조회해줘',
                         'B 호스트의 패키지 취약점을 확인해줘', 'SIEM 호스트 포트 목록 보여줘'):
            with self.subTest(question=question):
                p=H.read_plan(question)
                self.assertEqual(p['agent_name'],'groot-siem-host')
                self.assertEqual(H.READ.verified_ids(p,[manager]),[])
                self.assertEqual(H.READ.verified_ids(p,[manager,host]),['019'])

    def test_host_and_manager_remain_separate_compound_targets(self):
        p=H.read_plan('B 호스트와 Wazuh Manager의 프로세스를 각각 2개 조회해줘')
        self.assertEqual(p['kind'],'multi')
        self.assertEqual([x['agent_name'] for x in p['plans']],['groot-siem-host','wazuh.manager'])

    def test_container_location_is_not_a_second_host_request(self):
        for prefix in ('B 서버의', 'Groot_B에서', 'SIEM 호스트에 설치된'):
            with self.subTest(prefix=prefix):
                p=H.read_plan(prefix+' Wazuh Manager 프로세스를 최대 2개 보여줘')
                self.assertEqual(p['kind'],'wazuh')
                self.assertEqual(p['agent_name'],'wazuh.manager')
        p=H.read_plan('B 서버 프로세스와 Wazuh Manager 프로세스를 각각 2개 보여줘')
        self.assertEqual([x['agent_name'] for x in p['plans']],['groot-siem-host','wazuh.manager'])

    def test_fresh_b_name_uses_live_id_and_no_zero_fallback(self):
        p=H.read_plan('capstone-siem-host 프로세스를 보여줘')
        c=call('get_wazuh_agents','Agent ID: 023\nName: capstone-siem-host\nStatus: ACTIVE\nIP: 192.0.2.20',{'status':'active'})
        self.assertEqual(H.READ.verified_ids(p,[c]),['023'])

    def test_file_definition_paraphrase_preserves_both_runtime_and_table(self):
        q='IDS 구동 경로와 WAF Wazuh IDS 파일 정의 개수를 함께 표로 보여줘'
        combined=H.combined_rule_request(q);self.assertIsNotNone(combined)
        self.assertIn('표',combined)
        self.assertIn('a:suricata',H.missing_reads(q,[]))

    def test_time_reference_schema_uses_source_timestamp_not_event_label(self):
        q='A=2026-10-25T14:55:00Z, B=2026-10-25T15:10:00Z, 기준=2026-10-26T00:20:00+09:00. 시간 도구로 계산해줘'
        schema={'type':'object','properties':{'timestamps':{'type':'array','items':{'type':'object','properties':{'id':{'type':'string'},'value':{'type':'string'}}}},'reference':{'type':'string'}},'required':['timestamps']}
        selected=H.refine_read_schemas(q,{H.READ.TIME:schema},[])[H.READ.TIME]
        self.assertEqual(selected['properties']['reference']['enum'],['2026-10-26T00:20:00+09:00'])
        self.assertIn('reference',selected['required'])
        self.assertNotIn('enum',schema['properties']['reference'])
        self.assertEqual(len(selected['properties']['timestamps']['items']['properties']['value']['enum']),3)
        if Draft202012Validator:
            for invalid in ('base','ref','now','2026-10-25T14:55:00Z'):
                with self.assertRaises(Exception):Draft202012Validator(selected).validate({'timestamps':[],'reference':invalid})

    def test_time_result_with_wrong_reference_does_not_satisfy_request(self):
        q='A=2026-10-25T14:55:00Z, 기준=2026-10-26T00:20:00+09:00. 시간 계산해줘'
        args={'timestamps':[{'id':'A','value':'2026-10-25T14:55:00Z'},{'id':'base','value':'2026-10-26T00:20:00+09:00'}],'reference':'2026-10-25T14:55:00Z'}
        c=call('calculate_time',{'kind':'time_calculation','source_scope':'supplied_timestamps_only'},args,server='system-diagnostics')
        self.assertTrue(H.missing_reads(q,[c]))
        c['arguments']['reference']='2026-10-26T00:20:00+09:00'
        self.assertEqual(H.missing_reads(q,[c]),[])

    def test_multi_host_needs_every_requested_host_and_does_not_assume_ids(self):
        p=H.read_plan(MULTI)
        self.assertEqual(p['kind'],'multi')
        self.assertEqual([x['agent_name'] for x in p['plans']], list(NAMES))
        self.assertEqual(H.READ.verified_ids(p,[]),[])
        self.assertEqual(H.READ.verified_ids(p,[identity()]), sorted(IDS))
        calls=[identity(),process('017'),port('017')]
        missing=H.missing_reads(MULTI,calls)
        self.assertEqual(len(missing),2)
        self.assertTrue(all(x.startswith('groot-sec /') for x in missing))
        report=H.read_report(MULTI,calls)
        self.assertIn('전체 확인 완료가 아닙니다',report)
        self.assertIn('groot-sec',report);self.assertIn('groot-web',report)
        self.assertEqual(H.missing_reads(MULTI,calls+[process('019'),port('019')]),[])

    def test_agent_id_with_korean_particle_is_literal_not_a_host_guess(self):
        for token in ('ID 999의','agent_id=999는','에이전트 999를'):
            p=H.read_plan(token+' 프로세스 최대 3개 조회해줘')
            self.assertEqual(p['agent_id'],'999')
            self.assertEqual(H.READ.verified_ids(p,[]),['999'])
        p=H.read_plan('에이전트 ID 9999의 프로세스 조회해줘')
        self.assertIsNone(p['agent_id'])

    def test_filtered_agent_list_cannot_satisfy_all_status_request(self):
        q='Wazuh active disconnected 에이전트 조회해줘'
        c=identity();c['arguments']['name']='groot-web'
        self.assertIn('get_wazuh_agents:active',H.missing_reads(q,[c]))
        self.assertNotIn('get_wazuh_agents:active',H.missing_reads(q,[identity()]))

    def test_schema_requires_unfiltered_identity_then_pending_verified_hosts(self):
        original=schemas();pristine=copy.deepcopy(original)
        selected=H.refine_read_schemas(MULTI, original, [])
        self.assertEqual(set(selected),{H.READ.AGENTS})
        self.assertNotIn('name', selected[H.READ.AGENTS]['properties'])
        self.assertNotIn('limit', selected[H.READ.AGENTS]['properties'])
        self.assertFalse(selected[H.READ.AGENTS]['additionalProperties'])
        if Draft202012Validator:
            with self.assertRaises(Exception):Draft202012Validator(selected[H.READ.AGENTS]).validate({'status':'active','name':'Groot_A'})
        calls=[identity(),process('017'),port('017')]
        selected=H.refine_read_schemas(MULTI,original,calls)
        self.assertNotIn(H.READ.AGENTS,selected)
        for schema in selected.values():
            self.assertEqual(schema['properties']['agent_id']['enum'],['019'])
            self.assertEqual(schema['properties']['limit']['maximum'],3)
            if Draft202012Validator:
                with self.assertRaises(Exception):Draft202012Validator(schema).validate({'agent_id':'003','limit':3})
        self.assertEqual(original,pristine)

    def test_inventory_does_not_add_empty_search_and_explicit_search_keeps_native_path(self):
        sc=schemas();sc[H.READ.WAZUH+'get_wazuh_agent_processes']['properties']['search']={'type':'string'}
        selected=H.refine_read_schemas('Groot_C 프로세스를 최대 2개 조회해줘',sc,[identity()])
        s=selected[H.READ.WAZUH+'get_wazuh_agent_processes']
        self.assertNotIn('search',s['properties']);self.assertFalse(s['additionalProperties'])
        self.assertIsNone(H.read_plan('Groot_C 프로세스 중 sshd 이름으로 검색해줘'))

    @unittest.skipUnless(Draft202012Validator, 'existing server venv provides jsonschema; no Mac dependency install')
    def test_duplicate_read_selection_is_rejected(self):
        schema=H.selection_schema({H.READ.AGENTS:schemas()[H.READ.AGENTS]},8)
        c={'tool':H.READ.AGENTS,'arguments':{'status':'active'}}
        with self.assertRaises(Exception):Draft202012Validator(schema).validate({'calls':[c,c]})
        selected, removed = H.validated_selection({'calls':[c,c]},schema)
        self.assertEqual(selected,{'calls':[c]});self.assertEqual(removed,1)
        bad={'tool':'mcp__resp__block_ip','arguments':{}}
        with self.assertRaises(Exception):H.validated_selection({'calls':[c,bad]},schema)

    def test_missing_name_is_not_resolved_by_unrelated_active_host_or_repeated_forever(self):
        q='Wazuh 에이전트의 프로세스를 조회해줘'
        self.assertTrue(H.missing_reads(q,[identity()]))
        self.assertEqual(H.refine_read_schemas(q,schemas(),[identity()]),{})

    def test_limit_and_protocol_are_preserved_in_display_and_completion(self):
        q='Groot_C TCP LISTENING 포트와 프로세스 최대 3개 조회해줘'
        calls=[identity(),process('017',5),port('017','udp')]
        self.assertTrue(any('ports' in x for x in H.missing_reads(q,calls)))
        text=H.read_report(q,calls)
        self.assertNotIn('| 3 | p3 |',text)
        self.assertNotIn('| udp |',text)
        q='Groot_C UDP 포트 최대 3개 조회해줘'
        self.assertEqual(H.missing_reads(q,[identity(),port('017','udp')]),[])

    def test_known_tool_failure_is_reported_and_not_silently_repeated(self):
        q='에이전트 ID 999의 프로세스를 최대 3개 조회해줘'
        c=call('get_wazuh_agent_processes','Error fetching processes: agent not found',{'agent_id':'999','limit':3})
        self.assertTrue(H.missing_reads(q,[c]))
        self.assertEqual(H.refine_read_schemas(q,schemas(),[c]),{})
        text=H.read_report(q,[c]);self.assertIn('agent not found',text);self.assertIn('조회 실패',text)
        c['result_sha256']='0'*64
        self.assertIn(H.READ.WAZUH+'get_wazuh_agent_processes',H.refine_read_schemas(q,schemas(),[c]))
        self.assertNotIn('agent not found',H.read_report(q,[c]))

    def test_real_empty_message_cannot_prove_nonexistent_agent_or_zero_processes(self):
        q='ID 999의 프로세스를 최대 3개 조회해줘'
        c=call('get_wazuh_agent_processes','No processes for agent 999 matching the specified criteria found matching the specified criteria.',{'agent_id':'999','limit':3})
        self.assertTrue(H.missing_reads(q,[c]))
        self.assertEqual(H.refine_read_schemas(q,schemas(),[c]),{})
        text=H.read_report(q,[c]);self.assertIn('등록 여부',text);self.assertIn('구분할 수 없습니다',text)
        self.assertNotIn('반환 자료 0건입니다',text)

    def test_rule_counts_do_not_hide_requested_ids_runtime(self):
        calls=[call('get_rule_change_target',payload(t),{'target':t},server='rule-'+t[0]) for t in FILES]
        self.assertIsNone(H.inventory_question(COMBINED))
        self.assertEqual(H.missing_reads(COMBINED,calls),['a:suricata'])
        self.assertIn('IDS 구동 경로 조회 미완료',H.read_report(COMBINED,calls))
        self.assertFalse(PLUGIN._inventory_request(COMBINED))
        calls.append(call('get_service_action_target',{'target':'a:suricata','observation':{'running':True,'health':'none'},'rule_source_evidence':{'rule_source_option':'-S','rule_source_path':'/rules/all.rules','combined_is_exact_et_plus_local':True}}, {'target':'a:suricata'},server='rule-a'))
        self.assertEqual(H.missing_reads(COMBINED,calls),[])
        text=H.read_report(COMBINED,calls);self.assertIn('/rules/all.rules',text);self.assertIn('정의 수',text)
        self.assertIsNone(H.combined_rule_request('WAF IDS Wazuh 규칙을 수정해줘'))

    def test_inventory_caveat_does_not_replace_file_read_with_service_read(self):
        queries = ['Suricata 규칙 목록과 해시 보여줘. 엔진 활성 여부는 파일 정의와 구분해줘.',
                   'IDS 룰 목록 확인해줘. 파일 정의와 엔진 적재를 혼동하지 말아줘.']
        for q in queries:
            self.assertIsNotNone(H.inventory_question(q))
            self.assertFalse(H.ids_runtime_question(q))
            self.assertNotIn('mcp__rule_a__get_service_action_target', H.tool_scope(q))
        q = 'IDS 룰 목록과 현재 엔진 적재 상태도 조회해줘'
        self.assertIsNotNone(H.combined_rule_request(q))
        self.assertIn('a:suricata', H.missing_reads(q, []))
        self.assertIn('mcp__rule_a__get_security_rules', H.tool_scope(q))
        q = 'Suricata 커스텀 파일 규칙 목록과 해시 보여줘. 엔진 활성 여부는 파일 정의와 구분해줘.'
        target='a:suricata-local'; data=payload(target)
        calls=[call('get_rule_change_target',data,{'target':target},server='rule-a')]
        self.assertIn(data['sha256'], H.inventory(q,calls))
        for spelling in ('SHA를', 'SHA256을', 'SHA-256도'):
            self.assertIn(data['sha256'], H.inventory('Suricata 커스텀 파일 규칙 목록과 '+spelling+' 보여줘',calls))

    def test_inventory_discovery_uses_only_requested_hosts(self):
        a='mcp__rule_a__get_security_rules'; b='mcp__rule_b__get_security_rules'
        self.assertEqual(H.tool_scope('IDS 규칙 목록 보여줘'), {a})
        self.assertEqual(H.tool_scope('Wazuh 규칙 목록 보여줘'), {b})
        self.assertEqual(H.tool_scope('WAF와 IDS 규칙 목록 보여줘'), {a})
        self.assertEqual(H.tool_scope('WAF Wazuh 규칙 목록 보여줘'), {a,b})
        self.assertEqual(H.tool_scope('전체 규칙 목록 보여줘'), set())
        self.assertEqual(H.tool_scope('WAF IDS Wazuh 전체 규칙 목록 보여줘'), {a,b})
        self.assertEqual(H.tool_scope('IDS 규칙 목록과 구동 경로 보여줘'), {a,'mcp__rule_a__get_service_action_target'})

    def test_policy_facts_require_exact_available_definitions_and_exclude_incidents(self):
        tools=[{'function':{'name':'mcp__resp__block_ip','description':'Requires operator approval and refuses protected/management addresses and IPs with an active SSH session.'}},
               {'function':{'name':'mcp__rule_write_a__temporarily_contain_ip','description':'Protected/management/infrastructure/DGX and active SSH addresses are refused.'}}]
        text=H.policy_explanation(POLICY,tools)
        self.assertIn('우회하는 허가가 아닙니다',text)
        self.assertEqual(H.violations(POLICY,text,[]),[])
        for q in ('DGX를 차단해줘',POLICY+' 그리고 지금 로그를 분석해줘', 'DGX 차단 정책을 설명하고 조회해줘'):
            self.assertIsNone(H.policy_explanation(q,tools))
        self.assertIsNone(H.policy_explanation(POLICY,tools[:1]))
        tools[0]['function']['description']='unknown changed server policy'
        self.assertIsNone(H.policy_explanation(POLICY,tools))

    def test_diagnostic_schemas_keep_only_unverified_targets(self):
        q='A/B/C 서버의 모든 서비스 진단 오류를 조회해줘'
        alias='mcp__system_diagnostics__get_system_diagnostics';targets=['a:docker','b:docker','c:docker']
        schema={alias:{'type':'object','properties':{'target':{'type':'string','enum':targets}},'required':['target']}}
        c=call('get_system_diagnostics',{'schema':1,'target':'a:docker'},{'target':'a:docker'},server='system-diagnostics')
        selected=H.refine_read_schemas(q,schema,[c],targets)
        self.assertEqual(selected[alias]['properties']['target']['enum'],targets[1:])
        c['result_sha256']='0'*64
        self.assertEqual(H.refine_read_schemas(q,schema,[c],targets)[alias]['properties']['target']['enum'],targets)

    def test_native_diagnostics_keep_full_scope_before_removing_wire_tools(self):
        @dataclass
        class Request:
            api_kwargs:object
            api_messages:object=None
            _original_api_kwargs:object=None
        q='A/B/C 서버 전체 서비스 오류 진단해줘';rows=[{'role':'user','content':q}]
        targets=['a:docker','b:docker','c:docker'];alias='mcp__system_diagnostics__get_system_diagnostics'
        req=Request({'messages':rows,'tools':[{'type':'function','function':{'name':alias,'parameters':{'type':'object','properties':{'target':{'type':'string','enum':targets}},'required':['target']}}}]})
        a=SimpleNamespace(platform='mattermost',model='qwen3.6:35b',provider='custom',max_iterations=12,_current_turn_id='t')
        result=alignment.request_wrapper(lambda *a,**k:req,PLUGIN,H)(a,original_user_message=q,turn_id='t',messages=rows)
        self.assertEqual(a._capstone_alignment_diagnostic_targets,targets)
        self.assertIn('response_format',result.api_kwargs)
        self.assertNotIn('tools',result.api_kwargs)


if __name__=='__main__':unittest.main()
