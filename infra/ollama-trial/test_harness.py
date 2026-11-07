import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import harness
import policy
import chat


def fixture(target='a:modsecurity-custom'):
    content = 'fixture rule file\n'
    sha = hashlib.sha256(content.encode()).hexdigest()
    kind = {'a:modsecurity-custom': 'waf', 'a:suricata-local': 'suricata', 'b:wazuh-local-rules': 'wazuh'}[target]
    details = {'waf': {}, 'suricata': {'local_sid_count': 1, 'et_override_count': 0,
               'other_sid_count': 0, 'noalert_count': 0}, 'wazuh': {'level_counts': {'0': 1}, 'level0_count': 1}}[kind]
    data = {'target': target, 'content': content, 'sha256': sha, 'rule_inventory': {
        'schema_version': 1, 'scope': 'target_file_definitions', 'kind': kind,
        'source_sha256': sha, 'status': 'complete', 'runtime_load_verified': False,
        'ids': [10100], 'duplicate_ids': [], 'declared_count': 1, 'unique_id_count': 1, 'details': details}}
    raw = json.dumps(data)
    return {'server': 'rule-' + target[0], 'name': 'get_rule_change_target',
            'arguments': {'target': target}, 'result': raw, 'result_sha256': hashlib.sha256(raw.encode()).hexdigest(), 'is_error': False}


class Grounding(unittest.TestCase):
    def test_short_current_soc_backlog_questions_keep_existing_read_scope(self):
        for q in ('지금 관제 보고나 조사가 밀려 있어?','관제 처리 대기열 몇 개야?',
                  'SOC 보고 지연 현황 보여줘','관제 보고 대기 상태 확인해줘',
                  '지금 관제 조사 대기 상태 확인해줘'):
            with self.subTest(question=q):
                self.assertEqual(harness.diagnostic_request(q)['requested'],['b:management-pipeline'])
                self.assertTrue(harness.structured_read(q))
                self.assertTrue(harness.pipeline_lookup_request(q))
                self.assertEqual(harness.tool_scope(q),{'mcp__system_diagnostics__get_system_diagnostics'})
        for q in ('관제 보고서 양식만 설명해줘','어제 관제 보고가 밀린 원인 조사해줘',
                  '관제 조사 대기 사건을 삭제해줘','관제 보고가 왜 지연됐는지 원인을 분석해줘',
                  '어제 관제 보고가 밀려 있었어?','관제 처리 대기열 지난 3시간 현황 보여줘',
                  '관제 보고 대기열과 침해 위험을 판단해줘'):
            with self.subTest(question=q):self.assertIsNone(harness.diagnostic_request(q))

    def test_short_backlog_attributive_form_keeps_exact_current_scope(self):
        for question in ('지금 관제 처리나 보고 전송에 밀린 게 있어? 검토가 필요한 사건 수도 따로 알려줘.',
                         '관제 보고 밀린 건수 알려줘', '지금 SOC 처리에 밀린 일이 있어?'):
            with self.subTest(question=question):
                self.assertTrue(harness.pipeline_lookup_request(question))
                self.assertTrue(harness.structured_read(question))
                self.assertEqual(harness.tool_scope(question),{'mcp__system_diagnostics__get_system_diagnostics'})
                self.assertEqual(harness.diagnostic_request(question)['requested'],['b:management-pipeline'])

    def test_backlog_word_does_not_hide_history_actions_or_causal_inquiry(self):
        for question in ('어제 관제 처리에 밀린 일이 있었어?', '관제 처리에 밀린 사건을 삭제해줘',
                         '관제 보고에 밀린 일이 왜 생겼는지 분석해줘', '관제 보고 밀린 건수와 공격 위험 판단해줘'):
            with self.subTest(question=question):
                self.assertFalse(harness.pipeline_lookup_request(question))
                self.assertIsNone(harness.diagnostic_request(question))

    def test_current_pipeline_lookup_shows_requested_metrics_without_detailed_keyword(self):
        data={'schema':1,'kind':'runtime','host':'b','target':'b:management-pipeline',
            'status':'degraded','codes':['case_review_required'],'mutation_performed':False,
            'observed_at_kst':'2026-11-07T03:00:00+09:00','metrics':{
                'pending_reports':3,'running_cases':2,'overdue_cases':1,'review_required_cases':9}}
        text=harness.runtime_diagnostic_report(['b:management-pipeline'],{'b:management-pipeline':data},[])
        for value in ('보고 전송 3건','실행 중 2건','기한 초과 1건','검토 상태 사건 | 9건'):
            self.assertIn(value,text)
        self.assertNotIn('개별 수치는 생략',text)
        self.assertIn('전체 기능 정상 여부는 별개',text)

    def test_failed_service_judgment_preserves_pipeline_table_instead_of_brief_prose(self):
        data={'schema':1,'kind':'runtime','host':'b','target':'b:management-pipeline',
            'status':'degraded','codes':['case_review_required'],'mutation_performed':False,
            'observed_at_kst':'2026-11-07T03:00:00+09:00','metrics':{
                'pending_reports':0,'running_cases':0,'overdue_cases':0,'review_required_cases':9}}
        raw=json.dumps(data)
        calls=[{'server':'system-diagnostics','name':'get_system_diagnostics',
            'arguments':{'target':'b:management-pipeline'},'is_error':False,
            'result':raw,'result_sha256':hashlib.sha256(raw.encode()).hexdigest()}]
        text=harness.fallback('어제 관리 서비스 실패 원인과 지금 상태 알려줘',calls)
        self.assertIn('| 확인 항목 | 조회 결과 | 근거·범위 |',text)
        self.assertIn('검토 상태 사건 | 9건',text)
        self.assertIn('공격 확정·실행 실패 건수 아님',text)
        self.assertIn('위험 판단은 검증 미완료',text)
        self.assertNotIn('전체 정상입니다',text)

    def test_historical_failures_do_not_become_current_snapshot_only(self):
        for q in ('오늘 systemd 오류랑 현재 상태 비교해줘. 설정은 바꾸지 마.',
                  '금일 서버 에러와 지금 상태 대조해줘',
                  'Vector가 아까 실패했는데 지금 괜찮아?',
                  'systemd failure 또 나왔는데 현재는 어때?',
                  '최근 1시간 Docker 오류 보여줘',
                  'A/B/C 서버의 오늘 장애와 현재 상태 비교'):
            with self.subTest(question=q):
                self.assertTrue(harness.diagnostic_history_request(q))
                self.assertIsNone(harness.diagnostic_request(q))
                if harness.systemd_comparison_request(q):
                    self.assertEqual(harness.tool_scope(q),set(harness.SYSTEMD_COMPARE_TOOLS))
                    self.assertTrue(harness.structured_read(q))
                    self.assertIn('오늘 systemd 경보: 정확한 KST 구간·필터·반환 근거',harness.missing_reads(q,[]))
                else:
                    self.assertIsNone(harness.tool_scope(q))
                    self.assertFalse(harness.structured_read(q))
                self.assertIsNone(harness.diagnostic_report(q,[],['a:systemd','b:systemd','c:systemd']))

    def test_current_diagnostics_and_unrelated_rules_keep_fast_read_scope(self):
        for q in ('지금 systemd 상태 보여줘', '현재 systemd failed unit 몇 개야?',
                  '벡터 지금 살아 있나?', 'A/B/C 서버 실패한 서비스 오류 조회'):
            with self.subTest(question=q):
                self.assertFalse(harness.diagnostic_history_request(q))
                self.assertEqual(harness.tool_scope(q),{'mcp__system_diagnostics__get_system_diagnostics'})
                self.assertTrue(harness.structured_read(q))
        for q in ('현재 FW 룰 보여줘','Wazuh 상관분석 룰 조건 조회'):
            self.assertFalse(harness.diagnostic_history_request(q))
            self.assertTrue(harness.structured_read(q))

    def detail_fixture(self, content='<group name="test"><rule id="42" level="0"><description>base &amp; test | detail</description></rule></group>'):
        call=fixture('b:wazuh-local-rules');data=json.loads(call['result']);data['content']=content
        data['sha256']=hashlib.sha256(content.encode()).hexdigest();data['rule_inventory'].update(ids=[42],source_sha256=data['sha256'])
        call['result']=json.dumps(data);call['result_sha256']=hashlib.sha256(call['result'].encode()).hexdigest();return call

    def test_rule_detail_keeps_level_zero_description_and_cross_device_absence(self):
        q='Wazuh 커스텀 파일 ID 42 level과 description을 조회하고 WAF 같은 ID 존재 여부도 보여줘'
        calls=[self.detail_fixture(),fixture()]
        self.assertTrue(harness.structured_read(q))
        self.assertEqual(harness.tool_scope(q),{'mcp__rule_a__get_rule_change_target','mcp__rule_b__get_rule_change_target'})
        self.assertEqual(harness.missing_reads(q,calls),[])
        answer=harness.read_report(q,calls)
        self.assertIn('b:wazuh-local-rules | 42 | 정의됨 | 0',answer)
        self.assertIn('base & test',answer)
        self.assertIn('a:modsecurity-custom | 42 | 없음 (파일에 미정의)',answer)

    def test_rule_detail_failed_or_hash_changed_source_is_not_absence(self):
        q='Wazuh 커스텀 파일 ID 42의 level과 description을 조회해줘'
        call=self.detail_fixture();call['result_sha256']='0'*64
        self.assertEqual(harness.missing_reads(q,[call]),['b:wazuh-local-rules'])
        self.assertIn('미조회·미확인',harness.read_report(q,[call]))
        self.assertNotIn('없음 (파일에 미정의)',harness.read_report(q,[call]))

    def test_rule_detail_does_not_assign_different_ids_or_replace_change_analysis(self):
        for q in ('Wazuh 커스텀 파일 ID 42와 WAF ID 43을 조회해줘','Wazuh 커스텀 파일 ID 42 설명을 변경해줘',
                  'Wazuh 커스텀 파일 ID 42가 위험한 원인을 분석해서 보여줘'):
            self.assertIsNone(harness.rule_detail_request(q))

    def test_rule_detail_rejects_doctype_and_missing_xml_fields(self):
        q='Wazuh 커스텀 파일 ID 42 level과 description을 조회해줘'
        for content in ('<!DOCTYPE x><group><rule id="42" level="0"><description>x</description></rule></group>',
                        '<group><rule id="42" level="0"/></group>',
                        '<group><rule id="42" level="0"><description>x</description></rule><rule id="42" level="1"><description>y</description></rule></group>'):
            self.assertEqual(harness.missing_reads(q,[self.detail_fixture(content)]),['b:wazuh-local-rules'])

    def test_korean_running_and_active_requests_use_observed_read_renderers(self):
        q = '현재 IDS 서비스 실행 상태를 각자 조회하고 서로 검증해줘'
        self.assertTrue(harness.structured_read(q))
        self.assertEqual(harness.missing_reads(q, []), ['a:suricata'])
        p = harness.read_plan('현재 활성 Wazuh 에이전트 목록을 보여줘')
        self.assertEqual(p['states'], ['active'])
        self.assertEqual(harness.read_plan('현재 비활성 Wazuh 에이전트 목록을 보여줘'), None)
    def test_first_event_filters_share_the_native_explicit_evidence_boundary(self):
        name='mcp__security_events__search_wazuh_alerts'
        schema={'type':'object','additionalProperties':False,'properties':{'wazuh_rule_id':{'type':'string'},'source_ip':{'type':'string'},'agent_id':{'type':'string'}},'required':[]}
        out=harness.refine_read_schemas('systemd 경보 원인 조사',{name:schema},[])
        self.assertEqual(out[name]['properties'],{})
        out=harness.refine_read_schemas('규칙 100120 agent ID 007 출발지 192.0.2.44 경보',{name:schema},[])
        for key,val in [('wazuh_rule_id','100120'),('agent_id','007'),('source_ip','192.0.2.44')]:self.assertEqual(out[name]['properties'][key]['enum'],[val])
        self.assertEqual(set(schema['properties']),{'wazuh_rule_id','source_ip','agent_id'})

    def test_structured_read_selection_never_offers_protected_tools(self):
        with self.assertRaises(ValueError):
            harness.selection_schema({'mcp__rule_write_a__propose_rule_edit': {'type': 'object'}}, 3)
        with self.assertRaises(ValueError):
            harness.selection_schema({'execute_shell': {'type': 'object'}}, 3)
        schema = harness.selection_schema({'mcp__rule_a__get_rule_change_target': {'type': 'object'}}, 2)
        self.assertEqual(schema['properties']['calls']['maxItems'], 2)

    def test_inventory_and_ids_read_scope_do_not_strip_change_authority(self):
        self.assertEqual(harness.tool_scope('현재 커스텀 파일 규칙을 장비별로 표로 보여줘'),
                         {'mcp__rule_a__get_rule_change_target', 'mcp__rule_b__get_rule_change_target'})
        self.assertEqual(harness.tool_scope('IDS는 왜 활성화 안됐지? 지금 실제 상태와 SID 적재 확인해줘'),
                         {'mcp__rule_a__get_service_action_target'})
        self.assertIsNone(harness.tool_scope('IDS 규칙을 변경해줘'))
        self.assertIsNone(harness.tool_scope('IDS를 재시작해줘'))

    def test_event_and_diagnostic_coverage_requires_actual_success(self):
        q = 'WAF IDS Wazuh 보안 로그 조회해줘'
        self.assertEqual(len(harness.missing_reads(q, [])), 3)
        q = 'A/B/C 서버의 실패한 서비스 오류 조회'
        calls = [{'name': 'get_system_diagnostics', 'server': 'system-diagnostics',
                  'arguments': {'target': 'a:vector'}, 'result': '{}', 'is_error': False}]
        self.assertEqual(harness.missing_reads(q, calls, ['a:vector', 'b:vector']), ['a:vector', 'b:vector'])
        raw = json.dumps({'schema': 1, 'target': 'a:vector'})
        calls[0].update(result=raw, result_sha256=hashlib.sha256(raw.encode()).hexdigest())
        self.assertEqual(harness.missing_reads(q, calls, ['a:vector', 'b:vector']), ['b:vector'])
        calls[0]['is_error'] = True
        self.assertEqual(harness.missing_reads(q, calls, ['a:vector']), ['a:vector'])

    def test_diagnostic_renderer_keeps_every_host_and_unknowns(self):
        calls = []
        for target in ('a:one', 'b:two', 'c:three'):
            raw = json.dumps({'schema': 1, 'target': target, 'properties': {'Type': 'oneshot',
                'ActiveState': 'inactive', 'SubState': 'dead', 'Result': 'success'},
                'returned_error_count': 0, 'recent_errors': [], 'observed_at_kst': '2026-10-25T07:00:00+09:00'})
            calls.append({'server': 'system-diagnostics', 'name': 'get_system_diagnostics', 'arguments': {'target': target},
                'result': raw, 'result_sha256': hashlib.sha256(raw.encode()).hexdigest()})
        text = harness.diagnostic_report('A/B/C 서버 실패한 서비스 오류 조회', calls,
                                         ['a:one', 'b:two', 'c:three', 'c:missing'])
        for target in ('a:one', 'b:two', 'c:three', 'c:missing'):
            self.assertIn(target, text)
        self.assertIn('미확인(0건 아님)', text)
        self.assertNotIn('모두 정상', text)

    def test_event_renderer_preserves_actual_range_and_wazuh_timezone(self):
        raw = json.dumps({'result': 'Alert ID: 1.2\nTime: 2026-10-24T21:45:00+0000\nAgent: fixture\nLevel: 3\nDescription: sample\n'})
        calls = [{'server': 'wazuh-ro', 'name': 'get_wazuh_alert_summary', 'arguments': {'limit': 5},
                  'result': raw, 'result_sha256': hashlib.sha256(raw.encode()).hexdigest()}]
        text = harness.event_report('WAF IDS Wazuh 보안 로그 조회', calls)
        self.assertIn('반환 표본 1건', text)
        self.assertIn('2026-10-25T06:45:00+09:00', text)
        self.assertEqual(text.count('조회 미완료/실패'), 2)
        self.assertIn('until_kst와 lookback_minutes로 과거 구간을 조회', text)
        self.assertIn('Wazuh 요약은 최신 표본', text)
        self.assertNotIn('이 도구들은 고정 절대', text)
        calls[0]['result'] = json.loads(raw)['result']
        calls[0]['result_sha256'] = hashlib.sha256(calls[0]['result'].encode()).hexdigest()
        self.assertIn('반환 표본 1건', harness.event_report('WAF IDS Wazuh 보안 로그 조회', calls))
        self.assertIn('2026-10-25T06:45:00+09:00', harness.model_view('wazuh-ro', 'get_wazuh_alert_summary', calls[0]['result']))

    def test_ids_report_preserves_running_without_claiming_sid_load(self):
        raw = json.dumps({'target': 'a:suricata', 'observation': {'running': True, 'health': 'not_reported'},
            'rule_source_evidence': {'rule_source_option': '-S', 'rule_source_path': '/rules/all.rules',
                'combined_is_exact_et_plus_local': True}})
        call = {'server': 'rule-a', 'name': 'get_service_action_target', 'arguments': {'target': 'a:suricata'},
                'result': raw, 'result_sha256': hashlib.sha256(raw.encode()).hexdigest()}
        text = harness.service_report('IDS는 왜 활성화 안됐지? 실제 조회해줘', [call])
        self.assertIn('**실행 중**', text)
        self.assertIn('개별 SID 엔진 적재는 미확인', text)
        self.assertIn('not_reported', text)
        self.assertNotIn('정상 가동', text)

    def test_state_and_test_label_do_not_hide_inventory(self):
        question = '[비교시험 Q1] WAF IDS Wazuh 현재 커스텀 파일 룰 보여줘. 현재 상태 조회만 해줘.'
        missing = harness.inventory(question, [fixture()], missing_targets=True)
        self.assertEqual(missing, ['a:suricata-local', 'b:wazuh-local-rules'])

    def test_tampered_result_or_claimed_engine_load_is_not_evidence(self):
        for change in ({'result': 'fabricated'}, {'is_error': True}):
            c = {**fixture(), **change}
            self.assertEqual(harness.inventory('WAF 규칙 보여줘', [c], verified_targets=True), [])
        c = fixture(); data = json.loads(c['result']); data['rule_inventory']['runtime_load_verified'] = True
        c['result'] = json.dumps(data); c['result_sha256'] = hashlib.sha256(c['result'].encode()).hexdigest()
        self.assertEqual(harness.inventory('WAF 규칙 보여줘', [c], verified_targets=True), [])

    def test_latest_failure_invalidates_previous_success(self):
        good = fixture(); failed = {**good, 'is_error': True}
        self.assertEqual(harness.inventory('WAF 규칙 보여줘', [good, failed], verified_targets=True), [])

    def test_reformat_requires_complete_verified_evidence(self):
        evidence = {'question': 'WAF IDS Wazuh 현재 적용된 규칙 보여줘', 'calls': [fixture()], 'at_kst': '2026-10-25T06:00:00+09:00'}
        self.assertIsNone(harness.prior_inventory('장비별로 표로 보여줘', evidence))
        evidence['calls'] += [fixture('a:suricata-local'), fixture('b:wazuh-local-rules')]
        self.assertIn('이전 실제 조회 시각', harness.prior_inventory('장비별로 표로 보여줘', evidence))
        self.assertIsNone(harness.prior_inventory('지금 다시 조회해서 표로 보여줘', evidence))

    def test_no_tool_current_claim_and_real_facts(self):
        self.assertIn('current_state_requires_actual_read', harness.violations('서버 오류 확인해줘', '조회 완료', []))
        facts = harness.facts_for([fixture()])
        self.assertEqual(facts[0]['kind'], 'rules')
        self.assertEqual(facts[0]['declared_count'], 1)

    def test_write_claims_require_matching_observations(self):
        q = '관리 주소를 임시 차단해줘'
        for answer, issue in [
            ('현재 차단 목록에 없습니다.', 'unobserved_block_list_claim'),
            ('최근 7분 공격은 확인되지 않았습니다.', 'unobserved_attack_absence_claim'),
            ('실행 결과: 차단 요청 실패 (서버 거부).', 'unobserved_protected_execution_claim'),
            ('대안: 해당 관리 주소는 일반 block_ip를 통해 차단해야 합니다.', 'protected_address_bypass_advice')]:
            with self.subTest(answer=answer):
                self.assertIn(issue, harness.violations(q, answer, []))
                self.assertIn(issue, harness.violations(q, answer, [fixture()]))
        for answer in ['현재 차단 목록은 미조회/미확인입니다.',
                       '최근 공격은 조회하지 않았으므로 미확인입니다.',
                       '호출 시 서버가 보호 정책으로 거부합니다. 실제 호출은 하지 않았습니다.',
                       '관리 주소는 일반 block_ip에도 거부됩니다. 우회하지 않습니다.',
                       '경보 메시지에 표식만 추가하며 탐지 범위와 동작에는 영향이 없습니다.',
                       '탐지 로직 변경 없음. 경보 출력 메시지에만 태그 표시.',
                       '이 주소는 차단할 수 없습니다. 공인 공격자 IP에 대한 임시 차단만 지원합니다.']:
            self.assertEqual(harness.action_claim_violations(q, answer, []), [])

    def test_real_server_rejection_is_distinct_from_block_list_read(self):
        raw = json.dumps({'error': 'protected, non-public, or non-canonical source address'})
        c = {'server': 'rule-write-a', 'name': 'temporarily_contain_ip', 'arguments': {},
             'result': raw, 'result_sha256': hashlib.sha256(raw.encode()).hexdigest(), 'is_error': True}
        self.assertEqual(harness.action_claim_violations('관리 주소 차단해줘', '서버가 요청을 거절했습니다.', [c]), [])
        self.assertIn('unobserved_block_list_claim', harness.action_claim_violations('관리 주소 차단해줘', '현재 차단 목록에 없습니다.', [c]))
        self.assertIn('unobserved_protected_execution_claim', harness.action_claim_violations('관리 주소 차단해줘',
            '서버가 요청을 거절했습니다.', [{**c, 'result_sha256': '0'*64}]))

    def test_safe_action_report_does_not_claim_an_unobserved_rejection(self):
        text = harness.action_fallback('관리 주소 차단해줘', [])
        self.assertIn('호출하지 않았습니다', text)
        self.assertIn('공격이 없다는 뜻이 아닙니다', text)
        self.assertEqual(harness.action_claim_violations('관리 주소 차단해줘', text, []), [])
        self.assertEqual(harness.action_claim_violations('관리 서버 관제에서 공인 공격자 주소 차단안을 준비해줘',
            '공인 공격자는 일반 block_ip를 통해 승인받아 차단할 수 있습니다. 보호 주소는 거부됩니다.', []), [])

    def test_actual_retest_execution_and_tool_provenance_variants(self):
        q = '관리 서버 10.200.10.10 차단 요청을 처리해줘'
        for answer in ('차단 시도: 실패 (도구에서 즉시 거부됨)',
                       '결과: 서버의 보호 대상 검증에서 거부됨'):
            self.assertIn('unobserved_protected_execution_claim', harness.action_claim_violations(q, answer, []))
        self.assertIn('unsupported_firewall_proposal_advice', harness.action_claim_violations(q,
            'nftables 방화벽 규칙 변경은 propose_rule_change 승인 경로로 진행해야 합니다.', []))
        for text in ('일반 block_ip 도구를 사용하거나 방화벽 정책 자체를 수정해야 합니다.',
                     'block_ip를 통해 운영자에게 차단을 요청해야 합니다. (단, 보호 주소를 거부할 수 있습니다.)',
                     '사설 주소라도 운영자 승인을 받는 일반 block_ip는 가능할 수 있으나 권장되지 않습니다.'):
            self.assertIn('protected_address_bypass_advice', harness.action_claim_violations(q, text, []))
        self.assertNotIn('protected_address_bypass_advice', harness.action_claim_violations(q,
            '실제 공인 외부 공격자는 일반 block_ip를 통해 승인받아 차단할 수 있습니다.', []))
        self.assertIn('unobserved_tool_result_claim', harness.action_claim_violations('IDS 모드 변경해줘',
            '`get_service_action_target` 결과, 허용 작업은 restart와 reload입니다.', []))
        for text in ('get_service_action_target 결과를 확인해야 합니다.',
                     'get_service_action_target는 아직 호출하지 않았습니다.'):
            self.assertNotIn('unobserved_tool_result_claim', harness.action_claim_violations('IDS 확인해줘', text, []))
        text = harness.action_fallback('IDS 모드 변경해줘', [])
        self.assertNotIn('차단 목록', text)
        self.assertEqual(harness.action_claim_violations('IDS 모드 변경해줘', text, []), [])

    def test_wazuh_legacy_text_times_are_grounded_and_presented_in_kst(self):
        raw = json.dumps({'result': 'Time: 2026-10-24T21:45:00.110+0000'})
        call = {'server': 'wazuh-ro', 'name': 'get_wazuh_alert_summary', 'result': raw,
                'result_sha256':hashlib.sha256(raw.encode()).hexdigest(),'is_error':False}
        facts = harness.facts_for([call])
        self.assertEqual(facts[0]['instants'], ['2026-10-24T21:45:00.110+0000'])
        self.assertIn('2026-10-25T06:45:00.110000+09:00', harness.model_view('wazuh-ro', call['name'], raw))
        self.assertEqual(harness.model_view('rule-a', 'get_rule_change_target', raw), raw)

    def test_protected_subject_cannot_be_redirected_to_another_enforcement_path(self):
        q = '관리 주소 10.19.8.7 차단 요청'
        for answer in (
            '해당 주소가 실제 공격원천이 맞다면, 방화벽 정책(`nftables`)이나 WAF/Suricata의 IP 목록을 통해 영구 또는 장기적으로 관리해야 합니다.',
            '대신 방화벽에서 관리 주소를 차단하세요.',
            '보호 주소는 WAF의 IP 목록을 수정해야 합니다.',
        ):
            self.assertIn('protected_address_bypass_advice', harness.action_claim_violations(q, answer, []))
        for answer in (
            '해당 주소의 방화벽 우회 차단은 허용되지 않습니다.',
            '관리 주소의 nftables 정책을 조회해 원인을 조사해야 합니다.',
            '실제 공인 외부 공격자는 방화벽에서 차단할 수 있습니다.',
        ):
            self.assertEqual(harness.action_claim_violations(q, answer, []), [])

    def test_footer_and_explicit_kst_conversion(self):
        self.assertEqual(harness.footer_free('답변\n---\n읽기 전용 시험 · 옛날 · 처리 12.3초'), '답변')
        self.assertIn('2026-10-25T04:50:00', harness.EVIDENCE.kst_display('2026-10-24 19:50:00 UTC'))


class Parity(unittest.TestCase):
    def test_exact_hermes_capabilities_and_no_general_execution(self):
        tools = policy.capabilities('hermes-parity')
        self.assertEqual(sum(map(len, tools.values())), 44)
        self.assertIn('collect_incident_evidence',tools['security-events'])
        self.assertEqual(sum(policy.protected(s, t) for s, names in tools.items() for t in names), 9)
        policy.validate_call('rule-write-a', 'propose_service_action', {'target': 'a:suricata'}, 'hermes-parity')
        for server, name, args in [('rule-write-a', 'propose_service_action', {'target': 'b:wazuh-manager'}),
                ('rule-a', 'propose_rule_edit', {}), ('rule-write-b', 'temporarily_contain_ip', {}),
                ('resp', 'execute_shell', {})]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                policy.validate_call(server, name, args, 'hermes-parity')

    def test_restart_never_replays_a_protected_attempt(self):
        with tempfile.TemporaryDirectory() as state, patch.object(chat, 'agent_config', return_value={}):
            g = chat.Gateway({}, None, state)
            g.db.execute("insert into jobs(id,post,status,protected_started) values('p','{}','running',1)")
            g.db.commit(); g.db.close()
            g = chat.Gateway({}, None, state)
            row = g.db.execute('select status,answer from jobs').fetchone()
            self.assertEqual(row['status'], 'delivery')
            self.assertIn('재요청하지 않았', row['answer']); g.db.close()

    def test_evidence_never_crosses_root_or_human(self):
        with tempfile.TemporaryDirectory() as state, patch.object(chat, 'agent_config', return_value={}):
            g = chat.Gateway({}, None, state)
            prior = {'id': 'old', 'user_id': 'u', 'channel_id': 'c', 'create_at': 1}
            g.db.execute("insert into jobs(id,post,status,evidence) values(?,?,'done',?)", ('old', json.dumps(prior), '{"calls":[]}'))
            g.db.commit()
            current = {'id': 'new', 'user_id': 'u', 'channel_id': 'c', 'create_at': 2}
            self.assertIsNone(g.prior_evidence(current))
            self.assertIsNotNone(g.prior_evidence({**current, 'root_id': 'old'}))
            self.assertIsNone(g.prior_evidence({**current, 'root_id': 'old', 'user_id': 'other'}))
            g.db.close()


if __name__ == '__main__':
    unittest.main()
