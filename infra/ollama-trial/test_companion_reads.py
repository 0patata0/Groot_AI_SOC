"""Complete compound reads without replacing peers, history, or approval."""
import copy
import hashlib
import json
import unittest

from jsonschema import ValidationError
import harness as h

MOD, SUR, WAZ = ('mcp__security_events__search_' + k + '_alerts'
                 for k in ('modsecurity', 'suricata', 'wazuh'))
BLOCK = 'mcp__resp__list_blocks'
QUESTION = '오늘 WAF와 Suricata 경보의 출발지가 겹치는지 조사하고, 현재 IP 차단과 실제 요청 차단이 확인됐는지 구분해서 알려줘.'


def receipt(tool, data=None, envelope=False, **updates):
    server, name = tool.removeprefix('mcp__').split('__')
    if data is None:
        data = ({'blocks': []} if tool == BLOCK else
                {'source': name.removeprefix('search_').removesuffix('_alerts'), 'alerts': [], 'returned_count': 0})
    raw = json.dumps(data, ensure_ascii=False)
    if envelope:raw = json.dumps({'result': raw})
    return dict(server=server.replace('_', '-'), name=name, arguments={}, result=raw,
                result_sha256=hashlib.sha256(raw.encode()).hexdigest()) | updates


def schemas(names=(MOD, SUR, BLOCK)):
    return {n: {'type': 'object', 'properties': {} if n == BLOCK else {'limit': {'type': 'integer'}},
                'additionalProperties': False} for n in names}


class CompoundReadIntent(unittest.TestCase):
    def test_leading_current_time_covers_a_separate_coordinated_inventory_request(self):
        for q in ('지금 WAF·IDS 경보 조사하고 임시 차단 IP도 보여줘.',
                  '현재 IDS 로그 확인하고 막힌 아이피 보여줘',
                  '현 시점의 Wazuh 경보 분석한 뒤 차단 IP 알려줘',
                  '지금 WAF 경보 비교하고 임시 차단 주소도 대조해줘'):
            self.assertTrue(h.READ.companion_block_request(q),q)
            self.assertIn(BLOCK,h.incident_required_read_gaps(q,[]),q)
        for q in ('지금 WAF의 차단 IP도 보여줘', '현재 IDS 차단 주소 알려줘',
                  '현재 WAF 경보 조사하고 IDS 차단 IP 알려줘',
                  '현재 WAF 경보 조사하고 어제 차단 IP 보여줘',
                  '지금 WAF 경보 조사하고 임시 차단 IP는 제외해줘',
                  '지금 WAF 경보 조사하고 IP 차단해줘',
                  '"지금 WAF 경보 조사하고 차단 IP 보여줘"라는 문장 설명해줘'):
            self.assertFalse(h.READ.companion_block_request(q),q)

    def test_short_temporary_block_state_question_keeps_the_event_peers(self):
        for q in ('어제 WAF·IDS 경보 조사해줘. 출발지 겹쳤어? 지금 IP 임시차단은?',
                  'WAF·IDS 경보 조사하고 지금 아이피 임시 차단은?',
                  'WAF·IDS 경보와 현재 IPv4 임시차단은?'):
            self.assertTrue(h.READ.companion_block_request(q),q)
            self.assertIsNone(h.READ.block_list_plan(q),q)
            self.assertIn(BLOCK,h.incident_required_read_gaps(q,[]),q)
        for q in ('현재 IP 임시차단은?', '지금 아이피 임시 차단은?'):
            self.assertEqual(h.READ.block_list_plan(q)['kind'],'block_list')
        for q in ('어제 IP 임시차단은?', '현재 WAF IP 임시차단은?', '현재 IP 임시차단해줘',
                  '현재 IP 임시차단 정책은?', '"현재 IP 임시차단은?"이라는 문장 설명해줘'):
            self.assertFalse(h.READ.companion_block_request(q),q)
    def test_current_companions_keep_the_whole_investigation(self):
        for q in (QUESTION,
                  '지난 24시간 WAF와 IDS 경보에서 같은 출발지가 있는지 조사해줘. 현재 차단된 IP도 대조하고, 요청 차단과 IP 차단은 구분해줘.',
                  'WAF와 IDS 로그 조사하고 지금 차단된 IP도 함께 확인해줘',
                  'Wazuh 경보와 현재 IP 차단 상태를 비교해서 알려줘',
                  '오늘 IDS 경보를 조사하고 현재 차단 목록도 알려줘',
                  'B systemd 실패 원문과 현재 IP 차단 상태를 함께 확인해줘',
                  '도커 컨테이너 상태와 지금 차단 중인 IP를 보여줘'):
            with self.subTest(q=q):
                self.assertTrue(h.READ.companion_block_request(q))
                self.assertIsNone(h.READ.block_list_plan(q))
                self.assertIn(BLOCK, h.incident_required_read_gaps(q, []))

    def test_explicit_current_state_is_a_list_but_not_policy_or_history(self):
        for q in ('현재 IP 차단 상태 보여줘', '지금 아이피 차단 현황 알려줘'):
            self.assertEqual(h.READ.block_list_plan(q)['kind'], 'block_list')
        base = 'WAF와 IDS 경보 조사해줘. '
        for clause in ('`차단 목록 보여줘`라고 말한 이유는?', '“차단 목록 보여줘”를 번역해줘',
                       '어제 차단 목록 보여줘', '192.0.2.5의 차단 목록 보여줘',
                       '현재 차단 목록 보여줘. 차단 목록은 제외해줘', '현재 IP 차단 조회하지 마',
                       '공격이면 현재 차단 목록 보여줘', '현재 차단 목록 보여줘. 192.0.2.5 차단해줘',
                       '현재 IP 차단 정책 알려줘', '현재 IP 차단이 필요한지 판단해줘',
                       '현재 IP 차단이 필요한지 확인해줘', '현재 차단 목록의 정책 확인해줘',
                       '현재 차단 목록의 의미 알려줘', '차단 목록이란 뭔지 알려줘',
                       '현재 IP 차단 요청을 검토해줘', '현재 IP 차단 예정인지 알려줘',
                       '실제 요청 차단과 HTTP 403의 의미를 알려줘', 'IP 차단 기준과 승인 절차 알려줘'):
            with self.subTest(clause=clause):
                self.assertFalse(h.READ.companion_block_request(base+clause))

    def test_sensor_qualified_block_report_is_not_a_firewall_inventory(self):
        for q in ('WAF 차단 목록 보여줘', '현재 WAF 차단 IP 알려줘',
                  'IDS 차단 IP 조회해줘', 'Suricata의 차단된 IP를 확인해줘'):
            self.assertFalse(h.READ.companion_block_request(q))
            self.assertNotIn(BLOCK,h.incident_required_read_gaps(q,[]))

    def test_peer_service_subject_keeps_broader_scope(self):
        for q in ('WAF 경보와 B systemd 서비스 및 현재 IP 차단 상태 조사해줘',
                  'IDS 경보와 방화벽 정책 및 현재 차단 목록을 조사해줘'):
            self.assertIsNone(h.investigation_first_scope(q))
            self.assertIn(BLOCK,h.incident_selection_scope(q, []))
            self.assertIn('mcp__security_events__get_web_service_target',h.incident_selection_scope(q, []))


class RequiredReadReceipts(unittest.TestCase):
    def test_each_named_sensor_and_companion_must_be_observed(self):
        self.assertEqual(h.incident_selection_scope(QUESTION, []), {MOD, SUR, BLOCK})
        self.assertEqual(h.incident_selection_scope(QUESTION, [receipt(MOD)]), {SUR, BLOCK})
        self.assertEqual(h.incident_selection_scope(QUESTION, [receipt(MOD), receipt(SUR)]), {BLOCK})
        calls = [receipt(n) for n in (MOD,SUR,BLOCK)]
        before = copy.deepcopy(calls)
        self.assertIsNone(h.incident_selection_scope(QUESTION, calls))
        self.assertEqual(h.missing_reads(QUESTION, calls), [])
        self.assertEqual(calls, before)

    def test_zero_event_sample_is_a_read_not_a_benign_verdict(self):
        q = 'WAF와 Wazuh 경보를 함께 조사하고 위험 판단해줘'
        self.assertTrue(h.incident_evidence_gap(q, [receipt(MOD)]))
        self.assertEqual(h.incident_required_read_gaps(q, [receipt(MOD)]), {WAZ})
        self.assertFalse(h.incident_evidence_gap(q, [receipt(MOD),receipt(WAZ)]))

    def test_latest_error_or_invalid_hash_never_uses_an_older_success(self):
        good = [receipt(n) for n in (MOD,SUR,BLOCK)]
        for tool in (MOD,SUR,BLOCK):
            for failed in (receipt(tool,is_error=True), receipt(tool,result_sha256='0'*64),
                           receipt(tool,{'result':json.dumps({'source':'modsecurity','alerts':[]}), 'isError':True})):
                with self.subTest(tool=tool,failed=failed):
                    self.assertIn(tool,h.incident_required_read_gaps(QUESTION, good+[failed]))
        for bad in (receipt(MOD,{'source':'suricata','alerts':[]}),
                    receipt(MOD,{'source':'modsecurity','alerts':None}),
                    receipt(MOD,{'source':'modsecurity','alerts':[],'is_error':True}),
                    receipt(BLOCK,arguments={'ip':'192.0.2.1'})):
            self.assertTrue(h.incident_required_read_gaps(QUESTION,good+[bad]))

    def test_native_result_envelopes_keep_verified_source_and_errors(self):
        calls = [receipt(n,envelope=True) for n in (MOD,SUR,BLOCK)]
        self.assertEqual(h.incident_required_read_gaps(QUESTION,calls), set())
        bad = receipt(MOD,{'result':json.dumps({'source':'modsecurity','alerts':[]}), 'is_error':True},envelope=True)
        self.assertEqual(h.incident_required_read_gaps(QUESTION,calls+[bad]),{MOD})

    def test_no_write_is_retried_and_history_does_not_use_current_list(self):
        self.assertFalse(h.incident_evidence_gap('WAF 경보 조사하고 IP 차단해줘',[]))
        q='어제 WAF와 IDS 경보 및 어제 차단 이력을 조사해줘'
        self.assertNotIn(BLOCK,h.incident_required_read_gaps(q,[]))
        self.assertNotIn(BLOCK,h.incident_selection_scope(q,[]))
        prompt=h.incident_evidence_instruction(QUESTION,[receipt(MOD)])
        self.assertIn(SUR,prompt);self.assertIn(BLOCK,prompt)
        self.assertNotIn('실제 성공한 경보 조회가 없습니다',prompt)


class RequiredReadSelection(unittest.TestCase):
    def test_complete_named_batch_uses_existing_schemas_and_no_dispatch(self):
        source = schemas();before = copy.deepcopy(source)
        schema=h.selection_schema(source,32,question=QUESTION)
        self.assertEqual(schema['title'],'RequiredReadToolSelection')
        self.assertEqual(schema['properties']['calls']['minItems'],3)
        self.assertEqual(schema['properties']['calls']['maxItems'],3)
        plan={'calls':[{'tool':n,'arguments':{}} for n in source]}
        self.assertEqual(h.validated_selection(plan,schema),(plan,0))
        self.assertEqual(source,before)

    def test_incomplete_duplicate_or_write_batch_is_rejected_whole(self):
        schema=h.selection_schema(schemas(),32,question=QUESTION)
        for choices in ([{'tool':MOD,'arguments':{}}],
                        [{'tool':MOD,'arguments':{'limit':n}} for n in (1,2,3)],
                        [{'tool':n,'arguments':{}} for n in (MOD,SUR,'mcp__resp__block_ip')]):
            with self.subTest(choices=choices),self.assertRaises(ValidationError):
                h.validated_selection({'calls':choices},schema)
        value={'calls':[{'tool':MOD,'arguments':{'limit':n}} for n in (1,2,3)]}
        try:h.validated_selection(value,schema)
        except ValidationError as error:
            feedback=h.selection_error_feedback(error,value,schema)
        self.assertEqual(feedback['missing_tools'],sorted([SUR,BLOCK]))
        self.assertNotIn('limit',json.dumps(feedback))

    def test_smaller_remaining_budget_or_other_subject_never_drops_the_catalog(self):
        schema=h.selection_schema(schemas(),2,question=QUESTION)
        self.assertEqual(schema['title'],'ReadToolSelection')
        self.assertEqual(schema['properties']['calls']['maxItems'],2)
        wider=schemas();wider['mcp__security_events__get_web_service_target']={'type':'object','properties':{}}
        self.assertEqual(h.selection_schema(wider,32,question=QUESTION)['title'],'ReadToolSelection')
        self.assertEqual(h.selection_schema(schemas((BLOCK,)),32,question=QUESTION)['title'],'RequiredReadToolSelection')


if __name__ == '__main__':unittest.main()
