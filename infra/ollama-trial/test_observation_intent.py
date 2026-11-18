"""Natural observation requests and attached outcome modality share one contract."""
import copy
import unittest
import harness as h
import test_evidence_report as f

Q='어제 WAF와 IDS 사이에 출발지가 겹쳤는지 조사해줘. 지금 임시 IP 차단도 알려줘'
AT='2026-11-18T13:31:43+09:00'


class ObservationIntent(unittest.TestCase):
    def test_actual_failed_wording_enters_the_existing_read_only_investigation(self):
        self.assertTrue(h.EVIDENCE.incident_investigation_request(h.normalized(Q)))
        self.assertTrue(h.EVIDENCE.sensor_observation_request(h.normalized(Q)))
        self.assertTrue(h.incident_evidence_gap(Q,[]))
        self.assertEqual(h.investigation_first_scope(Q),frozenset((f.MOD,f.SUR)))
        scope=h.incident_selection_scope(Q,[])
        self.assertEqual({f.MOD,f.SUR,f.BLOCK},set(scope))
        self.assertNotIn('mcp__wazuh_ro__get_wazuh_alert_summary',scope)
        self.assertTrue(all(h.EVIDENCE.allowed(tool,'verify') for tool in scope))
        self.assertIsNone(h.event_report(Q,[]))

    def test_observation_fields_and_sensors_generalize_but_keep_time_context(self):
        for q in ('오늘 Wazuh 목적지를 대조해줘','최근 IDS 출발지 비교해줘',
                  '현재 ModSecurity source IP가 겹쳤는지 비교해줘','어제 수리카타 목적지를 조사해줘',
                  '금일 웹 방화벽 출발지가 같았는지 확인해줘'):
            self.assertTrue(h.EVIDENCE.incident_investigation_request(h.normalized(q)),q)
        for q in ('WAF와 IDS의 출발지 개념을 설명해줘','어제 WAF 룰의 출발지 조건을 비교해줘',
                  '현재 IDS 설정의 목적지 주소를 보여줘','WAF와 IDS 원리 비교해줘',
                  '현재 WAF 공격 탐지 규칙 목록 보여줘','어제 이름 없는 출발지를 비교해줘',
                  '현재 ModSecurity source IP를 알려줘'):
            self.assertFalse(h.EVIDENCE.incident_investigation_request(h.normalized(q)),q)

    def test_quoted_text_and_write_requests_do_not_authorize_a_read_report(self):
        self.assertFalse(h.EVIDENCE.incident_investigation_request(h.normalized('"'+Q+'" 문장의 뜻을 설명해줘')))
        calls=[f.call(tool) for tool in (f.MOD,f.SUR,f.BLOCK)];before=copy.deepcopy(calls)
        write=Q+' 192.0.2.232를 차단해줘'
        self.assertIsNone(h.evidence_report_context(write,calls,AT,(f.MOD,f.SUR,f.BLOCK)))
        self.assertEqual(calls,before)

    def test_recognized_request_keeps_the_calendar_and_current_inventory_separate(self):
        from test_initial_event_day import schema
        raw={f.MOD:schema(),f.SUR:schema(),f.BLOCK:{'type':'object','properties':{}}}
        result=h.refine_read_schemas(Q,h.initial_event_day_schemas(Q,raw,[],AT),[],())
        for tool in (f.MOD,f.SUR):
            self.assertEqual(result[tool]['properties']['since_kst']['const'],'2026-11-17T00:00:00+09:00')
            self.assertEqual(result[tool]['properties']['until_kst']['const'],'2026-11-17T23:59:59.999999+09:00')
        self.assertEqual(result[f.BLOCK],raw[f.BLOCK])


class CoordinatedOutcomeModality(unittest.TestCase):
    def test_actual_rejected_sentence_is_negative_evidence_not_a_block_claim(self):
        line=('HTTP 403는 응답 코드일 뿐 WAF 차단 성공·백엔드 미도달·공격 실패의 증거가 아닙니다. '
              '실제 백엔드 영향은 `search_web_access`로 확인해야 합니다.')
        calls=[f.call(f.MOD,{'source':'modsecurity','alerts':[{'source_ip':'192.0.2.232','http_status':403}]})]
        self.assertNotIn('http_status_used_as_security_outcome',h.incident_field_violations(line,calls))
        for tail in ('·백엔드 미도달·공격 실패의 증거가 아닙니다.','/백엔드 미도달/공격 실패의 근거가 아님',
                     ' 및 백엔드 미도달 및 공격 실패의 증거가 아닙니다.'):
            self.assertEqual(h.CONTRACT.claim_modality(tail),'not_asserted',tail)

    def test_double_negation_and_finite_predicates_cannot_be_list_nouns(self):
        prefix='·백엔드 미도달·공격 '
        tails=[prefix+'실패의 증거가 아닌 것은 아닙니다.',
               prefix+'실패의 근거가 아니라는 것은 아닙니다.',prefix+'실패의 증거입니다.']
        tails += [prefix+'성공'+ending+' 별개 상태는 근거가 아닙니다.'
                  for ending in ('했다.','했지만','했다며','해서','하여','하였다고','했다면서')]
        for tail in tails:
            self.assertEqual(h.CONTRACT.claim_modality(tail),'asserted_or_unspecified',tail)
        calls=[f.call(f.MOD,{'source':'modsecurity','alerts':[{'http_status':403}]})]
        for tail in ('·백엔드 미도달·공격 실패의 증거가 아닌 것은 아닙니다.',
                     '·백엔드 미도달·공격 실패의 증거입니다.'):
            self.assertIn('http_status_used_as_security_outcome',h.incident_field_violations('HTTP 403은 WAF 차단 성공'+tail,calls))

    def test_attached_conditions_unknowns_and_plans_remain_non_assertions(self):
        for tail in ('·백엔드 미도달·공격 실패의 증거라면','·백엔드 미도달·공격 실패의 증거가 아니라면',
                     '·백엔드 미도달·공격 실패 여부는 미확인입니다.'):
            self.assertEqual(h.CONTRACT.claim_modality(tail),'conditional_or_unverified',tail)
        self.assertEqual(h.CONTRACT.claim_modality('·백엔드 미도달·공격 실패를 추가 확인해야 합니다.'),'planned_check')

    def test_coordination_is_bounded_and_does_not_cross_punctuation(self):
        for tail in ('. 다른 상태의 근거가 아닙니다.','; 별개 상태는 근거가 아닙니다.',
                     '·A·B·C·D·E·F의 증거가 아닙니다.'):
            self.assertEqual(h.CONTRACT.claim_modality(tail),'asserted_or_unspecified',tail)

    def test_dense_or_spaced_untrusted_text_cannot_stall_the_parser(self):
        import inspect,json,subprocess,sys
        values=['나'*240+'?',('나 '*120)+'?',('·나'*120)+'?',('나'*30+' ')*8+'?']
        code=('import json,re,sys;v=json.load(sys.stdin);exec(v["source"]);'
              'print(json.dumps([claim_modality(x) for x in v["values"]]))')
        result=subprocess.run([sys.executable,'-B','-c',code],capture_output=True,text=True,timeout=2,
            input=json.dumps({'source':inspect.getsource(h.CONTRACT.claim_modality),'values':values}))
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout),['asserted_or_unspecified']*4)


if __name__=='__main__':unittest.main()
