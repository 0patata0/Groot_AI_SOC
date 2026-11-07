"""Regression cases from short health questions and the real no-argument catalog."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import harness


def observation(target='a:vector', *, error=False):
    raw = json.dumps({'schema': 1, 'target': target, 'kind': 'runtime',
                      'status': 'ok', 'properties': {'ActiveState': 'active', 'SubState': 'running'},
                      'observed_at_kst': '2026-11-03T06:20:00+09:00'})
    return {'server': 'system-diagnostics', 'name': 'get_system_diagnostics',
            'arguments': {'target': target}, 'result': raw,
            'result_sha256': hashlib.sha256(raw.encode()).hexdigest(), 'is_error': error}


class DiagnosticGrounding(unittest.TestCase):
    def test_unrequested_runtime_read_does_not_replace_the_service_properties_table(self):
        data={'schema':1,'target':'b:management','status':'observed','properties':{
            'Type':'oneshot','ActiveState':'inactive','SubState':'dead','Result':'success',
            'LoadState':'loaded','UnitFileState':'static'}}
        raw=json.dumps(data);call=observation('b:management');call.update(result=raw,result_sha256=hashlib.sha256(raw.encode()).hexdigest())
        other=observation('b:management-pipeline')
        question='B 서버 capstone-management.service의 지금 실행 상태와 시작 설정 알려줘.'
        text=harness.diagnostic_report(question,[call,other],['b:management','b:management-pipeline'])
        self.assertIn('| b:management | loaded | static |',text)
        self.assertNotIn('b:management-pipeline',text)
        self.assertNotIn('점검 통과 0',text)

    def test_mixed_runtime_and_unit_observation_retains_properties_and_count(self):
        records={'b:management':{'status':'observed','properties':{'LoadState':'loaded','UnitFileState':'static'}},
                 'b:management-pipeline':{'kind':'runtime','status':'degraded','codes':['case_review_required']}}
        text=harness.runtime_diagnostic_report(list(records),records,[])
        self.assertIn('속성 관측 1',text);self.assertIn('이상 징후 1',text)
        self.assertIn('속성 관측·판단 별도',text)
        self.assertIn('LoadState=loaded; UnitFileState=static',text)

    def test_current_table_preserves_load_and_install_state_without_inventing_missing_values(self):
        question='B 서버 capstone-management.service의 지금 실행 상태와 시작 설정 알려줘.'
        for state in ('static','disabled',None):
            data={'schema':1,'target':'b:management','kind':'unit','status':'ok',
                  'properties':{'Type':'oneshot','ActiveState':'inactive','SubState':'dead','Result':'success','LoadState':'loaded'},
                  'returned_error_count':0,'observed_at_kst':'2026-11-07T10:00:00+09:00'}
            if state is not None:data['properties']['UnitFileState']=state
            raw=json.dumps(data);call=observation('b:management');call.update(result=raw,result_sha256=hashlib.sha256(raw.encode()).hexdigest())
            text=harness.diagnostic_report(question,[call],['b:management'])
            self.assertIn('| 대상 | LoadState | UnitFileState |',text)
            self.assertIn('| b:management | loaded | '+(state or '미확인')+' |',text)
            self.assertIn('주기 실행·재시작 이력이나 전체 기능 정상',text)

    def test_colloquial_health_subjects_require_actual_fixed_target_reads(self):
        questions = [('벡터 살아 있니?', 'a:vector'), ('vector 잘 돌아가?', 'a:vector'),
                     ('헤르메스 돌고 있어?', 'b:hermes'), ('인덱서 running?', 'b:wazuh-indexer'),
                     ('올라마 지금 켜져 있어?', 'b:ollama'), ('WAF 살아있어?', 'a:waf')]
        for question, target in questions:
            with self.subTest(question=question):
                self.assertEqual(harness.tool_scope(question), {'mcp__system_diagnostics__get_system_diagnostics'})
                self.assertEqual(harness.missing_reads(question, [], [target]), [target])
                self.assertIn('current_state_requires_actual_read', harness.violations(question, '현재 정상입니다.', []))

    def test_concepts_quotes_and_protected_changes_do_not_become_health_reads(self):
        for question in ('벡터 작동 원리만 설명해줘', 'Vector 살아있다는 게 무슨 뜻이야?',
                         '"인덱서 running?"을 번역해줘', '벡터 살아있게 재시작해줘',
                         '올라마 켜줘', '도구 없이 벡터 상태 설명만 해줘'):
            with self.subTest(question=question):
                self.assertIsNone(harness.diagnostic_request(question))

    def test_an_unrecognized_question_cannot_invent_a_healthy_observation(self):
        question = '벡터는 어때?'
        self.assertIsNone(harness.diagnostic_request(question))
        self.assertIn('unverified_service_state_claim', harness.violations(question, '현재 정상입니다.', []))
        self.assertNotIn('unverified_service_state_claim', harness.violations(question, '정상 여부는 미확인입니다.', []))
        self.assertNotIn('unverified_service_state_claim', harness.violations(question, '실행 중인지 확인하지 못했습니다.', []))
        for text in ('현재 정상입니다. 전체 로그 무손실 여부는 미확인입니다.',
                     '현재 정상 상태입니다.다만 공격 탐지 성공은 미확인입니다.',
                     '실행 중입니다. 하지만 장애 원인은 미확인입니다.'):
            self.assertIn('unverified_service_state_claim', harness.violations(question, text, []))

    def test_unrelated_failed_tampered_or_other_target_reads_never_ground_health(self):
        question = '벡터 살아 있어?'
        records = [observation(error=True), observation('b:ollama')]
        bad = observation();bad['result_sha256'] = '0'*64;records.append(bad)
        bad = observation();bad['server'] = 'rule-a';records.append(bad)
        records.append({'server': 'resp', 'name': 'list_blocks', 'arguments': {},
                        'result': '{}', 'result_sha256': hashlib.sha256(b'{}').hexdigest()})
        for record in records:
            with self.subTest(record=record):
                self.assertEqual(harness.missing_reads(question, [record], ['a:vector']), ['a:vector'])
                self.assertIn('unverified_service_state_claim', harness.violations(question, '현재 정상입니다.', [record]))
        self.assertEqual(harness.missing_reads(question, [observation()], ['a:vector']), [])
        self.assertNotIn('unverified_service_state_claim', harness.violations(question, '현재 정상입니다.', [observation()]))

    def test_latest_failed_diagnostic_invalidates_an_earlier_success(self):
        calls = [observation(), observation(error=True)]
        self.assertEqual(harness.missing_reads('벡터 지금 상태는?', calls, ['a:vector']), ['a:vector'])
        rendered = harness.diagnostic_report('벡터 지금 상태는?', calls, ['a:vector'])
        self.assertIn('미확인', rendered)
        self.assertNotIn('| a:vector | 점검 통과', rendered)


class NoArgumentSchema(unittest.TestCase):
    def test_real_noargument_shape_has_explicit_object_properties_without_new_arguments(self):
        for name in ('get_wazuh_remoted_stats', 'get_wazuh_cluster_health', 'get_wazuh_weekly_stats'):
            raw = {'type': 'object', 'title': 'NoParams'}
            normalized = harness.CONTRACT.normalized_schema('mcp__wazuh_ro__'+name, raw)
            self.assertEqual(normalized['properties'], {})
            self.assertIs(normalized['additionalProperties'], True)
            self.assertEqual(raw, {'type': 'object', 'title': 'NoParams'})

    def test_existing_properties_required_and_constraints_remain_unchanged(self):
        schema = {'type': 'object', 'properties': {'target': {'type': 'string'},
                  'metadata': {'type': 'object', 'additionalProperties': {'type': 'integer'}}},
                  'required': ['target'], 'additionalProperties': False}
        self.assertEqual(harness.CONTRACT.normalized_schema('fixture', schema), schema)
        closed = {'type': 'object', 'additionalProperties': False}
        self.assertIs(harness.CONTRACT.normalized_schema('fixture', closed)['additionalProperties'], False)

    def test_shared_hermes_openai_normalization_also_repairs_noargument_tools(self):
        request = {'tools': [{'type': 'function', 'function': {'name': 'mcp__wazuh_ro__get_wazuh_cluster_health',
                    'parameters': {'type': 'object'}}}]}
        original = copy.deepcopy(request)
        normalized = harness.CONTRACT.normalize_openai(request)
        self.assertEqual(normalized['tools'][0]['function']['parameters']['properties'], {})
        self.assertEqual(request, original)


if __name__ == '__main__': unittest.main()
