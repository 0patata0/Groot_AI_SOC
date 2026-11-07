"""Current service scope uses registered targets and real MCP default semantics."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from jsonschema import Draft202012Validator, ValidationError
import harness as h

NAME='mcp__system_diagnostics__get_system_diagnostics'
QUESTION='B 서버 capstone-management.service의 지금 실행 상태와 시작 설정 알려줘.'
ROOT=Path(__file__).resolve().parents[2]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
mcp=load('current_diagnostic_mcp',ROOT/'infra/mcp/system-diagnostics-mcp.py')
mcp._library=load('current_diagnostic_core',ROOT/'infra/mcp/system_diagnostics.py')
def catalog():return {NAME:copy.deepcopy(next(t['inputSchema'] for t in mcp.tools() if t['name']=='get_system_diagnostics'))}
def choice(**args):return {'tool':NAME,'arguments':{'target':'b:management',**args}}
def receipt(target='b:management',error=False):
    raw=json.dumps({'schema':1,'target':target,'status':'observed','properties':{'UnitFileState':'static'}})
    return {'server':'system-diagnostics','name':'get_system_diagnostics','arguments':{'target':target},'result':raw,'result_sha256':hashlib.sha256(raw.encode()).hexdigest(),'is_error':error}

class CurrentDiagnosticSelection(unittest.TestCase):
    def refine(self,question=QUESTION,calls=(),source=None):
        return h.refine_read_schemas(question,source or catalog(),list(calls),['a:systemd','b:management','c:systemd'])

    def test_named_current_service_keeps_registered_constraints_and_excludes_other_hosts(self):
        original=catalog();before=copy.deepcopy(original);result=self.refine(source=original);schema=result[NAME]
        self.assertEqual(original,before)
        self.assertEqual(schema['properties']['target']['enum'],['b:management'])
        for key in ('limit','lookback_minutes'):self.assertEqual(schema['properties'][key],original[NAME]['properties'][key])
        self.assertEqual(schema['allOf'],original[NAME]['allOf'])
        for args in ({'target':'a:systemd'},{'target':'b:management-pipeline'},
                     {'target':'b:management','since_kst':'2026-11-07T00:00:00+09:00','until_kst':'2026-11-07T01:00:00+09:00'}):
            with self.subTest(args=args):self.assertFalse(Draft202012Validator(schema).is_valid(args))
        self.assertTrue(Draft202012Validator(schema).is_valid({'target':'b:management','limit':50}))
        self.assertEqual(h.selection_schema(result,32,question=QUESTION)['properties']['calls']['maxItems'],1)

    def test_missing_registration_and_required_history_are_not_invented(self):
        source=catalog();source[NAME]['properties']['target']['enum'].remove('b:management')
        self.assertEqual(self.refine(source=source),{})
        source=catalog();source[NAME]['required'].append('since_kst')
        self.assertEqual(self.refine(source=source),{})
        self.assertEqual(h.refine_read_schemas(QUESTION,{},[]),{})

    def test_multiple_requested_targets_are_all_retained_and_success_excluded(self):
        q='A 서버 Vector와 B 서버 capstone-management.service 현재 상태?'
        result=self.refine(q);self.assertEqual(set(result[NAME]['properties']['target']['enum']),{'a:vector','b:management'})
        self.assertEqual(h.selection_schema(result,32,question=q)['properties']['calls']['maxItems'],2)
        result=self.refine(q,[receipt()]);self.assertEqual(result[NAME]['properties']['target']['enum'],['a:vector'])
        result=self.refine(q,[receipt(),receipt(error=True)]);self.assertEqual(set(result[NAME]['properties']['target']['enum']),{'a:vector','b:management'})

    def test_completed_read_stops_but_latest_failure_or_bad_hash_remains_missing(self):
        self.assertEqual(self.refine(calls=[receipt()]),{})
        for failed in (receipt(error=True),dict(receipt(),result_sha256='0'*64)):
            self.assertEqual(self.refine(calls=[receipt(),failed])[NAME]['properties']['target']['enum'],['b:management'])

    def test_history_comparison_and_explicit_resampling_keep_investigative_scope(self):
        for q in ('어제 B 서버 capstone-management.service 실패와 현재 원인 조사',
                  'B 서버 capstone-management.service 지금 상태 두 번 비교해줘',
                  'B 서버 capstone-management.service 2회 연속 조회',
                  'B 서버 capstone-management.service 2026-11-07 상태 확인'):
            with self.subTest(q=q):
                self.assertFalse(h.current_diagnostic_lookup(q))
                self.assertIsNone(h.diagnostic_request(q))
                self.assertIsNone(h.tool_scope(q))
                self.assertEqual(h.selection_schema(catalog(),32,question=q)['properties']['calls']['maxItems'],4)

    def test_explicit_unit_host_is_not_replaced_by_default_in_multi_host_request(self):
        q='A 서버 Vector와 C 서버 capstone-management.service 현재 상태?'
        selected,unsupported=h.diagnostic_scope(q,catalog()[NAME]['properties']['target']['enum'])
        self.assertEqual(selected,['a:vector']);self.assertEqual(unsupported,['c:management'])
        self.assertTrue(h.missing_reads(q,[receipt('a:vector')],catalog()[NAME]['properties']['target']['enum']))

    def test_registered_defaults_collapse_only_equivalent_selection_without_rewriting(self):
        schema=h.selection_schema(self.refine(),32,question=QUESTION)
        choices=[choice(),choice(limit=20,lookback_minutes=15),choice(limit=20)]
        before=copy.deepcopy(choices);plan,removed=h.validated_selection({'calls':choices},schema)
        self.assertEqual(removed,2);self.assertEqual(plan['calls'],[choices[0]]);self.assertEqual(choices,before)
        self.assertEqual(mcp.arguments(choices[0]['arguments']),mcp.arguments(choices[1]['arguments']))

    def test_different_sample_limits_or_lookback_are_not_collapsed(self):
        schema=h.selection_schema(catalog(),32)
        for second in (choice(limit=50),choice(lookback_minutes=30)):
            with self.subTest(second=second):
                plan,removed=h.validated_selection({'calls':[choice(),second]},schema)
                self.assertEqual(removed,0);self.assertEqual(len(plan['calls']),2)

    def test_missing_or_invalid_default_annotation_is_not_assumed(self):
        for invalid in ('absent',0,True,'20'):
            source=catalog()
            if invalid=='absent':source[NAME]['properties']['limit'].pop('default')
            else:source[NAME]['properties']['limit']['default']=invalid
            schema=h.selection_schema(source,32)
            plan,removed=h.validated_selection({'calls':[choice(),choice(limit=20)]},schema)
            self.assertEqual(removed,0)

    def test_invalid_last_choice_rejects_entire_batch_before_deduplication(self):
        schema=h.selection_schema(self.refine(),32,question=QUESTION)
        for bad in (choice(limit=51),{'tool':NAME,'arguments':{'target':'a:systemd'}},
                    {'tool':'mcp__resp__block_ip','arguments':{'ip':'192.0.2.1'}}):
            with self.subTest(bad=bad),self.assertRaises(ValidationError):
                h.validated_selection({'calls':[choice(),choice(),bad]},schema)

if __name__=='__main__':unittest.main()
