"""Current queue read scope must match the registered endpoint, not a history guess."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
import harness as h

NAME='mcp__system_diagnostics__get_system_diagnostics'
TARGET='b:management-pipeline'
QUESTION='관제 조사 대기 현황 보여줘'


def schemas():
    return {NAME:{'type':'object','properties':{
        'target':{'type':'string','enum':[TARGET,'b:management','a:systemd']},
        'lookback_minutes':{'type':'integer','minimum':1,'maximum':240},
        'since_kst':{'type':'string'},'until_kst':{'type':'string'}},
        'required':['target'],'additionalProperties':False}}


class PipelineSelection(unittest.TestCase):
    def refine(self, question=QUESTION, catalog=None, calls=()):
        return h.refine_read_schemas(question,catalog or schemas(),list(calls),[TARGET,'b:management','a:systemd'])

    def test_current_queue_selects_registered_target_without_time_arguments(self):
        original=schemas();before=copy.deepcopy(original)
        for question in (QUESTION,'지금 관제 보고 밀려 있어?','관제 처리 대기 상태 보여줘'):
            with self.subTest(question=question):
                result=self.refine(question,original)
                self.assertEqual(set(result),{NAME})
                self.assertEqual(set(result[NAME]['properties']),{'target'})
                self.assertEqual(result[NAME]['properties']['target']['enum'],[TARGET])
                self.assertEqual(result[NAME]['required'],['target'])
                self.assertFalse(result[NAME]['additionalProperties'])
                self.assertEqual(h.selection_schema(result,32,question=question)['properties']['calls']['maxItems'],1)
        self.assertEqual(original,before)

    def test_unregistered_target_and_extra_required_argument_are_not_invented_or_weakened(self):
        catalog=schemas();catalog[NAME]['properties']['target']['enum'].remove(TARGET)
        self.assertEqual(self.refine(catalog=catalog),{})
        catalog=schemas();catalog[NAME]['required'].append('lookback_minutes')
        self.assertEqual(self.refine(catalog=catalog),{})
        self.assertEqual(h.refine_read_schemas(QUESTION,{},[],[TARGET]),{})

    def test_history_cause_and_changes_do_not_take_single_current_queue_shortcut(self):
        for question in ('어제 관제 보고가 밀린 원인 조사해줘','관제 대기열 왜 지연되는지 분석해줘',
                         '관제 대기 문제 복구해줘','어제 관제 대기 현황 보여줘'):
            with self.subTest(question=question):
                self.assertFalse(h.pipeline_lookup_request(question))
                self.assertEqual(h.selection_schema(schemas(),32,question=question)['properties']['calls']['maxItems'],4)

    def test_successful_current_receipt_is_not_silently_repeated_but_failed_latest_stays_missing(self):
        raw=json.dumps({'schema':1,'target':TARGET,'kind':'runtime','status':'ok',
                        'observed_at_kst':'2026-11-07T09:00:00+09:00'})
        call={'server':'system-diagnostics','name':'get_system_diagnostics','arguments':{'target':TARGET},
              'is_error':False,'result':raw,'result_sha256':hashlib.sha256(raw.encode()).hexdigest()}
        self.assertEqual(self.refine(calls=[call]),{})
        self.assertEqual(set(self.refine(calls=[call,dict(call,is_error=True)])),{NAME})
        self.assertEqual(set(self.refine(calls=[dict(call,result_sha256='0'*64)])),{NAME})

    @unittest.skipUnless(importlib.util.find_spec('jsonschema'),'use server installed validator')
    def test_real_validator_rejects_history_wrong_target_or_variations_before_dispatch(self):
        from jsonschema import ValidationError
        schema=h.selection_schema(self.refine(),32,question=QUESTION)
        for args in ({'target':TARGET,'lookback_minutes':15},{'target':'b:management'},
                     {'target':TARGET,'since_kst':'2026-11-06T00:00:00+09:00'}):
            with self.subTest(args=args),self.assertRaises(ValidationError):
                h.validated_selection({'calls':[{'tool':NAME,'arguments':args}]},schema)
        with self.assertRaises(ValidationError):
            h.validated_selection({'calls':[{'tool':NAME,'arguments':{'target':TARGET}},
                                          {'tool':NAME,'arguments':{'target':TARGET,'lookback_minutes':15}}]},schema)
        plan,removed=h.validated_selection({'calls':[{'tool':NAME,'arguments':{'target':TARGET}}]*2},schema)
        self.assertEqual(removed,1);self.assertEqual(len(plan['calls']),1)


if __name__=='__main__':unittest.main()
