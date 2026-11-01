"""A read snapshot must not silently become a complete training admission."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from capture_training_mcp import READS, validate_capture


def receipt():
    tools = {}
    reads = []
    for server, requests in READS.items():
        for name, arguments in requests:
            alias = 'mcp__' + server.replace('-', '_') + '__' + name
            tools[alias] = {'server': server, 'name': alias, 'protected': False,
                            'parameters': {'type': 'object', 'properties': {}}}
            text = json.dumps({'status': 'observed', 'current_file_checked': False})
            reads.append({'server': server, 'name': name, 'alias': alias,
                          'arguments': copy.deepcopy(arguments), 'result': text,
                          'sha256': hashlib.sha256(text.encode()).hexdigest(),
                          'is_error': False, 'at_kst': '2026-11-01T14:25:00+09:00'})
    return {'status': 'completed', 'errors': [], 'protected_calls': 0,
            'model_calls': 0, 'chat_posts': 0, 'cleansing_performed': False,
            'tools': list(tools.values()), 'reads': reads}


class CaptureTests(unittest.TestCase):
    def test_complete_read_receipt_is_not_training_or_quality_approval(self):
        review = validate_capture(receipt())
        self.assertEqual(review['reads'], 17)
        self.assertFalse(review['training_admitted'])
        self.assertFalse(review['answer_accuracy_reviewed'])

    def test_missing_duplicate_and_extra_reads_fail(self):
        for operation in ('missing', 'duplicate', 'extra'):
            r = receipt()
            if operation == 'missing':
                r['reads'].pop()
            elif operation == 'duplicate':
                r['reads'].append(copy.deepcopy(r['reads'][0]))
            else:
                r['reads'][0]['arguments']['unrequested'] = True
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                validate_capture(r)

    def test_wrong_alias_protected_tool_and_duplicate_catalog_fail(self):
        for operation in ('alias', 'protected', 'catalog'):
            r = receipt()
            if operation == 'alias':
                r['reads'][0]['alias'] = 'mcp__resp__block_ip'
            elif operation == 'protected':
                r['tools'][0]['protected'] = True
            else:
                r['tools'].append(copy.deepcopy(r['tools'][0]))
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                validate_capture(r)

    def test_tool_errors_and_digest_changes_fail(self):
        for operation in ('is_error', 'error_body', 'digest'):
            r = receipt()
            if operation == 'is_error':
                r['reads'][0]['is_error'] = True
            else:
                r['reads'][0]['result'] = json.dumps({'error': 'storage unavailable'})
                if operation == 'error_body':
                    r['reads'][0]['sha256'] = hashlib.sha256(r['reads'][0]['result'].encode()).hexdigest()
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                validate_capture(r)

    def test_schema_drift_is_not_accepted(self):
        r = receipt()
        r['tools'][0]['parameters']['required'] = ['new_required_argument']
        with self.assertRaises(ValueError):
            validate_capture(r)

    def test_partial_or_wrong_execution_location_fails(self):
        for key, value in [('status', 'partial'), ('errors', [{'phase': 'transport'}]),
                           ('protected_calls', 1), ('model_calls', 1), ('chat_posts', 1),
                           ('cleansing_performed', True), ('protected_calls', False)]:
            r = receipt()
            r[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_capture(r)

    def test_non_kst_receipt_fails(self):
        r = receipt()
        r['reads'][0]['at_kst'] = '2026-11-01T05:25:00+00:00'
        with self.assertRaises(ValueError):
            validate_capture(r)


if __name__ == '__main__':
    unittest.main()
