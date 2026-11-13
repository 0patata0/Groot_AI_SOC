"""2026-11-13 17:21 joint-channel lookup: a corrected read-time refusal.

The model rounded until_kst to 17:21:27 while the call ran at 17:21:26. The
event MCP refused it as "must be in the past 90 days", the model re-read with a
valid window and reported, yet the chat showed "tool lookup failed". Two fixes:
the shared contract refuses a future end with its real cause before any MCP
call, and the worker no longer counts a refusal the same run corrected.
"""
from datetime import datetime, timedelta, timezone
import copy
import json
import unittest

import chat_contract as c
import review_channel_worker as w
import soc_management_controller as controller

KST = timezone(timedelta(hours=9))
NOW = datetime(2026, 11, 13, 17, 21, 26, tzinfo=KST)
SCHEMA = {'type': 'object', 'properties': {k: {'type': 'string'} for k in ('since_kst', 'until_kst')} | {
    'limit': {'type': 'integer'}, 'lookback_minutes': {'type': 'integer'}, 'wazuh_rule_id': {'type': 'string'}}}
REFUSAL = json.dumps({'error': json.dumps({'error': 'until_kst must be in the past 90 days'})})


def receipt(name, arguments, error=False, result='{"returned_count": 0}'):
    return {'server': 'security-events', 'name': name, 'arguments': arguments,
            'is_error': error, 'result': REFUSAL if error else result}


class FutureEnd(unittest.TestCase):
    def test_the_1721_end_time_is_refused_with_its_real_cause_and_unchanged(self):
        args = {'since_kst': '2026-11-13T16:20:27+09:00', 'until_kst': '2026-11-13T17:21:27+09:00', 'limit': 50}
        before = copy.deepcopy(args)
        rejection = c.read_time_input_rejection(args, SCHEMA, now=NOW)
        self.assertEqual(rejection['error'], 'tool_input_time_future')
        self.assertFalse(rejection['mcp_executed'])
        self.assertIn('requested_at_kst', rejection['detail'])
        self.assertEqual(args, before)
        # One second later the same input is valid: nothing is rewritten or clamped.
        self.assertIsNone(c.read_time_input_rejection(args, SCHEMA, now=NOW + timedelta(seconds=2)))

    def test_until_only_reads_are_checked_too(self):
        self.assertEqual(c.read_time_input_rejection(
            {'until_kst': '2026-11-13T17:30:00+09:00', 'lookback_minutes': 60}, SCHEMA, now=NOW)['error'], 'tool_input_time_future')
        self.assertIsNone(c.read_time_input_rejection(
            {'until_kst': '2026-11-13T17:00:00+09:00', 'lookback_minutes': 60}, SCHEMA, now=NOW))
        self.assertEqual(c.read_time_input_rejection(
            {'until_kst': 'yesterday'}, SCHEMA, now=NOW)['error'], 'tool_input_time_invalid')

    def test_order_errors_keep_priority_and_schemas_without_until_are_untouched(self):
        args = {'since_kst': '2026-11-13T18:00:00+09:00', 'until_kst': '2026-11-13T17:59:00+09:00'}
        self.assertEqual(c.read_time_input_rejection(args, SCHEMA, now=NOW)['error'], 'tool_input_time_order_invalid')
        self.assertIsNone(c.read_time_input_rejection({'until_kst': '2026-11-14T00:00:00+09:00'}, {'type': 'object'}, now=NOW))
        self.assertIsNone(c.read_time_input_rejection({'target': 'a:suricata'}, SCHEMA, now=NOW))


class CorrectedRefusal(unittest.TestCase):
    def test_the_1721_run_is_not_a_tool_failure(self):
        # Order of the real session daa0fd: two refused reads, then the same tools re-read successfully.
        calls = [receipt('search_suricata_alerts', {'since_kst': '2026-11-13T16:20:27+09:00', 'until_kst': '2026-11-13T17:21:27+09:00', 'limit': 50}, True),
                 receipt('search_wazuh_alerts', {'since_kst': '2026-11-13T16:20:27+09:00', 'until_kst': '2026-11-13T17:21:27+09:00', 'limit': 50}, True),
                 receipt('search_wazuh_alerts', {'until_kst': '2026-11-13T17:21:27+09:00', 'wazuh_rule_id': '5712'}),
                 receipt('search_suricata_alerts', {'until_kst': '2026-11-13T17:21:27+09:00', 'lookback_minutes': 60, 'limit': 50}),
                 receipt('search_wazuh_alerts', {'until_kst': '2026-11-13T17:21:27+09:00', 'lookback_minutes': 60, 'limit': 50})]
        self.assertFalse(w.uncorrected_tool_failure(controller, calls))

    def test_a_refusal_only_corrected_by_a_different_filter_still_counts(self):
        calls = [receipt('search_wazuh_alerts', {'since_kst': '2026-11-13T16:20:27+09:00', 'until_kst': '2026-11-13T17:21:27+09:00'}, True),
                 receipt('search_wazuh_alerts', {'lookback_minutes': 60, 'wazuh_rule_id': '5712'})]
        self.assertTrue(w.uncorrected_tool_failure(controller, calls))

    def test_a_refusal_after_the_last_success_still_counts(self):
        args = {'since_kst': '2026-11-13T16:20:27+09:00', 'until_kst': '2026-11-13T17:21:27+09:00'}
        calls = [receipt('search_suricata_alerts', args), receipt('search_suricata_alerts', args, True)]
        self.assertTrue(w.uncorrected_tool_failure(controller, calls))

    def test_any_other_error_is_still_a_tool_failure(self):
        other = {'server': 'rule-a', 'name': 'get_service_action_target', 'arguments': {'target': 'a:suricata'},
                 'is_error': True, 'result': json.dumps({'error': 'timeout'})}
        calls = [other, receipt('search_suricata_alerts', {'lookback_minutes': 60})]
        self.assertTrue(w.uncorrected_tool_failure(controller, calls))
        self.assertFalse(w.uncorrected_tool_failure(controller, [receipt('search_suricata_alerts', {'lookback_minutes': 60})]))


if __name__ == '__main__':
    unittest.main()
