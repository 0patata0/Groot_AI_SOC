"""Explicit recent windows ("최근 30분") are pinned from the question, not computed.

2026-11-13: a model-computed end time 26 s ahead was refused (17:21), and
"최근 30분" was read with a 60-minute lookback (20:16). The shared contract
reads one explicit window; Native pins the first event read to that length and
drops absolute ends, exactly like the existing "오늘" handling.
"""
import copy
import unittest

import chat_contract as c
import soc_management_run as w

SCHEMA = {'type': 'object', 'properties': {
    'since_kst': {'type': 'string'}, 'until_kst': {'type': 'string'},
    'lookback_minutes': {'type': 'integer', 'minimum': 1, 'maximum': 1440},
    'limit': {'type': 'integer', 'minimum': 1, 'maximum': 50}}}
NAME = 'mcp__security_events__search_modsecurity_alerts'
AT = '2026-11-13T20:16:01+09:00'


class Parser(unittest.TestCase):
    def test_one_explicit_window(self):
        for question, minutes in (('최근 30분 WAF 경보', 30), ('지난 2시간 Wazuh 경보', 120), ('직전 10분 로그', 10),
                                  ('최근 한 시간 경보', 60), ('30분간 경보', 30), ('1시간 동안 경보', 60),
                                  ('최근 반시간', 30), ('최근 24시간 경보', 1440), ('최근30분 경보', 30)):
            with self.subTest(question=question):
                self.assertEqual(c.relative_lookback_minutes(question), minutes)

    def test_ambiguous_or_absolute_times_are_not_interpreted(self):
        for question in ('최근 경보 보여줘', '오늘 경보', '1시간 전 경보', '최근 30분과 지난 1시간 비교', '최근 1시간 30분',
                         '30분 간격으로 보여줘', '5분마다', '오후 3시 30분 이후', '어제 최근 1시간', '11월 10일 최근 1시간',
                         '최근 3일', '최근 48시간', '20:00부터 30분', '경보 30분 10개 보여줘', None):
            with self.subTest(question=question):
                self.assertIsNone(c.relative_lookback_minutes(question))

    def test_window_phrase_removal_only_for_an_accepted_window(self):
        self.assertNotIn('30분', c.without_relative_window('최근 30분 WAF 로그 보여줘'))
        self.assertEqual(c.without_relative_window('1시간 전 WAF 로그 보여줘'), '1시간 전 WAF 로그 보여줘')


class NativeFirstRead(unittest.TestCase):
    def test_recent_window_pins_length_and_drops_absolute_ends(self):
        before = copy.deepcopy(SCHEMA)
        out = w.initial_event_filter_schema(NAME, SCHEMA, '최근 30분 ModSecurity와 Wazuh 경보를 조사해줘', AT)
        self.assertEqual(SCHEMA, before)
        self.assertNotIn('since_kst', out['properties'])
        self.assertNotIn('until_kst', out['properties'])
        self.assertEqual(out['properties']['lookback_minutes']['enum'], [30])
        self.assertIn('lookback_minutes', out['required'])

    def test_controller_bound_interval_today_and_unspecified_are_unchanged(self):
        bound = dict(copy.deepcopy(SCHEMA), required=['since_kst', 'until_kst'])
        self.assertEqual(w.initial_event_filter_schema(NAME, bound, '최근 30분 WAF 경보', AT)['properties'].keys(),
                         SCHEMA['properties'].keys())
        today = w.initial_event_filter_schema(NAME, SCHEMA, '오늘 WAF 경보', AT)
        self.assertEqual(today['properties']['until_kst']['enum'], [AT])
        self.assertNotIn('lookback_minutes', today['properties'])
        self.assertEqual(w.initial_event_filter_schema(NAME, SCHEMA, '최근 WAF 경보', AT), SCHEMA)

    def test_window_outside_catalog_bounds_is_not_pinned(self):
        narrow = copy.deepcopy(SCHEMA)
        narrow['properties']['lookback_minutes']['maximum'] = 20
        self.assertEqual(w.initial_event_filter_schema(NAME, narrow, '최근 30분 WAF 경보', AT), narrow)
        fixed = copy.deepcopy(SCHEMA)
        fixed['properties']['lookback_minutes']['enum'] = [60]
        self.assertEqual(w.initial_event_filter_schema(NAME, fixed, '최근 30분 WAF 경보', AT), fixed)


if __name__ == '__main__':
    unittest.main()
