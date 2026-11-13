"""A first read is never narrower than the question (2026-11-13 22:22).

An unasked program_name='systemd' narrowed the peer's Wazuh read, and Hermes
sent an invented firewall snapshot (FileNotFoundError, failed answer). The
shared first-read rule now offers a filter only when the question names it and
starts a firewall read from a fresh snapshot.
"""
import copy
import unittest

from jsonschema import Draft202012Validator as V

import soc_management_run as w

WAZUH = 'mcp__security_events__search_wazuh_alerts'
FW = 'mcp__resp__get_firewall_rules'
SCHEMA = {'type': 'object', 'additionalProperties': False, 'properties': {
    'lookback_minutes': {'type': 'integer', 'minimum': 1, 'maximum': 1440},
    'limit': {'type': 'integer', 'minimum': 1, 'maximum': 50},
    'program_name': {'type': 'string', 'pattern': '^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}$'}}}
FW_SCHEMA = {'type': 'object', 'additionalProperties': False, 'properties': {
    'snapshot': {'type': 'string', 'pattern': '^[0-9a-f]{32}$'},
    'offset': {'type': 'integer', 'minimum': 0, 'maximum': 100000},
    'limit': {'type': 'integer', 'minimum': 1, 'maximum': 200}}}
AT = '2026-11-13T22:22:22+09:00'
REVIEW_QUESTION = '최근 30분 ModSecurity와 Wazuh 경보를 조사해서 지금 대응이 필요한 위험이 있는지 근거와 함께 판단해줘. 설정은 바꾸지 마.'


class FirstReadScope(unittest.TestCase):
    def test_unasked_program_filter_is_not_offered(self):
        for question in (REVIEW_QUESTION, 'sshd 로그인 성공이 많은지 봐줘', 'Wazuh 경보 보여줘', '프로그램 상태 알려줘'):
            with self.subTest(question=question):
                out = w.initial_event_filter_schema(WAZUH, SCHEMA, question, AT)
                self.assertNotIn('program_name', out['properties'])
                self.assertFalse(V(out).is_valid({'program_name': 'systemd'}))

    def test_named_program_is_pinned(self):
        for question, values in (('systemd 서비스 실패 경보 보여줘', ['systemd']), ('어제 서비스 실패 원인 조사해줘', ['systemd']),
                                 ('failed units 관련 경보', ['systemd']), ('program_name=sshd 경보', ['sshd']),
                                 ('프로그램 sudo 이벤트 보여줘', ['sudo'])):
            with self.subTest(question=question):
                self.assertEqual(w.initial_event_filter_schema(WAZUH, SCHEMA, question, AT)['properties']['program_name']['enum'], values)

    def test_required_program_name_and_input_schema_untouched(self):
        bound = dict(copy.deepcopy(SCHEMA), required=['program_name'])
        before = copy.deepcopy(bound)
        out = w.initial_event_filter_schema(WAZUH, bound, '경보 보여줘', AT)
        self.assertEqual(out['properties']['program_name'], SCHEMA['properties']['program_name'])
        self.assertEqual(bound, before)

    def test_first_firewall_read_is_a_fresh_snapshot(self):
        before = copy.deepcopy(FW_SCHEMA)
        out = w.initial_event_filter_schema(FW, FW_SCHEMA, '지금 방화벽 룰 보여줘', AT)
        self.assertEqual(set(out['properties']), {'offset', 'limit'})
        self.assertEqual(out['properties']['offset']['enum'], [0])
        self.assertEqual(FW_SCHEMA, before)
        self.assertFalse(V(out).is_valid({'snapshot': 'd41d8cd98f00b204e9800998ecf8427e'}))
        self.assertFalse(V(out).is_valid({'offset': 50}))
        self.assertTrue(V(out).is_valid({'limit': 50}))
        self.assertTrue(V(out).is_valid({'offset': 0, 'limit': 200}))
        bound = dict(copy.deepcopy(FW_SCHEMA), required=['snapshot', 'offset'])
        self.assertEqual(set(w.initial_event_filter_schema(FW, bound, 'x', AT)['properties']), {'snapshot', 'offset', 'limit'})

    def test_other_tools_are_unchanged(self):
        schema = {'type': 'object', 'properties': {'target': {'type': 'string'}, 'program_name': {'type': 'string'}}}
        self.assertIs(w.initial_event_filter_schema('mcp__system_diagnostics__get_system_diagnostics', schema, 'x', AT), schema)


if __name__ == '__main__':
    unittest.main()
