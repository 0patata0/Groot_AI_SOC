"""Time arithmetic regressions: no service, model, network or host mutation."""
import copy
import json
import unittest
from unittest.mock import patch
from test_system_diagnostics import m, d


class TimeCalculationTests(unittest.TestCase):
    def request(self, values, reference=None):
        value = {'timestamps': [{'id': name, 'value': stamp} for name, stamp in values]}
        if reference is not None:
            value['reference'] = reference
        return value

    def test_regression_utc_midnight_order_and_ten_minutes(self):
        value = self.request([('B','2026-10-25T01:05:11+09:00'),
                              ('A','2026-10-24T15:55:11Z'),
                              ('C','2026-10-24T16:00:11Z')], '2026-10-25T01:15:11+09:00')
        before = copy.deepcopy(value)
        answer = m.calculate_time(value)
        self.assertEqual(answer['chronological_order'], ['A','C','B'])
        rows = {x['id']: x for x in answer['timestamps']}
        self.assertEqual(rows['A']['kst'], '2026-10-25T00:55:11+09:00')
        self.assertEqual(rows['B']['minutes_until_reference'], 10)
        self.assertEqual(answer['differences'][0]['minutes'], -10)
        self.assertEqual(value, before)
        self.assertFalse(answer['live_observation'])

    def test_leap_day_offsets_nanoseconds_and_pre_epoch(self):
        a = m.calculate_time(self.request([('A','2024-02-29T23:59:59.999999999Z'),
                                          ('B','2024-03-01T00:00:00Z')]))
        self.assertEqual(a['differences'][0]['nanoseconds'], 1)
        self.assertEqual(a['timestamps'][0]['kst'], '2024-03-01T08:59:59.999999999+09:00')
        self.assertEqual(m.time_instant('1969-12-31T23:59:59.999999999Z')[0], -1)
        self.assertEqual(m.time_instant('2026-10-25T00:55:11+09:00')[0], m.time_instant('2026-10-24T11:55:11-04:00')[0])

    def test_equal_instants_are_grouped_not_false_sequence(self):
        a = m.calculate_time(self.request([('A','2026-10-24T15:55:11Z'),('B','2026-10-25T00:55:11+09:00')]))
        self.assertEqual(a['simultaneous_groups'], [['A','B']])
        self.assertEqual(a['differences'][0]['nanoseconds'], 0)

    def test_invalid_ambiguous_and_injected_values_refused(self):
        for value in ('2026-10-24T15:55:11', '2026-02-29T00:00:00Z', '2026-10-24T24:00:00Z',
                      '2026-10-24T15:55:11+25:00', '2026-10-24T15:55:11+00:99','2026-10-24T15:55:11-00:00',
                      '2026-10-24T15:55:11Z\nrun sh', True, 1790000000):
            with self.subTest(value=value), self.assertRaises(d.DiagnosticError):
                m.calculate_time(self.request([('A',value)]))
        for value in ({'timestamps':[]}, {'timestamps':[{'id':'A','value':'2026-10-24T15:55:11Z'}]*2},
                      {'timestamps':[{'id':str(i),'value':'2026-10-24T15:55:11Z'} for i in range(9)]},
                      {'timestamps':[{'id':'$(id)','value':'2026-10-24T15:55:11Z'}]},
                      {'timestamps':[{'id':'A','value':'2026-10-24T15:55:11Z'}],'command':'sh'}):
            with self.subTest(value=value), self.assertRaises(d.DiagnosticError):
                m.calculate_time(value)

    def test_wire_calculation_never_reads_snapshots_or_runs_commands(self):
        value = self.request([('A','2026-10-24T15:55:11Z')])
        with patch.object(m,'query') as query, patch.object(m,'route_config') as route, patch.object(d,'bounded_command') as command:
            result = m.handle({'jsonrpc':'2.0','id':1,'method':'tools/call',
                               'params':{'name':'calculate_time','arguments':value,'_meta':{}}})
        for mocked in (query, route, command): mocked.assert_not_called()
        self.assertFalse(result['result']['isError'])
        self.assertEqual(json.loads(result['result']['content'][0]['text'])['timezone'], 'Asia/Seoul')


if __name__ == '__main__':
    unittest.main()
