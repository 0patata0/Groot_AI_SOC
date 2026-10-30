import json
import unittest

from compare_dedale_clocks import epoch_microseconds, event_key, index_exports, compare_source


class ClockComparisonTests(unittest.TestCase):
    def setUp(self):
        self.source = {'program': 'suricata', '@version': '1', 'pid': '42',
                       '@timestamp': '2025-01-10T11:34:09.076Z',
                       'timestamp': '2025-01-10T11:34:09.076943+00:00',
                       'timestamp8601': '2025-01-10T11:34:09.076943+00:00',
                       'host': '192.0.2.1', 'message': 'synthetic event', 'priority': 171}
        stamp = epoch_microseconds(self.source['@timestamp']) // 1000
        self.export = {**self.source, '@version': 1, 'pid': 42,
                       **{k: stamp for k in ('@timestamp', 'timestamp', 'timestamp8601')}}

    def line(self, item):
        return json.dumps(item).encode() + b'\n'

    def test_equivalent_offset_and_microsecond_truncation(self):
        self.assertEqual(epoch_microseconds('2025-01-10T20:34:09.076+09:00'),
                         epoch_microseconds('2025-01-10T11:34:09.076Z'))
        self.assertEqual(event_key(self.source, representation='source-iso'),
                         event_key(self.export, representation='export-integer'))

    def test_naive_numeric_or_excess_precision_rejected(self):
        for value in ['2025-01-10T11:34:09', 1736508849076, '2025-01-10T11:34:09.1234567Z']:
            with self.assertRaises(ValueError): epoch_microseconds(value)

    def test_same_timestamp_different_sensor_or_message_is_not_same_event(self):
        expected = event_key(self.source, representation='source-iso')
        for item in [{**self.source, 'host': '192.0.2.9'}, {**self.source, 'message': 'different'}]:
            self.assertNotEqual(expected, event_key(item, representation='source-iso'))

    def test_priority_is_not_silently_normalized(self):
        self.assertNotEqual(event_key(self.export, representation='export-integer'),
                            event_key({**self.export, 'priority': '171'}, representation='export-integer'))

    def test_unrecognized_field_is_not_dropped(self):
        self.assertNotEqual(event_key(self.source, representation='source-iso'),
                            event_key({**self.source, 'extra': True}, representation='source-iso'))

    def test_conflicting_source_clock_rejected(self):
        for key, value in [('timestamp', '2025-01-10T11:34:09.077Z'),
                           ('timestamp8601', '2025-01-10T11:34:09.076944Z')]:
            with self.assertRaises(ValueError):
                event_key({**self.source, key: value}, representation='source-iso')

    def test_boolean_or_conflicting_export_clock_rejected(self):
        for value in [True, self.export['timestamp'] + 1]:
            with self.assertRaises(ValueError):
                event_key({**self.export, 'timestamp': value}, representation='export-integer')

    def test_duplicate_multiplicity_and_excess_source(self):
        remaining, info = index_exports([self.line(self.export)] * 2)
        self.assertEqual(info['duplicate_instances'], 1)
        result = compare_source([self.line(self.source)] * 3, remaining, source='fixture')
        self.assertEqual(result['counts']['matched'], 2)
        self.assertEqual(result['counts']['not_in_export_or_excess'], 1)
        self.assertFalse(remaining)

    def test_missing_export_is_not_hidden_by_other_program(self):
        remaining, _ = index_exports([self.line(self.export)])
        result = compare_source([self.line({'program': 'sshd'})], remaining, source='fixture')
        self.assertEqual(result['counts']['rows'], 1)
        self.assertEqual(result['counts']['suricata'], 0)
        self.assertEqual(sum(remaining.values()), 1)

    def test_submillisecond_events_are_not_deduplicated(self):
        other = {**self.source, 'timestamp': '2025-01-10T11:34:09.076111Z',
                 'timestamp8601': '2025-01-10T11:34:09.076111Z'}
        remaining, _ = index_exports([self.line(self.export)] * 2)
        result = compare_source([self.line(self.source), self.line(other)], remaining,
                                source='fixture', sample_limit=2)
        self.assertEqual(result['counts']['matched'], 2)
        self.assertEqual(result['samples'][0]['epoch_ms'], result['samples'][1]['epoch_ms'])
        self.assertNotEqual(result['samples'][0]['source_timestamps'], result['samples'][1]['source_timestamps'])
        self.assertFalse(remaining)

    def test_exact_coordinate_hash_and_kst(self):
        remaining, _ = index_exports([self.line(self.export)])
        prefix = self.line({'program': 'sshd'})
        result = compare_source([prefix, self.line(self.source)], remaining, source='fixture')
        sample = result['samples'][0]
        self.assertEqual(sample['line'], 2)
        self.assertEqual(sample['byte_offset'], len(prefix))
        self.assertEqual(sample['timestamp_kst'], '2025-01-10T20:34:09.076000+09:00')
        self.assertEqual(sample['source_timestamps']['timestamp'], self.source['timestamp'])


if __name__ == '__main__':
    unittest.main()
