"""Evidence-loss and false-match regression cases; all fixtures synthetic."""
import bz2
import io
import json
import unittest
from link_dedale_labels import (bounded_lines, index_labels, parse,
                               scan_raw_member, validate_subset)


def line(row):
    return json.dumps(row).encode() + b'\n'


class LinkageTests(unittest.TestCase):
    def setUp(self):
        self.a = {'@timestamp': '2025-01-10T11:35:00Z', 'host': {'name': 'fixture'},
                  'message': 'fixture content', 'event': {'code': '1'}}
        self.b = {**self.a, '@timestamp': '2025-01-10T11:36:00Z'}
        self.labels, _ = index_labels([line(self.a), line(self.b)], member='combined')
        self.class1, _ = index_labels([line(self.a)], member='class1')

    def scan(self, rows, **kwargs):
        return scan_raw_member(rows, labels=self.labels, class1=self.class1,
                               member='raw', start='2025-01-10T11:00:00Z',
                               end='2025-01-10T12:00:00Z', **kwargs)

    def test_matches_reordered_json_and_preserves_provenance_without_commands(self):
        matches = []
        reordered = json.dumps(dict(reversed(list(self.a.items())))).encode()+b'\n'
        result = self.scan([reordered, line(self.b)], on_match=matches.append)
        self.assertEqual(result['matched_unique_records'], 2)
        self.assertEqual(result['missing_label_hashes'], [])
        self.assertEqual((result['matched_class_1'], result['matched_class_2_only']), (1, 1))
        self.assertEqual(matches[1]['raw_byte_offset'], len(reordered))
        self.assertEqual(matches[0]['label']['timestamp_kst'], '2025-01-10T20:35:00+09:00')
        self.assertNotIn('fixture content', json.dumps(matches))

    def test_same_time_host_different_content_not_matched(self):
        result = self.scan([line({**self.a, 'message': 'different'})])
        self.assertEqual(result['matched_unique_records'], 0)
        self.assertEqual(result['counts']['same_identity_different_content'], 1)
        self.assertEqual(len(result['missing_label_hashes']), 2)

    def test_raw_duplicates_and_unsorted_timestamps_are_visible(self):
        result = self.scan([line(self.b), line(self.a), line(self.a)])
        self.assertEqual(result['duplicate_matches'], 1)
        self.assertEqual(result['counts']['time_regressions'], 1)

    def test_absence_is_missing_not_benign(self):
        result = self.scan([])
        self.assertEqual(len(result['missing_label_hashes']), 2)
        self.assertTrue(result['unmatched_rows_are_not_benign_labels'])
        self.assertEqual(result['training_admitted'], 0)

    def test_unknown_zone_is_not_assumed_utc_or_kst(self):
        result = self.scan([line({**self.a, '@timestamp': '2025-01-10T11:35:00'})])
        self.assertEqual(result['counts']['invalid_identity_or_time'], 1)
        with self.assertRaises(ValueError):
            index_labels([line({**self.a, '@timestamp': '2025-01-10T11:35:00'})], member='bad')

    def test_same_instant_with_different_representation_is_not_an_exact_record(self):
        result = self.scan([line({**self.a, '@timestamp': '2025-01-10T20:35:00+09:00'})])
        self.assertEqual(result['matched_unique_records'], 0)
        self.assertEqual(result['counts']['invalid_identity_or_time'], 0)
        self.assertEqual(result['min_observed_kst'], '2025-01-10T20:35:00+09:00')

    def test_duplicate_label_and_invalid_subset_fail(self):
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            index_labels([line(self.a), line(self.a)], member='bad')
        with self.assertRaisesRegex(ValueError, 'subset'):
            validate_subset(self.labels, self.class1)

    def test_duplicate_json_keys_nonfinite_and_nonobject_fail(self):
        for value in [b'{"a":1,"a":2}', b'{"a":NaN}', b'[]']:
            with self.assertRaises(ValueError):
                parse(value)

    def test_line_or_total_budget_never_silently_truncates(self):
        for options in [{'max_line_bytes': 2}, {'max_bytes': 2}]:
            with self.assertRaisesRegex(ValueError, 'budget'):
                list(bounded_lines(io.BytesIO(b'ab\n'), **options))

    def test_truncated_compression_is_not_reported_complete(self):
        body = bz2.compress(line(self.a))[:-6]
        with self.assertRaises((EOFError, OSError)):
            self.scan(bounded_lines(bz2.BZ2File(io.BytesIO(body))))

    def test_whole_compressed_stream_including_last_unterminated_line(self):
        body = bz2.compress(line(self.a)+line(self.b).rstrip(b'\n'))
        result = self.scan(bounded_lines(bz2.BZ2File(io.BytesIO(body))))
        self.assertEqual(result['matched_unique_records'], 2)
        self.assertTrue(result['iterator_exhausted'])

    def test_raw_window_is_observed_not_assumed_from_filename(self):
        result = self.scan([line({**self.a, '@timestamp': '2025-01-10T12:00:00Z'})])
        self.assertEqual(result['counts']['out_of_window'], 1)
        self.assertEqual(result['expected_label_records'], 2)


if __name__ == '__main__':
    unittest.main()
