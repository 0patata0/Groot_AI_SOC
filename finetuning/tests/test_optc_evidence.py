"""Omission, timestamp and partial-input checks; no network or model required."""
import gzip
import hashlib
import json
from pathlib import Path
import sys
import unittest
import io
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from inspect_optc_evidence import inspect_prefix, observed_time, scan_records


def row(**changes):
    value = {'timestamp': '2019-09-23T11:24:54-04:00', 'hostname': 'SysClient0201.systemia.com',
             'id': 'event-1', 'actorID': 'actor-1', 'objectID': 'object-1',
             'object': 'PROCESS', 'action': 'CREATE', 'properties': {'command_line': 'do-not-copy'}}
    value.update(changes)
    return (json.dumps(value) + '\n').encode()


def check(data, **kwargs):
    return inspect_prefix(data, source_id='fixture', expected_file_bytes=len(data),
                          target_host='sysclient0201', **kwargs)


class OpTCEvidenceTests(unittest.TestCase):
    def test_explicit_offset_and_kst_idempotence(self):
        value = observed_time({'timestamp': '2019-09-23T11:24:54-04:00'})
        self.assertEqual(value, observed_time({'timestamp': '2019-09-24T00:24:54+09:00'}))
        self.assertEqual(value, observed_time({'timestamp_ms': value.timestamp()*1000}))
        for bad in ('2019-09-23T11:24:54', 1569252294, True):
            with self.assertRaises(ValueError):
                observed_time({'timestamp': bad})

    def test_conflicting_time_fields_are_not_silently_preferred(self):
        with self.assertRaisesRegex(ValueError, 'Conflicting'):
            observed_time({'timestamp': '2019-09-23T11:24:54-04:00', 'timestamp_ms': 1569252400000})

    def test_whole_stream_keeps_coordinates_not_payload_or_verdict(self):
        raw = row()
        result = check(gzip.compress(raw, mtime=0))
        self.assertTrue(result['gzip_integrity_verified'])
        sample = result['metadata_samples'][0]
        self.assertEqual(sample['raw_line_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(sample['timestamp_kst'], '2019-09-24T00:24:54+09:00')
        self.assertEqual(sample['maliciousness'], 'not_adjudicated')
        self.assertIsNone(sample['report_event_link'])
        self.assertNotIn('do-not-copy', json.dumps(result))

    def test_bad_rows_missing_id_duplicate_id_unknown_time_are_counted(self):
        raw = row() + row() + row(id=None, timestamp='unparseable') + b'{broken\n' + b'[]\n'
        result = check(gzip.compress(raw, mtime=0))
        counts = result['counts']
        self.assertEqual(counts['complete_lines'], 5)
        self.assertEqual(counts['parsed_objects'], 3)
        self.assertEqual(counts['rejected_lines'], 2)
        self.assertEqual(counts['duplicate_event_id'], 1)
        self.assertEqual(counts['missing_event_id'], 1)
        self.assertEqual(counts['unknown_timestamp'], 1)

    def test_prefix_is_never_claimed_complete_and_partial_line_is_visible(self):
        raw = b''.join(row(id=str(i)) for i in range(200))
        whole = gzip.compress(raw, mtime=0)
        results = []
        for cut in range(40, len(whole)-8, 17):
            result = inspect_prefix(whole[:cut], source_id='fixture', expected_file_bytes=len(whole),
                                    target_host='sysclient0201')
            self.assertFalse(result['whole_file_read'])
            self.assertFalse(result['gzip_integrity_verified'])
            self.assertEqual(result['coverage'], 'prefix_only')
            results.append(result)
        self.assertTrue(any(r['partial_tail_bytes'] for r in results))

    def test_corruption_truncation_and_output_cap_are_failures(self):
        data = gzip.compress(row()*100, mtime=0)
        with self.assertRaisesRegex(ValueError, 'integrity trailer'):
            check(data[:-8])
        with self.assertRaisesRegex(ValueError, 'output limit'):
            check(data, max_output_bytes=128)
        broken = bytearray(data); broken[-8] ^= 1
        with self.assertRaises(zlib.error):
            check(bytes(broken))
        with self.assertRaisesRegex(ValueError, 'Multiple gzip'):
            check(data+data)

    def test_full_final_line_without_newline_is_not_lost(self):
        result = check(gzip.compress(row().rstrip(b'\n'), mtime=0))
        self.assertEqual(result['counts']['parsed_objects'], 1)
        self.assertEqual(result['partial_tail_bytes'], 0)

    def test_target_matching_does_not_include_nearby_hostname(self):
        result = check(gzip.compress(row()+row(hostname='sysclient02010.systemia.com'), mtime=0))
        self.assertEqual(result['counts']['target_host_records'], 1)

    def scan(self, data, **kwargs):
        return scan_records(io.BytesIO(data), source_id='fixture', target_host='sysclient0201',
                            start='2019-09-23T11:20:00-04:00', end='2019-09-23T11:45:00-04:00', **kwargs)

    def test_stream_does_not_stop_after_later_event_and_retains_unknowns(self):
        result = self.scan(row(timestamp='2019-09-23T15:00:00-04:00') + row() + row(timestamp='unknown') + b'[]\n')
        self.assertEqual(result['counts']['target_window'], 1)
        self.assertEqual(result['counts']['time_regressions'], 1)
        self.assertEqual(result['counts']['unknown_time'], 1)
        self.assertEqual(result['counts']['rejected'], 1)
        self.assertTrue(result['source_file_completeness_requires_transport_verification'])

    def test_stream_sampling_counts_all_rows_but_never_copies_commands(self):
        raw = row(pid=5452, properties={'command_line':'runme.bat password=not-for-copy', 'dest_ip':'132.197.158.98'}) * 200
        result = self.scan(raw)
        self.assertEqual(result['counts']['target_window'], 200)
        self.assertEqual(result['reference_match_counts']['reported_pid'], 200)
        self.assertEqual(result['reference_match_counts']['reported_c2_ip'], 200)
        self.assertLess(len(result['metadata_samples']), 20)
        self.assertNotIn('not-for-copy', json.dumps(result))
        self.assertEqual(result['decompressed_sha256'], hashlib.sha256(raw).hexdigest())

    def test_stream_rejects_oversized_lines_without_claiming_complete(self):
        with self.assertRaisesRegex(ValueError, 'Line size'):
            self.scan(row(), max_line_bytes=20)


if __name__ == '__main__':
    unittest.main()
