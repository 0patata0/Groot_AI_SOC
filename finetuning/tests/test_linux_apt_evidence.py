"""Meaningful omission/leakage/clock/duplicate regressions, no network needed."""
import csv
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from prepare_linux_apt import CorpusReview, rule_annotations, source_time, write_checkpoint, read_checkpoint


def fixture(rows):
    headers = sorted(set().union(*(row.keys() for row in rows)))
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream, fieldnames=headers)
    writer.writeheader()
    writer.writerows(rows)
    data = stream.getvalue().encode()
    entry = {'name': 'fixture.csv', 'url': 'https://example.invalid/fixture.csv',
             'bytes': len(data), 'md5': hashlib.md5(data).hexdigest()}
    return data, entry


def row(**values):
    base = {'_index': 'wazuh-alerts', '_id': 'id1', '_source.full_log': 'observed event',
            '_source.rule.id': '5501', '_source.decoder.name': 'pam',
            '_source.timestamp': 'Oct 20, 2023 @ 18:37:04.077'}
    base.update(values)
    return base


class LinuxAPTTests(unittest.TestCase):
    def test_kst_idempotent_and_equal_offsets(self):
        result = source_time({'_source.timestamp': '2023-10-20T18:37:04.077Z',
                              '_source.@timestamp': '2023-10-21T03:37:04.077+09:00'})
        self.assertEqual(result['timestamp_kst'], '2023-10-21T03:37:04.077000+09:00')
        self.assertEqual(result['status'], 'explicit_offset')

    def test_kibana_naive_stays_unknown_despite_embedded_timestamp(self):
        value = row(**{'_source.full_log': '2023-10-20T18:37:04Z',
                       '_source.predecoder.timestamp': 'Oct 20 23:37:04'})
        result = source_time(value)
        self.assertEqual(result['status'], 'timezone_unknown')
        self.assertIsNone(result['timestamp_kst'])

    def test_conflict_and_mixed_offsets(self):
        for other, status in [('2023-10-20T18:37:04', 'mixed_timezone_evidence'),
                              ('2023-10-20T18:37:05Z', 'conflicting_fields')]:
            self.assertEqual(source_time({'_source.timestamp': '2023-10-20T18:37:04Z',
                                          '_source.@timestamp': other})['status'], status)

    def test_bad_or_missing_time_never_defaults_now(self):
        self.assertEqual(source_time({})['status'], 'missing')
        self.assertEqual(source_time({'_source.timestamp': 'Oct 40, 2023 @ 18:00:00'})['status'], 'unparsed')

    def test_sca_reference_is_not_attack_annotation(self):
        annotation = rule_annotations({'_source.data.sca.check.compliance.mitre_techniques': 'T1078'})
        self.assertTrue(annotation['sca_mitre_references_present'])
        self.assertEqual(annotation['rule_technique_ids'], [])
        self.assertEqual(annotation['maliciousness'], 'not_adjudicated')

    def test_successful_login_rule_is_not_intrusion_success(self):
        annotation = rule_annotations({'_source.rule.mitre.id': '["T1078","T1021"]'})
        self.assertEqual(annotation['rule_technique_ids'], ['T1021', 'T1078'])
        self.assertEqual(annotation['attack_success'], 'not_adjudicated')

    def test_invalid_annotation_does_not_salvage_substrings(self):
        for value in ('T1078', '["pretend T1078"]', '{"id":"T1078"}', '[1]', 'null'):
            result = rule_annotations({'_source.rule.mitre.id': value})
            self.assertEqual(result['status'], 'invalid_format')
            self.assertEqual(result['rule_technique_ids'], [])

    def test_multiline_csv_coordinates_bind_exact_record_bytes(self):
        data, entry = fixture([row(**{'_source.full_log': 'first\nsecond'}), row(_id='id2')])
        review = CorpusReview()
        review.inspect(data, entry)
        samples = review.result('fixture')['samples']
        first = next(x for x in samples if x['source']['csv_record_number'] == 1)
        source = first['source']
        self.assertEqual((source['physical_start_line'], source['physical_end_line']), (2, 3))
        raw = b''.join(data.splitlines(keepends=True)[1:3])
        self.assertEqual(source['csv_record_bytes_sha256'], hashlib.sha256(raw).hexdigest())

    def test_duplicates_and_conflicting_ids_are_separate(self):
        data, entry = fixture([row(), row(), row(**{'_source.full_log': 'different'})])
        review = CorpusReview()
        review.inspect(data, entry)
        result = review.result('fixture')
        self.assertEqual(result['unique_normalized_records'], 2)
        self.assertEqual(result['counts']['duplicate_normalized_records'], 1)
        self.assertEqual(result['counts']['conflicting_document_id_records'], 1)

    def test_no_payload_or_person_identifiers_in_projection(self):
        data, entry = fixture([row(**{'_source.full_log': 'secret-fixture password=not-real',
                                    '_source.agent.name': 'private-host-fixture',
                                    '_source.data.command': 'rm -rf fixture'})])
        review = CorpusReview()
        review.inspect(data, entry)
        result = json.dumps(review.result('spec'))
        for secret in ('secret-fixture', 'not-real', 'private-host-fixture', 'rm -rf'):
            self.assertNotIn(secret, result)

    def test_bad_checksum_and_width_rejected(self):
        data, entry = fixture([row()])
        with self.assertRaisesRegex(ValueError, 'MD5'):
            CorpusReview().inspect(data + b'!', entry)
        bad = b'_source.full_log,_source.rule.id\r\ntext,1,extra\r\n'
        entry.update(bytes=len(bad), md5=hashlib.md5(bad).hexdigest())
        with self.assertRaisesRegex(ValueError, 'width'):
            CorpusReview().inspect(bad, entry)

    def test_sample_limit_reported_and_not_total_count(self):
        data, entry = fixture([row(), row(_id='2', **{'_source.rule.id': '9999'})])
        review = CorpusReview(max_groups=1, per_group=1)
        review.inspect(data, entry)
        result = review.result('fixture')
        self.assertEqual(result['counts']['rows'], 2)
        self.assertEqual(result['sample_records'], 1)
        self.assertEqual(result['counts']['sampling_group_limit_rows'], 1)
        self.assertEqual(result['training_examples_generated'], 0)

    def test_resume_keeps_cross_file_duplicate_detection(self):
        data, entry = fixture([row()])
        review = CorpusReview()
        review.inspect(data, entry)
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)
            write_checkpoint(p, review, 'spec', 'code')
            recovered = read_checkpoint(p, {'files': [entry]}, 'spec', 'code')
            other = dict(entry, name='second.csv')
            recovered.inspect(data, other)
            self.assertEqual(recovered.counts['rows'], 2)
            self.assertEqual(recovered.counts['duplicate_normalized_records'], 1)

    def test_changed_spec_code_and_corrupt_checkpoint_rejected(self):
        review = CorpusReview()
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)
            write_checkpoint(p, review, 'spec', 'code')
            for spec_sha, code_sha in [('other', 'code'), ('spec', 'other')]:
                with self.assertRaisesRegex(ValueError, 'different'):
                    read_checkpoint(p, {'files': []}, spec_sha, code_sha)
            envelope = json.loads((p / 'checkpoint.json').read_text())
            envelope['state']['counts']['rows'] = 100
            (p / 'checkpoint.json').write_text(json.dumps(envelope))
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                read_checkpoint(p, {'files': []}, 'spec', 'code')

    def test_failure_after_partial_file_does_not_change_saved_checkpoint(self):
        data, entry = fixture([row()])
        review = CorpusReview()
        review.inspect(data, entry)
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)
            write_checkpoint(p, review, 'spec', 'code')
            broken = b'_source.full_log,_source.rule.id\nvalid,1\nbad,1,extra\n'
            other = {'name': 'bad.csv', 'url': 'https://example.invalid/bad.csv',
                     'bytes': len(broken), 'md5': hashlib.md5(broken).hexdigest()}
            with self.assertRaises(ValueError):
                review.inspect(broken, other)
            recovered = read_checkpoint(p, {'files': [entry, other]}, 'spec', 'code')
            self.assertEqual(recovered.counts['rows'], 1)
            self.assertEqual(len(recovered.files), 1)


if __name__ == '__main__':
    unittest.main()
