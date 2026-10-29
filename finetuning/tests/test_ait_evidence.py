"""Evidence integrity and omission/leakage regressions without models or network."""
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from prepare_ait_evidence import (EXPECTED_SPLIT, OUTSIDE, TRAIN, build,
    file_hashes, matching_phases, parse_time, projection, scan_member, verify_split)


def alert(at='2022-01-01T00:00:10Z'):
    return {'@timestamp': at, 'id': 'provider-1', 'agent': {'id': '007'},
            'rule': {'id': '86601', 'level': 3, 'groups': ['ids', 'suricata']},
            'data': {'alert': {'signature_id': '2013504', 'severity': '1', 'action': 'allowed'}}}


def line(value):
    return (json.dumps(value) + '\n').encode()


class AITEvidenceTests(unittest.TestCase):
    def test_timezone_is_required_and_kst_is_not_shifted_twice(self):
        self.assertEqual(parse_time('2022-01-01T09:00:10+09:00'),
                         parse_time('2022-01-01T00:00:10Z'))
        with self.assertRaisesRegex(ValueError, 'timezone'):
            parse_time('2022-01-01T09:00:10')

    def test_shared_boundary_keeps_both_phases_and_no_verdict(self):
        epoch = parse_time('2022-01-01T00:00:10Z').timestamp()
        phases = [{'phase': 'scan', 'start_epoch': epoch-10, 'end_epoch': epoch},
                  {'phase': 'webshell', 'start_epoch': epoch, 'end_epoch': epoch+10}]
        groups, report = scan_member(io.BytesIO(line(alert())), 'fox', 'fox_wazuh.json', phases, 12)
        self.assertEqual(report['counts']['multiple_phase_matches'], 1)
        self.assertEqual([g['selected_records'] for g in groups], [1, 1, 0])
        self.assertEqual(groups[0]['evidence'][0]['provider_phase_matches'], ['scan', 'webshell'])
        self.assertIsNone(groups[0]['labels']['maliciousness'])
        self.assertEqual(matching_phases(epoch+11, phases), [])

    def test_unlabelled_records_are_retained_without_normal_verdict(self):
        groups, report = scan_member(io.BytesIO(line(alert())), 'fox', 'fox_wazuh.json', [], 12)
        self.assertEqual(groups[0]['phase_context'], OUTSIDE)
        self.assertEqual(groups[0]['evidence'][0]['maliciousness_ground_truth'], 'not_provided_per_alert')
        self.assertEqual(report['counts']['parsed'], 1)

    def test_detector_ids_and_severity_scales_remain_distinct(self):
        record = alert('2022-01-01T09:00:10+09:00')
        result = projection(record, 'fox', 'fox_wazuh.json', 8, line(record), [])
        self.assertEqual(result['timestamp_kst'], '2022-01-01T09:00:10+09:00')
        self.assertEqual(result['wazuh_rule']['id'], '86601')
        self.assertEqual(result['suricata_alert']['signature_id'], '2013504')
        self.assertEqual(result['wazuh_rule']['level'], 3)
        self.assertEqual(result['suricata_alert']['severity'], '1')
        self.assertEqual(result['raw_alert'], record)

    def test_missing_provider_id_does_not_silently_drop_evidence(self):
        record = alert(); del record['id']
        groups, report = scan_member(io.BytesIO(line(record)), 'fox', 'fox_wazuh.json', [], 12)
        self.assertEqual(report['counts']['missing_alert_id'], 1)
        self.assertEqual(groups[0]['evidence'][0]['evidence_id'], 'fox:fox_wazuh.json:1')
        self.assertEqual(groups[0]['selected_records'], 1)

    def test_malformed_json_and_ambiguous_time_are_counted(self):
        data = line(alert()) + b'{broken\n' + line(alert('2022-01-01T00:00:10'))
        groups, report = scan_member(io.BytesIO(data), 'fox', 'fox_wazuh.json', [], 12)
        self.assertEqual(report['counts'], {'lines': 3, 'parsed': 1, 'rejected': 2})
        self.assertTrue(report['source_lines_conserved'])
        self.assertEqual(len(report['rejected_examples']), 2)
        self.assertEqual(groups[0]['source_matching_records'], 1)

    def test_holdout_reassignment_and_environment_duplication_are_rejected(self):
        for action in ('move', 'duplicate'):
            split = copy.deepcopy(EXPECTED_SPLIT)
            if action == 'move':
                split['train'].append(split['holdout'].pop())
            else:
                split['train'].append('fox')
            with self.assertRaisesRegex(ValueError, 'split changed'):
                verify_split(split)

    def fixture(self, folder, bad=False):
        archive, labels, split = [folder / n for n in ('source.zip', 'labels.csv', 'split.json')]
        with zipfile.ZipFile(archive, 'w') as z:
            # Deliberately no holdout members: build must never open them.
            for env in TRAIN:
                z.writestr(env+'_wazuh.json', line(alert()) + (b'{broken\n' if bad else b''))
        epoch = parse_time('2022-01-01T00:00:10Z').timestamp()
        labels.write_text('scenario,attack,start,end\n' + ''.join(
            f'{env},scan,{epoch-5},{epoch+5}\n' for env in (*TRAIN, 'wheeler', 'wilson')))
        split.write_text(json.dumps(EXPECTED_SPLIT))
        expected = {'archive': file_hashes(archive)['md5'], 'labels': file_hashes(labels)['md5']}
        return archive, labels, split, expected

    def test_build_preserves_raw_data_and_never_reads_holdouts_or_emits_answers(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); archive, labels, split, expected = self.fixture(root)
            with contextlib.redirect_stdout(io.StringIO()):
                report = build(archive, labels, split, root/'out', expected_md5=expected)
            self.assertEqual(report['selected_unique_records'], 6)
            self.assertFalse(report['validation_test_members_read'])
            self.assertEqual(report['new_training_dialogues'], 0)
            groups = [json.loads(x) for x in (root/'out/evidence-groups.jsonl').read_text().splitlines()]
            self.assertEqual(groups[0]['evidence'][0]['raw_alert'], alert())
            self.assertNotIn('messages', groups[0])
            with self.assertRaisesRegex(ValueError, 'immutable'):
                build(archive, labels, split, root/'out', expected_md5=expected)

    def test_bad_source_blocks_admission_and_failed_checksum_writes_nothing(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); archive, labels, split, expected = self.fixture(root, bad=True)
            with contextlib.redirect_stdout(io.StringIO()):
                report = build(archive, labels, split, root/'out', expected_md5=expected)
            self.assertEqual(report['status'], 'blocked_source_errors')
            self.assertEqual(report['rejected_records'], 6)
            labels.write_text(labels.read_text() + '\n')
            with self.assertRaisesRegex(ValueError, 'content mismatch'):
                build(archive, labels, split, root/'bad-output', expected_md5=expected)
            self.assertFalse((root/'bad-output').exists())


if __name__ == '__main__':
    unittest.main()
