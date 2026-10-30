"""Offline synthetic fixtures; fake tokenizer results are not model token counts."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from prepare_soc_observation_inputs import compact, expand, build_record, verified, ait_input, audit_existing
from check_soc_observation_tokens import metadata_check, measure, MODEL, REVISION


def linux_case():
    return {'case_id': 'secret-phase-name', 'task': '기록의 근거와 한계를 설명해줘.',
            'source_family': 'linux-apt-2024-all-releases-and-derivatives',
            'source_scope': 'Selected original records',
            'review_answer': {'assessment': 'TARGET_NOT_AN_INPUT', 'evidence_ids': ['original-1']},
            'evidence': [{'id': 'original-1', 'source': {'file_sha256': 'a' * 64},
                          'time': {'status': 'timezone_unknown', 'timestamp_kst': None,
                                   'source_wall_time': '2023-10-07T19:00:00'},
                          'detector_fields': {'rule_id': '203', 'description': 'Source detector assertion',
                                              'decoder': 'wazuh'},
                          'reported_entities': {'agent': 'agent-1', 'source': None},
                          'raw_observations': {'raw_log_present': True, 'buffer_state': 'full'}}]}


def ait_case():
    return {'id': 'private-source-phase', 'question': '근거를 검토해줘.',
            'split': 'historical_train_only', 'leakage_group': 'ait-lds-ads:fox',
            'source_licenses': ['CC-BY-4.0', 'CC-BY-NC-SA-4.0'], 'sources': ['https://example.invalid'],
            'draft_answer': {'conclusion': 'TARGET_NOT_AN_INPUT', 'evidence_refs': ['original-1']},
            'context': {'environment': 'fox', 'phase_label': 'PHASE_TARGET_LEAK',
                        'start_kst': '2022-01-18T22:00:00+09:00', 'end_kst': '2022-01-18T22:01:00+09:00',
                        'ADS_Wazuh_Suricata_count': 0, 'AMiner_count': 1,
                        'AMiner_training_modes': {'false': 1}, 'provider_labelled_count': 0,
                        'raw_interval_count': 1, 'selected_count': 1,
                        'observations': [{'id': 'original-1', 'member': 'source-file', 'line': 8,
                                          'sha256': 'b' * 64, 'provider_label_source': None,
                                          'timestamp_kst': '2022-01-18T22:00:01+09:00',
                                          'provider_labels': [], 'facts': {'http_status': 200}}],
                        'shared_observations': [{'raw_id': 'original-1', 'training_mode': False}]}}


class FakeTokenizer:
    pad_token_id = 0

    def apply_chat_template(self, messages, **kwargs):
        return ''.join(m['role'] + ':' + m['content'] + '\n' for m in messages)

    def encode(self, text, **kwargs):
        return [ord(c) + 1 for c in text]


class InputTests(unittest.TestCase):
    def test_compaction_preserves_false_zero_null_empty_and_all_refs(self):
        rows = [{'ref': 'E01', 'same': 'fixed', 'value': False, 'missing': None},
                {'ref': 'E02', 'same': 'fixed', 'value': 0, 'missing': ''},
                {'ref': 'E03', 'same': 'fixed', 'value': [], 'missing': None}]
        self.assertEqual(expand(compact(rows)), rows)
        self.assertEqual(compact(rows)['common'], {'same': 'fixed'})

    def test_table_width_collision_and_duplicate_ref_fail(self):
        with self.assertRaises(ValueError):
            compact([{'ref': 'E01'}, {'ref': 'E01'}])
        for table in ({'common': {}, 'columns': ['ref'], 'rows': [[]]},
                      {'common': {'ref': 'E01'}, 'columns': ['ref'], 'rows': [['E02']]}):
            with self.assertRaises(ValueError):
                expand(table)

    def test_linux_target_and_identity_metadata_never_enter_prompt(self):
        row, trace = build_record(linux_case(), 'linux', 1)
        prompt = row['messages'][1]['content']
        for forbidden in ('TARGET_NOT_AN_INPUT', 'secret-phase-name', 'original-1', 'a' * 64):
            self.assertNotIn(forbidden, prompt)
        answer = json.loads(row['messages'][-1]['content'])
        self.assertEqual(answer['evidence_ids'], ['E01'])
        self.assertEqual(trace['bindings']['E01']['original_id'], 'original-1')
        self.assertFalse(trace['training_admitted'])
        self.assertEqual(row['tools'], [])

    def test_linux_unknown_new_fact_requires_review(self):
        case = linux_case()
        case['evidence'][0]['raw_observations']['new_critical_field'] = 'evidence'
        with self.assertRaisesRegex(ValueError, 'Unreviewed'):
            build_record(case, 'linux', 1)

    def test_unknown_clock_is_not_converted_and_changed_policy_rejected(self):
        row, _ = build_record(linux_case(), 'linux', 1)
        payload = json.loads(row['messages'][1]['content'])
        self.assertEqual(expand(payload['evidence'])[0]['source_wall_time'], '2023-10-07T19:00:00')
        case = linux_case()
        case['evidence'][0]['time']['timestamp_kst'] = '2023-10-08T04:00:00+09:00'
        with self.assertRaisesRegex(ValueError, 'time policy'):
            build_record(case, 'linux', 1)

    def test_answer_reference_must_bind(self):
        case = linux_case()
        case['review_answer']['evidence_ids'].append('nonexistent')
        with self.assertRaisesRegex(ValueError, 'Unbound'):
            build_record(case, 'linux', 1)

    def test_ait_phase_and_answer_removed_but_provider_observations_preserved(self):
        row, trace = build_record(ait_case(), 'ait', 1)
        prompt = row['messages'][1]['content']
        for forbidden in ('PHASE_TARGET_LEAK', 'TARGET_NOT_AN_INPUT', 'private-source-phase', 'phase_label'):
            self.assertNotIn(forbidden, prompt)
        payload = json.loads(prompt)
        self.assertEqual(payload['context']['ADS_Wazuh_Suricata_count'], 0)
        self.assertEqual(payload['context']['same_original_event_links'][0]['ref'], 'E01')
        self.assertEqual(expand(payload['evidence'])[0]['observed.http_status'], 200)
        self.assertIn('CC-BY-NC-SA-4.0', trace['licenses'])

    def test_ait_holdout_or_missing_shared_ref_is_rejected(self):
        for kind in ('holdout', 'unbound', 'count'):
            case = ait_case()
            if kind == 'holdout':
                case['context']['environment'] = 'wilson'
            elif kind == 'unbound':
                case['context']['shared_observations'][0]['raw_id'] = 'missing'
            else:
                case['context']['selected_count'] = 2
            with self.assertRaises(ValueError):
                ait_input(case)

    def test_tampered_source_hash_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'cases.jsonl'
            path.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                verified(path, hashlib.sha256(b'original').hexdigest())

    def test_case_metadata_changes_do_not_change_the_model_input(self):
        before, _ = build_record(linux_case(), 'linux', 1)
        changed = linux_case()
        changed.update(case_id='other-metadata', arbitrary_review_answer='DO_NOT_COPY')
        after, _ = build_record(changed, 'linux', 1)
        self.assertEqual(before, after)

    def test_existing_duplicate_and_missing_v5_are_reported(self):
        row, _ = build_record(linux_case(), 'linux', 1)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root / 'data-old'
            folder.mkdir()
            (folder / 'test.jsonl').write_text(json.dumps(row) + '\n')
            result = audit_existing(root, [row])
            self.assertEqual(len(result['matches']), 1)
            self.assertFalse(result['full_cross_corpus_audit_complete'])
            self.assertEqual(len(result['required_historical_files_missing']), 6)

    def test_complete_target_mask_with_fake_tokenizer_only(self):
        row, _ = build_record(linux_case(), 'linux', 1)
        result = measure([row], FakeTokenizer(), 4096)
        self.assertTrue(result['all_fit_and_aligned'])
        self.assertGreater(result['records'][0]['supervised_tokens'], 0)
        self.assertEqual(result['training_admitted'], 0)

    def test_empty_input_cannot_pass_token_gate(self):
        with self.assertRaisesRegex(ValueError, 'No candidate'):
            measure([], FakeTokenizer(), 4096)

    def test_over_budget_is_measured_not_truncated(self):
        row, _ = build_record(linux_case(), 'linux', 1)
        result = measure([row], FakeTokenizer(), 10)
        self.assertFalse(result['all_fit_and_aligned'])
        self.assertEqual(result['failures'], {'over_max_length': 1})
        self.assertFalse(result['records'][0]['truncated'])
        self.assertGreater(result['records'][0]['tokens'], 10)

    def test_token_prefix_mismatch_cannot_pass(self):
        class Mismatch(FakeTokenizer):
            def encode(self, text, **kwargs):
                return [len(text)] + super().encode(text, **kwargs)
        row, _ = build_record(linux_case(), 'linux', 1)
        result = measure([row], Mismatch(), 4096)
        self.assertFalse(result['all_fit_and_aligned'])
        self.assertEqual(result['failures'], {'token_prefix_mismatch': 1})

    def test_tokenizer_artifacts_pinned_and_extra_or_tampered_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = []
            for name in ('config.json', 'tokenizer.json', 'tokenizer_config.json'):
                (root / name).write_bytes(b'{}')
                files.append({'path': name, 'bytes': 2, 'sha256': hashlib.sha256(b'{}').hexdigest(), 'git_blob': None})
            manifest = {'model': MODEL, 'revision': REVISION, 'verified': True, 'files': files}
            self.assertEqual(len(metadata_check(root, manifest)), 3)
            (root / 'chat_template.jinja').write_text('unexpected')
            with self.assertRaisesRegex(ValueError, 'Unlisted'):
                metadata_check(root, manifest)
            (root / 'chat_template.jinja').unlink()
            (root / 'tokenizer.json').write_bytes(b'[]')
            with self.assertRaisesRegex(ValueError, 'checksum'):
                metadata_check(root, manifest)


if __name__ == '__main__':
    unittest.main()
