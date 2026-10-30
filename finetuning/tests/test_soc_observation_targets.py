from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from prepare_data import canonical
from prepare_soc_observation_inputs import compact
from refine_soc_observation_targets import moment, prepare, refine_ait, refine_record, sha
from check_soc_observation_tokens import load_candidates


def original():
    return {'conclusion': 'original', 'evidence_refs': ['E01', 'E02'],
            'next_evidence': ['service definition and DNS'], 'limits': ['generic'],
            'management_status': 'needs_review', 'live_action_taken': False, 'tools_called': []}


def payload():
    rows = [{'ref': f'E0{i}', 'timestamp_kst': '2022-01-01T09:00:01+09:00',
             'observed.event_type': event, 'observed.unit': 'sample-unit',
             'observed.res': 'success', 'provider_labels': ['dnsteal']}
            for i, event in enumerate(('SERVICE_START', 'SERVICE_STOP'), 1)]
    return {'question': 'Review this historical window', 'context': {
        'historical': True, 'clock': 'KST_explicit_offset_already_converted',
        'start_kst': '2022-01-01T09:00:00+09:00', 'end_kst': '2022-01-01T09:00:02+09:00',
        'ADS_Wazuh_Suricata_count': 0, 'AMiner_count': 2, 'provider_labelled_count': 2,
        'raw_interval_count': 2, 'selected_count': 2, 'AMiner_training_modes': {'false': 2},
        'same_original_event_links': [{'other_sensor': 'AMiner', 'ref': 'E01', 'training_mode': False},
                                      {'other_sensor': 'AMiner', 'ref': 'E02', 'training_mode': False}],
        'separate_execution_diary': {'steps': [{'step': 'dnsteal_stop', 'inside_phase_interval': False,
                                               'timestamp_kst': '2022-01-01T08:59:00+09:00'}]}},
        'evidence': compact(rows)}


def dialogue():
    row = {'id': 'test', 'tools': [], 'source': 'fixture_not_training', 'messages': [
        {'role': 'system', 'content': 'historical investigation'},
        {'role': 'user', 'content': canonical(payload())},
        {'role': 'assistant', 'content': canonical(original())}]}
    trace = {'record_id': 'test', 'record_sha256': sha(canonical(row).encode()),
             'source_family': 'AIT-LDS-ADS-all-derivatives', 'original_case_id': 'fixture',
             'partition': 'historical_training_candidate_only', 'training_admitted': False,
             'bindings': {'E01': {'sha256': 'a' * 64}, 'E02': {'sha256': 'b' * 64}}}
    return row, trace


class TargetTests(unittest.TestCase):
    def test_equal_timestamps_do_not_invent_order_or_runtime(self):
        answer, family = refine_ait(payload(), original())
        self.assertEqual(family, 'service_start_stop')
        self.assertEqual(answer['recorded_time_relation'], 'same_recorded_timestamp')
        self.assertIn('선후나 실행 시간을 정할 수 없습니다', answer['conclusion'])
        self.assertFalse(answer['separate_diary']['same_event_established'])

    def test_millisecond_order_and_both_diary_directions(self):
        p = payload()
        # Equal timestamp was factored into common: move it back into columns.
        from prepare_soc_observation_inputs import expand
        rows = expand(p['evidence'])
        rows[1]['timestamp_kst'] = '2022-01-01T09:00:01.004000+09:00'
        p['evidence'] = compact(rows)
        result, _ = refine_ait(p, original())
        self.assertEqual(result['recorded_time_relation'], 'start_before_stop')
        self.assertEqual(result['separate_diary']['relation_to_interval'], 'before_interval')
        p['context']['separate_execution_diary']['steps'][0]['timestamp_kst'] = '2022-01-03T09:00:00+09:00'
        result, _ = refine_ait(p, original())
        self.assertEqual(result['separate_diary']['relation_to_interval'], 'after_interval')
        self.assertEqual(result['evidence_findings'][1]['timestamp_kst'], rows[1]['timestamp_kst'])

    def test_reversed_record_times_are_not_reordered(self):
        p = payload()
        from prepare_soc_observation_inputs import expand
        rows = expand(p['evidence']); rows[0]['timestamp_kst'] = '2022-01-01T09:00:01.001000+09:00'
        p['evidence'] = compact(rows)
        answer, _ = refine_ait(p, original())
        self.assertEqual(answer['recorded_time_relation'], 'stop_before_start')

    def test_training_mode_limit_is_conditional_and_sensor_counts_not_invented(self):
        p = payload()
        answer, _ = refine_ait(p, original())
        self.assertFalse(any('TrainingMode=true' in item for item in answer['limits']))
        p['context']['AMiner_training_modes'] = {'true': 2}
        for item in p['context']['same_original_event_links']: item['training_mode'] = True
        answer, _ = refine_ait(p, original())
        self.assertEqual(sum('TrainingMode=true인 2객체' in x for x in answer['limits']), 1)
        p['context']['AMiner_training_modes']['true'] = 3
        with self.assertRaisesRegex(ValueError, 'mode/count'):
            refine_ait(p, original())

    def test_duplicate_sensor_links_preserve_multiplicity(self):
        p = payload(); p['context']['same_original_event_links'][1]['ref'] = 'E01'
        answer, _ = refine_ait(p, original())
        self.assertIn('E01 2연결', ' '.join(answer['limits']))
        self.assertEqual(len(answer['evidence_findings']), 2)

    def test_invalid_counts_ref_and_clock_are_rejected(self):
        for mutate in (
            lambda p: p['context'].update(selected_count=3),
            lambda p: p['context'].update(raw_interval_count=True),
            lambda p: p['context']['same_original_event_links'][0].update(ref='missing'),
            lambda p: p['context'].update(start_kst='2022-01-01T09:00:00'),
            lambda p: p['context'].update(start_kst='2022-01-01T09:00:00+00:00'),
            lambda p: p['context']['separate_execution_diary']['steps'][0].update(timestamp_kst='2022-01-01T09:00:01+09:00'),
        ):
            p = payload(); mutate(p)
            with self.assertRaises(ValueError): refine_ait(p, original())

    def test_partial_selection_limit_not_added_to_complete_selected_interval(self):
        p = payload(); a, _ = refine_ait(p, original())
        self.assertNotIn('일부 표본', ' '.join(a['limits']))
        p['context']['raw_interval_count'] = 12
        a, _ = refine_ait(p, original())
        self.assertIn('12행 중 2행', a['sensor_scope'])
        self.assertIn('일부 표본', ' '.join(a['limits']))

    def test_provider_label_without_parsed_command_does_not_become_execution(self):
        p = payload()
        p['evidence'] = compact([{'ref': 'E01', 'timestamp_kst': '2022-01-01T09:00:01+09:00',
                                  'provider_labels': ['webshell_cmd']}])
        p['context'].update(selected_count=1, same_original_event_links=[])
        with self.assertRaisesRegex(ValueError, 'label alone'):
            refine_ait(p, original())

    def test_request_tcp_target_remains_request_evidence(self):
        p = payload()
        p['evidence'] = compact([{'ref': 'E01', 'timestamp_kst': '2022-01-01T09:00:01+09:00',
            'provider_labels': [], 'observed.encoded_command_parse': 'json_string_array',
            'observed.program': 'bash', 'observed.shell_command_requested': True,
            'observed.literal_tcp_endpoints_in_request': ['192.0.2.8:443'], 'observed.http_status': 200}])
        p['context'].update(selected_count=1, same_original_event_links=[])
        answer, _ = refine_ait(p, original())
        self.assertEqual(answer['evidence_findings'][0]['literal_tcp_endpoints_in_request'], ['192.0.2.8:443'])
        self.assertIn('실제 연결이나 원격 명령 실행 성공은 확인되지 않았습니다', answer['conclusion'])
        self.assertEqual(answer['tools_called'], [])

    def test_prompts_bindings_and_original_not_mutated(self):
        row, trace = dialogue(); before = deepcopy((row, trace))
        revised, new_trace, review = refine_record(row, trace)
        self.assertEqual((row, trace), before)
        self.assertEqual(revised['messages'][:-1], row['messages'][:-1])
        self.assertEqual(new_trace['bindings'], trace['bindings'])
        self.assertFalse(new_trace['training_admitted'])
        self.assertFalse(new_trace['tokenizer_length_verified'])
        self.assertTrue(review['target_changed'])

    def test_missing_binding_mutated_target_tool_or_partition_cannot_pass(self):
        for kind in ('binding', 'target', 'tools', 'partition'):
            row, trace = dialogue()
            if kind == 'binding': del trace['bindings']['E01']
            if kind == 'target': row['messages'][-1]['content'] += 'x'
            if kind == 'tools': row['tools'] = [{'name': 'not-available'}]
            if kind == 'partition': trace['partition'] = 'test'
            with self.assertRaises(ValueError): refine_record(row, trace)

    def test_output_refused_before_reading_unavailable_source(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError, 'Output already exists'):
                prepare(Path('missing'), Path(d))

    def test_noncanonical_field_does_not_reveal_omitted_raw_contents(self):
        row, trace = dialogue()
        p = {'context': {'clock': 'source_wall_time_without_offset'}, 'evidence': compact([
            {'ref': 'E01', 'observed.audit_type': 'CONFIG_CHANGE', 'observed.audit_operation': 'add_rule',
             'observed.audit_result': '1', 'observed.structured_audit_result_status': 'noncanonical'}])}
        row['messages'][1]['content'] = canonical(p)
        row['messages'][-1]['content'] = canonical({'assessment': 'old unsupported extra contents claim',
                                                   'findings': {'raw_result': '1'}})
        trace.update(source_family='linux-apt-2024-all-releases-and-derivatives',
                     original_case_id='linux-apt-audit_config', bindings={'E01': {}},
                     record_sha256=sha(canonical(row).encode()))
        result, _, _ = refine_record(row, trace)
        answer = json.loads(result['messages'][-1]['content'])
        self.assertIn('구체적인 문자열은 이 입력에 없으므로', answer['assessment'])
        self.assertEqual(answer['findings'], {'raw_result': '1'})
        self.assertNotIn('unsupported extra contents', answer['assessment'])

    def test_token_gate_accepts_both_unadmitted_revisions_and_checks_lineage(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            rows, traces = [], []
            for i in range(17):
                row, trace = dialogue(); row['id'] = str(i)
                trace.update(record_id=str(i), record_sha256=sha(canonical(row).encode()))
                rows.append(row); traces.append(trace)
            raw = ''.join(canonical(r) + '\n' for r in rows).encode()
            trace_raw = ''.join(canonical(t) + '\n' for t in traces).encode()
            (root / 'candidate-dialogues.jsonl').write_bytes(raw)
            (root / 'lineage.jsonl').write_bytes(trace_raw)
            m = {'records': 17, 'training_admitted': 0, 'dialogues_sha256': sha(raw),
                 'lineage_sha256': sha(trace_raw)}
            for state in ('formatted_candidate_not_admitted_training', 'semantically_refined_candidate_not_admitted'):
                m['status'] = state
                (root / 'manifest.json').write_text(json.dumps(m))
                self.assertEqual(len(load_candidates(root)[1]), 17)
            # Even when a sidecar's own checksum is recomputed, a wrong row binding fails.
            traces[0]['record_sha256'] = 'f' * 64
            trace_raw = ''.join(canonical(t) + '\n' for t in traces).encode()
            (root / 'lineage.jsonl').write_bytes(trace_raw)
            m['lineage_sha256'] = sha(trace_raw)
            (root / 'manifest.json').write_text(json.dumps(m))
            with self.assertRaisesRegex(ValueError, 'lineage/partition'):
                load_candidates(root)


if __name__ == '__main__':
    unittest.main()
