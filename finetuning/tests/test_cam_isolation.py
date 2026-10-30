import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from audit_cam_isolation import (events, fingerprints, guard_candidates, normalized,
                                 scan_file, scan_row, sha, text_units, build_index)
from unittest.mock import patch


def index_for(text):
    return {'events': {key: {sha(text)} for key in fingerprints(text)}, 'prompts': {}}


class CamIsolationTests(unittest.TestCase):
    def test_audit_group_separator_is_not_newline(self):
        text='type=SYSCALL msg=audit(123.45:6): exe="/usr/bin/id"\x1dARCH=x86_64'
        result=events('Instructions\n\nhost:\n    logs/log/audit/audit.log:\n        '+text)
        self.assertEqual([x['text'] for x in result], [text])

    def test_indented_event_ending_colon_is_not_source(self):
        result=events('host:\n    logs/log/kern.log:\n        kernel: MTRR ranges:\n        kernel: next')
        self.assertEqual(len(result),2)
        self.assertEqual({x['source'] for x in result},{'logs/log/kern.log'})

    def test_malformed_source_and_event_refused(self):
        for prompt in ('host:\n        orphan','host:\n    unexpected:\n        event',
                       'host:\n    logs/a:\nunknown','no source'):
            with self.subTest(prompt=prompt),self.assertRaises(ValueError):events(prompt)

    def test_different_host_and_path_retained(self):
        data=events('h1:\n    logs/a:\n        x\nh2:\n    logs/b:\n        y')
        self.assertEqual([(x['host'],x['source']) for x in data],[('h1','logs/a'),('h2','logs/b')])

    def test_tool_result_and_assistant_are_checked(self):
        event='event 2025-09-22 root pid=12345 executable=/bin/id'
        for role in ('tool','assistant','user'):
            row={'messages':[{'role':role,'content':json.dumps({'data':{'raw':event}})}]}
            found,_=scan_row(row,index_for(event));self.assertIn(sha(event),found['line'])

    def test_reordered_json_detected_without_raw_text_equal(self):
        a='{"time":123,"process":{"exe":"/bin/id","pid":1}}'
        b='{"process": {"pid": 1, "exe": "/bin/id"}, "time": 123}'
        found,_=scan_row({'messages':[{'content':b}]},index_for(a))
        self.assertIn('json',found);self.assertNotIn('line',found)

    def test_whitespace_is_flagged_separately(self):
        found,_=scan_row({'content':'  date\t event pid=1  '},index_for('date event pid=1'))
        self.assertIn('whitespace',found);self.assertNotIn('line',found)

    def test_whole_prompt_after_reworded_wrapper(self):
        prompt='Original provided prompt\nwith event'
        index={'events':{},'prompts':{sha(normalized(prompt)):{'CAM-test'}}}
        found,_=scan_row({'messages':[{'role':'tool','content':prompt}]},index)
        self.assertEqual(found,{'whole_prompt':['CAM-test']})

    def test_source_family_markers_block_but_shared_technique_does_not(self):
        index=index_for('long observed event with source-specific timestamp')
        found,markers=scan_row({'content':'T1059 is used by many unrelated incidents'},index)
        self.assertFalse(found);self.assertFalse(markers)
        _,markers=scan_row({'source':'https://zenodo.org/records/18390561'},index)
        self.assertTrue(markers)

    def test_empty_modified_and_symlink_input_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'input.jsonl';p.write_text('')
            with self.assertRaises(ValueError):scan_file(p,index_for('example'))
            p.write_text('{"content":"safe"}\n')
            with self.assertRaises(ValueError):scan_file(p,index_for('example'),'0'*64)
            q=Path(d)/'link';q.symlink_to(p)
            with self.assertRaises(ValueError):scan_file(q,index_for('example'))

    def test_fingerprint_hit_cannot_be_silently_skipped(self):
        event='logged evidence with pid=1357 timestamp=1758523408'
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'input.jsonl';p.write_text(json.dumps({'messages':[{'content':event}]})+'\n')
            result=scan_file(p,index_for(event),hashlib.sha256(p.read_bytes()).hexdigest())
            self.assertEqual(len(result['matches']),1)
            self.assertNotIn(event,json.dumps(result))

    def test_json_duplicate_fields_are_not_silently_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'input.jsonl';p.write_text('{"content":"one","content":"two"}\n')
            with self.assertRaises(ValueError):scan_file(p,index_for('one'))

    def test_nested_json_string_decoded_without_executing(self):
        event='$(not-a-command) event seen at time=123'
        value=json.dumps({'result':json.dumps({'raw':event})})
        self.assertIn(event,list(text_units(value)))

    def test_blank_and_standard_header_preserved_but_not_event_identity(self):
        prompt='h:\n    logs/a:\n        \n        Traceback (most recent call last):\n        event time=2025-01-01 pid=3'
        trace={'eligible_for_training':False,'partition':'reserved_external_benchmark_candidate',
               'prompt_sha256':sha(prompt),'scenario_group':'cam-scenario:1','scenario_step':'1-1'}
        fake=({'counts':{'scenario_groups':1}}, {'inputs.jsonl':[{'id':'x','messages':[{'role':'user','content':prompt}]}],
                                                'lineage.jsonl':[trace]})
        with tempfile.TemporaryDirectory() as d,patch('audit_cam_isolation.load_bundle',return_value=fake):
            b=Path(d);(b/'manifest.json').write_text('{}');index=build_index(b)
            self.assertEqual(index['summary']['event_occurrences'],3)
            self.assertEqual(index['summary']['blank_event_occurrences_not_identity'],1)
            p=b/'rows.jsonl';p.write_text(json.dumps({'content':'\nTraceback (most recent call last):\n'})+'\n')
            result=scan_file(p,index)
            self.assertEqual(result['blocking_row_visits'],0)
            self.assertEqual(len(result['matches']),1)
            p.write_text(json.dumps({'content':'Traceback (most recent call last):\nevent time=2025-01-01 pid=3'})+'\n')
            self.assertEqual(scan_file(p,index)['blocking_row_visits'],1)

    def test_candidate_guard_fails_on_reserved_log_and_source(self):
        event='event time=2025-09-22 host=host01 pid=4321'
        with tempfile.TemporaryDirectory() as d,patch('audit_cam_isolation.build_index',return_value={**index_for(event),'manifest_sha256':'fixed'}):
            p=Path(d)/'rows.jsonl'
            for text in (event,'Source CAM-LDS, another wording'):
                p.write_text(json.dumps({'messages':[{'content':text}]})+'\n')
                with self.assertRaises(ValueError):guard_candidates(Path(d),[p])
            p.write_text(json.dumps({'messages':[{'content':'unrelated fresh corpus T1059'}]})+'\n')
            self.assertTrue(guard_candidates(Path(d),[p])['entire_CAM_corpus_reserved'])

    def test_pilot_builder_checks_guard_before_creating_output(self):
        import prepare_soc_pilot
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);out=root/'new-output'
            (root/'config.qwen36-soc-v5.json').write_text(json.dumps({
                'assistant_only_logits':True,'per_device_train_batch_size':1,'loss_mode':'all_assistant_turns'}))
            cam={'status':'reserved_benchmark_candidate_not_final_test','counts':{'training_admitted':0}}
            with patch.object(prepare_soc_pilot,'load_inventory',return_value=({}, {'pool.jsonl':{}}, {})), \
                 patch.object(prepare_soc_pilot,'load_cam_bundle',return_value=(cam,{})), \
                 patch.object(prepare_soc_pilot,'guard_candidates',side_effect=ValueError('Reserved CAM evidence')) as guard:
                with self.assertRaisesRegex(ValueError,'Reserved CAM evidence'):
                    prepare_soc_pilot.build(root,root/'inventory',root/'token-proof',out,root/'loss-proof')
                guard.assert_called_once();self.assertFalse(out.exists())


if __name__ == '__main__':unittest.main()
