"""A completion label alone must not allow partial or repeated-data export."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from prepare_evidence_v5 import sha
from training_lineage import prefix_identity
from verify_evidence_training import verify
from register_soc import candidate_name, with_source_notice


class TrainingCoverageTests(unittest.TestCase):
    def test_new_candidate_preserves_original_license_and_options(self):
        original={'license':'base license','template':'original template','parameters':'temperature 0'}
        candidate=with_source_notice(original,'\nMITRE source notice')
        self.assertEqual(original['license'],'base license')
        self.assertEqual(candidate['template'],original['template']);self.assertEqual(candidate['parameters'],original['parameters'])
        self.assertIn('MITRE source notice',candidate['license'])
        self.assertNotEqual(candidate_name('v5'),'qwen3.6:35b')
    def fixture(self, root):
        src = root/'finetuning'; src.mkdir(); data = src/'dataset'; data.mkdir()
        output = root/'outputs/soc-v5-train'; (output/'adapter').mkdir(parents=True)
        profile = {'max_steps':2, 'gradient_accumulation_steps':2}
        raw = json.dumps(profile).encode(); (src/'config.qwen36-soc-v5.json').write_bytes(raw)
        rows = [{'id':str(i),'source':'fixture','messages':[{'role':'system','content':'Policy'}, {'role':'user','content':str(i)}, {'role':'assistant','content':'Answer'}]} for i in range(4)]
        raw_data = ('\n'.join(json.dumps(r) for r in rows)+'\n').encode(); (data/'train.jsonl').write_bytes(raw_data)
        frozen = {'profile_sha256':sha(raw),'data_folder':'dataset','data_sha256':{'train':sha(raw_data)},'records':{'train':4}}
        (src/'V5_TRAINING_INPUTS.json').write_text(json.dumps(frozen))
        (output/'progress.json').write_text('{"status":"completed"}')
        (output/'trainer_state.json').write_text('{"global_step":2,"epoch":1}')
        run = {'data':{'sha256':frozen['data_sha256']},'base_revision_resolved':'995ad96eacd98c81ed38be0c5b274b04031597b0',
               'config':{**profile,'loss_mode':'all_assistant_turns','record_prefix_usage':True,'max_train_samples':0}}
        (output/'run_manifest.json').write_text(json.dumps(run))
        for name in ('train_results.json','eval_results.json'): (output/name).write_text('{"loss":1.0}')
        (output/'adapter/adapter_model.safetensors').write_bytes(b'Hash-only fixture; tensor validity is checked by the exporter.')
        events=[]
        for i,row in enumerate(rows):
            item=prefix_identity(row,2);item.update(encoding_mode='all_assistant_turns',supervised_assistant_indices=[2])
            events.append({'successful_forward_backward':True,'optimizer_step_before':i//2,'prefixes':[item]})
        self.trace(output, events)
        return output, events

    def trace(self, output, events):
        (output/'successful_microbatch_lineage.jsonl').write_text('\n'.join(json.dumps(e) for e in events)+'\n')

    def test_full_unique_coverage_is_required_in_addition_to_completed_state(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);out,events=self.fixture(root)
            self.assertEqual(verify(root)['distinct_observations'],4)
            self.trace(out,events[:-1])
            with self.assertRaisesRegex(ValueError,'omitted'):verify(root)
            changed=copy.deepcopy(events);changed[-1]['prefixes']=changed[0]['prefixes'];self.trace(out,changed)
            with self.assertRaisesRegex(ValueError,'omitted'):verify(root)

    def test_wrong_record_hash_target_span_and_update_trace_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);out,events=self.fixture(root)
            changed=copy.deepcopy(events);changed[0]['prefixes'][0]['record_sha256']='bad';self.trace(out,changed)
            with self.assertRaisesRegex(ValueError,'identity'):verify(root)
            changed=copy.deepcopy(events);changed[0]['prefixes'][0]['supervised_assistant_indices']=[];self.trace(out,changed)
            with self.assertRaisesRegex(ValueError,'coverage'):verify(root)
            changed=copy.deepcopy(events);changed[0]['optimizer_step_before']=1;self.trace(out,changed)
            with self.assertRaisesRegex(ValueError,'optimized'):verify(root)

    def test_partial_epoch_and_nonfinite_final_evaluation_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);out,events=self.fixture(root)
            (out/'trainer_state.json').write_text('{"global_step":1,"epoch":0.5}')
            with self.assertRaisesRegex(ValueError,'Complete'):verify(root)
            (out/'trainer_state.json').write_text('{"global_step":2,"epoch":1}')
            (out/'eval_results.json').write_text('{"eval_loss":NaN}')
            with self.assertRaisesRegex(ValueError,'Nonfinite'):verify(root)


if __name__ == '__main__':unittest.main()
