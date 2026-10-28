"""No service/network calls: protect the outage prerequisite and recovery boundaries."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import training_window as window


class WindowTests(unittest.TestCase):
    def memory_mode(self):
        return patch.multiple(window,MODE=window.MODE,STAGES=window.STAGES,STATE=window.STATE,
                              LIMIT_SECONDS=window.LIMIT_SECONDS,RESTORE_MINUTES=window.RESTORE_MINUTES,
                              RESTORE_UNIT=window.RESTORE_UNIT)

    def test_memory_repro_is_one_new_stage_with_its_own_short_recovery_timer(self):
        with self.memory_mode():
            window.select_mode('memory-repro')
            self.assertEqual(window.STAGES,('soc-memory-smoke',))
            self.assertEqual(window.LIMIT_SECONDS,360)
            self.assertNotEqual(window.STATE,Path('/var/lib/capstone-training-v2-window'))
            args=window.restore_command('/usr/local/libexec/inspected.py','/training')
            self.assertIn('--on-active=8m',args);self.assertIn('memory-repro',args)
            self.assertIn('--property=Type=oneshot',args);self.assertIn('--property=TimeoutStartSec=6min',args)
            self.assertLess(window.RESTORE_MINUTES+6,15)

    def test_memory_repro_keeps_existing_v2_results_and_rejects_its_own_retry(self):
        with tempfile.TemporaryDirectory() as d,self.memory_mode():
            root=Path(d);digests=self.fixture(root)
            (root/'soc-v2-smoke-status.json').write_text('{"status":"completed"}')
            (root/'outputs/soc-v2-pilot').mkdir(parents=True)
            window.select_mode('memory-repro')
            with patch.object(window,'DATA_HASHES',digests):
                window.verify_ready(root)
                (root/'soc-memory-smoke-status.json').write_text('{"status":"failed"}')
                with self.assertRaisesRegex(ValueError,'automatic retry'):window.verify_ready(root)

    def test_vmm_trial_preserves_native_evidence_and_has_its_own_recovery(self):
        with tempfile.TemporaryDirectory() as d,self.memory_mode():
            root=Path(d);digests=self.fixture(root)
            (root/'outputs/soc-memory-smoke').mkdir(parents=True)
            (root/'soc-memory-smoke-status.json').write_text('{"status":"completed"}')
            window.select_mode('memory-vmm')
            self.assertEqual(window.STAGES,('soc-memory-vmm',))
            self.assertEqual(window.STATE,Path('/var/lib/capstone-memory-vmm-20261028'))
            self.assertEqual(window.LIMIT_SECONDS,360)
            args=window.restore_command('/inspected.py',root)
            self.assertIn('--unit=capstone-memory-vmm-restore',args)
            self.assertIn('--on-active=8m',args)
            self.assertIn('--property=TimeoutStartSec=6min',args)
            self.assertEqual(args[-1],'memory-vmm')
            with patch.object(window,'DATA_HASHES',digests):
                window.verify_ready(root)
                (root/'outputs/soc-memory-vmm').mkdir()
                with self.assertRaisesRegex(ValueError,'automatic retry'):window.verify_ready(root)

    def test_trace_trial_has_a_distinct_stage_state_and_short_timer(self):
        with self.memory_mode():
            window.select_mode('memory-trace')
            self.assertEqual(window.STAGES,('soc-memory-trace',))
            self.assertEqual(window.STATE,Path('/var/lib/capstone-memory-trace-20261028'))
            args=window.restore_command('/inspected.py','/training')
            self.assertIn('--unit=capstone-memory-trace-restore',args)
            self.assertIn('--on-active=8m',args)
            self.assertIn('--property=TimeoutStartSec=6min',args)
            self.assertEqual(args[-1],'memory-trace')

    def test_unknown_operator_mode_is_rejected_and_v2_defaults_stay_reviewed(self):
        with self.memory_mode():
            with self.assertRaises(ValueError):window.select_mode('arbitrary')
            window.select_mode('memory-repro');window.select_mode('v2')
            self.assertEqual(window.STAGES,('soc-v2-smoke','soc-v2-pilot'))
            self.assertEqual(window.LIMIT_SECONDS,45*60);self.assertEqual(window.RESTORE_MINUTES,50)

    def test_v3_uses_its_own_bounded_window_and_root_restore_timeout(self):
        with self.memory_mode():
            window.select_mode('v3')
            self.assertEqual(window.STAGES,('soc-v3-smoke','soc-v3-pilot'))
            self.assertEqual(window.LIMIT_SECONDS,75*60)
            args=window.restore_command('/inspected.py','/training')
            self.assertIn('--on-active=80m',args);self.assertIn('--property=TimeoutStartSec=6min',args)
            self.assertLess(window.RESTORE_MINUTES+6,90)

    def test_v3_check_is_read_only_rejects_stale_tokens_and_never_reuses_outputs(self):
        with tempfile.TemporaryDirectory() as d,self.memory_mode():
            root=Path(d);folder=root/'finetuning';data=folder/'data-soc-operator-v3-r1';data.mkdir(parents=True)
            (folder/'config.qwen36-soc-v3.json').write_bytes((Path(__file__).resolve().parents[1]/'config.qwen36-soc-v3.json').read_bytes())
            hashes={}
            for split in ('train','validation','test'):
                payload=split.encode();(data/(split+'.jsonl')).write_bytes(payload);hashes[split]=hashlib.sha256(payload).hexdigest()
            tok=root/'soc-v3-tokenization';tok.mkdir();proof={s:{'kept':n,'candidate_turns':n} for s,n in [('train',696),('validation',168),('test',168)]};proof.update(max_length=4096,require_all_prefixes=True)
            (tok/'tokenization_report.json').write_text(json.dumps(proof));(tok/'data_check.json').write_text(json.dumps({'sha256':hashes}))
            cases=folder/'data-soc-source-operator-v3-r1';cases.mkdir();(cases/'cases.jsonl').write_text('fixture');(folder/'mcp_contract.json').write_text('fixture')
            evaluation=root/'soc-v3-evaluation';evaluation.mkdir();digest=hashlib.sha256(b'fixture').hexdigest();(evaluation/'frozen-plan.json').write_text(json.dumps({'cases_sha256':digest,'catalog_sha256':digest}))
            (evaluation/'base-development-v2-job.json').write_text(json.dumps({'status':'completed','original_warm_done':True}));(evaluation/'base-development-v2.json').write_text('{"status":"completed"}')
            window.select_mode('v3')
            with patch.object(window,'V3_DATA_HASHES',hashes),patch.object(window,'run',side_effect=AssertionError('No mutation')):
                window.verify_v3_ready(root)
                (root/'soc-v3-smoke-status.json').write_text('{"status":"failed"}')
                with self.assertRaisesRegex(ValueError,'automatic retry'):window.verify_v3_ready(root)
                (root/'soc-v3-smoke-status.json').unlink();proof['train']['kept']-=1;(tok/'tokenization_report.json').write_text(json.dumps(proof))
                with self.assertRaisesRegex(ValueError,'prefixes excluded'):window.verify_v3_ready(root)

    def test_full_epoch_window_preserves_three_hour_bound_and_independent_recovery(self):
        with self.memory_mode():
            window.select_mode('v4-full');self.assertEqual(window.STAGES,('soc-v4-full-smoke','soc-v4-full-train'));self.assertEqual(window.LIMIT_SECONDS,165*60);args=window.restore_command('/inspected.py','/training');self.assertIn('--on-active=170m',args);self.assertIn('--property=TimeoutStartSec=6min',args);self.assertLess(window.RESTORE_MINUTES+6,180)

    def test_v5_has_independent_restore_and_refuses_unfrozen_inputs_before_any_service_action(self):
        with self.memory_mode(),tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'finetuning').mkdir();(root/'finetuning/V5_TRAINING_INPUTS.json').write_text('{}')
            window.select_mode('v5');self.assertEqual(window.STAGES,('soc-v5-smoke','soc-v5-train'))
            args=window.restore_command('/inspected.py',root);self.assertIn('--on-active=170m',args);self.assertIn('--property=TimeoutStartSec=6min',args)
            with patch.object(window,'run',side_effect=AssertionError('No service action')):
                with self.assertRaisesRegex(ValueError,'Frozen V5 inputs differ'):window.window(root,Path('/inspected.py'))

    def test_full_epoch_readiness_pins_source_and_all_turn_coverage_without_service_actions(self):
        with tempfile.TemporaryDirectory() as d,self.memory_mode():
            root=Path(d);folder=root/'finetuning';folder.mkdir();freeze={'profile':'profile.json','source_cases':'cases.jsonl','data_folder':'data','source_sha256':{},'data_sha256':{},'records':{'train':332,'validation':94,'test':94},'assistant_turns':{'train':766,'validation':202,'test':202},'development_case_ids':['case1'],'development_evaluation_code_sha256':'fixture-code'}
            for name,key in [('profile.json','profile_sha256'),('cases.jsonl','source_cases_sha256'),('mcp_contract.json','catalog_sha256')]:
                data=name.encode();(folder/name).write_bytes(data);freeze[key]=hashlib.sha256(data).hexdigest()
            (folder/'data').mkdir()
            for split in ('train','validation','test'):
                payload=split.encode();(folder/'data'/(split+'.jsonl')).write_bytes(payload);freeze['data_sha256'][split]=hashlib.sha256(payload).hexdigest()
            (folder/'train.py').write_bytes(b'fixed-source');freeze['source_sha256']['train.py']=hashlib.sha256(b'fixed-source').hexdigest()
            raw=json.dumps(freeze).encode();(folder/'V4_TRAINING_INPUTS.json').write_bytes(raw);digest=hashlib.sha256(raw).hexdigest();tok=root/'soc-v4-full-tokenization';tok.mkdir();proof={s:{'kept':n,'candidate_examples':n,'candidate_turns':freeze['assistant_turns'][s],'covered_assistant_turns':freeze['assistant_turns'][s]} for s,n in freeze['records'].items()};proof.update(max_length=4096,loss='all_assistant_turns_per_conversation',require_all_prefixes=True);(tok/'tokenization_report.json').write_text(json.dumps(proof));(tok/'data_check.json').write_text(json.dumps({'sha256':freeze['data_sha256']}));(root/'soc-v4-dialogue-probe.json').write_text('{"status":"passed","tests_returncode":0}')
            evaluation=root/'soc-v4-evaluation';evaluation.mkdir();(evaluation/'base-development-job.json').write_text('{"status":"completed","original_warm_done":true}');report={'status':'completed','source_cases_sha256':freeze['source_cases_sha256'],'catalog_sha256':freeze['catalog_sha256'],'results':[{'case_id':'case1'}]};(evaluation/'base-development.json').write_text(json.dumps(report));(evaluation/'frozen-plan.json').write_text('{"case_ids":["case1"],"evaluation_code_sha256":"fixture-code"}')
            window.select_mode('v4-full')
            with patch.object(window,'V4_FULL_INPUTS_SHA256',digest),patch.object(window,'run',side_effect=AssertionError('No mutation')):
                window.verify_v4_full_ready(root);(folder/'train.py').write_bytes(b'changed')
                with self.assertRaisesRegex(ValueError,'source/corpus mismatch'):window.verify_v4_full_ready(root)
                (folder/'train.py').write_bytes(b'fixed-source');proof['train']['covered_assistant_turns']-=1;(tok/'tokenization_report.json').write_text(json.dumps(proof))
                with self.assertRaisesRegex(ValueError,'targets excluded'):window.verify_v4_full_ready(root)

    def test_unreviewed_soc_plans_cannot_reach_timer_or_service_stop(self):
        with self.memory_mode(),tempfile.TemporaryDirectory() as d:
            for mode in ('v3','v4-full'):
                window.select_mode(mode)
                with patch.object(window,'run',side_effect=AssertionError('No service action')):
                    with self.assertRaisesRegex(ValueError,'Training release withheld'):
                        window.window(Path(d),Path('/inspected-operator.py'))

    def test_measured_full_epoch_estimate_is_separate_from_actual_deadline(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);out=root/'outputs/soc-v4-full-smoke';out.mkdir(parents=True);(out/'successful_microbatch_lineage.jsonl').write_text('{"at_kst":"2026-10-29T04:00:00+09:00"}\n{"at_kst":"2026-10-29T04:00:20+09:00"}\n');(out/'eval_results.json').write_text('{"eval_runtime":16}');tok=root/'soc-v4-full-tokenization';tok.mkdir();(tok/'tokenization_report.json').write_text('{"train":{"tokens":332000,"kept":332,"max_tokens":2000}}');value=window.full_window_estimate(root);self.assertGreater(value['estimated_main_seconds'],0);self.assertEqual(value['length_ratio'],.5);self.assertIn('not completion',value['scope'])

    def fixture(self,root):
        (root/'finetuning/data-soc-v2-r2').mkdir(parents=True)
        config=Path(__file__).resolve().parents[1]/'config.qwen36-soc-v2.json'
        (root/'finetuning/config.qwen36-soc-v2.json').write_bytes(config.read_bytes())
        digests={}
        for split in ('train','validation','test'):
            p=root/'finetuning/data-soc-v2-r2'/(split+'.jsonl');p.write_text(split+'\n');digests[split]=hashlib.sha256(p.read_bytes()).hexdigest()
        (root/'soc-v2-tokenization').mkdir()
        report={s:{'kept':1,'candidate_turns':1} for s in digests};report.update(max_length=2048,require_all_prefixes=True)
        (root/'soc-v2-tokenization/tokenization_report.json').write_text(json.dumps(report))
        (root/'soc-v2-tokenization/data_check.json').write_text(json.dumps({'sha256':digests}))
        (root/'soc-v2-evaluation').mkdir()
        (root/'soc-v2-evaluation/base-development-r2-job.json').write_text(json.dumps({'status':'completed','original_warm_done':True,'source_sha256':window.BASELINE_INPUTS}))
        return digests

    def test_successful_checks_do_not_control_services_and_stale_proof_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);digests=self.fixture(root)
            with patch.object(window,'DATA_HASHES',digests),patch.object(window,'run',side_effect=AssertionError('No service action')):
                window.verify_ready(root)
                p=root/'soc-v2-tokenization/data_check.json';p.write_text('{"sha256":{}}')
                with self.assertRaisesRegex(ValueError,'different corpus'):window.verify_ready(root)

    def test_changed_profile_and_prior_training_cannot_be_reused(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);digests=self.fixture(root)
            with patch.object(window,'DATA_HASHES',digests):
                (root/'soc-v2-smoke-status.json').write_text('{"status":"failed"}')
                with self.assertRaisesRegex(ValueError,'automatic retry'):window.verify_ready(root)
                p=root/'finetuning/config.qwen36-soc-v2.json';p.write_text(p.read_text()+' ')
                with self.assertRaisesRegex(ValueError,'checksum'):window.verify_ready(root)

    def test_independent_timer_is_outside_the_supervisor_and_before_approved_limit(self):
        args=window.restore_command('/usr/local/libexec/inspected.py','/training')
        self.assertIn('--on-active=50m',args);self.assertIn('restore',args)
        self.assertLess(window.LIMIT_SECONDS,window.RESTORE_MINUTES*60)
        self.assertLess(window.RESTORE_MINUTES,60)

    def test_other_gpu_process_cannot_be_accepted_only_by_its_name(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for pid,parent in ((20,10),(10,1),(30,1)):
                (root/str(pid)).mkdir();(root/str(pid)/'status').write_text('PPid:\t'+str(parent)+'\n')
            self.assertTrue(window.process_belongs_to(20,10,root))
            self.assertFalse(window.process_belongs_to(30,10,root))

    def test_failed_stage_still_restores_and_timer_precedes_service_stop(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);calls=[]
            def command(args,**kwargs):
                calls.append([str(a) for a in args])
                if args[0]=='runuser':raise RuntimeError('stage launch failed')
                stdout='10' if 'MainPID' in args else 'active' if 'is-active' in args else ''
                return SimpleNamespace(returncode=0,stdout=stdout)
            tags={'models':[{'name':window.ORIGINAL,'digest':window.ORIGINAL_DIGEST}]}
            with patch.object(window,'STATE',root),patch.object(window,'verify_ready'),patch.object(window,'api',return_value=tags), \
                 patch.object(window,'run',side_effect=command),patch.object(window,'restore') as recovery, \
                 patch('training_window.pwd.getpwuid',return_value=SimpleNamespace(pw_name='fixture')):
                with self.assertRaises(RuntimeError):window.window(root,Path('/root/inspected.py'))
                recovery.assert_called_once_with(root)
            timer=next(i for i,a in enumerate(calls) if a[0]=='systemd-run')
            stop=calls.index(['systemctl','stop','ollama']);self.assertLess(timer,stop)
            self.assertEqual(json.loads((root/'window.json').read_text())['status'],'training_failed_restored')

    def test_failed_warmup_leaves_independent_timer_available(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);tags={'models':[{'name':window.ORIGINAL,'digest':window.ORIGINAL_DIGEST}]}
            with patch.object(window,'STATE',root),patch.object(window,'run',return_value=SimpleNamespace(returncode=1,stdout='')) as command, \
                 patch.object(window,'api',side_effect=[tags,{'done':False}]):
                with self.assertRaises(RuntimeError):window.restore(root)
            self.assertFalse(any(c.args[0]==['systemctl','stop',window.RESTORE_UNIT+'.timer'] for c in command.call_args_list))
            self.assertEqual(json.loads((root/'restore.json').read_text())['status'],'restore_failed')


if __name__=='__main__':unittest.main()
