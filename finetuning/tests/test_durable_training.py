import copy,hashlib,json,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from contextlib import ExitStack
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import durable_training_window as w
from prepare_evidence_run import split_guard

class Separation(unittest.TestCase):
    def row(self,i,g=None):
        return {'id':i,'messages':[{'role':'user','content':i},{'role':'assistant','content':'source-bound'}],'provenance':{'group':g} if g else {}}
    def test_missing_group_refused(self):
        with self.assertRaisesRegex(ValueError,'Missing source'):split_guard({'train':[self.row('a')]})
    def test_source_group_overlap_refused(self):
        with self.assertRaisesRegex(ValueError,'Source group'):split_guard({'train':[self.row('a','g')],'test':[self.row('b','g')]})
    def test_id_reuse_refused(self):
        with self.assertRaisesRegex(ValueError,'Repeated record'):split_guard({'train':[self.row('a','g')],'test':[self.row('a','h')]})
    def test_exact_payload_in_other_group_refused(self):
        a=self.row('a','g');b=copy.deepcopy(a);b['id']='b';b['provenance']['group']='h'
        with self.assertRaisesRegex(ValueError,'Payload'):split_guard({'train':[a],'test':[b]})
    def test_verified_external_group_used_without_rewriting_payload(self):
        row=self.row('a');before=copy.deepcopy(row)
        result=split_guard({'train':[row],'test':[self.row('b','test')]},{'a':'source-sidecar'})
        self.assertEqual(result['cross_split_ids_groups_exact_payloads'],0);self.assertEqual(before,row)

class Isolation(unittest.TestCase):
    def test_cpu_audit_has_no_gpu_or_network_or_package_pull(self):
        args=w.container_command(Path('/base'),Path('/base/runs/new'),'tokenize')
        self.assertIn('--runtime=runc',args);self.assertNotIn('--gpus',args);self.assertIn('--pull=never',args)
        self.assertEqual(args[args.index('--network')+1],'none');self.assertIn('--read-only',args)
    def test_training_is_unprivileged_bounded_and_readonly_inputs(self):
        args=w.container_command(Path('/base'),Path('/base/runs/new'),'main')
        self.assertEqual(args[args.index('--user')+1],'1000:1000');self.assertIn('--gpus',args)
        self.assertEqual(args[args.index('--memory')+1],'112g');self.assertIn('--cap-drop',args)
        mounts=[args[i+1] for i,a in enumerate(args) if a=='--mount']
        self.assertTrue(any('target=/workspace,readonly' in s for s in mounts))
        for target in ('source','data','profiles'):self.assertTrue(any('target=/trial/'+target+',readonly' in s for s in mounts))
    def test_unknown_stage_rejected(self):
        with self.assertRaises(ValueError):w.container_command(Path('/base'),Path('/run'),'shell')
    def test_independent_timer_is_bounded_and_not_ssh_owned(self):
        args=w.restore_command('/root/window.py','/base/run')
        self.assertIn('--on-active=245m',args);self.assertIn('--property=TimeoutStartSec=6min',args)
        self.assertEqual(args[-3:][0],'restore');self.assertLess(w.RESTORE_MINUTES+6,255)

class Lifecycle(unittest.TestCase):
    def exercise(self,fail_at=None,timer_active=True,estimate=100,prior=False):
        with tempfile.TemporaryDirectory() as d,ExitStack() as stack:
            root=Path(d)/'run';root.mkdir();(root/'release.json').write_text('{}')
            state=Path(d)/'state';state.mkdir()
            if prior:(state/'window.json').write_text('{}')
            calls=[];records={};restored=[]
            def command(args,**kwargs):
                a=[str(x) for x in args];calls.append(a)
                if fail_at=='stop' and a==['systemctl','stop','ollama']:raise RuntimeError('stop failed')
                if a==['systemctl','is-active',w.RESTORE+'.timer']:return SimpleNamespace(stdout='active' if timer_active else 'inactive')
                if a[:2]==['systemctl','is-active']:return SimpleNamespace(stdout='active')
                if a[:2]==['systemctl','is-enabled']:return SimpleNamespace(stdout='enabled')
                if a[:2]==['systemctl','show']:return SimpleNamespace(stdout='12')
                return SimpleNamespace(stdout='')
            stack.enter_context(patch.object(w,'STATE',state));stack.enter_context(patch.object(w,'run',side_effect=command))
            stack.enter_context(patch.object(w,'verify_bundle',return_value={'min_disk_free_bytes':1}))
            stack.enter_context(patch.object(w,'save',side_effect=lambda name,x:records.update({name:copy.deepcopy(x)})))
            stack.enter_context(patch.object(w,'available_bytes',return_value=100*2**30))
            stack.enter_context(patch.object(w.recovery,'api',return_value={'models':[{'name':w.recovery.ORIGINAL,'digest':w.recovery.ORIGINAL_DIGEST}]}))
            stack.enter_context(patch.object(w.recovery,'restore',side_effect=lambda r:restored.append(r)))
            stack.enter_context(patch.object(w,'wait_stage',side_effect=RuntimeError('smoke failed') if fail_at=='smoke' else None))
            stack.enter_context(patch.object(w,'estimate_main',return_value={'estimated_main_seconds':estimate}))
            stack.enter_context(patch.object(w,'verify_completion',return_value={'status':'passed'}))
            try:w.window(root,Path('/root/window.py'))
            except (ValueError,RuntimeError):pass
            return calls,records,restored
    def test_timer_failure_never_stops_inference(self):
        calls,records,restored=self.exercise(timer_active=False)
        self.assertNotIn(['systemctl','stop','ollama'],calls);self.assertEqual(restored,[])
    def test_stop_failure_still_runs_restoration(self):
        calls,records,restored=self.exercise(fail_at='stop');self.assertEqual(len(restored),1)
        self.assertEqual(records['window.json']['status'],'training_failed_restored')
    def test_smoke_failure_never_starts_main_and_restores(self):
        calls,records,restored=self.exercise(fail_at='smoke');self.assertEqual(len(restored),1)
        self.assertFalse(any(a[-1]=='main' for a in calls))
    def test_over_budget_smoke_never_starts_main(self):
        calls,records,restored=self.exercise(estimate=20000);self.assertEqual(len(restored),1)
        self.assertFalse(any(a[-1]=='main' for a in calls))
    def test_previous_window_refuses_every_service_action(self):
        calls,records,restored=self.exercise(prior=True);self.assertEqual(calls,[]);self.assertEqual(restored,[])
    def test_success_restores_before_completion_check(self):
        calls,records,restored=self.exercise();self.assertEqual(len(restored),1)
        self.assertEqual(records['window.json']['status'],'training_completed_restored')
        self.assertEqual(records['completion-verification.json']['status'],'passed')
        arm=next(i for i,c in enumerate(calls) if c[0]=='systemd-run')
        stop=calls.index(['systemctl','stop','ollama']);self.assertLess(arm,stop)

class Completion(unittest.TestCase):
    def test_estimate_does_not_multiply_evaluation_time_per_training_row(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);p=root/'smoke';p.mkdir()
            (p/'train_results.json').write_text('{"train_runtime":122}')
            (p/'eval_results.json').write_text('{"eval_runtime":35}')
            (p/'progress.json').write_text('{"status":"completed","step":2}')
            rows=[{'successful_forward_backward':True,'prefixes':[{'record_id':str(i)}]} for i in range(2)]
            (p/'successful_microbatch_lineage.jsonl').write_text(''.join(json.dumps(x)+'\n' for x in rows))
            events=[{'phase':'training','step':i,'at_kst':t} for i,t in [(0,'2026-10-31T09:00:00+09:00'),(1,'2026-10-31T09:00:52+09:00'),(2,'2026-10-31T09:01:26+09:00'),(2,'2026-10-31T09:02:01+09:00')]]
            (p/'memory_telemetry.jsonl').write_text(''.join(json.dumps(x)+'\n' for x in events))
            x=w.estimate_main(root);self.assertEqual(x['longest_example_seconds'],52)
            self.assertAlmostEqual(x['estimated_main_seconds'],52*191*1.15+35/8*128+300)
            self.assertTrue(x['evaluation_counted_once'])
    def test_unknown_run_refused_and_r2_has_shorter_main_only_window(self):
        keys=['RUN_ID','UNIT','STATE','RESTORE','LIMIT','RESTORE_MINUTES','STAGES']
        with patch.multiple(w,**{k:getattr(w,k) for k in keys}):
            with self.assertRaises(ValueError):w.select_run('arbitrary')
            w.select_run('soc-evidence-20261031-r2');self.assertEqual(w.STAGES,('main',))
            self.assertEqual(w.LIMIT,235*60);self.assertEqual(w.RESTORE_MINUTES,240)
            self.assertIn('r2',str(w.STATE))
    def test_incomplete_epoch_is_not_success(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d);(r/'main').mkdir();(r/'main/progress.json').write_text('{"status":"completed","step":95,"epoch":0.99}')
            with self.assertRaisesRegex(ValueError,'Full epoch'):w.verify_completion(r)
    def test_duplicated_smoke_identity_is_not_timing_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d);p=r/'smoke';p.mkdir()
            (p/'train_results.json').write_text('{"train_runtime":100}')
            (p/'eval_results.json').write_text('{"eval_runtime":4}')
            row={'successful_forward_backward':True,'prefixes':[{'record_id':'same'}]}
            (p/'successful_microbatch_lineage.jsonl').write_text((json.dumps(row)+'\n')*2)
            with self.assertRaisesRegex(ValueError,'Repeated smoke'):w.estimate_main(r)

class FrozenInputChecks(unittest.TestCase):
    def fixture(self,d):
        base=Path(d)/'base';r=base/'runs'/w.RUN_ID;r.mkdir(parents=True)
        for n in ('source','data','profiles','tokenization'):(r/n).mkdir()
        for n in w.SOURCE_FILES:(r/'source'/n).write_text('# frozen fixture\n')
        cfg={'num_train_epochs':1,'max_steps':-1,'gradient_accumulation_steps':2,'learning_rate':5e-7,
             'max_train_samples':0,'max_eval_samples':0,'require_all_prefixes':True,'max_length':4096,
             'loss_mode':'all_assistant_turns','assistant_only_logits':True,'deterministic_training':True,
             'gradient_checkpointing':True,'quantization':'none','revision':'fixed-revision'}
        (r/'profiles/main.json').write_text(json.dumps(cfg));outputs={}
        for s,n in [('train',191),('validation',128),('test',128)]:
            (r/'data'/(s+'.jsonl')).write_text('fixture-'+s);outputs[s]={'records':n,'sha256':w.sha(r/'data'/(s+'.jsonl'))}
        (r/'data/manifest.json').write_text(json.dumps({'outputs':outputs}));(base/'base').mkdir();(base/'base/weight').write_text('fixture')
        (base/'base-manifest.json').write_text(json.dumps({'verified':True,'revision':'fixed-revision','files':[{'path':'weight'}]}))
        st=(base/'base/weight').stat();(r/'base-recheck.json').write_text(json.dumps({'status':'passed','manifest_sha256':w.sha(base/'base-manifest.json'),'files':[{'path':'weight','size':st.st_size,'mtime_ns':st.st_mtime_ns}]}))
        release={'run_id':w.RUN_ID,'status':'experimental_training_only','training_rows':191,'expected_optimizer_steps':96,
                 'train_limit_seconds':w.LIMIT,'independent_restore_minutes':w.RESTORE_MINUTES,'automatic_promotion':False,
                 'guide_rows_admitted':0,'optional_harness_rows_admitted':0,'base_revision':'fixed-revision',
                 'files':{str(p.relative_to(r)):w.sha(p) for folder in ('source','data','profiles') for p in (r/folder).iterdir()}}
        (r/'release.json').write_text(json.dumps(release));(r/'tokenize-status.json').write_text('{"status":"completed"}')
        (r/'tokenization/data_check.json').write_text(json.dumps({'sha256':{s:v['sha256'] for s,v in outputs.items()}}))
        proof={'loss':'all_assistant_turns_per_conversation','require_all_prefixes':True,'max_length':4096}
        for s,n in [('train',191),('validation',128),('test',128)]:proof[s]={'kept':n,'candidate_examples':n,'covered_assistant_turns':n,'candidate_turns':n}
        (r/'tokenization/tokenization_report.json').write_text(json.dumps(proof));return r
    def test_complete_fixture_passes_without_services(self):
        with tempfile.TemporaryDirectory() as d,patch.object(w,'run',side_effect=AssertionError('no commands')):
            self.assertEqual(w.verify_bundle(self.fixture(d))['training_rows'],191)
    def test_mutated_training_source_refused(self):
        with tempfile.TemporaryDirectory() as d:
            r=self.fixture(d);(r/'source/train.py').write_text('changed')
            with self.assertRaisesRegex(ValueError,'Frozen input'):w.verify_bundle(r)
    def test_base_modified_after_full_hash_refused(self):
        with tempfile.TemporaryDirectory() as d:
            r=self.fixture(d);(r.parents[1]/'base/weight').write_text('different')
            with self.assertRaisesRegex(ValueError,'Base changed'):w.verify_bundle(r)
    def test_omitted_assistant_target_refused(self):
        with tempfile.TemporaryDirectory() as d:
            r=self.fixture(d);p=r/'tokenization/tokenization_report.json';x=w.load(p);x['train']['covered_assistant_turns']=190;p.write_text(json.dumps(x))
            with self.assertRaisesRegex(ValueError,'omitted'):w.verify_bundle(r)
    def test_modified_split_not_covered_by_token_proof_refused(self):
        with tempfile.TemporaryDirectory() as d:
            r=self.fixture(d);p=r/'tokenization/data_check.json';x=w.load(p);x['sha256']['train']='other';p.write_text(json.dumps(x))
            with self.assertRaisesRegex(ValueError,'Token proof corpus'):w.verify_bundle(r)
    def test_automatic_promotion_refused(self):
        with tempfile.TemporaryDirectory() as d:
            r=self.fixture(d);p=r/'release.json';x=w.load(p);x['automatic_promotion']=True;p.write_text(json.dumps(x))
            with self.assertRaisesRegex(ValueError,'admission/promotion'):w.verify_bundle(r)
    def test_extended_interruption_refused(self):
        with tempfile.TemporaryDirectory() as d:
            r=self.fixture(d);p=r/'release.json';x=w.load(p);x['train_limit_seconds']+=3600;p.write_text(json.dumps(x))
            with self.assertRaisesRegex(ValueError,'Restoration bound'):w.verify_bundle(r)

if __name__=='__main__':unittest.main()
