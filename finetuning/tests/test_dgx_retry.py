"""Bounded retries must preserve provenance and stop on unrelated failures."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import dgx_supervisor as dgx
import resume_training as resume
import prepare_dgx_resume as builder

class RetryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'controller';self.root.mkdir()
        (self.root/'profiles').mkdir()
        (self.root/'profiles/resume.json').write_text(json.dumps({'step':168}))
        self.c={'root':str(self.root),'resume_parent':str(self.root.parent/'old'),
                'run_id':'capstone-dgx-20261101-r2','deadline_kst':'2026-11-01T11:35:00+09:00',
                'image':'pinned','uid':1000,'gid':1000,
                'retry_policy':{'max_attempts':3,'idle_seconds':60}}

    def checkpoint(self,root,step=176):
        output=root/'workspace/main';output.mkdir(parents=True)
        (output/'run_manifest.json').write_text(json.dumps({'config':{},'data':{},'base_artifact_manifest':{}}))
        p=output/('checkpoint-'+str(step));p.mkdir()
        for name in resume.REQUIRED:(p/name).write_text('fixture')
        (p/'trainer_state.json').write_text(json.dumps({'global_step':step,'max_steps':224}))
        return output,p

    def build(self,parent,root,run_id,deadline,sources,step):
        root.mkdir()
        c={k:v for k,v in self.c.items() if k!='retry_policy'}
        c.update(root=str(root),resume_parent=str(parent))
        (root/'control.json').write_text(json.dumps(c))

    def run_controller(self,action,idle=True):
        with patch.object(dgx,'verify_files'),patch.object(dgx,'wait_idle',return_value=idle), \
             patch.object(builder,'build',side_effect=self.build), \
             patch.object(dgx,'read_config',side_effect=lambda p:json.loads(p.read_text())), \
             patch.object(dgx,'run_once',side_effect=action) as calls:
            dgx.run(self.c)
            return calls.call_count,json.loads((self.root/'supervisor-status.json').read_text())

    def test_missing_or_corrupt_marker_is_never_selected(self):
        out,p=self.checkpoint(self.root)
        self.assertIsNone(dgx.newest_checkpoint(self.root,168))
        resume.mark_completed(out,p)
        self.assertEqual(dgx.newest_checkpoint(self.root,168),176)
        (p/'optimizer.pt').write_text('partial overwrite')
        self.assertIsNone(dgx.newest_checkpoint(self.root,168))

    def test_full_plan_checkpoint_never_runs_extra_optimizer_step(self):
        out,p=self.checkpoint(self.root,224)
        resume.mark_completed(out,p)
        self.assertFalse((p/resume.COMPLETION_MARKER).exists())
        self.assertIsNone(dgx.newest_checkpoint(self.root,168))

    def test_shared_interruption_retries_newest_complete_checkpoint(self):
        seen=[]
        def action(c):
            seen.append(c)
            if len(seen)==1:
                out,p=self.checkpoint(Path(c['root']))
                resume.mark_completed(out,p)
                raise dgx.SharedInferenceBusy('shared worker')
            dgx.save(c,{'status':'completed'})
        count,status=self.run_controller(action)
        self.assertEqual(count,2);self.assertEqual(status['status'],'completed')
        self.assertEqual(status['attempts'][1]['resumed_from_step'],176)
        self.assertEqual(seen[1]['resume_parent'],seen[0]['root'])
        self.assertEqual(seen[1]['run_id'],self.c['run_id'])
        self.assertEqual(seen[1]['deadline_kst'],self.c['deadline_kst'])

    def test_interrupted_load_reuses_original_and_stops_at_attempt_limit(self):
        seen=[]
        def action(c):
            seen.append(c);raise dgx.SharedInferenceBusy('load contention')
        count,status=self.run_controller(action)
        self.assertEqual(count,3);self.assertEqual(status['status'],'stopped_retry_limit')
        self.assertTrue(all(c['resume_parent']==self.c['resume_parent'] for c in seen))

    def test_unrelated_training_failure_is_not_retried(self):
        with self.assertRaisesRegex(RuntimeError,'nonfinite'):
            self.run_controller(lambda c:(_ for _ in ()).throw(RuntimeError('nonfinite')))
        status=json.loads((self.root/'supervisor-status.json').read_text())
        self.assertEqual(status['status'],'failed');self.assertEqual(len(status['attempts']),1)

    def test_cutoff_does_not_start_an_attempt(self):
        count,status=self.run_controller(lambda c:self.fail('must not run'),idle=False)
        self.assertEqual(count,0);self.assertEqual(status['status'],'stopped_deadline')

    def test_idle_requires_continuous_window_and_memory_floor(self):
        status={}
        with patch.object(dgx.time,'time',return_value=0),patch.object(dgx,'cutoff',return_value=9999), \
             patch.object(dgx.time,'sleep'),patch.object(dgx.time,'monotonic',side_effect=[0,0,20,30,30,91]), \
             patch.object(dgx,'shared_model_active',side_effect=[False,False,True,False,False]), \
             patch.object(dgx,'available_memory',return_value=100*2**30):
            self.assertTrue(dgx.wait_idle(self.c,status))
        self.assertEqual(status['idle_seconds'],61)

    def test_resource_chain_reuses_original_and_rejects_cycle_identity_and_misdirection(self):
        a={**self.c,'root':'/home/u/Capstone_Groot_training/a','resume_parent':'/home/u/Capstone_Groot_training/b'}
        b={**a,'root':a['resume_parent'],'resume_parent':'/home/u/Capstone_Groot_training/original'}
        original={k:v for k,v in b.items() if k not in ('resume_parent','retry_policy')};original['root']=b['resume_parent']
        mapping={c['root']:c for c in (a,b,original)}
        with patch.object(dgx,'verify_files'),patch.object(dgx,'read_config',side_effect=lambda p:mapping[str(p.parent)]):
            self.assertEqual(dgx.resource_config(a)['root'],original['root'])
            b['resource_root']=a['root']
            with self.assertRaisesRegex(ValueError,'Declared'):dgx.resource_config(a)
            del b['resource_root'];original['uid']=1001
            with self.assertRaisesRegex(ValueError,'identity'):dgx.resource_config(a)
            original['uid']=1000;original['resume_parent']=a['root']
            with self.assertRaisesRegex(ValueError,'Cyclic'):dgx.resource_config(a)

    def test_chained_mount_uses_actual_base_and_immediate_checkpoint(self):
        c={**self.c,'resource_root':'/home/u/Capstone_Groot_training/original'}
        args=dgx.docker_args(c,'main')
        self.assertIn('type=bind,src=/home/u/Capstone_Groot_training/original/workspace/base,dst=/workspace/base,readonly',args)
        self.assertIn('type=bind,src='+self.c['resume_parent']+'/workspace/main,dst=/resume,readonly',args)

    def test_api_uncertainty_releases_only_own_training_and_is_retryable(self):
        with patch.object(dgx,'shared_model_active',side_effect=TimeoutError('timeout')):
            with self.assertRaisesRegex(dgx.SharedInferenceBusy,'unavailable'):dgx.check_shared_during_training()

    def fresh_build(self,control,root):
        root.mkdir()
        current={k:v for k,v in control.items()if k!='retry_policy'}
        current['root']=str(root);(root/'control.json').write_text(json.dumps(current))

    def test_fresh_training_retries_before_first_checkpoint_then_resumes_verified_checkpoint(self):
        self.c.pop('resume_parent');self.c.update(environment_parent=str(self.root.parent/'original'),purpose='main_training')
        seen=[]
        def action(c):
            seen.append(c)
            if len(seen)==1:raise dgx.SharedInferenceBusy('other model loaded before checkpoint')
            if len(seen)==2:
                out,p=self.checkpoint(Path(c['root']),step=4);resume.mark_completed(out,p)
                raise dgx.SharedInferenceBusy('other model after checkpoint')
            dgx.save(c,{'status':'completed'})
        with patch.object(builder,'build_fresh',side_effect=self.fresh_build)as fresh:
            count,status=self.run_controller(action)
        self.assertEqual(count,3);self.assertEqual(fresh.call_count,2)
        self.assertEqual([r['resumed_from_step']for r in status['attempts']],[0,0,4])
        self.assertNotIn('resume_parent',seen[0]);self.assertNotIn('resume_parent',seen[1])
        self.assertEqual(seen[2]['resume_parent'],seen[1]['root']);self.assertEqual(status['status'],'completed')

    def test_verified_release_requires_full_runtime_and_exact_training_data(self):
        data=self.root/'data';data.mkdir()
        c={**self.c,'files':{'data/release.json':'r'*64,'data/train.jsonl':'a'*64,'source/train.py':'b'*64}}
        valid={'status':'ready_for_bounded_training','gpu_preflight_passed':True,'train_sha256':'a'*64,'runtime_sources':{'train.py':'b'*64}}
        p=data/'release.json';p.write_text(json.dumps(valid));self.assertTrue(dgx.verified_operator_release(c))
        for change in ({'train_sha256':'c'*64},{'runtime_sources':{}},{'gpu_preflight_passed':False}):
            p.write_text(json.dumps({**valid,**change}))
            with self.subTest(change=change),self.assertRaises(ValueError):dgx.verified_operator_release(c)

if __name__=='__main__':unittest.main()
