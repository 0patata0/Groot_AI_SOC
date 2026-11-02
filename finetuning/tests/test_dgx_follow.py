"""No active mutation, no accidental restart, and no extra optimizer step."""
import copy
import json
import math
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import dgx_follow as follow


class FollowTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'follow';self.root.mkdir()
        self.p={'root':str(self.root),'unit':'capstone-dgx-20261102-follow',
                'parent_control':str(self.root.parent/'old/control.json'),
                'max_steps':100,'initial_step':10,'initial_started_at_kst':'2026-11-02T00:00:00+09:00',
                'fallback_seconds_per_step':18,'validation_seconds':2700,
                'startup_seconds':900,'save_grace_seconds':900,'poll_seconds':60}
        self.c={'root':str(self.root.parent/'old'),'run_id':'capstone-dgx-20261102-r6',
                'deadline_kst':'2026-11-02T17:30:00+09:00'}
        self.s={'status':{'status':'stopped_deadline'},'attempt':str(self.root.parent/'old-a1'),
                'service':{'ActiveState':'inactive','MainPID':'0','Result':'success'},'containers':[],
                'progress':{'step':80,'max_steps':100,'resumed_from_step':10,'elapsed_seconds':1260}}
        self.time=follow.datetime.fromisoformat(self.c['deadline_kst']).timestamp()

    def test_running_service_pid_or_container_always_waits(self):
        for change in ({'ActiveState':'active'},{'MainPID':'123'},{'ActiveState':'deactivating'}):
            s=copy.deepcopy(self.s);s['service'].update(change)
            self.assertEqual(follow.decision(s,self.c,self.time),'wait')
        s=copy.deepcopy(self.s);s['containers']=['own-job']
        self.assertEqual(follow.decision(s,self.c,self.time),'wait')

    def test_only_saved_deadline_exit_is_renewable(self):
        self.assertEqual(follow.decision(self.s,self.c,self.time),'continue')
        for status in ('failed','running','stopped_by_operator','stopped_retry_limit'):
            self.s['status']['status']=status
            with self.subTest(status=status),self.assertRaises(RuntimeError):
                follow.decision(self.s,self.c,self.time)

    def test_early_manual_stop_and_failed_service_are_not_renewed(self):
        with self.assertRaisesRegex(RuntimeError,'Early/manual'):
            follow.decision(self.s,self.c,self.time-901)
        self.s['service']['Result']='signal'
        with self.assertRaises(RuntimeError):follow.decision(self.s,self.c,self.time)

    def test_complete_and_validation_pending_never_resume_training(self):
        for value,expected in [('completed','complete'),('completed_training_validation_pending','validation_pending')]:
            self.s['status']['status']=value
            self.assertEqual(follow.decision(self.s,self.c,self.time),expected)
        self.s['status']['status']='completed';self.s['service']['Result']='exit-code'
        with self.assertRaises(RuntimeError):follow.decision(self.s,self.c,self.time)

    def test_estimate_includes_actual_waits_eval_startup_and_save_margin(self):
        at=follow.datetime.fromisoformat(self.p['initial_started_at_kst']).timestamp()+2520
        estimate=follow.estimate(self.p,self.s['progress'],at)
        self.assertEqual(estimate['seconds_per_step_with_observed_waits'],36)
        self.assertEqual(estimate['remaining_training_seconds'],720)
        self.assertGreaterEqual(estimate['window_seconds'],720+2700+900+900)
        self.assertEqual(follow.datetime.fromisoformat(estimate['proposed_deadline_kst']).utcoffset().total_seconds(),32400)

    def test_window_is_bounded_and_plan_mismatch_rejected(self):
        p={**self.p,'max_steps':10000000};s={**self.s['progress'],'max_steps':10000000}
        estimate=follow.estimate(p,s,self.time)
        self.assertEqual(estimate['window_seconds'],86400);self.assertTrue(estimate['window_capped'])
        for changed in ({'max_steps':101},{'step':101},{'step':False}):
            with self.assertRaises(ValueError):follow.estimate(self.p,{**self.s['progress'],**changed},self.time)

    def runtime(self,actions,step=80):
        dgx=types.SimpleNamespace(apply=unittest.mock.Mock())
        def build(parent,target,*args):
            target.mkdir();(target/'control.json').write_text('{}')
        builder=types.SimpleNamespace(build=unittest.mock.Mock(side_effect=build))
        ctx=patch.multiple(follow,runtime=unittest.mock.Mock(return_value=(dgx,builder,None,self.c)),
            bound_control=unittest.mock.Mock(return_value=self.c),snapshot=unittest.mock.Mock(return_value=self.s),
            decision=unittest.mock.Mock(side_effect=actions),
            checkpoint=unittest.mock.Mock(return_value=(step,Path(self.s['attempt']),{'max_steps':100})),
            completion=unittest.mock.Mock(return_value={'step':100,'operational_quality_passed':False}))
        return dgx,builder,ctx

    def test_active_run_is_observed_without_build_or_apply_then_ends_early(self):
        dgx,builder,ctx=self.runtime(['wait','complete'])
        with ctx,patch.object(follow.time,'sleep'),patch.object(follow.subprocess,'run') as commands:
            follow.run(self.p)
        builder.build.assert_not_called();dgx.apply.assert_not_called()
        state=follow.read(self.root/'follow-status.json')
        self.assertEqual(state['status'],'completed')
        self.assertEqual(commands.call_args.args[0],['systemctl','disable','--now',self.c['run_id']+'-deadline.timer'])

    def test_saved_window_starts_distinct_resume_with_same_original_sources(self):
        dgx,builder,ctx=self.runtime(['continue','complete'])
        with ctx,patch.object(follow.time,'sleep'),patch.object(follow.subprocess,'run'):
            follow.run(self.p)
        args=builder.build.call_args.args
        self.assertEqual(args[0],Path(self.s['attempt']))
        self.assertEqual(args[2],'capstone-dgx-20261102-f1')
        self.assertEqual(args[4],Path(self.c['root'])/'source')
        self.assertEqual(args[5],80)
        self.assertEqual(args[6],{'max_attempts':32,'idle_seconds':60})
        self.assertEqual(dgx.apply.call_args.kwargs,{'reviewed_window_hours':24})

    def test_preparation_between_attempts_waits_without_stale_eta_or_restart(self):
        preparing = {**self.s, 'progress': {'status': 'tokenizing'}}
        dgx,builder,ctx=self.runtime(['wait','wait','complete'])
        states=[]
        with ctx,patch.object(follow,'snapshot',side_effect=[self.s,preparing,self.s]), \
             patch.object(follow.time,'sleep',side_effect=lambda _:states.append(follow.read(self.root/'follow-status.json'))), \
             patch.object(follow.subprocess,'run'):
            follow.run(self.p)
        self.assertIn('estimate',states[0])
        self.assertNotIn('estimate',states[1])
        self.assertIn('estimate_pending',states[1])
        self.assertEqual(states[1]['status'],'running')
        self.assertEqual(follow.read(self.root/'follow-status.json')['status'],'completed')
        builder.build.assert_not_called();dgx.apply.assert_not_called()

    def test_numeric_plan_mismatch_still_fails_while_waiting(self):
        self.s['progress']['max_steps']=101
        dgx,builder,ctx=self.runtime(['wait'])
        with ctx,self.assertRaisesRegex(ValueError,'matching progress'):
            follow.run(self.p)
        builder.build.assert_not_called();dgx.apply.assert_not_called()

    def test_no_progress_or_existing_output_never_restarts(self):
        dgx,builder,ctx=self.runtime(['continue'],step=10)
        with ctx,self.assertRaisesRegex(RuntimeError,'forward progress'):
            follow.run(self.p)
        builder.build.assert_not_called();dgx.apply.assert_not_called()
        self.assertEqual(follow.read(self.root/'follow-status.json')['status'],'failed')

    def test_validation_pending_does_not_replay_final_training_steps(self):
        dgx,builder,ctx=self.runtime(['validation_pending'])
        with ctx:follow.run(self.p)
        builder.build.assert_not_called();dgx.apply.assert_not_called()
        self.assertEqual(follow.read(self.root/'follow-status.json')['status'],'validation_pending')

    def test_prior_follower_state_cannot_be_overwritten_on_restart(self):
        (self.root/'follow-status.json').write_text('{"status":"completed"}')
        dgx,builder,ctx=self.runtime([])
        with ctx,self.assertRaisesRegex(RuntimeError,'already attempted'):
            follow.run(self.p)
        self.assertEqual(follow.read(self.root/'follow-status.json')['status'],'completed')

    def test_transient_observation_timeout_waits_and_does_not_restart_training(self):
        dgx,builder,ctx=self.runtime(['complete'])
        with ctx,patch.object(follow,'snapshot',side_effect=[follow.subprocess.TimeoutExpired('show',30),self.s]), \
             patch.object(follow.time,'sleep') as sleep,patch.object(follow.subprocess,'run'):
            follow.run(self.p)
        self.assertEqual(sleep.call_count,1)
        builder.build.assert_not_called();dgx.apply.assert_not_called()
        self.assertEqual(follow.read(self.root/'follow-status.json')['status'],'completed')

    def test_completion_requires_full_steps_finite_validation_and_correct_lineage(self):
        out=Path(self.s['attempt'])/'workspace/main';out.mkdir(parents=True)
        (out/'adapter').mkdir()
        for name in ('adapter_model.safetensors','adapter_config.json'):(out/'adapter'/name).write_text('fixture')
        (out/'progress.json').write_text(json.dumps({'status':'completed','step':100,'max_steps':100}))
        (out.parent/'main-status.json').write_text('{"status":"completed"}')
        (out/'eval_results.json').write_text('{"eval_loss":0.5}')
        (out/'run_manifest.json').write_text(json.dumps({'data':{'sha256':{s:s for s in ('train','validation','test')}}}))
        origin={'files':{'data/'+s+'.jsonl':s for s in ('train','validation','test')}}
        self.assertEqual(follow.completion(self.s,self.c,self.p,origin)['step'],100)
        for name,body in [('progress.json',{'status':'completed','step':99,'max_steps':100}),
                          ('eval_results.json',{'eval_loss':float('nan')}),
                          ('run_manifest.json',{'data':{'sha256':{'train':'wrong','validation':'validation','test':'test'}}})]:
            path=out/name;old=path.read_text();path.write_text(json.dumps(body))
            with self.subTest(name=name),self.assertRaises(RuntimeError):follow.completion(self.s,self.c,self.p,origin)
            path.write_text(old)
        (out/'adapter/adapter_model.safetensors').unlink()
        with self.assertRaisesRegex(RuntimeError,'incomplete'):follow.completion(self.s,self.c,self.p,origin)

    def test_policy_rejects_unbound_paths_extra_files_or_unsafe_limits(self):
        root=Path('/home/operator/Capstone_Groot_training/follow')
        p={**self.p,'schema':1,'root':str(root),'parent_control':str(root.parent/'old/control.json'),
            'parent_sha256':'a'*64,'authorized_at_kst':'2026-11-02T10:37:00+09:00',
            'files':{'deploy.sh':'a'*64,'finetuning/dgx_follow.py':'a'*64}}
        with patch.object(follow,'trusted'),patch.object(follow,'sha',return_value='a'*64),patch.object(follow,'read',return_value=p):
            self.assertEqual(follow.load_policy(root/'follow.json'),p)
            for field,value in [('parent_control','/etc/passwd'),('unit','other.service'),
                                ('files',{'deploy.sh':'a'*64}),('poll_seconds',0),
                                ('save_grace_seconds',0),('max_steps',True),('initial_step',100),
                                ('fallback_seconds_per_step',float('inf'))]:
                old=p[field];p[field]=value
                with self.subTest(field=field),self.assertRaises(ValueError):follow.load_policy(root/'follow.json')
                p[field]=old

    def test_current_checkpoint_does_not_revalidate_unrelated_original_controller_source(self):
        current=Path(self.s['attempt']);old=current.parent/'older-controller'
        checkpoint=current/'workspace/main/checkpoint-80';checkpoint.mkdir(parents=True)
        (checkpoint/'checkpoint-complete.json').write_text('{}')
        c={**self.c,'resume_parent':str(old)}
        resume=types.SimpleNamespace(COMPLETION_MARKER='checkpoint-complete.json',
                verified_completion=lambda output,path:{'step':80,'max_steps':100})
        def bound(path,*args):
            if path.parent==old:raise ValueError('Old controller source differs')
            return c
        with patch.object(follow,'bound_control',side_effect=bound) as checked:
            step,parent,_=follow.checkpoint(self.s,c,self.c,None,resume)
        self.assertEqual(step,80);self.assertEqual(parent,current)
        self.assertEqual([call.args[0] for call in checked.call_args_list],[current/'control.json'])


if __name__=='__main__':unittest.main()
