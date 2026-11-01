import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import dgx_supervisor as dgx
from prepare_operator_release import explicit_secret, private_observations


class OperatorPreflightTests(unittest.TestCase):
    def setUp(self):
        self.c={'run_id':'capstone-dgx-20261101-r5preflight',
                'root':'/home/operator/Capstone_Groot_training/operator-r5',
                'uid':1000,'gid':1000,'image':'nvcr.io/nvidia/pytorch@sha256:'+'a'*64,
                'deadline_kst':'2026-11-01T17:00:00+09:00','files':{'source/train.py':'b'*64},
                'environment_parent':'/home/operator/Capstone_Groot_training/base-run',
                'purpose':'preflight_only','smoke_data_subdir':'smoke'}

    def test_fresh_environment_reuse_never_mounts_old_checkpoint(self):
        args=dgx.docker_args(self.c,'smoke');text=' '.join(args)
        self.assertIn('/base-run/workspace/base,dst=/workspace/base,readonly',text)
        self.assertIn('/base-run/workspace/venv,dst=/workspace/venv,readonly',text)
        self.assertNotIn('dst=/resume',text)
        self.assertIn('/data/smoke,dst=/data,readonly',text)
        self.assertIn('--network=none',args)
        for stage in ('download','tokenize'):
            cpu=dgx.docker_args(self.c,stage)
            self.assertIn('--runtime=runc',cpu);self.assertNotIn('--gpus',cpu)
            self.assertIn('--network=none',cpu)

    def test_preflight_refuses_main_entrypoints_before_any_mutation(self):
        with patch.object(dgx,'verify_files')as verify,patch.object(dgx.subprocess,'run')as run:
            with self.assertRaises(ValueError):dgx.apply(self.c,Path(self.c['root'])/'control.json')
            with self.assertRaises(ValueError):dgx.run_once(self.c)
            verify.assert_not_called();run.assert_not_called()

    def test_preflight_config_cannot_mix_resume_or_unbounded_subdirectory(self):
        with tempfile.TemporaryDirectory()as tmp:
            p=Path(tmp)/'c.json'
            for update in ({'resume_parent':self.c['environment_parent']},
                           {'smoke_data_subdir':'../../other'}, {'purpose':'anything'}):
                p.write_text(json.dumps({**self.c,**update}))
                with self.subTest(update=update),self.assertRaises(ValueError):dgx.read_config(p)
            p.write_text(json.dumps(self.c));self.assertEqual(dgx.read_config(p),self.c)

    def test_preflight_unit_is_bounded_and_enters_only_smoke_path(self):
        original={'root':self.c['environment_parent']}
        with patch.object(dgx,'verify_files'),patch.object(dgx,'resource_config',return_value=original),\
             patch.object(Path,'read_text',side_effect=[json.dumps({'status':'completed'}),json.dumps({'compute_capability':[12,1],'cuda_forward_backward':'passed'})]),\
             patch.object(dgx,'shared_model_active',return_value=False),\
             patch.object(dgx,'available_memory',return_value=100*2**30),\
             patch.object(dgx.time,'time',return_value=dgx.cutoff(self.c['deadline_kst'])-2700),\
             patch.object(dgx.subprocess,'run')as execute:
            dgx.start_preflight(self.c,Path(self.c['root'])/'control.json')
        command=execute.call_args.args[0]
        self.assertEqual(command[0],'systemd-run')
        self.assertIn('--property=RuntimeMaxSec=1800',command)
        self.assertEqual(command[-1],'--run-smoke')
        self.assertNotIn('--run',command)
        self.assertTrue(any('ExecStopPost='in x and '--stop-container'in x for x in command))

    def test_shared_inference_prevents_start_without_stopping_it(self):
        with patch.object(dgx,'verify_files'),patch.object(dgx,'resource_config',return_value={'root':self.c['environment_parent']}),\
             patch.object(Path,'read_text',side_effect=[json.dumps({'status':'completed'}),json.dumps({'compute_capability':[12,1],'cuda_forward_backward':'passed'})]),\
             patch.object(dgx,'shared_model_active',return_value=True),\
             patch.object(dgx.time,'time',return_value=dgx.cutoff(self.c['deadline_kst'])-2700),\
             patch.object(dgx.subprocess,'run')as execute:
            with self.assertRaises(dgx.SharedInferenceBusy):dgx.start_preflight(self.c,Path(self.c['root'])/'control.json')
            execute.assert_not_called()

    def test_credential_fields_are_checked_even_inside_json_user_text(self):
        for key in ('secretAccessKey','session_token','Authorization'):
            self.assertTrue(explicit_secret({key:'example-secret'}))
        self.assertFalse(explicit_secret({'secretAccessKey':'[REDACTED]'}))
        self.assertTrue(private_observations({'messages':[{'role':'user','content':'evidence\n'+json.dumps({'sessionToken':'example-secret'})}]}))

    def test_queue_waits_for_shared_inference_then_sixty_seconds_idle(self):
        clock=[0];saved=[]
        def sleep(seconds):clock[0]+=seconds
        def busy():return clock[0]<20
        with patch.object(dgx.time,'time',side_effect=lambda:clock[0]),patch.object(dgx.time,'sleep',side_effect=sleep),\
             patch.object(dgx,'cutoff',return_value=4000),patch.object(dgx,'shared_model_active',side_effect=busy),\
             patch.object(dgx,'available_memory',return_value=100*2**30),patch.object(dgx,'save_queue',side_effect=lambda *a,**kw:saved.append(kw)):
            dgx.wait_for_preflight_idle(self.c)
        self.assertEqual(clock[0],80)
        self.assertEqual(saved[0]['reason'],'shared_inference_active')
        self.assertEqual(saved[-1]['reason'],'confirming_60_seconds_idle')

    def test_queue_never_starts_if_memory_remains_low_or_state_unknown(self):
        for active in (False,OSError('unavailable')):
            clock=[0]
            with patch.object(dgx.time,'time',side_effect=lambda:clock[0]),\
                 patch.object(dgx.time,'sleep',side_effect=lambda seconds:clock.__setitem__(0,clock[0]+seconds)),\
                 patch.object(dgx,'cutoff',return_value=1830),\
                 patch.object(dgx,'shared_model_active',**({'side_effect':active}if isinstance(active,Exception)else{'return_value':active})),\
                 patch.object(dgx,'available_memory',return_value=80*2**30),patch.object(dgx,'save_queue'):
                with self.assertRaisesRegex(RuntimeError,'No idle'):dgx.wait_for_preflight_idle(self.c)

    def test_queued_child_is_bounded_and_failure_stops_only_owned_container(self):
        import subprocess
        with tempfile.TemporaryDirectory()as tmp:
            c={**self.c,'root':tmp}
            with patch.object(dgx,'wait_for_preflight_idle'),patch.object(dgx.subprocess,'run',side_effect=subprocess.TimeoutExpired('smoke',1800))as run,\
                 patch.object(dgx,'stop_container')as stop:
                with self.assertRaises(subprocess.TimeoutExpired):dgx.run_queued_smoke(c,Path(tmp)/'control.json')
            self.assertEqual(run.call_args.kwargs['timeout'],1800)
            self.assertEqual(run.call_args.args[0][-1],'--run-smoke')
            stop.assert_called_once_with(c)
            status=json.loads((Path(tmp)/'preflight-queue.json').read_text())
            self.assertFalse(status['gpu_smoke_passed']);self.assertFalse(status['main_training_started'])

    def test_stop_targets_the_waiting_preflight_unit_not_a_nonexistent_main_unit(self):
        with patch.object(sys,'argv',['dgx_supervisor','--config','ignored','--stop']),\
             patch.object(dgx,'read_config',return_value=self.c),patch.object(dgx.os,'geteuid',return_value=0),\
             patch.object(dgx,'stop_container'),patch.object(dgx,'save_queue')as save,patch.object(dgx.subprocess,'run')as run:
            dgx.main()
        run.assert_called_once_with(['systemctl','stop',self.c['run_id']+'-preflight.service'],check=True)
        self.assertEqual(save.call_args.args[1],'stopped_by_operator')


if __name__=='__main__':unittest.main()
