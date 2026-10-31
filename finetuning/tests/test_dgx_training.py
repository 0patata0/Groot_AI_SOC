"""Safety boundaries require no GPU or host service changes in these tests."""
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import dgx_supervisor as dgx
import model_profile
import memory_budget
from train import deadline_reached


class DgxTests(unittest.TestCase):
    def setUp(self):
        self.c={'run_id':'capstone-dgx-20261031','root':'/home/operator/Capstone_Groot_training/dgx-20261031',
                'uid':1000,'gid':1000,'image':'nvcr.io/nvidia/pytorch@sha256:'+'a'*64,
                'deadline_kst':'2026-11-01T06:30:00+09:00','files':{'source/train.py':'b'*64}}

    def test_explicit_spark_profile_does_not_change_thor_default(self):
        c=json.loads((Path(__file__).resolve().parents[1]/'config.qwen36-thor.json').read_text())
        hardware={'platform':'aarch64','compute_capability':[12,1],'available_memory_gib':100,'bf16_supported':True}
        with self.assertRaises(RuntimeError): model_profile.check_training_capacity(c,hardware)
        model_profile.check_training_capacity({**c,'hardware_profile':'dgx-spark-sm121'},hardware)
        with self.assertRaises(RuntimeError): model_profile.check_training_capacity({**c,'hardware_profile':'dgx-spark-sm121'},{**hardware,'available_memory_gib':95})

    def test_deadline_has_explicit_kst_and_finite_timestamp(self):
        for value in ('2026-11-01T06:30:00','2026-11-01T06:30:00+00:00'):
            with self.assertRaises(ValueError): dgx.cutoff(value)
        self.assertFalse(deadline_reached({},100))
        self.assertTrue(deadline_reached({'training_deadline_epoch':100},100))
        self.assertFalse(deadline_reached({'training_deadline_epoch':100},99))
        for value in (True,0,float('nan'),float('inf')):
            with self.assertRaises(ValueError): deadline_reached({'training_deadline_epoch':value})

    def test_spark_uma_cache_is_not_dedicated_vram_and_cgroup_still_caps(self):
        result=memory_budget.budget(116,74,121,'aarch64',[12,1],109)
        self.assertEqual(result['available_memory_gib'],109)
        self.assertEqual(result['cuda_free_gib'],74)
        self.assertEqual(memory_budget.budget(116,74,121,'x86_64',[12,1],109)['available_memory_gib'],74)
        self.assertEqual(memory_budget.budget(80,74,121,'aarch64',[12,1],109)['available_memory_gib'],80)

    def test_training_network_and_privilege_boundaries(self):
        args=dgx.docker_args(self.c,'main')
        for expected in ('--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','1000:1000','--memory-swap=110g'):
            self.assertIn(expected,args)
        self.assertNotIn('--privileged',args)
        self.assertNotIn('/var/run/docker.sock',' '.join(args))
        self.assertNotIn('--network=none',dgx.docker_args(self.c,'download'))
        self.assertNotIn('--gpus',dgx.docker_args(self.c,'tokenize'))

    def test_installer_admission_is_cpu_only_with_single_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'control.json';p.write_text(json.dumps(self.c))
            with patch.object(sys,'argv',['dgx','--config',str(p),'--admit-guide']), \
                 patch.object(dgx,'verify_files'),patch.object(dgx.os,'geteuid',return_value=0), \
                 patch.object(dgx.time,'time',return_value=dgx.cutoff(self.c['deadline_kst'])-3600), \
                 patch.object(dgx.subprocess,'run') as execute:
                dgx.main()
            args=execute.call_args.args[0]
            self.assertEqual(args.count(self.c['image']),1)
            self.assertNotIn('--gpus',args)
            self.assertIn('--memory=4g',args)
            self.assertIn('--network=none',args)

    def test_deadline_never_kills_other_named_container(self):
        with patch.object(dgx.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=json.dumps([{'Config':{'Labels':{'capstone.run':'other'}}}]))) as run:
            with self.assertRaises(RuntimeError): dgx.stop_container(self.c)
            self.assertEqual(run.call_count,1)

    def test_unpinned_image_root_identity_and_path_escape_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'c.json'
            p.write_text(json.dumps(self.c)); self.assertEqual(dgx.read_config(p),self.c)
            for change in ({'image':'nvcr.io/nvidia/pytorch:latest'},{'uid':0},{'root':'/etc'},
                           {'files':{'source/../../etc/passwd':'b'*64}},{'run_id':'docker.service'}):
                p.write_text(json.dumps({**self.c,**change}))
                with self.assertRaises(ValueError): dgx.read_config(p)

    def test_past_deadline_does_not_create_service(self):
        with patch.object(dgx,'verify_files'),patch.object(dgx.time,'time',return_value=dgx.cutoff(self.c['deadline_kst'])+1),patch.object(dgx.subprocess,'run') as run:
            with self.assertRaises(ValueError): dgx.apply(self.c,Path('/unused'))
            run.assert_not_called()


if __name__=='__main__': unittest.main()
