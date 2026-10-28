"""Protect real training launch boundaries and artifact integrity without a GPU."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import memory_budget
import model_profile
import thor_container
import train
from download_model import verify_artifact


class MemoryTests(unittest.TestCase):
    def test_thor_reclaimable_cache_counts_but_not_on_discrete_gpu(self):
        self.assertEqual(memory_budget.budget(100, 20, 123, 'aarch64', [11,0])['available_memory_gib'],100)
        self.assertEqual(memory_budget.budget(100, 20, 123, 'x86_64', [9,0])['available_memory_gib'],20)
        self.assertEqual(memory_budget.budget(100, 20, 123, 'aarch64', [12,1])['available_memory_gib'],20)

    def test_cgroup_cannot_be_bypassed_by_large_host_memory(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'memory.max').write_text(str(112*2**30))
            (root/'memory.current').write_text(str(20*2**30))
            headroom=memory_budget.cgroup_headroom(root)
            result=memory_budget.budget(105,20,123,'aarch64',[11,0],headroom)
            self.assertEqual(result['available_memory_gib'],92)
            config=json.loads((train.ROOT/'config.qwen36-thor.json').read_text())
            with self.assertRaisesRegex(RuntimeError,'Insufficient'):
                model_profile.check_training_capacity(config,{**result,'bf16_supported':True,'platform':'aarch64','compute_capability':[11,0]})
            (root/'memory.max').write_text('max')
            self.assertIsNone(memory_budget.cgroup_headroom(root))

    def test_exhausted_cgroup_is_zero_not_negative(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'memory.max').write_text('100');(root/'memory.current').write_text('200')
            self.assertEqual(memory_budget.cgroup_headroom(root),0)


class ArtifactTests(unittest.TestCase):
    def test_sha256_and_git_blob_hashes_then_same_length_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);payload=b'abcdef';(root/'artifact').write_bytes(payload)
            for large in (True,False):
                item={'path':'artifact','bytes':len(payload),'sha256':hashlib.sha256(payload).hexdigest() if large else None,
                      'git_blob':hashlib.sha1(b'blob 6\0'+payload).hexdigest()}
                verify_artifact(root,item)
                (root/'artifact').write_bytes(b'abcdeg')
                with self.assertRaisesRegex(ValueError,'checksum'):verify_artifact(root,item)
                (root/'artifact').write_bytes(payload)

    def test_traversal_and_symlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'link').symlink_to('/etc/passwd')
            for name in ('../outside','/etc/passwd','link'):
                with self.assertRaisesRegex(ValueError,'Unsafe'):verify_artifact(root,{'path':name})


class LaunchTests(unittest.TestCase):
    def test_final_evaluation_reuses_only_the_current_step(self):
        trainer=SimpleNamespace(state=SimpleNamespace(global_step=2,log_history=[
            {'step':2,'eval_loss':0.25,'eval_runtime':5,'epoch':1}, {'step':2,'train_loss':0.1}]),evaluate=Mock(return_value={'eval_loss':0.3}))
        self.assertEqual(train.final_eval_metrics(trainer)['eval_loss'],0.25)
        trainer.evaluate.assert_not_called()
        trainer.state.global_step=3
        self.assertEqual(train.final_eval_metrics(trainer)['eval_loss'],0.3)
        trainer.evaluate.assert_called_once()

    def test_nonfinite_final_evaluation_cannot_be_reused(self):
        trainer=SimpleNamespace(state=SimpleNamespace(global_step=2,log_history=[{'step':2,'eval_loss':float('nan')}]))
        with self.assertRaisesRegex(RuntimeError,'Nonfinite'):train.final_eval_metrics(trainer)

    def test_thor_loader_avoids_vendor_sm90_only_grouped_mm(self):
        config=json.loads((train.ROOT/'config.qwen36-thor.json').read_text())
        self.assertEqual(model_profile.loading_kwargs(config),{'experts_implementation':'eager'})
        with self.assertRaisesRegex(ValueError,'grouped_mm'):
            model_profile.loading_kwargs({**config,'experts_implementation':'grouped_mm'})
        self.assertEqual(model_profile.loading_kwargs(json.loads((train.ROOT/'config.json').read_text())),{})

    def test_offline_training_has_limits_no_ports_and_no_privilege(self):
        cmd=thor_container.command('/tmp/training','train',1000,1000)
        for flag,value in (('--network','none'),('--memory','112g'),('--memory-swap','112g'),
                           ('--cap-drop','ALL'),('--security-opt','no-new-privileges'),('--pull=never',None)):
            self.assertIn(flag,cmd)
            if value:self.assertEqual(cmd[cmd.index(flag)+1],value)
        self.assertNotIn('--privileged',cmd);self.assertNotIn('-p',cmd)
        self.assertIn('HF_HUB_OFFLINE=1',cmd)
        self.assertEqual(cmd.count('--mount'),1)

    def test_tokenizer_and_download_have_no_gpu_access(self):
        for stage in ('download','tokenize','soc-tokenize','soc-v2-tokenize'):
            cmd=thor_container.command('/tmp/training',stage,1000,1000)
            self.assertNotIn('--gpus',cmd)
        with self.assertRaises(ValueError):thor_container.command('/tmp/training','shell',1000,1000)

    def test_v2_training_has_the_same_limits_and_distinct_stage(self):
        for stage in ('soc-v2-smoke','soc-v2-pilot'):
            cmd=thor_container.command('/tmp/training',stage,1000,1000)
            self.assertIn('--gpus',cmd);self.assertEqual(cmd[cmd.index('--network')+1],'none')
            self.assertEqual(cmd[cmd.index('--memory')+1],'112g')
            self.assertIn('HF_DEACTIVATE_ASYNC_LOAD=1',cmd)
            self.assertEqual(cmd[-1],stage)

    def test_soc_full_training_keeps_the_same_offline_boundary(self):
        cmd=thor_container.command('/tmp/training','soc-train',1000,1000)
        self.assertEqual(cmd[cmd.index('--network')+1],'none')
        self.assertEqual(cmd[cmd.index('--memory')+1],'112g')
        self.assertIn('HF_DEACTIVATE_ASYNC_LOAD=1',cmd)
        self.assertNotIn('--privileged',cmd)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'finetuning').mkdir()
            config={'model_name_or_path':'fixture','revision':'a'*40}
            (root/'finetuning/config.qwen36-thor.json').write_text(json.dumps(config))
            for stage in ('prepare','download','tokenize','soc-tokenize'):
                (root/f'{stage}-status.json').write_text('{"status":"completed"}')
            (root/'soc-pilot-status.json').write_text('{"status":"failed"}')
            (root/'base-manifest.json').write_text(json.dumps({'model':'fixture','revision':'a'*40,'verified':True}))
            with patch.object(sys,'argv',['thor_container','soc-train','--root',str(root)]), \
                 patch('thor_container.platform.system',return_value='Linux'), \
                 patch('thor_container.platform.machine',return_value='aarch64'), \
                 patch('thor_container.subprocess.run',return_value=SimpleNamespace(returncode=1,stdout='')), \
                 patch('thor_container.subprocess.check_output') as docker:
                with self.assertRaisesRegex(SystemExit,'SOC pilot'):thor_container.main()
                docker.assert_not_called()

    def test_main_training_requires_completed_smoke_before_docker_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'finetuning').mkdir()
            config={'model_name_or_path':'fixture','revision':'a'*40}
            (root/'finetuning/config.qwen36-thor.json').write_text(json.dumps(config))
            for stage in ('prepare','download','tokenize'):
                (root/f'{stage}-status.json').write_text('{"status":"completed"}')
            (root/'smoke-status.json').write_text('{"status":"failed"}')
            (root/'base-manifest.json').write_text(json.dumps({'model':'fixture','revision':'a'*40,'verified':True}))
            with patch.object(sys,'argv',['thor_container','train','--root',str(root)]), \
                 patch('thor_container.platform.system',return_value='Linux'), \
                 patch('thor_container.platform.machine',return_value='aarch64'), \
                 patch('thor_container.subprocess.run',return_value=SimpleNamespace(returncode=1,stdout='')), \
                 patch('thor_container.subprocess.check_output') as docker:
                with self.assertRaisesRegex(SystemExit,'smoke'):thor_container.main()
                docker.assert_not_called()

    def test_tokenize_action_does_not_enter_cuda_preflight_or_training(self):
        with patch.object(sys,'argv',['train','--tokenize-only']), \
             patch('train.check_data',return_value={}),patch('train.tokenize_only') as tokenize, \
             patch('train.preflight',side_effect=AssertionError('CUDA forbidden')), \
             patch('train.run_training',side_effect=AssertionError('training forbidden')):
            self.assertEqual(train.main(),0)
            tokenize.assert_called_once()


if __name__=='__main__':unittest.main()
