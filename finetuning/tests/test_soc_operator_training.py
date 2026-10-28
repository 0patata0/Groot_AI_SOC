"""Protect new workflow stages from bypassing memory and source boundaries."""
import json
from pathlib import Path
import tempfile,unittest
from unittest.mock import patch
import container_task,thor_container
from prepare_soc_operator import archived_case
class OperatorTrainingTests(unittest.TestCase):
 def test_v5_cpu_stage_cannot_fall_through_to_training(self):
  self.assertNotIn('--gpus',thor_container.command('/tmp/training','soc-v5-tokenize',1000,1000))
  for stage in ('soc-v5-smoke','soc-v5-train'):
   self.assertIn('--gpus',thor_container.command('/tmp/training',stage,1000,1000))
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);source=root/'finetuning';source.mkdir();profile=Path(__file__).resolve().parents[1]/'config.qwen36-soc-v5.json';(source/profile.name).write_bytes(profile.read_bytes())
   with patch.object(container_task,'ROOT',root),patch.object(container_task,'SOURCE',source),patch('container_task.sys.argv',['container_task.py','soc-v5-tokenize']),patch('container_task.signal.signal'),patch('container_task.run') as run,patch('container_task.guarded_process.run',side_effect=AssertionError('Tokenization cannot train')):
    container_task.main()
   args=run.call_args.args[0];self.assertIn('--tokenize-only',args);self.assertNotIn('--train',args);self.assertEqual(args[args.index('--output-dir')+1],'/workspace/soc-v5-tokenization')
 def test_cpu_tokenization_has_no_gpu_and_no_network(self):
  c=thor_container.command('/tmp/training','soc-v3-tokenize',1000,1000)
  self.assertNotIn('--gpus',c);self.assertEqual(c[c.index('--network')+1],'none');self.assertEqual(c[c.index('--memory')+1],'12g')
 def test_training_has_explicit_gpu_memory_limits_and_vmm(self):
  for stage in ('soc-v3-smoke','soc-v3-pilot'):
   c=thor_container.command('/tmp/training',stage,1000,1000);self.assertIn('--gpus',c);self.assertIn('PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True',c);self.assertEqual(c[c.index('--memory')+1],'112g')
 def test_smoke_uses_longest_prefixes_and_guarded_process(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);source=root/'finetuning';source.mkdir();cfg=json.loads((Path(__file__).resolve().parents[1]/'config.qwen36-soc-v3.json').read_text());(source/'config.qwen36-soc-v3.json').write_text(json.dumps(cfg));(root/'base-manifest.json').write_text(json.dumps({'verified':True,'model':cfg['model_name_or_path'],'revision':cfg['revision']}))
   with patch.object(container_task,'ROOT',root),patch.object(container_task,'SOURCE',source),patch('container_task.sys.argv',['container_task.py','soc-v3-smoke']),patch('container_task.signal.signal'),patch('container_task.guarded_process.run') as run:
    container_task.main()
   c=json.loads((source/'config.soc-v3.run.local.json').read_text());self.assertTrue(c['smoke_longest_prefixes']);self.assertTrue(c['assistant_only_logits']);self.assertEqual(c['gradient_accumulation_steps'],1);self.assertTrue(c['base_artifact_manifest']);args=run.call_args.args[0];self.assertEqual(args[args.index('--max-steps')+1],'2');self.assertEqual(args[args.index('--output-dir')+1],'/workspace/outputs/soc-v3-smoke')
 def test_v4_keeps_cpu_tokenization_and_guarded_longest_smoke_separate(self):
  cpu=thor_container.command('/tmp/training','soc-v4-tokenize',1000,1000);self.assertNotIn('--gpus',cpu);self.assertEqual(cpu[cpu.index('--network')+1],'none')
  for stage in ('soc-v4-smoke','soc-v4-pilot'):
   cmd=thor_container.command('/tmp/training',stage,1000,1000);self.assertIn('--gpus',cmd);self.assertIn('PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True',cmd)
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);source=root/'finetuning';source.mkdir();cfg=json.loads((Path(__file__).resolve().parents[1]/'config.qwen36-soc-v4.json').read_text());(source/'config.qwen36-soc-v4.json').write_text(json.dumps(cfg));(root/'base-manifest.json').write_text(json.dumps({'verified':True,'model':cfg['model_name_or_path'],'revision':cfg['revision']}))
   with patch.object(container_task,'ROOT',root),patch.object(container_task,'SOURCE',source),patch('container_task.sys.argv',['container_task.py','soc-v4-smoke']),patch('container_task.signal.signal'),patch('container_task.guarded_process.run') as run:
    container_task.main()
   config=json.loads((source/'config.soc-v4.run.local.json').read_text());self.assertEqual(config['data_dir'],'data-soc-operator-v4-r1');self.assertTrue(config['record_prefix_usage']);self.assertTrue(config['smoke_longest_prefixes']);args=run.call_args.args[0];self.assertEqual(args[args.index('--max-steps')+1],'2');self.assertEqual(args[args.index('--output-dir')+1],'/workspace/outputs/soc-v4-smoke')
 def test_full_conversation_stage_uses_all_examples_and_guarded_smoke(self):
  self.assertNotIn('--gpus',thor_container.command('/tmp/training','soc-v4-full-tokenize',1000,1000))
  self.assertIn('--gpus',thor_container.command('/tmp/training','soc-v4-full-train',1000,1000))
  profile=Path(__file__).resolve().parents[1]/'config.qwen36-soc-v4-full.json';cfg=json.loads(profile.read_text());self.assertEqual(cfg['max_steps']*cfg['gradient_accumulation_steps'],332);self.assertEqual(cfg['loss_mode'],'all_assistant_turns')
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);source=root/'finetuning';source.mkdir();(source/profile.name).write_bytes(profile.read_bytes());(root/'base-manifest.json').write_text(json.dumps({'verified':True,'model':cfg['model_name_or_path'],'revision':cfg['revision']}))
   with patch.object(container_task,'ROOT',root),patch.object(container_task,'SOURCE',source),patch('container_task.sys.argv',['container_task.py','soc-v4-full-smoke']),patch('container_task.signal.signal'),patch('container_task.guarded_process.run') as run:
    container_task.main()
   local=json.loads((source/'config.soc-v4-full.run.local.json').read_text());self.assertEqual(local['loss_mode'],'all_assistant_turns');self.assertTrue(local['smoke_longest_prefixes']);self.assertEqual(local['gradient_accumulation_steps'],1);args=run.call_args.args[0];self.assertEqual(args[args.index('--max-train-samples')+1],'2');self.assertEqual(args[args.index('--output-dir')+1],'/workspace/outputs/soc-v4-full-smoke')
 def test_archive_keeps_original_fields_and_does_not_label_normal_benign(self):
  def row(i):return {'key':str(i),'projection':{'source_id':str(i),'timestamp_kst':'2022-01-17T18:07:24+09:00','agent_id':'18','rule_id':'9701','level':3,'description':'Dovecot Authentication Success.','phase_window':'normal'},'lineage':{'source_line':i}}
  case=archived_case('train','fox',0,row(1),row(2));text=case['messages'][-1]['content'];self.assertIn('2022-01-17',text);self.assertIn('normal도 정상 판정을 뜻하지',text);self.assertIn('미확인',text);self.assertEqual(case['checks']['expected_calls'],[])
if __name__=='__main__':unittest.main()
