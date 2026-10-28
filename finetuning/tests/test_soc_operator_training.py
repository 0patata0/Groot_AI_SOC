"""Protect new workflow stages from bypassing memory and source boundaries."""
import json
from pathlib import Path
import tempfile,unittest
from unittest.mock import patch
import container_task,thor_container
from prepare_soc_operator import archived_case
class OperatorTrainingTests(unittest.TestCase):
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
 def test_archive_keeps_original_fields_and_does_not_label_normal_benign(self):
  def row(i):return {'key':str(i),'projection':{'source_id':str(i),'timestamp_kst':'2022-01-17T18:07:24+09:00','agent_id':'18','rule_id':'9701','level':3,'description':'Dovecot Authentication Success.','phase_window':'normal'},'lineage':{'source_line':i}}
  case=archived_case('train','fox',0,row(1),row(2));text=case['messages'][-1]['content'];self.assertIn('2022-01-17',text);self.assertIn('normal도 정상 판정을 뜻하지',text);self.assertIn('미확인',text);self.assertEqual(case['checks']['expected_calls'],[])
if __name__=='__main__':unittest.main()
