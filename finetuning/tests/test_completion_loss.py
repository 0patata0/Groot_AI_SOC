"""Real loss/gradient equivalence; run in the existing no-GPU Torch image."""
import importlib.util
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
import tempfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

HAS_TORCH=importlib.util.find_spec('torch') is not None and importlib.util.find_spec('transformers') is not None


@unittest.skipUnless(HAS_TORCH,'Run in the existing Torch/Transformers container')
class CompletionLossTests(unittest.TestCase):
    def test_loss_and_all_parameter_gradients_preserve_masks_padding_and_batch_union(self):
        import torch
        from transformers.loss.loss_utils import ForCausalLMLoss
        from completion_loss import completion_loss
        class Toy(torch.nn.Module):
            def __init__(self):
                super().__init__();self.embedding=torch.nn.Embedding(19,8);self.head=torch.nn.Linear(8,19,bias=False)
            def forward(self,input_ids,logits_to_keep=None):
                hidden=self.embedding(input_ids).cumsum(dim=1)
                if logits_to_keep is not None:hidden=hidden[:,logits_to_keep,:]
                return SimpleNamespace(logits=self.head(hidden))
        for labels in ([[-100,-100,2,3,-100,5]], [[-100,1,-100,3,-100,-100],[-100,-100,2,-100,4,5]], [[-100,-100,-100,-100,-100,5]]):
            torch.manual_seed(7);model=Toy();labels=torch.tensor(labels);ids=torch.arange(labels.numel()).reshape(labels.shape)%19
            full=model(ids).logits;expected=ForCausalLMLoss(full,labels,19);expected.backward();grads=[p.grad.clone() for p in model.parameters()];model.zero_grad()
            actual,output,counts=completion_loss(model,{'input_ids':ids,'labels':labels});actual.backward()
            torch.testing.assert_close(actual,expected,rtol=1e-6,atol=1e-7)
            for p,g in zip(model.parameters(),grads):torch.testing.assert_close(p.grad,g,rtol=1e-6,atol=1e-7)
            self.assertEqual(counts['supervised_targets'],int(labels[:,1:].ne(-100).sum()))
            self.assertLess(output.logits.shape[1],labels.shape[1])

    def test_empty_targets_and_external_projection_cannot_silently_change_loss(self):
        import torch
        from completion_loss import completion_loss,supervised_positions
        with self.assertRaisesRegex(ValueError,'No supervised'):supervised_positions(torch.tensor([[4,-100,-100]]))
        with self.assertRaisesRegex(ValueError,'Conflicting'):
            completion_loss(object(),{'labels':torch.tensor([[-100,2]]),'logits_to_keep':torch.tensor([0])})

    def test_real_trainer_keeps_gradient_accumulation_and_loss_only_evaluation(self):
        import json,torch
        from transformers import Trainer,TrainingArguments
        from transformers.modeling_outputs import CausalLMOutput
        from completion_loss import trainer_class
        class Toy(torch.nn.Module):
            accepts_loss_kwargs=False
            def __init__(self):
                super().__init__();self.embedding=torch.nn.Embedding(19,8);self.head=torch.nn.Linear(8,19,bias=False)
            def forward(self,input_ids,logits_to_keep=None):
                hidden=self.embedding(input_ids).cumsum(dim=1)
                return CausalLMOutput(logits=self.head(hidden[:,logits_to_keep,:]))
        data=[{'input_ids':[1,2,3,4],'labels':[-100,-100,3,4]}]*2
        with tempfile.TemporaryDirectory() as d:
            args=TrainingArguments(output_dir=d,use_cpu=True,prediction_loss_only=True,report_to=[],
                remove_unused_columns=False,label_names=['labels'],per_device_train_batch_size=1,per_device_eval_batch_size=1,
                gradient_accumulation_steps=2,max_steps=1,save_strategy='no',logging_strategy='no',
                disable_tqdm=True,dataloader_pin_memory=False)
            trainer=trainer_class(Trainer)(model=Toy(),args=args,train_dataset=data,eval_dataset=data)
            result=trainer.train();metrics=trainer.evaluate()
            self.assertEqual(result.global_step,1);self.assertTrue(torch.isfinite(torch.tensor(metrics['eval_loss'])))
            rows=[json.loads(l) for l in (Path(d)/'completion-loss-selection.jsonl').read_text().splitlines()]
            self.assertEqual(len(rows),4)
            self.assertTrue(all(r['supervised_targets']==2 and r['projected_positions']==2 for r in rows))
