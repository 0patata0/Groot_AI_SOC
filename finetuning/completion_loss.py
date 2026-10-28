"""Keep every causal target while omitting vocabulary logits at ignored positions.

For the pinned Qwen3.5-MoE conditional model only. Context tokens still pass
through the entire backbone; only the final vocabulary projection is selected.
"""
import json
from pathlib import Path


def supervised_positions(labels):
    import torch
    if labels.ndim!=2:raise ValueError('Expected batch/sequence labels')
    shifted=torch.nn.functional.pad(labels,(0,1),value=-100)[...,1:].contiguous()
    positions=shifted.ne(-100).any(dim=0).nonzero(as_tuple=True)[0]
    if positions.numel()==0:raise ValueError('No supervised causal targets')
    selected=shifted.index_select(1,positions).contiguous()
    if int(selected.ne(-100).sum())!=int(shifted.ne(-100).sum()):
        raise RuntimeError('Supervised target coverage changed')
    return positions,selected


def completion_loss(model,inputs):
    from transformers.loss.loss_utils import ForCausalLMLoss
    if 'labels' not in inputs:raise ValueError('Supervised labels required')
    if any(k in inputs for k in ('logits_to_keep','shift_labels','output_router_logits')):
        raise ValueError('Conflicting loss/projection options')
    positions,shifted=supervised_positions(inputs['labels'])
    forward={k:v for k,v in inputs.items() if k!='labels'}
    outputs=model(**forward,logits_to_keep=positions)
    loss=ForCausalLMLoss(outputs.logits,labels=None,vocab_size=outputs.logits.shape[-1],shift_labels=shifted)
    counts={'sequence_positions':inputs['labels'].shape[-1],'projected_positions':positions.numel(),
            'batch_size':inputs['labels'].shape[0],'supervised_targets':int(shifted.ne(-100).sum())}
    return loss,outputs,counts


def trainer_class(base):
    class CompletionTrainer(base):
        def __init__(self,*args,**kwargs):
            super().__init__(*args,**kwargs)
            if self.model_accepts_loss_kwargs or self.compute_loss_func is not None or self.label_smoother is not None:
                raise ValueError('Revalidate Qwen loss normalization before changing the Trainer contract')
            if not self.args.prediction_loss_only:
                raise ValueError('Selected logits require prediction_loss_only')

        def compute_loss(self,model,inputs,return_outputs=False,num_items_in_batch=None):
            if num_items_in_batch is not None:raise ValueError('Unexpected token normalization override')
            loss,outputs,counts=completion_loss(model,inputs)
            with (Path(self.args.output_dir)/'completion-loss-selection.jsonl').open('a') as handle:
                handle.write(json.dumps(counts)+'\n')
            return (loss,outputs) if return_outputs else loss
    return CompletionTrainer
