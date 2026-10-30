"""CPU-only loss normalization check; tiny analytic logits, no model weights.

Confirms the pinned completion-loss code against the installed Transformers
implementation. This is not a full-model gradient, Trainer epoch, or quality test.
"""
import argparse
from datetime import datetime, timezone, timedelta
import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
from types import SimpleNamespace


def require(ok, message):
    if not ok: raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check(frozen_root, log_directory):
    spec = json.loads((frozen_root/'V5_TRAINING_INPUTS.json').read_text())
    path = frozen_root/'completion_loss.py'
    require(sha(path.read_bytes()) == spec['source_sha256']['completion_loss.py'], 'Frozen loss code differs')
    profile_raw = (frozen_root/spec['profile']).read_bytes()
    require(sha(profile_raw) == spec['profile_sha256'], 'Frozen profile differs')
    config = json.loads(profile_raw)
    require(config['assistant_only_logits'] is True and config['per_device_train_batch_size'] == 1
            and config['loss_mode'] == 'all_assistant_turns', 'Different loss/batch configuration')
    os.environ.update(CUDA_VISIBLE_DEVICES='', NVIDIA_VISIBLE_DEVICES='void')
    import torch
    import transformers
    from transformers.loss.loss_utils import ForCausalLMLoss, fixed_cross_entropy
    require(not torch.cuda.is_initialized(), 'Unexpected CUDA initialization')
    module_spec = importlib.util.spec_from_file_location('pinned_completion_loss', path)
    loss_module = importlib.util.module_from_spec(module_spec);module_spec.loader.exec_module(loss_module)
    parameter = torch.tensor(0.7, device='cpu', requires_grad=True)

    class Tiny:
        def __call__(self, input_ids, logits_to_keep):
            base = torch.stack([parameter, parameter*0, parameter*0]).reshape(1,1,3)
            logits = base.expand(input_ids.shape[0], input_ids.shape[1], 3).index_select(1,logits_to_keep)
            return SimpleNamespace(logits=logits)

    examples = {'short': {'input_ids': torch.zeros((1,2),dtype=torch.long),
                          'labels': torch.tensor([[-100,0]])},
                'long': {'input_ids': torch.zeros((1,11),dtype=torch.long),
                         'labels': torch.tensor([[-100]+[1]*10])}}
    measurements, losses, gradients = {}, {}, {}
    for name, inputs in examples.items():
        loss, outputs, counts = loss_module.completion_loss(Tiny(),inputs)
        target = inputs['labels'][:,1:].reshape(-1)
        expected = torch.nn.functional.cross_entropy(outputs.logits.reshape(-1,3),target,reduction='mean')
        require(torch.allclose(loss,expected), 'Loss is not per-call mean')
        gradient, = torch.autograd.grad(loss,parameter,retain_graph=True)
        losses[name] = loss;gradients[name] = gradient
        measurements[name] = {**counts, 'loss': float(loss.detach()), 'scalar_gradient': float(gradient)}
    macro = (losses['short']+losses['long'])/2
    micro = (losses['short']+10*losses['long'])/11
    macro_g, = torch.autograd.grad(macro,parameter,retain_graph=True)
    micro_g, = torch.autograd.grad(micro,parameter)
    require(torch.allclose(macro_g,(gradients['short']+gradients['long'])/2)
            and not torch.allclose(macro_g,micro_g), 'Row and token averages unexpectedly equated')

    class Base:
        def __init__(self):
            self.model_accepts_loss_kwargs = False;self.compute_loss_func = None;self.label_smoother = None
            self.args = SimpleNamespace(prediction_loss_only=True,output_dir=str(log_directory))

    trainer = loss_module.trainer_class(Base)()
    refused = False
    try: trainer.compute_loss(Tiny(),examples['short'],num_items_in_batch=11)
    except ValueError: refused = True
    require(refused and not torch.cuda.is_initialized(), 'Loss override/CUDA boundary violated')
    return {'at_kst': datetime.now(timezone(timedelta(hours=9))).isoformat(),
            'torch': torch.__version__, 'transformers': transformers.__version__,
            'profile_sha256': sha(profile_raw), 'completion_loss_sha256': sha(path.read_bytes()),
            'installed_source_sha256': {f.__name__:sha(inspect.getsource(f).encode())
                                        for f in (ForCausalLMLoss,fixed_cross_entropy)},
            'tiny_examples': measurements, 'equal_example_mean_gradient': float(macro_g),
            'global_token_mean_gradient': float(micro_g), 'external_token_denominator_refused': refused,
            'checks_passed': 5, 'cuda_initialized': False, 'model_weights_loaded': False,
            'training_started': False,
            'interpretation': 'With batch1, the frozen helper averages supervised tokens within each call. Equal-call averaging differs from pooling all target tokens. Full Trainer accumulation/last-batch behavior and real-model gradients were not measured.'}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--frozen-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();require(not a.output.exists(),'Output already exists')
    result=check(a.frozen_root,a.output.parent)
    with a.output.open('x') as stream:stream.write(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(result))


if __name__=='__main__':main()
