"""CPU-only installed Trainer/PEFT integration for quality checkpoints and resume.

Tiny synthetic tensors test execution semantics, not SOC accuracy or 35B GPU
capacity. A controlled evaluation-loss sequence makes early-stop assertions exact.
"""
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))


def check(output):
    import torch
    from safetensors.torch import load_file
    from transformers import GPT2Config, GPT2LMHeadModel, Trainer, TrainingArguments, TrainerCallback, set_seed
    from peft import get_peft_model, LoraConfig
    from resume_training import mark_completed, verified_completion
    from training_quality import callback_class, verify_checkpoint_state
    torch.set_num_threads(2)
    output = Path(output); output.mkdir(exist_ok=False)
    examples = [{'input_ids': torch.tensor([1, i+2, 3, 4]),
                 'labels': torch.tensor([1, i+2, 3, 4])} for i in range(8)]
    config = {'quality_control': {'patience': 2, 'min_delta': 0.01},
              'eval_steps': 2, 'save_steps': 1, 'final_eval_only': False}

    def model():
        set_seed(42)
        base = GPT2LMHeadModel(GPT2Config(vocab_size=16, n_positions=8, n_embd=16,
            n_layer=1, n_head=2, resid_pdrop=0.0, embd_pdrop=0.0, attn_pdrop=0.0))
        return get_peft_model(base, LoraConfig(task_type='CAUSAL_LM', r=2, lora_alpha=4, target_modules=['c_attn']))

    class ControlledEvaluation(Trainer):
        def prediction_step(self, model, inputs, prediction_loss_only, ignore_keys=None):
            actual = super().prediction_step(model, inputs, prediction_loss_only, ignore_keys)
            expected = {2: 1.0, 4: 0.8, 6: 0.81, 8: 0.82}[self.state.global_step]
            return torch.tensor(expected), actual[1], actual[2]

    class Mark(TrainerCallback):
        def on_save(self, args, state, control, **kwargs):
            mark_completed(Path(args.output_dir), Path(args.output_dir)/f'checkpoint-{state.global_step}')
            return control

    class Interrupt(TrainerCallback):
        def on_step_end(self, args, state, control, **kwargs):
            if state.global_step == 5:
                control.should_training_stop = True; control.should_save = True
            return control

    def run(name, resume=None, interrupt=False):
        directory = output/name; directory.mkdir()
        current = {**config, 'output_dir': str(directory)}
        if resume: current['resume_from_checkpoint'] = str(resume)
        (directory/'run_manifest.json').write_text(json.dumps({'config': current, 'data': {}, 'base_artifact_manifest': {}}))
        quality = callback_class(TrainerCallback)(current, directory)
        args = TrainingArguments(output_dir=str(directory), use_cpu=True, max_steps=12,
            per_device_train_batch_size=1, per_device_eval_batch_size=1,
            learning_rate=1e-3, save_steps=1, save_total_limit=2,
            eval_strategy='steps', eval_steps=2, logging_steps=1,
            report_to=[], disable_tqdm=True, seed=42, data_seed=42,
            dataloader_pin_memory=False, optim='adamw_torch', lr_scheduler_type='cosine')
        trainer = ControlledEvaluation(model=model(), args=args, train_dataset=examples,
            eval_dataset=examples[:2], callbacks=[quality, Mark(), *([Interrupt()] if interrupt else [])])
        trainer.train(**({'resume_from_checkpoint': str(resume)} if resume else {}))
        quality.finish()
        return trainer, quality

    full, fq = run('full')
    split, _ = run('split', interrupt=True)
    if split.state.global_step != 5: raise RuntimeError('Interruption checkpoint mismatch')
    checkpoint = output/'split/checkpoint-5'
    receipt = verified_completion(output/'split', checkpoint)
    if receipt['quality_control']['best_step'] != 4: raise RuntimeError('Best state not bound into recovery receipt')
    resumed, rq = run('resumed', resume=checkpoint)
    if full.state.global_step != 8 or resumed.state.global_step != 8:
        raise RuntimeError('Patience did not stop at the same optimizer step')
    a, b = full.model.state_dict(), resumed.model.state_dict()
    if a.keys() != b.keys() or not all(torch.equal(v, b[k]) for k, v in a.items()):
        raise RuntimeError('Quality-enabled resume changed trained weights')
    best_files = [output/name/q.tracker.state['best_directory']/'adapter_model.safetensors'
                  for name, q in (('full', fq), ('resumed', rq))]
    a, b = (load_file(str(p), device='cpu') for p in best_files)
    if not all(torch.isfinite(v).all().item() and torch.equal(v, b[k]) for k, v in a.items()):
        raise RuntimeError('Retained best adapter differs after resume')
    verify_checkpoint_state(output/'resumed', output/'resumed/checkpoint-8', config['quality_control'])
    if (output/'full/checkpoint-4').exists(): raise RuntimeError('Test did not exercise checkpoint rotation')
    return {'cpu_trainer_peft_quality': 'passed', 'early_stop_step': 8,
        'planned_steps': 12, 'best_step': 4, 'best_preserved_after_checkpoint_rotation': True,
        'resume_last_and_best_weights': 'bitwise_equal_to_uninterrupted',
        'best_state_bound_to_checkpoint_receipt': True,
        'scope': 'Tiny CPU integration with controlled losses; not SOC quality or full 35B GPU evidence.'}


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('--output', type=Path, required=True)
    print(json.dumps(check(p.parse_args().output), indent=2))
