"""CPU-only checkpoint integrity and installed Trainer/PEFT continuation test."""
import json
from pathlib import Path


def check(config, output):
    import torch
    from safetensors.torch import load_file
    from transformers import GPT2Config, GPT2LMHeadModel, Trainer, TrainingArguments, TrainerCallback, set_seed
    from peft import get_peft_model, LoraConfig
    from train import check_data
    from resume_training import validate_resume,mark_completed,verified_completion
    torch.set_num_threads(2)
    receipt=validate_resume(config,check_data(config))
    if not receipt:raise ValueError('Explicit resume receipt required')
    weights=load_file(str(Path(config['resume_from_checkpoint'])/'adapter_model.safetensors'),device='cpu')
    expected=2*sum(config['expected_lora_modules'].values())
    if len(weights)!=expected or not all(torch.isfinite(t).all().item() for t in weights.values()):
        raise ValueError('Nonfinite or incomplete LoRA weights')
    del weights
    output=Path(output);output.mkdir(exist_ok=False)
    examples=[{'input_ids':torch.tensor([1,i+2,3,4]),'labels':torch.tensor([1,i+2,3,4])} for i in range(8)]
    def model():
        set_seed(42)
        base=GPT2LMHeadModel(GPT2Config(vocab_size=16,n_positions=8,n_embd=16,n_layer=1,n_head=2,
                                     resid_pdrop=0.0,embd_pdrop=0.0,attn_pdrop=0.0))
        return get_peft_model(base,LoraConfig(task_type='CAUSAL_LM',r=2,lora_alpha=4,target_modules=['c_attn']))
    class Stop(TrainerCallback):
        def on_step_end(self,args,state,control,**kw):
            if state.global_step==2:control.should_training_stop=True;control.should_save=True
            return control
    class Mark(TrainerCallback):
        def on_save(self,args,state,control,**kw):
            mark_completed(Path(args.output_dir),Path(args.output_dir)/('checkpoint-'+str(state.global_step)))
            return control
    def trainer(name,callbacks=None):
        args=TrainingArguments(output_dir=str(output/name),use_cpu=True,max_steps=4,
            per_device_train_batch_size=1,gradient_accumulation_steps=2,
            learning_rate=1e-3,save_steps=2,save_total_limit=2,logging_steps=1,
            report_to=[],disable_tqdm=True,seed=42,data_seed=42,dataloader_pin_memory=False,
            optim='adamw_torch',lr_scheduler_type='cosine')
        directory=output/name;directory.mkdir()
        (directory/'run_manifest.json').write_text(json.dumps({'config':{},'data':{},'base_artifact_manifest':{}}))
        return Trainer(model=model(),args=args,train_dataset=examples,callbacks=[Mark(),*(callbacks or [])])
    full=trainer('full');full.train()
    split=trainer('split',[Stop()]);split.train()
    resumed=trainer('resumed');resumed.train(resume_from_checkpoint=str(output/'split/checkpoint-2'))
    if resumed.state.global_step!=4:raise RuntimeError('CPU continuation step mismatch')
    full_weights=full.model.state_dict();resumed_weights=resumed.model.state_dict()
    if full_weights.keys()!=resumed_weights.keys() or not all(torch.equal(v,resumed_weights[k]) for k,v in full_weights.items()):
        raise RuntimeError('CPU continuation differs from uninterrupted training')
    if verified_completion(output/'split',output/'split/checkpoint-2')['step']!=2:
        raise RuntimeError('Post-save completion marker verification failed')
    return {'checkpoint_step':receipt['step'],'adapter_tensors_finite':expected,
            'cpu_trainer_peft_resume':'bitwise_equal_to_uninterrupted_4_steps',
            'post_save_checkpoint_completion':'verified_on_installed_trainer',
            'scope':'Small CPU integration; full 35B resumption still requires actual GPU progress'}
