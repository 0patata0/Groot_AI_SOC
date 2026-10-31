"""Tiny random 40-layer architecture probe, not full-model training/quality."""
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from train import configure_determinism, kst_now
import model_profile


def main():
    import torch
    from transformers import AutoConfig
    from peft import LoraConfig,get_peft_model
    recipe=json.loads(Path('/workspace/profiles/main.json').read_text())
    configure_determinism(recipe,torch)
    config=AutoConfig.from_pretrained('/workspace/base',trust_remote_code=False,local_files_only=True)
    text=config.text_config
    for key,value in {'hidden_size':64,'intermediate_size':128,'num_attention_heads':4,
        'num_key_value_heads':2,'head_dim':16,'vocab_size':128,'num_experts':4,'num_experts_per_tok':2,
        'moe_intermediate_size':32,'shared_expert_intermediate_size':32,
        'linear_num_key_heads':2,'linear_num_value_heads':4,'linear_key_head_dim':16,
        'linear_value_head_dim':16,'max_position_embeddings':256,'pad_token_id':0,
        'bos_token_id':1,'eos_token_id':2,'use_cache':False}.items():setattr(text,key,value)
    text.rope_parameters={**text.rope_parameters,'partial_rotary_factor':1.0,'mrope_section':[2,3,3]}
    for key,value in {'depth':1,'hidden_size':64,'intermediate_size':128,'num_heads':4,
                      'out_hidden_size':64,'deepstack_visual_indexes':[]}.items():setattr(config.vision_config,key,value)
    for c in (config,text):
        c._experts_implementation='eager';c._attn_implementation='sdpa';c.use_cache=False
    model=model_profile.model_class(recipe)(config).to(device='cuda',dtype=torch.bfloat16)
    coverage=model_profile.check_lora_targets(recipe,model.named_modules())
    model.requires_grad_(False);model.enable_input_require_grads()
    model=get_peft_model(model,LoraConfig(task_type='CAUSAL_LM',r=16,lora_alpha=32,
        lora_dropout=0.0,target_modules=recipe['target_modules'],bias='none'))
    model_profile.check_trainable_scope(recipe,model.named_parameters())
    model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={'use_reentrant':False})
    optimizer=torch.optim.AdamW([p for p in model.parameters()if p.requires_grad],lr=5e-7)
    losses=[]
    for _ in range(2):
        optimizer.zero_grad();ids=torch.randint(3,128,(1,8),device='cuda')
        loss=model(input_ids=ids,attention_mask=torch.ones_like(ids),labels=ids).loss
        if not torch.isfinite(loss):raise RuntimeError('Nonfinite tiny loss')
        loss.backward()
        gradients=[p.grad for p in model.parameters()if p.requires_grad]
        if len(gradients)!=380 or any(g is None or not torch.isfinite(g).all()for g in gradients):
            raise RuntimeError('Incomplete/nonfinite LoRA gradients')
        optimizer.step();torch.cuda.synchronize();losses.append(float(loss))
    result={'at_kst':kst_now(),'status':'passed','optimizer_steps':2,
        'target_counts':coverage['counts'],'finite_adapter_gradients':len(gradients),'losses':losses,
        'compute_capability':list(torch.cuda.get_device_capability()),'full_35b_training_verified':False}
    Path('/workspace/tiny-architecture.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))


if __name__=='__main__':main()
