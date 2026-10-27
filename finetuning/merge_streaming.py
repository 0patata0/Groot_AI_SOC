"""Merge vanilla BF16 SOC LoRA on CPU, preserving every original checkpoint key.

Unlike rebuilding a model from its Transformers class, this keeps unused MTP
and vision tensors and all verified base metadata. No GPU or network is used.
"""
import argparse
import gc
import hashlib
import importlib.metadata as md
import json
import math
from pathlib import Path
import re
import shutil
import signal
from datetime import datetime
from zoneinfo import ZoneInfo

from download_model import verify_artifact
from merge_adapter import inspect_adapter


def sha256(path):
    result=hashlib.sha256()
    with Path(path).open('rb') as handle:
        for chunk in iter(lambda:handle.read(8*1024*1024),b''):result.update(chunk)
    return result.hexdigest()


def plan_lora(keys,index,peft,config):
    if config.get('model_kind')!='qwen3_5_moe' or config.get('quantization')!='none':
        raise ValueError('Only the reviewed unquantized Qwen SOC profile is supported')
    if peft.get('peft_type')!='LORA' or peft.get('bias')!='none':
        raise ValueError('Vanilla bias-free LoRA required')
    for name in ('use_dora','use_rslora','use_qalora','lora_bias','fan_in_fan_out',
                 'rank_pattern','alpha_pattern','modules_to_save','target_parameters',
                 'layer_replication','alora_invocation_tokens','trainable_token_indices',
                 'exclude_modules'):
        if peft.get(name):raise ValueError('Unsupported LoRA feature: '+name)
    rank=peft['r'];alpha=peft['lora_alpha']
    if not isinstance(rank,int) or isinstance(rank,bool) or rank<1 or not math.isfinite(alpha) or alpha<=0:
        raise ValueError('Invalid LoRA rank/scaling')
    target=peft['target_modules']
    if not isinstance(target,str) or target!=config['target_modules']:
        raise ValueError('Target module policy mismatch')
    pairs={}
    for key in keys:
        match=re.fullmatch(r'base_model\.model\.(.+)\.lora_([AB])\.weight',key)
        if not match or not re.fullmatch(target,match[1]):raise ValueError('Unexpected adapter key: '+key)
        base=match[1]+'.weight'
        if base not in index:raise ValueError('Adapter target absent from base: '+base)
        pair=pairs.setdefault(base,{})
        if match[2] in pair:raise ValueError('Duplicate adapter key')
        pair[match[2]]=key
    expected=sum(config['expected_lora_modules'].values())
    if len(pairs)!=expected or any(set(pair)!=set('AB') for pair in pairs.values()):
        raise ValueError('Incomplete LoRA target coverage')
    return pairs,alpha/rank


def merge_weight(base,a,b,scale):
    import torch
    if base.ndim!=2 or a.ndim!=2 or b.ndim!=2 or (b.shape[0],a.shape[1])!=base.shape or b.shape[1]!=a.shape[0]:
        raise ValueError('LoRA/base shape mismatch')
    if base.dtype!=torch.bfloat16 or a.dtype!=torch.float32 or b.dtype!=torch.float32:
        raise ValueError('Expected BF16 base and FP32 trained adapters')
    if not torch.isfinite(a).all() or not torch.isfinite(b).all():raise ValueError('Nonfinite adapter')
    if not torch.count_nonzero(b):raise ValueError('Untrained LoRA B matrix')
    # Match PEFT 0.18.1 safe_merge, including rounding the delta before addition.
    result=base.clone()
    result+=((b@a)*scale).to(base.dtype)
    if not torch.isfinite(result).all():raise ValueError('Nonfinite merged weight')
    return result


def merge(adapter,output,base_manifest,threads=2):
    import torch
    from safetensors import safe_open
    from safetensors.torch import load_file,save_file
    if md.version('peft')!='0.18.1':raise ValueError('Revalidate safe_merge math for this PEFT version')
    info=inspect_adapter(adapter);config=info['training_config'];base=Path(info['base_model_name_or_path']).resolve()
    manifest_path=Path(base_manifest);manifest=json.loads(manifest_path.read_text())
    provenance=config['base_artifact_manifest']
    if not manifest.get('verified') or manifest['model']!=provenance['model'] or manifest['revision']!=provenance['revision'] or sha256(manifest_path)!=provenance['manifest_sha256']:
        raise ValueError('Exact verified training base provenance required')
    index=json.loads((base/'model.safetensors.index.json').read_text())['weight_map']
    weights=load_file(Path(adapter)/'adapter_model.safetensors',device='cpu')
    peft=json.loads((Path(adapter)/'adapter_config.json').read_text())
    pairs,scale=plan_lora(weights,index,peft,config)
    if any(weights[p['A']].shape[0]!=peft['r'] or weights[p['B']].shape[1]!=peft['r'] for p in pairs.values()):
        raise ValueError('Adapter rank mismatch')
    artifacts={a['path']:a for a in manifest['files']};shards=set(index.values())
    if not shards<=artifacts.keys() or {n for n in artifacts if n.endswith('.safetensors')}!=shards:
        raise ValueError('Checkpoint shard inventory mismatch')
    torch.set_num_threads(threads)
    output=Path(output).resolve();output.mkdir(parents=True,exist_ok=False)
    state={'status':'merging','started_at_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),
           'adapter_sha256':sha256(Path(adapter)/'adapter_model.safetensors'),
           'base_manifest_sha256':sha256(manifest_path),'base_revision':manifest['revision'],
           'device':'cpu','dtype':'bfloat16','peft_version':md.version('peft'),'torch_version':torch.__version__,
           'rounding':'PEFT 0.18.1 CPU safe_merge: FP32 delta to BF16 before adding',
           'target_modules':len(pairs),'files':[],
           'verified_tensors':0,'preserved_tensors':0,'changed_modules':0}
    def save():
        temp=output/'merge-status.tmp';temp.write_text(json.dumps(state,indent=2)+'\n');temp.replace(output/'merge-status.json')
    save();seen=set()
    try:
        for name,item in artifacts.items():
            if name in shards:continue
            verify_artifact(base,item);destination=output/name;destination.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(base/name,destination)
            state['files'].append({'path':name,'sha256':sha256(destination),'bytes':destination.stat().st_size,'unchanged':True})
        for name in sorted(shards):
            verify_artifact(base,artifacts[name]);destination=output/name
            with safe_open(base/name,framework='pt',device='cpu') as original:
                names=set(original.keys());expected={k for k,v in index.items() if v==name}
                if names!=expected:raise ValueError('Unindexed or missing base tensors: '+name)
                tensors={}
                for key in sorted(names):
                    tensor=original.get_tensor(key)
                    if key in pairs:
                        pair=pairs[key];merged=merge_weight(tensor,weights[pair['A']],weights[pair['B']],scale)
                        state['changed_modules']+=int(not torch.equal(tensor,merged));tensors[key]=merged;seen.add(key)
                    else:tensors[key]=tensor
                destination.parent.mkdir(parents=True,exist_ok=True)
                temp=destination.with_suffix('.tmp');save_file(tensors,temp,metadata=original.metadata());temp.replace(destination)
                with safe_open(destination,framework='pt',device='cpu') as check:
                    if set(check.keys())!=names:raise ValueError('Saved tensor inventory mismatch')
                    for key in sorted(names):
                        actual=check.get_tensor(key);expected_tensor=tensors[key]
                        if actual.dtype!=expected_tensor.dtype or not torch.equal(actual,expected_tensor):raise ValueError('Saved tensor mismatch: '+key)
                        state['verified_tensors']+=1
                        if key not in pairs:state['preserved_tensors']+=1
                        del actual,expected_tensor
                del tensors,tensor
                if 'merged' in locals():del merged
            gc.collect()
            state['files'].append({'path':name,'bytes':destination.stat().st_size,'sha256':sha256(destination),'unchanged':not any(index[k]==name for k in pairs)})
            state['last_shard']=name;save()
        if seen!=set(pairs) or state['verified_tensors']!=len(index):raise ValueError('Incomplete export coverage')
        state.update(status='completed',completed_at_kst=datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),
                     preserved_mtp_tensors=sum(k.startswith('mtp.') for k in index),
                     total_checkpoint_tensors=len(index))
    except BaseException as error:
        state.update(status='failed',error=repr(error));save();raise
    save();return state


def main():
    def interrupted(signum,frame):raise InterruptedError(f'Export interrupted by signal {signum}')
    signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adapter',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--base-manifest',type=Path,required=True)
    parser.add_argument('--threads',type=int,default=2,choices=range(1,17))
    args=parser.parse_args();print(json.dumps(merge(args.adapter,args.output,args.base_manifest,args.threads)))


if __name__=='__main__':main()
