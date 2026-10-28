"""Convert the pinned base or verified SOC merge to GGUF without using a GPU."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import signal
from datetime import datetime
from zoneinfo import ZoneInfo

from convert_reference import REVISION,digest
from download_model import verify_artifact


def convert(root,variant):
    root=Path(root);tools=root/'comparisons/foundation-sec-8b-instruct-20261027'
    source=tools/'llama.cpp';quantizer=source/'build-cpu/bin/llama-quantize'
    if subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip()!=REVISION:
        raise ValueError('Pinned converter source required')
    subprocess.run(['git','diff','--quiet','HEAD'],cwd=source,check=True)
    known=json.loads((tools/'conversion-manifest.json').read_text())
    artifact=next(a for a in known['artifacts'] if a['path']=='llama-quantize')
    if digest(quantizer)!=artifact['sha256']:raise ValueError('CPU quantizer hash mismatch')
    if variant=='base':
        model=root/'base';manifest=json.loads((root/'base-manifest.json').read_text())
        if not manifest.get('verified') or manifest['revision']!='995ad96eacd98c81ed38be0c5b274b04031597b0':
            raise ValueError('Verified pinned base required')
        files=manifest['files']
    elif variant in ('pilot','main','v2-step24','v2-step48','v5'):
        model=root/f'exports/qwen36-soc-{variant}-hf';manifest=json.loads((model/'merge-status.json').read_text())
        if manifest.get('status')!='completed' or manifest['base_revision']!='995ad96eacd98c81ed38be0c5b274b04031597b0' or manifest['verified_tensors']!=1045 or manifest['target_modules']!=190 or manifest['preserved_mtp_tensors']!=19:
            raise ValueError('Complete verified SOC merge required')
        files=manifest['files']
        if variant=='v5':
            from verify_evidence_training import verify
            if verify(root)['adapter_sha256']!=manifest['adapter_sha256']:
                raise ValueError('Merged V5 adapter differs from the completed full epoch')
        if variant.startswith('v2-step'):
            step=int(variant.removeprefix('v2-step'));checkpoint=root/f'outputs/soc-v2-pilot/checkpoint-{step}'
            saved=json.loads((checkpoint/'trainer_state.json').read_text())
            if saved.get('global_step')!=step or digest(checkpoint/'adapter_model.safetensors')!=manifest['adapter_sha256']:
                raise ValueError('Merged v2 adapter does not match the named checkpoint')
    else:raise ValueError('Unknown conversion variant')
    folder=root/f'exports/qwen36-soc-{variant}-gguf';folder.mkdir(parents=True,exist_ok=False)
    record=folder/'conversion-status.json';state={'status':'checking','variant':variant,'started_at_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),'llama_cpp_revision':REVISION}
    def save():
        temp=record.with_suffix('.tmp');temp.write_text(json.dumps(state,indent=2)+'\n');temp.replace(record)
    save()
    try:
        for item in files:
            if variant=='base':
                verify_artifact(model,item)
                continue
            path=model/item['path']
            if path.is_symlink() or not path.resolve().is_relative_to(model.resolve()) or path.stat().st_size!=item['bytes'] or digest(path)!=item['sha256']:
                raise ValueError('Source model artifact mismatch: '+item['path'])
        env=os.environ.copy();env.update(PYTHONDONTWRITEBYTECODE='1',HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1',
            PYTHONPATH=str(tools/'conversion-python-deps')+os.pathsep+str(source/'gguf-py'))
        with (folder/'conversion.log').open('a',buffering=1) as log:
            def run(args):
                subprocess.run([str(a) for a in args],cwd=source,env=env,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=3600)
            full=folder/'qwen36-soc-bf16.gguf';quant=folder/'qwen36-soc-q4_k_m.gguf';projector=folder/'mmproj-qwen36-soc-f16.gguf'
            state['status']='converting_text_with_mtp';save()
            run([sys.executable,'-B',source/'convert_hf_to_gguf.py',model,'--outfile',full,'--outtype','bf16'])
            state['status']='converting_projector';save()
            if variant=='base':
                run([sys.executable,'-B',source/'convert_hf_to_gguf.py',model,'--mmproj','--outfile',projector,'--outtype','f16'])
            else:
                # Streaming merge proves every non-LoRA tensor identical to the base.
                # Reuse the already verified projector rather than converting it again.
                import shutil
                baseline=root/'exports/qwen36-soc-base-gguf';reference=json.loads((baseline/'conversion-status.json').read_text())
                if reference.get('status')!='completed':raise ValueError('Verified base projector required')
                expected=next(a for a in reference['artifacts'] if a['path']==projector.name)
                if digest(baseline/projector.name)!=expected['sha256']:raise ValueError('Base projector hash mismatch')
                shutil.copyfile(baseline/projector.name,projector)
            state['status']='quantizing_q4_k_m';save()
            run([quantizer,full,quant,'Q4_K_M','2'])
            # Inspect metadata only; GGUFReader keeps tensor storage memory-mapped.
            sys.path[:0]=[str(tools/'conversion-python-deps'),str(source/'gguf-py')]
            import gguf
            reader=gguf.GGUFReader(str(quant),'r')
            def field(name):return reader.fields[name].contents() if name in reader.fields else None
            if field('general.architecture')!='qwen35moe' or field('qwen35moe.nextn_predict_layers')!=1:
                raise ValueError('Expected Qwen35 MoE with embedded MTP')
            state['text_metadata']={name:field(name) for name in ['general.architecture','general.file_type','qwen35moe.block_count','qwen35moe.nextn_predict_layers','qwen35moe.context_length']}
            state['text_tensor_count']=len(reader.tensors)
            vision=gguf.GGUFReader(str(projector),'r')
            state['projector_metadata']={name:vision.fields[name].contents() for name in ['general.architecture','general.type'] if name in vision.fields}
            state['projector_tensor_count']=len(vision.tensors)
            if not vision.tensors:raise ValueError('Empty projector')
            artifacts=[]
            for path in [full,quant,projector]:
                with path.open('rb') as handle:
                    if handle.read(4)!=b'GGUF':raise ValueError('Invalid GGUF header')
                artifacts.append({'path':path.name,'bytes':path.stat().st_size,'sha256':digest(path)})
            state.update(status='completed',completed_at_kst=datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),artifacts=artifacts,gpu_used=False)
    except BaseException as error:state.update(status='failed',error=repr(error));save();raise
    save();return state


def main():
    def interrupted(signum,frame):raise InterruptedError(f'Conversion interrupted by signal {signum}')
    signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=Path('/workspace'));parser.add_argument('--variant',choices=['base','pilot','main','v2-step24','v2-step48','v5'],required=True)
    args=parser.parse_args();print(json.dumps(convert(args.root,args.variant)))


if __name__=='__main__':main()
