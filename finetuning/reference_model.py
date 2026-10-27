"""Register the pinned Cisco comparison model in the existing Thor Ollama.

No service settings or bot configuration change. This administrator-owned helper
does not give the SOC LLM installation, Docker or shell capabilities.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
from urllib import request
from datetime import datetime
from zoneinfo import ZoneInfo
from download_model import verify_artifact


def now():return datetime.now(ZoneInfo('Asia/Seoul')).isoformat()


def register(root,config):
    root=Path(root).resolve();folder=root/'comparisons/foundation-sec-8b-instruct-20261027';folder.mkdir(parents=True,exist_ok=True)
    state={'status':'checking','started_at_kst':now(),'model':config['ollama_model']};record=folder/'import-status.json'
    if record.exists():raise ValueError('Prior import evidence exists; inspect before retry')
    def save():
        temporary=record.with_suffix('.tmp');temporary.write_text(json.dumps(state,indent=2)+'\n');temporary.replace(record)
    save()
    try:
        manifest=json.loads((folder/'base-manifest.json').read_text())
        if not manifest.get('verified') or manifest['model']!=config['model_name_or_path'] or manifest['revision']!=config['revision']:
            raise ValueError('Verified pinned reference model required')
        for artifact in manifest['files']:verify_artifact(folder/'base',artifact)
        conversion=json.loads((folder/'conversion-manifest.json').read_text())
        if conversion['base_revision']!=config['revision']:
            raise ValueError('Converted model revision mismatch')
        artifact=next(a for a in conversion['artifacts'] if a['path']==config['gguf_file'])
        gguf=folder/config['gguf_file']
        if gguf.parent!=folder or gguf.is_symlink() or gguf.stat().st_size!=artifact['bytes']:
            raise ValueError('Unsafe or incomplete converted model')
        digest=hashlib.sha256()
        with gguf.open('rb') as handle:
            if handle.read(4)!=b'GGUF':raise ValueError('Invalid GGUF header')
            handle.seek(0)
            for chunk in iter(lambda:handle.read(8*1024*1024),b''):digest.update(chunk)
        if digest.hexdigest()!=artifact['sha256']:raise ValueError('Converted model hash mismatch')
        with request.urlopen('http://127.0.0.1:11434/api/tags',timeout=10) as response:names={m['name'] for m in json.load(response)['models']}
        if config['ollama_model'] in names:raise ValueError('Comparison name already exists; refusing replacement')
        model_file=folder/'Modelfile'
        model_file.write_text(f'FROM {gguf}\nPARAMETER temperature 0\nPARAMETER num_ctx {config["num_ctx"]}\nPARAMETER num_predict 512\n')
        state['status']='importing';save()
        env=os.environ.copy();env['OLLAMA_HOST']='http://127.0.0.1:11434'
        with (folder/'import.log').open('a',buffering=1) as log:
            subprocess.run(['ollama','create',config['ollama_model'],'--file',str(model_file)],
                env=env,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=1800)
        body=json.dumps({'model':config['ollama_model']}).encode()
        with request.urlopen(request.Request('http://127.0.0.1:11434/api/show',data=body,headers={'Content-Type':'application/json'}),timeout=20) as response:result=json.load(response)
        state.update(status='completed',completed_at_kst=now(),details=result.get('details'),capabilities=result.get('capabilities'),gguf=artifact)
        (folder/'ollama-show.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    except Exception as error:
        state.update(status='failed',error=repr(error),failed_at_kst=now());save();raise
    save();return state


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path.home()/'Capstone_Groot_training/qwen36-20261027')
    parser.add_argument('--config',type=Path,default=Path(__file__).with_name('config.foundation-sec-8b.json'))
    args=parser.parse_args()
    if platform.system()!='Linux' or platform.machine()!='aarch64':raise SystemExit('Run on the Thor host')
    print(json.dumps(register(args.root,json.loads(args.config.read_text())),ensure_ascii=False))


if __name__=='__main__':main()
