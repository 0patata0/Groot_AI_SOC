"""Build pinned CPU-only llama.cpp tools and convert the verified Cisco model.

Run inside the existing pinned Thor container. No GPU, system package manager,
production Ollama update, or Mac installation is involved.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from datetime import datetime
from zoneinfo import ZoneInfo

REVISION='276378515ceebee5d14bcc8536603dd5c87491a2'
ROOT=Path('/workspace/comparisons/foundation-sec-8b-instruct-20261027')


def digest(path):
    value=hashlib.sha256()
    with Path(path).open('rb') as handle:
        for chunk in iter(lambda:handle.read(8*1024*1024),b''):value.update(chunk)
    return value.hexdigest()


def main():
    record=ROOT/'conversion-status.json'
    if record.exists():raise ValueError('Inspect prior conversion before explicitly retrying')
    status={'status':'checking','started_at_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),'llama_cpp_revision':REVISION}
    def save():
        temp=record.with_suffix('.tmp');temp.write_text(json.dumps(status,indent=2)+'\n');temp.replace(record)
    save()
    try:
        manifest=json.loads((ROOT/'base-manifest.json').read_text())
        if not manifest.get('verified') or manifest['revision']!='aa13cb996e7fc700e7efd6b7367992f14cf349c0':
            raise ValueError('Pinned verified Cisco base required')
        source=ROOT/'llama.cpp';source.mkdir(exist_ok=True)
        env=os.environ.copy();env.update(PYTHONDONTWRITEBYTECODE='1',PIP_NO_CACHE_DIR='1',PIP_DISABLE_PIP_VERSION_CHECK='1',HF_HUB_DISABLE_IMPLICIT_TOKEN='1')
        with (ROOT/'conversion.log').open('a',buffering=1) as log:
            def run(args,timeout=1200,cwd=source):
                subprocess.run([str(a) for a in args],cwd=cwd,env=env,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=timeout)
            status['status']='fetching_pinned_source';save()
            if not (source/'.git').exists():
                run(['git','init']);run(['git','remote','add','origin','https://github.com/ggml-org/llama.cpp.git'])
                run(['git','fetch','--depth','1','origin',REVISION]);run(['git','checkout','--detach','FETCH_HEAD'])
            head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip()
            if head!=REVISION:raise ValueError('Converter source revision mismatch')
            deps=ROOT/'conversion-python-deps';deps.mkdir(exist_ok=True)
            # Keep converter-only packages outside the training venv.
            if not (deps/'sentencepiece').exists():
                run([sys.executable,'-m','pip','install','--no-deps','--no-cache-dir','--disable-pip-version-check',
                     '--target',deps,'--report',ROOT/'conversion-install-report.json','sentencepiece==0.2.1'])
            env['PYTHONPATH']=str(deps)+os.pathsep+str(source/'gguf-py')
            status['status']='building_cpu_quantizer';save()
            build=source/'build-cpu'
            run(['cmake','-S',source,'-B',build,'-DCMAKE_BUILD_TYPE=Release','-DGGML_CUDA=OFF',
                 '-DGGML_NATIVE=OFF','-DGGML_OPENMP=OFF','-DGGML_BLAS=OFF','-DLLAMA_CURL=OFF',
                 '-DLLAMA_BUILD_TESTS=OFF','-DLLAMA_BUILD_EXAMPLES=OFF'])
            run(['cmake','--build',build,'--target','llama-quantize','--parallel','2'],timeout=1800)
            env.update(HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1')
            status['status']='converting_bf16';save()
            full=ROOT/'foundation-sec-8b-bf16.gguf';quant=ROOT/'foundation-sec-8b-q4_k_m.gguf'
            if full.exists() or quant.exists():raise ValueError('Conversion output already exists')
            run([sys.executable,'-B',source/'convert_hf_to_gguf.py',ROOT/'base','--outfile',full,'--outtype','bf16'],timeout=1800)
            status['status']='quantizing_q4_k_m';save()
            run([build/'bin/llama-quantize',full,quant,'Q4_K_M','2'],timeout=1800)
            with quant.open('rb') as handle:
                if handle.read(4)!=b'GGUF':raise ValueError('Invalid GGUF output header')
            artifacts=[{'path':p.name,'bytes':p.stat().st_size,'sha256':digest(p)} for p in (full,quant,build/'bin/llama-quantize')]
            result={'base_revision':manifest['revision'],'llama_cpp_revision':REVISION,'artifacts':artifacts,'gpu_used':False}
            (ROOT/'conversion-manifest.json').write_text(json.dumps(result,indent=2)+'\n')
            status.update(status='completed',completed_at_kst=datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),artifacts=artifacts)
    except Exception as error:
        status.update(status='failed',error=repr(error));save();raise
    save()


if __name__=='__main__':main()
