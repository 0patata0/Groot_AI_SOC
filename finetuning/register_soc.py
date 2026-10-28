"""Register verified SOC GGUF files under new names in Thor's local Ollama.

Copies the original runtime template/options but never changes bot selection.
Uploads stream directly on Thor; no weights pass through the Mac.
"""
import argparse
import http.client
import hashlib
import json
from pathlib import Path
import platform
import re
from urllib import request,error
from datetime import datetime
from zoneinfo import ZoneInfo

from convert_reference import digest
from download_model import verify_artifact


def api(path,payload=None,timeout=30):
    data=None if payload is None else json.dumps(payload).encode()
    req=request.Request('http://127.0.0.1:11434'+path,data=data,headers={'Content-Type':'application/json'})
    try:
        with request.urlopen(req,timeout=timeout) as response:return json.load(response)
    except error.HTTPError as exc:
        raise RuntimeError(f'Ollama HTTP {exc.code}: '+exc.read().decode(errors='replace')[:2000]) from None


def parameters(text):
    result={}
    for line in text.splitlines():
        if not line.strip():continue
        key,value=line.split(maxsplit=1);value=json.loads(value)
        if key=='stop':result.setdefault(key,[]).append(value)
        elif key in result:raise ValueError('Duplicate runtime parameter: '+key)
        else:result[key]=value
    return result


def upload(path,sha):
    url='/api/blobs/sha256:'+sha
    try:
        with request.urlopen(request.Request('http://127.0.0.1:11434'+url,method='HEAD'),timeout=15) as response:
            if response.status==200:return
    except error.HTTPError as exc:
        if exc.code!=404:raise
    connection=http.client.HTTPConnection('127.0.0.1',11434,timeout=1200)
    try:
        connection.putrequest('POST',url);connection.putheader('Content-Type','application/octet-stream')
        connection.putheader('Content-Length',str(path.stat().st_size));connection.endheaders()
        with path.open('rb') as handle:
            for chunk in iter(lambda:handle.read(8*1024*1024),b''):connection.send(chunk)
        response=connection.getresponse();body=response.read()
        if response.status not in (200,201):raise RuntimeError(f'Blob upload HTTP {response.status}: {body[:1000]!r}')
    finally:connection.close()


def hf_template(root):
    root=Path(root);manifest=json.loads((root/'base-manifest.json').read_text())
    if not manifest.get('verified') or manifest['revision']!='995ad96eacd98c81ed38be0c5b274b04031597b0':
        raise ValueError('Pinned HF template provenance required')
    artifact=next(a for a in manifest['files'] if a['path']=='chat_template.jinja')
    verify_artifact(root/'base',artifact)
    return (root/'base/chat_template.jinja').read_text()


def verify_runtime(original,show,expected_template,files):
    # Native llama.cpp show selects the embedded GGUF Jinja template, even when
    # the manifest also contains the original legacy Go {{ .Prompt }} layer.
    if show.get('template')!=expected_template:raise ValueError('Effective template differs from pinned HF')
    for key in ('system','renderer','parser','requires','license','messages'):
        if show.get(key)!=original.get(key):raise ValueError('Runtime metadata differs: '+key)
    if parameters(show.get('parameters',''))!=parameters(original.get('parameters','')):raise ValueError('Effective runtime options differ')
    if show['details']['quantization_level']!='Q4_K_M' or not show.get('projector_info'):raise ValueError('Text/projector import incomplete')
    if set(show.get('capabilities',[]))!=set(original.get('capabilities',[])):raise ValueError('Candidate capabilities differ from original')
    if show['details'].get('runner')!=original['details'].get('runner'):raise ValueError('Candidate runner differs from original')
    actual=set(re.findall(r'(?m)^FROM\s+\S*sha256-([0-9a-f]{64})\s*$',show.get('modelfile','')))
    if actual!={value.removeprefix('sha256:') for value in files.values()}:raise ValueError('Registered text/projector blob mismatch')
    return {'runtime_options_match_original':True,'chat_template_matches_hf':True,
            'chat_template_matches_original':show.get('template')==original.get('template'),
            'hf_template_sha256':hashlib.sha256(expected_template.encode()).hexdigest()}


def candidate_name(variant):
    if variant in ('base','main'):return f'soc-qwen36:35b-{variant}-q4km-20261027'
    if variant in ('v2-step24','v2-step48'):return f'soc-qwen36:35b-{variant}-q4km-20261028'
    if variant=='v5':return 'soc-qwen36:35b-evidence-v5-q4km-20261029'
    raise ValueError('Unknown candidate')


def v5_source_notice(root):
    root=Path(root);folder=root/'finetuning/data-soc-evidence-v5-r3'
    manifest=json.loads((folder/'manifest.json').read_text())
    license=(folder/'MITRE-ATTACK-LICENSE.txt').read_text()
    attribution=(folder/'SOURCE_ATTRIBUTION.json').read_text()
    if digest(folder/'MITRE-ATTACK-LICENSE.txt')!=manifest['MITRE_license_sha256'] or digest(folder/'SOURCE_ATTRIBUTION.json')!=manifest['attribution_sha256']:
        raise ValueError('Training source attribution changed')
    return ('\n\nSOC evidence V5 training-source attribution (not institutional certification):\n'
            +license+'\nOriginal report/source provenance:\n'+attribution)


def with_source_notice(original,notice):
    result=dict(original);license=original.get('license')
    if isinstance(license,str):result['license']=license+notice
    elif isinstance(license,list) and all(isinstance(s,str) for s in license):result['license']=[*license,notice]
    else:raise ValueError('Original model license must be preserved')
    return result


def register(root,variant):
    model=candidate_name(variant)
    folder=Path(root)/f'exports/qwen36-soc-{variant}-gguf';record=folder/'registration-status.json'
    if record.exists():raise ValueError('Inspect previous registration before explicitly retrying')
    state={'status':'checking','model':model,'variant':variant,'started_at_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat()}
    def save():
        temp=record.with_suffix('.tmp');temp.write_text(json.dumps(state,indent=2)+'\n');temp.replace(record)
    save()
    try:
        conversion=json.loads((folder/'conversion-status.json').read_text())
        if conversion.get('status')!='completed' or conversion['variant']!=variant:
            raise ValueError('Completed verified conversion required')
        before={m['name']:m['digest'] for m in api('/api/tags')['models']}
        if model in before:raise ValueError('Candidate already exists; refusing replacement')
        original=api('/api/show',{'model':'qwen3.6:35b'})
        expected_runtime=original
        if variant=='v5':
            from verify_evidence_training import verify
            state['training_coverage']=verify(root)
            notice=v5_source_notice(root)
            expected_runtime=with_source_notice(original,notice)
            (folder/'training-source-attribution.txt').write_text(notice)
            state['training_source_attribution_sha256']=hashlib.sha256(notice.encode()).hexdigest()
        expected_template=hf_template(root)
        if original['details']['quantization_level']!='Q4_K_M':raise ValueError('Original quantization changed')
        chosen={a['path']:a for a in conversion['artifacts'] if a['path'] in ['qwen36-soc-q4_k_m.gguf','mmproj-qwen36-soc-f16.gguf']}
        if len(chosen)!=2:raise ValueError('Text and vision projector required')
        files={}
        for name,item in chosen.items():
            path=folder/name
            if path.is_symlink() or path.stat().st_size!=item['bytes'] or digest(path)!=item['sha256']:raise ValueError('GGUF hash mismatch')
            upload(path,item['sha256']);files[name]='sha256:'+item['sha256']
        (folder/'original-runtime-show.json').write_text(json.dumps(original,ensure_ascii=False,indent=2)+'\n')
        payload={'model':model,'files':files,'stream':False,'parameters':parameters(original.get('parameters',''))}
        for key in ('template','system','renderer','parser','requires','license','messages'):
            if expected_runtime.get(key):payload[key]=expected_runtime[key]
        state.update(status='registering',files=files,original_digest=before['qwen3.6:35b']);save()
        result=api('/api/create',payload,timeout=1200)
        if result.get('status')!='success':raise ValueError('Model registration incomplete: '+repr(result))
        show=api('/api/show',{'model':model})
        verified=verify_runtime(expected_runtime,show,expected_template,files)
        (folder/'ollama-show.json').write_text(json.dumps(show,ensure_ascii=False,indent=2)+'\n')
        tags=api('/api/tags')['models'];after={m['name']:m['digest'] for m in tags}
        if any(after.get(name)!=sha for name,sha in before.items()):raise ValueError('An existing model changed during registration')
        tag=next(m for m in tags if m['name']==model)
        state.update(status='completed',completed_at_kst=datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),
                     digest=tag['digest'],files=files,capabilities=show['capabilities'],**verified,
                     conversion_manifest_sha256=digest(folder/'conversion-status.json'),
                     original_digest=before['qwen3.6:35b'],existing_models_unchanged=True)
    except BaseException as exc:state.update(status='failed',error=repr(exc));save();raise
    save();return state


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=Path.home()/'Capstone_Groot_training/qwen36-20261027');parser.add_argument('--variant',choices=['base','main','v2-step24','v2-step48','v5'],required=True)
    args=parser.parse_args()
    if platform.system()!='Linux' or platform.machine()!='aarch64':raise SystemExit('Run on Thor host')
    print(json.dumps(register(args.root,args.variant)))


if __name__=='__main__':main()
