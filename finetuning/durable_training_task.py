"""Unprivileged container stage: offline token audit or memory-guarded training."""
from datetime import datetime
import hashlib,json,os,signal,subprocess,sys
from pathlib import Path
from zoneinfo import ZoneInfo
import guarded_process

def save(path,value):
    tmp=path.with_suffix('.tmp');tmp.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n');tmp.replace(path)

def main():
    stage=sys.argv[1]
    if stage not in ('tokenize','smoke','main'):raise ValueError('Unknown stage')
    root=Path('/trial');status=root/(stage+'-status.json')
    if status.exists():raise ValueError('Prior stage receipt exists; no automatic retry')
    value={'stage':stage,'status':'running','started_at_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat()};save(status,value)
    def interrupted(signum,frame):raise InterruptedError('Container interrupted')
    signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
    try:
        config=json.loads((root/'profiles'/(stage+'.json')).read_text())
        raw=Path('/workspace/base-manifest.json').read_bytes();base=json.loads(raw)
        if not base['verified'] or base['revision']!=config['revision'] or base['model']!='Qwen/Qwen3.6-35B-A3B':raise ValueError('Base identity mismatch')
        config['base_artifact_manifest']={'model':base['model'],'revision':base['revision'],'manifest_sha256':hashlib.sha256(raw).hexdigest()}
        cfg=root/(stage+'-runtime.json');save(cfg,config)
        args=['/workspace/venv/bin/python','-B','/trial/source/train.py','--config',str(cfg),'--tokenize-only' if stage=='tokenize' else '--train']
        with (root/(stage+'.log')).open('x',buffering=1) as log:
            if stage=='tokenize':subprocess.run(args,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=300)
            else:guarded_process.run(args,log=log,cwd=root/'source',env=os.environ.copy(),report=root/(stage+'-memory-guard.json'))
        value['status']='completed'
    except BaseException as exc:
        value.update(status='failed',error_type=type(exc).__name__);raise
    finally:
        value['updated_at_kst']=datetime.now(ZoneInfo('Asia/Seoul')).isoformat();save(status,value)

if __name__=='__main__':main()
