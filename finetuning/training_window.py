"""Operator-only v2 smoke/pilot window with an independent systemd restoration timer.

Install an inspected, root-owned copy before running. This is never an MCP tool
or LLM sudo permission. It does not merge, register, select or promote a model.
"""
import argparse
from datetime import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import signal
import stat
import subprocess
import tempfile
import time
from urllib import request
from zoneinfo import ZoneInfo

ORIGINAL='qwen3.6:35b'
ORIGINAL_DIGEST='a7eb95c53bcf96b4bdd008d0fab4a5dac88047d9c1a7a9ab88ed453423fbd87c'
RESTORE_UNIT='capstone-soc-v2-restore'
STAGES=('soc-v2-smoke','soc-v2-pilot')
STATE=Path('/var/lib/capstone-training-v2-window')
LIMIT_SECONDS=45*60
RESTORE_MINUTES=50
MODE='v2'
DATA_HASHES={'train':'73e6345fd0e7fdd35c31272bcdd271528ffee52d86d9fd15af363d23bef25ac7',
             'validation':'ac515b0ed1ad2e7c613512d5e32c9aa707ed68c03356e55dcb59cfcfa6320850',
             'test':'4e7bf5e8f988895fcd9efb437c1c231295befdf7e0bc1d59614481974edb755d'}
PROFILE_SHA256='2d76cd0dd8f52ee5372a7690be8eef8d75bd7fc2499bd0b89792dc6a414da9da'
BASELINE_INPUTS={'cases.jsonl':'b89ddbc86a40dd55743513a255f7d35e05adad701fca4468f347f3a5980fdeae',
                 'mcp_contract.json':'ffcfb0bc8393e483e395a2348cb258dc7b843ee677579c8da577c7f1636390bd'}


def select_mode(mode):
    global MODE,STAGES,STATE,LIMIT_SECONDS,RESTORE_MINUTES,RESTORE_UNIT
    if mode=='v2':
        STAGES=('soc-v2-smoke','soc-v2-pilot');STATE=Path('/var/lib/capstone-training-v2-window')
        LIMIT_SECONDS=45*60;RESTORE_MINUTES=50;RESTORE_UNIT='capstone-soc-v2-restore'
    elif mode=='memory-repro':
        STAGES=('soc-memory-smoke',);STATE=Path('/var/lib/capstone-memory-repro-20261028')
        LIMIT_SECONDS=6*60;RESTORE_MINUTES=8;RESTORE_UNIT='capstone-memory-repro-restore'
    elif mode=='memory-vmm':
        STAGES=('soc-memory-vmm',);STATE=Path('/var/lib/capstone-memory-vmm-20261028')
        LIMIT_SECONDS=6*60;RESTORE_MINUTES=8;RESTORE_UNIT='capstone-memory-vmm-restore'
    elif mode=='memory-trace':
        STAGES=('soc-memory-trace',);STATE=Path('/var/lib/capstone-memory-trace-20261028')
        LIMIT_SECONDS=6*60;RESTORE_MINUTES=8;RESTORE_UNIT='capstone-memory-trace-restore'
    elif mode=='memory-loss':
        STAGES=('soc-memory-loss',);STATE=Path('/var/lib/capstone-memory-loss-20261028')
        LIMIT_SECONDS=6*60;RESTORE_MINUTES=8;RESTORE_UNIT='capstone-memory-loss-restore'
    else:raise ValueError('Unknown fixed operator mode')
    MODE=mode


def now():return datetime.now(ZoneInfo('Asia/Seoul')).isoformat()


def run(argv,timeout=30,check=True):
    result=subprocess.run([str(a) for a in argv],capture_output=True,text=True,timeout=timeout)
    if check and result.returncode:raise RuntimeError('Fixed operator command failed: '+Path(argv[0]).name)
    return result


def api(path,payload=None,timeout=90):
    data=None if payload is None else json.dumps(payload).encode()
    req=request.Request('http://127.0.0.1:11434/api/'+path,data=data,headers={'Content-Type':'application/json'})
    with request.urlopen(req,timeout=timeout) as response:return json.load(response)


def save(name,value):
    with tempfile.NamedTemporaryFile('w',dir=STATE,delete=False) as handle:
        temporary=Path(handle.name);json.dump(value,handle,ensure_ascii=False,indent=2);handle.write('\n')
    temporary.chmod(0o644);temporary.replace(STATE/name)


def verify_ready(root):
    raw=(root/'finetuning/config.qwen36-soc-v2.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=PROFILE_SHA256:raise ValueError('Frozen pilot profile checksum mismatch')
    profile=json.loads(raw)
    if (profile.get('max_steps'),profile.get('learning_rate'),profile.get('max_length'),profile.get('require_all_prefixes'))!=(48,5e-6,2048,True):
        raise ValueError('Frozen v2 pilot profile differs from the reviewed plan')
    if profile.get('data_dir')!='data-soc-v2-r2':raise ValueError('Unreviewed dataset path')
    for split,digest in DATA_HASHES.items():
        if hashlib.sha256((root/'finetuning/data-soc-v2-r2'/(split+'.jsonl')).read_bytes()).hexdigest()!=digest:
            raise ValueError('Frozen curriculum hash mismatch')
    proof=json.loads((root/'soc-v2-tokenization/tokenization_report.json').read_text())
    if proof.get('max_length')!=2048 or proof.get('require_all_prefixes') is not True:
        raise ValueError('Strict tokenization proof required')
    if any(proof[s].get('kept')!=proof[s].get('candidate_turns') for s in DATA_HASHES):
        raise ValueError('Required curriculum examples were excluded')
    checks=json.loads((root/'soc-v2-tokenization/data_check.json').read_text())
    if checks.get('sha256')!=DATA_HASHES:raise ValueError('Tokenization proof belongs to a different corpus')
    for stage in STAGES:
        if (root/(stage+'-status.json')).exists() or (root/'outputs'/stage).exists():
            raise ValueError('Prior v2 training evidence exists; automatic retry forbidden')
    job=json.loads((root/'soc-v2-evaluation/base-development-r2-job.json').read_text())
    if job.get('status')!='completed' or not job.get('original_warm_done'):
        raise ValueError('Completed current development baseline and original warm-up required')
    if job.get('source_sha256')!=BASELINE_INPUTS:raise ValueError('Development baseline used different inputs')


def restore_command(script,root):
    args=['systemd-run','--unit='+RESTORE_UNIT,'--on-active='+str(RESTORE_MINUTES)+'m',
          '--timer-property=AccuracySec=1s']
    if MODE in ('memory-repro','memory-vmm','memory-trace','memory-loss'):args+=['--property=Type=oneshot','--property=TimeoutStartSec=6min']
    args+=['/usr/bin/python3','-B',str(script),'restore','--root',str(root)]
    if MODE!='v2':args+=['--mode',MODE]
    return args


def process_belongs_to(pid,ancestor,proc=Path('/proc')):
    seen=set()
    while pid>1 and pid not in seen:
        if pid==ancestor:return True
        seen.add(pid)
        try:
            lines=(proc/str(pid)/'status').read_text().splitlines()
            pid=int(next(line.split()[1] for line in lines if line.startswith('PPid:')))
        except (OSError,ValueError,StopIteration):return False
    return False


def restore(root):
    with (STATE/'restore.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        result={'started_at_kst':now(),'status':'restoring'};save('restore.json',result)
        try:
            for stage in STAGES:
                name='capstone-qwen36-'+stage
                running=run(['docker','inspect','--format','{{.State.Running}}',name],check=False)
                if running.returncode==0 and running.stdout.strip()=='true':
                    run(['docker','stop','--time','10',name],timeout=30)
            run(['systemctl','start','ollama'],timeout=45)
            deadline=time.monotonic()+120
            while True:
                try:
                    tags={m['name']:m['digest'] for m in api('tags',timeout=10)['models']}
                    if tags.get(ORIGINAL)!=ORIGINAL_DIGEST:raise ValueError('Original model digest changed')
                    break
                except (OSError,ValueError):
                    if time.monotonic()>deadline:raise
                    time.sleep(2)
            warm=api('generate',{'model':ORIGINAL,'keep_alive':'10m','options':{'num_ctx':8192}},timeout=90)
            if not warm.get('done'):raise RuntimeError('Original model warm-up incomplete')
            result.update(status='restored',original_model=ORIGINAL,original_digest=tags[ORIGINAL],completed_at_kst=now())
            run(['systemctl','stop',RESTORE_UNIT+'.timer'],check=False)
        except Exception as exc:
            result.update(status='restore_failed',error_type=type(exc).__name__,completed_at_kst=now())
            raise
        finally:save('restore.json',result)
    return result


def window(root,script):
    if (STATE/'window.json').exists():raise ValueError('Prior window receipt exists; no automatic retry')
    verify_ready(root)
    if run(['systemctl','is-active','ollama']).stdout.strip()!='active':raise ValueError('Ollama was not active before the window')
    tags={m['name']:m['digest'] for m in api('tags')['models']}
    if tags.get(ORIGINAL)!=ORIGINAL_DIGEST:raise ValueError('Original model identity mismatch')
    gpu=run(['nvidia-smi','--query-compute-apps=pid,process_name','--format=csv,noheader'])
    main_pid=int(run(['systemctl','show','-p','MainPID','--value','ollama']).stdout.strip())
    for line in gpu.stdout.splitlines():
        if ',' in line and not process_belongs_to(int(line.split(',')[0].strip()),main_pid):
            raise ValueError('Another GPU compute process is present')
    if any(line.startswith('capstone-qwen36-') for line in run(['docker','ps','--format','{{.Names}}']).stdout.splitlines()):
        raise ValueError('Another training stage is running')
    user=pwd.getpwuid(1000).pw_name
    job={'status':'prepared','mode':MODE,'started_at_kst':now(),'stages':list(STAGES),'deadline_seconds':LIMIT_SECONDS,
         'independent_restore_minutes':RESTORE_MINUTES,'original_digest':ORIGINAL_DIGEST};save('window.json',job)
    paused=False
    try:
        run(restore_command(script,root))
        if run(['systemctl','is-active',RESTORE_UNIT+'.timer']).stdout.strip()!='active':raise RuntimeError('Independent restore timer not active')
        job.update(status='training',pause_started_at_kst=now());save('window.json',job)
        paused=True
        run(['systemctl','stop','ollama'],timeout=45)
        deadline=time.monotonic()+LIMIT_SECONDS
        for stage in STAGES:
            job['stage']=stage;save('window.json',job)
            run(['runuser','-u',user,'--','/usr/bin/python3','-B',root/'finetuning/thor_container.py',stage,'--root',root],timeout=60)
            name='capstone-qwen36-'+stage
            while True:
                if time.monotonic()>deadline:raise TimeoutError('Reviewed training deadline reached')
                state=json.loads(run(['docker','inspect','--format','{{json .State}}',name]).stdout)
                if not state['Running']:
                    if state['ExitCode']!=0 or state.get('OOMKilled'):raise RuntimeError('Training stage failed')
                    if json.loads((root/(stage+'-status.json')).read_text())['status']!='completed':raise RuntimeError('Training completion receipt missing')
                    break
                time.sleep(2)
        job.update(status='training_completed',training_finished_at_kst=now())
    except BaseException as exc:
        job.update(status='training_failed',error_type=type(exc).__name__)
        raise
    finally:
        if paused:
            try:
                restore(root)
                job['status']+='_'+('restored')
                job['restored_at_kst']=now()
                if {m['name']:m['digest'] for m in api('tags')['models']}!=tags:job['model_registry_changed']=True
            except Exception as exc:job.update(recovery_error_type=type(exc).__name__)
        else:run(['systemctl','stop',RESTORE_UNIT+'.timer'],check=False)
        job['finished_at_kst']=now();save('window.json',job)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=['check','run','restore']);parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--mode',choices=['v2','memory-repro','memory-vmm','memory-trace','memory-loss'],default='v2');args=parser.parse_args();select_mode(args.mode)
    if args.action=='check':
        verify_ready(args.root.resolve());print(json.dumps({'ready':True,'no_service_action':True}));return
    script=Path(__file__).resolve()
    if os.geteuid()!=0 or script.stat().st_uid!=0 or stat.S_IMODE(script.stat().st_mode)&0o022:
        raise SystemExit('Use a root-owned inspected operator copy')
    if any(p.stat().st_uid!=0 or stat.S_IMODE(p.stat().st_mode)&0o022 for p in script.parents):
        raise SystemExit('Operator script parents must be root-owned and not writable by others')
    STATE.mkdir(mode=0o755,parents=True,exist_ok=True)
    if STATE.is_symlink() or STATE.stat().st_uid!=0 or stat.S_IMODE(STATE.stat().st_mode)&0o022:raise SystemExit('Unsafe operator state directory')
    def interrupted(signum,frame):raise InterruptedError('Operator window interrupted')
    if args.action=='run':
        signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
        window(args.root.resolve(),script)
    else:restore(args.root.resolve())


if __name__=='__main__':main()
