"""Operator-only, pinned evidence run. SSH is not the supervisor.

Install this file and training_window.py in a root-owned, non-writable directory.
The systemd service owns the run; a separate timer restores original inference.
No model promotion, package installation, driver change or chat posting occurs.
"""
import argparse
from collections import Counter
from datetime import datetime
import fcntl,hashlib,json,math,os,pwd,signal,stat,struct,subprocess,time
from pathlib import Path
import training_window as recovery

RUN_ID='soc-evidence-20261031-r1'
IMAGE='nvcr.io/nvidia/pytorch@sha256:ace9a848c0ae543317e3c4763b6b4248961c47902625abfe3c77a0fb931c50fb'
UNIT='capstone-'+RUN_ID
STATE=Path('/var/lib/'+UNIT)
RESTORE=UNIT+'-restore'
LIMIT=240*60
RESTORE_MINUTES=245
STAGES=('smoke','main')
SOURCE_FILES={'train.py','model_profile.py','memory_budget.py','memory_telemetry.py',
              'bounded_loading.py','completion_loss.py','dialogue_encoding.py',
              'training_lineage.py','guarded_process.py','durable_training_task.py'}

def select_run(run_id):
    global RUN_ID,UNIT,STATE,RESTORE,LIMIT,RESTORE_MINUTES,STAGES
    require(run_id in ('soc-evidence-20261031-r1','soc-evidence-20261031-r2'),'Unknown fixed run')
    RUN_ID=run_id;UNIT='capstone-'+run_id;STATE=Path('/var/lib/'+UNIT);RESTORE=UNIT+'-restore'
    LIMIT=(235 if run_id.endswith('r2') else 240)*60
    RESTORE_MINUTES=240 if run_id.endswith('r2') else 245
    STAGES=('main',) if run_id.endswith('r2') else ('smoke','main')

def require(ok,message):
    if not ok:raise ValueError(message)
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def load(path):return json.loads(Path(path).read_text())
def now():return recovery.now()
def run(*args,**kwargs):return recovery.run(*args,**kwargs)
def save(name,value):recovery.save(name,value)
def available_bytes():
    return int(next(l.split()[1] for l in Path('/proc/meminfo').read_text().splitlines() if l.startswith('MemAvailable:')))*1024

def configure():
    recovery.STATE=STATE;recovery.STAGES=tuple(RUN_ID+'-'+s for s in STAGES)
    recovery.RESTORE_UNIT=RESTORE

def verify_bundle(root,require_tokens=True):
    release=load(root/'release.json')
    require(release['run_id']==RUN_ID and release['status']=='experimental_training_only','Unexpected release')
    require(release['training_rows']==191 and release['expected_optimizer_steps']==96,'Reviewed row/step plan changed')
    require(release['train_limit_seconds']==LIMIT and release['independent_restore_minutes']==RESTORE_MINUTES,'Restoration bound changed')
    require(release['automatic_promotion'] is False and release['guide_rows_admitted']==0 and release['optional_harness_rows_admitted']==0,'Unreviewed admission/promotion')
    require({p[7:] for p in release['files'] if p.startswith('source/')}==SOURCE_FILES,'Unexpected executable input')
    for name,digest in release['files'].items():
        p=root/name
        require(not p.is_symlink() and p.resolve().is_relative_to(root.resolve()) and sha(p)==digest,'Frozen input mismatch: '+name)
    if RUN_ID.endswith('r2'):verify_prior_smoke(root,release)
    cfg=load(root/'profiles/main.json')
    require((cfg['num_train_epochs'],cfg['max_steps'],cfg['gradient_accumulation_steps'],cfg['learning_rate'])==(1,-1,2,5e-7),'One-epoch numerical profile changed')
    require(cfg['max_train_samples']==cfg['max_eval_samples']==0 and cfg['require_all_prefixes'] is True,'Sample coverage changed')
    require(cfg['max_length']==4096 and cfg['loss_mode']=='all_assistant_turns' and cfg['assistant_only_logits'] is True,'Token/loss contract changed')
    require(cfg['deterministic_training'] is True and cfg['gradient_checkpointing'] is True and cfg['quantization']=='none','Execution profile changed')
    base=load(root.parents[1]/'base-manifest.json')
    require(base['verified'] is True and base['revision']==cfg['revision']==release['base_revision'],'Base revision differs')
    manifest=load(root/'data/manifest.json')
    for s in ('train','validation','test'):
        require(sha(root/'data'/(s+'.jsonl'))==manifest['outputs'][s]['sha256'],'Data manifest mismatch')
    if require_tokens:
        bp=load(root/'base-recheck.json');require(bp['status']=='passed' and bp['manifest_sha256']==sha(root.parents[1]/'base-manifest.json'),'Full base artifact verification missing')
        require(len(bp['files'])==len(base['files']),'Base proof incomplete')
        for item in bp['files']:
            p=root.parents[1]/'base'/item['path'];st=p.stat()
            require(not p.is_symlink() and p.resolve().is_relative_to((root.parents[1]/'base').resolve()) and (st.st_size,st.st_mtime_ns)==(item['size'],item['mtime_ns']),'Base changed after hashing')
        require(load(root/'tokenize-status.json')['status']=='completed','Actual tokenizer must complete')
        checks=load(root/'tokenization/data_check.json');proof=load(root/'tokenization/tokenization_report.json')
        require(checks['sha256']=={s:v['sha256'] for s,v in manifest['outputs'].items()},'Token proof corpus differs')
        require(proof['loss']=='all_assistant_turns_per_conversation' and proof['require_all_prefixes'] is True and proof['max_length']==4096,'Strict token proof required')
        for s,n in [('train',191),('validation',128),('test',128)]:
            row=proof[s]
            require(row['kept']==row['candidate_examples']==n and row['covered_assistant_turns']==row['candidate_turns'],'Example or assistant target omitted')
    return release

def verify_prior_smoke(root,release):
    reference=load(root/'smoke-reference.json');previous=root.parent/'soc-evidence-20261031-r1'
    require(reference['previous_run']=='soc-evidence-20261031-r1','Unexpected smoke origin')
    for name,digest in reference['files'].items():
        require(sha(previous/name)==digest==sha(root/name),'Smoke/input reference differs')
    prior_state=Path('/var/lib/capstone-soc-evidence-20261031-r1')
    require(sha(prior_state/'window.json')==reference['prior_window_sha256'] and sha(prior_state/'restore.json')==reference['prior_restore_sha256'],'Prior restoration receipt differs')
    job=load(prior_state/'window.json');restored=load(prior_state/'restore.json')
    require(job['status']=='training_failed_restored' and job['stage']=='smoke' and job['error']=='Measured epoch exceeds remaining bounded window','Unexpected prior termination')
    require(restored['status']=='restored' and restored['generation_probe']['generation_verified'] is True and job['original_registry_unchanged'] is True,'Prior original inference restoration missing')
    elapsed=(datetime.fromisoformat(job['restored_at_kst'])-datetime.fromisoformat(job['pause_started_at_kst'])).total_seconds()
    require(0<elapsed==reference['prior_outage_seconds'] and elapsed+249*60<=255*60,'Combined interruption would exceed 4h15')
    require(release['cumulative_interruption_limit_seconds']==255*60,'Combined interruption bound changed')
    require(load(root/'smoke-status.json')['status']=='completed','Prior smoke did not complete')
    old_cfg=load(root/'smoke/run_manifest.json')['config'];wanted=load(root/'profiles/smoke.json')
    require(all(old_cfg.get(k)==v for k,v in wanted.items()),'Smoke numerical settings differ')

def container_command(base,root,stage):
    require(stage in ('tokenize',*STAGES),'Unknown stage')
    gpu=stage!='tokenize';env={'PYTHONDONTWRITEBYTECODE':'1','HF_HUB_OFFLINE':'1','TRANSFORMERS_OFFLINE':'1',
        'HF_HUB_DISABLE_TELEMETRY':'1','HF_HUB_DISABLE_IMPLICIT_TOKEN':'1','TOKENIZERS_PARALLELISM':'false',
        'HF_DEACTIVATE_ASYNC_LOAD':'1','PYTORCH_CUDA_ALLOC_CONF':'expandable_segments:True',
        'HF_HOME':'/trial/cache/hf','XDG_CACHE_HOME':'/trial/cache','TRITON_CACHE_DIR':'/trial/cache/triton',
        'HOME':'/tmp','TZ':'Asia/Seoul','CUDA_VISIBLE_DEVICES':'0' if gpu else ''}
    args=['docker','run','-d','--pull=never','--name','capstone-qwen36-'+RUN_ID+'-'+stage,
          '--user','1000:1000','--cap-drop','ALL','--security-opt','no-new-privileges','--read-only',
          '--pids-limit','512','--cpus','10' if gpu else '4','--memory','112g' if gpu else '8g',
          '--memory-swap','112g' if gpu else '8g','--shm-size','1g','--network','none',
          '--tmpfs','/tmp:rw,nosuid,nodev,size=512m','--log-driver','local','--log-opt','max-size=10m','--log-opt','max-file=2',
          '--mount',f'type=bind,source={base},target=/workspace,readonly',
          '--mount',f'type=bind,source={root},target=/trial',
          '--mount',f'type=bind,source={root}/source,target=/trial/source,readonly',
          '--mount',f'type=bind,source={root}/data,target=/trial/data,readonly',
          '--mount',f'type=bind,source={root}/profiles,target=/trial/profiles,readonly',
          '--workdir','/trial/source']
    args+=['--gpus','device=0'] if gpu else ['--runtime=runc']
    for key,value in env.items():args+=['--env',key+'='+value]
    return args+['--entrypoint','/workspace/venv/bin/python',IMAGE,'-B','/trial/source/durable_training_task.py',stage]

def restore_command(script,root):
    return ['systemd-run','--unit='+RESTORE,'--on-active='+str(RESTORE_MINUTES)+'m','--timer-property=AccuracySec=1s',
            '--property=Type=oneshot','--property=TimeoutStartSec=6min','/usr/bin/python3','-B',script,'restore','--root',root]

def wait_stage(root,stage,deadline):
    name='capstone-qwen36-'+RUN_ID+'-'+stage
    while True:
        if time.monotonic()>deadline:raise TimeoutError('Training deadline reached')
        if os.statvfs(root).f_bavail*os.statvfs(root).f_frsize<12*2**30:raise RuntimeError('Disk reserve reached')
        state=json.loads(run(['docker','inspect','--format','{{json .State}}',name]).stdout)
        if not state['Running']:
            require(state['ExitCode']==0 and not state.get('OOMKilled'),'Stage exit/OOM failure')
            require(load(root/(stage+'-status.json'))['status']=='completed','Stage completion receipt missing')
            return state
        time.sleep(5)

def estimate_main(root):
    metrics=load(root/'smoke/train_results.json');evaluation=load(root/'smoke/eval_results.json')
    rows=[json.loads(l) for l in (root/'smoke/successful_microbatch_lineage.jsonl').read_text().splitlines()]
    require(len(rows)==2 and all(x['successful_forward_backward'] for x in rows),'Two successful longest-input microbatches required')
    require(len({x['prefixes'][0]['record_id'] for x in rows})==2,'Repeated smoke example')
    progress=load(root/'smoke/progress.json');require(progress['status']=='completed' and progress['step']==2,'Smoke optimizer completion missing')
    for m in (metrics,evaluation):require(all(not isinstance(v,(int,float)) or math.isfinite(v) for v in m.values()),'Nonfinite smoke metric')
    # train_runtime includes evaluation. Use first optimizer-completion records
    # for each step, before validation, and count evaluation exactly once.
    telemetry=[json.loads(l) for l in (root/'smoke/memory_telemetry.jsonl').read_text().splitlines()]
    times={}
    for event in telemetry:
        if event.get('phase')=='training' and event.get('step') in (0,1,2):
            times.setdefault(event['step'],datetime.fromisoformat(event['at_kst']))
    require(set(times)=={0,1,2},'Optimizer timing evidence incomplete')
    intervals=[(times[i]-times[i-1]).total_seconds() for i in (1,2)]
    require(all(math.isfinite(x) and x>0 for x in intervals),'Invalid optimizer timing')
    per_example=max(intervals)
    estimate=per_example*191*1.15+evaluation['eval_runtime']/8*128+300
    return {'estimated_main_seconds':estimate,'longest_example_seconds':per_example,
            'scope':'Worst measured longest-input optimizer step times all191 rows plus15% and one128-row evaluation, loading/save margin; not completion guarantee',
            'optimizer_step_seconds':intervals,'evaluation_counted_once':True,'observed_train_runtime':metrics['train_runtime']}

def verify_completion(root):
    progress=load(root/'main/progress.json');require(progress['status']=='completed' and progress['step']==96 and abs(progress['epoch']-1)<1e-6,'Full epoch not completed')
    expected={r['id']:r for r in map(json.loads,(root/'data/train.jsonl').read_text().splitlines())}
    rows=[json.loads(l) for l in (root/'main/successful_microbatch_lineage.jsonl').read_text().splitlines()]
    ids=[]
    for row in rows:
        require(row['successful_forward_backward'] and len(row['prefixes'])==1,'Invalid microbatch evidence')
        identity=row['prefixes'][0];rid=identity['record_id'];require(rid in expected,'Unexpected trained record')
        raw=json.dumps(expected[rid],ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
        require(hashlib.sha256(raw).hexdigest()==identity['record_sha256'],'Trained record differs')
        require(identity['supervised_assistant_indices']==[i for i,m in enumerate(expected[rid]['messages']) if m['role']=='assistant'],'Assistant turn omitted')
        ids.append(rid)
    require(len(rows)==191 and Counter(ids)==Counter(expected.keys()),'Training omission/duplication')
    for name in ('train_results.json','eval_results.json'):
        metrics=load(root/'main'/name);require(all(not isinstance(v,(int,float)) or math.isfinite(v) for v in metrics.values()),'Nonfinite final metrics')
    adapter=root/'main/adapter/adapter_model.safetensors'
    with adapter.open('rb') as f:
        length=struct.unpack('<Q',f.read(8))[0];require(length<2**20,'Unexpected adapter header');header=json.loads(f.read(length))
    tensors=[k for k in header if k!='__metadata__'];require(len(tensors)==380 and all('lora_' in k for k in tensors),'Adapter tensor scope differs')
    return {'status':'passed','rows':191,'optimizer_steps':96,'adapter_tensors':380,'adapter_sha256':sha(adapter),'quality_or_promotion_verified':False,'at_kst':now()}

def window(root,script):
    require(not (STATE/'window.json').exists(),'Prior window exists; no retry')
    release=verify_bundle(root)
    require(not any((root/s).exists() or (root/(s+'-status.json')).exists() for s in STAGES),'Prior outputs exist')
    require(os.statvfs(root).f_bavail*os.statvfs(root).f_frsize>=release['min_disk_free_bytes'],'Insufficient initial disk reserve')
    require(run(['systemctl','is-active','ollama']).stdout.strip()=='active','Original inference not active')
    require(run(['systemctl','is-enabled','ollama']).stdout.strip()=='enabled','Original inference boot recovery not enabled')
    tags={m['name']:m['digest'] for m in recovery.api('tags')['models']}
    require(tags.get(recovery.ORIGINAL)==recovery.ORIGINAL_DIGEST,'Original model identity changed')
    pid=int(run(['systemctl','show','-p','MainPID','--value','ollama']).stdout.strip())
    gpu=run(['nvidia-smi','--query-compute-apps=pid,process_name','--format=csv,noheader'])
    for line in gpu.stdout.splitlines():
        if ',' in line:require(recovery.process_belongs_to(int(line.split(',')[0]),pid),'Another GPU process is active')
    require(not any(n.startswith('capstone-qwen36-') for n in run(['docker','ps','--format','{{.Names}}']).stdout.splitlines()),'Another training stage active')
    job={'status':'prepared','started_at_kst':now(),'run_id':RUN_ID,'limit_seconds':LIMIT,'independent_restore_minutes':RESTORE_MINUTES,
         'input_release_sha256':sha(root/'release.json'),'original_registry':tags}
    save('window.json',job);paused=False
    try:
        run(restore_command(script,root))
        require(run(['systemctl','is-active',RESTORE+'.timer']).stdout.strip()=='active','Independent restoration not armed')
        job.update(status='training',pause_started_at_kst=now());save('window.json',job)
        paused=True;deadline=time.monotonic()+LIMIT
        run(['systemctl','stop','ollama'],timeout=45)
        memory_deadline=time.monotonic()+45
        while available_bytes()<96*2**30 and time.monotonic()<memory_deadline:time.sleep(2)
        require(available_bytes()>=96*2**30,'Post-stop host memory below 96GiB')
        job['post_stop_available_gib']=available_bytes()/2**30;save('window.json',job)
        for stage in STAGES:
            if stage=='main':
                job['estimate']=estimate_main(root);save('window.json',job)
                require(job['estimate']['estimated_main_seconds']<deadline-time.monotonic(),'Measured epoch exceeds remaining bounded window')
            job['stage']=stage;save('window.json',job)
            run(container_command(root.parents[1],root,stage),timeout=60)
            wait_stage(root,stage,min(deadline,time.monotonic()+900) if stage=='smoke' else deadline)
        job.update(status='training_completed',training_finished_at_kst=now())
    except BaseException as exc:
        job.update(status='training_failed',error_type=type(exc).__name__,error=str(exc));raise
    finally:
        if paused:
            try:
                recovery.restore(root);job['status']+='_restored';job['restored_at_kst']=now()
                job['original_registry_unchanged']=tags=={m['name']:m['digest'] for m in recovery.api('tags')['models']}
            except BaseException as exc:job.update(recovery_error_type=type(exc).__name__)
        else:run(['systemctl','stop',RESTORE+'.timer'],check=False)
        job['finished_at_kst']=now();save('window.json',job)
    if job['status']=='training_completed_restored':
        try:save('completion-verification.json',verify_completion(root))
        except BaseException as exc:
            save('completion-verification.json',{'status':'failed','error_type':type(exc).__name__,'at_kst':now()});raise

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('check','run','restore'));p.add_argument('--root',type=Path,required=True);a=p.parse_args();root=a.root.resolve();select_run(root.name);configure()
    require(root==Path(pwd.getpwuid(1000).pw_dir)/'Capstone_Groot_training/qwen36-20261027/runs'/RUN_ID,'Unexpected run root')
    script=Path(__file__).resolve()
    if a.action!='restore':require(sha(root/'release.json')==(script.parent/'release.sha256').read_text().strip(),'Root-approved release changed')
    if a.action=='check':print(json.dumps({'ready':bool(verify_bundle(root)),'no_service_action':True}));return
    for file in (script,script.parent/'training_window.py',*script.parents):
        require(file.stat().st_uid==0 and not stat.S_IMODE(file.stat().st_mode)&0o022,'Operator source/parents must be root-owned')
    require(os.geteuid()==0,'Root-owned operator service required')
    STATE.mkdir(mode=0o755,exist_ok=True)
    require(not STATE.is_symlink() and STATE.stat().st_uid==0 and not stat.S_IMODE(STATE.stat().st_mode)&0o022,'Unsafe state directory')
    if a.action=='restore':recovery.restore(root);return
    def interrupted(signum,frame):raise InterruptedError('Supervisor interrupted')
    signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
    fd=os.open('/run/lock/capstone-evidence-training.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);window(root,script)

if __name__=='__main__':main()
