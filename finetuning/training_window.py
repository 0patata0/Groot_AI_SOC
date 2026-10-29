"""Operator-only bounded training window with independent systemd restoration.

Install an inspected, root-owned copy before running. This is never an MCP tool
or LLM sudo permission. It does not merge, register, select or promote a model.
"""
import argparse
from datetime import datetime
import fcntl
import hashlib
import json
import math
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
# Source attribution and technical input checks do not validate authored gold
# answers. These unexecuted plans are withdrawn pending corpus/label rework.
UNRELEASED_SOC_MODES=frozenset({'v3','v4-full'})
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
    elif mode=='v3':
        STAGES=('soc-v3-smoke','soc-v3-pilot');STATE=Path('/var/lib/capstone-training-v3-window')
        LIMIT_SECONDS=75*60;RESTORE_MINUTES=80;RESTORE_UNIT='capstone-soc-v3-restore'
    elif mode=='v5':
        STAGES=('soc-v5-smoke','soc-v5-train');STATE=Path('/var/lib/capstone-training-v5-r6-window')
        LIMIT_SECONDS=245*60;RESTORE_MINUTES=250;RESTORE_UNIT='capstone-soc-v5-r6-restore'
    elif mode=='v4-full':
        STAGES=('soc-v4-full-smoke','soc-v4-full-train');STATE=Path('/var/lib/capstone-training-v4-full-window')
        LIMIT_SECONDS=165*60;RESTORE_MINUTES=170;RESTORE_UNIT='capstone-soc-v4-full-restore'
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
    if MODE in UNRELEASED_SOC_MODES:
        raise ValueError('Training release withheld: project-authored gold answers lack independent validation; rework corpus before training')
    if MODE=='v5':return verify_v5_ready(root)
    if MODE=='v4-full':return verify_v4_full_ready(root)
    if MODE=='v3':return verify_v3_ready(root)
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


V3_DATA_HASHES={'train':'b2110b772aa0e3d8c7f40da4fd2e4d41a5f9a50ff99fc649e30c13c95b43e484',
    'validation':'919ffd74b36aaa0d9c6ebd16e7735b7cef15db539c9ac7b7cf195108f4cc4812',
    'test':'0873bc148ca2ccab683df1c53a4460cd6a1861736b54afeb9bd0379093a2e8c5'}

def verify_v3_ready(root):
    hashes=V3_DATA_HASHES
    expected_profile='a36f7158b035baa9156f6350af0c79535152e499a9f425f11669e89f653466a4'
    if hashlib.sha256((root/'finetuning/config.qwen36-soc-v3.json').read_bytes()).hexdigest()!=expected_profile:
        raise ValueError('Frozen v3 profile checksum mismatch')
    for split,digest in hashes.items():
        if hashlib.sha256((root/'finetuning/data-soc-operator-v3-r1'/(split+'.jsonl')).read_bytes()).hexdigest()!=digest:
            raise ValueError('Frozen v3 corpus mismatch')
    proof=json.loads((root/'soc-v3-tokenization/tokenization_report.json').read_text())
    checks=json.loads((root/'soc-v3-tokenization/data_check.json').read_text())
    if proof.get('max_length')!=4096 or proof.get('require_all_prefixes') is not True or checks.get('sha256')!=hashes:
        raise ValueError('Strict v3 tokenization proof required')
    for split,count in [('train',696),('validation',168),('test',168)]:
        if proof[split].get('candidate_turns')!=count or proof[split].get('kept')!=count:
            raise ValueError('Required v3 prefixes excluded')
    sources={'cases':root/'finetuning/data-soc-source-operator-v3-r1/cases.jsonl','catalog':root/'finetuning/mcp_contract.json'}
    frozen=json.loads((root/'soc-v3-evaluation/frozen-plan.json').read_text())
    for key,path in sources.items():
        if hashlib.sha256(path.read_bytes()).hexdigest()!=frozen[key+'_sha256']:raise ValueError('v3 baseline source mismatch')
    job=json.loads((root/'soc-v3-evaluation/base-development-v2-job.json').read_text())
    report=json.loads((root/'soc-v3-evaluation/base-development-v2.json').read_text())
    if job.get('status')!='completed' or not job.get('original_warm_done') or report.get('status')!='completed':
        raise ValueError('Completed v3 development baseline and original warm-up required')
    for stage in STAGES:
        if (root/(stage+'-status.json')).exists() or (root/'outputs'/stage).exists():
            raise ValueError('Prior v3 training evidence exists; automatic retry forbidden')


V4_FULL_INPUTS_SHA256='2be7f3f32288a814944dfd8932d783500f29c1fa49e770c595819de2eff3ec83'
V5_INPUTS_SHA256='33754a20cabf032a51bfde8b4bcea29dcf0a3da5527818ba8b15cec93c4c428a'


def verify_v5_ready(root):
    """Pinned provider-labelled inputs, no calls to services during checking."""
    folder=root/'finetuning';raw=(folder/'V5_TRAINING_INPUTS.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=V5_INPUTS_SHA256:raise ValueError('Frozen V5 inputs differ')
    frozen=json.loads(raw)
    if frozen.get('gold_derivation')!='original_provider_labels' or frozen.get('project_authored_incident_scenarios')!=0:
        raise ValueError('V5 source-label release required')
    checks=[(folder/frozen['profile'],frozen['profile_sha256']),
            (folder/frozen['source_cases'],frozen['source_cases_sha256']),
            (folder/'V5_EVIDENCE_SPEC.json',frozen['spec_file_sha256'])]
    checks.extend((folder/name,digest) for name,digest in frozen['source_sha256'].items())
    checks.extend((folder/frozen['data_folder']/(split+'.jsonl'),digest) for split,digest in frozen['data_sha256'].items())
    for path,digest in checks:
        if path.is_symlink() or not path.resolve().is_relative_to(folder.resolve()) or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
            raise ValueError('Frozen V5 source/corpus mismatch')
    audit_path=folder/frozen['data_folder']/'independent-source-audit.json'
    if hashlib.sha256(audit_path.read_bytes()).hexdigest()!=frozen['source_audit_sha256']:raise ValueError('V5 source proof differs')
    audit=json.loads(audit_path.read_text())
    if audit.get('status')!='passed' or audit.get('records')!=frozen['records'] or audit.get('cross_split_shared_reports_or_groups_or_identical_observations')!=0:
        raise ValueError('V5 original source proof incomplete')
    profile=json.loads((folder/frozen['profile']).read_text())
    if (profile['max_steps'],profile['gradient_accumulation_steps'],profile['num_train_epochs'],profile['learning_rate'])!=(512,2,1,5e-7):
        raise ValueError('Reviewed full-epoch V5 plan changed')
    if frozen.get('prior_attempt'):
        prior = frozen['prior_attempt']; prior_path = root/prior['window_path']
        if hashlib.sha256(prior_path.read_bytes()).hexdigest()!=prior['window_sha256'] or profile.get('gradient_checkpointing') is not frozen.get('planned_gradient_checkpointing'):
            raise ValueError('Reviewed V5 execution optimization differs')
        receipt = json.loads(prior_path.read_text())
        if receipt.get('status')!='training_failed_restored' or receipt.get('stage')!='soc-v5-smoke' or receipt.get('error_type')!='TimeoutError':
            raise ValueError('Prior bounded smoke must have restored the original model')
        elapsed = (datetime.fromisoformat(receipt['restored_at_kst'])-datetime.fromisoformat(receipt['pause_started_at_kst'])).total_seconds()
        for other in frozen.get('additional_prior_attempts', []):
            path=root/other['window_path']
            if hashlib.sha256(path.read_bytes()).hexdigest()!=other['window_sha256']:
                raise ValueError('Prior retry receipt differs')
            row=json.loads(path.read_text())
            if row.get('status')!='training_failed_restored' or row.get('stage')!='soc-v5-smoke':
                raise ValueError('Prior retry did not restore the original model')
            elapsed+=(datetime.fromisoformat(row['restored_at_kst'])-datetime.fromisoformat(row['pause_started_at_kst'])).total_seconds()
        budget=frozen.get('total_planned_outage_seconds',frozen['total_approved_outage_seconds'])
        if elapsed+(RESTORE_MINUTES+6)*60>budget:
            raise ValueError('Combined old and new restoration bounds exceed the reviewed interruption plan')
    proof=json.loads((root/'soc-v5-tokenization/tokenization_report.json').read_text());data=json.loads((root/'soc-v5-tokenization/data_check.json').read_text())
    if proof.get('loss')!='all_assistant_turns_per_conversation' or proof.get('require_all_prefixes') is not True or proof.get('max_length')!=profile['max_length'] or data.get('sha256')!=frozen['data_sha256']:
        raise ValueError('V5 all-assistant token proof differs')
    for split,count in frozen['records'].items():
        row=proof[split]
        if (row.get('kept'),row.get('candidate_examples'),row.get('covered_assistant_turns'),row.get('candidate_turns'))!=(count,)*4:
            raise ValueError('V5 observations or target turns excluded')
    evaluation=root/'soc-evidence-v5-evaluation';plan=json.loads((evaluation/'frozen-plan.json').read_text())
    if hashlib.sha256((evaluation/'frozen-plan.json').read_bytes()).hexdigest()!=frozen['development_plan_sha256']:raise ValueError('V5 development plan differs')
    job=json.loads((evaluation/'baseline-job.json').read_text());report=json.loads((evaluation/'base-evidence-development.json').read_text());operator=json.loads((evaluation/'base-operator-development.json').read_text())
    if job.get('status')!='completed' or job.get('original_warm_done') is not True or report.get('status')!='completed' or operator.get('status')!='completed':
        raise ValueError('Completed V5 and operator baselines and original restoration required')
    ids=[r['case_id'] for r in report['results']]
    if len(ids)!=32 or len(ids)!=len(set(ids)) or ids!=plan['case_ids'] or report.get('validation_sha256')!=frozen['data_sha256']['validation']:
        raise ValueError('V5 development baseline incomplete')
    if report.get('model_digest')!=frozen['HF_control_digest']:raise ValueError('V5 control model changed')
    if operator.get('source_cases_sha256')!=frozen['operator_cases_sha256'] or operator.get('catalog_sha256')!=frozen['operator_catalog_sha256'] or len(operator['results'])!=12:
        raise ValueError('Operator regression baseline differs')
    for stage in STAGES:
        if (root/(stage+'-status.json')).exists() or (root/'outputs'/stage).exists():raise ValueError('Prior V5 training evidence; no automatic retry')

def verify_v4_full_ready(root):
    raw=(root/'finetuning/V4_TRAINING_INPUTS.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=V4_FULL_INPUTS_SHA256:raise ValueError('Frozen full-training inputs changed')
    frozen=json.loads(raw);folder=root/'finetuning'
    checks=[(folder/frozen['profile'],frozen['profile_sha256']),
            (folder/frozen['source_cases'],frozen['source_cases_sha256']),
            (folder/'mcp_contract.json',frozen['catalog_sha256'])]
    checks.extend((folder/name,digest) for name,digest in frozen['source_sha256'].items())
    checks.extend((folder/frozen['data_folder']/(split+'.jsonl'),digest) for split,digest in frozen['data_sha256'].items())
    for path,digest in checks:
        if path.is_symlink() or not path.resolve().is_relative_to(folder.resolve()) or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
            raise ValueError('Frozen full-training source/corpus mismatch')
    proof=json.loads((root/'soc-v4-full-tokenization/tokenization_report.json').read_text())
    data=json.loads((root/'soc-v4-full-tokenization/data_check.json').read_text())
    if proof.get('max_length')!=4096 or proof.get('loss')!='all_assistant_turns_per_conversation' or proof.get('require_all_prefixes') is not True:
        raise ValueError('Strict all-assistant tokenization proof required')
    if data.get('sha256')!=frozen['data_sha256']:raise ValueError('Full tokenization proof uses different corpus')
    for split,rows in frozen['records'].items():
        row=proof[split];turns=frozen['assistant_turns'][split]
        if (row.get('kept'),row.get('candidate_examples'),row.get('candidate_turns'),row.get('covered_assistant_turns'))!=(rows,rows,turns,turns):
            raise ValueError('Full-conversation examples or assistant targets excluded')
    probe=json.loads((root/'soc-v4-dialogue-probe.json').read_text())
    if probe.get('status')!='passed' or probe.get('tests_returncode')!=0:raise ValueError('Real tokenizer/loss CPU probe required')
    evaluation=root/'soc-v4-evaluation';job=json.loads((evaluation/'base-development-job.json').read_text());report=json.loads((evaluation/'base-development.json').read_text());plan=json.loads((evaluation/'frozen-plan.json').read_text())
    if job.get('status')!='completed' or not job.get('original_warm_done') or report.get('status')!='completed':raise ValueError('Completed full-training development baseline required')
    if report.get('source_cases_sha256')!=frozen['source_cases_sha256'] or report.get('catalog_sha256')!=frozen['catalog_sha256']:
        raise ValueError('Development baseline source mismatch')
    ids=[r['case_id'] for r in report['results']]
    if len(ids)!=len(set(ids)) or set(ids)!=set(plan['case_ids']) or set(ids)!=set(frozen['development_case_ids']):raise ValueError('Incomplete development baseline cases')
    if plan.get('evaluation_code_sha256')!=frozen['development_evaluation_code_sha256']:raise ValueError('Development evaluation code differs from frozen plan')
    for stage in STAGES:
        if (root/(stage+'-status.json')).exists() or (root/'outputs'/stage).exists():raise ValueError('Prior full-training evidence; automatic retry forbidden')


def full_window_estimate(root,mode='v4-full'):
    """Use measured longest smoke microbatches; deadline remains authoritative."""
    if mode not in ('v4-full','v5'):raise ValueError('Unsupported full-epoch mode')
    prefix='soc-v5' if mode=='v5' else 'soc-v4-full'
    folder=root/'outputs'/(prefix+'-smoke')
    rows=list(map(json.loads,(folder/'successful_microbatch_lineage.jsonl').read_text().splitlines()))
    if len(rows)!=2:raise ValueError('Two real longest smoke backward passes required')
    seconds=(datetime.fromisoformat(rows[1]['at_kst'])-datetime.fromisoformat(rows[0]['at_kst'])).total_seconds()
    if not 0<seconds<3600:raise ValueError('Invalid measured smoke interval')
    proof=json.loads((root/(prefix+'-tokenization')/'tokenization_report.json').read_text());train=proof['train'];evaluation=json.loads((folder/'eval_results.json').read_text())
    ratio=min(1.0,train['tokens']/train['kept']/train['max_tokens'])
    # Smoke uses accumulation1 at longest inputs; main accumulation2 at the
    # full measured length mix. Include evaluation/loading/saving headroom.
    eval_count=128 if mode=='v5' else 94;eval_passes=2 if mode=='v5' else 1
    estimate=seconds*train['kept']*ratio*1.25+evaluation['eval_runtime']/8*eval_count*eval_passes*1.25+300
    result={'estimated_main_seconds':round(estimate,1),'longest_microbatch_interval_seconds':round(seconds,3),'length_ratio':round(ratio,4),'scope':'planning estimate, not completion or latency guarantee'}
    if mode=='v5':result['smoke_reference_check']=verify_v5_smoke_equivalence(root)
    return result


def verify_v5_smoke_equivalence(root):
    frozen=json.loads((root/'finetuning/V5_TRAINING_INPUTS.json').read_text())
    prior=frozen.get('prior_attempt')
    if not prior:return {'scope':'initial smoke, no prior comparison'}
    old=root/prior['smoke_path'];new=root/'outputs/soc-v5-smoke'
    if json.loads((new/'run_manifest.json').read_text())['config'].get('gradient_checkpointing') is not frozen.get('planned_gradient_checkpointing',False):
        raise ValueError('Smoke used a different checkpointing policy')
    def identities(folder):
        return [r['prefixes'] for r in map(json.loads,(folder/'successful_microbatch_lineage.jsonl').read_text().splitlines())]
    if len(identities(new))!=2 or identities(new)!=identities(old):
        raise ValueError('Optimized smoke changed original input or supervised targets')
    metrics={}
    for name,key in [('train_results.json','train_loss'),('eval_results.json','eval_loss')]:
        a=json.loads((old/name).read_text())[key];b=json.loads((new/name).read_text())[key]
        if not math.isfinite(b) or not math.isclose(a,b,rel_tol=1e-3,abs_tol=1e-4):
            raise ValueError('Optimized smoke loss differs from the original computation')
        metrics[key]={'reference':a,'candidate':b}
    return {'same_two_inputs_and_target_tokens':True,'loss_consistent_within_relative_1e_3_absolute_1e_4':True,
            'adapter_bytes_identical':hashlib.sha256((old/'adapter/adapter_model.safetensors').read_bytes()).digest()==hashlib.sha256((new/'adapter/adapter_model.safetensors').read_bytes()).digest(),
            'metrics':metrics,'planned_gradient_checkpointing':frozen.get('planned_gradient_checkpointing',False),
            'scope':'actual smoke equivalence check; not a full training quality result'}


def restore_command(script,root):
    args=['systemd-run','--unit='+RESTORE_UNIT,'--on-active='+str(RESTORE_MINUTES)+'m',
          '--timer-property=AccuracySec=1s']
    if MODE in ('v3','v5','v4-full','memory-repro','memory-vmm','memory-trace','memory-loss'):args+=['--property=Type=oneshot','--property=TimeoutStartSec=6min']
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
    if MODE=='v5':
        frozen=json.loads((root/'finetuning/V5_TRAINING_INPUTS.json').read_text())
        if frozen.get('total_planned_outage_seconds',frozen['total_approved_outage_seconds'])>frozen['total_approved_outage_seconds']:
            raise ValueError('Extended shared interruption has not been approved; no service action')
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
            if MODE in ('v4-full','v5') and stage==STAGES[-1]:
                estimate=full_window_estimate(root,MODE);job['smoke_estimate']=estimate;save('window.json',job)
                if estimate['estimated_main_seconds']>deadline-time.monotonic():raise TimeoutError('Measured full training would exceed reviewed window')
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
    parser.add_argument('--mode',choices=['v2','v3','v5','v4-full','memory-repro','memory-vmm','memory-trace','memory-loss'],default='v2');args=parser.parse_args();select_mode(args.mode)
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
