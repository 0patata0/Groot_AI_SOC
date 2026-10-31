"""Prepare a new main-only run from the exact successful R1 smoke, no services.

Run by the operator on Thor. Never modifies the earlier attempt or its receipts.
"""
import argparse,hashlib,json,os,shutil
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo
import durable_training_window as w

def prepare(previous,output):
    w.require(previous.name=='soc-evidence-20261031-r1' and output.name=='soc-evidence-20261031-r2' and output.parent==previous.parent,'Fixed sibling runs required')
    w.require(not output.exists(),'Do not overwrite retry evidence')
    w.select_run(previous.name);old=w.verify_bundle(previous)
    state=Path('/var/lib/capstone-soc-evidence-20261031-r1');job=w.load(state/'window.json')
    w.require(job['status']=='training_failed_restored' and job['stage']=='smoke','Previous attempt not safely restored')
    evidence=['smoke-status.json','smoke/train_results.json','smoke/eval_results.json','smoke/run_manifest.json',
              'smoke/progress.json','smoke/successful_microbatch_lineage.jsonl','smoke/memory_telemetry.jsonl',
              'tokenize-status.json','tokenization/tokenization_report.json','tokenization/data_check.json','base-recheck.json']
    files={**old['files'],**{n:w.sha(previous/n) for n in evidence}}
    output.mkdir(mode=0o700);os.chown(output,1000,1000)
    for name,digest in files.items():
        w.require(w.sha(previous/name)==digest,'Prior source changed')
        target=output/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(previous/name,target);target.chmod(0o444)
    elapsed=(datetime.fromisoformat(job['restored_at_kst'])-datetime.fromisoformat(job['pause_started_at_kst'])).total_seconds()
    ref={'previous_run':previous.name,'files':files,'prior_window_sha256':w.sha(state/'window.json'),
         'prior_restore_sha256':w.sha(state/'restore.json'),'prior_outage_seconds':elapsed,'reason':'Correct timing estimator; reuse successful identical-source smoke, start main from original base'}
    p=output/'smoke-reference.json';p.write_text(json.dumps(ref,indent=2)+'\n');p.chmod(0o444);files['smoke-reference.json']=w.sha(p)
    release={**old,'run_id':output.name,'created_at_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),
             'train_limit_seconds':235*60,'independent_restore_minutes':240,'cumulative_interruption_limit_seconds':255*60,
             'prior_outage_seconds':elapsed,'files':files}
    p=output/'release.json';p.write_text(json.dumps(release,ensure_ascii=False,sort_keys=True,indent=2)+'\n');p.chmod(0o444)
    w.select_run(output.name);w.verify_bundle(output);return {'release_sha256':w.sha(p),'estimate':w.estimate_main(output),'prior_outage_seconds':elapsed}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--previous',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(json.dumps(prepare(a.previous.resolve(),a.output.resolve()),indent=2))
