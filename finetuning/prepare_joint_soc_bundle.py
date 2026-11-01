"""Combine vetted source modules without converting evidence blocks into answers.

The executable SFT subset is explicitly separate from candidate/reference/eval
modules. A final joint training run remains disabled until its review gates pass.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import shutil
from collect_defensive_sources import sha, write, now
from prepare_guide_sft import canonical, org_split

ROOT=Path(__file__).resolve().parent


def rows(path):
    with path.open()as stream:return [json.loads(line)for line in stream if line.strip()]
def dump(path,values):path.write_text(''.join(canonical(x)+'\n'for x in values))


def prepare_sft(output):
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    candidates=ROOT/'data-guide-candidates-20261101-r1';prior=ROOT/'data-guide-mixed-20261101-r1'
    ledger=json.loads((ROOT/'GUIDE_ADMISSION_20261101.json').read_text())
    review=json.loads((candidates/'review.json').read_text());old=json.loads((prior/'manifest.json').read_text())
    if old!=ledger['admission']:raise ValueError('Prior training admission ledger mismatch')
    if sha((candidates/'review.json').read_bytes())!=old['candidate_review_sha256']:raise ValueError('GUIDE review changed')
    for name,h in review['files'].items():
        if sha((candidates/name).read_bytes())!=h:raise ValueError('GUIDE candidate changed')
    lineage={r['id']:r for r in rows(candidates/'source-lineage.jsonl')}
    train=[];orgs={s:set()for s in ('train','validation','test')}
    for split in orgs:
        for row in rows(candidates/(split+'.candidates.jsonl')):
            item=lineage[row['id']];target=json.loads(row['messages'][-1]['content']);features=json.loads(row['messages'][1]['content'].split('\n',1)[1])
            if (item['split']!=split or org_split(item['organization'])!=split or
                item['target_value']!=target.get('classification')or sha(canonical(features).encode())!=item['input_sha256']or
                item['source_rows']!=item['represented_rows']or features['observed_rows']!=sum(r['count']for r in features['observations'])):
                raise ValueError('GUIDE source lineage mismatch')
            orgs[split].add(item['organization'])
            if split=='train':train.append(row)
    if any(orgs[a]&orgs[b]for a,b in (('train','test'),('train','validation'),('validation','test'))):raise ValueError('GUIDE organization leakage')
    prior_counts={};allsets={}
    for split in ('train','validation','test'):
        path=prior/(split+'.jsonl')
        if sha(path.read_bytes())!=old['outputs'][split]['sha256']:raise ValueError('Prior training split changed')
        original=rows(path)
        if split=='train':
            replay=[r for r in original if not r['id'].startswith('guide-v2-')];selected=replay+train;prior_counts['replay']=len(replay)
        else:selected=original
        allsets[split]=selected;dump(output/(split+'.candidates.jsonl'),selected)
    allids=[r['id']for vals in allsets.values()for r in vals]
    if len(allids)!=len(set(allids)):raise ValueError('Duplicate IDs across splits')
    # Exact messages excluding assistant target; conflicting target copies also fail.
    fingerprints={s:{sha(canonical(r['messages'][:-1]).encode())for r in rs}for s,rs in allsets.items()}
    if any(fingerprints[a]&fingerprints[b]for a,b in (('train','test'),('train','validation'),('validation','test'))):raise ValueError('SFT input leakage')
    for p in prior.iterdir():
        if p.is_file()and p.name not in ('train.jsonl','validation.jsonl','test.jsonl','manifest.json'):shutil.copyfile(p,output/p.name)
    shutil.copyfile(candidates/'source-lineage.jsonl',output/'all-guide-source-lineage.jsonl')
    report={'at_kst':now(),'status':'source_verified_waiting_fresh_cpu_token_check','candidate_counts':{s:len(r)for s,r in allsets.items()},
            'guide_train_candidates':len(train),'prior_replay':prior_counts['replay'],'provider_test_training_records':0,
            'prior_evaluation_preserved':True,'guide_organization_overlap':0,'cross_split_exact_message_overlap':0,
            'source_candidate_review_sha256':sha((candidates/'review.json').read_bytes()),'prior_admission_sha256':sha((prior/'manifest.json').read_bytes()),
            'ready_for_gpu_training':False,'quality_passed':False}
    write(output/'preparation.json',report);return report


def admit_sft(output, token_report):
    output=Path(output);check=json.loads(Path(token_report).read_text());data=[]
    for split in ('train','validation','test'):
        for r in rows(output/(split+'.candidates.jsonl')):data.append({'split':split,'row':r})
    payload=''.join(canonical(x)+'\n'for x in data).encode()
    if sha(payload)!=check['input_sha256']or check['max_length']!=4096 or check['truncation']:raise ValueError('Token check input mismatch')
    actual={(x['split'],x['id']):x for x in check['records']}
    if len(actual)!=len(data)or len(check['records'])!=len(data):raise ValueError('Token report coverage mismatch')
    rejected=[];by_split={s:[]for s in ('train','validation','test')};maximum={s:0 for s in by_split}
    for item in data:
        r=item['row'];s=item['split'];v=actual[(s,r['id'])]
        if v['reason']:rejected.append(v);continue
        if not isinstance(v['tokens'],int)or not 0<v['tokens']<=4096:raise ValueError('Invalid token count')
        maximum[s]=max(maximum[s],v['tokens']);by_split[s].append(r)
    if any(x['split']!='train'or x['reason']!='over_max_length'for x in rejected):raise ValueError('Unexpected token admission failure')
    outputs={}
    for s,rs in by_split.items():
        p=output/(s+'.jsonl');dump(p,rs);outputs[s]={'records':len(rs),'sha256':sha(p.read_bytes()),'max_tokens':maximum[s]}
    dump(output/'fresh-token-rejections.jsonl',rejected)
    report={**json.loads((output/'preparation.json').read_text()),'status':'source_and_fresh_cpu_token_verified_expanded_subset',
            'at_kst':now(),'outputs':outputs,'guide_train_records':sum(r['id'].startswith('guide-v2-')for r in by_split['train']),
            'guide_class_counts':dict(Counter(json.loads(r['messages'][-1]['content'])['classification']for r in by_split['train']if r['id'].startswith('guide-v2-'))),
            'token_rejected':len(rejected),'token_report_sha256':sha(Path(token_report).read_bytes()),
            'mcp_execution_trajectories':0,'training_started':False,
            'limitations':['GUIDE is retrospective analyst-labelled triage; not action success or live evidence.',
                'Expanded subset is class-imbalanced. Final mixture weighting/length/runtime and independent quality gate remain.',
                'Old validation/test remain development regression, not a fresh unseen performance claim.']}
    write(output/'MANIFEST.json',report);return report


def assemble(output,sft,events):
    output=Path(output);output.mkdir(parents=True,exist_ok=False);sft=Path(sft);events=Path(events)
    sft_report=json.loads((sft/'MANIFEST.json').read_text());event_report=json.loads((events/'MANIFEST.json').read_text())
    modules={};sources=[('sft',sft),('event-evidence',events),('investigation',ROOT/'data-investigation-clean-20261101-r2')]
    for name,path in sources:
        dest=output/name;dest.mkdir()
        manifest=json.loads((path/'MANIFEST.json').read_text())
        declared=manifest.get('files',{})
        entries=((x['path'],x)for x in declared)if isinstance(declared,list)else declared.items()
        for rel,h in entries:
            expected=h['sha256']if isinstance(h,dict)else h
            if sha((path/rel).read_bytes())!=expected:raise ValueError('Module manifest mismatch: '+name)
        for file in sorted(path.iterdir()):
            if not file.is_file()or file.name.endswith('.candidates.jsonl')or file.name in ('transfer-receipt.json','TRANSFER_MANIFEST.json','preparation.json'):continue
            shutil.copyfile(file,dest/file.name)
        modules[name]={'manifest_sha256':sha((dest/'MANIFEST.json').read_bytes())}
    old=ROOT/'data-source-expansion-20261101-r1';dest=output/'regression-reference';dest.mkdir()
    review=json.loads((old/'review/review-summary.json').read_text())
    for n,h in review['output_sha256'].items():
        if sha((old/'review'/n).read_bytes())!=h:raise ValueError('Prior review changed')
    regress=rows(old/'review/regression-records.jsonl');counts={}
    for split,part in [('train','training_candidate'),('eval','reserved_evaluation')]:
        selected=[r for r in regress if not r['reasons']and r['provisional_partition']==part]
        dump(dest/('regression-'+split+'.jsonl'),selected);counts[split]=dict(Counter(r['source']for r in selected))
    dump(dest/'exclusions.jsonl',[{'id':r['id'],'reasons':r['reasons']}for r in regress if r['reasons']])
    shutil.copyfile(old/'review/knowledge-records.jsonl',dest/'knowledge-reference.jsonl')
    # Include pinned definitions/decoders and notices; no scripts, package blobs or old archives.
    acq=json.loads((old/'acquisition.json').read_text())
    for item in acq['files']:
        n=item['path'];key=item['source']
        if (Path(n).name.startswith(('LICENSE','NOTICE'))or key=='crs'and n.startswith('rules/')or key=='wazuh'and n.endswith('.xml')):
            p=old/'raw'/key/n
            if sha(p.read_bytes())!=item['sha256']:raise ValueError('Reference definition changed')
            target=dest/'source-definitions'/key/n;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,target)
    write(dest/'MANIFEST.json',{'scope':'provider regression assertions and official references; not executed engine outcomes',
          'counts':counts,'references':review['knowledge_units'],'training_admitted':0,'ready_for_gpu_training':False,
          'source_review_sha256':sha((old/'review/review-summary.json').read_bytes())})
    modules['regression-reference']={'manifest_sha256':sha((dest/'MANIFEST.json').read_bytes())}
    cti=ROOT/'data-joint-expansion-20261101-r3/raw/cti_realm';dest=output/'cti-eval-reserved';dest.mkdir()
    import yaml
    taskfile=cti/'domains/cti_realm/tasks/cti_realm_50/cti_realm_50.yaml';tasks=yaml.safe_load(taskfile.read_text())['tasks']
    if len(tasks)!=50 or len({r['task_id']for r in tasks})!=50:raise ValueError('Unexpected CTI release')
    # These are source evaluation definitions, not instruction-following SFT data.
    shutil.copyfile(taskfile,dest/'source-evaluation-tasks.yaml')
    for n in ('LICENSE','NOTICE.md'):shutil.copyfile(cti/n,dest/n)
    write(dest/'MANIFEST.json',{'source':'microsoft/ACESEvals','commit':'2c76fbdea415d6fa6a87bbad846686fefd6ee9bb',
          'unique_tasks':50,'training_records':0,'external_hf_data_collected':False,
          'status':'evaluation_definitions_only; execution and HF/third-party data reuse rights unresolved'})
    modules['cti-eval-reserved']={'manifest_sha256':sha((dest/'MANIFEST.json').read_bytes())}
    plan={'at_kst':now(),'ready_for_gpu_training':False,'automatic_training':False,'automatic_promotion':False,
          'sft_subset':{'train':sft_report['outputs']['train']['records'],'guide':sft_report['guide_train_records'],'replay':sft_report['prior_replay'],
                        'validation':sft_report['outputs']['validation']['records'],'test':sft_report['outputs']['test']['records'],'scope':'retrospective triage/evidence interpretation only'},
          'event_evidence':event_report['observation_blocks'],'regression_candidates':counts,
          'cti_eval_reserved':50,'remaining_gates':['Event/case causal and privacy review; source-specific labelling; historical/semantic overlap.',
              'Current MCP schema and multi-turn evidence/approval/postcheck/rollback supervision with verifiable execution evidence.',
              'Final sample mix weights and token/runtime budget; new modules must pass actual tokenizer and critical-error quality checks.',
              'Independent evaluation before a reviewed training run; no service interruption authorized by this collection.'],
          'do_not_sum_units':'SFT conversations, evidence blocks, regression fixtures, reference sections and eval tasks are different units.'}
    write(output/'BATCH-PLAN.json',plan)
    (output/'README.md').write_text('# SOC 통합 준비 묶음\n\nSFT 부분집합은 `sft/train.jsonl`이며 새 GPU 학습은 시작하지 않았다. 다른 폴더는 근거/후보/평가 정의로 학습 loader에 자동 연결하지 않는다. `BATCH-PLAN.json`의 미완료 검수를 통과한 모듈을 최종 조합한 뒤 한번의 학습 실행을 준비한다. 관측 블록 수를 독립 사건이나 정답 대화 수로 더하지 않는다.\n')
    for name in ('JOINT_SOURCE_SPEC.json','GUIDE_ADMISSION_20261101.json','DEFENSIVE_SOURCE_REVIEW.json','INVESTIGATION_SOURCE_REVIEW.json'):shutil.copyfile(ROOT/name,output/name)
    manifest={'at_kst':now(),'modules':modules,'ready_for_gpu_training':False,'files':{
        str(p.relative_to(output)):{'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())}for p in sorted(output.rglob('*'))if p.is_file()}}
    write(output/'MANIFEST.json',manifest)
    return {'files':len(manifest['files']),'bytes':sum(x['bytes']for x in manifest['files'].values()),'plan':plan}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--phase',choices=('prepare-sft','admit-sft','assemble'),required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--token-report',type=Path);p.add_argument('--sft',type=Path);p.add_argument('--events',type=Path);a=p.parse_args()
    result=prepare_sft(a.output)if a.phase=='prepare-sft'else admit_sft(a.output,a.token_report)if a.phase=='admit-sft'else assemble(a.output,a.sft,a.events)
    print(json.dumps(result,ensure_ascii=False))
