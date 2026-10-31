"""Actual pinned-tokenizer admission and a bounded GUIDE/evidence training mix."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import shutil
import sys
from datetime import datetime
from zoneinfo import ZoneInfo
sys.path.insert(0,str(Path(__file__).resolve().parent))
from train import encode_completion, sha256_file
from dialogue_encoding import encode_dialogue

GRADES=('TruePositive','FalsePositive','BenignPositive')


def select_balanced(rows,total):
    selected=[]
    for index,grade in enumerate(GRADES):
        quota=total//3+(index<total%3)
        group=[r for r in rows if json.loads(r['messages'][-1]['content'])['classification']==grade]
        group.sort(key=lambda r:hashlib.sha256(('guide-admission-v1:'+r['id']).encode()).hexdigest())
        if len(group)<quota: raise ValueError('Insufficient token-eligible cases for class quota')
        selected.extend(group[:quota])
    return sorted(selected,key=lambda r:r['id'])


def main(candidates,evidence,base,output,train_count):
    from transformers import AutoTokenizer
    if train_count not in (128,192,256): raise ValueError('Choose a reviewed bounded pilot size')
    review=json.loads((candidates/'review.json').read_text())
    if review['status']!='candidates_waiting_actual_tokenizer' or review['training_admitted']!=0:
        raise ValueError('Unexpected candidate review state')
    for name,sha in review['files'].items():
        p=candidates/name
        if p.is_symlink() or not p.resolve().is_relative_to(candidates.resolve()) or sha256_file(p)!=sha:
            raise ValueError('Candidate file changed: '+name)
    lineage={x['id']:x for x in map(json.loads,(candidates/'source-lineage.jsonl').read_text().splitlines())}
    tokenizer=AutoTokenizer.from_pretrained(base,trust_remote_code=False,local_files_only=True)
    output.mkdir(parents=True,exist_ok=False)
    selected={};rejected=[];eligible_counts={};max_tokens={};tokens_by_id={}
    for split in ('train','validation','test'):
        eligible=[];counts=Counter();maximum=0
        for line in (candidates/(split+'.candidates.jsonl')).open():
            row=json.loads(line);item=lineage[row['id']]
            if item['split']!=split: raise ValueError('Source partition mismatch')
            target=json.loads(row['messages'][-1]['content'])
            features=json.loads(row['messages'][1]['content'].split('\n',1)[1])
            digest=hashlib.sha256(json.dumps(features,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest()
            if (target!={'classification':item['target_value']} or digest!=item['input_sha256']
                    or item['source_rows']!=item['represented_rows']
                    or features['observed_rows']!=sum(x['count']for x in features['observations'])
                    or features['observed_rows']!=item['source_rows']):
                raise ValueError('Source target/input/count lineage mismatch')
            encoded,reason=encode_dialogue(row,tokenizer,4096,encode_completion)
            if reason:
                rejected.append({'id':row['id'],'reason':reason,'split':split})
                continue
            tokens_by_id[row['id']]=len(encoded['input_ids'])
            maximum=max(maximum,len(encoded['input_ids']));counts[target['classification']]+=1
            eligible.append(row)
        selected[split]=select_balanced(eligible,train_count if split=='train' else 48)
        eligible_counts[split]=dict(counts);max_tokens[split]=maximum
    chosen={r['id'] for rows in selected.values()for r in rows}
    orgs={s:{lineage[r['id']]['organization']for r in rows}for s,rows in selected.items()}
    if any(orgs[a]&orgs[b]for a,b in (('train','validation'),('train','test'),('validation','test'))):
        raise ValueError('Organization overlap')
    original=json.loads((evidence/'manifest.json').read_text())
    # Provenance notices and previous source sidecars remain alongside the mixture.
    for p in evidence.iterdir():
        if p.is_file() and p.name not in ('manifest.json','train.jsonl','validation.jsonl','test.jsonl'):
            shutil.copyfile(p,output/p.name)
    shutil.copyfile(candidates/'CDLA-Permissive-2.0.txt',output/'GUIDE_LICENSE.txt')
    (output/'guide-source-lineage.jsonl').write_text(''.join(json.dumps({**lineage[i],'actual_tokens':tokens_by_id[i]},ensure_ascii=False)+'\n'for i in sorted(chosen)))
    (output/'guide-token-rejections.jsonl').write_text(''.join(json.dumps(x)+'\n'for x in rejected))
    outputs={}
    for split,rows in selected.items():
        original_path=evidence/(split+'.jsonl')
        if sha256_file(original_path)!=original['outputs'][split]['sha256']:
            raise ValueError('Evidence replay changed')
        old=[json.loads(line)for line in original_path.open()]
        all_rows=old+rows
        if len({r['id']for r in all_rows})!=len(all_rows): raise ValueError('Duplicate record IDs')
        p=output/(split+'.jsonl')
        p.write_text(''.join(json.dumps(r,ensure_ascii=False,separators=(',',':'))+'\n'for r in all_rows))
        outputs[split]={'records':len(all_rows),'sha256':sha256_file(p),'guide_records':len(rows),'prior_records':len(old)}
    report={'status':'source_and_token_verified_bounded_pilot','at_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),
        'model':'Qwen/Qwen3.6-35B-A3B','base_revision':'995ad96eacd98c81ed38be0c5b274b04031597b0',
        'tokenizer_class':type(tokenizer).__name__,'max_length':4096,'truncation':False,
        'candidate_review_sha256':sha256_file(candidates/'review.json'),
        'prior_manifest_sha256':sha256_file(evidence/'manifest.json'),
        'candidate_incidents':review['candidate_incidents'],'token_eligible_counts':eligible_counts,
        'token_rejected_incidents':len(rejected),'max_eligible_tokens':max_tokens,
        'outputs':outputs,'guide_training_admitted':train_count,'guide_validation_admitted':48,'guide_test_reserved':48,
        'selected_max_tokens':{s:max(tokens_by_id[r['id']]for r in rows)for s,rows in selected.items()},
        'selected_class_counts':{s:dict(Counter(json.loads(r['messages'][-1]['content'])['classification']for r in rows))for s,rows in selected.items()},
        'cross_split_organization_overlap':0,'provider_test_training_records':0,'mcp_action_supervision_records':0,
        'scope':'Provider-labelled retrospective triage, plus previous evidence/CTI replay; not real-time decision or execution ground truth.',
        'quality_passed':False,'automatic_promotion':False,
        'limitations':['Class-balanced development sample is not an estimate of natural incident prevalence.',
          'Prior CTI validation/test were used before. New GUIDE test is reserved and not used for gradient or validation.',
          'Provider label provenance and exact extraction do not establish live deployment judgement accuracy.']}
    (output/'manifest.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(report,ensure_ascii=False,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('candidates','evidence','base','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--train-count',type=int,default=256)
    a=p.parse_args();main(a.candidates,a.evidence,a.base,a.output,a.train_count)
