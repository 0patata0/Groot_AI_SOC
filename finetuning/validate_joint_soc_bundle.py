"""Read-back integrity and partition/admission-boundary checks for joint bundles."""
import argparse
from collections import Counter
import json
from pathlib import Path
from collect_defensive_sources import sha,now,write,safe_path
from prepare_joint_soc_bundle import canonical


def items(path):
    with path.open()as f:
        for line in f:
            if line.strip():yield json.loads(line)


def validate(root):
    root=Path(root);manifest=json.loads((root/'MANIFEST.json').read_text());plan=json.loads((root/'BATCH-PLAN.json').read_text())
    if manifest['ready_for_gpu_training']or any(plan[k]for k in ('ready_for_gpu_training','automatic_training','automatic_promotion')):
        raise ValueError('Unreviewed automatic training/promotion')
    for rel,v in manifest['files'].items():
        p=root/str(safe_path(rel))
        if p.is_symlink()or not p.resolve().is_relative_to(root.resolve())or p.stat().st_size!=v['bytes']or sha(p.read_bytes())!=v['sha256']:
            raise ValueError('Bundle file changed: '+rel)
    for name,v in manifest['modules'].items():
        if sha((root/name/'MANIFEST.json').read_bytes())!=v['manifest_sha256']:raise ValueError('Module manifest changed')
    counts={};seen_ids=set();sft_inputs={}
    sft=json.loads((root/'sft/MANIFEST.json').read_text())
    for split in ('train','validation','test'):
        path=root/'sft'/(split+'.jsonl');expected=sft['outputs'][split]
        if sha(path.read_bytes())!=expected['sha256']:raise ValueError('SFT split changed')
        rows=list(items(path));counts['sft_'+split]=len(rows)
        if len(rows)!=expected['records']:raise ValueError('SFT count mismatch')
        ids={r['id']for r in rows}
        if len(ids)!=len(rows)or seen_ids&ids:raise ValueError('SFT ID overlap')
        seen_ids|=ids;sft_inputs[split]={sha(canonical(r['messages'][:-1]).encode())for r in rows}
    if any(sft_inputs[a]&sft_inputs[b]for a,b in (('train','validation'),('train','test'),('validation','test'))):raise ValueError('SFT input overlap')
    inputs={};groups={}
    for split in ('train','eval'):
        hashes=set();gs=set();count=0
        for row in items(root/'event-evidence'/('observations-'+split+'.jsonl')):
            if row['partition']!=split or row['training_admitted']or row['target']is not None:raise ValueError('Observation became answer')
            h=sha(canonical([row['format'],row['observation']]).encode())
            if h!=row['input_sha256']or h in hashes:raise ValueError('Observation hash/duplicate mismatch')
            hashes.add(h);gs.add(row['split_group']);count+=1
        counts['event_'+split]=count;inputs[split]=hashes;groups[split]=gs
    if inputs['train']&inputs['eval']or groups['train']&groups['eval']:raise ValueError('Event partition overlap')
    for split,part in (('train','training_candidate'),('eval','reserved_evaluation')):
        c=Counter()
        for r in items(root/'regression-reference'/('regression-'+split+'.jsonl')):
            if r['reasons']or r['training_admitted']or r['engine_executed']or r['provisional_partition']!=part:raise ValueError('Regression boundary mismatch')
            c[r['source']]+=1
        if dict(c)!=plan['regression_candidates'][split]:raise ValueError('Regression count mismatch')
        counts['regression_'+split]=dict(c)
    report={'at_kst':now(),'status':'passed_integrity_and_structural_boundaries','files_verified':len(manifest['files']),
            'counts':counts,'event_exact_input_overlap':0,'event_known_case_group_overlap':0,'sft_exact_input_overlap':0,
            'ready_for_gpu_training':False,'not_verified':['Cross-source historical/semantic deduplication','New observation/fixture answer correctness and current MCP supervision','Live deployment performance or GPU training']}
    write(root/'validation.json',report);return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True);a=p.parse_args()
    print(json.dumps(validate(a.root),ensure_ascii=False))
