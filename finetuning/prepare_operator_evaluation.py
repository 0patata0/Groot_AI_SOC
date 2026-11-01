"""Locally reserve source-family-disjoint examples; never add them to training."""
import argparse
from collections import Counter
import copy
import json
from pathlib import Path

from prepare_operator_sources import (ROOT, rows, dump, sha, regression_examples,
    investigation_examples, telemetry_examples)
from prepare_operator_release import input_identity, private_observations


def group(row):
    proof=row['provenance']
    value=proof.get('split_group') or proof.get('base_incident')
    if value is None:raise ValueError('Missing source family')
    return row['source'],str(value)


def select(candidates, training, per_source=64, per_group=8):
    ids={r['id']for r in training};inputs={input_identity(r)for r in training}
    families={group(r)for r in training if r['source']in {'crs','wazuh','microsoft_excytin','splunk_attack'}}
    selected=[];held=[];counts=Counter();groups=Counter();seen=set()
    for row in sorted(candidates,key=lambda r:sha(r['id'].encode())):
        if row['id']in seen:raise ValueError('Duplicate evaluation ID')
        seen.add(row['id']);family=group(row)
        if row['id']in ids or input_identity(row)in inputs or family in families:
            raise ValueError('Evaluation overlaps training')
        if private_observations(row):
            held.append({'id':row['id'],'reason':'explicit_credential_pattern_or_field'});continue
        if counts[row['source']]>=per_source or groups[family]>=per_group:
            held.append({'id':row['id'],'reason':'source_family_sampling_cap'});continue
        item=copy.deepcopy(row);item['provenance']['reserved_for_quality_evaluation']=True
        selected.append(item);counts[row['source']]+=1;groups[family]+=1
    return sorted(selected,key=lambda r:(r['source'],r['id'])),held


def build(training_path, output):
    output=Path(output)
    if output.exists():raise ValueError('Preserve earlier evaluation artifacts')
    candidates=[];held=[]
    modules=[('regression',lambda:regression_examples(ROOT/'data-source-expansion-20261101-r1','reserved_evaluation')),
        ('investigation',lambda:investigation_examples(ROOT/'data-investigation-expansion-20261101-r2',ROOT/'data-investigation-clean-20261101-r2','eval')),
        ('telemetry',lambda:telemetry_examples(ROOT/'data-soc-events-clean-20261101-r3-v2','eval'))]
    for name,call in modules:
        examples,rejected=call();candidates.extend(examples);held.extend({**r,'module':name}for r in rejected)
    selected,rejected=select(candidates,rows(training_path));held.extend(rejected)
    output.mkdir(parents=True)
    dump(output/'cases.candidates.jsonl',selected);dump(output/'held.jsonl',held)
    dump(output/'token-input.jsonl',[{'split':'operator_evaluation','row':r}for r in selected])
    report={'status':'source_reserved_waiting_token_review','counts':dict(Counter(r['source']for r in selected)),
        'rows':len(selected),'source_groups_disjoint':True,'exact_inputs_disjoint':True,
        'training_sha256':sha(Path(training_path).read_bytes()),'model_evaluation_run':False,'training_included':False,
        'selection':{'order':'sha256(id)','per_source_max':64,'per_source_group_max':8},
        'not_covered':['Independent CISA guidance generalization','Unseen live MCP channels and actual approved production writes; retain separate critical-error gate'],
        'files':{p.name:sha(p.read_bytes())for p in output.iterdir()if p.is_file()}}
    (output/'manifest.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--train',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();print(json.dumps(build(args.train,args.output),ensure_ascii=False,indent=2))
