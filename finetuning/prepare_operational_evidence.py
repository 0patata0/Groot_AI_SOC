"""Freeze actual read-only MCP observations for later operational evaluation.

No synthetic successes, reference prose answers, training rows, model calls or
protected dispatch. A complete FW observation is not a complete SOC benchmark.
"""
import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re

from prepare_soc_observation_inputs import require


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def complete_firewall(capture):
    require(capture['status']=='completed' and capture['model_calls']==capture['protected_calls']==capture['chat_posts']==0,
            'Read-only capture did not complete')
    tools=capture['tools'];names=[t['name'] for t in tools]
    require(len(names)==len(set(names))==38 and all(type(t['protected']) is bool for t in tools)
            and sum(t['protected'] for t in tools)==9,
            'Full observed catalog required')
    require('mcp__resp__get_firewall_rules' in names, 'FW absent from catalog')
    pages=capture['calls'];require(bool(pages),'No firewall pages')
    objects=[];first=None;ledger=[]
    shared=('schema','target','observed_at_kst','source','scope','excluded_scope',
            'legacy_tables','coverage_warnings','sha256','snapshot','counts','total_objects')
    for n,call in enumerate(pages):
        require(call['server']=='resp' and call['name']=='get_firewall_rules', 'Unexpected dispatch in FW capture')
        result=call['result'];require(result.get('isError') is False and len(result['content'])==1 and
                result['content'][0]['type']=='text', 'Failed/unsupported FW result')
        raw=result['content'][0]['text'];page=json.loads(raw);args=call['arguments']
        require(re.fullmatch('[0-9a-f]{32}',page['snapshot']) and re.fullmatch('[0-9a-f]{64}',page['sha256']),
                'Invalid snapshot/hash identity')
        require(page['schema']==1 and page['target']=='a:firewall' and isinstance(page['objects'],list), 'Wrong FW target/shape')
        require(type(page['total_objects']) is int and page['total_objects']>=0 and
                type(page['offset']) is int and page['offset']==len(objects), 'Missing/repeated/noncontiguous FW page')
        observed=datetime.fromisoformat(page['observed_at_kst']);require(observed.utcoffset()==timedelta(hours=9),'FW time is not KST')
        require(set(args)<={'snapshot','offset','limit'} and type(args.get('limit',200)) is int and
                1<=args.get('limit',200)<=200, 'Invalid capture call arguments')
        require(type(args.get('offset',0)) is int and args.get('offset',0)==page['offset'], 'Result differs from requested offset')
        if first is None:
            require(page['offset']==0 and 'snapshot' not in args, 'Capture must start with a fresh first page')
            first=page
        else:
            require(all(page[k]==first[k] for k in shared), 'Snapshot identity/scope changed across pages')
            require(args.get('snapshot')==first['snapshot'], 'Follow-up call does not bind the snapshot')
        require(len(page['objects'])<=args.get('limit',200) and
                all(isinstance(o,dict) and len(o)==1 for o in page['objects']), 'Invalid object page')
        end=len(objects)+len(page['objects'])
        require(end<=page['total_objects'] and type(page['complete']) is bool and
                page['complete']==(end==page['total_objects']), 'False completion or total')
        require(page['next_offset']==(None if page['complete'] else end), 'Wrong next offset')
        require(page['complete']==(n==len(pages)-1), 'Missing last page or pages after completion')
        require(page['complete'] or bool(page['objects']), 'Non-progressing page')
        objects.extend(page['objects'])
        ledger.append({'page':n+1,'arguments':args,'response_text_sha256':sha(raw.encode()),
                       'offset':page['offset'],'objects':len(page['objects']),'complete':page['complete']})
    counts=dict(Counter(next(iter(o)) for o in objects));require(counts==first['counts'] and
        all(type(v) is int and v>=0 for v in first['counts'].values()),'Full object counts differ')
    policies=[o['chain'] for o in objects if 'chain' in o and 'hook' in o['chain']]
    require(all('policy' in x for x in policies),'Base chain missing default policy')
    return {'target':first['target'],'observed_at_kst':first['observed_at_kst'],'objects':objects,
        'counts':counts,'total_objects':len(objects),'base_chains':policies,'scope':first['scope'],
        'excluded_scope':first['excluded_scope'],'legacy_tables':first['legacy_tables'],
        'coverage_warnings':first['coverage_warnings'],'snapshot':first['snapshot'],
        'upstream_raw_sha256':first['sha256'],'upstream_raw_hash_independently_recomputed':False,
        'page_ledger':ledger,'complete':True}


def prepare(capture_path, output):
    require(not output.exists(),'Output already exists')
    raw=capture_path.read_bytes();capture=json.loads(raw);fw=complete_firewall(capture)
    catalog={'observed_at_kst':capture['at_kst'],'scope':'Actual complete8-server roster, read-only discovery',
             'tools':[{k:t[k] for k in ('server','name','protected','description','parameters')} for t in capture['tools']]}
    # Facts come from captured objects. There is no assistant answer to memorize.
    facts={k:v for k,v in fw.items() if k not in ('objects','page_ledger')}
    facts['reporting_requirements']=['Distinguish rule count from all nft objects and retain base-chain policies.',
        'Tables/NAT/Docker/sets/maps in this namespace are in scope; absence of a kind is not a fabricated instance.',
        'Every requested page must be accounted for; a later complete=true flag does not certify a missing first page.',
        'Keep the captured KST time and excluded hosts/namespaces/legacy scope; this is a snapshot, not future live state.']
    payloads={'catalog.json':catalog,'firewall-capture.json':capture,'firewall-facts.json':facts}
    files={n:(json.dumps(v,ensure_ascii=False,indent=2)+'\n').encode() for n,v in payloads.items()}
    manifest={'schema':1,'prepared_at_kst':datetime.now(timezone(timedelta(hours=9))).isoformat(),
        'status':'operational_read_evidence_reserved_not_complete_benchmark','source_capture_sha256':sha(raw),
        'files':{n:{'sha256':sha(v),'bytes':len(v)} for n,v in files.items()},
        'counts':{'servers':len({t['server'] for t in catalog['tools']}),'tools':len(catalog['tools']),
            'read_tools':sum(not t['protected'] for t in catalog['tools']),'protected_tools':sum(t['protected'] for t in catalog['tools']),
            'FW_pages':len(fw['page_ledger']),'FW_objects':fw['total_objects'],'FW_base_chains':len(fw['base_chains'])},
        'training_admitted':0,'model_predictions':0,'final_operational_cases_created':0,
        'source_type':'Project operational snapshot, not institutional/expert-certified incident data',
        'independence':'Fresh capture is not proof of independent policy contents; the same infrastructure was used in older tests.',
        'remaining':['Unused operational tasks and blind-condition review; no answer fixture generated here.',
            'Approved edit/apply/post-check/rollback and failure-state evidence; current capture is read-only.',
            'Same complete catalog/context/permissions and fair compute before model/harness comparison.']}
    output.mkdir(parents=True,exist_ok=False)
    for n,v in files.items():(output/n).write_bytes(v)
    (output/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
    return manifest


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--capture',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args();m=prepare(a.capture,a.output)
    print(json.dumps({'status':m['status'],**m['counts'],'training_admitted':0}))


if __name__=='__main__':main()
