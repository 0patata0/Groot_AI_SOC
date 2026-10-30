"""Reconcile an explicitly reviewed description delta, preserving frozen data.

This is not policy enforcement, a training release, or permission to run tools.
The old corpus/catalog remain unchanged. New bytes require a new token check.
"""
import argparse
import ast
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

from prepare_data import canonical
from prepare_soc_observation_inputs import require, verified
from audit_cam_isolation import guard_candidates

TOOL = 'mcp__rule_write_a__temporarily_contain_ip'


def sha(raw):
    return hashlib.sha256(raw if isinstance(raw, bytes) else canonical(raw).encode()).hexdigest()


def source_entry(source):
    entries=[]
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Dict):continue
        for k,v in zip(node.keys,node.values):
            if isinstance(k,ast.Constant) and k.value=='name' and isinstance(v,ast.Constant) and v.value=='temporarily_contain_ip':
                entries.append(ast.literal_eval(node))
    require(len(entries)==1, 'Ambiguous containment source declaration')
    return entries[0]


def reviewed_delta(old, live, source):
    require(live['status']=='completed' and live['model_calls']==live['protected_calls']==live['chat_posts']==0,
            'Read-only discovery receipt required')
    before={t['name']:t for t in old['tools']};after={t['name']:t for t in live['tools']}
    require(len(before)==len(old['tools'])==len(after)==len(live['tools'])==38 and before.keys()==after.keys(),
            'Catalog names/count changed; review separately')
    changes=[]
    for name,a in before.items():
        b=after[name]
        require(all(a[k]==b[k] for k in ('server','protected','parameters')), 'Schema/permission drift; description-only refresh refused')
        if a['description']!=b['description']:changes.append(name)
    require(changes==[TOOL], 'Unexpected or missing description delta')
    entry=source_entry(source)
    require(after[TOOL]['description']==entry['description'] and after[TOOL]['parameters']==entry['inputSchema'],
            'Live description differs from reviewed project source')
    require('public or RFC1918' in entry['description'] and 'Protected/management/infrastructure/DGX' in entry['description']
            and '10 minutes' in entry['description'] and 'never extend' in entry['description'], 'Containment boundary changed')
    return before[TOOL],after[TOOL]


def refresh_row(row, old, new):
    out=copy.deepcopy(row);changed=0
    for t in out.get('tools',[]):
        fn=t.get('function',{})
        if fn.get('name')==TOOL:
            require(fn['description']==old['description'] and fn['parameters']==old['parameters'], 'Unreviewed row contract')
            fn['description']=new['description'];changed+=1
    require(changed<=1, 'Repeated tool in one row')
    return out,bool(changed)


def build(root, inventory, capture, output):
    require(not output.exists(), 'Output already exists')
    manifest_raw=(inventory/'manifest.json').read_bytes();old_manifest=json.loads(manifest_raw)
    require(old_manifest['status']=='separate_candidate_inventory_not_training_release' and old_manifest['training_admitted']==0,
            'Candidate inventory required')
    support={n:verified(inventory/n,h) for n,h in old_manifest['support_files'].items()}
    catalog=json.loads(support['mcp-contract-candidate.json']);live_raw=capture.read_bytes();live=json.loads(live_raw)
    source_path=root.parent/'infra/mcp/rule_change_mcp.py'
    if not source_path.is_file():source_path=root/'contract_sources/rule_change_mcp.py'
    source=source_path.read_bytes()
    old,new=reviewed_delta(catalog,live,source)
    output_files={};changes={}
    for name,spec in old_manifest['pool_files'].items():
        raw=verified(inventory/name,spec['sha256']);lines=raw.splitlines(keepends=True);require(len(lines)==spec['rows'], 'Pool count changed')
        rewritten=[]
        for line in lines:
            row=json.loads(line);updated,changed=refresh_row(row,old,new)
            if changed:
                require(name=='optional-harness-candidates.jsonl', 'Unexpected tool-bearing pool')
                replacement=(canonical(updated)+'\n').encode()
                require(updated['messages']==row['messages'], 'Messages changed')
                require(row['id'] not in changes, 'Duplicate changed identity')
                changes[row['id']]={'old_record_line_sha256':sha(line),'new_record_line_sha256':sha(replacement),
                                    'messages_sha256':sha(row['messages'])}
                rewritten.append(replacement)
            else:rewritten.append(line)
        output_files[name]=b''.join(rewritten)
    require(len(changes)==3, 'Expected three selected containment examples')
    traces=[]
    for line in support['lineage.jsonl'].splitlines(keepends=True):
        trace=json.loads(line)
        if trace['id'] in changes:
            change=changes[trace['id']]
            require(trace['record_line_sha256']==change['old_record_line_sha256'], 'Original lineage differs')
            trace['previous_record_line_sha256']=trace['record_line_sha256']
            trace['record_line_sha256']=change['new_record_line_sha256']
            trace['description_refresh']={'tool':TOOL,'live_observed_at_kst':live['at_kst'],
                'scope':'Tool description only; messages and source case unchanged; not an institutional answer.'}
            line=(canonical(trace)+'\n').encode()
        traces.append(line)
    support['lineage.jsonl']=b''.join(traces)
    current={'observed_at_kst':live['at_kst'],'scope':'Actual38-tool discovery; permissions/schemas preserved. No model or protected call.',
             'previous_catalog_sha256':sha(support['mcp-contract-candidate.json']),
             'tools':[{k:t[k] for k in ('server','name','protected','description','parameters')}
                      for t in sorted(live['tools'],key=lambda t:t['name'])]}
    support['mcp-contract-candidate.json']=(json.dumps(current,ensure_ascii=False,indent=2)+'\n').encode()
    manifest=copy.deepcopy(old_manifest)
    manifest.update(at_kst=datetime.now(timezone(timedelta(hours=9))).isoformat(),
        previous_inventory_manifest_sha256=sha(manifest_raw),
        tool_description_refresh={'tool':TOOL,'rows':changes,'capture_sha256':sha(live_raw),
            'observed_at_kst':live['at_kst'],'rule_change_mcp_source_sha256':sha(source),
            'old_description':old['description'],'new_description':new['description'],
            'messages_unchanged':True,'schemas_permissions_unchanged':True,'new_token_proof_required':True,
            'policy_enforcement_changed':False,'original_frozen_catalog_and_splits_changed':False})
    manifest['pool_files']={n:{**old_manifest['pool_files'][n],'sha256':sha(raw)} for n,raw in output_files.items()}
    manifest['support_files']={n:sha(raw) for n,raw in support.items()}
    output.mkdir(parents=True,exist_ok=False)
    for n,raw in {**output_files,**support}.items():(output/n).write_bytes(raw)
    # Candidate files contain no actions to dispatch. Reuse the whole-source
    # evaluation isolation gate and keep its receipt in the manifest.
    manifest['CAM_isolation_guard']=guard_candidates(root/'data-cam-benchmark-20261030-r2',
                                                    [output/n for n in sorted(output_files)])
    (output/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
    return manifest


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=Path(__file__).resolve().parent)
    p.add_argument('--inventory',type=Path,required=True);p.add_argument('--capture',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args();m=build(a.root,a.inventory,a.capture,a.output)
    print(json.dumps({'rows_changed':len(m['tool_description_refresh']['rows']),'total_rows':sum(x['rows'] for x in m['pool_files'].values()),
                      'messages_unchanged':True,'new_token_proof_required':True,'training_admitted':0}))


if __name__=='__main__':main()
