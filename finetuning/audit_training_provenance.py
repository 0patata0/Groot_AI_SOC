"""Audit retained local corpus, run-manifest and AIT row lineage; never train.

Raw data and remote inventory remain local. Checks establish file/record identity,
not expert correctness or historical per-batch sample order.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import zipfile

CORPORA=('data','data-soc-v1','data-soc-v2-r2')

def require(ok,reason):
    if not ok:raise ValueError(reason)

def sha(data):return hashlib.sha256(data).hexdigest()
def canonical(value):return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))

def source_path(root,name):
    rel=Path(name)
    require(not rel.is_absolute() and '..' not in rel.parts,'Unsafe source path')
    require(rel.parent==Path('datasets/processed/ait') and rel.name.endswith('.labeled.jsonl'),'Unexpected AIT source')
    result=root/rel
    require(not result.is_symlink() and result.resolve().is_relative_to(root.resolve()),'Escaping source path')
    return result

def check_corpus(folder,server):
    manifest=json.loads((folder/'manifest.json').read_text());checks=[];records={}
    for split in ('train','validation','test'):
        name=split+'.jsonl';data=(folder/name).read_bytes();expected=manifest['outputs'][split];digest=sha(data)
        require(digest==expected['sha256'],'Local manifest hash mismatch')
        require(digest==server[name],'Server corpus hash mismatch')
        rows=[json.loads(line) for line in data.splitlines()]
        require(len(rows)==expected['records'],'Corpus record count mismatch')
        checks.append({'path':'finetuning/'+folder.name+'/'+name,'sha256':digest,'records':len(rows),'manifest_match':True,'server_match':True});records[split]=rows
    return checks,records

def bind_run(run,corpora):
    name=Path(run['config']['data_dir']).name
    require(name in corpora,'Unrecognized run corpus')
    expected={Path(c['path']).stem:c['sha256'] for c in corpora[name]}
    require(run['data']['sha256']==expected,'Run corpus hash mismatch')
    require(run['data']['records']=={Path(c['path']).stem:c['records'] for c in corpora[name]},'Run record count mismatch')
    return name

def verify_ait(root,rows):
    files={};targets=defaultdict(dict);verified=[];raw_targets=defaultdict(dict)
    for row in rows:
        review=row['provenance']['review']
        if review['evidence_kind']!='public_testbed_log':continue
        name=review['source_file'];source_path(root,name);files[name]=review['source_file_sha256']
        require(review['source_line'] not in targets[name],'Duplicate source row')
        targets[name][review['source_line']]=(row['id'],review['source_line_sha256'])
    for name,lines in targets.items():
        path=source_path(root,name);require(sha(path.read_bytes())==files[name],'AIT processed file hash mismatch')
        with path.open('rb') as handle:
            for index,line in enumerate(handle,1):
                if index not in lines:continue
                case_id,digest=lines[index];require(sha(line)==digest,'AIT line hash mismatch (newline included)')
                value=json.loads(line);env=value.pop('ait_env');value.pop('phase_window');require(env.isalnum(),'Invalid AIT environment')
                require(value['id'] not in raw_targets[env],'Duplicate source alert ID')
                raw_targets[env][value['id']]=sha(canonical(value).encode())
                verified.append({'case_id':case_id,'source_file':name,'line':index,'source_line_sha256':digest,'processed_source_match':True})
    require(len(verified)==sum(len(x) for x in targets.values()),'AIT source line missing')
    matched=Counter()
    with zipfile.ZipFile(root/'datasets/raw/ait-ads/ait_ads.zip') as archive:
        for env,remaining in raw_targets.items():
            with archive.open(env+'_wazuh.json') as handle:
                for line in handle:
                    value=json.loads(line)
                    if value.get('id') in remaining and sha(canonical(value).encode())==remaining[value['id']]:
                        matched[env]+=1;del remaining[value['id']]
                    if not remaining:break
            require(not remaining,'Original AIT alert not found')
    return verified,dict(matched)

def audit(root,remote):
    checks=[];corpora={};records={}
    for name in CORPORA:
        corpora[name],records[name]=check_corpus(root/'finetuning'/name,remote['data'][name]);checks.extend(corpora[name])
    runs=[{'path':r['path'],'manifest_sha256':r['sha256'],'corpus':bind_run(r,corpora)} for r in remote['runs']]
    ait_rows=[x for rows in records['data-soc-v1'].values() for x in rows];verified,matched=verify_ait(root,ait_rows)
    from soc_curriculum import build
    raw=''.join(canonical(c)+'\n' for c in build()).encode();source=(root/'finetuning/data-soc-source-v2-r2/cases.jsonl').read_bytes();require(raw==source,'R2 source replay differs')
    return {'data_checks':checks,'run_bindings':runs,'ait_reference_rows':verified,'raw_zip_matches_by_environment':matched,'raw_zip_matches':sum(matched.values()),'source_line_hash_includes_newline':True,'r2_source_replay_sha256':sha(source),'r2_source_replay_exact':True,'server_run_manifests':len(runs),'limitations':__doc__.strip()}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parent.parent);parser.add_argument('--run-inventory',required=True,type=Path);parser.add_argument('--output',required=True,type=Path);args=parser.parse_args()
    require(not args.output.exists(),'Use a new audit output path');result=audit(args.root,json.loads(args.run_inventory.read_text()))
    with args.output.open('x') as handle:handle.write(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'split_hash_matches':len(result['data_checks']),'bound_runs':len(result['run_bindings']),'ait_raw_matches':result['raw_zip_matches'],'r2_replayed':result['r2_source_replay_exact']}))

if __name__=='__main__':main()
