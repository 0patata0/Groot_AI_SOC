"""Release the frozen evidence-only arm for one bounded experimental epoch.

Preserves candidate/withheld records. This admits training, never production.
The 143 source-bound operator targets include project-authored interpretation;
they are not independently certified SOC answers. No new records are invented.
"""
import argparse
from collections import Counter
from datetime import datetime
import hashlib
import json
from pathlib import Path
import shutil
from zoneinfo import ZoneInfo

RUN_ID = 'soc-evidence-20261031-r1'
ARM_SHA = 'acee5ff65c57b50991620504713d0b22703516715ffa9ae7107aa9444dddaf84'
SPLIT_SHA = {'validation':'ebd242dbea94545b5beb2fce4c2e3f55c4d00c1687ad51dd88c6dd9ccbf593b7',
             'test':'a3906e018b6ad2cdfd02dcbe2bf21ea542d9aae60536a21d7617ad44b3fa5045'}
SOURCE_FILES = ('train.py','model_profile.py','memory_budget.py','memory_telemetry.py',
                'bounded_loading.py','completion_loss.py','dialogue_encoding.py',
                'training_lineage.py','guarded_process.py','durable_training_task.py')


def digest(raw): return hashlib.sha256(raw).hexdigest()
def encoded(x): return (json.dumps(x,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode()
def require(ok,message):
    if not ok: raise ValueError(message)


def split_guard(splits,external_groups=None):
    seen_ids, seen_groups, seen_payloads = {}, {}, {}
    for split, rows in splits.items():
        for row in rows:
            require(row.get('id') and row.get('messages') and row['messages'][-1]['role']=='assistant','Invalid example')
            require(row['id'] not in seen_ids,'Repeated record ID across/within splits')
            seen_ids[row['id']] = split
            prov=row.get('provenance',{})
            group=prov.get('group') or prov.get('scenario_group') or (external_groups or {}).get(row['id'])
            require(group,'Missing source group')
            require(group not in seen_groups or seen_groups[group]==split,'Source group crosses splits')
            seen_groups[group]=split
            h=digest(encoded({'messages':row['messages'],'tools':row.get('tools',[])}))
            require(h not in seen_payloads or seen_payloads[h]==split,'Payload crosses splits')
            seen_payloads[h]=split
    return {'records':{s:len(v) for s,v in splits.items()},'source_groups':dict(Counter(seen_groups.values())),
            'cross_split_ids_groups_exact_payloads':0,'semantic_or_pretraining_disjointness_proven':False}


def build(root,output):
    require(not output.exists(),'Never overwrite a release or prior run')
    pilot=root/'data-soc-pilot-candidate-20261030-r5'; inventory=root/'data-soc-mixture-candidate-20261030-r5'
    manifest=json.loads((pilot/'manifest.json').read_text()); inv=json.loads((inventory/'manifest.json').read_text())
    require(manifest['status']=='small_comparison_candidates_not_training_release' and manifest['training_admitted']==0,'Candidate state changed')
    require(manifest['full_inventory_manifest_sha256']==digest((inventory/'manifest.json').read_bytes()),'Inventory differs')
    for name,item in manifest['files'].items():require(digest((pilot/name).read_bytes())==item['sha256'],'Candidate support checksum mismatch')
    require(inv['known_held_out_environment_conflicts']==[] and not inv['V5_report_entity_split_audit']['cross_split_groups'],'Held-out conflicts')
    for name,item in inv['pool_files'].items():require(digest((inventory/name).read_bytes())==item['sha256'],'Pool checksum differs')
    for name,d in inv['support_files'].items():require(digest((inventory/name).read_bytes())==d,'Source sidecar checksum differs')
    raw=(pilot/'evidence-only.jsonl').read_bytes();require(digest(raw)==ARM_SHA,'Frozen 191-row arm differs')
    splits={'train':[json.loads(l) for l in raw.splitlines()]};payloads={'train':raw}
    for split,expected in SPLIT_SHA.items():
        raw=(root/'data-soc-evidence-v5-r3'/(split+'.jsonl')).read_bytes();require(digest(raw)==expected,'Regression split differs')
        payloads[split]=raw;splits[split]=[json.loads(l) for l in raw.splitlines()]
    require([len(splits[s]) for s in ('train','validation','test')]==[191,128,128],'Unexpected split sizes')
    obs={json.loads(l)['id'] for l in (inventory/'observation-candidates.jsonl').read_text().splitlines()}
    cti={json.loads(l)['id'] for l in (inventory/'cti-replay-candidates.jsonl').read_text().splitlines()}
    ids={r['id'] for r in splits['train']};require(len(ids&obs)==143 and len(ids&cti)==48 and ids<=obs|cti,'Arm includes unreviewed/harness examples')
    lineage=[json.loads(l) for l in (inventory/'lineage.jsonl').read_text().splitlines()]
    groups={x['id']:x['group'] for x in lineage if x.get('group')}
    check=split_guard(splits,groups)
    observation=root/'data-soc-observation-candidate-20261030-r2'
    om= json.loads((observation/'manifest.json').read_text())
    require(digest((observation/'lineage.jsonl').read_bytes())==om['lineage_sha256'],'Observation source binding differs')
    bindings=[json.loads(l) for l in (observation/'lineage.jsonl').read_text().splitlines()]
    require(len(bindings)==17 and {x['record_id'] for x in bindings}<=ids,'Observation source binding IDs differ')
    config=json.loads((root/'config.qwen36-soc-v5.json').read_text())
    config.update(data_dir='/trial/data',output_dir='/trial/main',num_train_epochs=1,max_steps=-1,
                  learning_rate=5e-7,eval_steps=96,save_steps=48,save_total_limit=2,offline=True,
                  model_name_or_path='/workspace/base',max_train_samples=0,max_eval_samples=0)
    smoke={**config,'output_dir':'/trial/smoke','max_steps':2,'gradient_accumulation_steps':1,
           'max_train_samples':2,'max_eval_samples':8,'smoke_longest_prefixes':True,'eval_steps':2,'save_steps':2}
    token={**config,'output_dir':'/trial/tokenization'}
    output.mkdir(parents=True);(output/'data').mkdir();(output/'source').mkdir();(output/'profiles').mkdir()
    for split,raw in payloads.items():(output/'data'/(split+'.jsonl')).write_bytes(raw)
    data={'outputs':{s:{'records':len(splits[s]),'sha256':digest(raw)} for s,raw in payloads.items()},'source_split_audit':check,
          'status':'bounded_experimental_training_release_not_production','source_bound_observation_rows':143,'new_independent_incident_count_claimed':False,'cti_replay':48,
          'authorship':'Provider CTI labels; operator targets source-bound project interpretation, not independent expert gold',
          'validation_test_scope':'Existing used CTI development/regression, not new operational generalization test'}
    (output/'data/manifest.json').write_bytes(encoded(data))
    (output/'data/source-lineage.jsonl').write_text(''.join(json.dumps(x,ensure_ascii=False,sort_keys=True)+'\n' for x in lineage if x['id'] in ids))
    shutil.copyfile(observation/'lineage.jsonl',output/'data/observation-source-bindings.jsonl')
    for name in SOURCE_FILES:shutil.copyfile(root/name,output/'source'/name)
    for name,cfg in [('main',config),('smoke',smoke),('tokenize',token)]:(output/'profiles'/(name+'.json')).write_bytes(encoded(cfg))
    for p in pilot.iterdir():
        if p.name.endswith('NOTICE.txt') or p.name in ('MITRE-ATTACK-LICENSE.txt','V5_SOURCE_ATTRIBUTION.json','evaluation-boundaries.json'):
            shutil.copyfile(p,output/'data'/p.name)
    release={'schema':1,'run_id':RUN_ID,'created_at_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),
             'status':'experimental_training_only','training_rows':191,'expected_optimizer_steps':96,
             'train_limit_seconds':14400,'independent_restore_minutes':245,'restore_timeout_seconds':360,
             'smoke_limit_seconds':900,'min_disk_free_bytes':30*2**30,'min_host_available_gib':96,
             'original_model':'qwen3.6:35b','original_digest':'a7eb95c53bcf96b4bdd008d0fab4a5dac88047d9c1a7a9ab88ed453423fbd87c',
             'base_revision':'995ad96eacd98c81ed38be0c5b274b04031597b0','source_arm_sha256':ARM_SHA,
             'source_manifest_sha256':digest((pilot/'manifest.json').read_bytes()),'split_audit':check,
             'evaluation_boundaries_sha256':digest((pilot/'evaluation-boundaries.json').read_bytes()),
             'automatic_promotion':False,'harness_changes':False,'guide_rows_admitted':0,'optional_harness_rows_admitted':0,
             'comparison_limit':'Only evidence-only arm; no matched-compute harness comparison or new final operational quality claim',
             'coverage_limit':manifest['coverage_warning'],
             'files':{str(p.relative_to(output)):digest(p.read_bytes()) for p in sorted(output.rglob('*')) if p.is_file()}}
    (output/'release.json').write_bytes(encoded(release));return release


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    print(json.dumps(build(Path(__file__).resolve().parent,a.output),ensure_ascii=False,indent=2))
