"""Append new reviewed versions to the single cleaned archive transactionally.

Original stays unchanged. Existing bytes and per-file source metadata are kept.
Both old and new archives are fully restored/hashed before replacement. The
staging directory retains rollback evidence until the caller verifies cleanup.
"""
import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import shutil
import sys
from zoneinfo import ZoneInfo
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'finetuning'))
from verified_archive import build, digest, verify_extract, safe_name, MANIFEST

SUFFIXES={'.json','.jsonl','.md','.txt','.py','.sh','.yaml','.yml','.toml','.csv','.tsv','.xml','.ini'}


def sync_file(path):
    with Path(path).open('rb') as stream: os.fsync(stream.fileno())


def append(plan_path, archives, stage):
    plan_path, archives, stage = Path(plan_path), Path(archives), Path(stage)
    if stage.exists() or stage.is_symlink(): raise ValueError('Fresh transaction directory required')
    if archives.is_symlink() or archives.resolve()!=archives.absolute(): raise ValueError('No linked archive store')
    catalog_path=archives/'catalog.json'; old_catalog_bytes=catalog_path.read_bytes()
    old=json.loads(old_catalog_bytes);plan=json.loads(plan_path.read_text())
    if plan.get('schema')!='groot-cleaned-append-v1' or plan['parent_catalog_sha256']!=digest(catalog_path):
        raise ValueError('Append plan does not bind current catalog')
    additions={}
    for r in plan['members']:
        name=safe_name(r['member']);p=Path(r['source'])
        if (name in additions or not name.startswith('finetuning/data-') or len(Path(name).parts)<3
                or p.suffix not in SUFFIXES or p.is_symlink() or not p.is_file() or p.resolve()!=p):
            raise ValueError('Only explicit regular curated-version files may be appended')
        if p.stat().st_size!=r['bytes'] or digest(p)!=r['sha256']:raise ValueError('New source changed')
        additions[name]=p
    if not additions:raise ValueError('No reviewed additions')
    for kind in ('original','cleaned'):
        p=archives/(kind+'.tar.gz')
        if p.is_symlink() or digest(p)!=old['archives'][kind]['sha256']:raise ValueError('Current archive changed')
    stage.mkdir(parents=True,mode=0o700)
    print(json.dumps({'stage':'restore_previous_cleaned'}),flush=True)
    restored=stage/'previous-cleaned'
    verify_extract(archives/'cleaned.tar.gz',old['archives']['cleaned'],restored)
    manifest=json.loads((restored/MANIFEST).read_text())
    preserved={r['path']:r for r in manifest['members']}
    if set(additions)&set(preserved):raise ValueError('Existing versions cannot be overwritten')
    files={name:restored/name for name in preserved};files.update(additions)
    print(json.dumps({'stage':'build_new_cleaned','new_files':len(additions)}),flush=True)
    receipt=build(stage/'cleaned.tar.gz',files,'cleaned',preserved_records=preserved)
    print(json.dumps({'stage':'full_restore_new_cleaned'}),flush=True)
    verify_extract(stage/'cleaned.tar.gz',receipt,stage/'verified-new-cleaned')
    # Recheck all source files and the fixed-store precondition before any swap.
    for r in plan['members']:
        if digest(Path(r['source']))!=r['sha256']:raise ValueError('Source changed during compression')
    if digest(catalog_path)!=plan['parent_catalog_sha256'] or digest(archives/'cleaned.tar.gz')!=old['archives']['cleaned']['sha256']:
        raise ValueError('Archive store changed during staging')
    new={**old,'at_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),
         'parent_catalog_sha256':plan['parent_catalog_sha256'],
         'initial_migration_plan_sha256':old.get('initial_migration_plan_sha256',old['plan_sha256']),
         'plan_sha256':digest(plan_path),'append_members':len(additions),
         'archives':{**old['archives'],'cleaned':receipt},'full_restore_verified':True}
    new_bytes=(json.dumps(new,ensure_ascii=False,indent=2)+'\n').encode()
    (stage/'old-catalog.json').write_bytes(old_catalog_bytes)
    shutil.copyfile(archives/'cleaned.tar.gz',stage/'rollback-cleaned.tar.gz')
    if digest(stage/'rollback-cleaned.tar.gz')!=old['archives']['cleaned']['sha256']:raise ValueError('Rollback copy mismatch')
    journal={'status':'prepared','archives':str(archives.resolve()),'old_cleaned_sha256':old['archives']['cleaned']['sha256'],
             'new_cleaned_sha256':receipt['sha256'],'old_catalog_sha256':plan['parent_catalog_sha256']}
    (stage/'transaction.json').write_text(json.dumps(journal,indent=2)+'\n')
    pending=archives/'.cleaned.pending';pending_catalog=archives/'.catalog.pending'
    if pending.exists() or pending_catalog.exists():raise ValueError('Unfinished store transaction exists')
    try:
        shutil.copyfile(stage/'cleaned.tar.gz',pending);pending.chmod(0o600);sync_file(pending)
        if digest(pending)!=receipt['sha256']:raise ValueError('Replacement copy mismatch')
        pending_catalog.write_bytes(new_bytes);pending_catalog.chmod(0o600);sync_file(pending_catalog)
        os.replace(pending,archives/'cleaned.tar.gz')
        os.replace(pending_catalog,catalog_path)
        if digest(archives/'cleaned.tar.gz')!=receipt['sha256'] or catalog_path.read_bytes()!=new_bytes:
            raise ValueError('Installed pair mismatch')
        if digest(archives/'original.tar.gz')!=old['archives']['original']['sha256']:
            raise ValueError('Original archive changed')
        journal['status']='completed';(stage/'transaction.json').write_text(json.dumps(journal,indent=2)+'\n')
    except BaseException:
        shutil.copyfile(stage/'rollback-cleaned.tar.gz',pending);os.replace(pending,archives/'cleaned.tar.gz')
        pending_catalog.write_bytes(old_catalog_bytes);os.replace(pending_catalog,catalog_path)
        journal['status']='rolled_back';(stage/'transaction.json').write_text(json.dumps(journal,indent=2)+'\n')
        raise
    return {'status':'completed','added_files':len(additions),'cleaned':receipt,
            'original_sha256':old['archives']['original']['sha256'],
            'catalog_sha256':digest(catalog_path),'rollback_directory':str(stage),
            'temporary_cleanup_pending':True}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('plan','archives','stage'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();result=append(a.plan,a.archives,a.stage)
    (a.stage/'result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='cleaned'},ensure_ascii=False,indent=2))
