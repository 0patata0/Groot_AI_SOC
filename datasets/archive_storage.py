"""Verify, restore, and prune explicitly inventoried local dataset copies.

No directory-wide deletion. A prune plan binds each untracked source file to a
member hash in one of the two verified archives. Existing run inputs on remote
servers are outside this utility's scope.
"""
import argparse
from datetime import datetime
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
from zoneinfo import ZoneInfo
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'finetuning'))
from verified_archive import build,digest,verify_extract,safe_name,MANIFEST

KINDS=('original','cleaned')

def read_plan(path):
    plan=json.loads(Path(path).read_text())
    if plan.get('schema')!='groot-dataset-migration-v1':raise ValueError('Unknown migration plan')
    for kind in KINDS:
        records=plan['archives'][kind]
        if not records:raise ValueError('Empty archive')
        seen=set()
        for r in records:
            safe_name(r['member'])
            if r['member'] in seen:raise ValueError('Duplicate member')
            seen.add(r['member'])
            p=Path(r['source'])
            if p.is_symlink() or not p.is_file() or p.resolve()!=p:raise ValueError('Require absolute regular source without symlinks')
            if p.stat().st_size!=r['bytes'] or digest(p)!=r['sha256']:raise ValueError('Source changed: '+r['member'])
    return plan


def create(plan_path,stage):
    plan=read_plan(plan_path);stage=Path(stage)
    stage.mkdir(parents=True,exist_ok=False,mode=0o700)
    receipts={}
    for kind in KINDS:
        print(json.dumps({'stage':'compress','kind':kind}),flush=True)
        files={r['member']:Path(r['source'])for r in plan['archives'][kind]}
        receipt=build(stage/(kind+'.tar.gz'),files,kind)
        print(json.dumps({'stage':'restore_verify','kind':kind,'bytes':receipt['bytes']}),flush=True)
        verify_extract(stage/(kind+'.tar.gz'),receipt,stage/('restore-'+kind))
        # Bind the source inventory to the generated internal manifest too.
        for r in plan['archives'][kind]:
            if digest(stage/('restore-'+kind)/r['member'])!=r['sha256']:raise ValueError('Source changed during archive build')
        receipts[kind]=receipt
    catalog={'schema':'groot-two-archive-catalog-v1','at_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),
             'plan_sha256':digest(plan_path),'archives':receipts,'full_restore_verified':True,
             'training_eligibility':'Use each preserved run admission and input allowlist; archive membership alone grants none.'}
    (stage/'catalog.json').write_text(json.dumps(catalog,ensure_ascii=False,indent=2)+'\n')
    (stage/'catalog.json').chmod(0o600)
    return catalog


def install(stage,destination):
    stage=Path(stage);destination=Path(destination)
    catalog=json.loads((stage/'catalog.json').read_text())
    if not catalog['full_restore_verified']:raise ValueError('Unverified stage')
    if destination.exists():raise ValueError('Initial migration only; existing archive replacement needs a new reviewed transaction')
    for kind in KINDS:
        if digest(stage/(kind+'.tar.gz'))!=catalog['archives'][kind]['sha256']:raise ValueError('Staged archive changed')
    pending=destination.with_name(destination.name+'.installing')
    pending.mkdir(parents=True,exist_ok=False,mode=0o700)
    try:
        for name in ('original.tar.gz','cleaned.tar.gz','catalog.json'):
            shutil.copyfile(stage/name,pending/name);(pending/name).chmod(0o600)
        for kind in KINDS:
            if digest(pending/(kind+'.tar.gz'))!=catalog['archives'][kind]['sha256']:raise ValueError('Copy changed')
        pending.rename(destination)
    except Exception:
        # Keep the stage and any partial destination for explicit recovery.
        raise
    return {'installed':str(destination),'archives':2,'source_copies_removed':False}


def restore(archive_dir,destination,kind,prefixes=None):
    archive_dir=Path(archive_dir);catalog=json.loads((archive_dir/'catalog.json').read_text())
    return verify_extract(archive_dir/(kind+'.tar.gz'),catalog['archives'][kind],Path(destination),prefixes)


def prune(plan_path,archive_dir,repo):
    plan=read_plan(plan_path);repo=Path(repo).resolve();archive_dir=Path(archive_dir)
    catalog=json.loads((archive_dir/'catalog.json').read_text())
    if catalog['plan_sha256']!=digest(plan_path) or not catalog['full_restore_verified']:raise ValueError('Catalog does not bind the plan')
    tracked=set(subprocess.check_output(['git','-C',str(repo),'ls-files','-z']).decode().split('\0'))
    removals=[];seen=set()
    for kind in KINDS:
        receipt=catalog['archives'][kind];archive=archive_dir/(kind+'.tar.gz')
        if digest(archive)!=receipt['sha256']:raise ValueError('Archive changed before cleanup')
        with tarfile.open(archive,'r:gz')as tar:
            manifest=json.load(tar.extractfile(MANIFEST))
        archived={r['path']:r for r in manifest['members']}
        for r in plan['archives'][kind]:
            a=archived[r['member']]
            if (a['sha256'],a['bytes'])!=(r['sha256'],r['bytes']):raise ValueError('Source is not archived intact')
            if not r.get('remove'):continue
            p=Path(r['source'])
            if not p.is_relative_to(repo):raise ValueError('Prune is restricted to repo dataset copies')
            rel=str(p.relative_to(repo))
            allowed=rel.startswith(('datasets/raw/','datasets/processed/','finetuning/data/','finetuning/bundles/')) or (rel.startswith('finetuning/data-') and len(Path(rel).parts)>=3)
            if not allowed or rel in tracked or p in seen:raise ValueError('Unsafe or repeated prune target')
            seen.add(p);removals.append(p)
    # All hashes/ownership boundaries are checked before any deletion.
    expected={Path(r['source']):r for kind in KINDS for r in plan['archives'][kind] if r.get('remove')}
    for p in removals:
        r=expected[p]
        if p.is_symlink() or p.stat().st_size!=r['bytes'] or digest(p)!=r['sha256']:raise ValueError('Source changed during cleanup')
        p.unlink()
    parents={parent for p in removals for parent in p.parents if parent!=repo and parent.is_relative_to(repo)}
    for p in sorted(parents,key=lambda p:len(p.parts),reverse=True):
        if p in (repo/'datasets',repo/'finetuning'):continue
        try:p.rmdir()
        except OSError:pass  # Preserve any unselected file/directory.
    result={'at_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),'removed_exact_files':len(removals),
            'missing_after_cleanup':sum(not p.exists()for p in removals),'remote_training_changed':False}
    if result['missing_after_cleanup']!=len(removals):raise ValueError('Cleanup verification failed')
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='action',required=True)
    c=sub.add_parser('create');c.add_argument('--plan',required=True);c.add_argument('--stage',required=True)
    c=sub.add_parser('install');c.add_argument('--stage',required=True);c.add_argument('--destination',required=True)
    c=sub.add_parser('restore');c.add_argument('--archives',required=True);c.add_argument('--destination',required=True);c.add_argument('--kind',choices=KINDS,required=True)
    c.add_argument('--prefix',action='append',help='Exact member or directory prefix; repeat to restore selected versions')
    c=sub.add_parser('prune');c.add_argument('--plan',required=True);c.add_argument('--archives',required=True);c.add_argument('--repo',required=True)
    a=p.parse_args()
    if a.action=='create':r=create(a.plan,a.stage);r={k:v for k,v in r.items()if k!='archives'}
    elif a.action=='install':r=install(a.stage,a.destination)
    elif a.action=='restore':r=restore(a.archives,a.destination,a.kind,a.prefix)
    else:r=prune(a.plan,a.archives,a.repo)
    print(json.dumps(r,ensure_ascii=False,indent=2))

if __name__=='__main__':main()
