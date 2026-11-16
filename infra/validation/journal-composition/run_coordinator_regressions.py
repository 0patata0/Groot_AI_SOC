#!/usr/bin/env python3
"""Reproduce the fixed isolated lifecycle regressions, never a deployment.

Existing Python only. No root, model requests, package installation or live
systemd/Docker access is required. Kernel-backed local files and owned child
processes are exercised; the native-service and reader backends are fixtures.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timedelta,timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent


def sources(manifest):
    expected=manifest['source_sha256'];result={}
    for name,digest in expected.items():
        assert Path(name).name==name
        path=HERE/name;assert not path.is_symlink()and path.is_file()
        actual=hashlib.sha256(path.read_bytes()).hexdigest();assert actual==digest,name;result[name]=actual
    witness=json.loads((HERE/'witness-manifest.json').read_text())
    assert hashlib.sha256((HERE/'witness-manifest.json').read_bytes()).hexdigest()==manifest['witness_manifest_sha256']
    for name,digest in witness['source_sha256'].items():
        assert Path(name).name==name and not(HERE/name).is_symlink()
        assert hashlib.sha256((HERE/name).read_bytes()).hexdigest()==digest,name
    for name,digest in manifest['dependencies_sha256'].items():
        assert Path(name).name==name and not(HERE/name).is_symlink()
        assert hashlib.sha256((HERE/name).read_bytes()).hexdigest()==digest,name
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--jobs',type=int,choices=(1,2,4),default=4)
    args=parser.parse_args();assert os.geteuid()!=0,'run_as_unprivileged_user'
    out=args.output.absolute();assert out==out.resolve()and not out.exists()and out.parent.is_dir()
    # The same frozen sources can be mounted flat at /check in an isolated
    # container. This runner is unprivileged and never a production entry.
    repo=HERE.parents[2]if HERE.parts[-3:]==('infra','validation','journal-composition')else HERE
    assert not out.is_relative_to(repo),'output_must_be_outside_repository'
    manifest=json.loads((HERE/'coordinator-manifest.json').read_text());before=sources(manifest)
    expected=manifest['regressions'];assert len(expected)==15
    out.mkdir(mode=0o700)
    work=out/'work';work.mkdir(mode=0o700);os.chown(work,-1,os.getgid())
    def one(item):
        name,count=item;assert re.fullmatch('[a-z_]+',name)and type(count)is int and count>0
        start=time.monotonic();command=[sys.executable,'-I','-B',str(HERE/('test_release_'+name+'.py'))]
        try:
            run=subprocess.run(command,stdin=subprocess.DEVNULL,capture_output=True,timeout=150,
                env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1','TMPDIR':str(work)})
            raw=run.stdout+run.stderr;assert len(raw)<=1024*1024,'test_output_bound'
            (out/(name+'.log')).write_bytes(raw);text=raw.decode('utf-8',errors='replace')
            match=re.search(r'Ran (\d+) tests?',text);skip=re.search(r'skipped=(\d+)',text)
            actual=int(match[1])if match else 0;skipped=int(skip[1])if skip else 0
            passed=run.returncode==0 and actual==count and skipped==0 and re.search(r'(?m)^OK(?:\s|$)',text)is not None
            return {'profile':name,'tests':actual,'skipped':skipped,'exit':run.returncode,'ok':passed,'seconds':time.monotonic()-start}
        except subprocess.TimeoutExpired:
            return {'profile':name,'tests':0,'skipped':0,'exit':124,'ok':False,'seconds':time.monotonic()-start,'reason':'isolated_test_timeout'}
    with ThreadPoolExecutor(max_workers=args.jobs)as pool:results=list(pool.map(one,expected.items()))
    unchanged=sources(manifest)==before
    work_empty=not any(work.iterdir())
    if work_empty:work.rmdir()
    value={'schema':1,'at_kst':datetime.now(timezone(timedelta(hours=9))).isoformat(),'python':sys.version.split()[0],
        'platform':sys.platform,'source_sha256':before,'source_unchanged':unchanged,'profiles':results,
        'tests':sum(v['tests']for v in results),'skipped':sum(v['skipped']for v in results),
        'complete':unchanged and work_empty and all(v['ok']for v in results),'own_work_removed':work_empty,'operating_changes':0,'model_calls':0,
        'scope':'15 isolated filesystem/SQLite/fixed-backend profiles. Cache42 includes 40 inherited cases; synthetic acceptance is not actual MCP/chat evidence. Not native systemd, independent recovery, production CLI or bot/detection accuracy.'}
    (out/'results.json').write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:value[k]for k in ('complete','tests','skipped','source_unchanged','operating_changes','model_calls')}))
    raise SystemExit(0 if value['complete']else 1)


if __name__=='__main__':main()
