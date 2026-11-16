#!/usr/bin/env python3
"""Run the frozen regression profiles in existing Python; never install or deploy."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import socket
import subprocess
import sys
import time
import unittest

HERE=Path(__file__).resolve().parent


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def identity(root):
    values={}
    for path in sorted(root.rglob('*')):
        assert not path.is_symlink()
        if path.is_file():values[str(path.relative_to(root))]=digest(path)
        else:assert path.is_dir()
    return len(values),hashlib.sha256(json.dumps(values,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def environment(root,comparison):
    for key in ('SOC_BOUNDARIES_ROOT','SOC_PARTITION_ROOT','SOC_HOST_JOURNAL_ROOT','SOC_TARGET_ROOT',
                'SOC_INTENT_ROOT','SOC_ATTEMPT_ROOT','SOC_MODALITY_ROOT','SOC_CONTRACT_ROOT',
                'SOC_TYPED_ROOT','SOC_FACTUAL_ROOT','SOC_PROVENANCE_ROOT','SOC_ERROR_COVERAGE_ROOT',
                'SOC_APP_ERROR_ROOT','SOC_JOURNAL_COMPOSITION_ROOT'):
        os.environ[key]=str(root)
    for key in ('SOC_BOUNDARIES_BASE','SOC_PARTITION_BASE'):os.environ[key]=str(comparison)
    for key,name in [('SOC_FROZEN_HOST_TEST','host-journal/test_host_journal.py'),
                     ('SOC_FROZEN_CLOCK_TEST','diagnostic-read-boundaries/test_clock.py'),
                     ('SOC_TYPED_TEST','typed-service/test_typed_service.py'),
                     ('SOC_FACTUAL_TEST','factual-service/test_factual_service.py'),
                     ('SOC_PROVENANCE_TEST','service-provenance/test_service_provenance.py')]:
        os.environ[key]=str(root/'infra/validation'/name)
    os.environ['PYTHONDONTWRITEBYTECODE']='1';sys.dont_write_bytecode=True


def child(args,profile):
    root=args.root.resolve();comparison=args.comparison.resolve();environment(root,comparison)
    def deny(*unused,**kwargs):raise AssertionError('isolated_regression_socket_connect_denied')
    socket.socket.connect=deny;socket.socket.connect_ex=deny;socket.create_connection=deny
    os.chdir(root/profile['cwd']);sys.path[:0]=[str(Path.cwd()),str(root/'infra/ollama-trial')]
    command=profile.get('hermes_command',profile['command']) if args.environment=='hermes' else profile['command']
    if command['kind']=='script':
        script=(HERE if command['origin']=='artifact' else root)/command['path']
        sys.argv=[str(script)];runpy.run_path(str(script),run_name='__main__')
    else:
        result=unittest.main(module=None,argv=['unittest',*command['arguments']],verbosity=2,exit=False).result
        raise SystemExit(0 if result.wasSuccessful() else 1)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--comparison',type=Path,required=True)
    parser.add_argument('--environment',choices=('mac','hermes'),required=True)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--job',help=argparse.SUPPRESS)
    args=parser.parse_args();root=args.root.resolve();comparison=args.comparison.resolve()
    frozen=json.loads((HERE/'manifest.json').read_text())
    for name,expected in frozen['tests_sha256'].items():assert digest(HERE/name)==expected,name
    profiles=json.loads((HERE/'regressions.json').read_text())['groups']
    assert len({p['group']for p in profiles})==len(profiles)==27
    if args.job:
        selected=[p for p in profiles if p['group']==args.job];assert len(selected)==1
        child(args,selected[0]);return
    assert identity(root)==(frozen['candidate_tree_file_count'],frozen['candidate_tree_sha256'])
    for name,info in frozen['comparison_sources'].items():assert digest(comparison/name)==info['comparison_sha256']
    assert args.output is not None
    out=args.output.resolve()
    assert not out.exists() and out.parent.is_dir() and not out.is_relative_to(root) and not out.is_relative_to(HERE.parents[2])
    out.mkdir(mode=0o700);rows=[]
    for profile in profiles:
        label=profile['group'];start=time.monotonic()
        command=[sys.executable,'-B',str(Path(__file__).resolve()),'--root',str(root),'--comparison',str(comparison),
            '--environment',args.environment,'--job',label]
        proc=subprocess.run(command,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=30,
            env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
        assert len(proc.stdout.encode())<=2097152 and len(proc.stderr.encode())<=2097152
        (out/(label+'.stdout')).write_text(proc.stdout);(out/(label+'.stderr')).write_text(proc.stderr)
        count=re.search(r'Ran ([0-9]+) tests?',proc.stderr);skips=re.search(r'skipped=([0-9]+)',proc.stderr)
        tests=int(count[1])if count else None;skipped=int(skips[1])if skips else 0
        expected=profile[args.environment+'_tests']
        allowed_skips=6 if args.environment=='mac' and label=='root' else 0
        passed=proc.returncode==0 and tests==expected and skipped<=allowed_skips
        rows.append({'group':label,'rc':proc.returncode,'tests':tests,'skipped':skipped,'passed':passed,
            'seconds':round(time.monotonic()-start,3)})
        print(json.dumps(rows[-1]),flush=True)
        if not passed:break
    complete=len(rows)==len(profiles)and all(r['passed']for r in rows)
    assert identity(root)==(frozen['candidate_tree_file_count'],frozen['candidate_tree_sha256'])
    report={'complete':complete,'environment':args.environment,'groups':rows,
        'tests':sum(r['tests']or 0 for r in rows),'skipped':sum(r['skipped']for r in rows),
        'candidate_sources_unchanged':True,'scope':'Regression executions with Python socket connects denied; not live model/MCP/chat or an independent SOC score'}
    (out/'results.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    assert complete,'Inspect the bounded local output directory; no deployment or model execution was started'
    print(json.dumps({k:v for k,v in report.items()if k!='groups'}))


if __name__=='__main__':main()
