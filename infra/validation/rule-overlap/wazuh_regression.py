#!/usr/bin/env python3
"""Run native, private logtest sessions without changing production rules.

The installed first-party client is used. Session tokens stay in that process.
EventChannel input through logtest does not establish actual Windows decoding;
these cases remain unverified, even if a generic JSON decoder returns a rule.
No API credentials, operating queue injection, restart or external messages.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

CLIENT_SHA = '59fb8b25a9315f3007aaea3bd572a8e5098012ca12046617b9615ce367672414'
CONTAINER = 'single-node-wazuh.manager-1'
NATIVE = r'''
import importlib.util,json,socket,concurrent.futures,sys,hashlib
from pathlib import Path
socket.setdefaulttimeout(8)
p=Path('/var/ossec/framework/scripts/wazuh_logtest.py')
assert hashlib.sha256(p.read_bytes()).hexdigest()==CLIENT_SHA, 'reviewed_native_client_required'
s=importlib.util.spec_from_file_location('private_native_logtest',p)
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
rows=json.loads(sys.stdin.read())
def test(row):
 c=m.WazuhLogtest(location=row['location'],log_format=row['log_format'])
 removed=None
 try:
  reply=c.process_log(row['input']);out=reply['output']
  rule=out.get('rule') or {};decoder=out.get('decoder') or {}
  correct=(str(rule.get('id')) in row['candidate_ids'] if row['candidate_ids']
           else str(rule.get('id')) not in {i for r in rows for i in r['candidate_ids']})
  windows=row['log_format']=='eventchannel'
  result={'name':row['name'],'candidate_ids':row['candidate_ids'],
          'log_format':row['log_format'],'actual_id':rule.get('id'),
          'level':rule.get('level'),'decoder':decoder.get('name'),
          'classification':'unverified_eventchannel_path' if windows else ('pass' if correct else 'fail')}
 finally:
  if c.last_token:removed=c.remove_session(c.last_token)
 result['test_session_removed']=removed
 if removed is not True:result['classification']='test_session_cleanup_failed'
 return result
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
 results=list(pool.map(test,rows))
print(json.dumps({'cases':results,'client_sha256':CLIENT_SHA,
 'session_tokens_exported':False,'operating_rule_writes':0,'external_messages':0,
 'scope':'native_test_sessions_not_live_agent_detection_or_alert_pipeline'}))
'''.replace('CLIENT_SHA',repr(CLIENT_SHA))


def fixtures():
    path=Path(__file__).with_name('wazuh-fixtures.json')
    raw=path.read_bytes()
    if len(raw)>65536:raise ValueError('fixture_size_limit')
    data=json.loads(raw)
    if data.get('schema')!=1 or data.get('purpose')!='rule_overlap_regression_not_training_data':
        raise ValueError('fixture_schema')
    rows=data['fixtures']
    if len(rows)!=19 or len({row['name'] for row in rows})!=19:
        raise ValueError('exact_fixture_set_required')
    for row in rows:
        if (not re.fullmatch(r'[A-Za-z0-9_-]{1,80}',row['name']) or
            row['log_format'] not in ('syslog','eventchannel') or
            row['location'] not in ('stdin','/var/log/osquery') or
            not isinstance(row['input'],str) or len(row['input'])>4096 or
            '\n' in row['input'] or '\r' in row['input'] or
            len(row['candidate_ids']) not in (0,2) or
            not all(re.fullmatch('[0-9]{1,6}',sid) for sid in row['candidate_ids']) or
            row['scope']!='synthetic_test_only_not_SFT'):
            raise ValueError('fixed_synthetic_fixture_required')
    return rows,hashlib.sha256(raw).hexdigest()


def native(rows):
    p=subprocess.run(['/usr/local/bin/docker','exec','-i',CONTAINER,
                     '/var/ossec/framework/python/bin/python3','-B','-c',NATIVE],
        input=json.dumps(rows),capture_output=True,text=True,timeout=65)
    if p.returncode:
        raise RuntimeError('native_logtest_failed_rc_'+str(p.returncode))
    result=json.loads(p.stdout)
    counts={key:sum(r['classification']==key for r in result['cases'])
            for key in ('pass','fail','unverified_eventchannel_path','test_session_cleanup_failed')}
    result['counts']=counts
    result['status']='partial' if any(v for k,v in counts.items() if k!='pass') else 'passed'
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--native',action='store_true',help='Use the fixed existing B manager test client.')
    args=p.parse_args();rows,digest=fixtures()
    if args.native:
        result=native(rows);result['fixture_sha256']=digest
        print(json.dumps(result))
        raise SystemExit(0 if result['status']=='passed' else 2)
    print(json.dumps({'status':'fixture_structure_checked_native_not_run',
                      'fixtures':len(rows),'fixture_sha256':digest}))


if __name__=='__main__':main()
