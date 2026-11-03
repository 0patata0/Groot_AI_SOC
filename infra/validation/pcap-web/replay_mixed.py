import collections,hashlib,http.client,json,os,socket,time
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo
work=Path('/home/attack/.local/state/capstone-web-eval/20261103-r1');m=json.loads((work/'initial-manifest.json').read_text());assert m['source_ip']=='192.168.16.233' and m['connect_ip']=='192.168.16.230' and m['connect_port']==80
result=work/'initial-results.jsonl';assert not result.exists();os.umask(0o077)
def now():return datetime.now(ZoneInfo('Asia/Seoul')).isoformat(timespec='milliseconds')
rows=[];start=time.monotonic();begin=now()
for i in range(1,101):
 attack=i in m['attack_positions'];case=m['selected'][m['attack_positions'].index(i)] if attack else None
 host=case['host'] if attack else ('dvwa.grootlab.duckdns.org' if i%2 else 'log4shell.grootlab.duckdns.org')
 path=case['wire_uri'] if attack else ('/dvwa/login.php' if i%2 else '/log4shell/')
 ua=case['user_agent'] if attack else 'Mozilla/5.0'
 conn=http.client.HTTPConnection(m['connect_ip'],80,timeout=2.0,source_address=(m['source_ip'],0));row={'seq':i,'case':case['case'] if attack else 'normal','host':host,'wire_uri_sha256':hashlib.sha256(path.encode()).hexdigest(),'at_kst':now(),'connected':False,'sent':False,'status':None};t=time.monotonic()
 try:
  conn.connect();row['connected']=True;row['local_endpoint']=conn.sock.getsockname();row['peer_endpoint']=conn.sock.getpeername()
  conn.putrequest('GET',path,skip_host=True,skip_accept_encoding=True);conn.putheader('Host',host);conn.putheader('User-Agent',ua);conn.putheader('X-SOC-Test-ID',m['run_id']+'/'+str(i));conn.putheader('Connection','close');conn.endheaders();row['sent']=True
  response=conn.getresponse();row['status']=response.status;body=response.read(8192);row['response_prefix_sha256']=hashlib.sha256(body).hexdigest()
 except (OSError,http.client.HTTPException) as exc:row['error_type']=type(exc).__name__;row['error']=str(exc)[:120]
 finally:conn.close()
 row['elapsed_s']=round(time.monotonic()-t,3);rows.append(row)
 with result.open('a') as f:f.write(json.dumps(row)+'\n');f.flush()
 delay=start+i*0.25-time.monotonic()
 if delay>0:time.sleep(delay)
summary={'run_id':m['run_id'],'started_kst':begin,'ended_kst':now(),'attempted':len(rows),'sent':sum(x['sent'] for x in rows),'normal':dict(collections.Counter(str(x['status']) for x in rows if x['case']=='normal')),'samples':[{k:v for k,v in x.items() if k not in ('wire_uri_sha256','response_prefix_sha256')} for x in rows if x['case']!='normal'],'source_ips':sorted(set(x['local_endpoint'][0] for x in rows if x.get('local_endpoint'))),'runtime_s':round(time.monotonic()-start,3),'results_sha256':hashlib.sha256(result.read_bytes()).hexdigest()}
(work/'initial-summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary))
