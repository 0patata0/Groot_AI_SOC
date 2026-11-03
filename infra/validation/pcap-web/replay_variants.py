import collections,hashlib,http.client,json,os,time
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo
work=Path('/home/attack/.local/state/capstone-web-eval/20261103-r1');p=work/'expanded-results.jsonl';assert not p.exists();m=json.loads((work/'expanded-manifest.json').read_text());assert len(m['cases'])==21 and m['connect_ip']=='192.168.16.230' and m['source_ip']=='192.168.16.233';os.umask(0o077)
rows=[];begin=datetime.now(ZoneInfo('Asia/Seoul')).isoformat();start=time.monotonic()
for seq,c in enumerate(m['cases'],1):
 conn=http.client.HTTPConnection(m['connect_ip'],80,timeout=1,source_address=(m['source_ip'],0));row={'seq':seq,'case_id':c['case_id'],'family':c['family'],'at_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),'sent':False,'connected':False,'status':None}
 try:
  conn.connect();row['connected']=True;row['local_endpoint']=conn.sock.getsockname();conn.putrequest('GET',c['uri'],skip_host=True,skip_accept_encoding=True);conn.putheader('Host',c['host']);conn.putheader('User-Agent',c['user_agent']);conn.putheader('X-SOC-Test-ID',m['run_id']+'/'+c['case_id']);conn.putheader('Connection','close')
  for k,v in c['extra_headers'].items():conn.putheader(k,v)
  conn.endheaders();row['sent']=True;response=conn.getresponse();row['status']=response.status;row['body_prefix_sha256']=hashlib.sha256(response.read(8192)).hexdigest()
 except (OSError,http.client.HTTPException) as exc:row['error_type']=type(exc).__name__;row['error']=str(exc)[:120]
 finally:conn.close()
 rows.append(row)
 with p.open('a') as f:f.write(json.dumps(row)+'\n')
 delay=start+seq*0.25-time.monotonic()
 if delay>0:time.sleep(delay)
summary={'run_id':m['run_id'],'started_kst':begin,'ended_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),'attempted':len(rows),'sent':sum(x['sent'] for x in rows),'by_family':{k:dict(collections.Counter(str(x['status']) for x in rows if x['family']==k)) for k in m['counts']},'cases':rows,'result_sha256':hashlib.sha256(p.read_bytes()).hexdigest()};(work/'expanded-summary.json').write_text(json.dumps(summary));print(json.dumps(summary))
