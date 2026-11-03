import concurrent.futures,hashlib,json,os,re,subprocess,time,urllib.parse
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo
ROOT=Path('/home/attack/Desktop/PCAP');WORK=Path('/home/attack/.local/state/capstone-web-eval/20261103-r1');WORK.mkdir(parents=True,mode=0o700,exist_ok=False);os.umask(0o077)
def now():return datetime.now(ZoneInfo('Asia/Seoul')).isoformat()
patterns={
 'sqli':r'(?i)\bunion(?:\s|/\*.*?\*/)+(?:all\s+)?select\b|\b(?:sleep|benchmark)\s*\(|information_schema|\b(?:or|and)\s+[\x22\x27]?\d+[\x22\x27]?\s*=\s*[\x22\x27]?\d+',
 'traversal':r'(?:\.\./){2,}|(?i:/etc/(?:passwd|shadow)|boot\.ini|win\.ini)',
 'xss':r'(?i)<script\b|<[^>]+\bon(?:error|load)\s*=|javascript\s*:',
 'shell':r'(?i)/bin/(?:sh|bash)\b|cmd\.exe|powershell|(?:[;&|]|%3[bB])\s*(?:id|whoami|cat|wget|curl)\b',
 'shellshock':r'\(\)\s*\{',
 'callback':r'(?i)\$\{jndi:|ldap://|rmi://',
 'scanner':r'(?i)sqlmap|nikto|nessus|acunetix|nmap|masscan|zgrab|metasploit',
 'download':r'(?i)\.(?:exe|dll|scr)(?:[?]|$)',
}
compiled={k:re.compile(v) for k,v in patterns.items()}
def one(f):
 start=time.monotonic();rows=[];count=0;methods={};sha=hashlib.file_digest(f.open('rb'),'sha256').hexdigest()
 args=['tshark','-n','-r',str(f),'-Y','http.request && tcp','-T','fields','-E','separator=\t','-E','occurrence=f','-e','frame.number','-e','tcp.stream','-e','http.request.method','-e','http.request.uri','-e','http.host','-e','http.user_agent','-e','http.file_data','-e','http.request.line','-e','tcp.dstport']
 p=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 for line in p.stdout:
  c=line.rstrip('\n').split('\t');c+=['']*(9-len(c));frame,stream,method,uri,host,ua,data,headers,port=c[:9];count+=1;methods[method]=methods.get(method,0)+1
  text=uri+'\n'+ua+'\n'+headers+'\n'+data
  for _ in range(2):text=urllib.parse.unquote(text)
  flags=[k for k,v in compiled.items() if v.search(text)]
  if flags:
   rows.append({'source':str(f.relative_to(ROOT)),'pcap_sha256':sha,'frame':int(frame),'stream':stream,'method':method,'uri':uri,'host':host,'user_agent':ua,'body_field':data,'headers_field':headers,'dst_port':port,'flags':flags,'request_fields_sha256':hashlib.sha256(json.dumps(c,ensure_ascii=False).encode()).hexdigest()})
 _,err=p.communicate();return {'file':str(f.relative_to(ROOT)),'sha256':sha,'http_tcp_requests':count,'methods':methods,'candidates':rows,'rc':p.returncode,'stderr':err[:500],'elapsed_s':round(time.monotonic()-start,2)}
files=sorted(ROOT.rglob('snort.log.*'));results=[]
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
 futures=[pool.submit(one,f) for f in files]
 for fut in concurrent.futures.as_completed(futures):
  row=fut.result();results.append(row)
  progress={'at_kst':now(),'completed':len(results),'total':len(files),'http_tcp_requests':sum(x['http_tcp_requests'] for x in results),'candidates':sum(len(x['candidates']) for x in results)}
  (WORK/'scan-progress.json').write_text(json.dumps(progress));(WORK/'scan-results.json').write_text(json.dumps(results,ensure_ascii=False));
summary={'at_kst':now(),'completed':len(results),'total':len(files),'http_tcp_requests':sum(x['http_tcp_requests'] for x in results),'candidates':sum(len(x['candidates']) for x in results),'candidate_by_type':{k:sum(k in c['flags'] for x in results for c in x['candidates']) for k in patterns},'errors':[{k:x[k] for k in ['file','rc','stderr']} for x in results if x['rc']],'work_dir':str(WORK)}
(WORK/'summary.json').write_text(json.dumps(summary));print(json.dumps(summary))
