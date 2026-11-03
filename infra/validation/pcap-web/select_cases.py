import collections,hashlib,json,re,urllib.parse
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo
root=Path('/home/attack/Desktop/PCAP');work=Path('/home/attack/.local/state/capstone-web-eval/20261103-r1');rows=json.loads((work/'fast-candidates.json').read_text());selected=[];counts={};sha={};used=set()
limits={'scanner':3,'sqli':4,'traversal':5,'shellshock':3,'xss':6}
for typ,n in limits.items():
 for c in rows:
  if c['method']!='GET' or c['dst_port']!=80 or typ not in c['flags']:continue
  payload=bytes.fromhex(c['payload_hex']);parts=payload.split(b'\r\n\r\n',1)
  if len(parts)!=2 or parts[1]:continue
  lines=parts[0].decode('latin1').split('\r\n');heads={k.lower():v.strip() for k,v in [x.split(':',1) for x in lines[1:] if ':' in x]};uri=c['uri'];dec=urllib.parse.unquote(urllib.parse.unquote(uri))
  if len(uri)>1800 or not uri.startswith('/') or uri.startswith('//') or re.search(r'[\r\n\x00-\x20]',uri):continue
  try:uri.encode('ascii')
  except UnicodeError:continue
  if re.search(r'(?i)://|document\.cookie|benchmark|outfile|load_file|\b(?:insert|delete|update|drop|create|truncate)\b',dec):continue
  special={};ua=heads.get('user-agent','Mozilla/5.0')
  if typ=='scanner':
   if not re.search(r'(?i)masscan|nikto|nessus|nmap|sqlmap|zgrab',ua):continue
  elif typ=='sqli':
   if not re.search(r'(?i)SLEEP\(0?[1-3]\)|\bunion\s+(?:all\s+)?select\b|\b(?:or|and)\s+[\x22\x27]?\d+[\x22\x27]?\s*=\s*[\x22\x27]?\d+',dec):continue
  elif typ=='traversal':
   if not re.search(r'(?:\.\./){2,}',dec):continue
  elif typ=='xss':
   if not re.search(r'(?i)<script\b|onmouseover\s*=|onerror\s*=',dec):continue
   if not re.search(r'(?i)alert\s*\(',dec):continue
  elif typ=='shellshock':
   bad=[(k,v) for k,v in heads.items() if '()' in v]
   if len(bad)!=1:continue
   key,val=bad[0]
   if key not in ['user-agent','referrer','cookie'] or not val.startswith('() { ignored; };') or not val.rstrip().endswith('/usr/bin/id'):continue
   if re.search(r'(?i)/dev/|wget|curl|bash|rm\s|nc\s',val):continue
   if key=='user-agent':ua=val
   else:special[{ 'referrer':'Referrer','cookie':'Cookie'}[key]]=val
  marker=(typ,uri,ua,tuple(special.items()))
  if marker in used:continue
  used.add(marker)
  if c['source'] not in sha:sha[c['source']]=hashlib.file_digest((root/c['source']).open('rb'),'sha256').hexdigest()
  count=counts.get(typ,0)+1;counts[typ]=count
  selected.append({'case_id':typ+'-'+str(count),'family':typ,'source':c['source'],'pcap_sha256':sha[c['source']],'frame':c['frame'],'original_payload_sha256':c['payload_sha256'],'original_uri_sha256':hashlib.sha256(uri.encode()).hexdigest(),'host':'dvwa.grootlab.duckdns.org','method':'GET','uri':'/dvwa'+uri,'user_agent':ua,'extra_headers':special})
  if count>=n:break
assert counts==limits,(counts,limits)
manifest={'schema_version':1,'run_id':'pcap-web-20261103-expanded-r1','at_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),'source_ip':'192.168.16.233','connect_ip':'192.168.16.230','port':80,'counts':counts,'cases':selected,'purpose':'additional abnormal HTTP variants; separate from initial 97:3 batch','transformation':'stateful GET; prefix /dvwa; lab Host; original URI query/UA and only reviewed Shellshock id header preserved; remove other original credentials/headers; no external callback'}
p=work/'expanded-manifest.json';assert not p.exists();p.write_text(json.dumps(manifest,ensure_ascii=False,indent=2));p.chmod(0o600)
public={'at_kst':manifest['at_kst'],'run_id':manifest['run_id'],'counts':counts,'cases':[{k:c[k] for k in ['case_id','family','source','pcap_sha256','frame','original_payload_sha256','original_uri_sha256']} for c in selected],'manifest_sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
print(json.dumps(public))
