import hashlib,json,mmap,re,struct,time,urllib.parse,os
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo
root=Path('/home/attack/Desktop/PCAP');work=Path('/home/attack/.local/state/capstone-web-eval/20261103-r1');out=[];totals=[]
patterns={
'sqli':r'(?i)\bunion(?:\s|/\*.*?\*/)+(?:all\s+)?select\b|\b(?:sleep|benchmark)\s*\(|information_schema|\b(?:or|and)\s+[\x22\x27]?\d+[\x22\x27]?\s*=\s*[\x22\x27]?\d+',
 'traversal':r'(?:\.\./){2,}|(?i:/etc/(?:passwd|shadow)|boot\.ini|win\.ini)',
 'xss':r'(?i)<script\b|<[^>]+\bon(?:error|load)\s*=|javascript\s*:',
 'shell':r'(?i)/bin/(?:sh|bash)\b|cmd\.exe|powershell|[;&|]\s*(?:id|whoami|cat|wget|curl)\b',
 'shellshock':r'\(\)\s*\{','callback':r'(?i)\$\{jndi:|ldap://|rmi://',
 'scanner':r'(?i)sqlmap|nikto|nessus|acunetix|nmap|masscan|zgrab|metasploit',
 'download':r'(?i)\.(?:exe|dll|scr)(?:[?\s]|$)'}
compiled={k:re.compile(v) for k,v in patterns.items()};request=re.compile(rb'^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE) ([^\r\n]{1,12000}) HTTP/1\.[01]\r\n')
for f in sorted(root.rglob('snort.log.*')):
 start=time.monotonic();count=0;frames=0;candidates=[]
 with f.open('rb') as fd,mmap.mmap(fd.fileno(),0,access=mmap.ACCESS_READ) as m:
  assert m[:4] in (b'\xd4\xc3\xb2\xa1',b'\xa1\xb2\xc3\xd4',b'\x4d\x3c\xb2\xa1',b'\xa1\xb2\x3c\x4d')
  endian='<' if m[:4] in (b'\xd4\xc3\xb2\xa1',b'\x4d\x3c\xb2\xa1') else '>';link=struct.unpack_from(endian+'I',m,20)[0];assert link==1
  pos=24
  while pos+16<=len(m):
   sec,usec,cap,orig=struct.unpack_from(endian+'4I',m,pos);pos+=16;packet=m[pos:pos+cap];pos+=cap;frames+=1
   if len(packet)<54:continue
   off=14;eth=struct.unpack_from('!H',packet,12)[0]
   if eth in (0x8100,0x88a8):eth=struct.unpack_from('!H',packet,16)[0];off=18
   if eth!=0x0800 or packet[off]>>4!=4 or packet[off+9]!=6:continue
   ihl=(packet[off]&15)*4
   if len(packet)<off+ihl+20:continue
   tcp=off+ihl;length=(packet[tcp+12]>>4)*4;data=packet[tcp+length:]
   match=request.match(data)
   if not match:continue
   count+=1;method,uri=match[1].decode(),match[2].decode('latin1');text=data.decode('latin1')
   for _ in range(2):text=urllib.parse.unquote(text)
   flags=[k for k,p in compiled.items() if p.search(text)]
   if flags:
    candidates.append({'source':str(f.relative_to(root)),'frame':frames,'method':method,'uri':uri,'flags':flags,'payload_sha256':hashlib.sha256(data).hexdigest(),'payload_hex':data.hex(),'dst_port':struct.unpack_from('!H',packet,tcp+2)[0]})
  if pos!=len(m):raise ValueError('truncated pcap record')
 info={'source':str(f.relative_to(root)),'frames':frames,'single_packet_http_requests':count,'candidate_count':len(candidates),'elapsed_s':round(time.monotonic()-start,2)};totals.append(info);out+=candidates
 (work/'fast-progress.json').write_text(json.dumps({'at_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),'files':len(totals),'candidates':len(out),'totals':totals}))
(work/'fast-candidates.json').write_text(json.dumps(out));(work/'fast-candidates.json').chmod(0o600)
summary={'at_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),'files':len(totals),'frames':sum(x['frames'] for x in totals),'single_packet_http_requests':sum(x['single_packet_http_requests'] for x in totals),'candidates':len(out),'by_type':{k:sum(k in c['flags'] for c in out) for k in patterns},'non_download_sample':[{'source':c['source'],'frame':c['frame'],'method':c['method'],'uri':c['uri'][:500],'flags':c['flags']} for c in out if set(c['flags'])-{'download'}][:30]}
(work/'fast-summary.json').write_text(json.dumps(summary));print(json.dumps(summary))
