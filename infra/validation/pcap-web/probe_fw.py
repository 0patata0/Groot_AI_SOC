import json,socket,time,hashlib
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo
work=Path('/home/attack/.local/state/capstone-web-eval/20261103-r1');p=work/'fw-scan-results.json';assert not p.exists()
ports=[22,23,25,111,135,139,445,465,587,631,873,1433,1521,2049,2375,3306,3389,5432,5900,6379,9200,9300,11211,27017];rows=[];start=time.monotonic()
for i,port in enumerate(ports):
 s=socket.socket();s.settimeout(0.3);s.bind(('192.168.16.233',0));row={'port':port,'at_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),'source_port':s.getsockname()[1]}
 try:s.connect(('192.168.16.230',port));row['result']='connected'
 except OSError as exc:row['result']=type(exc).__name__
 finally:s.close()
 rows.append(row);p.write_text(json.dumps({'source':'192.168.16.233','target':'192.168.16.230','rows':rows}))
 delay=start+(i+1)*1.1-time.monotonic()
 if delay>0:time.sleep(delay)
print(p.read_text())
