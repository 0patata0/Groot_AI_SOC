#!/usr/bin/env python3
"""Bounded HTTP rate/connection tests in a network-none nginx container only."""
import argparse,json,os,secrets,subprocess,tempfile,time
from pathlib import Path

def run(a,**kw):
 p=subprocess.run(a,capture_output=True,text=True,timeout=30,**kw)
 if p.returncode:raise RuntimeError(p.stderr[-1600:])
 return p.stdout

def main():
 p=argparse.ArgumentParser();p.add_argument('candidate',type=Path);a=p.parse_args()
 raw=a.candidate.read_text();guard=raw.split('# BEGIN SOC_WEB_TRAFFIC_GUARD',1)[1].split('# END SOC_WEB_TRAFFIC_GUARD',1)[0]
 image=run(['docker','inspect','--format','{{.Image}}','waf']).strip();name='capstone-web-check-'+secrets.token_hex(6);cid=None;backend=None
 with tempfile.TemporaryDirectory(prefix='web-guard-',dir='/var/lib') as tmp:
  folder=Path(tmp);config=folder/'nginx.conf';config.write_text('worker_processes 1; pid /tmp/nginx.pid; error_log /dev/stderr warn; events { worker_connections 256; } http { access_log off; client_body_temp_path /tmp/body; proxy_temp_path /tmp/proxy; fastcgi_temp_path /tmp/fastcgi; uwsgi_temp_path /tmp/uwsgi; scgi_temp_path /tmp/scgi; '+guard+' server { listen 8080 default_server; server_name fixture; location / { proxy_pass http://127.0.0.1:18090; } } server { listen 8080; server_name wazuh.groot.lab wazuh.grootlab.duckdns.org; return 308 https://$host$request_uri; } }');config.chmod(0o644)
  try:
   cid=run(['docker','run','-d','--name',name,'--label','io.capstone.web-guard-test='+name,'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','64','--memory','128m','--cpus','1','--tmpfs','/tmp:rw,noexec,nosuid,size=16m,mode=1777','--mount','type=bind,src='+str(config)+',dst=/etc/nginx/nginx.conf,readonly','--entrypoint','nginx',image,'-c','/etc/nginx/nginx.conf','-g','daemon off;']).strip()
   pid=int(run(['docker','inspect','--format','{{.State.Pid}}',cid]));assert pid>1
   ns=['nsenter','--target',str(pid),'--net','/usr/bin/python3','-B','-c']
   server="from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer;import time\nclass H(BaseHTTPRequestHandler):\n def do_GET(self):\n  if self.path=='/slow':time.sleep(1)\n  self.send_response(200);self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'ok')\n def log_message(self,*a):pass\nThreadingHTTPServer(('127.0.0.1',18090),H).serve_forever()"
   backend=subprocess.Popen(ns+[server],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   time.sleep(.5)
   client="""import http.client,json,time,concurrent.futures,collections

def one(path='/',host='fixture'):
 c=http.client.HTTPConnection('127.0.0.1',8080,timeout=5)
 try:
  c.request('GET',path,headers={'Host':host});r=c.getresponse();r.read();return r.status,r.getheader('Location')
 finally:c.close()
normal=[]
for _ in range(8):normal.append(one()[0]);time.sleep(.1)
redirect=one('/app/login?next=x','wazuh.grootlab.duckdns.org')
with concurrent.futures.ThreadPoolExecutor(64) as pool:connections=[v[0] for v in pool.map(lambda _:one('/slow'),range(64))]
time.sleep(2.1)
with concurrent.futures.ThreadPoolExecutor(16) as pool:burst=[v[0] for v in pool.map(lambda _:one(),range(240))]
result={'normal':dict(collections.Counter(normal)),'wazuh_http_redirect':redirect,'connection_64':dict(collections.Counter(connections)),'burst_240':dict(collections.Counter(burst)),'external_traffic':0}
assert normal==[200]*8 and redirect==(308,'https://wazuh.grootlab.duckdns.org/app/login?next=x')
assert 200 in connections and 429 in connections and 429 in burst and all(v in (200,429) for v in connections+burst)
print(json.dumps(result))
"""
   result=json.loads(run(ns+[client]));result['scope']='network-none fixture, not production load/capacity';print(json.dumps(result))
  finally:
   if backend:
    backend.terminate()
    try:backend.wait(timeout=3)
    except subprocess.TimeoutExpired:backend.kill();backend.wait(timeout=3)
   if cid:
    actual=json.loads(run(['docker','inspect','--format','{{json .Config.Labels}}',cid]));assert actual.get('io.capstone.web-guard-test')==name
    run(['docker','rm','-f',cid])
if __name__=='__main__':main()
