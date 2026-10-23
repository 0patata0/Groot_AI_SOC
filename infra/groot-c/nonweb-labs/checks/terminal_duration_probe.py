#!/usr/bin/env python3
"""Fixed read-only C metadata probe for the real-time terminal duration check. No lab writes."""
import os,stat,json,time,hashlib,sys,re,importlib.util,subprocess
from pathlib import Path
ROOT=Path('/opt/capstone-nonweb-labs')
EXPECTED={'runtime.py': '6e104959cc3a03c8d400d8438a2051246f6db7e66f1c43563c658eafd010a4b0', 'terminal_server.py': '61a1fc0cfee3748e1e73c7cbbc805e206d823a4225481387a02de7877eba1fb1', 'sudo_terminal.py': '35825535c02539f9815df3c556e7676158281f2d15cd058f577efc2bd2edcf51', 'terminal.service': '3862bf3019345822e5a182104e3554997225c4f5d464f8386949273b148435ac'}
def load(name):
 q=ROOT/(name+'.py');spec=importlib.util.spec_from_file_location('ttl_fixed_'+name,q);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod
for name,digest in EXPECTED.items():
 q=ROOT/name;m=q.lstat();assert stat.S_ISREG(m.st_mode) and m.st_uid==0 and m.st_nlink==1 and not m.st_mode&0o022 and hashlib.sha256(q.read_bytes()).hexdigest()==digest,'approved_source_mismatch'
r=load('runtime');config=r.load_config();docker=r.Docker();found=r.inventory(docker,config)
try:r.guard();guard_ok=True
except r.Rejected:guard_ok=False
states={}
for lab in ('redis','samba'):
 status=r.status(docker,config,lab,found)
 row={k:status[k] for k in ('status','container_id','image_id','image_present')}
 row['deployment_allowed']=guard_ok
 row['started_at']=found[lab]['State']['StartedAt'] if lab in found else None
 states[lab]=row
s=load('sudo_terminal');s.Adapter()._context()
args=s.operator_prefix()+[s.executable('/usr/local/bin/docker') if Path('/usr/local/bin/docker').is_file() else s.executable('/usr/bin/docker'),'--host',s.SOCKET]
def rootless(command):
 result=subprocess.run(args+command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=s.ENV,timeout=12,check=True)
 assert len(result.stdout)<=131072
 return result.stdout
ids=rootless(['container','ls','-aq','--no-trunc','--filter','name=^/capstone-sudo-cve-2021-3156$']).decode().splitlines();assert len(ids)<=1 and all(re.fullmatch('[0-9a-f]{64}',cid) for cid in ids)
if ids:
 form='{{json .Id}}|{{json .Image}}|{{json .State.Running}}|{{json .State.StartedAt}}|{{json .State.Pid}}'
 vals=[json.loads(v) for v in rootless(['container','inspect','--format',form,ids[0]]).decode().strip().split('|')]
 assert len(vals)==5 and vals[0]==ids[0] and vals[1]==s.APPROVED_CONFIG['image_id']
 states['sudo']={'status':'running' if vals[2] else 'stopped','container_id':vals[0],'image_id':vals[1],'started_at':vals[3],'pid':vals[4]}
else:states['sudo']={'status':'not_deployed','container_id':None,'image_id':s.APPROVED_CONFIG['image_id'],'started_at':None,'pid':0}
pidraw=r.command(['/usr/bin/systemctl','show','--value','--property=MainPID','capstone-nonweb-terminal.service'],timeout=8).stdout.decode().strip();assert pidraw.isdigit() and int(pidraw)>1
mainpid=int(pidraw)
def children(pid):
 rows=set()
 try:tasks=list(Path('/proc',str(pid),'task').iterdir())
 except FileNotFoundError:return rows
 for task in tasks:
  try:rows.update(int(v) for v in (task/'children').read_text().split())
  except FileNotFoundError:pass
 return rows
seen=set();pending=list(children(mainpid))
while pending:
 pid=pending.pop()
 if pid in seen:continue
 seen.add(pid);pending.extend(children(pid)-seen)
counts={lab:0 for lab in states};other_pty=0;lifecycle=0;pty_processes=[]
for pid in seen:
 try:argv=Path('/proc',str(pid),'cmdline').read_bytes().split(b'\0');argv=[x.decode('utf8','replace') for x in argv if x]
 except FileNotFoundError:continue
 if 'lab.sh' in ' '.join(argv) and any(x in argv for x in ('up','stop','reset','down')):lifecycle+=1
 if 'exec' in argv and '-i' in argv and '-t' in argv and argv and Path(argv[0]).name=='docker':
  labs=[lab for lab,state in states.items() if state['container_id'] and state['container_id'] in argv]
  if len(labs)==1:
   counts[labs[0]]+=1
   try:start=int(Path('/proc',str(pid),'stat').read_text().rsplit(')',1)[1].split()[19])
   except FileNotFoundError:continue
   pty_processes.append({'lab':labs[0],'pid':pid,'start_ticks':start})
  else:other_pty+=1
worker_counts={lab:0 for lab in ('redis','samba')};worker_processes=[]
for lab in ('redis','samba'):
 if states[lab]['status']!='running':continue
 raw=docker.run('container','top',states[lab]['container_id'],'-eo','pid,uid,comm',timeout=10).stdout.decode()
 for row in raw.splitlines()[1:]:
  cells=row.split()
  if len(cells)!=3 or cells[1]!='10001' or cells[2]!='sh':continue
  try:argv=Path('/proc',cells[0],'cmdline').read_bytes().split(b'\0');argv=[x for x in argv if x]
  except FileNotFoundError:continue
  if len(argv)==4 and argv[:3]==[b'/bin/sh',b'/lab/terminal-session.sh',b'--worker'] and re.fullmatch(b'[0-9a-f]{64}',argv[3]):
   worker_counts[lab]+=1
   try:start=int(Path('/proc',cells[0],'stat').read_text().rsplit(')',1)[1].split()[19])
   except FileNotFoundError:continue
   worker_processes.append({'lab':lab,'pid':int(cells[0]),'start_ticks':start})
publish={}
for name,q in [('nonweb',Path('/var/lib/capstone-nonweb-labs/status.json')),('sudo',Path('/var/lib/capstone-offline-labs/nonweb-status.json'))]:
 try:
  doc=json.loads(q.read_text());publish[name]={'fresh':doc.get('expires_at',0)>int(time.time()),'age_seconds':int(time.time())-doc.get('checked_at',0),'labs':doc.get('labs',{})}
 except (FileNotFoundError,ValueError):publish[name]={'fresh':False}
result={'schema':1,'observed_at':int(time.time()),'status':'readonly_preflight','lab_states':states,'daemon_active_PTY_clients_by_lab':counts,'other_daemon_PTY_clients':other_pty,'daemon_lifecycle_mutations_in_progress':lifecycle,'container_session_workers':worker_counts,'daemon_PTY_processes':pty_processes,'container_worker_processes':worker_processes,'status_publishers':publish,'limitations':['active PTY/worker process counts observed; in-memory closed/stale session map is not exposed by current API','rootless sudo state inspected without start/stop/verify execution','no session capability or process tag returned'],'source_matches_reviewed':True,'terminal_daemon_main_pid':mainpid,'control_socket_inode':Path('/run/capstone-nonweb-labs/control.sock').lstat().st_ino,'source_or_config_writes':0,'terminal_open_or_input_or_close':0,'container_start_stop_or_restart':0}
print(json.dumps(result,sort_keys=True))
