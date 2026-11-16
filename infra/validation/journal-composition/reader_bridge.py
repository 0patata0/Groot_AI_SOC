"""Build a temporary operator-status relay around the exact existing reader.

The original byte stream and all normal requests retain their original reader.
This builder is not a deployer and has no CLI, approval or service-control API.
"""
import ast
import base64
import hashlib
import importlib.util
from pathlib import Path

SPEC=importlib.util.spec_from_file_location('release_bridge_contract',Path(__file__).with_name('release_status.py'))
contract=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(contract)

PREFIX=r'''#!/usr/bin/env python3
"""Temporary operator-only source-status relay; normal reader preserved."""
import base64,hashlib,json,os,re,socket,stat,struct,sys,syslog,types
from pathlib import Path
from datetime import datetime,timedelta
_SOCKET=Path('/run/capstone-journal-release-status/reader.sock')
_REPLY=65536
_TARGETS=__TARGETS__
_ORIGINAL=__ORIGINAL__
_BEFORE=__BEFORE__

def _need(value,reason):
 if not value:raise ValueError(reason)
def _pairs(items):
 out={}
 for k,v in items:
  _need(k not in out,'duplicate_key');out[k]=v
 return out
def _parse(raw):
 return json.loads(raw,object_pairs_hook=_pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite')))
def _client(query,*,_socket_path=_SOCKET,_peer_uid=0,_allow_fixture=False):
 _need(isinstance(query,dict) and set(query)=={'schema','host','release_id'},'status_request')
 _need(type(query['schema']) is int and query['schema']==1 and isinstance(query['host'],str) and query['host'] in _TARGETS,'status_identity')
 _need(isinstance(query['release_id'],str) and re.fullmatch('[0-9a-f]{32}',query['release_id']),'status_release')
 parent=_socket_path.parent;st=parent.lstat()
 _need(stat.S_ISDIR(st.st_mode) and st.st_uid==_peer_uid and not st.st_mode&0o022,'status_directory')
 if _socket_path==_SOCKET:
  for p in parent.parents:
   s=p.lstat();_need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'status_parent')
 s=_socket_path.lstat();_need(stat.S_ISSOCK(s.st_mode) and s.st_uid==_peer_uid and s.st_nlink==1,'status_socket')
 with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as conn:
  conn.settimeout(2);conn.connect(str(_socket_path))
  _,uid,_=struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));_need(uid==_peer_uid,'status_peer')
  conn.sendall(json.dumps(query,sort_keys=True,separators=(',',':')).encode())
  raw,_,flags,_=conn.recvmsg(_REPLY+1);_need(raw and len(raw)<=_REPLY and not flags&socket.MSG_TRUNC,'status_reply_bound')
 value=_parse(raw)
 _need(isinstance(value,dict) and set(value)=={'schema','kind','host','release_id','source_contract_sha256','observed_at_kst','generation','phase','files','cache','mutation_performed','isolated_filesystem'},'status_reply')
 _need(type(value['schema']) is int and value['schema']==1 and value['kind']=='release_status' and value['host']==query['host'] and value['release_id']==query['release_id'],'status_reply_identity')
 _need(isinstance(value['source_contract_sha256'],str) and re.fullmatch('[0-9a-f]{64}',value['source_contract_sha256']),'status_source_contract')
 _need(value['mutation_performed'] is False and type(value['isolated_filesystem']) is bool and (_allow_fixture or not value['isolated_filesystem']),'status_read_only')
 _need(value['generation'] in ('baseline','candidate','mixed','foreign') and value['phase'] in ('unknown','staged','armed','quiesced','backed_up','applying','applied','verified','confirming','confirmed','rolling_back','rolled_back','failed'),'status_phase')
 at=datetime.fromisoformat(value['observed_at_kst']);_need(at.utcoffset()==timedelta(hours=9),'status_time')
 files=value['files'];_need(isinstance(files,list) and len(files)==len(_TARGETS[query['host']]),'status_files')
 for row in files:
  _need(isinstance(row,dict) and set(row)=={'target','sha256','metadata_matches'} and type(row['metadata_matches']) is bool,'status_file_shape')
  _need(row['target'] in _TARGETS[query['host']] and (row['sha256'] is None or isinstance(row['sha256'],str) and re.fullmatch('[0-9a-f]{64}',row['sha256'])),'status_file')
 _need({r['target'] for r in files}==set(_TARGETS[query['host']]),'status_targets')
 cache=value['cache'];_need(isinstance(cache,dict) and set(cache)=={'status','source_filter_policy'} and cache['status'] in ('observed','unavailable') and cache['source_filter_policy'] in (None,'application-severity-v1'),'status_cache')
 return value

def _base():
 raw=base64.b64decode(_ORIGINAL,validate=True);_need(hashlib.sha256(raw).hexdigest()==_BEFORE,'original_reader_changed')
 module=types.ModuleType('unchanged_release_reader');module.__file__=__file__
 exec(compile(raw,'pinned-original-reader','exec'),module.__dict__)
 return module
def main():
 _need(len(sys.argv)==1 and not os.environ.get('SSH_ORIGINAL_COMMAND',''),'reader_takes_no_command')
 original=_base();raw=original.incoming()
 if raw:
  value=_parse(raw)
  if isinstance(value,dict) and set(value)=={'release_status'}:
   reply=_client(value['release_status'])
   syslog.syslog(syslog.LOG_NOTICE,'system_diagnostics_operator_release_status_read')
   sys.stdout.buffer.write(json.dumps(reply,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode());sys.stdout.buffer.flush();return
 original.incoming=lambda:raw
 original.main()
if __name__=='__main__':
 try:main()
 except (ValueError,OSError,KeyError,TypeError):
  syslog.syslog(syslog.LOG_WARNING,'system_diagnostics_operator_release_status unavailable')
  raise SystemExit(1) from None
'''


def build(original, expected_sha256):
    if not isinstance(original,bytes) or not 0<len(original)<=131072:
        raise ValueError('original_reader_bound')
    if hashlib.sha256(original).hexdigest()!=expected_sha256:
        raise ValueError('original_reader_changed')
    ast.parse(original)
    targets={host:sorted(paths) for host,paths in contract.TARGETS.items()}
    text=PREFIX.replace('__TARGETS__',repr(targets),1)
    text=text.replace('__ORIGINAL__',repr(base64.b64encode(original).decode()),1)
    text=text.replace('__BEFORE__',repr(expected_sha256),1)
    ast.parse(text)
    return text.encode()
