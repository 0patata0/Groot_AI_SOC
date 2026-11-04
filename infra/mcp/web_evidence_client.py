"""B-to-C fixed read transport using the installed diagnostic reader key.

Never accept a host, port, key, path, command or SSH option from a caller.
The reused reader remains unprivileged and may only return fixed snapshots.
"""
import json
import os
from pathlib import Path
import stat
import types

SERVER = Path('/opt/mcp/system-diagnostics-mcp.py')
_diagnostics = None


def diagnostics():
    global _diagnostics
    if _diagnostics is None:
        for p in (SERVER.parent, *SERVER.parent.parents):
            s=p.lstat()
            if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:
                raise ValueError('web_dependency_unsafe')
        fd=os.open(SERVER,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as stream:
            meta=os.fstat(stream.fileno())
            if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=0 or meta.st_nlink!=1 or meta.st_mode&0o022 or meta.st_size>131072:
                raise ValueError('web_dependency_unsafe')
            raw=stream.read(131073)
        module=types.ModuleType('fixed_web_diagnostic_transport');module.__file__=str(SERVER)
        exec(compile(raw,str(SERVER),'exec'),module.__dict__)
        _diagnostics=module
    return _diagnostics


def call(operation, arguments):
    if operation not in ('get_web_service_target','search_web_access') or not isinstance(arguments,dict):
        raise ValueError('web_operation_invalid')
    wire=(json.dumps({'operation':operation,'arguments':arguments},ensure_ascii=True,separators=(',',':'))+'\n').encode()
    if len(wire)>4096:
        raise ValueError('web_arguments_too_large')
    server=diagnostics();config=server.route_config();d=server.library()
    core=types.ModuleType('fixed_web_evidence_contract');path=Path(__file__).with_name('web_evidence.py');core.__file__=str(path)
    exec(compile(d.root_file(path,131072),str(path),'exec'),core.__dict__)
    value=core.request({'operation':operation,'arguments':arguments})
    wire=(json.dumps(value,ensure_ascii=True,separators=(',',':'))+'\n').encode()
    command=['/usr/bin/ssh','-F','/dev/null','-T','-p',str(config['ssh_port']),
        '-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes',
        '-o','UpdateHostKeys=no','-o','ControlMaster=no','-o','ControlPath=none',
        '-o','ForwardAgent=no','-o','ClearAllForwardings=yes','-o','PermitLocalCommand=no',
        '-o','ConnectTimeout=5','-o','ConnectionAttempts=1',
        '-o','UserKnownHostsFile='+str(server.KNOWN_HOSTS),'-i',str(server.IDENTITY),
        'capstone-web-evidence@'+config['hosts']['c']]
    code,raw=d.bounded_command(command,262144,12,input_data=wire)
    if code!=0:
        raise ValueError('web_evidence_unavailable')
    result=d.parsed(raw)
    if (not isinstance(result,dict) or result.get('source')!='c_apache_access_snapshot'
            or result.get('target')!=arguments.get('target') or result.get('mutation_performed') is not False
            or result.get('untrusted_evidence') is not True):
        raise ValueError('web_evidence_response_invalid')
    return result
