"""Existing fixed SSH MCP endpoints: initialize/tools/list only, actual UID 995.

No tools/call, model, chat, Docker, package or policy mutation. Output is metadata.
"""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

ENDPOINTS={'wazuh-ro':['mcp-b'],'security-events':['mcp-b','security-events'],
           'resp':['resp-a'],'rule-a':['rule-a'],'rule-b':['rule-b']}
DIAGNOSTIC_ENDPOINT=['mcp-b','system-diagnostics']


def require(value):
    if not value: raise ValueError('read_only_probe_failed')


async def request(args):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    server=StdioServerParameters(command='/usr/bin/ssh',args=[
        '-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
        '-o','UpdateHostKeys=no','-o','ControlMaster=no','-o','ControlPath=none','-o','ConnectTimeout=10',
        '-F','/opt/data/home/.ssh/config']+args,
        env={'HOME':'/opt/data/home','PATH':'/usr/bin:/bin','LC_ALL':'C'})
    with open(os.devnull,'w') as errlog:
        async with stdio_client(server,errlog=errlog) as (read,write):
            async with ClientSession(read,write) as session:
                initialized=await session.initialize()
                require(bool(initialized.server_info.name))
                response=await session.list_tools()
                require(response.next_cursor is None)
                tools=response.tools
                require(0<len(tools)<=100)
                names=sorted(tool.name for tool in tools)
                require(len(names)==len(set(names)))
                if args == DIAGNOSTIC_ENDPOINT:
                    require(names == ['get_system_diagnostics'])
                return {'tools':len(names),'names_sha256':hashlib.sha256(json.dumps(names,separators=(',',':')).encode()).hexdigest()}


async def connections(endpoints=ENDPOINTS):
    values=await asyncio.wait_for(asyncio.gather(*(request(args) for args in endpoints.values())),timeout=60)
    return dict(zip(endpoints,values))


def configured_endpoints(config):
    require(type(config) is dict and set(config) in (set(ENDPOINTS), set(ENDPOINTS) | {'system-diagnostics'}))
    endpoints=dict(ENDPOINTS)
    if 'system-diagnostics' in config:endpoints['system-diagnostics']=DIAGNOSTIC_ENDPOINT
    for name,tail in endpoints.items():
        server=config[name]
        require(type(server) is dict and server.get('enabled',True) is True and server.get('command')=='ssh' and
                server.get('args')==['-T','-F','/opt/data/home/.ssh/config']+tail and
                server.get('env')=={'HOME':'/opt/data/home'})
    return endpoints


def main():
    require(os.getuid()==995 and os.getgid()==986)
    # Source and dependency parents must not allow the service account to replace files.
    paths=['/opt/hermes/capstone_korean_output_guard.py','/opt/hermes/plugins/platforms/mattermost/adapter.py',
           '/opt/hermes/gateway/run_turn.py','/opt/capstone-guard-runtime/regex-2026.9.29/lib/python3.13/site-packages/regex/_regex.cpython-313-x86_64-linux-gnu.so']
    for path in paths:
        for parent in [Path(path),*Path(path).parents]:
            st=parent.lstat();require(not stat.S_ISLNK(st.st_mode) and st.st_uid==0 and st.st_gid==0 and not st.st_mode&0o022)
    # Validate actual configured names/argv without printing environment or keys.
    import yaml
    config=yaml.safe_load(Path('/opt/data/config.yaml').read_text())['mcp_servers']
    endpoints=configured_endpoints(config)
    result=asyncio.run(connections(endpoints))
    print(json.dumps({'uid':995,'gid':986,'servers':result,'initialize':len(endpoints),'tools_list':len(endpoints),
                      'tools_call':0,'model_calls':0,'chat_posts':0,'parents_write_protected':True},sort_keys=True))

if __name__=='__main__':
    try:main()
    except Exception:
        print('{"error":"read_only_mcp_probe_failed"}');sys.exit(1)
