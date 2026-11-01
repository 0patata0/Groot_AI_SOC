"""Capture current MCP contracts/read evidence on B; no model or chat calls.

Run with the existing unprivileged SOC account/environment. The caller retains
the private JSON receipt locally and performs all cleansing there.
"""
import argparse
import asyncio
from datetime import datetime,timedelta
import hashlib
import json
import os
from pathlib import Path
import sys
from zoneinfo import ZoneInfo

READS={
 'resp':[('get_firewall_rules',{'limit':100})],
 'rule-a':[
  ('get_security_rules',{'target':'a:waf','origin':'all','view':'summary'}),
  ('get_security_rules',{'target':'a:waf','origin':'all','view':'details','limit':3}),
  ('get_security_rules',{'target':'a:suricata','origin':'all','view':'summary'}),
  ('get_security_rules',{'target':'a:suricata','origin':'all','view':'details','limit':3}),
  ('get_rule_change_target',{'target':'a:modsecurity-custom'}),
  ('get_rule_change_target',{'target':'a:suricata-local'})],
 'rule-b':[
  ('get_security_rules',{'target':'b:wazuh','origin':'all','view':'summary'}),
  ('get_security_rules',{'target':'b:wazuh','origin':'all','view':'summary','correlation_only':True}),
  ('get_security_rules',{'target':'b:wazuh','origin':'all','view':'details','correlation_only':True,'limit':3}),
  ('get_rule_change_target',{'target':'b:wazuh-local-rules'})],
 'system-diagnostics': [('get_system_diagnostics',{'target':t})for t in ('a:systemd','b:systemd','c:systemd','a:suricata','a:waf','a:vector')],
}


def validate_capture(report):
    """Verify a completed read receipt locally; never execute its contents.

    This proves collection/schema consistency, not answer quality, per-rule
    runtime loading, or permission to train on the captured observations.
    """
    from audit_tools import audit_rows

    if report.get('status') != 'completed' or report.get('errors'):
        raise ValueError('Incomplete MCP collection')
    for key in ('protected_calls', 'model_calls', 'chat_posts'):
        if type(report.get(key)) is not int or report[key] != 0:
            raise ValueError('Collection must be read-only without model/chat calls')
    if report.get('cleansing_performed') is not False:
        raise ValueError('Cleansing belongs on the local workstation')
    tools = report['tools']
    lookup = {t['name']: t for t in tools}
    if len(lookup) != len(tools):
        raise ValueError('Duplicate tool aliases')
    expected = {(server, name, json.dumps(args, sort_keys=True))
                for server, reads in READS.items() for name, args in reads}
    seen = set()
    rows = []
    for read in report['reads']:
        key = (read['server'], read['name'], json.dumps(read['arguments'], sort_keys=True))
        alias = 'mcp__' + read['server'].replace('-', '_') + '__' + read['name']
        tool = lookup.get(alias)
        if (key not in expected or key in seen or read['alias'] != alias
                or not tool or tool['server'] != read['server']
                or tool['protected'] is not False):
            raise ValueError('Unexpected, duplicated or protected read')
        seen.add(key)
        if read['is_error'] is not False:
            raise ValueError('MCP tool returned an error')
        if hashlib.sha256(read['result'].encode()).hexdigest() != read['sha256']:
            raise ValueError('MCP result digest mismatch')
        data = json.loads(read['result'])
        if not isinstance(data, dict) or data.get('error'):
            raise ValueError('Invalid or failed MCP result')
        stamp = datetime.fromisoformat(read['at_kst'])
        if stamp.utcoffset() != timedelta(hours=9):
            raise ValueError('Receipt timestamp must be KST')
        rows.append({'messages': [{'role': 'assistant', 'tool_calls': [
            {'function': {'name': alias, 'arguments': read['arguments']}}]}]})
    if seen != expected:
        raise ValueError('Missing required reads')
    audit = audit_rows(rows, {'tools': tools})
    if audit['counts'].get('schema_valid_calls') != len(rows):
        raise ValueError('Read arguments do not match the captured schema')
    return {'tools': len(tools), 'reads': len(rows), 'schema_audit': audit,
            'training_admitted': False, 'answer_accuracy_reviewed': False}


async def capture():
    sys.path.insert(0,'/opt/capstone-ollama-trial')
    from mcp_use import MCPClient
    from jsonschema import Draft202012Validator
    from policy import protected,alias,filter_catalog
    config=json.loads(Path('/etc/capstone-ollama-trial/config.json').read_text())
    report={'at_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),'tools':[],'reads':[],'errors':[],
            'protected_calls':0,'model_calls':0,'chat_posts':0,'cleansing_performed':False}
    for server,profile in config['mcpServers'].items():
        client=MCPClient(config={'mcpServers':{server:profile}},code_mode=False,sandbox=False,sampling_callback=None,elicitation_callback=None)
        try:
            session=await asyncio.wait_for(client.create_session(server,auto_initialize=False),30)
            await asyncio.wait_for(session.initialize(),30)
            connector=session.connector
            tools=await asyncio.wait_for(connector.list_tools(),30)
            lookup={t.name:t for t in filter_catalog(server,tools,'hermes-parity')}
            for name,t in lookup.items():
                report['tools'].append({'server':server,'name':alias(server,name),'protected':protected(server,name),
                    'description':t.description or '', 'parameters':t.inputSchema})
            for name,arguments in READS.get(server,[]):
                if protected(server,name):raise ValueError('Protected call forbidden')
                if name not in lookup:raise ValueError('Read tool missing')
                try:Draft202012Validator(lookup[name].inputSchema).validate(arguments)
                except Exception as e:
                    report['errors'].append({'server':server,'name':name,'arguments':arguments,'phase':'schema','error':type(e).__name__});continue
                result=await asyncio.wait_for(connector.call_tool(name,arguments,read_timeout_seconds=timedelta(seconds=60)),65)
                text='\n'.join(c.text for c in result.content if getattr(c,'type',None)=='text')
                if len(text.encode())>2*1024**2:raise ValueError('Read result bound')
                report['reads'].append({'server':server,'name':name,'alias':alias(server,name),'arguments':arguments,
                    'result':text,'is_error':bool(result.isError),'sha256':hashlib.sha256(text.encode()).hexdigest(),
                    'at_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat()})
                if result.isError:
                    report['errors'].append({'server':server,'name':name,'phase':'tool_result','error':'isError'})
        except Exception as e:report['errors'].append({'server':server,'error':type(e).__name__,'phase':'transport'})
        finally:
            try:await asyncio.wait_for(client.close_all_sessions(),10)
            except Exception as e:report['errors'].append({'server':server,'error':type(e).__name__,'phase':'close'})
    report['tools'].sort(key=lambda t:t['name']);report['status']='completed'if not report['errors']else'partial'
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify',type=Path,help='Verify a private receipt locally; no network or model calls')
    parser.add_argument('--catalog',type=Path,help='Write a new contract snapshot after local verification')
    options=parser.parse_args()
    if options.catalog and not options.verify:parser.error('--catalog requires --verify')
    if options.verify:
        raw=options.verify.read_bytes();report=json.loads(raw)
        review=validate_capture(report)
        if options.catalog:
            catalog={'observed_at_kst':report['at_kst'],
                     'scope':'Live discovery of allowed tools; schema and read receipts only, not training/quality approval',
                     'capture_sha256':hashlib.sha256(raw).hexdigest(),'tools':report['tools']}
            with options.catalog.open('x')as f:json.dump(catalog,f,ensure_ascii=False,indent=2);f.write('\n')
            review['catalog_sha256']=hashlib.sha256(options.catalog.read_bytes()).hexdigest()
        print(json.dumps(review,ensure_ascii=False,indent=2))
    else:
        public=os.dup(1);os.dup2(2,1)
        report=asyncio.run(capture())
        with os.fdopen(public,'w')as f:f.write(json.dumps(report,ensure_ascii=False)+'\n')
