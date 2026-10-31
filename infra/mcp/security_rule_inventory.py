"""Bounded read-only inventories of installed security rule definitions.

Only fixed container paths are read. No input becomes a command/path. File
selection is configuration evidence, never proof of per-rule runtime loading.
"""
from collections import Counter
from datetime import datetime, timedelta, timezone
import base64
import fnmatch
import hashlib
import io
import json
import posixpath
import re
import shlex
import ssl
import stat
import urllib.request
import selectors
import subprocess
import tarfile
import time

TARGETS = {'a:waf': 'a:modsecurity-custom', 'a:suricata': 'a:suricata-local',
           'b:wazuh': 'b:wazuh-local-rules'}
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_FILE = 8 * 1024 * 1024
MAX_ROWS = 200000
WAF_ROOT = '/etc/modsecurity.d/'
WAF_AUDIT = '/var/log/modsecurity/capstone-managed/audit-path.conf'
WAZUH_ROOT = '/var/ossec/'
WAZUH_CREDENTIALS = '/etc/mcp/wazuh-ro.env'
WAZUH_CREDENTIAL_FORMAT = 'env'
WAZUH_API_HOST = '127.0.0.1'
WAZUH_API_USER = 'mcp-ro'


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else
                          json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def bounded_command(argv):
    """Drain stderr as well; stop before an unbounded archive enters memory."""
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    buffers = [bytearray(), bytearray()]
    try:
        with selectors.DefaultSelector() as sel:
            sel.register(process.stdout, selectors.EVENT_READ, 0)
            sel.register(process.stderr, selectors.EVENT_READ, 1)
            deadline = time.monotonic() + 40
            while sel.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError('inventory_read_timeout')
                for key, _ in sel.select(min(remaining, 1)):
                    raw = key.fileobj.read1(65536)
                    if not raw:
                        sel.unregister(key.fileobj)
                        continue
                    buffers[key.data].extend(raw)
                    if len(buffers[key.data]) > (MAX_ARCHIVE if key.data == 0 else 65536):
                        raise ValueError('inventory_read_too_large')
            if process.wait(timeout=max(.1, deadline-time.monotonic())) != 0:
                raise ValueError('inventory_read_failed')
        return bytes(buffers[0])
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()
        process.stderr.close()


def archive_files(raw, roots):
    files = {}
    if len(raw) > MAX_ARCHIVE:
        raise ValueError('archive_too_large')
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for member in archive:
            name = '/' + member.name.lstrip('/')
            if '..' in name.split('/') or posixpath.normpath(name) != name:
                raise ValueError('archive_path_invalid')
            if member.isdir():
                continue
            if not any(name == root or name.startswith(root.rstrip('/')+'/') for root in roots):
                raise ValueError('archive_outside_fixed_roots')
            if not member.isfile() or member.size > MAX_FILE or name in files:
                raise ValueError('archive_entry_invalid')
            if len(files) >= 2048:
                raise ValueError('archive_file_limit')
            data = archive.extractfile(member).read(MAX_FILE+1)
            if len(data) != member.size:
                raise ValueError('archive_incomplete')
            files[name] = data
    return files


def wazuh_api_reader(parser):
    """Existing readonly identity; no credential copies, caller URL or paths."""
    raw, metadata = parser._read_regular(WAZUH_CREDENTIALS, 65536)
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o027:
        raise ValueError('untrusted_readonly_API_credentials')
    if WAZUH_CREDENTIAL_FORMAT == 'json':
        env = json.loads(raw)
    else:
        env = {}
        for line in raw.decode('utf-8').splitlines():
            tokens = shlex.split(line, comments=True)
            if not tokens:
                continue
            if tokens[0] == 'export':
                tokens = tokens[1:]
            if len(tokens) != 1 or '=' not in tokens[0]:
                raise ValueError('invalid_readonly_API_configuration')
            key, value = tokens[0].split('=', 1)
            if key in env:
                raise ValueError('duplicate_readonly_API_configuration')
            env[key] = value
    if (env.get('WAZUH_API_HOST') != WAZUH_API_HOST or str(env.get('WAZUH_API_PORT')) != '55000'
            or env.get('WAZUH_API_USERNAME') != WAZUH_API_USER
            or not isinstance(env.get('WAZUH_API_PASSWORD'), str) or not env['WAZUH_API_PASSWORD']):
        raise ValueError('readonly_API_identity_mismatch')
    verify = str(env.get('WAZUH_VERIFY_SSL', 'true')).lower()
    if verify not in ('true', 'false') or (verify == 'false' and WAZUH_API_HOST != '127.0.0.1'):
        raise ValueError('invalid_readonly_API_TLS_configuration')
    context = (ssl.create_default_context(cafile=env.get('SSL_CERT_FILE')) if verify == 'true'
               else ssl._create_unverified_context())
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            raise ValueError('readonly_API_redirect_refused')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                        urllib.request.HTTPSHandler(context=context))
    deadline = time.monotonic() + 30
    def request(path, authorization, method='GET'):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError('readonly_API_deadline')
        try:
            req = urllib.request.Request('https://' + WAZUH_API_HOST + ':55000' + path,
                                         headers={'Authorization': authorization}, method=method)
            with opener.open(req, timeout=min(12, remaining)) as response:
                data = response.read(16 * 1024 * 1024 + 1)
            if len(data) > 16 * 1024 * 1024:
                raise ValueError('response_limit')
            result = json.loads(data)
            if result.get('error') != 0 or not isinstance(result.get('data'), dict):
                raise ValueError('response_error')
            return result['data']
        except (OSError, ValueError, TypeError):
            # Do not expose a server error body, credential or token in an RPC.
            raise ValueError('wazuh_readonly_API_unavailable') from None
    basic = base64.b64encode((WAZUH_API_USER + ':' + env['WAZUH_API_PASSWORD']).encode()).decode('ascii')
    token = request('/security/user/authenticate', 'Basic ' + basic, 'POST').get('token')
    if not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,16384}', token):
        raise ValueError('wazuh_readonly_API_authentication_failed')
    def read_all():
        items = []; total = None
        while total is None or len(items) < total:
            data = request('/rules?limit=5000&sort=id&offset=' + str(len(items)), 'Bearer ' + token)
            count, page = data.get('total_affected_items'), data.get('affected_items')
            if (type(count) is not int or not 0 <= count <= MAX_ROWS or not isinstance(page, list)
                    or len(page) > 5000 or data.get('total_failed_items') != 0
                    or (total is not None and count != total) or len(items) + len(page) > count
                    or (not page and count > len(items))):
                raise ValueError('wazuh_API_incomplete_inventory')
            total = count; items.extend(page)
        keys = [(r.get('relative_dirname'), r.get('filename'), r.get('id')) for r in items if isinstance(r, dict)]
        if len(keys) != len(items) or len(set(keys)) != len(keys):
            raise ValueError('wazuh_API_duplicate_or_invalid_page')
        return items
    return read_all


def wazuh_rules(items):
    """Use Wazuh's own interpretation, retaining its complete details object."""
    rows, grouped = [], {}
    for item in items:
        rid, directory, filename = item.get('id'), item.get('relative_dirname'), item.get('filename')
        if (type(rid) is not int or not 0 <= rid <= 999999 or not isinstance(directory, str)
                or directory.startswith('/') or '..' in directory.split('/')
                or not isinstance(filename, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,255}', filename)
                or item.get('status') not in ('enabled', 'disabled')
                or not isinstance(item.get('details'), dict) or not isinstance(item.get('groups'), list)
                or not all(isinstance(g, str) for g in item['groups'])):
            raise ValueError('wazuh_API_rule_schema_changed')
        source = WAZUH_ROOT + directory + '/' + filename
        origin = 'builtin' if directory == 'ruleset/rules' or directory.startswith('ruleset/rules/') else 'custom'
        configuration = 'selected' if item['status'] == 'enabled' else 'excluded'
        details = item['details']
        temporal = any(k.startswith(('if_matched_', 'same_', 'different_')) or k in
                       ('frequency', 'timeframe', 'global_frequency', 'not_same_source_ip') for k in details)
        dependency = any(k in details for k in ('if_sid', 'if_group', 'if_level'))
        row = {'id':str(rid), 'source':source, 'origin':origin, 'configuration':configuration,
               'attributes':{'id':str(rid), 'level':item.get('level'), **{k:v for k,v in details.items()
                   if k in ('frequency', 'timeframe', 'ignore', 'overwrite', 'noalert')}},
               'description':item.get('description', ''), 'groups':item['groups'], 'mitre':item.get('mitre', []),
               'correlation':temporal or dependency,
               'correlation_kind':'temporal' if temporal else 'dependency' if dependency else 'none',
               'conditions':[{'name':k, 'value':v} for k,v in details.items()],
               'details':details, 'api_definition':item}
        rows.append(row); grouped.setdefault(source, []).append(row)
    ids = {r['id'] for r in rows}; configured = {r['id'] for r in rows if r['configuration'] == 'selected'}
    groups = {g for r in rows for g in r['groups']}
    configured_groups = {g for r in rows if r['configuration'] == 'selected' for g in r['groups']}
    for row in rows:
        refs = []
        for condition in row['conditions']:
            if condition['name'] in ('if_sid', 'if_matched_sid', 'if_group', 'if_matched_group'):
                values = condition['value'] if isinstance(condition['value'], list) else [condition['value']]
                for value in values:
                    if not isinstance(value, str):
                        raise ValueError('wazuh_API_reference_schema_changed')
                    for key in filter(None, re.split(r'[,\s]+', value)):
                        is_id = condition['name'].endswith('sid')
                        refs.append({'kind':condition['name'], 'value':key,
                                     'definition_found':key in (ids if is_id else groups),
                                     'configured_definition_found':key in (configured if is_id else configured_groups)})
        row['references'] = refs
    files = [{'path':name, 'origin':records[0]['origin'], 'configuration':records[0]['configuration'],
              'api_definitions_sha256':digest([r['api_definition'] for r in records])}
             for name, records in sorted(grouped.items())]
    return rows, files, []


def waf_rules(files, parser):
    rows, sources, warnings, selected = [], [], [], set()
    statements = {}
    for name, raw in files.items():
        if name.endswith('.conf'):
            try:
                statements[name] = list(parser._waf_inventory_statements(raw.decode('utf-8')))
            except (ValueError, UnicodeError):
                warnings.append('unparsed_rule_file:'+name)
    def visit(name, stack=()):
        if name in stack:
            warnings.append('include_cycle:'+name); return
        selected.add(name)
        for line in statements.get(name, []):
            if re.match(r'^\s*Include\s', line, re.I):
                value = line.split(None, 1)[1].strip().strip('"\'')
                if not value.startswith(WAF_ROOT) and value != WAF_AUDIT:
                    warnings.append('unread_include:'+value); continue
                matches = sorted(n for n in statements if fnmatch.fnmatchcase(n, value))
                if not matches:
                    warnings.append('unmatched_include:'+value)
                for match in matches:
                    visit(match, stack+(name,))
    visit(WAF_ROOT+'setup.conf')
    removals = []
    for name in sorted(statements):
        origin = 'custom' if re.search(r'(?:GROOT|CAPSTONE)',posixpath.basename(name)) else 'builtin'
        sources.append({'path':name, 'sha256':digest(files[name]), 'origin':origin,
                        'configuration':'selected' if name in selected else 'unselected'})
        previous = None
        for line in statements[name]:
            try:
                args = parser._waf_inventory_arguments(line)
                directive = args[0].lower()
                if name in selected and directive.startswith(('secruleremove','secruleupdate')):
                    removals.append({'source':name,'directive':line})
                if directive not in ('secrule','secaction'):
                    continue
                actions = args[3] if directive=='secrule' and len(args)==4 else args[1] if directive=='secaction' and len(args)==2 else ''
                ids, chain = parser._waf_inventory_actions(actions) if actions else ([],False)
                if not ids:
                    if previous is None or not previous.pop('_chain',False):
                        raise ValueError('missing_rule_id')
                    previous['definition'] += '\n'+line
                    previous['_chain'] = chain
                    continue
                if len(ids) != 1:
                    raise ValueError('multiple_rule_ids')
                if previous is not None and previous.get('_chain'):
                    raise ValueError('unfinished_chain')
                previous = {'id':str(ids[0]),'source':name,'origin':origin,'configuration':sources[-1]['configuration'],
                            'directive':directive,'definition':line,'_chain':chain,'correlation':False}
                rows.append(previous)
            except (ValueError,IndexError):
                warnings.append('unparsed_rule_statement:'+name)
        if previous and previous.get('_chain'):
            warnings.append('unfinished_rule_chain:'+name)
    for row in rows:
        row.pop('_chain',None)
    # Dynamic ctl exclusions/updates depend on request context. Never calculate
    # an effective/active count by subtracting textual remove directives.
    return rows, sources, warnings, removals


def suricata_options(line):
    opening,closing=line.find(b'('),line.rfind(b')')
    if opening<0 or closing<=opening or line[closing+1:].strip():
        raise ValueError('invalid_rule_boundary')
    options=[];start=opening+1;quoted=False;escaped=False
    for i in range(start,closing):
        char=line[i]
        if escaped: escaped=False
        elif char==92: escaped=True
        elif char==34:
            if not quoted: quoted=True
            elif re.match(rb'\s*;',line[i+1:closing]): quoted=False
        elif char==59 and not quoted:
            key,_,value=line[start:i].strip().partition(b':')
            if not re.fullmatch(rb'[A-Za-z0-9_.-]+',key.strip()):
                raise ValueError('invalid_option_boundary')
            options.append((key.strip().lower(),value.strip()));start=i+1
    if quoted or escaped or line[start:closing].strip():
        raise ValueError('unterminated_rule_option')
    return options


def suricata_rules(data, source, origin, parser):
    rows = []
    for line, single in parser._suricata_lines(data):
        options=suricata_options(line)
        ids=[value for key,value in options if key==b'sid']
        if len(ids)!=1 or not ids[0].isdigit() or not 0<int(ids[0])<2**32:
            raise ValueError('invalid_signature_id')
        sid=int(ids[0])
        fields = {key.decode():value.decode('utf-8') for key,value in options if key in (b'msg',b'rev',b'gid',b'classtype',b'priority')}
        rows.append({'id':str(sid),'gid':fields.get('gid','1'),'source':source,'origin':origin,'configuration':'selected',
                     'header':line[:line.index(b'(')].decode('utf-8').strip(), 'attributes':fields,
                     'definition':line.decode('utf-8'), 'correlation':False})
    return rows


def inventory(engine, parser, request, command=bounded_command, api_reader=None):
    target=request.get('target'); origin=request.get('origin','all'); view=request.get('view','summary')
    offset=request.get('offset',0); limit=request.get('limit',20); rid=request.get('rule_id'); correlation=request.get('correlation_only',False)
    expected=request.get('snapshot_id')
    if (set(request)-{'target','origin','view','offset','limit','rule_id','correlation_only','snapshot_id'} or
            not isinstance(target,str) or target not in TARGETS or origin not in ('all','builtin','custom') or view not in ('summary','details') or
            type(offset) is not int or not 0<=offset<=MAX_ROWS or type(limit) is not int or not 1<=limit<=100 or
            type(correlation) is not bool or (correlation and target!='b:wazuh') or
            (rid is not None and (not isinstance(rid,str) or not re.fullmatch(r'[0-9]{1,10}',rid))) or
            (expected is not None and (not isinstance(expected,str) or not re.fullmatch('[0-9a-f]{64}',expected))) or
            (offset and not expected)):
        raise ValueError('invalid_inventory_arguments')
    spec=engine.spec(TARGETS[target]); warnings=[]; exclusions=[]
    with engine.locked():
        runtime=engine._inspect(spec)
        # Include stable container identity/start in pagination binding. Do not
        # return environment variables or the full inspection.
        info=json.loads(engine.runner.call([parser.DOCKER,'inspect',spec['container']]))[0]
        identity={'container':spec['container'],'id':info['Id'],'started_at':info['State']['StartedAt']}
        if target=='a:suricata':
            current,_,aux=engine._snapshot(spec)
            et,_=parser._read_regular(spec['et_path'],parser.MAX_RULESET)
            if digest(et)!=aux['et_sha256']:
                raise ValueError('rules_changed_during_read')
            rows=suricata_rules(et,spec['et_path'],'builtin',parser)+suricata_rules(current,spec['path'],'custom',parser)
            files=[{'path':spec[k], 'sha256':digest(v), 'origin':o,'configuration':'selected'}
                   for k,v,o in [('et_path',et,'builtin'),('path',current,'custom')]]
            runtime.update(rule_source_option='-S',rule_source_path='/rules/all.rules',combined_is_exact_et_plus_local=True,
                           combined_sha256=aux['all_sha256'])
        elif target == 'b:wazuh':
            read_api = api_reader or wazuh_api_reader(parser)
            items = read_api()
            if items != read_api():
                raise ValueError('rules_changed_during_read')
            rows, files, warnings = wazuh_rules(items)
            runtime.update(definition_source='official_wazuh_API_rules', API_identity='existing_readonly_account',
                           status_scope='API_configuration_selection_not_engine_memory')
        else:
            roots=[WAF_ROOT+n for n in ('setup.conf','modsecurity.conf','modsecurity-override.conf','owasp-crs/crs-setup.conf',
                                        'owasp-crs/plugins','owasp-crs/rules')]+[WAF_AUDIT]
            raw=command([parser.DOCKER,'exec',spec['container'],'tar','-chf','-',*roots])
            contents=archive_files(raw,roots)
            second=archive_files(command([parser.DOCKER,'exec',spec['container'],'tar','-chf','-',*roots]),roots)
            if contents != second:
                raise ValueError('rules_changed_during_read')
            entry=engine.runner.call([parser.DOCKER,'exec',spec['container'],'cat','/etc/nginx/conf.d/modsecurity.conf']).decode()
            if not re.search(r'^\s*modsecurity\s+on;',entry,re.M) or not re.search(r'^\s*modsecurity_rules_file\s+/etc/modsecurity\.d/setup\.conf;',entry,re.M):
                raise ValueError('waf_entrypoint_changed')
            rows,files,warnings,exclusions=waf_rules(contents,parser)
            files.append({'path':'/etc/nginx/conf.d/modsecurity.conf','sha256':digest(entry.encode()),'origin':'builtin','configuration':'selected'})
        final=json.loads(engine.runner.call([parser.DOCKER,'inspect',spec['container']]))[0]
        if final['Id']!=identity['id'] or final['State']['StartedAt']!=identity['started_at']:
            raise ValueError('engine_changed_during_read')
    if target == 'a:suricata':
        service = parser._load_extension('service_action_executor').ServiceActionService(engine)
        runtime['engine_counters'] = service._rule_engine_evidence(runtime)
    for field in ('started_at', 'observed_at'):
        value = runtime.pop(field, None)
        if value is not None:
            instant = (datetime.fromtimestamp(value, timezone.utc) if type(value) in (float, int)
                       else datetime.fromisoformat(value.replace('Z', '+00:00')))
            if instant.tzinfo is None:
                raise ValueError('timezone_free_runtime_timestamp')
            runtime[field + '_kst'] = instant.astimezone(timezone(timedelta(hours=9))).isoformat()
    if len(rows)>MAX_ROWS:
        raise ValueError('rule_count_limit')
    snapshot=digest({'files':files,'identity':identity})
    if expected and expected!=snapshot:
        raise ValueError('inventory_snapshot_changed_restart_pagination')
    counts={'definitions':len(rows),'builtin':sum(r['origin']=='builtin' for r in rows),
            'custom':sum(r['origin']=='custom' for r in rows),'configured':sum(r['configuration']=='selected' for r in rows),
            'excluded':sum(r['configuration']=='excluded' for r in rows),'correlation':sum(r['correlation'] for r in rows),
            'temporal_correlation':sum(r.get('correlation_kind')=='temporal' for r in rows),
            'dependency_rules':sum(r.get('correlation_kind')=='dependency' for r in rows)}
    multiplicity=Counter((r.get('gid','1'),r['id']) for r in rows)
    duplicate_ids=[{'gid':gid,'id':rid,'definitions':n} for (gid,rid),n in multiplicity.items() if n>1]
    selected=[r for r in rows if (origin=='all' or r['origin']==origin) and (rid is None or r['id']==rid)
              and (not correlation or r['correlation'])]
    if offset>len(selected):
        raise ValueError('inventory_offset_out_of_range')
    page=selected[offset:offset+limit]
    if view=='summary':
        page=[{k:v for k,v in r.items() if k in ('id','gid','source','origin','configuration','correlation','description')} for r in page]
    result={'schema_version':1,'target':target,'status':'partial' if warnings else 'complete',
            'observed_at_kst':datetime.now(timezone(timedelta(hours=9))).isoformat(), 'snapshot_id':snapshot,
            'scope':'installed_rule_definitions_and_configuration_selection','runtime_load_verified':False,
            'runtime':runtime,'counts':counts,'source_file_count':len(files),
            'files_scope':'sources_of_returned_rules',
            'files':[f for f in files if f['path'] in {r['source'] for r in page}],'warnings':list(dict.fromkeys(warnings)),
            'duplicate_rule_ids':duplicate_ids,'exclusions_and_updates':exclusions,'filter':{'origin':origin,'rule_id':rid,'correlation_only':correlation},
            'view':view,'matched_count':len(selected),'offset':offset,'limit':limit,'returned_count':len(page),
            'next_offset':offset+len(page) if offset+len(page)<len(selected) else None,'rules':page,
            'limits':['Configuration selection is not per-rule runtime loading or actual detection proof.',
                      'Summary rules are a labeled sample; use details and snapshot-bound pagination for a complete list.',
                      'Unparsed files/statements make totals incomplete; missing evidence is not zero.',
                      'Changes use existing approved custom-target proposals; vendor files remain read-only.']}
    result['receipt_sha256']=digest(result)
    if len(json.dumps(result,ensure_ascii=False).encode())>1024*1024:
        raise ValueError('inventory_response_too_large_reduce_limit')
    return result
