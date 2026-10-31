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


def bounded_command(argv, *, diagnostics=False):
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
            exit_code = process.wait(timeout=max(.1, deadline-time.monotonic()))
            if exit_code != 0 and not diagnostics:
                raise ValueError('inventory_read_failed')
        return (bytes(buffers[0]), bytes(buffers[1]), exit_code) if diagnostics else bytes(buffers[0])
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


def waf_statements(content, parser):
    """Retain the starting physical line while using the reviewed lexer."""
    pending = ''; start = None
    for number, line in enumerate(content.split('\n'), 1):
        if not line.strip() or line.lstrip().startswith('#'):
            if pending: raise ValueError('comment_inside_continuation')
            continue
        if start is None: start = number
        pending += line[:-1] if line.endswith('\\') else line
        if not line.endswith('\\'):
            # The existing parser validates escapes and argument boundaries.
            yield start, pending, parser._waf_inventory_arguments(pending)
            pending = ''; start = None
    if pending: raise ValueError('unfinished_continuation')


def waf_actions(text, parser):
    if not text: return []
    parser._waf_inventory_actions(text)
    parts = []; start = 0; quote = None; escaped = False
    for index, char in enumerate(text):
        if escaped: escaped = False
        elif char == '\\': escaped = True
        elif quote:
            if char == quote: quote = None
        elif char in "\"'": quote = char
        elif char == ',': parts.append(text[start:index]); start = index + 1
    parts.append(text[start:])
    result = []
    for part in parts:
        key, colon, value = part.strip().partition(':'); value = value.strip()
        if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]: value = value[1:-1]
        result.append({'name':key.strip().lower(), 'value':value if colon else None})
    return result


def waf_rules(files, parser, metadata=None):
    rows, sources, warnings, selected = [], [], [], set()
    statements = {}; ordered = []; include_edges = []
    def parse(name):
        if name not in statements:
            try: statements[name] = list(waf_statements(files[name].decode('utf-8'), parser))
            except (ValueError, UnicodeError):
                warnings.append('unparsed_rule_file:'+name); statements[name] = []
        return statements[name]
    def visit(name, stack=()):
        if len(stack) > 32 or name in stack:
            warnings.append('include_cycle_or_depth:'+name); return
        if name in selected:
            warnings.append('repeated_include:'+name); return
        if name not in files:
            warnings.append('unread_include:'+name); return
        selected.add(name)
        for number, line, args in parse(name):
            if args and args[0].lower() == 'include':
                if len(args) != 2:
                    warnings.append('unsupported_include:'+name+':'+str(number)); continue
                value = args[1]
                if (not value.startswith(WAF_ROOT) and value != WAF_AUDIT) or '..' in value.split('/'):
                    warnings.append('unread_include:'+value); continue
                matches = sorted(n for n in files if fnmatch.fnmatchcase(n, value))
                include_edges.append({'source':name,'line':number,'pattern':value,'matches':matches})
                if not matches: warnings.append('unmatched_include:'+value)
                for match in matches: visit(match, stack+(name,))
            else: ordered.append((name,number,line,args,True))
    visit(WAF_ROOT+'setup.conf')
    for name in sorted(files):
        if name.endswith('.conf') and name not in selected:
            ordered.extend((name,n,line,args,False) for n,line,args in parse(name))
    for name in sorted(statements):
        sources.append({'path':name,'sha256':digest(files[name]),
                        'origin':'custom' if re.search(r'(?:GROOT|CAPSTONE)',posixpath.basename(name)) else 'builtin',
                        'configuration':'selected' if name in selected else 'unselected'})
    origins = {s['path']:s['origin'] for s in sources}
    removals = []; markers = []; defaults = {}; modes = []; previous = None; controls = []
    disruptive = {'allow','block','deny','drop','pass','redirect','proxy'}
    for name, number, line, args, included in ordered:
        try:
            directive = args[0].lower(); location = {'source':name,'line':number}
            if previous and previous.get('_chain') and (directive != 'secrule' or previous['source'] != name):
                warnings.append('interrupted_rule_chain:'+previous['source']+':'+str(previous['line'])); previous['_chain'] = False
            if included and directive == 'secruleengine':
                if len(args) != 2 or args[1].lower() not in ('on','off','detectiononly'): raise ValueError('invalid_engine_mode')
                modes.append({**location,'value':args[1]})
            if included and directive == 'secdefaultaction':
                actions = waf_actions(args[1],parser) if len(args)==2 else []
                phases = [a['value'] for a in actions if a['name']=='phase']
                if len(phases)!=1 or phases[0] not in ('1','2','3','4','5'): raise ValueError('unsupported_default_phase')
                defaults[phases[0]] = {**location,'actions':actions}
            if included and directive == 'secmarker':
                if len(args)!=2: raise ValueError('invalid_marker')
                markers.append({**location,'name':args[1]})
            if included and directive.startswith(('secruleremove','secruleupdate')):
                removals.append({**location,'directive':line,'kind':directive,'arguments':args[1:],
                                 'scope':'configuration_time_exception_or_update'})
            if directive not in ('secrule','secaction'):
                if included and (directive in ('secrulescript','secremoterules','includeoptional') or directive.startswith('<')):
                    warnings.append('unsupported_rule_source:'+name+':'+str(number))
                continue
            if (directive=='secrule' and len(args) not in (3,4)) or (directive=='secaction' and len(args)!=2):
                raise ValueError('invalid_rule_arguments')
            text = args[3] if len(args)==4 else args[1] if directive=='secaction' else ''
            ids, chain = parser._waf_inventory_actions(text) if text else ([],False)
            actions = waf_actions(text,parser)
            segment = {**location,'variables':args[1] if directive=='secrule' else None,
                       'operator':args[2] if directive=='secrule' else None,'actions':actions}
            if not ids:
                if previous is None or not previous.pop('_chain',False) or previous['source']!=name:
                    raise ValueError('missing_rule_id')
                previous['definition'] += '\n'+line; previous['conditions'].append(segment); previous['_chain']=chain
            else:
                if len(ids)!=1: raise ValueError('multiple_rule_ids')
                if previous and previous.get('_chain'): raise ValueError('unfinished_chain')
                values = lambda key:[a['value'] for a in actions if a['name']==key]
                phase_values = values('phase'); phase = phase_values[-1] if phase_values else '2'
                if phase not in ('1','2','3','4','5'): raise ValueError('unsupported_phase')
                default = defaults.get(phase) if included else None
                declared = [a['name'] for a in actions if a['name'] in disruptive]
                inherited = [a['name'] for a in (default or {}).get('actions',[]) if a['name'] in disruptive]
                # Expose the configured base action, before updates and runtime ctl.
                action = declared[-1] if declared else (inherited[-1] if inherited else 'pass')
                if action=='block': action = inherited[-1] if inherited else 'pass'
                previous = {'id':str(ids[0]),'source':name,'line':number,'origin':origins[name],
                            'configuration':'selected' if included else 'unselected','directive':directive,
                            'definition':line,'_chain':chain,'correlation':False,'conditions':[segment],
                            'description':(values('msg') or [''])[0],
                            'attributes':{'phase':phase,'phase_explicit':bool(phase_values),'severity':values('severity'),
                                          'tags':values('tag'),'revision':values('rev')},
                            'default_actions':default,'declared_disruptive_actions':declared,
                            'configured_base_action':action if included else None,
                            'action_scope':'before_configuration_updates_and_request_time_controls'}
                rows.append(previous)
            if included:
                controls.extend({**location,'rule_id':previous['id'],'control':a['value'],
                                 'scope':'conditional_on_matching_rule_and_chain'} for a in actions if a['name']=='ctl')
        except (ValueError,IndexError):
            warnings.append('unparsed_rule_statement:'+name+':'+str(number))
    if previous and previous.get('_chain'): warnings.append('unfinished_rule_chain:'+previous['source'])
    for row in rows:
        row.pop('_chain',None)
        row['chain_length'] = len(row['conditions'])
        row['runtime_controls'] = [c for c in controls if c['rule_id']==row['id'] and c['source']==row['source']]
        row['configuration_changes_by_id'] = []
        for change in removals:
            if not change['kind'].endswith('byid'): continue
            selectors = change['arguments'] if change['kind']=='secruleremovebyid' else change['arguments'][:1]
            for selector in selectors:
                spans = re.split(r'[,\s]+',selector)
                if not all(re.fullmatch(r'[0-9]+(?:-[0-9]+)?',span) for span in spans): continue
                if any(int(span.split('-')[0]) <= int(row['id']) <= int(span.split('-')[-1]) for span in spans):
                    row['configuration_changes_by_id'].append(change); break
    chosen = [r for r in rows if r['configuration']=='selected']
    info = {'schema_version':1,'scope':'single_fixed_ModSecurity_file_context',
            'engine_mode':{'on':'On','off':'Off','detectiononly':'DetectionOnly'}[modes[-1]['value'].lower()] if modes else 'Off','engine_mode_directives':modes,
            'default_actions_by_phase':defaults,'include_graph':include_edges,'markers':markers,
            'id_definitions':len(chosen),'chain_continuations':sum(len(r['conditions'])-1 for r in chosen),
            'configuration_exceptions':len(removals),'runtime_controls':controls,
            'native_count_formula':'ID definitions + SecMarker declarations * 7 (libmodsecurity 3.0.16 only)',
            'native_expected_objects_3_0_16':len(chosen)+len(markers)*7,
            'per_request_effective_actions_verified':False}
    if metadata is not None: metadata.update(info)
    return rows, sources, warnings, removals


def nginx_security_directives(text):
    """Read nginx -T's actual loaded sources, exposing only ModSecurity flags.

    This does not infer request matching or inherited per-location coverage.
    Unknown inline/remote rule contexts are reported as coverage gaps.
    """
    sections = re.split(r'(?m)^# configuration file ([^\n]+):\n',text)
    result = []; warnings = []
    for i in range(1,len(sections),2):
        source, body = sections[i:i+2]
        # Quoted multiline values are handled by the lexer; comments and quoted
        # strings mentioning modsecurity never become directives.
        tokens=[]; token=''; quote=None; escaped=False; comment=False; line=1; start=1
        for char in body:
            if comment:
                if char=='\n': comment=False
            elif escaped: token+=char; escaped=False
            elif char=='\\': token+=char; escaped=True
            elif quote:
                if char==quote: quote=None
                else: token+=char
            elif char in "\"'": quote=char
            elif char=='#': comment=True
            elif char.isspace() or char in ';{}':
                if token: tokens.append(token);token=''
                if char in ';{}':
                    if char==';' and tokens and tokens[0].startswith('modsecurity'):
                        key=tokens[0];args=tokens[1:]
                        if key=='modsecurity' and len(args)==1 and args[0] in ('on','off'):
                            result.append({'source':source,'line':start,'directive':key,'value':args[0]})
                        elif key=='modsecurity_rules_file' and len(args)==1:
                            result.append({'source':source,'line':start,'directive':key,'value':args[0]})
                        elif key in ('modsecurity_rules','modsecurity_rules_remote'):
                            warnings.append('additional_nginx_rule_context:'+source+':'+str(start))
                            result.append({'source':source,'line':start,'directive':key,'value_sha256':digest(args)})
                        elif key not in ('modsecurity_transaction_id',):
                            warnings.append('unparsed_nginx_modsecurity_directive:'+source+':'+str(start))
                    tokens=[];start=line
            else:
                if not tokens and not token:start=line
                token+=char
            if char=='\n':line+=1
        if quote or escaped or tokens or token: warnings.append('unparsed_nginx_dump:'+source)
    if not result: warnings.append('nginx_modsecurity_directives_missing')
    rule_files=[r['value'] for r in result if r['directive']=='modsecurity_rules_file']
    if rule_files != [WAF_ROOT+'setup.conf']: warnings.append('waf_rule_context_not_fully_covered')
    return result,warnings


def waf_native_result(stdout, stderr, exit_code, metadata):
    """Actual nginx/libmodsecurity parser check; never a running-worker claim."""
    text=stdout.decode('utf-8'); diagnostic=stderr.decode('utf-8','replace')
    directives,warnings=nginx_security_directives(text)
    versions=re.findall(r'libmodsecurity3 version ([0-9.]+)',diagnostic)
    counts=re.findall(r'rules loaded inline/local/remote: ([0-9]+)/([0-9]+)/([0-9]+)',diagnostic)
    success=exit_code==0 and 'syntax is ok' in diagnostic and 'test is successful' in diagnostic
    result={'status':'passed' if success else 'failed','exit_code':exit_code,
            'scope':'new_nginx_configuration_test_not_running_worker_memory',
            'nginx_configuration_sha256':digest(stdout),'diagnostic_sha256':digest(stderr),
            'libmodsecurity_version':versions[-1] if versions else None,
            'explicit_nginx_directives':directives,'connector_object_counts':[
                dict(zip(('inline','local','remote'),map(int,c))) for c in counts],
            'running_worker_rule_state_verified':False,
            'warning_codes':(['ssl_stapling_issuer_missing'] if '"ssl_stapling" ignored, issuer certificate not found' in diagnostic else [])}
    if not success:warnings.append('native_waf_configuration_check_failed')
    if len(counts)!=1:warnings.append('native_waf_count_unavailable_or_multiple_contexts')
    if versions and versions[-1]=='3.0.16' and len(counts)==1:
        expected=metadata['native_expected_objects_3_0_16'];actual=sum(map(int,counts[0]))
        result['object_count_reconciliation']={'matched':actual==expected,'expected':expected,'observed':actual,
            'id_definitions':metadata['id_definitions'],'marker_declarations':len(metadata['markers']),
            'internal_marker_phases':7,'chain_continuations_counted_separately':metadata['chain_continuations']}
        if actual!=expected:warnings.append('native_waf_object_count_mismatch')
    else:result['object_count_reconciliation']={'matched':None,'reason':'unverified_native_version_or_context'}
    return result,warnings


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


def inventory(engine, parser, request, command=bounded_command, api_reader=None, native_check=None):
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
            validate = native_check or (lambda argv: bounded_command(argv, diagnostics=True))
            check_before = validate([parser.DOCKER,'exec',spec['container'],'nginx','-T'])
            roots=[WAF_ROOT+n for n in ('setup.conf','modsecurity.conf','modsecurity-override.conf','owasp-crs/crs-setup.conf',
                                        'owasp-crs/plugins','owasp-crs/rules')]+[WAF_AUDIT]
            raw=command([parser.DOCKER,'exec',spec['container'],'tar','-chf','-',*roots])
            contents=archive_files(raw,roots)
            second=archive_files(command([parser.DOCKER,'exec',spec['container'],'tar','-chf','-',*roots]),roots)
            if contents != second:
                raise ValueError('rules_changed_during_read')
            check_after = validate([parser.DOCKER,'exec',spec['container'],'nginx','-T'])
            if (check_before[0],check_before[2]) != (check_after[0],check_after[2]):
                raise ValueError('nginx_configuration_changed_during_read')
            waf = {}
            rows,files,warnings,exclusions=waf_rules(contents,parser,waf)
            native, gaps = waf_native_result(*check_after,waf)
            first_native, _ = waf_native_result(*check_before,waf)
            if any(native[k]!=first_native[k] for k in ('libmodsecurity_version','connector_object_counts')):
                raise ValueError('nginx_validation_changed_during_read')
            warnings.extend(gaps)
            runtime.update(waf_configuration=waf,native_configuration_validation=native)
            files.append({'path':'nginx:-T:loaded_configuration','sha256':digest(check_after[0]),
                          'origin':'builtin','configuration':'selected'})
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
        if target=='a:waf':
            full=runtime['waf_configuration']
            runtime['waf_configuration']={k:v for k,v in full.items() if k not in ('include_graph','markers','runtime_controls')}
            runtime['waf_configuration'].update(marker_declarations=len(full['markers']),
                runtime_control_count=len(full['runtime_controls']),include_edge_count=len(full['include_graph']),
                detail_collections_scope='omitted_in_summary_available_in_details')
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
