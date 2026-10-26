"""SOC answer grounding shared with Hermes; no tools or incident decisions here.

The installer copies the two canonical Hermes sources verbatim. Development
imports those same sources, rather than maintaining a second rules parser.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
contract_path = HERE / 'chat_contract.py'
if not contract_path.exists():
    contract_path = HERE.parent / 'hermes/chat_contract.py'
contract_spec = importlib.util.spec_from_file_location('_soc_chat_contract', contract_path)
CONTRACT = importlib.util.module_from_spec(contract_spec)
contract_spec.loader.exec_module(CONTRACT)
read_path = HERE / 'read_contract.py'
if not read_path.exists():
    read_path = HERE.parent / 'hermes/read_contract.py'
read_spec = importlib.util.spec_from_file_location('_soc_read_contract', read_path)
READ = importlib.util.module_from_spec(read_spec)
read_spec.loader.exec_module(READ)
path = HERE / 'query_grounding.py'
if not path.exists():
    path = HERE / '__init__.py' if (HERE / '__init__.py').exists() else HERE.parent / 'hermes/query-completion/__init__.py'
spec = importlib.util.spec_from_file_location('_ollama_shared_grounding', path)
SHARED = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = SHARED
spec.loader.exec_module(SHARED)
EVIDENCE = SHARED.EVIDENCE

# One contract shared by both production chat adapters.
SYSTEM_PROMPT = CONTRACT.system_prompt()


def normalized(question):
    # Only classification: original user instructions still go to the model.
    text = re.sub(r'^\[비교시험 Q\d+\]\s*', '', question)
    return READ.without_prohibitions(SHARED._unquoted_text(text))


def read_plan(question):
    text = normalized(question)
    # Recover literal data only, never instructions inside quotations.
    literals = EVIDENCE._AWARE_TIME.findall(question) + re.findall(r'(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])', question)
    for value in literals:
        if value not in text:
            text += '\n' + value
    return READ.plan(text, EVIDENCE._AWARE_TIME)


def read_report(question, calls):
    combined = combined_rule_request(question)
    if combined:
        missing = missing_reads(question, calls)
        inventory_text = SHARED.render_rule_inventory(combined, linked_rows(calls))
        service_text = service_report('IDS 실제 가동 상태 조회', calls)
        return '\n\n'.join(['**전체 요청 범위**\n' + ('규칙 파일과 IDS 구동 근거를 모두 확인했습니다.' if not missing else '일부 요청 항목이 미완료입니다. 전체 확인 완료가 아닙니다.'),
            inventory_text or '규칙 파일 조회 미완료/실패입니다.', service_text or 'IDS 구동 경로 조회 미완료/실패입니다.'] +
            (['미확인 항목: ' + ', '.join(missing)] if missing else []))
    plan = read_plan(question)
    return READ.report(plan, calls, EVIDENCE) if plan else None


def ids_runtime_question(question):
    text = READ.scope_text(normalized(question))
    return bool(re.search(r'IDS|Suricata|수리카타', text, re.I)
        and re.search(r'활성|가동|적재|사용(?:\s*중|하는|하고)|구동|불러오|로드|실행\s*(?:상태|여부|중)', text)
        and not re.search(r'WAF|Wazuh', text, re.I) and not READ.wants_write(text))


def _inventory_question(question):
    text = READ.scope_text(normalized(question))
    if ids_runtime_question(question): return None
    if re.search(r'왜|원인|차이|변경|수정|차단|삭제|추가|적용해|재시작|원문|전문|분석', text):
        return None
    if '비교' in text and not re.search(r'(?:개수|정의\s*수).{0,12}비교|비교.{0,12}(?:개수|정의\s*수)', text): return None
    if not (re.search(r'룰|규칙|rules?', text, re.I) and re.search(r'조회|보여|개수|목록|장비별|몇', text)):
        return None
    devices = [label for pattern, label in [('WAF|ModSecurity', 'WAF'),
               (r'(?<![A-Za-z])IDS(?![A-Za-z])|Suricata', 'Suricata'), ('Wazuh|와주', 'Wazuh')] if re.search(pattern, text, re.I)]
    return '현재 적용된 규칙 목록 보여줘 ' + ' '.join(devices) + (' 장비별로 표로 보여줘' if re.search(r'표|테이블', text) else '')


def combined_rule_request(question):
    text = READ.scope_text(normalized(question))
    if READ.wants_write(text): return None
    runtime = re.search(r'(?:IDS|Suricata|수리카타)(?:가|는|의)?[^.!?。]{0,90}(?:local\.rules|all\.rules|구동\s*경로|실행\s*경로|룰\s*경로|실제\s*사용|사용하는지|가동\s*상태)', text, re.I)
    if runtime and re.search(r'(?:규칙|룰|파일\s*정의).{0,35}(?:개수|목록|정의\s*수)|(?:개수|목록|정의\s*수).{0,20}(?:규칙|룰|파일\s*정의)', text):
        labels = [label for pattern, label in [('WAF|ModSecurity', 'WAF'), ('IDS|Suricata|수리카타', 'Suricata'), ('Wazuh|와주', 'Wazuh')] if re.search(pattern, text, re.I)]
        return '현재 규칙 목록 보여줘 ' + ' '.join(labels) + (' 장비별로 표로 보여줘' if re.search(r'표|테이블', text) else '')
    return None


def inventory_question(question):
    return None if combined_rule_request(question) else _inventory_question(question)


def structured_read(question):
    return bool(read_plan(question) or combined_rule_request(question) or inventory_question(question) or
                tool_scope(question) in ({'mcp__rule_a__get_service_action_target'}, {'mcp__system_diagnostics__get_system_diagnostics'}))


def linked_rows(calls):
    rows = []
    for index, call in enumerate(calls):
        name = 'mcp__' + call['server'].replace('-', '_') + '__' + call['name']
        cid = 'observed-' + str(index)
        raw = call.get('result', '')
        if (call.get('is_error') or not isinstance(raw, str) or
                hashlib.sha256(raw.encode()).hexdigest() != call.get('result_sha256')):
            raw = json.dumps({'error': 'MCP result unavailable or failed'})
        rows.extend([{'role': 'assistant', 'tool_calls': [{'id': cid,
            'function': {'name': name, 'arguments': call['arguments']}}]},
            {'role': 'tool', 'tool_call_id': cid, 'content': raw}])
    return rows


def inventory(question, calls, **kwargs):
    request = inventory_question(question)
    return SHARED.render_rule_inventory(request, linked_rows(calls), **kwargs) if request else None


def facts_for(calls):
    facts = []
    for call in calls:
        if call.get('is_error') or not call.get('result'):
            continue
        name = 'mcp__' + call['server'].replace('-', '_') + '__' + call['name']
        if EVIDENCE.allowed(name, 'verify'):
            try:
                facts.extend(EVIDENCE.observation_facts(call['name'], SimpleNamespace(isError=False,
                    content=[SimpleNamespace(text=call['result'])])))
                if call['server'] == 'wazuh-ro':
                    # Wazuh MCP returns human-readable text inside {result: ...},
                    # rather than the structured sensor schema used by Hermes.
                    raw = wazuh_text(call['result'])
                    if isinstance(raw, str):
                        instants = [v for v in EVIDENCE._AWARE_TIME.findall(raw) if EVIDENCE.parse_instant(v)]
                        if instants:
                            facts.append({'kind': 'times', 'instants': list(dict.fromkeys(instants))})
            except (ValueError, TypeError, KeyError):
                continue
    return facts


def model_view(server, name, raw):
    # Normalize only the legacy read-only Wazuh presentation. Keep the original
    # result/hash in the audit record; never rewrite hashed rules or write data.
    if server != 'wazuh-ro':
        return raw
    text = wazuh_text(raw)
    if name == 'get_wazuh_log_collector_stats' and isinstance(text, str):
        text = re.sub(r'(?m)^(\s*(?:Start|End): ).*$', r'\1원본 시간대 검증 필요; 절대시각 미확인', text)
    if name == 'get_wazuh_vulnerability_summary' and isinstance(text, str) and 'CVE:' in text:
        return json.dumps(READ.vulnerability_view(text), ensure_ascii=False)
    return json.dumps({'result': EVIDENCE.kst_display(text), 'display_timezone': 'Asia/Seoul',
        'time_scope': '반환 표본만 표시합니다. 지정 절대 구간 전체 건수는 미확인입니다.'}, ensure_ascii=False) if text is not None else raw


def wazuh_text(raw):
    try:
        value = json.loads(raw)
        if isinstance(value, dict) and isinstance(value.get('result'), str):
            return value['result']
        return None
    except (ValueError, TypeError):
        return raw if isinstance(raw, str) else None


def violations(question, answer, calls):
    facts = facts_for(calls)
    issues = EVIDENCE.evidence_claim_violations(answer, facts) + EVIDENCE.calculated_json_violations(answer, facts)
    text = normalized(question)
    if (not calls and not READ.wants_write(text)
            and (tool_scope(question) or re.search(r'현재|실제.{0,12}(?:조회|확인)|조회해|확인해|보여줘', text))):
        issues.append('current_state_requires_actual_read')
    return sorted(set(issues))


def footer_free(text):
    return re.sub(r'\n*(?:---\s*\n)?(?:읽기 전용 시험|SOC 비교 시험)\s*·[^\n]*', '', text).strip()


def reuse_only(question):
    text = SHARED._unquoted_text(question)
    return bool(re.search(r'표|테이블|정리', text) and re.search(r'(?:추가|새로|다시)?\s*조회(?:는|를|도)?\s*하지\s*말', text))


def prior_inventory(question, evidence):
    # Pure reformat only. Fresh roots never receive evidence from the gateway.
    if (not isinstance(evidence, dict) or not re.search(r'표|테이블|정리', question)
            or re.search(r'현재|지금|다시\s*조회|최신|갱신|변경|수정|삭제|추가', normalized(question))):
        return None
    previous = evidence.get('question', '')
    if not inventory_question(previous):
        return None
    combined = previous + '\n' + question
    calls = evidence.get('calls', [])
    if inventory(combined, calls, missing_targets=True):
        return None
    verified = inventory(combined, calls, verified_targets=True)
    if not verified:
        return None
    rendered = inventory(combined, calls)
    if rendered:
        stamps = []
        for call in calls:
            if call.get('name') == 'get_rule_change_target' and READ.successful(call):
                data = READ.unpack(call['result'])
                stamp = data.get('time_display', {}).get('rendered_at_kst') if isinstance(data, dict) else None
                if EVIDENCE.parse_instant(stamp): stamps.append(EVIDENCE.kst_time(stamp))
        when = ' / '.join(dict.fromkeys(stamps)) if stamps else str(evidence.get('at_kst', '미확인'))
        return '이전 실제 조회 시각: ' + when + '\n새 조회 없이 검증된 동일 스레드 결과를 재구성했습니다.\n\n' + rendered.replace('현재 조회 결과', '이전 조회 결과')
    return None


def guidance(question):
    text = normalized(question)
    result = SHARED.status_lookup_guidance(text)
    plan = read_plan(question)
    if plan:
        result += '\n' + READ.guidance(plan)
    if combined_rule_request(question):
        result += '\n이 요청에는 규칙 파일 목록과 IDS 구동 경로라는 두 조회가 있습니다. get_rule_change_target의 모든 요청 파일과 rule-a.get_service_action_target(a:suricata)를 각각 선택하세요. 한쪽만 완료한 것을 전체 완료로 보고하지 마세요.'
    if inventory_question(question):
        result += '\n이번 규칙 목록은 요청한 장비의 파일을 빠짐없이 조회하세요. 장비 미지정이면 WAF/IDS/Wazuh 세 파일 모두입니다.'
    if tool_scope(question):
        result += '\n현재 상태를 답할 근거가 아직 없습니다. 첫 응답에서 제공된 읽기 도구를 실제로 호출하세요. 도구 설명이나 예시 숫자를 조회 결과로 제시하지 마세요.'
    return result


def diagnostic_request(question):
    text = READ.scope_text(normalized(question))
    if READ.wants_write(text): return None
    health = re.search(r'진단|관제.*(?:공백|상태|건강)|상태.*(?:점검|확인)|연결.*(?:점검|진단)|수집.*(?:점검|진단)', text)
    if not re.search(r'진단|관제|Hermes|헤르메스|Ollama|올라마|Wazuh\s*(?:manager|매니저)|Indexer|인덱서|Mattermost|매터모스트|LLM|모델|파이프라인|[abc]:|A\s*/\s*B\s*/\s*C', text, re.I): return None
    if not health and not (re.search(r'A\s*/\s*B\s*/\s*C',text,re.I) and re.search(r'실패|오류',text)): return None
    if re.search(r'(?:전체|모든).*관제|관제.*(?:전체|공백)|A\s*/\s*B\s*/\s*C|soc:coverage',text,re.I):
        return {'all':True,'requested':[]}
    host_matches=list(re.finditer(r'(?<![A-Za-z0-9])([ABC])\s*서버',text,re.I))
    hosts=[m[1].lower() for m in host_matches]
    host=hosts[0] if len(hosts)==1 else None
    wanted=re.findall(r'(?<![A-Za-z0-9_])[abc]:[a-z][a-z0-9-]*(?![A-Za-z0-9_-])',text)
    for pattern,name,default in [
        (r'(?<![A-Za-z])Hermes(?![A-Za-z])|헤르메스','hermes','b'),
        (r'Suricata|IDS|수리카타','suricata','a'),(r'WAF|ModSecurity','waf','a'),
        (r'에이전트|수집기|\bcollection\b','collection',None),
        (r'Ollama|올라마','ollama','b'),(r'Wazuh\s*(?:manager|매니저)','wazuh-manager','b'),
        (r'Indexer|인덱서','wazuh-indexer','b'),(r'Mattermost|매터모스트','mattermost','b'),
        (r'LLM|모델','llm','b'),(r'사건.*(?:처리|전달)|관리.*파이프라인','management-pipeline','b'),
        (r'수집.*(?:경로|전달|파이프라인)|ingestion','ingestion','b'),
        (r'\bsoc-bot\b','soc-bot',None),(r'\bDocker\b|도커','docker',None),
        (r'\bVector\b|벡터','vector',None)]:
        for match in re.finditer(pattern,text,re.I):
            if re.search(r'[abc]:$',text[max(0,match.start()-2):match.start()]): continue
            preceding=[m[1].lower() for m in host_matches if m.end()<=match.start()]
            selected=(preceding[-1] if preceding else host) or default
            if selected: wanted.append(selected+':'+name)
    return {'all':False,'requested':list(dict.fromkeys(wanted)),'unresolved':not wanted}


def diagnostic_scope(question, targets):
    request=diagnostic_request(question)
    if not request: return [],[]
    if request['all']: return (['soc:coverage'] if 'soc:coverage' in targets else list(targets)),[]
    return ([t for t in request['requested'] if t in targets],
            [t for t in request['requested'] if t not in targets]+(['요청 서비스 이름/범위 해석 미확인'] if request.get('unresolved') else []))


def tool_scope(question, calls=None):
    """Same kind of read-turn narrowing as Hermes; does not invoke any tool."""
    if diagnostic_request(question):
        return {'mcp__system_diagnostics__get_system_diagnostics'}
    combined = combined_rule_request(question)
    if combined:
        scope = {'mcp__rule_a__get_rule_change_target', 'mcp__rule_b__get_rule_change_target', 'mcp__rule_a__get_service_action_target'}
        return scope
    plan = read_plan(question)
    if plan:
        scope = READ.scope(plan, calls)
        if calls is not None and plan['kind'] == 'wazuh' and (not plan['needs_agent'] or READ.target_id(plan, calls)):
            missing = READ.missing(plan, calls, EVIDENCE)
            scope = {n for n in scope if any(m.startswith(n.split('__')[-1] + ':') or m == n.split('__')[-1] for m in missing)}
        return scope
    if ids_runtime_question(question):
        return {'mcp__rule_a__get_service_action_target'}
    if inventory_question(question):
        return {'mcp__rule_a__get_rule_change_target', 'mcp__rule_b__get_rule_change_target'}
    text = normalized(question)
    if re.search(r'변경|수정|차단해|재시작|추가해|삭제|적용해|설치|배포', text):
        return None
    if (re.search(r'IDS|Suricata|수리카타', text, re.I) and re.search(r'활성|가동|적재', text)
            and not re.search(r'WAF|Wazuh|변경|수정|차단|재시작|추가|삭제|적용해', text, re.I)):
        return {'mcp__rule_a__get_service_action_target'}
    if re.search(r'로그|경보|이벤트', text) and re.search(r'WAF|IDS|Wazuh', text, re.I):
        scope = set()
        if re.search(r'WAF|ModSecurity', text, re.I):
            scope.add('mcp__security_events__search_modsecurity_alerts')
        if re.search(r'IDS|Suricata', text, re.I):
            scope.add('mcp__security_events__search_suricata_alerts')
        if re.search(r'Wazuh|와주', text, re.I):
            scope.add('mcp__wazuh_ro__get_wazuh_alert_summary')
        return scope
    if re.search(r'A\s*/\s*B\s*/\s*C', text, re.I) and re.search(r'서비스|서버', text) and re.search(r'실패|오류|진단', text):
        return {'mcp__system_diagnostics__get_system_diagnostics'}
    return None


def missing_reads(question, calls, diagnostic_targets=()):
    combined = combined_rule_request(question)
    if combined:
        return missing_reads(combined, calls, diagnostic_targets) + missing_reads('IDS 실제 가동 상태 조회', calls, diagnostic_targets)
    plan = read_plan(question)
    if plan:
        return READ.missing(plan, calls, EVIDENCE)
    scope = tool_scope(question)
    inventory_request = inventory_question(question)
    if inventory_request:
        patterns = [('WAF|ModSecurity', 'a:modsecurity-custom'),
                    ('IDS|Suricata', 'a:suricata-local'), ('Wazuh|와주', 'b:wazuh-local-rules')]
        expected = [target for pattern, target in patterns if re.search(pattern, inventory_request, re.I)]
        if not expected:
            expected = [target for _, target in patterns]
        verified = inventory(question, calls, verified_targets=True) or []
        return [target for target in expected if target not in verified]
    successful = [c for c in calls if not c.get('is_error') and c.get('result')]
    names = {'mcp__' + c['server'].replace('-', '_') + '__' + c['name'] for c in successful}
    if scope == {'mcp__rule_a__get_service_action_target'}:
        return [] if any(c.get('server') == 'rule-a' and c.get('name') == 'get_service_action_target'
                         and c.get('arguments', {}).get('target') == 'a:suricata'
                         and payload(c) for c in successful) else ['a:suricata']
    if scope == {'mcp__system_diagnostics__get_system_diagnostics'}:
        done = {c['arguments'].get('target') for c in successful if c['name'] == 'get_system_diagnostics'
                and payload(c) and payload(c).get('schema') == 1 and payload(c).get('target') == c['arguments'].get('target')}
        selected, unsupported = diagnostic_scope(question, diagnostic_targets)
        return [t for t in selected if t not in done] + ['진단 대상 미지원/미확인: ' + t for t in unsupported]
    if scope and any('search_' in n or 'alert_summary' in n for n in scope):
        return sorted(scope - names)
    return []


def refine_read_schemas(question, schemas, calls, diagnostic_targets=()):
    """Narrow actual read schemas to unmet requirements; never dispatch calls."""
    result = json.loads(json.dumps(schemas))
    p = read_plan(question)
    if p and p['kind'] == 'time' and READ.TIME in result:
        schema = result[READ.TIME]
        props = schema.get('properties', {})
        values = props.get('timestamps', {}).get('items', {}).get('properties', {}).get('value')
        if isinstance(values, dict):
            values['enum'] = list(dict.fromkeys(p['stamps']))
        reference = READ.explicit_reference(p)
        if 'reference' in props:
            props['reference'] = {**props['reference'], 'enum': [reference] if reference else list(dict.fromkeys(p['stamps'])) + ['now']}
            if reference:
                schema['required'] = list(dict.fromkeys(schema.get('required', []) + ['reference']))
    if p and p['kind'] in ('wazuh', 'multi'):
        plans = READ.parts(p)
        for alias in list(result):
            name = alias.split('__')[-1]
            props = result[alias].get('properties', {})
            if name == 'get_wazuh_agents':
                states = {state for part in plans for state in part['states'] if not READ.valid_wazuh(READ.state_call(part, calls, state), name)}
                if any(part['needs_agent'] and not READ.target_id(part, calls) and not READ.valid_wazuh(READ.state_call(part, calls, 'active'), 'get_wazuh_agents') for part in plans): states.add('active')
                if not states:
                    result.pop(alias); continue
                if 'status' in props: props['status'] = {**props['status'], 'enum': sorted(states)}
                # Full status lists resolve physical names and cannot silently
                # satisfy a request for all agents with a guessed name filter.
                for key in list(props):
                    if key != 'status' and key not in result[alias].get('required', []): props.pop(key)
                result[alias]['additionalProperties'] = False
            elif name.startswith('get_wazuh_'):
                relevant = [part for part in plans if name in part['features']]
                needed = []
                for part in relevant:
                    agent = READ.target_id(part, calls)
                    args = READ.feature_args(part, name, agent)
                    if args and not agent: continue
                    c = READ.matching(part, calls, name, **args)
                    if READ.valid_wazuh(c, name) or READ.failed_attempt(part, calls, name, args): continue
                    needed.append(part)
                if not needed:
                    result.pop(alias); continue
                if 'agent_id' in props:
                    props['agent_id'] = {**props['agent_id'], 'enum': sorted({READ.target_id(part, calls) for part in needed})}
                if name == 'get_wazuh_vulnerability_summary':
                    # The maximum for displayed Critical examples must never
                    # truncate the separate severity-distribution source.
                    for key in list(props):
                        if key != 'agent_id' and key not in result[alias].get('required', []):
                            props.pop(key)
                    result[alias]['additionalProperties'] = False
                if 'limit' in props and name in ('get_wazuh_agent_processes', 'get_wazuh_agent_ports', 'get_wazuh_critical_vulnerabilities'):
                    props['limit'] = {**props['limit'], 'minimum': 1, 'maximum': max(part.get('limit', 5) for part in needed)}
                    result[alias]['required'] = list(dict.fromkeys(result[alias].get('required', []) + ['limit']))
                if name == 'get_wazuh_agent_processes' and 'search' not in result[alias].get('required', []):
                    # This bounded plan requests an inventory, not an inferred
                    # process-name filter. Even search="" is rejected upstream.
                    searches = {part.get('search') for part in needed}
                    if searches == {None}: props.pop('search', None)
                    else:
                        props['search'] = {**props.get('search', {'type':'string'}), 'enum': sorted(s for s in searches if s)}
                        if None not in searches: result[alias]['required'] = list(dict.fromkeys(result[alias].get('required', []) + ['search']))
                    result[alias]['additionalProperties'] = False
                if name == 'get_wazuh_agent_ports':
                    filters = [{'protocol': '', 'state': '', **READ.port_filters(part)} for part in needed]
                    for key in ('protocol', 'state'):
                        if key in props: props[key] = {**props[key], 'enum': sorted({f[key] for f in filters})}
                # Bind each device to its own predicate, filter and count.
                # Independent enums would allow another cross-product error.
                variants = []
                for part in needed:
                    exact = READ.feature_args(part, name, READ.target_id(part, calls))
                    if name == 'get_wazuh_agent_ports': exact = {'protocol':'', 'state':'', **exact}
                    if 'limit' in props and name in ('get_wazuh_agent_processes', 'get_wazuh_agent_ports', 'get_wazuh_critical_vulnerabilities'):
                        exact['limit'] = part.get('limit', 5)
                    variant = {'properties': {k: {'enum':[v]} for k,v in exact.items() if k in props}, 'required':[k for k in exact if k in props]}
                    if name == 'get_wazuh_agent_processes' and not part.get('search') and 'search' in props:
                        variant['not'] = {'required':['search']}
                    if variant not in variants: variants.append(variant)
                if variants: result[alias]['anyOf'] = variants
    pending = missing_reads(question, calls, diagnostic_targets)
    for alias in list(result):
        name = alias.split('__')[-1];props = result[alias].get('properties', {})
        if 'target' not in props or name not in ('get_rule_change_target', 'get_service_action_target', 'get_system_diagnostics'): continue
        targets = [x for x in pending if x.startswith(('a:', 'b:', 'c:')) or
                   (name == 'get_system_diagnostics' and x == 'soc:coverage')]
        if name == 'get_rule_change_target': targets = [x for x in targets if x in ('a:modsecurity-custom', 'a:suricata-local', 'b:wazuh-local-rules')]
        if name == 'get_service_action_target': targets = [x for x in targets if x == 'a:suricata']
        actual = props['target'].get('enum')
        if actual: targets = [x for x in targets if x in actual]
        if name != 'get_system_diagnostics':
            host = 'a:' if '__rule_a__' in alias else 'b:'
            targets = [x for x in targets if x.startswith(host)]
        if not targets: result.pop(alias); continue
        props['target'] = {**props['target'], 'enum': targets}
    return result


def policy_explanation(question, tools):
    """Quote verified tool-policy facts for a narrow explanation-only request.

    This is policy documentation, not an incident decision or a tool action.
    Unknown descriptions and mixed investigative/action requests decline it.
    """
    text = normalized(question)
    if (READ.wants_write(text) or not re.search(r'DGX', text, re.I) or not re.search(r'보호', text)
            or not re.search(r'차단', text) or not re.search(r'거절|거부|불가', text)
            or not re.search(r'정책.{0,15}(?:만|설명)|설명만', text)
            or re.search(r'조회해|확인해|최근|경보|로그.{0,12}(?:분석|확인)|사건.{0,12}(?:분석|판단)', text)):
        return None
    descriptions = {t.get('function', {}).get('name'): t.get('function', {}).get('description', '') for t in tools}
    regular = descriptions.get('mcp__resp__block_ip', '')
    temporary = descriptions.get('mcp__rule_write_a__temporarily_contain_ip', '')
    if ('refuses protected/management addresses' not in regular or
            'Protected/private/management/DGX and active SSH addresses are refused' not in temporary):
        return None
    return ('**요약**\n보호된 DGX 주소는 일반 차단과 긴급 임시 차단 모두의 거절 대상입니다.\n\n'
            '**확인 내역**\n'
            '| 도구 정의 | 확인한 보호 경계 |\n| --- | --- |\n'
            '| block_ip | protected/management 주소와 활성 SSH 주소를 거절 |\n'
            '| temporarily_contain_ip | protected/private/management/DGX 및 활성 SSH 주소를 거절 |\n\n'
            '운영자 승인은 보호 주소 거절을 우회하는 허가가 아닙니다. 일반 block_ip나 다른 차단 경로로 우회하라고 안내하지 않습니다. '
            '이 정책 정의는 실제 공격·장애 발생 여부나 DGX의 다른 역할에 대한 근거가 아닙니다.\n\n'
            '**조치 및 다음 단계**\n도구 정의에 근거한 정책 설명입니다. 실제 조회·차단 도구 호출은 수행하지 않았습니다. '
            '실제 사건은 증거 조사와 기존 승인·보호 절차에 따라 별도로 판단해야 합니다.')


def validated_selection(value, schema):
    """Validate every model-selected read; collapse only exact duplicates."""
    from jsonschema import Draft202012Validator
    strict = json.loads(json.dumps(schema))
    strict['properties']['calls'].pop('uniqueItems', None)
    Draft202012Validator(strict).validate(value)
    result = json.loads(json.dumps(value));seen = set();calls = []
    for item in result['calls']:
        identity=item
        if item['tool']=='mcp__system_diagnostics__get_system_diagnostics' and item['arguments'].get('target')=='soc:coverage':
            # This endpoint always returns the same latest full snapshot;
            # history/row-limit arguments do not change aggregate scope.
            identity={'tool':item['tool'],'arguments':{'target':'soc:coverage'}}
        key = json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
        if key not in seen: calls.append(item);seen.add(key)
    removed = len(result['calls']) - len(calls);result['calls'] = calls
    Draft202012Validator(schema).validate(result)
    return result, removed


def selection_schema(schemas, limit):
    if not schemas or not 1 <= limit <= 40 or any(not EVIDENCE.allowed(n, 'verify') for n in schemas):
        raise ValueError('read_selection_scope')
    return {'title': 'ReadToolSelection', 'type': 'object', 'additionalProperties': False,
        'properties': {'calls': {'type': 'array', 'minItems': 1, 'maxItems': limit, 'uniqueItems': True, 'items': {'anyOf': [
            {'type': 'object', 'additionalProperties': False, 'required': ['tool', 'arguments'],
             'properties': {'tool': {'type': 'string', 'const': name}, 'arguments': schema}}
            for name, schema in schemas.items()]}}}, 'required': ['calls']}


def payload(call):
    raw = call.get('result', '')
    if call.get('is_error') or hashlib.sha256(raw.encode()).hexdigest() != call.get('result_sha256'):
        return None
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) and not data.get('error') else None
    except (ValueError, TypeError):
        # Native MCP returns text directly; Hermes adds a JSON result envelope.
        return {'result': raw} if call.get('server') == 'wazuh-ro' else None


def service_report(question, calls):
    if tool_scope(question) != {'mcp__rule_a__get_service_action_target'}:
        return None
    relevant = [c for c in calls if c['server'] == 'rule-a' and c['name'] == 'get_service_action_target'
                and c['arguments'].get('target') == 'a:suricata']
    if not relevant:
        return None
    data = payload(relevant[-1])
    if not data or data.get('target') != 'a:suricata' or not isinstance(data.get('observation'), dict):
        return 'IDS 상태 조회에 실패하여 현재 가동 여부를 확인하지 못했습니다. 비활성이나 정상으로 판단하지 않습니다.'
    observation = data['observation']
    running = observation.get('running')
    status = '실행 중' if running is True else '실행 중이 아님' if running is False else '실행 여부 미확인'
    rows = ['**요약**', 'A의 Suricata 컨테이너는 이번 조회에서 **' + status + '**입니다. 개별 SID 엔진 적재는 미확인입니다.',
            '', '**확인 내역**', '- 실제 조회 대상: `a:suricata`',
            '- running: `' + cell(running) + '`; health: `' + cell(observation.get('health')) + '` (미보고는 healthy를 뜻하지 않음)']
    if EVIDENCE.parse_instant(observation.get('started_at')):
        rows.append('- 시작 시각: ' + EVIDENCE.kst_time(observation['started_at']))
    runtime = data.get('rule_source_evidence')
    if isinstance(runtime, dict):
        rows.append('- 실행 룰 지정: `' + cell(runtime.get('rule_source_option')) + ' ' + cell(runtime.get('rule_source_path')) + '`')
        rows.append('- ET+local 파일 바이트의 정확한 결합: `' + cell(runtime.get('combined_is_exact_et_plus_local')) + '`')
        observed = runtime.get('observed_at')
        if type(observed) in (int, float):
            from datetime import datetime
            rows.append('- 근거 관측 시각: ' + datetime.fromtimestamp(observed, EVIDENCE.KST).isoformat())
    rows.extend(['', '**조치 및 다음 단계**', '- 위 근거는 컨테이너 가동과 현재 지정 파일에 관한 것입니다. -S 옵션 자체로 비활성을 뜻하지 않습니다.',
                 '- 전체 엔진 활성 규칙 수·SID별 실제 적재·탐지 성공은 확인하지 않았습니다. 변경/재시작은 수행하지 않았습니다.'])
    return '\n'.join(rows)


def cell(value):
    text = str(value if value is not None else '미확인').replace('|', '\\|').replace('\n', ' ')
    return text if len(text) <= 240 else text[:237] + '…'


def diagnostic_report(question, calls, targets):
    if tool_scope(question) != {'mcp__system_diagnostics__get_system_diagnostics'}:
        return None
    selected, unsupported = diagnostic_scope(question, targets)
    catalog = list(targets)
    targets = selected
    latest = {}
    for call in calls:
        if call['name'] == 'get_system_diagnostics':
            target = call['arguments'].get('target')
            data = payload(call)
            latest[target] = data if data and data.get('target') == target and data.get('schema') == 1 else None
    if not latest and not unsupported:
        return None
    if any(v and v.get('kind') in ('runtime','coverage') for v in latest.values()):
        return runtime_diagnostic_report(targets, latest, unsupported)
    verified = [t for t in targets if latest.get(t)]
    rows = ['**요약**', f'전체 대상 {len(targets)}개 / 유효 조회 {len(verified)}개 / 미확인 {len(targets)-len(verified)}개. 미확인 목록: ' + (', '.join(t for t in targets if t not in verified) or '없음') + '\n고정 진단 대상별 수집 스냅샷입니다. 원인과 전체 오류 발생 여부는 이 표본만으로 확정하지 않습니다.',
            '', '**확인 내역**', '', '| 대상 | Type | ActiveState / SubState | Result | 오류 반환 표본 | 수집 시각 KST |',
            '| --- | --- | --- | --- | --- | --- |']
    if unsupported:
        rows[1] = ('요청 범위 중 등록 진단 대상 ' + str(len(selected)) + '개 / 실제 유효 조회 ' + str(len(verified)) + '개 / 미지원·대상 미확인 ' + str(len(unsupported)) + '개입니다. 서비스 상태를 확인했다는 뜻이 아닙니다.\n'
                   '현재 연결된 MCP의 실제 도구 스키마에서 요청 대상에 해당하는 등록 이름을 확인하지 못했습니다. 다른 서비스로 대신 조회하지 않았습니다.\n'
                   '미지원·미확인: ' + ', '.join(unsupported) + '\n등록된 진단 대상: ' + ', '.join(catalog))
        if not selected:
            return '\n'.join(['**요약**', rows[1], '', '**확인 내역**', '',
                *READ.table(['요청 대상', '진단 지원', '실제 서비스 상태'], [(t, '등록 대상 미지원/미확인', '조회 미실행·미확인') for t in unsupported]),
                '', '**조치 및 다음 단계**', '도구 목록의 지원 범위만 확인했습니다. 서비스 상태·로그 조회는 수행하지 않았고 정상·장애·오류 0건으로 판정하지 않았습니다.'])
        rows += ['| ' + ' | '.join(cell(v) for v in (t,'등록 대상 미지원','조회 미실행','미확인','미확인','미확인')) + ' |' for t in unsupported]
    windows, errors = [], []
    for target in targets:
        data = latest.get(target)
        if not data:
            rows.append(f'| {cell(target)} | 미확인 | 조회 미완료/실패 | 미확인 | 미확인(0건 아님) | 미확인 |')
            continue
        props = data.get('properties', {})
        rows.append('| ' + ' | '.join(cell(v) for v in (target, props.get('Type'),
            str(props.get('ActiveState')) + ' / ' + str(props.get('SubState')), props.get('Result'),
            data.get('returned_error_count'), data.get('observed_at_kst'))) + ' |')
        windows.append(f"- `{target}`: {cell(data.get('requested_since_kst'))} ~ {cell(data.get('requested_until_kst'))}")
        for error in data.get('recent_errors', [])[:5]:
            errors.append('- `' + target + '`: ' + cell(json.dumps(error, ensure_ascii=False)))
    rows.extend(['', '요청 구간(KST, 대상별 조회 시각이 다름):', *windows, '',
        '반환 오류 표본(최대10건):', *(errors[:10] or ['- 반환된 오류 표본이 없습니다. 구간 전체 오류가 없다는 뜻은 아닙니다.']),
        '', '**조치 및 다음 단계**',
        '- inactive/dead인 oneshot과 failed를 구분해야 합니다. 위 표의 상태값을 임의로 정상/장애로 바꾸지 않았습니다.',
        '- 약60초 주기 수집 자료이며 실시간 journal 전체 조회가 아닙니다. 현재 장애 원인·미수집 구간은 미확인입니다.'])
    return '\n'.join(rows)


def runtime_diagnostic_report(targets, latest, unsupported):
    records={}
    for t in targets:
        data=latest.get(t)
        if data and data.get('kind')=='coverage': records.update(data.get('targets',{}))
        else: records[t]=data or {'status':'unavailable','codes':['조회 미완료']}
    counts={k:sum(r.get('status')==k for r in records.values()) for k in ('ok','degraded','unavailable','not_installed')}
    rows=['**요약**',f"진단 대상 {len(records)}개: 점검 통과 {counts['ok']}, 이상 징후 {counts['degraded']}, 미확인 {counts['unavailable']}, 미설치 {counts['not_installed']}. 전체 공격 탐지·대응 성공을 뜻하지 않습니다.",'','**확인 내역**','',
          '| 대상 | 판정 | 근거 | 수집 시각 KST |','| --- | --- | --- | --- |']
    labels={'ok':'점검 통과','degraded':'이상 징후','unavailable':'미확인','not_installed':'미설치'}
    details=[]
    for target,data in records.items():
        p=data.get('properties',{});codes=data.get('codes',[])
        evidence=(', '.join(codes) if codes else (' / '.join(str(p.get(k,'미확인')) for k in ('Type','ActiveState','SubState','Result')) if p else '고정 점검 항목 통과'))
        rows.append('| '+' | '.join(cell(v) for v in (target,labels.get(data.get('status'),'미확인'),evidence,data.get('observed_at_kst')))+' |')
        if len(records)<=4 and data.get('metrics'):
            details += ['', '**'+cell(target)+' 근거 수치**'] + ['- `'+cell(k)+'`: '+cell(__import__('datetime').datetime.fromtimestamp(v,EVIDENCE.KST).isoformat() if k.endswith('_at') and type(v) in (int,float) else v) for k,v in data['metrics'].items()]
    rows += details
    if 'inspection_limit_reached' in records.get('a:suricata',{}).get('codes',[]):
        rows += ['', 'IDS 검사 깊이/재조립 한도 수치는 엔진 시작 이후 누적입니다. 커널 드롭과 다른 항목이며 현재 공격 발생을 뜻하지 않습니다.']
    if 'case_review_required' in records.get('b:management-pipeline',{}).get('codes',[]):
        rows += ['', '관리 파이프라인에 needs_review/outcome_unknown 사건이 남아 있습니다. 조회 성공과 사건 처리 완료는 다르며 임의 종결하지 않았습니다.']
    if unsupported: rows += ['','미지원·미확인 요청: '+', '.join(unsupported)]
    rows += ['','**조치 및 다음 단계**',
        '- 약60초 주기 자료입니다. 모델·수집 경로 합성 점검은 별도 주기이며, 미확인은 정상이나 0건이 아닙니다.',
        '- 미설치는 역할별 기대 구성을 확인해야 합니다. 표본 오류·누적 드롭은 현재 장애 원인으로 단정하지 않습니다.',
        '- B/Mattermost 장애는 A에 보존하고 복구 후 알립니다. 장애 중 외부 즉시 알림 경로는 없습니다.',
        '- 실제 공격·탐지·LLM 판단·승인·대응의 전체 E2E 성공 여부는 별도 검증 대상입니다.']
    return '\n'.join(rows)


def event_report(question, calls):
    scope = tool_scope(question)
    if not scope or not any('search_' in name or 'alert_summary' in name for name in scope):
        return None
    latest = {}
    for call in calls:
        name = 'mcp__' + call['server'].replace('-', '_') + '__' + call['name']
        if name in scope:
            latest[name] = payload(call)
    if not latest:
        return None
    rows = ['**요약**', '이 도구들은 고정 절대 시작/종료 구간을 지원하지 않습니다. 아래 실제 조회 범위의 반환 표본을 표시하며 요청한 고정 구간 전체 건수는 미확인입니다.', '', '**확인 내역**']
    labels = {'mcp__security_events__search_modsecurity_alerts': 'WAF',
              'mcp__security_events__search_suricata_alerts': 'IDS',
              'mcp__wazuh_ro__get_wazuh_alert_summary': 'Wazuh'}
    for name in sorted(scope):
        data = latest.get(name)
        rows.extend(['', '**' + labels[name] + '**'])
        if not data:
            rows.append('- 조회 미완료/실패: 0건으로 판단하지 않습니다.'); continue
        if name.endswith('get_wazuh_alert_summary'):
            raw = data.get('result')
            if not isinstance(raw, str):
                rows.append('- 반환 형식 미확인.'); continue
            records = re.findall(r'(?m)^Alert ID: [^\n]+\n(?:(?!Alert ID:)[\s\S])*?(?=^Alert ID:|\Z)', raw)
            stamps = [v for v in re.findall(r'(?m)^Time: ([^\n]+)', raw) if EVIDENCE.parse_instant(v)]
            if not records or len(stamps) != len(records):
                rows.append('- 원본 표본 형식을 집계하지 못했습니다. 0건이라는 뜻은 아닙니다.'); continue
            ordered = sorted(stamps, key=EVIDENCE.parse_instant)
            rows.append(f'- 최신 반환 표본 {len(records)}건; 실제 표본 시각 {EVIDENCE.kst_time(ordered[0])} ~ {EVIDENCE.kst_time(ordered[-1])}. 절대 구간/전체 건수 조회 아님.')
            for record in records[:5]:
                rows.append('- ' + cell(EVIDENCE.kst_display(record.strip())))
        else:
            if data.get('source') not in ('suricata', 'modsecurity') or not isinstance(data.get('alerts'), list):
                rows.append('- 반환 형식 미확인.'); continue
            rows.append(f"- 실제 요청 구간 {cell(data.get('requested_since_kst'))} ~ {cell(data.get('requested_until_kst'))}; 반환 표본 {cell(data.get('returned_count'))}건. 구간 전체 건수 미확인.")
            for alert in data['alerts'][:5]:
                if data['source'] == 'suricata':
                    rows.append('- ' + cell(f"{alert.get('timestamp')} · SID {alert.get('signature_id')} · {alert.get('signature')} · {alert.get('source_ip')} → {alert.get('destination_ip')}:{alert.get('destination_port')} ({alert.get('protocol')})"))
                else:
                    rows.append('- ' + cell(f"{alert.get('timestamp')} · WAF IDs {alert.get('waf_rule_ids')} · {alert.get('source_ip')} · {alert.get('method')} · HTTP {alert.get('http_status')} · engine {alert.get('engine')}"))
    rows.extend(['', '**조치 및 다음 단계**', '- 조회만 수행했습니다. 반환0건은 전체 경보/공격 부재나 정상의 증거가 아니며, 행위자와 원인은 별도 조사 대상입니다.'])
    return '\n'.join(rows)


def fallback(question, calls):
    rendered = read_report(question, calls) or inventory(question, calls)
    if rendered:
        return rendered
    summary = EVIDENCE.literal_evidence_summary(facts_for(calls))
    failures = [c['server'] + '.' + c['name'] for c in calls if c.get('is_error') or not c.get('result')]
    return ('모델 답변을 조회 근거로 검증하지 못해 확인된 자료만 표시합니다. 요청 범위 전체의 확인 완료를 뜻하지 않습니다.\n' +
            (summary or '성공한 현재 조회 근거가 없습니다. 정상이나 0건으로 판단하지 않았습니다.') +
            ('\n조회 실패: ' + ', '.join(failures) if failures else ''))


def write_progress(question, calls):
    """Report proposal receipts, including partial failure, without dispatch/retry.

    These are submission observations, not a replacement for fresh apply-status
    verification. Preserve every real receipt even if a later attempt fails.
    """
    text = normalized(question)
    writing = READ.wants_write(text)
    observed = {}
    for c in calls:
        if c.get('name') not in ('propose_rule_edit', 'propose_rule_change') or c.get('server') not in ('rule-write-a', 'rule-write-b'):
            continue
        target = c.get('arguments', {}).get('target')
        if target not in ('a:modsecurity-custom', 'a:suricata-local', 'b:wazuh-local-rules') or not target.startswith(c['server'][-1] + ':'):
            continue
        entry = observed.setdefault(target, {'receipts': {}, 'failures': [], 'unresolved': False, 'rejected_edits': []})
        raw = c.get('result', '')
        valid = isinstance(raw, str) and hashlib.sha256(raw.encode()).hexdigest() == c.get('result_sha256')
        try: data = json.loads(raw) if valid else None
        except (ValueError, TypeError): data = None
        if not isinstance(data, dict):
            entry['failures'].append('호출 결과 미확인; 상태 조회 필요')
            entry['unresolved'] = True
        elif c.get('is_error') or data.get('error'):
            # Transport errors may occur after a server has accepted the call.
            error = str(data.get('error', '도구 오류'))[:160]
            if re.fullmatch(r'edit [1-9][0-9]* old_text must match exactly once in the original file', error):
                entry['rejected_edits'].append(error)
            else:
                entry['failures'].append('오류 반환/처리 상태 확인 필요: ' + error)
                entry['unresolved'] = True
        elif (data.get('target') == target and data.get('status') == 'pending' and data.get('review_posted') is True
              and re.fullmatch(r'[0-9a-f]{32}', str(data.get('proposal_id', '')))
              and all(re.fullmatch(r'[0-9a-f]{64}', str(data.get(k, ''))) for k in ('before_sha256', 'after_sha256'))):
            entry['receipts'][data['proposal_id']] = data
            for error in entry['rejected_edits']:
                entry['failures'].append('이전 편집 검증 거절; 이후 별도 후보 제출됨: ' + error)
            entry['rejected_edits'] = []
        else:
            entry['failures'].append('제출 완료 근거 불충분; 상태 조회 필요')
            entry['unresolved'] = True
    if not observed and (not writing or not re.search(r'룰|규칙|파일|주석|원복|modsecurity|suricata|wazuh', text, re.I)):
        return None
    expected = []
    for pattern, target in [('WAF|ModSecurity', 'a:modsecurity-custom'), ('IDS|Suricata|수리카타', 'a:suricata-local'), ('Wazuh|와주', 'b:wazuh-local-rules')]:
        if writing and re.search(pattern, text, re.I): expected.append(target)
    expected += [target for target in observed if target not in expected]
    if not expected: return None
    rows = ['**요청 항목별 변경안 제출 근거**', '| 대상 | 상태 | 제안 ID 또는 확인 필요 사항 |', '| --- | --- | --- |']
    missing, hashes = [], []
    for target in expected:
        entry = observed.get(target, {'receipts': {}, 'failures': [], 'unresolved': False, 'rejected_edits': []})
        receipts, failures = entry['receipts'], entry['failures']
        for pid, data in receipts.items():
            rows.append('| ' + target + ' | 제출 당시 승인 대기 (적용 여부는 별도 확인) | ' + pid + ' |')
            hashes.append('- ' + target + ' / ' + pid + ' 변경 전 SHA: `' + data['before_sha256'] + '`; 후보 SHA: `' + data['after_sha256'] + '`.')
        for failure in failures:
            status = '이전 거절 이력' if failure.startswith('이전 편집 검증 거절;') else '추가 확인 필요'
            rows.append('| ' + target + ' | ' + status + ' | ' + re.sub(r'[\r\n|]', ' ', failure) + ' |')
        for failure in entry['rejected_edits']:
            rows.append('| ' + target + ' | 편집 검증 거절/미완료 | ' + failure + ' |')
        if not receipts or entry['unresolved'] or entry['rejected_edits']:
            missing.append(target)
        if not receipts and not failures:
            rows.append('| ' + target + ' | 미처리/확인 필요 | 이번 요청의 변경안 제출 근거 없음 |')
    return {'text': '\n'.join(rows + [''] + hashes), 'missing': missing, 'complete': not missing}
