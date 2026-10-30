"""SOC answer grounding shared with Hermes; no tools or incident decisions here.

The installer copies the two canonical Hermes sources verbatim. Development
imports those same sources, rather than maintaining a second rules parser.
"""
import hashlib
from datetime import datetime
import ipaddress
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
    return CONTRACT.normalize_query_text(READ.without_prohibitions(SHARED._unquoted_text(text)))


def rule_scope_request(question):
    if re.search(r'조회(?:는|하지)?\s*(?:마|말)|조회하지|도구\s*없이', SHARED._unquoted_text(question)):
        return None
    text = READ.scope_text(normalized(question))
    if READ.wants_write(text):
        return None
    return CONTRACT.rule_scope_request(text)


def scope_notice(question):
    """Scope/capability explanation only; never an observation or tool result."""
    request = rule_scope_request(question)
    if not request:
        return None
    if request['ambiguous']:
        return ('어느 장비의 규칙을 볼까요? FW(네트워크 방화벽), WAF, IDS(Suricata), Wazuh 중 '
                '대상을 알려주세요. 아직 조회하지 않았습니다.')
    if request['basic_only'] and 'FW' not in request['devices']:
        return ('요청하신 기본·내장 규칙 전체는 현재 커스텀 파일 조회 도구로 확인할 수 없습니다. '
                '커스텀 규칙을 기본 규칙 대신 표시하지 않았습니다. 기본 룰 목록은 미조회·미확인입니다.')
    return None


def firewall_request(question):
    request = rule_scope_request(question)
    return request if request and 'FW' in request['devices'] else None


def firewall_state(calls):
    """Only contiguous, hashed pages from one actual MCP snapshot are complete."""
    pages = []
    for call in calls:
        if call.get('server') != 'resp' or call.get('name') != 'get_firewall_rules': continue
        data = payload(call)
        if not data or data.get('offset') == 0: pages = []
        if (not data or data.get('schema') != 1 or data.get('target') != 'a:firewall'
                or not EVIDENCE.parse_instant(data.get('observed_at_kst'))
                or not isinstance(data.get('objects'), list)): continue
        if not pages:
            if data.get('offset') != 0: continue
        elif (data.get('snapshot') != pages[0]['snapshot'] or data.get('sha256') != pages[0]['sha256']
              or data.get('offset') != pages[-1].get('next_offset')
              or data.get('total_objects') != pages[0]['total_objects']): continue
        pages.append(data)
    if not pages: return None
    data = dict(pages[-1]); data['objects'] = [o for p in pages for o in p['objects']]
    counts = {}
    for obj in data['objects']:
        if not isinstance(obj, dict) or len(obj) != 1: return None
        key = next(iter(obj)); counts[key] = counts.get(key, 0) + 1
    data['verified_complete'] = (data.get('complete') is True and data.get('next_offset') is None
        and len(data['objects']) == data.get('total_objects') and counts == data.get('counts'))
    return data


def firewall_report(question, calls):
    data = firewall_state(calls)
    if not data or not data['verified_complete']:
        return 'FW 전체 조회 미완료입니다. 실패·미조회·페이지 누락을 규칙 0개로 해석하지 않습니다.'
    def cell(value):
        return str(value).replace('|', r'\|').replace('\n', ' ').replace('`', "'").replace('<', '&lt;').replace('>', '&gt;')
    counts = data['counts']; objects = data['objects']
    rows = ['**A 서버 FW 전체 nftables 조회**', '조회 시각: ' + data['observed_at_kst'] + ' (KST)',
            '테이블 ' + str(counts.get('table', 0)) + '개 · 체인 ' + str(counts.get('chain', 0)) + '개 · 규칙 ' + str(counts.get('rule', 0)) + '개 · 집합 ' + str(counts.get('set', 0)) + '개.',
            '호스트 네임스페이스의 기본 정책·NAT·Docker·커스텀을 함께 조회했습니다. 다음 표는 체인별 요약입니다.', '',
            '| family / table | chain | hook / 우선순위 | 기본 정책 | 규칙 수 |', '| --- | --- | --- | --- | --- |']
    rules = [o['rule'] for o in objects if 'rule' in o]
    for obj in objects:
        if 'chain' not in obj: continue
        c = obj['chain']; key = tuple(c.get(k) for k in ('family', 'table', 'name'))
        n = sum(tuple(r.get(k) for k in ('family', 'table', 'chain')) == key for r in rules)
        rows.append('| ' + ' | '.join(map(cell, [str(c.get('family')) + ' / ' + str(c.get('table')), c.get('name'),
            str(c.get('hook', '일반 체인')) + ' / ' + str(c.get('prio', '—')), c.get('policy', '해당 없음'), n])) + ' |')
    if re.search(r'상세|자세|개별|전문|원문|조건|전체\s*(?:룰|규칙)', normalized(question)):
        # Mattermost posts are bounded. All kernel objects were read, while
        # display pages are explicitly separate from MCP capture pagination.
        requested = re.search(r'([1-9][0-9]{0,3})\s*페이지', normalized(question))
        number = int(requested[1]) if requested else 1
        display_pages, page = [], []
        for r in rules:
            expr = [e for e in r.get('expr', []) if 'counter' not in e]
            line = '| ' + ' | '.join(map(cell, ['/'.join(str(r.get(k)) for k in ('family','table','chain')),
                r.get('handle'), json.dumps(expr, ensure_ascii=False, separators=(',', ':'))])) + ' |'
            if len(line) > 5000:
                line = line[:4900] + ' … [긴 규칙 표시 생략; 전체 조건은 MCP 원문에 보존] |'
            if page and (len(page) >= 16 or sum(map(len, page)) + len(line) > 6000):
                display_pages.append(page); page = []
            page.append(line)
        if page: display_pages.append(page)
        selected = display_pages[number - 1] if number <= len(display_pages) else []
        rows += ['', '**개별 규칙 표시 ' + str(number) + '/' + str(len(display_pages)) + '페이지 (전체 ' + str(len(rules)) + '개 조회, 이 페이지 ' + str(len(selected)) + '개 표시)**',
            '채팅 표시 페이지입니다. 다른 규칙은 “FW 전체 규칙 상세 N페이지”로 확인하세요. MCP 조회 누락과 구분합니다.',
            '| family / table / chain | handle | 조건·동작 (nft JSON, counter 제외) |', '| --- | --- | --- |', *selected]
        if not selected: rows += ['요청한 표시 페이지에 규칙이 없습니다. 전체 규칙 0개라는 뜻은 아닙니다.']
        sets = [o for o in objects if 'set' in o or 'map' in o or 'element' in o]
        if sets:
            raw = json.dumps(sets,ensure_ascii=False,separators=(',',':')).replace('```', '\\u0060\\u0060\\u0060')
            rows += ['', '집합·맵·원소 ' + str(len(sets)) + '개 조회.']
            if len(raw) <= 2000: rows += ['```json', raw, '```']
            else: rows += ['집합 원문은 채팅 길이 제한으로 표시 생략했습니다. 전체 원소는 MCP 응답에 보존되어 있습니다.']
    else:
        rows += ['', '개별 조건·집합 원소는 위 요약표에 생략했습니다. “FW 전체 규칙 상세”로 확인할 수 있습니다.']
    rows += ['', '범위: A 호스트 nftables만 확인했습니다. 다른 서버·컨테이너 내부 네임스페이스·legacy iptables는 포함하지 않습니다.',
             'list_blocks는 별도의 임시 차단 목록입니다. 이번 조회로 규칙을 변경하지 않았습니다.']
    rows += [str(w) for w in data.get('coverage_warnings', [])]
    return '\n'.join(rows)


def read_plan(question):
    text = normalized(question)
    # Recover literal data only, never instructions inside quotations.
    literals = EVIDENCE._AWARE_TIME.findall(question) + re.findall(r'(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])', question)
    for value in literals:
        if value not in text:
            text += '\n' + value
    return READ.plan(text, EVIDENCE._AWARE_TIME)


def rule_detail_request(question):
    text = READ.scope_text(normalized(question))
    if READ.wants_write(text) or re.search(r'설명만|조회하지|도구\s*없이', text):
        return None
    if not re.search(r'조회|확인|보여', text):
        return None
    ids = re.findall(r'\b(?:ID|SID)\s*[:=]?\s*([0-9]{1,10})(?![0-9])', text, re.I)
    unique = list(dict.fromkeys(map(int, ids)))
    if len(unique) != 1 or not 0 < unique[0] < 2**32:
        return None
    targets = [target for pattern,target in [('WAF|ModSecurity','a:modsecurity-custom'),
        ('IDS|Suricata','a:suricata-local'),('Wazuh|와주','b:wazuh-local-rules')] if re.search(pattern,text,re.I)]
    if not targets or (len(targets)>1 and len(ids)<len(targets) and not re.search(r'같은\s*(?:ID|SID|숫자)',text,re.I)):
        return None
    fields = re.search(r'레벨|(?<![A-Za-z_])(?:level|description)(?![A-Za-z_])',text,re.I)
    presence = re.search(r'존재|있는지|있나|없으면|존재\s*여부',text)
    if (not fields and not presence) or (fields and 'b:wazuh-local-rules' not in targets) or (len(targets)>1 and not presence):
        return None
    # Other rule semantics stay with the model, never substitute a presence table.
    if re.search(r'왜|원인|분석|영향|탐지\s*조건|\bmsg(?![A-Za-z_])', text, re.I):
        return None
    return {'id':unique[0], 'targets':targets}


def rule_detail_values(request, calls):
    import xml.etree.ElementTree as ET
    result = {}
    for target in request['targets']:
        for call in reversed(calls):
            if (call.get('server') != 'rule-'+target[0] or call.get('name') != 'get_rule_change_target'
                    or call.get('arguments',{}).get('target') != target):
                continue
            data = payload(call)
            inv = SHARED._verified_inventory(data, target)
            if inv is None: break
            present = request['id'] in inv['ids']
            value = {'present':present, 'sha256':data['sha256'], 'level':None, 'description':None}
            if target=='b:wazuh-local-rules' and present:
                content = data['content']
                if re.search(r'<!\s*(?:DOCTYPE|ENTITY)',content,re.I): break
                try:
                    root = ET.fromstring('<verified_rules>'+content+'</verified_rules>')
                    rules = [r for r in root.iter('rule') if r.get('id')==str(request['id'])]
                    if len(rules)!=1 or not re.fullmatch(r'[0-9]+',rules[0].get('level','')): break
                    desc = rules[0].find('description')
                    if desc is None: break
                    value.update(level=int(rules[0].get('level')),description=''.join(desc.itertext()))
                    if len(value['description'])>4096: break
                except (ET.ParseError,ValueError): break
            result[target] = value
            break
    return result


def rule_detail_report(request, calls):
    values = rule_detail_values(request,calls)
    rows = ['**요약**', '요청한 ID를 장비별 현재 파일에서 확인했습니다.' if len(values)==len(request['targets']) else
        '일부 대상이 미조회·검증 실패입니다. 미확인은 규칙이 없다는 뜻이 아닙니다.', '', '**확인 내역**', '',
        '| 대상 파일 | ID / SID | 파일 정의 | level | description |', '| --- | --- | --- | --- | --- |']
    for target in request['targets']:
        v=values.get(target)
        present='미조회·미확인' if v is None else '정의됨' if v['present'] else '없음 (파일에 미정의)'
        level='미확인' if v is None else str(v['level']) if v['level'] is not None else '해당 없음'
        desc='미확인' if v is None else json.dumps(v['description'],ensure_ascii=False).replace('|',r'\|') if v['description'] is not None else '해당 없음'
        rows.append('| '+target+' | '+str(request['id'])+' | '+present+' | '+level+' | '+desc+' |')
    rows += ['', *['- '+target+' SHA-256: `'+v['sha256']+'`.' for target,v in values.items()], '',
        '파일의 정의·필드를 확인한 결과이며 장비 간 같은 숫자는 별개의 규칙입니다. 엔진별 적재·탐지 성공은 미확인입니다.']
    return '\n'.join(rows)


def read_report(question, calls):
    notice = scope_notice(question)
    if notice: return notice
    scope = rule_scope_request(question)
    if scope and 'FW' in scope['devices']:
        other = [d for d in scope['devices'] if d != 'FW']
        return firewall_report(question, calls) + ('\n\n' + (inventory(question, calls) or '나머지 요청 대상은 미조회입니다.') if other else '')
    detail = rule_detail_request(question)
    if detail: return rule_detail_report(detail, calls)
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


def rule_scope_text(question):
    """Separate an inventory request's interpretation caveat from a live query."""
    text = READ.scope_text(normalized(question))
    if re.search(r'(?:규칙|룰|파일\s*정의|\bID\b|\bSID\b).{0,35}(?:목록|개수|정의\s*수)', text, re.I):
        text = re.sub(r'(?:엔진\s*)?(?:적재|로드|활성)(?:\s*(?:여부|상태))?(?:는|를)?\s*'
                      r'(?:파일\s*)?정의(?:와|과)\s*(?:구분(?:해|하)|혼동하지)', '', text)
        text = re.sub(r'(?:파일\s*)?정의(?:와|과)\s*(?:엔진\s*)?(?:적재|로드|활성)'
                      r'(?:\s*(?:여부|상태))?(?:를|는)?\s*(?:구분(?:해|하)|혼동하지)', '', text)
    return text


def ids_runtime_question(question):
    text = rule_scope_text(question)
    return bool(re.search(r'IDS|Suricata|수리카타', text, re.I)
        and re.search(r'활성|가동|적재|사용(?:\s*중|하는|하고)|구동|불러오|로드|실행\s*(?:상태|여부|중)', text)
        and not re.search(r'WAF|Wazuh', text, re.I) and not READ.wants_write(text))


def _inventory_question(question):
    text = rule_scope_text(question)
    request = rule_scope_request(question)
    if scope_notice(question): return None
    if request and 'FW' in request['devices']:
        selected = [d for d in request['devices'] if d != 'FW']
        return ('현재 적용된 규칙 목록 보여줘 ' + ' '.join(selected)
                + (' 장비별로 표로 보여줘' if re.search(r'표|테이블', text) else '')
                + (' SHA-256' if re.search(r'SHA|해시', text, re.I) else '')) if selected else None
    if ids_runtime_question(question): return None
    if re.search(r'설명|레벨|심각도|메시지|탐지\s*조건|(?<![A-Za-z_])(?:level|description|severity|msg)(?![A-Za-z_])|\b(?:ID|SID)\s*[:=]?\s*[0-9]+', text, re.I):
        return None  # Specific fields/IDs must not become a whole-file count table.
    if re.search(r'왜|원인|차이|변경|수정|차단|삭제|추가|적용해|재시작|원문|전문|분석', text):
        return None
    if '비교' in text and not re.search(r'(?:개수|정의\s*수).{0,12}비교|비교.{0,12}(?:개수|정의\s*수)', text): return None
    if not (re.search(r'룰|규칙|rules?', text, re.I) and re.search(r'조회|보여|출력|개수|목록|장비별|몇', text)):
        return None
    devices = [label for pattern, label in [('WAF|ModSecurity', 'WAF'),
               (r'(?<![A-Za-z])IDS(?![A-Za-z])|Suricata', 'Suricata'), ('Wazuh|와주', 'Wazuh')] if re.search(pattern, text, re.I)]
    if request and request['devices']:
        devices = request['devices']
    return ('현재 적용된 규칙 목록 보여줘 ' + ' '.join(devices)
            + (' 장비별로 표로 보여줘' if re.search(r'표|테이블', text) else '')
            + (' SHA-256' if re.search(r'(?<![A-Za-z])SHA(?:-?256)?(?![A-Za-z0-9])|해시', text, re.I) else ''))


def combined_rule_request(question):
    text = rule_scope_text(question)
    if READ.wants_write(text): return None
    runtime = re.search(r'(?:IDS|Suricata|수리카타)(?:가|는|의)?[^.!?。]{0,90}(?:local\.rules|all\.rules|구동\s*경로|실행\s*경로|룰\s*경로|실제\s*사용|사용하는지|가동\s*상태|(?:활성|적재|로드)\s*(?:상태|여부))', text, re.I)
    if runtime and re.search(r'(?:규칙|룰|파일\s*정의).{0,35}(?:개수|목록|정의\s*수)|(?:개수|목록|정의\s*수).{0,20}(?:규칙|룰|파일\s*정의)', text):
        labels = [label for pattern, label in [('WAF|ModSecurity', 'WAF'), ('IDS|Suricata|수리카타', 'Suricata'), ('Wazuh|와주', 'Wazuh')] if re.search(pattern, text, re.I)]
        return '현재 규칙 목록 보여줘 ' + ' '.join(labels) + (' 장비별로 표로 보여줘' if re.search(r'표|테이블', text) else '')
    return None


def inventory_question(question):
    return None if combined_rule_request(question) else _inventory_question(question)


def structured_read(question):
    return bool(firewall_request(question) or rule_detail_request(question) or read_plan(question) or combined_rule_request(question) or inventory_question(question) or
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
    rendered = SHARED.render_rule_inventory(request, linked_rows(calls), **kwargs) if request else None
    scope = rule_scope_request(question)
    if isinstance(rendered, str) and scope and not scope['custom_only']:
        rendered = ('**조회 범위: 커스텀 파일만 확인**\n기본·내장 규칙과 엔진 전체 적재 목록은 '
                    '이 조회에 포함되지 않아 전체 룰 확인은 미완료입니다.\n\n' + rendered)
        if not scope['devices']:
            rendered = 'FW(네트워크 방화벽) 전체 규칙도 현재 조회 도구 범위 밖이라 미확인입니다.\n\n' + rendered
    return rendered


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



def rule_edit_anchors(data):
    """Bounded unique edge excerpts from a hash-verified file, never a candidate."""
    content = data.get('content')
    if not isinstance(content, str) or not content or len(content.encode('utf-8')) > 128 * 1024:
        return None
    if hashlib.sha256(content.encode('utf-8')).hexdigest() != data.get('sha256'):
        return None
    lines = content.splitlines(keepends=True)
    found = {'source_sha256': data['sha256']}
    for position, parts in (('file_start', lines), ('file_end', reversed(lines))):
        excerpt = ''
        for count, line in enumerate(parts):
            if count >= 128:
                break
            excerpt = excerpt + line if position == 'file_start' else line + excerpt
            if len(excerpt.encode('utf-8')) > 4096:
                break
            start = content.find(excerpt)
            if content.find(excerpt, start + 1) == -1:
                found[position] = {'old_text': excerpt}
                break
    return found if len(found) > 1 else None


def model_view(server, name, raw):
    if server in ('rule-a', 'rule-b') and name == 'get_rule_change_target':
        try:
            data = json.loads(raw)
            if isinstance(data, dict) and not data.get('error') and str(data.get('target', '')).startswith(server[-1] + ':'):
                anchors = rule_edit_anchors(data)
                if anchors:
                    data['edit_anchors'] = anchors
                    return json.dumps(data, ensure_ascii=False)
        except (ValueError, TypeError):
            pass
        return raw
    if server in ('rule-write-a', 'rule-write-b') and name in ('propose_rule_edit', 'propose_rule_change'):
        try:
            data = json.loads(raw)
            if isinstance(data, dict) and not data.get('error') and data.get('status') == 'pending':
                stamp = approval_expiry_kst(data.get('approval_expires_at'))
                if stamp:
                    data['approval_expires_at_kst'] = stamp
                    data.pop('approval_expires_at', None)  # Epoch stays in the untouched audit/approval receipt.
                    return json.dumps(data, ensure_ascii=False)
        except (ValueError, TypeError):
            pass
        return raw

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
    issues.extend(action_claim_violations(question, answer, calls))
    return sorted(set(issues))


def action_claim_violations(question, answer, calls):
    """Check claimed observations/execution, including on the write path.

    This does not decide whether an incident warrants a change or run a tool.
    Policy-only refusal is valid; invented current state or server outcomes are not.
    """
    if not isinstance(answer, str):
        return []
    verified = []
    for call in calls:
        raw = call.get('result')
        if isinstance(raw, str) and hashlib.sha256(raw.encode()).hexdigest() == call.get('result_sha256'):
            verified.append(call)
    block_reads = any(c.get('server') == 'resp' and c.get('name') == 'list_blocks'
                      and payload(c) for c in verified)
    event_reads = any(c.get('name') in ('search_suricata_alerts', 'search_modsecurity_alerts',
                      'get_wazuh_alert_summary') and payload(c) for c in verified)
    actual_actions = [c for c in verified if (c.get('server'), c.get('name')) in (
        ('resp', 'block_ip'), ('resp', 'unblock_ip'),
        ('rule-write-a', 'temporarily_contain_ip'))]
    issues = set()
    for line in answer.splitlines():
        clean = re.sub(r'[*`]', '', line)
        unobserved = re.search(r'미조회|미확인|조회하지|조회\s*(?:못|안)|확인하지|확인\s*불가|알\s*수\s*없|단정.{0,8}(?:않|없)', clean)
        if not block_reads and not unobserved and re.search(r'차단\s*(?:목록|리스트)', clean) and re.search(r'없|비어|포함|등록|있습니다|있음', clean):
            issues.add('unobserved_block_list_claim')
        event = r'(?:공격(?!자)|경보|[Ss]everity\s*[0-9]+)'
        absence = (event + r'[^.!?;\n]{0,60}?(?:확인되지|발견되지|관측되지)\s*않|'
                   + event + r'(?:\s*(?:증거|징후|기록|발생|로그))?\s*(?:은|는|이|가)?\s*(?:없(?:습|음|다|었)|0\s*건)')
        if not event_reads and not unobserved and re.search(absence, clean):
            issues.add('unobserved_attack_absence_claim')
        if (not actual_actions and not re.search(r'호출\s*전|호출하지|호출\s*시|호출한다면|정책\s*(?:설명|상)|미호출', clean)
                and (re.search(r'(?:실행|처리)\s*(?:결과|상태).{0,70}(?:서버\s*거부|요청\s*실패|차단\s*완료)', clean)
                     or re.search(r'차단\s*시도.{0,70}(?:실패|거부)', clean)
                     or re.search(r'(?:서버|도구).{0,40}(?:거부했|거절했|거부되었|거절되었|거부됐|거절됐|거부됨|거절됨)', clean))):
            issues.add('unobserved_protected_execution_claim')
        if not re.search(r'호출하지|조회하지|미조회|미호출|조회할|확인할|확인해야|조회해야|호출해야|호출할', clean):
            claimed = re.findall(r'\b((?:get_|list_|search_|calculate_)[a-z_]+)\s*(?:\([^)]*\))?\s*(?:조회\s*결과|반환\s*결과|결과)', clean)
            for name in claimed:
                if not any(c.get('name') == name and payload(c) for c in verified):
                    issues.add('unobserved_tool_result_claim')
    # The model itself identifies a protected subject; it must not then propose
    # a different API as a way around that boundary. Conditional denials stay valid.
    addresses = set(re.findall(r'(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])', question))
    try:
        nonpublic_subject = len(addresses) == 1 and not ipaddress.ip_address(next(iter(addresses))).is_global
    except ValueError:
        nonpublic_subject = False
    protected_subject = nonpublic_subject or re.search(
        r'(?:해당|요청|대상|이\s*주소)[^\n]{0,60}(?:보호|사설|관리)|(?:보호된|보호\s*대상인)\s*(?:DGX\s*)?주소', answer)
    if protected_subject:
        for line in re.split(r'\n|(?<=[.!?;])\s+|\s*\(단[, ]', answer):
            public_alternative = re.search(r'공인|외부', line) and not re.search(r'사설|내부|관리|해당\s*(?:IP|주소)', line, re.I)
            if (re.search(r'block_ip|일반\s*차단', line, re.I) and not public_alternative
                    and re.search(r'대안|대신|사용|진행|차단|승인|가능', line)
                    and not re.search(r'거부|거절|불가|허용되지|지원하지|수\s*없|가능하지|사용하지|우회.{0,12}(?:않|안|못|없)|사용.{0,8}(?:않|안|못|없)', line)):
                issues.add('protected_address_bypass_advice')
            if (re.search(r'방화벽|nftables|(?:WAF|Suricata).{0,25}(?:IP|주소)\s*목록', line, re.I)
                    and not public_alternative
                    and re.search(r'해당\s*(?:IP|주소)|관리\s*주소|보호\s*주소|대신|우회', line, re.I)
                    and re.search(r'차단|수정해야|관리해야|관리할\s*수|변경해야', line)
                    and not re.search(r'거부|거절|불가|허용되지|지원하지|수\s*없|해서는\s*안|하지\s*않|우회.{0,12}(?:않|안|못|없)', line)):
                issues.add('protected_address_bypass_advice')
            if (re.search(r'propose_rule_change|propose_rule_edit', line) and
                    re.search(r'방화벽|nftables', line, re.I) and
                    re.search(r'변경|진행|승인', line) and
                    not re.search(r'불가|미지원|범위.{0,8}밖|지원하지|수\s*없', line)):
                issues.add('unsupported_firewall_proposal_advice')
    return sorted(issues)


def action_fallback(question, calls):
    """Report observable limits; never replace a missing model decision with a change."""
    attempts = [c for c in calls if (c.get('server'), c.get('name')) in (
        ('resp', 'block_ip'), ('resp', 'unblock_ip'), ('rule-write-a', 'temporarily_contain_ip'))]
    lines = ['답변의 상태·실행 설명에 확인되지 않은 근거가 있어 확인 범위만 표시합니다.',
             '이 답변은 변경 적용이나 현재 보안 상태가 정상이라는 판정이 아닙니다.']
    reads = sorted({c.get('name', '') for c in calls if payload(c) and
                    c.get('name', '').startswith(('get_', 'list_', 'search_', 'calculate_'))})
    lines.append('- 이번 요청에서 성공한 조회·계산: ' + (', '.join(reads) if reads else '없음/미조회'))
    if not re.search(r'차단|해제|block|contain', question, re.I) and not attempts:
        lines.append('- 실제 조회하지 않은 도구의 반환 결과나 현재 상태를 대신 보고할 수 없습니다. 허용된 조사와 변경안 준비를 이어가야 합니다.')
        return '\n'.join(lines)
    if attempts:
        lines.append('- 차단/해제 도구 호출 기록: ' + str(len(attempts)) + '건. 실제 적용 여부는 반환 결과와 후속 상태로 확인해야 합니다.')
    else:
        lines.append('- 이번 요청에서 차단/해제 도구를 호출하지 않았습니다. 서버가 요청을 거절했다고 보고하지 않습니다.')
    if not any(c.get('server') == 'resp' and c.get('name') == 'list_blocks' and payload(c) for c in calls):
        lines.append('- 현재 차단 목록: 성공한 조회 근거 없음/미확인.')
    if not any(c.get('name') in ('search_suricata_alerts', 'search_modsecurity_alerts', 'get_wazuh_alert_summary')
               and payload(c) for c in calls):
        lines.append('- 최근 공격 여부: 성공한 경보 조회 근거 없음/미확인. 공격이 없다는 뜻이 아닙니다.')
    lines.append('- 보호 주소의 거절은 운영자 승인이나 일반 block_ip 호출로 우회할 수 없습니다. 실제 사건 판단과 허용된 조사는 별도로 이어가야 합니다.')
    return '\n'.join(lines)


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
    if firewall_request(question):
        result += '\nFW는 resp.get_firewall_rules로 기본 정책·체인·NAT 포함 전체 nftables를 조회하세요. list_blocks나 WAF/IDS 파일로 대체하지 마세요. next_offset이 있으면 같은 snapshot으로 끝까지 조회하고 complete/전체 개수를 검증하세요. 실패를 0건으로 보고하지 마세요.'
    plan = read_plan(question)
    if plan:
        result += '\n' + READ.guidance(plan)
    if combined_rule_request(question):
        result += '\n이 요청에는 규칙 파일 목록과 IDS 구동 경로라는 두 조회가 있습니다. get_rule_change_target의 모든 요청 파일과 rule-a.get_service_action_target(a:suricata)를 각각 선택하세요. 한쪽만 완료한 것을 전체 완료로 보고하지 마세요.'
    if inventory_question(question):
        result += '\n명시한 장비만 조회하세요. 이 도구는 커스텀 파일 조회이며 기본 룰·전체 적재 확인이 아닙니다. 전체 요청이면 미조회 범위를 먼저 밝히세요.'
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
    if scope_notice(question): return set()
    operation = read_plan(question)
    if operation and operation['kind'] == 'operation': return READ.scope(operation,calls)
    request = firewall_request(question)
    if request:
        other = [d for d in request['devices'] if d != 'FW']
        return {'mcp__resp__get_firewall_rules'} | (inventory_tool_scope(' '.join(other)) if other else set())
    detail = rule_detail_request(question)
    if detail: return {'mcp__rule_'+t[0]+'__get_rule_change_target' for t in detail['targets']}
    if diagnostic_request(question):
        return {'mcp__system_diagnostics__get_system_diagnostics'}
    combined = combined_rule_request(question)
    if combined:
        return inventory_tool_scope(combined) | {'mcp__rule_a__get_service_action_target'}
    plan = read_plan(question)
    if plan:
        scope = READ.scope(plan, calls)
        if calls is not None and plan['kind'] == 'wazuh' and (not plan['needs_agent'] or READ.target_id(plan, calls)):
            missing = READ.missing(plan, calls, EVIDENCE)
            scope = {n for n in scope if any(m.startswith(n.split('__')[-1] + ':') or m == n.split('__')[-1] for m in missing)}
        return scope
    if ids_runtime_question(question):
        return {'mcp__rule_a__get_service_action_target'}
    inventory_request = inventory_question(question)
    if inventory_request:
        return inventory_tool_scope(inventory_request)
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


def inventory_tool_scope(request):
    """Limit catalog discovery to the hosts named by the normalized inventory."""
    a = bool(re.search(r'WAF|Suricata', request, re.I))
    b = bool(re.search(r'Wazuh', request, re.I))
    return {name for name, selected in [('mcp__rule_a__get_rule_change_target', a or not b),
                                       ('mcp__rule_b__get_rule_change_target', b or not a)] if selected}


def missing_reads(question, calls, diagnostic_targets=()):
    request = rule_scope_request(question)
    if request and 'FW' in request['devices']:
        other = [d for d in request['devices'] if d != 'FW']
        data = firewall_state(calls)
        return ([] if data and data['verified_complete'] else ['FW 전체 규칙(기본 정책·NAT 포함): 조회 미완료']) + (
            missing_reads('현재 커스텀 규칙 목록 보여줘 ' + ' '.join(other), calls, diagnostic_targets) if other else [])
    if request and request['basic_only']:
        return ['기본·내장 규칙 전체: 현재 커스텀 조회 도구 범위 밖']
    detail = rule_detail_request(question)
    if detail:
        verified = rule_detail_values(detail,calls)
        return [t for t in detail['targets'] if t not in verified]
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
    fw = 'mcp__resp__get_firewall_rules'
    if firewall_request(question) and fw in result:
        state = firewall_state(calls)
        if state and state['verified_complete']:
            result.pop(fw)
        elif state and type(state.get('next_offset')) is int:
            props = result[fw]['properties']
            props['snapshot']['enum'] = [state['snapshot']]
            props['offset']['enum'] = [state['next_offset']]
            result[fw]['required'] = ['snapshot', 'offset']
        if fw in result:
            # Preserve an explicit per-page bound on every model-selected call.
            # The MCP may return fewer objects when its byte budget is reached.
            limits = {int(v) for v in re.findall(r'(?<!\d)(\d{1,6})\s*개씩', normalized(question))}
            if len(limits) == 1 and 1 <= next(iter(limits)) <= 200:
                schema = result[fw]
                schema['properties']['limit']['enum'] = [next(iter(limits))]
                schema['required'] = list(dict.fromkeys([*schema.get('required', []), 'limit']))
    p = read_plan(question)
    if p and p['kind'] == 'operation':
        prefix = 'mcp__rule_' + p['target'][0] + '__'
        wanted = {prefix+'get_operation_status':('request_id',[rid for rid in p['ids'] if not READ.operation_attempt(p,calls,rid)])}
        if p['current'] and not READ.operation_current(p,calls):
            wanted[prefix+'get_service_action_target'] = ('target',[p['target']])
        narrowed = {}
        for alias,(key,values) in wanted.items():
            if alias in result and values:
                schema=result[alias];schema['properties'][key]['enum']=values
                schema['required']=list(dict.fromkeys([*schema.get('required',[]),key]));narrowed[alias]=schema
        return narrowed
    if p and p['kind'] == 'status':
        pending = READ.missing(p, calls, EVIDENCE)
        prefix = 'mcp__rule_' + p['target'][0] + '__'
        wanted = {prefix + 'get_rule_change_status': ('proposal_id', [pid for pid in p['ids'] if 'proposal:' + pid in pending])}
        if p['current'] and p['target'] in pending:
            wanted[prefix + 'get_rule_change_target'] = ('target', [p['target']])
        narrowed = {}
        for alias, (key, values) in wanted.items():
            if alias in result and values:
                schema = result[alias]
                schema['properties'][key]['enum'] = values
                schema['required'] = list(dict.fromkeys([*schema.get('required', []), key]))
                narrowed[alias] = schema
        return narrowed
    if p and p['kind'] == 'agent_identity':
        if READ.AGENTS not in result: return {}
        states = [state for state in READ.identity_states(p, calls) if not READ.failed_attempt(
            p, calls, 'get_wazuh_agents', {'status': state})]
        if not states: return {}
        schema = result[READ.AGENTS]
        props = schema['properties']
        schema['properties'] = {'status': {**props['status'], 'enum': states}}
        schema['required'] = ['status']
        schema['additionalProperties'] = False
        return {READ.AGENTS: schema}
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
            'Protected/management/infrastructure/DGX and active SSH addresses are refused' not in temporary):
        return None
    return ('**요약**\n보호된 DGX 주소는 일반 차단과 긴급 임시 차단 모두의 거절 대상입니다.\n\n'
            '**확인 내역**\n'
            '| 도구 정의 | 확인한 보호 경계 |\n| --- | --- |\n'
            '| block_ip | protected/management 주소와 활성 SSH 주소를 거절 |\n'
            '| temporarily_contain_ip | protected/management/infrastructure/DGX 및 활성 SSH 주소를 거절 |\n\n'
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
    if not isinstance(raw, str) or call.get('is_error') or hashlib.sha256(raw.encode()).hexdigest() != call.get('result_sha256'):
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
    engine = data.get('rule_engine_evidence')
    valid_engine = (isinstance(engine, dict) and engine.get('status') == 'observed'
                    and engine.get('scope') == 'single_tenant_engine_counters'
                    and isinstance(engine.get('container_id'), str) and re.fullmatch(r'[0-9a-f]{64}',engine['container_id'])
                    and engine.get('container_id') == observation.get('container_id')
                    and all(type(engine.get(key)) is int and engine[key] >= 0
                            for key in ('rules_loaded', 'rules_failed', 'rules_skipped'))
                    and EVIDENCE.parse_instant(engine.get('last_reload_kst'))
                    and EVIDENCE.parse_instant(engine.get('observed_at_kst')))
    if valid_engine:
        rows += ['', '| 엔진 적재 | 로딩 실패 | 건너뜀 |', '| --- | --- | --- |',
                 '| ' + ' | '.join(str(engine[key]) for key in ('rules_loaded','rules_failed','rules_skipped')) + ' |',
                 '- 마지막 적재 시각: ' + EVIDENCE.kst_time(engine['last_reload_kst']),
                 '- 엔진 통계 관측 시각: ' + EVIDENCE.kst_time(engine['observed_at_kst']),
                 '- 엔진 전체 카운터입니다. 로컬 파일 정의 수·개별 SID 적재·현재 파일과 적재 세대의 일치를 뜻하지 않습니다.']
    else:
        rows += ['- 엔진 적재 통계는 조회 불가 또는 근거 미확인입니다. 실패 수 0이나 정상 적재로 판단하지 않습니다.']
    rows.extend(['', '**조치 및 다음 단계**', '- 위 근거는 컨테이너 가동과 현재 지정 파일에 관한 것입니다. -S 옵션 자체로 비활성을 뜻하지 않습니다.',
                 '- SID별 실제 적재·탐지 성공은 확인하지 않았습니다. 변경/재시작은 수행하지 않았습니다.'])
    return '\n'.join(rows)


def cell(value):
    text = str(value if value is not None else '미확인').replace('|', '\\|').replace('\n', ' ')
    return text if len(text) <= 240 else text[:237] + '…'


def operational_text(value):
    """Keep the whole operational warning; table-cell shortening is inappropriate."""
    if not isinstance(value, str) or not value:
        return '미확인'
    if len(value) > 4096:
        return '상세 설명이 표시 한도를 초과했습니다. 영향 전체가 미확인이므로 원문 확인이 필요합니다.'
    return value.replace('\r', ' ').replace('\n', ' ')


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


def proposal_error(value):
    """Unwrap bounded MCP error envelopes without turning unknown errors into success."""
    for _ in range(4):
        if isinstance(value, dict) and set(value) == {'error'}:
            value = value['error']
        elif isinstance(value, str):
            try:
                nested = json.loads(value)
            except (ValueError, TypeError):
                return value
            if not isinstance(nested, dict) or set(nested) != {'error'}:
                return value
            value = nested
        else:
            break
    return value if isinstance(value, str) else str(value)


def approval_expiry_kst(value):
    if type(value) is not int:
        return None
    try:
        return datetime.fromtimestamp(value, EVIDENCE.KST).isoformat() + ' (KST)'
    except (OverflowError, ValueError, OSError):
        return None


def expiry_prose(answer, expiries):
    """Replace only expiry-time prose with verified receipts; fenced data is immutable."""
    if not expiries:
        return answer
    parts = re.split(r'(^```[^\n]*\n.*?^```[^\n]*$)', answer, flags=re.M | re.S)
    for i in range(0, len(parts), 2):
        lines = parts[i].splitlines(keepends=True)
        for j, line in enumerate(lines):
            if (re.search(r'만료|approval_expires_at', line) and
                    re.search(r'\d{4}-\d{2}-\d{2}|\d{1,2}:\d{2}|\b[0-9]{9,12}\b|\d+\s*(?:시간|분|초)', line)):
                selected = [v for v in expiries if v['proposal_id'] in line or str(v['epoch']) in line]
                selected = selected or expiries
                lines[j] = '- 승인 만료 (서버 기준): ' + '; '.join(v['target'] + ' / ' + v['proposal_id'] + ': ' + v['kst'] for v in selected) + ('\n' if line.endswith('\n') else '')
        parts[i] = ''.join(lines)
    return ''.join(parts)


def write_report(answer, progress):
    """Keep a grounded refusal explanation without presenting missing work as done."""
    answer = expiry_prose(str(answer or ''), progress.get('expiries', []))
    answer = write_metadata_prose(answer, progress.get('file_metadata', []))
    if progress['complete']:
        return answer + '\n\n' + progress['text']
    header = '요청한 변경안 준비가 일부 미완료입니다. 승인 대기는 실제 적용 완료가 아닙니다.'
    refusal = re.search(r'지원하지|지원되지|제공하지|제공되지|수행할 수 없|실행할 수 없|변경할 수 없|권한이 없|도구가 없|기능이 없|범위.{0,6}벗어|불가능|실행\s*불가|허용되지', answer)
    completed = re.search(r'(?:적용|변경|제출|처리|실행)\s*(?:을|이|를)?\s*완료|모두\s*(?:반영|성공)|(?:적용|변경|실행|제출|처리|작성|준비)했', answer)
    if refusal and not completed:
        return header + '\n\n' + answer + '\n\n' + progress['text']
    return header + '\n\n' + progress['text']


def write_metadata_prose(answer, metadata):
    """Ground incidental total counts and rollback bases; keep code/diffs intact."""
    if not metadata:
        return answer
    def field_values(key):
        return '; '.join(v['target'] + ': ' + operational_text(v.get(key)) for v in metadata)
    parts = re.split(r'(^```[^\n]*\n.*?^```[^\n]*$)', answer, flags=re.M | re.S)
    for i in range(0, len(parts), 2):
        lines = parts[i].splitlines(keepends=True)
        for j, line in enumerate(lines):
            clean = re.sub(r'[*`]', '', line)
            total = re.search(r'(?:총|전체|기존|나머지)\s*(?:규칙|룰)?[^.!?\n]{0,15}?[0-9]+\s*개(?:의)?\s*(?:규칙|룰)|(?:전체|총)\s*(?:규칙|룰)[^.!?\n]{0,15}?[0-9]+\s*개', clean)
            ending = '\n' if line.endswith('\n') else ''
            if (re.search(r'^\s*(?:[-0-9.]+\s*)?검증\s*(?:범위|결과)?\s*:', clean) or
                    re.search(r'엔진.{0,30}구문.{0,50}(?:검증됨|검증됐|완료|통과했)', clean)):
                lines[j] = '- 제출 검증 범위 (서버 영수증): ' + field_values('validation') + ending
            elif (re.search(r'^\s*(?:[-0-9.]+\s*)?(?:적용|예상)\s*영향\s*:', clean) or
                  re.search(r'(?:승인|적용).{0,35}(?:재시작|재로딩|리로드|재적재|reload|restart)', clean, re.I) or
                  re.search(r'(?:동작|중단|서비스|WAF|Suricata|Wazuh).{0,25}영향.{0,10}없|중단.{0,10}없|무중단',clean,re.I)):
                lines[j] = '- 승인된 후보 적용에 포함된 영향 (서버 조회): ' + field_values('impact') + ending
            elif total:
                values = {v['target']: v.get('declared_count') for v in metadata}
                lines[j] = '- 제출 전 파일 정의 수 (실제 엔진 적재와 별개): ' + '; '.join(
                    target + ': ' + (str(count) + '개' if type(count) is int else '미확인')
                    for target, count in values.items()) + '.' + ending
            elif ((re.search(r'원복|되돌리', clean) and re.search(r'SHA|해시|방법|복원|원본|거부|만료', clean, re.I)) or
                  (re.search(r'거부|만료', clean) and re.search(r'원본|복원|되돌리', clean)) or
                  (re.search(r'현재.{0,20}(?:SHA|해시)', clean, re.I) and
                   any(re.search(r'(?<![0-9a-f])' + v['after_sha256'][:8] + r'(?:[0-9a-f]{56}|\.\.\.|…)', clean) for v in metadata))):
                lines[j] = '- 취소·원복 방법: 미적용 후보는 카드 거부/만료 시 파일을 복원할 필요가 없습니다. 적용 후 원복 시 실제 파일을 재조회한 SHA로 이전 내용을 복원하는 새 후보를 만들고 승인을 받습니다.' + ending
        parts[i] = ''.join(lines)
    return ''.join(parts)


def preparation_gap(question, calls):
    """One model continuation may prepare requested edits before any protected call.

    Never dispatch here or retry an attempted change, including unknown outcomes.
    Infrastructure reconfiguration and unsupported mode changes are not file edits.
    """
    text = normalized(question)
    if (not READ.wants_write(text) or re.search(r'모드|컨테이너|재구성|\binline\b|\bDetectionOnly\b', text, re.I)
            or not re.search(r'변경안|수정안|주석|description|\bmsg\b', text, re.I)):
        return []
    if any('write' in c.get('server', '') or
           (c.get('server') == 'resp' and c.get('name') not in {'list_blocks', 'get_firewall_rules'}) or
           re.match(r'propose_|submit_|apply_|temporarily_|restart_|block_|unblock_', c.get('name', ''))
           for c in calls):
        return []
    progress = write_progress(question, calls)
    return progress['missing'] if progress else []


def preparation_instruction(targets):
    return ('요청한 변경안 준비가 아직 끝나지 않았습니다: ' + ', '.join(targets) +
            '. 이번 요청에서 보호 도구 호출은 아직 없습니다. 사용자는 초안 작성과 승인 카드 제출을 이미 요청했습니다. '
            'get_rule_change_target의 현재 SHA와 원문을 확인하고 propose_rule_edit로 검토용 후보를 준비할 수 있습니다. '
            '파일 맨 앞/뒤 삽입에는 반환된 edit_anchors의 해당 old_text를 그대로 보존하고 새 텍스트를 앞/뒤에 붙이세요. '
            '실제 도구와 인자는 직접 선택하세요. 제출하지 못했다면 대상별 이유를 밝히고 제출 완료라고 쓰지 마세요. '
            '이 안내는 적용 승인이나 일반 shell/sudo/Docker 권한이 아닙니다.')


def rejected_before_proposal(error):
    # These exact executor validations precede _propose_candidate and cannot have
    # submitted a card. Transport/timeouts/unknown errors remain unresolved.
    return bool(re.fullmatch(
        r'edit [1-9][0-9]* old_text (?:must match exactly once in|is absent from) the original file'
        r'|candidate must end with a newline'
        r'|base_sha256 must be a SHA-256 from get_rule_change_target'
        r'|target changed since it was read; fetch current content and retry'
        r'|Wazuh comments must use XML syntax; non-whitespace text outside rule elements is forbidden', error))


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
            error = proposal_error(data.get('error', '도구 오류'))
            if rejected_before_proposal(error):
                entry['rejected_edits'].append(error)
            else:
                entry['failures'].append('오류 반환/처리 상태 확인 필요: ' + error[:160])
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
    missing, hashes, expiries, metadata = [], [], [], []
    for target in expected:
        entry = observed.get(target, {'receipts': {}, 'failures': [], 'unresolved': False, 'rejected_edits': []})
        receipts, failures = entry['receipts'], entry['failures']
        for pid, data in receipts.items():
            rows.append('| ' + target + ' | 제출 당시 승인 대기 (적용 여부는 별도 확인) | ' + pid + ' |')
            hashes.append('- ' + target + ' / ' + pid + ' 변경 전 SHA: `' + data['before_sha256'] + '`; 후보 SHA: `' + data['after_sha256'] + '`.')
            if isinstance(data.get('validation'), str):
                hashes.append('  - 제출 검증 범위: ' + operational_text(data['validation']))
            reads = [payload(c) for c in calls if c.get('name') == 'get_rule_change_target'
                     and c.get('server') == 'rule-' + target[0] and c.get('arguments', {}).get('target') == target]
            source = next((v for v in reversed(reads) if v and v.get('target') == target
                           and v.get('sha256') == data['before_sha256']), None)
            inv = SHARED._verified_inventory(source, target)
            metadata.append({'target': target, 'before_sha256': data['before_sha256'],
                             'after_sha256': data['after_sha256'],
                             'validation': data.get('validation') if isinstance(data.get('validation'), str) else None,
                             'impact': source.get('impact') if source and isinstance(source.get('impact'), str) else None,
                             'declared_count': inv['declared_count'] if inv else None})
            if inv:
                hashes.append('  - 제출 전 파일 정의 수: ' + str(inv['declared_count']) + '개; 실제 엔진 적재 검증과 별개입니다.')
            if source and isinstance(source.get('impact'), str):
                hashes.append('  - 승인된 후보 적용에 포함된 영향: ' + operational_text(source['impact']))
            expiry = data.get('approval_expires_at')
            if type(expiry) is int:
                stamp = approval_expiry_kst(expiry)
                if stamp:
                    hashes.append('  - 승인 만료: ' + stamp)
                    expiries.append({'target': target, 'proposal_id': pid, 'epoch': expiry, 'kst': stamp})
                else:
                    hashes.append('  - 승인 만료 시각: 변환 범위 초과/미확인')
        for failure in failures:
            status = '이전 거절 이력' if failure.startswith('이전 편집 검증 거절;') else '추가 확인 필요'
            rows.append('| ' + target + ' | ' + status + ' | ' + re.sub(r'[\r\n|]', ' ', failure) + ' |')
        for failure in entry['rejected_edits']:
            rows.append('| ' + target + ' | 편집 검증 거절/미완료 | ' + failure + ' |')
        if not receipts or entry['unresolved'] or entry['rejected_edits']:
            missing.append(target)
        if not receipts and not failures:
            rows.append('| ' + target + ' | 미처리/확인 필요 | 이번 요청의 변경안 제출 근거 없음 |')
    if metadata:
        hashes.append('- 취소·원복: 미적용 후보는 승인 카드에서 거부합니다. 적용 후 원복은 실제 파일을 다시 조회한 SHA를 기준으로 이전 내용을 복원하는 새 후보를 만들고 승인을 받습니다.')
    return {'text': '\n'.join(rows + [''] + hashes), 'missing': missing, 'complete': not missing,
            'expiries': expiries, 'file_metadata': metadata}
