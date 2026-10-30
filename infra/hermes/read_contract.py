"""Shared read requirements and lossless, bounded presentation of MCP facts.

No dispatch, approval, incident decision or network access. The model still
selects every tool and argument. A successful unrelated read never satisfies a
requested device. Legacy Wazuh strings are parsed conservatively, not executed.
"""
from collections import Counter
from datetime import datetime
import hashlib
import json
import re

AGGREGATE_PREFIX = 'SOC_VULNERABILITY_AGGREGATE_V1\n'
MAX_VULNERABILITY_BYTES = 8 * 1024 * 1024
WAZUH = 'mcp__wazuh_ro__'
AGENTS = WAZUH + 'get_wazuh_agents'
TIME = 'mcp__system_diagnostics__calculate_time'
STATES = ('active', 'disconnected', 'pending', 'never_connected')
ASSET_NAMES = {'groot-web': ('groot-web', 'capstone-service'),
               'groot-sec': ('groot-sec', 'capstone-security'),
               'groot-siem-host': ('groot-siem-host', 'capstone-siem-host'),
               'wazuh.manager': ('wazuh.manager', 'capstone-wazuh-manager')}
ASSET_PATTERNS = (
    (r'Groot[_ ]?A|groot-sec|capstone-security|보안\s*(?:서버|호스트)|(?<![A-Za-z0-9])A\s*(?:서버|호스트)', 'groot-sec'),
    (r'Groot[_ ]?B|groot-siem(?:-host)?|capstone-siem-host|SIEM\s*(?:서버|호스트)|(?<![A-Za-z0-9])B\s*(?:서버|호스트)', 'groot-siem-host'),
    (r'wazuh[._ ]manager|(?:Wazuh|와주)\s*(?:매니저|manager)|capstone-wazuh-manager', 'wazuh.manager'),
    (r'Groot[_ ]?C|groot-web|capstone-service|서비스\s*(?:서버|호스트)|(?<![A-Za-z0-9])C\s*(?:서버|호스트)', 'groot-web'))
AGENT_ID_PATTERN = r'(?:agent[_ ]?id|에이전트\s*(?:ID)?|ID)\s*[:=]?\s*[\x60\'\"]?(\d{3})(?![0-9])'
FEATURES = ((r'프로세스|process', 'get_wazuh_agent_processes'),
            (r'포트|ports?|LISTENING', 'get_wazuh_agent_ports'),
            (r'취약점|vulnerabil', 'get_wazuh_vulnerability_summary'),
            (r'Critical|치명적|심각한', 'get_wazuh_critical_vulnerabilities'),
            (r'remoted|수신\s*통계', 'get_wazuh_remoted_stats'),
            (r'로그\s*수집기?[^.!?\n]{0,35}통계|log.?collector', 'get_wazuh_log_collector_stats'))


def asset_mentions(text):
    mentions = sorted((m.start(), m.end(), name, None)
                      for pattern, name in ASSET_PATTERNS
                      for m in re.finditer(pattern, text, re.I))
    result = []
    for i, mention in enumerate(mentions):
        # "B 서버의 Wazuh Manager" names a container's location, whereas
        # "B 호스트와 Wazuh Manager" requests two independent assets.
        if i + 1 < len(mentions) and mention[2] == 'groot-siem-host':
            following = mentions[i + 1]
            if following[2] == 'wazuh.manager' and re.fullmatch(
                    r'\s*(?:의|에서|에\s*(?:있는|설치된|실행\s*중인))\s*',
                    text[mention[1]:following[0]]):
                continue
        result.append(mention)
    return result


def exclusion_spans(text):
    """Remove explicitly excluded subjects only from the read-scope view.

    Positive clauses and the original model request are kept. A negated
    exclusion ("제외하지 마") is not an exclusion.
    """
    subject = '(?:' + '|'.join(p for p, _ in ASSET_PATTERNS) + '|' + AGENT_ID_PATTERN + r'|WAF|ModSecurity|IDS|Suricata|Wazuh|와주)'
    pattern = subject + r'[^.!?\n]{0,65}?(?:제외(?:해|하(?:고|여|세요)|한다)|빼(?:고|줘|주세요))'
    spans = []
    for m in re.finditer(pattern, text, re.I):
        if re.search(r'조회해|확인해|보여줘|제외하지', m[0]):
            continue
        spans.append(m.span())
    return spans


def scope_text(text):
    if wants_write(text): return text
    for start, end in reversed(exclusion_spans(text)):
        text = text[:start] + ' ' * (end - start) + text[end:]
    return text


def process_search(text):
    # Literal name/command search only. Arbitrary filters stay on the general path.
    match = re.search(r'(?:이름|명령줄)(?:에|이|은|는)?\s*[`\'\"]?([A-Za-z0-9_.:/-]+)[`\'\"]?(?:가|이)?\s*(?:들어|포함)', text)
    return match[1] if match else None


def without_prohibitions(text):
    action = r'(?:(?:추가|새로|다시)\s*조회|조회|(?:(?:변경안|원복안|제안)\s*)?(?:변경|수정|추가|삭제|차단|재시작|원복|복구|작성|준비|제출|적용|배포|설치))'
    join = r'\s*(?:[·,/]|및|또는|이나|와|과)\s*'
    end = r'(?:은|는|을|를|도)?\s*(?:하지\s*(?:말고|마세요|말아(?:줘|주세요)?|마|않고|않는)|없이|금지)'
    text = re.sub(action + '(?:' + join + action + ')*' + end, '', text)
    return re.sub(r'만들지\s*(?:말고|마세요|말아(?:줘|주세요)?|마)', '', text)


def wants_write(text):
    text = without_prohibitions(text)
    # Presentation conversion alone does not authorize an operational change.
    text = re.sub(r'(?:KST|UTC|한국\s*시간|표|테이블|목록)(?:으)?로\s*(?:바꿔(?:줘|주세요)?|바꾸(?:어|고))', '', text, flags=re.I)
    return bool(re.search(
        r'(?:변경안|수정안|원복안|제안|후보|검토안|승인안|승인\s*카드).{0,60}(?:만들|작성|준비|제출)(?:해|하|해줘|해주|해줄|하세요|을|한다|$)'
        r'|(?:변경안|수정안|원복안|제안|후보|검토안|승인안|승인\s*카드).{0,60}만들어(?:줘|주|줄|주세요|라|요|$)'
        r'|(?:바꿔|바꾸어|바꾸고|바꿔줘|재구성해|재구성하(?:고|라|세요|자))'
        r'|(?:추가|삭제|수정|변경|원복|복구|재시작|설치|배포|차단|해제|승인|거부|적용)(?:해|하(?:고|라|세요|는|여|자)|해줘|해주|해줄)', text))


def _single_plan(question, aware_time):
    text = scope_text(without_prohibitions(question))
    if wants_write(text) or re.search(r'도구\s*없이|조회(?:는|하지)\s*말|설명만|번역|라는\s*문장', text):
        return None
    stamps = aware_time.findall(text)
    if stamps and re.search(r'시간|시각|계산|KST|UTC|timeline', text, re.I):
        return {'kind': 'time', 'stamps': stamps, 'question': question}
    ids = re.findall(r'(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])', text)
    if ids and re.search(r'요청|작업|operation', text, re.I) and re.search(r'재시작|재로드|reload|restart|임시\s*차단|containment', text, re.I):
        if re.search(r'임시\s*차단|containment', text, re.I):
            targets = ['a:incident-ip']
        else:
            patterns = [('WAF|ModSecurity', 'a:waf'), ('IDS|Suricata', 'a:suricata'),
                        (r'chatproxy|채팅\s*프록시', 'a:chatproxy'),
                        ('대시보드|dashboard', 'b:wazuh-dashboard')]
            targets = [target for pattern, target in patterns if re.search(pattern, text, re.I)]
            if re.search(r'Wazuh|와주', text, re.I) and 'b:wazuh-dashboard' not in targets:
                targets.append('b:wazuh-manager')
        if len(targets) == 1:
            return {'kind':'operation', 'ids':list(dict.fromkeys(ids)), 'target':targets[0],
                    'current': targets[0] != 'a:incident-ip' and bool(re.search(r'현재|지금|최신', text)), 'question':question}
        return None
    if ids and re.search(r'제안|proposal|변경', text, re.I) and re.search(r'상태|이력|실패|처리|승인|적용|원복|복구|알림|결과|해시', text):
        targets = [t for pattern, t in [('WAF|ModSecurity', 'a:modsecurity-custom'),
            ('IDS|Suricata', 'a:suricata-local'), ('Wazuh|와주', 'b:wazuh-local-rules')]
            if re.search(pattern, text, re.I)]
        if len(targets) == 1:
            return {'kind': 'status', 'ids': list(dict.fromkeys(ids)), 'target': targets[0],
                    'current': bool(re.search(r'현재|지금|최신', text)), 'question': question}
        return None  # An ambiguous change target is not an agent-inventory read.
    features = []
    for pattern, name in FEATURES:
        if re.search(pattern, text, re.I):
            features.append(name)
    states = [s for s in STATES if re.search(r'(?<![a-z_])' + s + r'(?![a-z_])', text, re.I)]
    if re.search(r'(?<![가-힣])활성(?:화)?(?:된|인)?\s*(?:Wazuh\s*)?(?:에이전트|agent)|(?:에이전트|agent).{0,20}활성\s*(?:상태|목록)', text, re.I):
        if 'active' not in states:
            states.append('active')
    if not features:
        identity = identity_plan(text, states)
        if identity:
            return identity
    if not features and not (re.search(r'Wazuh|와주|에이전트|agent', text, re.I) and states):
        return None
    search = process_search(text)
    if 'get_wazuh_agent_processes' in features and re.search(r'검색|필터|search\s*[:=]', text, re.I) and not search:
        return None  # A filtered process search stays with the general agent.
    if not re.search(r'조회|보여|확인|정리|상태|목록|통계|요약', text):
        return None
    explicit = re.search(AGENT_ID_PATTERN, text, re.I)
    alias = next((name for _, _, name, _ in asset_mentions(text)), None)
    literal_name = re.search(r'이름(?:이|은|으로)?\s*[`\'\"]?([A-Za-z][A-Za-z0-9_.-]*)', text)
    if not alias and literal_name:
        # Only a named device clause may supply an unknown asset name.
        if re.search(r'장비|에이전트|서버', text[literal_name.end():literal_name.end()+20]):
            alias = literal_name[1]
    dependent = any(n not in ('get_wazuh_remoted_stats',) for n in features)
    return {'kind': 'wazuh', 'features': features, 'states': states or ([] if features else ['active']),
            'agent_id': explicit[1] if explicit else None, 'agent_name': alias,
            'needs_agent': dependent, 'limit': requested_limit(text), 'search': search, 'question': text}


def identity_plan(text, states):
    """Current identity/state only; never reinterpret a diagnosis or a change."""
    if re.search(r'비활성|원인|분석|위험|침해|왜|설명|정책|설정|룰|규칙|로그|경보|보안', text, re.I):
        # A server alias itself may contain 보안; remove that alias for this test.
        residual = text
        for pattern, _ in ASSET_PATTERNS:
            residual = re.sub(pattern, '', residual, flags=re.I)
        if re.search(r'비활성|원인|분석|위험|침해|왜|설명|정책|설정|룰|규칙|로그|경보|보안', residual, re.I):
            return None
    if re.search(r'그룹|필터|검색|os_platform|version\s*[:=]|group\s*[:=]|IP\s*(?:[:=]|\d)', text, re.I):
        return None
    mentions = asset_mentions(text)
    mentions += [(m.start(), m.end(), None, m[1]) for m in re.finditer(AGENT_ID_PATTERN, text, re.I)]
    literal = re.search(r'이름(?:이|은|으로)?\s*[`\'\"]?([A-Za-z][A-Za-z0-9_.-]*)', text)
    if not mentions and literal and re.search(r'장비|에이전트|서버', text[literal.end():literal.end()+20]):
        mentions.append((literal.start(), literal.end(), literal[1], None))
    if not mentions and (states or not re.search(r'Wazuh|에이전트|\bagents?\b', text, re.I)):
        return None
    if not re.search(r'(?<![a-z])ID(?![a-z])|식별|연결|상태|등록|목록|리스트|status|identity', text, re.I):
        return None
    subjects = []
    previous_end = 0
    for start, end, name, agent_id in sorted(mentions):
        if (agent_id and subjects and subjects[-1]['agent_name'] and not subjects[-1]['agent_id']
                and re.fullmatch(r'\s*(?:의|에이전트)?\s*', text[previous_end:start])):
            subjects[-1]['agent_id'] = agent_id
        else:
            subject = {'agent_name': name, 'agent_id': agent_id}
            if subject not in subjects: subjects.append(subject)
        previous_end = end
    return {'kind': 'agent_identity', 'subjects': subjects, 'states': states, 'question': text}


def identity_calls(p, calls, state):
    names = {name for subject in p['subjects'] if subject['agent_name']
             for name in ASSET_NAMES.get(subject['agent_name'], (subject['agent_name'],))}
    selected = {}
    for c in calls:
        if c.get('server') != 'wazuh-ro' or c.get('name') != 'get_wazuh_agents': continue
        args = c.get('arguments', {})
        if args.get('status') != state: continue
        if any(v not in (None, '') for k,v in args.items() if k not in ('status','name','limit','offset')): continue
        name = args.get('name')
        if name not in (None, '') and name not in names: continue
        if not valid_wazuh(c, 'get_wazuh_agents'): continue
        raw = text_result(c); rows = agents(raw)
        if rows:
            if (len(rows) != len(records(raw, r'Agent ID:'))
                    or any(not re.fullmatch(r'[\W_]*' + re.escape(state) + r'[\W_]*', a['status'], re.I) for a in rows)):
                continue
        elif not re.match(r'No Wazuh agents matching', raw.strip()): continue
        selected[name or ''] = c
    return list(selected.values())


def identity_call(p, calls, state):
    found = identity_calls(p, calls, state)
    return found[-1] if found else None


def identity_rows(p, calls):
    rows = {}
    for state in p['states'] or STATES:
        for c in identity_calls(p, calls, state):
            for a in agents(text_result(c)):
                rows[(a['id'], a['name'], state)] = a
    return list(rows.values())


def subject_rows(subject, rows):
    names = ASSET_NAMES.get(subject['agent_name'], (subject['agent_name'],))
    return [a for a in rows if (not subject['agent_name'] or a['name'] in names)
            and (not subject['agent_id'] or a['id'] == subject['agent_id'])]


def identity_states(p, calls):
    """Expose unmet read choices, not a fixed tool invocation."""
    if p['states'] or not p['subjects']:
        return [state for state in p['states'] or STATES if not identity_call(p, calls, state)]
    rows = identity_rows(p, calls)
    if all(len(subject_rows(subject, rows)) == 1 for subject in p['subjects']): return []
    if not identity_call(p, calls, 'active'): return ['active']
    return [state for state in STATES if not identity_call(p, calls, state)]


def identity_missing(p, calls):
    pending = ['get_wazuh_agents:' + state for state in identity_states(p, calls)]
    rows = identity_rows(p, calls)
    for subject in p['subjects']:
        if len(subject_rows(subject, rows)) != 1:
            pending.append('get_wazuh_agents: 대상 식별 미확인/중복 ' + part_label(subject))
    return pending


def identity_report(p, calls, evidence):
    pending = identity_missing(p, calls); all_rows = identity_rows(p, calls)
    rows = ['**요약**', '요청한 에이전트 ID·연결 상태를 실제 조회로 확인했습니다.' if not pending else
            '대상 식별 또는 상태 조회가 미완료입니다. 미등록이나 정상으로 단정하지 않았습니다.', '', '**확인 내역**']
    displayed = []
    if p['subjects']:
        for subject in p['subjects']:
            matched = subject_rows(subject, all_rows)
            rows += ['요청 대상: ' + cell(part_label(subject))]
            if len(matched) == 1: displayed.extend(matched)
            else: rows += ['실제 반환에서 일치하는 대상을 유일하게 식별하지 못했습니다. 후보 ' + str(len(matched)) + '개; 상태 미확인.']
    else: displayed = all_rows
    rows += table(['ID', '이름', '주소', '상태', '마지막 연결 KST'], [(a['id'], a['name'], a['ip'], a['status'],
        '특수값: 실제 연결 시각 미확인' if (a['last_keepalive'] or '').startswith('9999-') else evidence.kst_time(a['last_keepalive'])) for a in displayed])
    rows += ['표시한 반환 레코드: ' + str(len(displayed)) + '개. 이름/ID로 대조했으며 IP만으로 호스트를 추정하지 않았습니다.']
    queried = [state for state in p['states'] or STATES if identity_call(p, calls, state)]
    rows += ['확인한 상태 범위: ' + (', '.join(queried) or '없음') + '. 반환 목록/페이지 밖과 모든 보안 기능의 정상 여부는 미확인입니다.']
    if pending: rows += ['미확인: ' + '; '.join(pending)]
    rows += ['', '**조치 및 다음 단계**', '조회만 수행했습니다. 보호된 변경은 실행하지 않았습니다.']
    return '\n'.join(rows)


def identity_comparison(p, review_question, calls, evidence):
    """Compare only displayed identity/state claims with this model's own reads.

    This is evidence presentation, not an incident verdict or model dispatch.
    Free prose, missing/truncated tables and changed observation times are not
    promoted into verified facts or security decisions.
    """
    if not p or p['kind'] != 'agent_identity': return None
    literal = identity_report(p, calls, evidence)
    def incomplete(reason):
        return {'complete': False, 'verdict': 'unverified', 'text':
                'ID·연결 상태의 교차 대조가 미완료입니다. ' + reason + '\n\n**독립 조회 근거**\n' + literal}
    if identity_missing(p, calls): return incomplete('요청 대상의 독립 조회가 부족합니다.')
    try:
        envelope = json.loads(review_question.split('\nUNTRUSTED_REVIEW_DATA\n', 1)[1])
        other = envelope['other_agent_answer']
        if not isinstance(other, str) or envelope.get('other_answer_truncated') is not False:
            return incomplete('상대 답변의 전체 자료를 확인하지 못했습니다.')
    except (ValueError, KeyError, IndexError, TypeError):
        return incomplete('상대 답변의 자료 경계를 확인하지 못했습니다.')
    header = '| ID | 이름 | 주소 | 상태 | 마지막 연결 KST |'
    if other.count(header) != 1: return incomplete('상대 답변에서 동일한 범위의 ID·상태 표를 식별하지 못했습니다.')
    body = other.split(header, 1)[1].splitlines()[1:]
    claims = []
    for line in body:
        if not line.startswith('|'): break
        if re.fullmatch(r'[| :\-]+', line): continue
        m = re.fullmatch(r'\| (\d{3}) \| ([A-Za-z0-9_.-]+) \| [^|]+ \| ([^|]+) \| [^|]+ \|', line)
        if not m: return incomplete('상대 표의 형식을 검증하지 못했습니다.')
        status = re.fullmatch(r'[\W_]*(active|disconnected|pending|never_connected)[\W_]*', m[3], re.I)
        if not status: return incomplete('상대 표의 상태 토큰을 확인하지 못했습니다.')
        claims.append((m[1], m[2], status[1].lower()))
    if len(set((i,n) for i,n,_ in claims)) != len(claims): return incomplete('상대 표에 중복된 대상이 있습니다.')
    fresh = identity_rows(p, calls)
    if p['subjects']: fresh = [a for subject in p['subjects'] for a in subject_rows(subject, fresh)]
    actual = [(a['id'], a['name'], re.fullmatch(r'[\W_]*(active|disconnected|pending|never_connected)[\W_]*', a['status'], re.I)[1].lower()) for a in fresh]
    match = set(claims) == set(actual)
    rows = ['**ID·연결 상태 교차 대조**',
            '상대 표의 ID·이름·연결 상태가 이번 독립 조회와 일치합니다.' if match else
            '상대 표와 이번 독립 조회에 차이가 있습니다. 관측 시점 차이인지 오기인지는 이 비교만으로 확정하지 않았습니다.']
    shown = []
    for i,n,status in actual:
        prior = [c for c in claims if c[:2] == (i,n)]
        shown.append((i,n,prior[0][2] if prior else '상대 표에 없음',status,
                      '일치' if prior and prior[0][2] == status else '현재 조회와 차이'))
    for i,n,status in claims:
        if not any(a[:2] == (i,n) for a in actual): shown.append((i,n,status,'요청 대상의 독립 반환에서 미확인','범위/관측 차이'))
    rows += table(['ID','이름','상대 상태','독립 조회 상태','대조 결과'], shown)
    rows += ['이름/ID는 요청 대상의 실제 반환과 대조했습니다. 같은 IP라는 이유로 호스트와 관리 컨테이너를 합치지 않았습니다.',
             '대조 범위는 위 표의 ID·이름·연결 상태입니다. 상대의 다른 서술·원인·보안 정상 여부는 검증 완료로 확대하지 않습니다.',
             '', '**독립 조회 근거**', literal]
    return {'complete':True,'verdict':'matching_observed_fields' if match else 'observed_difference','text':'\n'.join(rows)}


def requested_limit(question):
    found = re.search(r'(?:최대|상위|각각|각)\s*(\d{1,3})\s*(?:개|건)|(?<!\d)(\d{1,3})\s*(?:개|건)\s*이하', question)
    return min(100, max(1, int(next(x for x in found.groups() if x)))) if found else 5


def plan(question, aware_time):
    text = scope_text(without_prohibitions(question))
    p = _single_plan(text, aware_time)
    if not p or p['kind'] != 'wazuh' or not p['needs_agent']:
        return p
    mentions = [(m.start(), m.end(), None, m[1]) for m in re.finditer(AGENT_ID_PATTERN, text, re.I)]
    mentions += asset_mentions(text)
    mentions.sort()
    if len(mentions) < 2:
        return p
    bound, pending = [], []
    for i, (start, end, name, agent_id) in enumerate(mentions):
        segment = text[start:mentions[i+1][0] if i+1 < len(mentions) else len(text)]
        segment = re.split(r'[.!?]\s|[;\n]', segment, maxsplit=1)[0]
        pending.append((name, agent_id))
        if not any(re.search(pattern, segment, re.I) for pattern, _ in FEATURES):
            continue  # Coordinated subjects share the following predicate.
        local = _single_plan(segment + ' 조회', aware_time)
        if not local or local['kind'] != 'wazuh': return None
        if not re.search(r'\d{1,3}\s*(?:개|건)', segment): local['limit'] = p['limit']
        for local_name, local_id in pending:
            bound.append({**local, 'agent_name': local_name, 'agent_id': local_id, 'states': []})
        pending = []
    if pending:
        # A repeated subject in a limit/summary clause is not a new workload;
        # an unresolved different subject must not be silently omitted.
        known = {(x['agent_name'], x['agent_id']) for x in bound}
        if any(x not in known for x in pending): return None
    unique = []
    for part in bound:
        key = (part['agent_name'], part['agent_id'], tuple(part['features']), part['limit'], part.get('search'), tuple(sorted(port_filters(part).items())))
        if not any(key == k for k, _ in unique): unique.append((key, part))
    bound = [part for _, part in unique]
    if not bound: return p
    if p['states']: bound[0]['states'] = p['states']
    return bound[0] if len(bound) == 1 else {'kind': 'multi', 'plans': bound, 'question': question}


def part_label(p):
    return p.get('agent_name') or ('agent_id=' + p['agent_id'] if p.get('agent_id') else '대상 미확인')


def feature_args(p, name, agent):
    args = {} if name == 'get_wazuh_remoted_stats' else {'agent_id': agent}
    if name == 'get_wazuh_agent_ports': args.update(port_filters(p))
    if name == 'get_wazuh_agent_processes' and p.get('search'): args['search'] = p['search']
    return args


def parts(p):
    return p['plans'] if p and p['kind'] == 'multi' else [p] if p else []


def explicit_reference(p):
    if not p or p['kind'] != 'time':
        return None
    return next((stamp for stamp in p['stamps'] if re.search(
        r'(?:기준(?:\s*시각)?|reference)(?:은|는)?\s*[:=]?\s*' + re.escape(stamp),
        p['question'], re.I)), None)


def verified_ids(p, calls):
    return sorted({target_id(part, calls) for part in parts(p)
                   if part['kind'] == 'wazuh' and target_id(part, calls)})


def successful(call):
    raw = call.get('result')
    return (not call.get('is_error') and isinstance(raw, str) and
            hashlib.sha256(raw.encode()).hexdigest() == call.get('result_sha256'))


def unpack(raw):
    try:
        data = json.loads(raw)
        for _ in range(3):
            if (not isinstance(data, dict) or not set(data) <= {'result', 'isError', 'is_error'}
                    or not isinstance(data.get('result'), str)):
                break
            try: data = json.loads(data['result'])
            except ValueError: return data['result']
        return data
    except (ValueError, TypeError):
        return raw


def text_result(call):
    if not successful(call):
        return None
    data = unpack(call['result'])
    if not isinstance(data, str) or re.match(r'\s*(?:Error\b|Failed\b|Traceback|Exception\b)', data, re.I):
        return None
    return data


def records(text, start):
    return [chunk for chunk in re.split(r'(?=^' + start + r')', text, flags=re.M) if re.match(start, chunk)]


def field(text, name):
    found = re.search(r'^\s*' + re.escape(name) + r':\s*([^\n]*)', text, re.M)
    return found[1].strip() if found else None


def agents(text):
    result = []
    for chunk in records(text, r'Agent ID:'):
        m = re.match(r'Agent ID: (\d{3})(?:\s|$)', chunk)
        if m and field(chunk, 'Name') and field(chunk, 'IP') and field(chunk, 'Status'):
            result.append({'id': m[1], 'name': field(chunk, 'Name'), 'ip': field(chunk, 'IP'),
                           'status': field(chunk, 'Status'), 'last_keepalive': field(chunk, 'Last Keep Alive')})
    return result


def target_id(p, calls):
    if p.get('agent_id') and not p.get('agent_name'):
        return p['agent_id']
    matches = set()
    for c in calls:
        if c.get('server') == 'wazuh-ro' and c.get('name') == 'get_wazuh_agents':
            for a in agents(text_result(c) or ''):
                names = ASSET_NAMES.get(p.get('agent_name'), (p.get('agent_name'),))
                if a['name'] in names and (not p.get('agent_id') or a['id'] == p['agent_id']):
                    matches.add(a['id'])
    return next(iter(matches)) if len(matches) == 1 else None


def scope(p, calls=None):
    if p['kind'] == 'agent_identity': return {AGENTS}
    if p['kind'] == 'multi':
        return set().union(*(scope(part, calls) for part in p['plans']))
    if p['kind'] == 'time': return {TIME}
    if p['kind'] == 'operation':
        prefix = 'mcp__rule_' + p['target'][0] + '__'
        return {prefix + 'get_operation_status'} | ({prefix + 'get_service_action_target'} if p['current'] else set())
    if p['kind'] == 'status':
        prefix = 'mcp__rule_' + p['target'][0] + '__'
        return {prefix + 'get_rule_change_status'} | ({prefix + 'get_rule_change_target'} if p['current'] else set())
    tools = {WAZUH + name for name in p['features']}
    if p['states'] or p['needs_agent'] and not p.get('agent_id'):
        tools.add(AGENTS)
    # Only the outgoing model catalog is narrowed; no read is dispatched here.
    if calls is not None and p['needs_agent'] and not target_id(p, calls):
        return {AGENTS}
    return tools


def matching(p, calls, name, **args):
    server = ('wazuh-ro' if name.startswith('get_wazuh_') else
              'system-diagnostics' if name == 'calculate_time' else 'rule-' + p['target'][0])
    def equal(k, a, b):
        return str(a).lower() == str(b).lower() if k in ('state', 'protocol') else a == b
    found = [c for c in calls if c.get('server') == server and c.get('name') == name
             and successful(c) and all(equal(k, c.get('arguments', {}).get(k), v) for k, v in args.items())]
    if name == 'get_wazuh_vulnerability_summary':
        found = [c for c in found if not any(v not in (None, '') for k, v in c.get('arguments', {}).items() if k != 'agent_id')]
    return found[-1] if found else None


def operation_attempt(p, calls, rid):
    # A hash-bound failed lookup is evidence of failure, not of completion or
    # absent/expired state. Do not blindly repeat the same terminal error.
    rows = [c for c in calls if c.get('server') == 'rule-' + p['target'][0]
            and c.get('name') == 'get_operation_status' and c.get('arguments') == {'request_id':rid}
            and isinstance(c.get('result'), str)
            and hashlib.sha256(c['result'].encode()).hexdigest() == c.get('result_sha256')]
    return rows[-1] if rows else None


def operation_record(p, calls, rid):
    c = operation_attempt(p, calls, rid)
    d = unpack(c['result']) if c and not c.get('is_error') else None
    return d if isinstance(d, dict) and not d.get('error') and d.get('request_id') == rid and d.get('target') == p['target'] and isinstance(d.get('status'), str) else None


def operation_current(p, calls):
    c = matching(p, calls, 'get_service_action_target', target=p['target']) if p['current'] else None
    d = unpack(c['result']) if c else None
    if not isinstance(d, dict) or d.get('target') != p['target'] or not isinstance(d.get('observation'), dict): return None
    raw = json.dumps(d['observation'], sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    return d if hashlib.sha256(raw).hexdigest() == d.get('base_state_sha256') else None


def port_filters(p):
    text = p['question']
    values = {}
    if re.search(r'\bTCP\b', text, re.I): values['protocol'] = 'tcp'
    elif re.search(r'\bUDP\b', text, re.I): values['protocol'] = 'udp'
    if re.search(r'LISTENING|수신\s*대기|리스닝', text, re.I): values['state'] = 'LISTENING'
    else:
        state = re.search(r'(?<![A-Za-z_])(ESTABLISHED|TIME_WAIT|CLOSE_WAIT|SYN_SENT|SYN_RECV|FIN_WAIT1|FIN_WAIT2|LAST_ACK|CLOSING|CLOSE)(?![A-Za-z_])', text, re.I)
        if state: values['state'] = state[1].upper()
    return values


def failed_attempt(p, calls, name, args):
    for c in reversed(calls):
        if c.get('server') != 'wazuh-ro' or c.get('name') != name or not all(c.get('arguments', {}).get(k) == v for k, v in args.items()): continue
        raw = c.get('result')
        if not isinstance(raw, str) or hashlib.sha256(raw.encode()).hexdigest() != c.get('result_sha256'): continue
        data = unpack(raw)
        if c.get('is_error') or isinstance(data, dict) and data.get('error') or isinstance(data, str) and re.match(r'\s*(?:Error\b|Failed\b|Traceback|Exception\b)', data, re.I):
            return c
    return None


def state_call(p, calls, state):
    rows = [c for c in calls if c.get('name') == 'get_wazuh_agents' and
            not any(v is not None and v != '' for k, v in c.get('arguments', {}).items() if k not in ('status', 'limit', 'offset'))]
    return matching(p, rows, 'get_wazuh_agents', status=state)


def valid_wazuh(call, name):
    raw = text_result(call) if call else None
    if raw is None: return False
    markers = {'get_wazuh_agents': r'Agent ID:|No Wazuh agents matching',
        'get_wazuh_agent_processes': r'PID:|No processes (?:found|for agent)',
        'get_wazuh_agent_ports': r'Protocol:|No (?:network )?ports (?:found|for agent)',
        'get_wazuh_vulnerability_summary': r'CVE:|No vulnerabilit|^SOC_VULNERABILITY_AGGREGATE_V1',
        'get_wazuh_critical_vulnerabilities': r'CRITICAL VULNERABILITY|No critical vulnerabilit',
        'get_wazuh_remoted_stats': r'Wazuh Remoted Statistics:',
        'get_wazuh_log_collector_stats': r'Log Collector Stats for Agent:'}
    return bool(re.search(markers[name], raw, re.I))


def ambiguous_empty(p, calls, name, c):
    raw = text_result(c) if c else None
    if name not in ('get_wazuh_agent_processes', 'get_wazuh_agent_ports') or not raw or not re.match(r'No (?:processes|(?:network )?ports) for agent', raw): return False
    # The MCP collapses missing syscollector data and empty matches, even for a registered ID.
    return True


def missing(p, calls, evidence):
    if p['kind'] == 'agent_identity': return identity_missing(p, calls)
    if p['kind'] == 'multi':
        return [part_label(part) + ' / ' + item for part in p['plans'] for item in missing(part, calls, evidence)]
    if p['kind'] == 'operation':
        pending = ['operation:' + rid for rid in p['ids'] if not operation_record(p,calls,rid)]
        if p['current'] and not operation_current(p,calls): pending.append(p['target'])
        return pending
    if p['kind'] == 'time':
        for c in reversed(calls):
            if c.get('name') != 'calculate_time' or c.get('server') != 'system-diagnostics' or not successful(c): continue
            data = unpack(c['result']);args = c.get('arguments', {})
            supplied = [x.get('value') for x in args.get('timestamps', []) if isinstance(x, dict)] + [args.get('reference')]
            expected = {evidence.parse_instant(s) for s in p['stamps']}
            actual = {evidence.parse_instant(s) for s in supplied}
            reference = explicit_reference(p)
            if (None not in expected and expected <= actual and (not reference or args.get('reference') == reference) and isinstance(data, dict)
                    and data.get('kind') == 'time_calculation' and data.get('source_scope') == 'supplied_timestamps_only'):
                return []
        return ['calculate_time: 사용자 제공 시각/기준 시각']
    if p['kind'] == 'status':
        pending = []
        for pid in p['ids']:
            c = matching(p, calls, 'get_rule_change_status', proposal_id=pid)
            data = unpack(c['result']) if c else None
            if not isinstance(data, dict) or data.get('proposal_id') != pid or data.get('target') != p['target'] or not data.get('status') or data.get('error'):
                pending.append('proposal:' + pid)
        if p['current']:
            c = matching(p, calls, 'get_rule_change_target', target=p['target'])
            data = unpack(c['result']) if c else None
            if (not isinstance(data, dict) or data.get('target') != p['target'] or not isinstance(data.get('content'), str)
                    or hashlib.sha256(data['content'].encode()).hexdigest() != data.get('sha256')):
                pending.append(p['target'])
        return pending
    pending = []
    for state in p['states']:
        if not valid_wazuh(state_call(p, calls, state), 'get_wazuh_agents'):
            pending.append('get_wazuh_agents:' + state)
    agent = target_id(p, calls)
    if p['needs_agent'] and not agent:
        pending.append('get_wazuh_agents: 대상 이름/ID 실제 식별')
    for name in p['features']:
        args = feature_args(p, name, agent)
        c = matching(p, calls, name, **args) if agent or not args else None
        if not valid_wazuh(c, name) or ambiguous_empty(p, calls, name, c) or name == 'get_wazuh_vulnerability_summary' and vulnerability_view(text_result(c) or '').get('transport_truncated'):
            pending.append(name + (':' + (agent or '대상 미확인') if args else ''))
    return pending


def guidance(p, calls=()):
    if p['kind'] == 'agent_identity':
        return ('이 요청은 에이전트 식별/연결 상태의 읽기 전용 조회입니다. 모델이 get_wazuh_agents를 실제 선택하세요. '
                'B 호스트/SIEM은 groot-siem-host(새 설치 capstone-siem-host), A는 groot-sec(capstone-security), '
                'C는 groot-web(capstone-service)입니다. Wazuh Manager는 별도 wazuh.manager(capstone-wazuh-manager)입니다. '
                '고정 ID나 IP로 추정하지 말고 실제 반환 이름과 ID를 대조하세요. 127.0.0.1도 그 이름의 관측 주소일 뿐입니다. '
                '대상 이름 필터를 추측하지 말고 name/ip/group 필터 없이 상태별 목록을 조회하세요. '
                '지정 상태가 없으면 active에서 시작해 대상이 없을 때 disconnected/pending/never_connected도 확인하세요. '
                '전체 목록은 네 상태 모두 필요합니다. 중복 대상·오류·목록 밖은 미확인으로 남기세요. '
                '목록 개수는 실제 반환 행으로 계산하세요. 요청 대상=' +
                ', '.join(part_label(x) for x in p['subjects']) + '; 지정 상태=' + ', '.join(p['states']) + '.')
    if p['kind'] == 'multi':
        return ('요청한 각 장비를 빠짐없이 식별하고 장비별 모든 조회를 수행하세요. 동일 상태의 에이전트 목록을 반복하지 말고 name 필터 없이 받은 실제 이름→ID 매핑을 재사용하세요. ' + '\n'.join(guidance(part, calls) for part in p['plans']))
    text = ('요청은 읽기 전용입니다. 변경안 제출/재시작 금지는 변경 목표가 아닙니다. '
            '제공된 도구를 실제로 선택해 모든 요청 항목을 확인하세요. 성공한 같은 조회를 반복하지 마세요. ')
    if p['kind'] == 'wazuh':
        text += ('장비 이름과 에이전트 번호는 다릅니다. Groot_A/보안 서버는 groot-sec(새 설치 capstone-security), '
                 'Groot_C/서비스 서버는 groot-web(새 설치 capstone-service), Groot_B/B 호스트는 groot-siem-host(새 설치 capstone-siem-host)입니다. Wazuh Manager/wazuh.manager는 별도 관리 컨테이너입니다. 000의 SCA·프로세스·패키지를 B Ubuntu 호스트 결과로 대신하지 마세요. '
                 '이 이름은 ID가 아닙니다. get_wazuh_agents(status=active)의 실제 반환 이름/ID를 사용하세요. '
                 'name 필터를 추측하거나 빈 필터 결과를 같은 인자로 반복하지 말고 name 없이 조회해 식별하세요. '
                 '프로세스/포트는 수집 인벤토리이며 시작 시각은 수집 시각이 아닙니다. '
                 'remoted/로그수집기 통계는 alert_summary로 대신하지 않습니다. '
                 '취약점 요약은 반환 목록의 심각도를 집계하고 전체 범위/페이지 한계를 밝힙니다. '
                 'CVE/패키지/버전이 미제공이면 미확인, 참조 URL은 검증된 공식 사실이 아닙니다. '
                 '시각 표시는 이미 KST로 변환됩니다. 현재시간만 얻으려고 calculate_time을 반복하지 마세요. ')
        text += '이 항목의 요청 대상=' + part_label(p) + '; 조회 항목=' + ', '.join(p['features']) + '; 요청 최대 개수=' + str(p['limit']) + '. '
        if p.get('search'): text += '프로세스 검색어=' + p['search'] + '; 임의 다른 필터로 바꾸지 마세요. '
        if target_id(p, calls): text += '이번 조회로 식별된 대상 agent_id=' + target_id(p, calls) + '. '
    elif p['kind'] == 'time':
        text += ('calculate_time에 사용자 원본 시각과 비교 기준을 옮기고 반환값을 요청한 표로 보여주세요. '
                 'reference에는 사건 ID나 base/ref라는 이름이 아니라 offset이 포함된 실제 시각 문자열을 넣으세요. ')
    elif p['kind'] == 'operation':
        text += ('서비스 재시작/재로드·임시차단 요청은 get_operation_status(request_id)로 조회하세요. '
                 '룰 파일 제안 상태 도구와 다릅니다. 과거 실행 상태와 현재 서비스/실시간 차단 상태를 구분하세요. '
                 'missing or ambiguous는 조회 실패이며 삭제·만료·미등록·미차단을 확정하지 않습니다. '
                 'WAF/IDS/채팅프록시·임시차단은 A, Wazuh Manager/Dashboard는 B입니다. 조회 실패를 새 변경 요청으로 바꾸지 마세요. ')
    else:
        text += ('제안의 실행 상태와 승인 상태·승인 소모·결과 알림 전달 여부를 구분하세요. '
                 '실행 pending만으로 미승인이라 단정하지 말고 approval_status를 확인하세요. '
                 'approval_status=unavailable은 승인 조회 실패이며 pending과 다릅니다. '
                 '과거 제안 상태와 현재 파일/컨테이너를 따로 조회하세요. before/after는 원본/후보 해시이며 '
                 'recorded_result는 과거 결과입니다. 현재 해시는 get_rule_change_target에서 확인하세요. '
                 '과거 recovery_failed만으로 현재 장애라고 단정하지 마세요. 결과 알림 재전송은 변경 재실행이 아닙니다. ')
    return text


def vulnerability_view(text):
    if text.startswith(AGGREGATE_PREFIX):
        value = json.loads(text[len(AGGREGATE_PREFIX):])
        counts = value['severity_counts']
        if (not isinstance(counts, dict) or any(k not in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN') or type(v) is not int or v < 0 for k, v in counts.items())
                or sum(counts.values()) != value['returned_records']
                or not re.fullmatch('[0-9a-f]{64}', value['source_sha256'])):
            raise ValueError('vulnerability_aggregate_invalid')
        return value
    chunks = records(text, r'CVE:')
    counts = Counter()
    for chunk in chunks:
        severity = re.search(r'\b(CRITICAL|HIGH|MEDIUM|LOW)\b', field(chunk, 'Severity') or '')
        counts[severity[1] if severity else 'UNKNOWN'] += 1
    return {'returned_records': len(chunks), 'severity_counts': dict(counts),
            'scope': '반환된 레코드만 집계. 전체 설치 취약점 수/페이지 완전성 미확인.',
            'samples': [c[:1200] for c in chunks[:5]], 'samples_truncated': any(len(c) > 1200 for c in chunks[:5]),
            'package_version': '현재 MCP 응답에서 미제공이면 미확인',
            'source_sha256': hashlib.sha256(text.encode()).hexdigest(),
            'source_bytes': len(text.encode()),
            'transport_truncated': bool(re.search(r'\[MCP RESULT TRUNCATED - [\d,]+ chars omitted out of [\d,]+ total\]', text))}


def compact_vulnerability(text):
    # Aggregate before the native flood cap. The cap itself remains unchanged.
    if len(text.encode()) > MAX_VULNERABILITY_BYTES or not text.startswith('CVE:'):
        return None
    value = vulnerability_view(text)
    return AGGREGATE_PREFIX + json.dumps(value, ensure_ascii=False)


def cell(value):
    return str(value if value is not None else '미확인').replace('|', '\\|').replace('\n', ' ').replace('<', '&lt;').replace('>', '&gt;')


def table(headers, rows):
    return ['| ' + ' | '.join(headers) + ' |', '| ' + ' | '.join('---' for _ in headers) + ' |'] + [
        '| ' + ' | '.join(cell(v) for v in row) + ' |' for row in rows]


def operation_report(p, calls, evidence):
    pending = missing(p,calls,evidence)
    rows = ['**요약**', '작업 기록을 조회했습니다. 과거 처리 상태와 현재 관측을 구분합니다.' if not pending else
            '작업 상태 조회가 미완료입니다. 실행 성공·만료·차단 해제나 요청 부재로 단정하지 않습니다.', '', '**확인 내역**']
    def stamp(value):
        if type(value) not in (int,float): return '미확인'
        try:return datetime.fromtimestamp(value,evidence.KST).isoformat()
        except (ValueError,OverflowError,OSError):return '미확인'
    for rid in p['ids']:
        rows += ['', '- 요청 ID: `' + rid + '`; 대상: `' + p['target'] + '`']
        d = operation_record(p,calls,rid)
        if not d:
            c = operation_attempt(p,calls,rid);error = unpack(c['result']) if c else None
            rows += ['조회 결과: ' + cell(error.get('error') if isinstance(error,dict) and error.get('error') else '실제 조회 근거 없음 또는 대상/응답 검증 실패'),
                     '등록되지 않음·삭제·만료·다른 서버 제출 중 어느 원인인지 확인되지 않았습니다.']
            continue
        rows += table(['기록 항목','값'], [('처리 상태(현재 상태와 별개)',d.get('status')),('승인 상태',d.get('approval_status')),
                     ('결과 알림 게시 확인',d.get('result_posted')),('실행 결과',d.get('result'))])
        if d.get('approval_status') == 'unavailable':rows += ['승인 조회 실패이며 승인 대기로 단정하지 않습니다.']
        if p['target'] == 'a:incident-ip':
            rows += table(['현재 차단 관측','값'], [('대상 IP',d.get('ip')),('현재 상태',d.get('live_block_state')),
                        ('관측 시각(KST)',stamp(d.get('live_observed_at'))),('확인된 잔여 초',d.get('live_remaining_seconds')),
                        ('소유 차단 만료(KST)',stamp(d.get('live_owned_deadline'))),('과거 워크플로 만료(KST)',stamp(d.get('owned_deadline')))])
            rows += ['owned는 이 요청 소유의 차단, foreign은 다른 소유의 규칙, absent는 이번 nft 집합 조회에서 부재, unavailable은 조회 실패입니다. 과거 기한만으로 현재 차단 여부를 계산하지 않습니다.']
        else:
            rows += ['과거 실행 후 관측 해시: ' + cell(d.get('after_observation_sha256')) + ' (현재 서비스 관측이 아님)']
    current = operation_current(p,calls)
    if current:
        obs=current['observation']
        rows += ['', *table(['현재 서비스','running','health','관측 해시'],[(p['target'],obs.get('running'),obs.get('health'),current.get('base_state_sha256'))]),
                 '현재 서비스 가동은 과거 재시작 요청의 승인·성공 증명이 아닙니다.']
    elif p['target'] != 'a:incident-ip':rows += ['현재 서비스 상태는 별도 확인되지 않았습니다.']
    rows += ['', '**조치 및 다음 단계**', '조회만 수행했습니다. 재시작·차단·새 승인안 제출은 수행하지 않았습니다.']
    return '\n'.join(rows)


def report(p, calls, evidence):
    if p['kind'] == 'operation': return operation_report(p,calls,evidence)
    if p['kind'] == 'agent_identity': return identity_report(p, calls, evidence)
    if p['kind'] == 'multi':
        pending = missing(p, calls, evidence)
        title = '요청한 모든 장비의 조회 항목을 확인했습니다.' if not pending else '일부 장비/항목이 미완료입니다. 전체 확인 완료가 아닙니다.'
        sections = ['**전체 요청 범위**', title]
        for part in p['plans']:
            sections += ['', '**장비: ' + cell(part_label(part)) + '**', report(part, calls, evidence)]
        if pending: sections += ['', '전체 미확인 목록: ' + ', '.join(pending)]
        return '\n'.join(sections)
    pending = missing(p, calls, evidence)
    rows = ['**요약**', '요청한 조회 항목을 확인했습니다.' if not pending else '일부 조회가 미완료입니다. 정상이나 0건으로 판단하지 않았습니다.', '', '**확인 내역**']
    if p['kind'] == 'time':
        if re.search(r'JSON', p['question'], re.I): return None
        if not pending:
            c = next(c for c in reversed(calls) if c.get('name') == 'calculate_time' and successful(c))
            d = unpack(c['result'])
            rows += ['기준 시각: ' + cell(d.get('reference_kst')), '']
            rows += table(['사건', 'KST 시각', '기준 시각까지 분(양수=전)'], [(t.get('id'), t.get('kst'), t.get('minutes_until_reference')) for t in d.get('timestamps', [])])
            rows += ['', *table(['간격', '분', '초'], [(str(t.get('from')) + ' → ' + str(t.get('to')), t.get('minutes'), t.get('seconds')) for t in d.get('differences', [])])]
            rows += ['시간순: ' + ' → '.join(map(str, d.get('chronological_order', []))), '제공된 시각의 계산이며 실시간 서버 관측이 아닙니다.']
    elif p['kind'] == 'status':
        for pid in p['ids']:
            c = matching(p, calls, 'get_rule_change_status', proposal_id=pid)
            if c and 'proposal:' + pid not in pending:
                d = unpack(c['result'])
                if isinstance(d, dict):
                    rows += ['', '**변경 `' + pid + '`의 실행 기록**',
                             *table(['항목', '조회 근거'], [
                                 ('실행 상태(현재 서비스 상태와 별개)', d.get('status')),
                                 ('승인 상태', d.get('approval_status')),
                                 ('승인 상태 근거', d.get('approval_status_source')),
                                 ('일회 승인 소모 여부', d.get('approval_consumed')),
                                 ('결과 알림 전달', d.get('result_delivery', {}).get('status')),
                                 ('원본 SHA-256', d.get('before_sha256')),
                                 ('후보 SHA-256', d.get('after_sha256')),
                                 ('과거 결과 읽기 SHA-256', d.get('recorded_result', {}).get('readback_sha256')),
                                 ('조회 시각(KST)', d.get('observed_at_kst'))]),
                             '실행 결과: ' + cell(d.get('result'))]
                    if d.get('approval_status') == 'unavailable': rows += ['승인 조회 실패입니다. 승인 대기·거부·미승인으로 단정할 수 없습니다.']
                    if d.get('status') in ('pending', 'prepared'): rows += ['실행기의 대기/준비 상태와 승인 결정은 별개입니다.']
                    if d.get('result_delivery', {}).get('status') == 'retry_pending': rows += ['결과 알림 재전송 대기입니다. 변경을 재실행하지 않습니다.']
        c = matching(p, calls, 'get_rule_change_target', target=p['target']) if p['current'] else None
        if c and p['target'] not in pending:
            d = unpack(c['result']);inv = d.get('rule_inventory', {});runtime = d.get('runtime', {})
            rows += ['', *table(['현재 대상', 'SHA-256', '파일 정의 수', '컨테이너 running'], [(p['target'], d.get('sha256'), inv.get('declared_count'), runtime.get('running'))])]
            for pid in p['ids']:
                status_call = matching(p, calls, 'get_rule_change_status', proposal_id=pid)
                if status_call and 'proposal:' + pid not in pending:
                    receipt = unpack(status_call['result'])
                    comparisons = [(label, '일치' if d['sha256'] == receipt[key] else '불일치')
                                   for key, label in [('before_sha256', '원본'), ('after_sha256', '후보')]
                                   if isinstance(receipt.get(key), str) and re.fullmatch(r'[0-9a-f]{64}', receipt[key])]
                    rows += ['변경 `' + pid + '` 대비 현재 파일: ' + ', '.join(label + ' ' + value for label, value in comparisons)]
            rows += ['과거 실패 기록은 그대로 보존됩니다. 현재 파일/컨테이너 관측과 별개입니다. 개별 룰 적재·필수 내부 프로세스의 현재 정상 여부는 이 조회만으로 확정하지 않습니다.']
        elif not p['current']:
            rows += ['현재 파일/서비스는 별도 조회하지 않았습니다. 후보·과거 결과 해시를 현재 해시로 해석하지 않습니다.']
    else:
        agent = target_id(p, calls)
        if p['needs_agent']: rows += ['대상: ' + cell(p.get('agent_name')) + ' / agent_id=' + cell(agent)]
        if p['states']:
            counts = []
            for state in p['states']:
                c = state_call(p, calls, state)
                parsed = agents(text_result(c) or '') if c else []
                valid = valid_wazuh(c, 'get_wazuh_agents')
                counts.append((state, len(parsed) if valid else '미확인', ', '.join(a['id'] for a in parsed) or ('없음' if valid else '미확인')))
            rows += ['', *table(['조회 상태', '반환 개수', '장비 ID'], counts)]
        for state in p['states']:
            c = state_call(p, calls, state)
            raw = text_result(c) if c else None
            if raw is None: continue
            parsed = agents(raw)
            rows += ['', '조회 상태: ' + state + '; 반환 ' + str(len(parsed)) + '행 (manager 000 포함 시 별도 관리 노드).']
            if parsed:
                rows += table(['ID', '이름', '주소', '상태', '마지막 연결 KST'], [(a['id'], a['name'], a['ip'], a['status'],
                    '특수값: 실제 연결 시각 미확인' if (a['last_keepalive'] or '').startswith('9999-') else evidence.kst_time(a['last_keepalive'])) for a in parsed])
            elif valid_wazuh(c, 'get_wazuh_agents'): rows += ['해당 상태 조건에 일치하는 반환 자료가 없습니다. 조회 실패와 구분합니다.']
        if p['states']: rows += ['상태 범위: ' + ', '.join(p['states']) + '. 다른 상태는 별도 확인하지 않았습니다. 목록 limit/페이지 범위 밖은 미확인입니다.']
        for name in p['features']:
            args = feature_args(p, name, agent)
            c = matching(p, calls, name, **args) if agent or not args else None
            raw = text_result(c) if c else None
            if not raw or not valid_wazuh(c, name):
                failed = failed_attempt(p, calls, name, args)
                if failed:
                    reason = unpack(failed['result'])
                    rows += ['', '`' + name + '` 조회 실패/미확인: ' + cell(str(reason)[:400]), '이 오류를 0건이나 정상 상태로 해석하지 않았습니다. 같은 실패 호출을 자동 반복하지 않았습니다.']
                continue
            rows += ['', '`' + name + '` (실제 인자: ' + cell(json.dumps(c['arguments'], ensure_ascii=False)) + ')']
            if ambiguous_empty(p, calls, name, c):
                rows += ['도구는 조건에 맞는 반환 자료가 없다고 응답했습니다: ' + cell(raw), '이 응답만으로 요청 ID의 등록 여부, 자료 미수집, 조회 실패와 실제 0건을 구분할 수 없습니다. 현재 정상이나 장비 부재로 확정하지 않았습니다. 같은 호출을 반복하지 않고 미확인으로 남깁니다.']
                continue
            if name == 'get_wazuh_agent_processes':
                rows += table(['PID', '프로세스', '상태', '실행 시작 KST'], [(field(x, 'PID'), field(x, 'Name'), field(x, 'State'), evidence.kst_time(field(x, 'Start Time'))) for x in records(raw, r'PID:')[:p.get('limit', 5)]])
                if re.search(r'명령줄|command', p['question'], re.I):
                    rows += ['', *table(['PID', '명령줄(미제공이면 미확인)'], [(field(x, 'PID'), field(x, 'Command') or field(x, 'Command Line')) for x in records(raw, r'PID:')[:p.get('limit', 5)]])]
                if not records(raw, r'PID:'): rows += ['해당 조건의 반환 자료 0건입니다. 조회 실패·현재 전체 프로세스 부재와 구분합니다.']
                rows += ['마지막 수집 인벤토리입니다. 수집 시각은 응답에서 미제공/미확인이고 실행 시작 시각과 다릅니다. 실시간 전체 프로세스 목록이 아닙니다.']
            elif name == 'get_wazuh_agent_ports':
                rows += table(['프로토콜', '로컬', '상태', '프로세스', 'PID'], [(field(x, 'Protocol'), field(x, 'Local'), field(x, 'State'), field(x, 'Process Name'), field(x, 'PID')) for x in records(raw, r'Protocol:')[:p.get('limit', 5)]])
                if not records(raw, r'Protocol:'): rows += ['해당 조건의 반환 자료 0건입니다. 조회 실패·현재 전체 포트 부재와 구분합니다.']
                rows += ['마지막 수집 인벤토리이며 수집 시각은 미확인입니다. 필터/limit 밖의 포트와 실시간 노출 여부는 미확인입니다.']
            elif name == 'get_wazuh_vulnerability_summary':
                d = vulnerability_view(raw)
                rows += table(['심각도', '반환 레코드 수'], [(k, d['severity_counts'].get(k, 0)) for k in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')])
                rows += ['반환 합계 ' + str(d['returned_records']) + '건. ' + d['scope'], '집계 원문 SHA-256: `' + d['source_sha256'] + '`.']
                if d.get('transport_truncated'): rows += ['전송 단계에서 원문 일부가 잘렸습니다. 위 수치는 남은 부분만의 집계이며 전체 반환 목록 요약은 미완료입니다.']
            elif name == 'get_wazuh_critical_vulnerabilities':
                chunks = records(raw, r'(?:🔴 )?CRITICAL VULNERABILITY')
                rows += table(['CVE 필드', '참조 URL에 포함된 ID(미검증)', '패키지', '버전'], [(field(x, 'CVE'),
                    ', '.join(dict.fromkeys(re.findall(r'CVE-\d{4}-\d+', field(x, 'Reference') or ''))) or '미제공', field(x, 'Package'), field(x, 'Version')) for x in chunks[:p.get('limit', 5)]])
                rows += ['CVE Unknown은 참조 URL만으로 확정하지 않았습니다. 패키지/버전 미제공은 미확인입니다. 취약점 자료는 실제 침해 발생의 증거가 아닙니다.']
            else:
                # Keep every returned counter, including both collector periods.
                # Period timestamps retain their stated offset; anomalies are explicit.
                lines = [x.strip() for x in raw.splitlines() if x.strip()]
                pairs = []
                for x in lines[:160]:
                    key, value = x.split(': ', 1) if ': ' in x else (x, '')
                    if name == 'get_wazuh_log_collector_stats' and key in ('Start', 'End'):
                        value = '원본 시간대 표기 검증 필요; KST 절대시각 미확인'
                    else:
                        value = evidence.kst_display(value)
                    pairs.append((key, value))
                rows += table(['반환 항목', '값/범위'], pairs)
                if len(lines) > 160: rows += ['표시 한도160행 초과; 나머지 반환 항목은 미표시/미확인입니다.']
                if name == 'get_wazuh_log_collector_stats':
                    rows += ['Global/Interval 카운터 범위는 원문 구분을 유지했습니다. 이 MCP는 수집기의 시간대 없는 현지 시각에 Z를 붙일 수 있어 구간 시각을 확정하지 않았습니다. 원본은 감사 기록에 보존하며 임의 환산하지 않습니다.']
                rows += ['카운터0/자료없음은 전체 공격 부재·전체 수집 정상의 증거가 아닙니다. 누적/구간·파일·대상 범위를 구분합니다.']
    rows += ['', '**조치 및 다음 단계**', '- 읽기/계산 결과이며 변경안 제출·적용·차단·재시작은 수행하지 않았습니다.']
    if pending: rows += ['- 미확인: ' + ', '.join(pending)]
    return '\n'.join(rows)
