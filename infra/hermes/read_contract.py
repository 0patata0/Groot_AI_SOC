"""Shared read requirements and lossless, bounded presentation of MCP facts.

No dispatch, approval, incident decision or network access. The model still
selects every tool and argument. A successful unrelated read never satisfies a
requested device. Legacy Wazuh strings are parsed conservatively, not executed.
"""
from collections import Counter
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
               'wazuh.manager': ('wazuh.manager', 'capstone-wazuh-manager')}


def without_prohibitions(text):
    action = r'(?:(?:추가|새로|다시)\s*조회|조회|(?:(?:변경안|원복안|제안)\s*)?(?:변경|수정|추가|삭제|차단|재시작|원복|복구|작성|준비|제출|적용|배포|설치))'
    join = r'\s*(?:[·,/]|및|또는|이나|와|과)\s*'
    end = r'(?:은|는|을|를|도)?\s*(?:하지\s*(?:말고|마세요|말아(?:줘|주세요)?|마|않고|않는)|없이|금지)'
    text = re.sub(action + '(?:' + join + action + ')*' + end, '', text)
    return re.sub(r'만들지\s*(?:말고|마세요|말아(?:줘|주세요)?|마)', '', text)


def wants_write(text):
    text = without_prohibitions(text)
    return bool(re.search(
        r'(?:변경안|원복안|제안).{0,60}(?:만들|작성|준비|제출)(?:해|하|해줘|해주|해줄|하세요|을|한다|$)'
        r'|(?:추가|삭제|수정|변경|원복|복구|재시작|설치|배포|차단|해제|승인|거부|적용)(?:해|하(?:고|라|세요|는|여|자)|해줘|해주|해줄)', text))


def plan(question, aware_time):
    text = without_prohibitions(question)
    if wants_write(text) or re.search(r'도구\s*없이|조회(?:는|하지)\s*말|설명만|번역|라는\s*문장', text):
        return None
    stamps = aware_time.findall(text)
    if stamps and re.search(r'시간|시각|계산|KST|UTC|timeline', text, re.I):
        return {'kind': 'time', 'stamps': stamps, 'question': question}
    ids = re.findall(r'(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])', text)
    if ids and re.search(r'제안|proposal|변경', text, re.I) and re.search(r'상태|이력|실패|처리', text):
        targets = [t for pattern, t in [('WAF|ModSecurity', 'a:modsecurity-custom'),
            ('IDS|Suricata', 'a:suricata-local'), ('Wazuh|와주', 'b:wazuh-local-rules')]
            if re.search(pattern, text, re.I)]
        if len(targets) == 1:
            return {'kind': 'status', 'ids': list(dict.fromkeys(ids)), 'target': targets[0],
                    'current': bool(re.search(r'현재|지금|최신', text)), 'question': question}
    features = []
    for pattern, name in [(r'프로세스|process', 'get_wazuh_agent_processes'),
                          (r'포트|ports?|LISTENING', 'get_wazuh_agent_ports'),
                          (r'취약점|vulnerabil', 'get_wazuh_vulnerability_summary'),
                          (r'Critical|치명적|심각한', 'get_wazuh_critical_vulnerabilities'),
                          (r'remoted|수신\s*통계', 'get_wazuh_remoted_stats'),
                          (r'로그\s*수집기?\s*통계|log.?collector', 'get_wazuh_log_collector_stats')]:
        if re.search(pattern, text, re.I):
            features.append(name)
    states = [s for s in STATES if re.search(r'(?<![a-z_])' + s + r'(?![a-z_])', text, re.I)]
    if not features and not (re.search(r'Wazuh|와주|에이전트|agent', text, re.I) and states):
        return None
    if not re.search(r'조회|보여|확인|정리|상태|목록|통계|요약', text):
        return None
    explicit = re.search(r'(?:agent[_ ]?id|에이전트\s*(?:ID)?|ID)\s*[:=]?\s*[\x60\'\"]?(\d{3})\b', text, re.I)
    alias = next((name for pattern, name in [(r'Groot[_ ]?C|groot-web|capstone-service|서비스\s*서버', 'groot-web'),
        (r'Groot[_ ]?A|groot-sec|capstone-security', 'groot-sec'), (r'Groot[_ ]?B|wazuh\.manager|capstone-wazuh-manager', 'wazuh.manager')]
        if re.search(pattern, text, re.I)), None)
    dependent = any(n not in ('get_wazuh_remoted_stats',) for n in features)
    return {'kind': 'wazuh', 'features': features, 'states': states or ([] if features else ['active']),
            'agent_id': explicit[1] if explicit else None, 'agent_name': alias,
            'needs_agent': dependent, 'question': question}


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
    if p.get('agent_id'):
        return p['agent_id']
    matches = set()
    for c in calls:
        if c.get('server') == 'wazuh-ro' and c.get('name') == 'get_wazuh_agents':
            for a in agents(text_result(c) or ''):
                if a['name'] in ASSET_NAMES.get(p.get('agent_name'), ()):
                    matches.add(a['id'])
    return next(iter(matches)) if len(matches) == 1 else None


def scope(p, calls=None):
    if p['kind'] == 'time': return {TIME}
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
    return found[-1] if found else None


def valid_wazuh(call, name):
    raw = text_result(call) if call else None
    if raw is None: return False
    markers = {'get_wazuh_agents': r'Agent ID:|No Wazuh agents matching',
        'get_wazuh_agent_processes': r'PID:|No processes found',
        'get_wazuh_agent_ports': r'Protocol:|No ports found',
        'get_wazuh_vulnerability_summary': r'CVE:|No vulnerabilit|^SOC_VULNERABILITY_AGGREGATE_V1',
        'get_wazuh_critical_vulnerabilities': r'CRITICAL VULNERABILITY|No critical vulnerabilit',
        'get_wazuh_remoted_stats': r'Wazuh Remoted Statistics:',
        'get_wazuh_log_collector_stats': r'Log Collector Stats for Agent:'}
    return bool(re.search(markers[name], raw, re.I))


def missing(p, calls, evidence):
    if p['kind'] == 'time':
        for c in reversed(calls):
            if c.get('name') != 'calculate_time' or c.get('server') != 'system-diagnostics' or not successful(c): continue
            data = unpack(c['result']);args = c.get('arguments', {})
            supplied = [x.get('value') for x in args.get('timestamps', []) if isinstance(x, dict)] + [args.get('reference')]
            expected = {evidence.parse_instant(s) for s in p['stamps']}
            actual = {evidence.parse_instant(s) for s in supplied}
            if (None not in expected and expected <= actual and isinstance(data, dict)
                    and data.get('kind') == 'time_calculation' and data.get('source_scope') == 'supplied_timestamps_only'):
                return []
        return ['calculate_time: 사용자 제공 시각/기준 시각']
    if p['kind'] == 'status':
        pending = []
        for pid in p['ids']:
            c = matching(p, calls, 'get_rule_change_status', proposal_id=pid)
            data = unpack(c['result']) if c else None
            if not isinstance(data, dict) or data.get('proposal_id') != pid or not data.get('status') or data.get('error'):
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
        if not valid_wazuh(matching(p, calls, 'get_wazuh_agents', status=state), 'get_wazuh_agents'):
            pending.append('get_wazuh_agents:' + state)
    agent = target_id(p, calls)
    if p['needs_agent'] and not agent:
        pending.append('get_wazuh_agents: 대상 이름/ID 실제 식별')
    for name in p['features']:
        args = {} if name == 'get_wazuh_remoted_stats' else {'agent_id': agent}
        if name == 'get_wazuh_agent_ports' and re.search(r'TCP|LISTENING', p['question'], re.I):
            args.update(protocol='tcp', state='LISTENING')
        c = matching(p, calls, name, **args) if agent or not args else None
        if not valid_wazuh(c, name) or name == 'get_wazuh_vulnerability_summary' and vulnerability_view(text_result(c) or '').get('transport_truncated'):
            pending.append(name + (':' + (agent or '대상 미확인') if args else ''))
    return pending


def guidance(p, calls=()):
    text = ('요청은 읽기 전용입니다. 변경안 제출/재시작 금지는 변경 목표가 아닙니다. '
            '제공된 도구를 실제로 선택해 모든 요청 항목을 확인하세요. 성공한 같은 조회를 반복하지 마세요. ')
    if p['kind'] == 'wazuh':
        text += ('장비 이름과 에이전트 번호는 다릅니다. Groot_C는 서비스 호스트 groot-web이라는 이름으로 '
                 '(새 설치는 capstone-service) get_wazuh_agents(status=active) 결과에서 ID를 확인하세요. c/003 같은 추측 ID를 쓰지 마세요. '
                 '프로세스/포트는 수집 인벤토리이며 시작 시각은 수집 시각이 아닙니다. '
                 'remoted/로그수집기 통계는 alert_summary로 대신하지 않습니다. '
                 '취약점 요약은 반환 목록의 심각도를 집계하고 전체 범위/페이지 한계를 밝힙니다. '
                 'CVE/패키지/버전이 미제공이면 미확인, 참조 URL은 검증된 공식 사실이 아닙니다. '
                 '시각 표시는 이미 KST로 변환됩니다. 현재시간만 얻으려고 calculate_time을 반복하지 마세요. ')
        if target_id(p, calls): text += '이번 조회로 식별된 대상 agent_id=' + target_id(p, calls) + '. '
    elif p['kind'] == 'time':
        text += 'calculate_time에 사용자 원본 시각과 비교 기준을 옮기고 반환값을 요청한 표로 보여주세요. '
    else:
        text += '과거 제안 상태와 현재 파일/컨테이너를 따로 조회하세요. 과거 recovery_failed만으로 현재 장애라고 단정하지 마세요. '
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


def report(p, calls, evidence):
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
            if c:
                d = unpack(c['result'])
                if isinstance(d, dict): rows += ['- 과거 제안 `' + pid + '`: ' + cell(d.get('status')) + '; ' + cell(d.get('result'))]
        c = matching(p, calls, 'get_rule_change_target', target=p['target']) if p['current'] else None
        if c and p['target'] not in pending:
            d = unpack(c['result']);inv = d.get('rule_inventory', {});runtime = d.get('runtime', {})
            rows += ['', *table(['현재 대상', 'SHA-256', '파일 정의 수', '컨테이너 running'], [(p['target'], d.get('sha256'), inv.get('declared_count'), runtime.get('running'))])]
            rows += ['과거 실패 기록은 그대로 보존됩니다. 현재 파일/컨테이너 관측과 별개입니다. 개별 룰 적재·필수 내부 프로세스의 현재 정상 여부는 이 조회만으로 확정하지 않습니다.']
    else:
        agent = target_id(p, calls)
        if p['needs_agent']: rows += ['대상: ' + cell(p.get('agent_name')) + ' / agent_id=' + cell(agent)]
        for state in p['states']:
            c = matching(p, calls, 'get_wazuh_agents', status=state)
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
            args = {} if name == 'get_wazuh_remoted_stats' else {'agent_id': agent}
            c = matching(p, calls, name, **args) if agent or not args else None
            raw = text_result(c) if c else None
            if not raw or not valid_wazuh(c, name): continue
            rows += ['', '`' + name + '` (실제 인자: ' + cell(json.dumps(c['arguments'], ensure_ascii=False)) + ')']
            if name == 'get_wazuh_agent_processes':
                rows += table(['PID', '프로세스', '상태', '실행 시작 KST'], [(field(x, 'PID'), field(x, 'Name'), field(x, 'State'), evidence.kst_time(field(x, 'Start Time'))) for x in records(raw, r'PID:')[:5]])
                rows += ['마지막 수집 인벤토리입니다. 수집 시각은 응답에서 미제공/미확인이고 실행 시작 시각과 다릅니다. 실시간 전체 프로세스 목록이 아닙니다.']
            elif name == 'get_wazuh_agent_ports':
                rows += table(['프로토콜', '로컬', '상태', '프로세스', 'PID'], [(field(x, 'Protocol'), field(x, 'Local'), field(x, 'State'), field(x, 'Process Name'), field(x, 'PID')) for x in records(raw, r'Protocol:')[:5]])
                rows += ['마지막 수집 인벤토리이며 수집 시각은 미확인입니다. 필터/limit 밖의 포트와 실시간 노출 여부는 미확인입니다.']
            elif name == 'get_wazuh_vulnerability_summary':
                d = vulnerability_view(raw)
                rows += table(['심각도', '반환 레코드 수'], [(k, d['severity_counts'].get(k, 0)) for k in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')])
                rows += ['반환 합계 ' + str(d['returned_records']) + '건. ' + d['scope'], '집계 원문 SHA-256: `' + d['source_sha256'] + '`.']
                if d.get('transport_truncated'): rows += ['전송 단계에서 원문 일부가 잘렸습니다. 위 수치는 남은 부분만의 집계이며 전체 반환 목록 요약은 미완료입니다.']
            elif name == 'get_wazuh_critical_vulnerabilities':
                chunks = records(raw, r'(?:🔴 )?CRITICAL VULNERABILITY')
                rows += table(['CVE 필드', '참조 URL에 포함된 ID(미검증)', '패키지', '버전'], [(field(x, 'CVE'),
                    ', '.join(dict.fromkeys(re.findall(r'CVE-\d{4}-\d+', field(x, 'Reference') or ''))) or '미제공', field(x, 'Package'), field(x, 'Version')) for x in chunks[:5]])
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
