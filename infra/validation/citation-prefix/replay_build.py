"""Rebuild the 11-12 21:52 investigation session requests in three shapes (local only).

Inputs are local-only evidence files (session dump, MCP schema list) under
대화기록/검증/2026-11-13-latency/; nothing here contacts a server. A = current
(system suffix), B = in-process notes (candidate), C = persisted notes.
"""
import json, sys, os, copy, hashlib
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
root = os.environ.get('CAPSTONE_REPO', os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
sys.path.insert(0, root + '/infra/hermes')
os.environ['CAPSTONE_MANAGEMENT_MODE'] = 'verify'
import soc_management_run as R
ev = root + '/대화기록/검증/2026-11-13-latency/'
S = json.load(open(ev + 'session_5a43b3.json'))
schemas = json.load(open(ev + 'mcp-schemas-live.json'))
tools = [{'type': 'function', 'function': {'name': 'mcp__%s__%s' % (t['server'].replace('-', '_'), t['name']),
          'description': t['description'] or '', 'parameters': t['inputSchema']}} for t in schemas if 'name' in t]
for t in tools:
    t['function']['parameters'].setdefault('properties', {})
tools = R.permitted_tools(tools, 'verify')
system = S['system_prompt_row']['prompt']
def conv(m):
    if m['role'] == 'assistant':
        row = {'role': 'assistant', 'content': m['content'] or ''}
        if m['tool_calls']:
            row['tool_calls'] = [{'id': c['id'], 'type': 'function', 'function': {'name': c['function']['name'], 'arguments': c['function']['arguments']}} for c in json.loads(m['tool_calls'])]
        return row
    if m['role'] == 'tool':
        return {'role': 'tool', 'tool_call_id': m['tool_call_id'], 'content': m['content']}
    return {'role': m['role'], 'content': m['content']}
M = {m['id']: conv(m) for m in S['messages']}
def note(names):
    # The text the current runner appended to the system message ('\n' + hint).
    if hasattr(R, 'citation_note_text'):
        return '\n' + R.citation_note_text(set(names))
    req = {'messages': [{'role': 'system', 'content': system}]}
    out = R.completed_citation_request(req, set(names))
    return out['messages'][0]['content'][len(system):]
REPORT = {'role': 'user', 'content': '필수 조회 이후의 읽기 전용 조사 단계입니다. 추가 근거가 필요하면 등록된 calls를 직접 선택하고 report=null로 답하세요. 보고할 때는 calls=[]와 report를 작성하세요. 출력은 지정 JSON만 사용하세요.\n' + json.dumps({'type': 'object', 'required': ['request_nonce', 'calls', 'report'], 'properties': {'request_nonce': {'const': 'x'}, 'calls': {'type': 'array'}, 'report': {'type': ['object', 'null']}}}, ensure_ascii=False)}
ids = sorted(M)
upto = lambda last: [M[i] for i in ids if i <= last]
# Real session order (11/12 21:52-22:02). run = controller process; successful reads reset per process.
OP, SUM, BLK = 'mcp__rule_a__get_operation_status', 'mcp__wazuh_ro__get_wazuh_alert_summary', 'mcp__resp__list_blocks'
steps = [('run1_main', 1, 10463, [OP]), ('run1_next', 1, 10466, [OP, SUM, BLK]),
         ('run2_main', 2, 10470, [OP]), ('run2_next', 2, 10472, [OP, BLK])]
seqs = {'A_current': [], 'B_inprocess_notes': [], 'C_persisted_notes': []}
created = []  # (run, after_id, text)
for name, run, last, reads in steps:
    n = note(reads).strip()
    if not created or created[-1][2] != n or created[-1][0] != run:
        created.append((run, last, n))
    seqs['A_current'].append({'step': name, 'messages': [{'role': 'system', 'content': system + note(reads)}] + upto(last), 'tools': tools})
    for key, keep in (('B_inprocess_notes', lambda r: r == run), ('C_persisted_notes', lambda r: True)):
        body = []
        for i in ids:
            if i > last: break
            body.append(M[i])
            body += [{'role': 'user', 'content': t} for (r, after, t) in created if after == i and keep(r)]
        seqs[key].append({'step': name, 'messages': [{'role': 'system', 'content': system}] + body, 'tools': tools})
current, candidate = seqs['A_current'], seqs['C_persisted_notes']
foreign = {'step': 'foreign_selection_like', 'messages': [{'role': 'system', 'content': 'SOC 추가 읽기 선택 단계다. 등록된 calls와 정확한 인자로 선택한다.'}, {'role': 'user', 'content': M[10468]['content'][:6000]}], 'tools': None}
out = {'tools_count': len(tools), 'tools_sha256': hashlib.sha256(json.dumps(tools, ensure_ascii=False).encode()).hexdigest(),
       'system_chars': len(system), 'note_example': note([OP]), 'seqs': seqs, 'foreign': foreign}
json.dump(out, open(ev + 'replay-payloads.json', 'w'), ensure_ascii=False)
os.chmod(ev + 'replay-payloads.json', 0o600)
print(out['tools_count'], out['system_chars'], repr(out['note_example'][:200]))
for k, v in seqs.items():
    print(k, [(x['step'], len(x['messages']), len(json.dumps(x['messages'], ensure_ascii=False))) for x in v])
