"""Local MCP curriculum from real read receipts and isolated executor evidence.

No production mutation, model call, external approval, or chat post occurs here.
The isolated backend really writes temporary files, but its broker and device
runner are mocks. This distinction stays in every affected training example.
"""
import argparse
import copy
from datetime import datetime, timezone
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path
from unittest import mock

from audit_tools import audit_rows
from capture_training_mcp import validate_capture
from prepare_operator_sources import SYSTEM, canonical, sha, dump

ROOT = Path(__file__).resolve().parent
MCP = ROOT.parent/'infra/mcp'
if not MCP.is_dir():
    MCP = ROOT/'contract_sources'


def tool(catalog, name):
    row = next(x for x in catalog['tools'] if x['name'] == name)
    return {'type': 'function', 'function': {k: copy.deepcopy(row[k]) for k in ('name', 'description', 'parameters')}}


def call(messages, name, arguments, result, content=''):
    call_id = 'call_'+str(len(messages))
    messages.append({'role': 'assistant', 'content': content, 'tool_calls': [
        {'id': call_id, 'type': 'function', 'function': {'name': name, 'arguments': arguments}}]})
    messages.append({'role': 'tool', 'name': name, 'tool_call_id': call_id,
                     'content': result if isinstance(result, str) else canonical(result)})


def live_answer(read):
    data = json.loads(read['result'])
    target = read['arguments'].get('target', 'a:firewall')
    stamp = data.get('observed_at_kst', read['at_kst'])
    if read['name'] == 'get_security_rules':
        c = data['counts']
        lines = [f"{stamp} 조회 기준 {target}의 규칙 정의 {c['definitions']}개 중 설정상 선택 {c['configured']}개입니다.",
                 '| 기본 정의 | 커스텀 정의 | 설정 제외 |', '|---|---|---|',
                 f"| {c['builtin']} | {c['custom']} | {c['excluded']} |"]
        if read['arguments'].get('correlation_only'):
            lines.append(f"상관 조건에 해당하는 정의는 {data['matched_count']}개입니다. 전체 인벤토리에서 의존 규칙 {c['dependency_rules']}개와 시간 상관 규칙 {c['temporal_correlation']}개를 구분합니다.")
        if read['arguments']['view'] == 'details':
            lines += ['| ID | 구분 | 설정 선택 |', '|---|---|---|']
            lines += [f"| {r['id']} | {r['origin']} | {r['configuration']} |" for r in data['rules']]
        lines.append(f"반환된 목록은 {data['returned_count']}/{data['matched_count']}개이며 다음 offset은 {data['next_offset']}입니다. 전체 개별 목록 확인은 같은 snapshot으로 이어서 조회해야 합니다.")
        verified=data.get('runtime_load_verified')
        state='true' if verified is True else 'false' if verified is False else '미확인'
        lines.append('설정 선택은 개별 룰의 실제 엔진 적재·탐지 증명과 다릅니다. 현재 결과의 runtime_load_verified는 '+state+'입니다.')
        if data['duplicate_rule_ids']:
            lines.append('중복 ID 정의가 보고됐습니다: '+', '.join(x['id'] for x in data['duplicate_rule_ids'])+'. 정의 개수를 고유 ID 수로 바꾸어 말하지 않습니다.')
        return '\n'.join(lines)
    if read['name'] == 'get_firewall_rules':
        return (f"{stamp} A 호스트 nftables 전체 범위를 조회했습니다. 확보 목록은 {len(data['objects'])}/{data['total_objects']} 객체이고 "
                f"다음 offset은 {data['next_offset']}입니다. 객체에는 테이블·체인·집합·규칙이 포함되므로 객체 수를 룰 수로 표현하지 않습니다.\n"
                '집계: '+canonical(data['counts'])+'\n전체 개별 목록이 필요하면 반환된 snapshot으로 다음 페이지를 조회합니다. 다른 네트워크 네임스페이스와 legacy 범위는 이 결과의 제외 범위를 따릅니다.')
    if read['name'] == 'get_rule_change_target':
        return (f"{stamp} {target}의 현재 커스텀 파일을 조회했습니다. SHA256은 `{data['sha256']}`입니다.\n"
                '읽은 파일 인벤토리: '+canonical(data['rule_inventory'])+'\n이 파일은 해당 장비의 전체 기본 룰 목록이 아닙니다. '
                '수정 시 읽은 원본 해시와 실제 원문을 기준으로 최소 편집안을 작성하고 정확한 후보 승인을 요청합니다. 이번에는 변경하지 않았습니다.')
    if target.endswith(':systemd'):
        m = data['metrics']
        result = f"{stamp} 현재 loaded failed unit은 {m['failed_units_total']}개입니다."
        if m['failed_units_total']:
            result += '\n확인된 unit: '+', '.join(str(v) for k, v in m.items() if k.startswith('failed_unit_'))+'.'
            result += '\n이 결과만으로 종료 원인은 확정할 수 없습니다. 해당 unit의 경보 이력과 등록된 진단 범위를 대조해 영향과 후속 조치안을 확인합니다.'
        return result+'\n현재 스냅샷이며 과거 journal 조회가 아닙니다. failed 0도 모든 서비스가 정상이라는 증거는 아닙니다.'
    if target == 'a:suricata':
        m = data['metrics']
        return (f"{stamp} IDS running={m['running']}, rules_loaded={m['rules_loaded']}, rules_failed={m['rules_failed']}입니다. "
                f"엔진 시작 이후 kernel_drops={m['kernel_drops']}, tcp_stream_depth_reached={m['tcp_stream_depth_reached']}가 관측됐습니다.\n"
                '누적 카운터이므로 현재 공격이나 현재의 지속 손실을 단정하지 않습니다. 다음 관측과의 증가량, 수집 지연·검사 한도 및 관련 경보를 대조해 관제 누락 여부를 조사합니다. 개별 SID 탐지는 이 자료로 검증되지 않았습니다.')
    if target == 'a:waf':
        return f"{stamp} WAF 컨테이너는 running={data['metrics']['running']}, health={data['metrics']['docker_health']}입니다. 컨테이너 상태만으로 웹 요청부터 탐지·대응까지 전체 경로가 정상임을 보장하지 않습니다."
    if target == 'a:vector':
        return (f"{stamp} 수집된 Vector 진단 상태는 {data['status']}입니다.\n"
                '서비스 속성: '+canonical(data['properties'])+'\n'
                f"반환 오류 {data['returned_error_count']}개, 요청 구간 전체 오류 수는 {data['requested_window_total_count']}입니다. "
                '반환 표본과 전체 오류 수를 구분하며 수집 범위 밖의 과거 오류까지 없었다고 판단하지 않습니다. 커버리지: '+canonical(data['coverage']))
    raise ValueError('No reviewed answer for captured read')


def live_examples(capture, catalog):
    validate_capture(capture)
    result = []
    for index, read in enumerate(capture['reads']):
        target = read['arguments'].get('target', 'a:firewall')
        if read['name'] == 'get_security_rules':
            label = {'a:waf': 'WAF', 'a:suricata': 'IDS', 'b:wazuh': 'Wazuh'}[target]
            question = label+(' 상관 규칙 현황은?' if read['arguments'].get('correlation_only') else ' 규칙 현황 알려줘')
            if read['arguments']['view'] == 'details':question += ' 앞쪽 3개를 개별 표로 보여줘.'
        elif read['name'] == 'get_rule_change_target':
            question = target+' 수정 전에 현재 커스텀 파일 확인해줘.'
        elif read['name'] == 'get_firewall_rules':
            question = '지금 FW 규칙 현황은?'
        else:
            question = target.replace(':', ' ')+' 상태 봐줘.'
        messages = [{'role': 'system', 'content': SYSTEM+' 이 대화는 '+read['at_kst']+' 당시 실제 읽기의 재현입니다. 이후 현재 상태를 이 값으로 암기하지 마세요.'},
                    {'role': 'user', 'content': question}]
        call(messages, read['alias'], read['arguments'], read['result'])
        messages.append({'role': 'assistant', 'content': live_answer(read)})
        names = {read['alias']}
        if read['name'] in ('get_security_rules', 'get_firewall_rules'):
            names.update(('mcp__rule_a__get_security_rules', 'mcp__rule_b__get_security_rules', 'mcp__resp__get_firewall_rules'))
        else:
            names.add('mcp__system_diagnostics__get_system_diagnostics')
        result.append({'id': 'operator-live-'+str(index), 'source': 'project_live_mcp',
                       'messages': messages, 'tools': [tool(catalog, name) for name in sorted(names)],
                       'provenance': {'kind': 'actual_read_with_project_authored_response', 'captured_at_kst': read['at_kst'],
                                      'result_sha256': read['sha256'], 'protected_calls': 0,
                                      'whole_result_preserved': True, 'production_write_performed': False}})
    return result


def isolated_examples(catalog):
    fixtures = SourceFileLoader('operator_rule_fixtures', str(MCP/'test_rule_change_executor.py')).load_module()
    server = SourceFileLoader('operator_rule_mcp', str(MCP/'rule_change_mcp.py')).load_module()
    executor = fixtures.MOD
    proofs = []
    examples = []
    code_hashes = {name: sha((MCP/name).read_bytes()) for name in ('rule_change_executor.py','rule_change_mcp.py','test_rule_change_executor.py')}
    for kind in ('waf', 'suricata', 'wazuh'):
        for scenario in ('pending','applied','denied','expired','binding_mismatch','rolled_back','recovery_failed'):
            harness = fixtures.ExecutorTests()
            harness.setUp()
            try:
                engine, runner, target, original = harness.engine(kind)
                host = target[0]
                read_prefix, write_prefix = 'mcp__rule_'+host+'__', 'mcp__rule_write_'+host+'__'
                events = []

                def helper(payload, readonly=False):
                    args = {k: v for k, v in payload.items() if k != 'operation'}
                    try:
                        if payload['operation'] == 'get':
                            data = engine.get_target(args['target'])
                            data = server.with_time_display(data, datetime.fromtimestamp(engine.clock(), timezone.utc))
                        elif payload['operation'] == 'propose-edit':data = engine.propose_edit(**args)
                        elif payload['operation'] == 'status':data = engine.status(args['proposal_id'])
                        else:raise AssertionError('Unreviewed local operation')
                        return server._result(data, False)
                    except executor.RuleChangeError as exc:
                        return server._result({'error': str(exc)}, True)

                def dispatch(name, args, access):
                    with mock.patch.object(server, '_call_helper', side_effect=helper):
                        result = server.handle({'jsonrpc':'2.0','id':1,'method':'tools/call',
                                                'params':{'name':name,'arguments':args}}, access, host)['result']
                    text = '\n'.join(x['text'] for x in result['content'] if x['type']=='text')
                    if result.get('isError'):raise ValueError('Isolated tool failed: '+name)
                    events.append({'name': name, 'arguments': args, 'result_sha256': sha(text.encode()), 'result': text})
                    return text, json.loads(text)

                before_text, before = dispatch('get_rule_change_target', {'target': target}, 'read')
                arguments = {'target':target,'base_sha256':before['sha256'],
                             'edits':[{'old_text':'old','new_text':'reviewed_marker_r5'}],
                             'reason':'격리 시험의 문구 변경 검토'}
                proposed_text, proposal = dispatch('propose_rule_edit', arguments, 'write')
                rid = proposal['proposal_id']
                assert Path(engine.targets[target]['path']).read_bytes() == original
                assert harness.broker.consumes == 0
                common = SYSTEM+' 이 대화는 로컬 격리 계약시험입니다. 실제 executor와 임시 파일을 쓰지만 승인 broker와 보안장비 응답은 모의 객체입니다. 실서버 적용·채팅 게시가 아닙니다.'
                if scenario == 'pending':
                    messages = [{'role':'system','content':common},{'role':'user','content':f'{target}에서 old를 reviewed_marker_r5로 바꾸는 변경안을 준비해.'}]
                    call(messages,read_prefix+'get_rule_change_target',{'target':target},before_text)
                    call(messages,write_prefix+'propose_rule_edit',arguments,proposed_text,
                         '읽은 원문과 해시에 맞는 최소 편집안을 준비하고 정확한 후보 승인을 요청합니다.')
                    messages.append({'role':'assistant','content':f"격리 시험 변경안 {rid}을 제출했습니다. 후보 SHA256 `{proposal['after_sha256']}`의 승인 대기이며 아직 적용하지 않았습니다. 승인 후 실행 상태와 현재 파일을 재조회해 확인합니다."})
                    examples.append({'id':'operator-proposal-'+kind,'source':'project_isolated_executor','messages':messages,
                                     'tools':[tool(catalog,read_prefix+'get_rule_change_target'),tool(catalog,write_prefix+'propose_rule_edit')],
                                     'provenance':{'kind':'actual_local_executor_with_mock_broker_and_device','scenario':'proposal_pending','code_sha256':code_hashes}})
                # An external fixture changes broker state. The model has no approval-granting tool.
                if scenario in ('applied','rolled_back','recovery_failed','binding_mismatch'):
                    harness.broker.rows[rid]['status'] = 'approved'
                elif scenario in ('denied','expired'):
                    harness.broker.rows[rid]['status'] = scenario
                if scenario == 'binding_mismatch':
                    harness.broker.rows[rid]['candidate_sha256'] = 'f'*64
                if scenario in ('rolled_back','recovery_failed'):
                    previous_call = runner.call
                    failures = [0]
                    def failing_service(argv, timeout=30):
                        transition = (argv[1]=='restart' or ('nginx' in argv and 'reload' in argv))
                        if transition and (scenario=='recovery_failed' or failures[0]==0):
                            failures[0] += 1
                            raise executor.RuleChangeError('isolated device transition failed')
                        return previous_call(argv,timeout)
                    runner.call = failing_service
                engine.worker_once()
                status_text, status = dispatch('get_rule_change_status', {'proposal_id':rid}, 'read')
                after_text, after = dispatch('get_rule_change_target', {'target':target}, 'read')
                expected = 'pending' if scenario=='binding_mismatch' else scenario
                if status['status'] != expected:
                    raise ValueError('Unexpected actual executor outcome: '+kind+'/'+scenario+'/'+status['status'])
                file_digest = sha(Path(engine.targets[target]['path']).read_bytes())
                assert after['sha256'] == file_digest
                assert file_digest == (proposal['after_sha256'] if scenario=='applied' else proposal['before_sha256'])
                expected_consumes = int(scenario in ('applied','rolled_back','recovery_failed'))
                assert harness.broker.consumes == expected_consumes
                messages = [{'role':'system','content':common}, {'role':'user','content':
                    f"변경안 {rid} 지금 어떻게 됐어? 대상 {target}, 원본 SHA {proposal['before_sha256']}, 후보 SHA {proposal['after_sha256']}였어."}]
                call(messages,read_prefix+'get_rule_change_status',{'proposal_id':rid},status_text)
                call(messages,read_prefix+'get_rule_change_target',{'target':target},after_text,
                     '실행 기록의 후보 해시는 현재 파일 해시가 아니므로 현재 대상을 다시 조회합니다.')
                explanation = {
                    'pending':'승인 대기이며 적용되지 않았습니다. 같은 후보를 중복 제출하지 않고 정확한 후보 승인을 기다립니다.',
                    'applied':'승인이 소비된 적용 기록과 현재 파일의 후보 SHA 일치를 확인했습니다.',
                    'denied':'승인이 거부되어 적용되지 않았습니다. 거부 결정을 우회하거나 자동 재제출하지 않습니다.',
                    'expired':'승인이 만료되어 적용되지 않았습니다. 여전히 변경이 필요하면 현재 상태로 새 변경안을 준비하고 정확한 후보 승인을 요청합니다.',
                    'binding_mismatch':'승인 대상 해시의 연결 검증이 실패해 적용되지 않았습니다. 이전 승인을 다른 후보에 사용할 수 없습니다. 승인 연결 오류를 확인하고 현재 원본·후보를 다시 대조해 유효한 승인안을 준비합니다.',
                    'rolled_back':'적용이 실패해 원복됐고 현재 파일도 원본 SHA와 일치합니다. 변경 성공으로 보고하지 않으며 실패 원인을 조사해 수정안을 준비합니다.',
                    'recovery_failed':'적용과 복구의 장비 전환 검증이 실패했습니다. 현재 파일이 원본 SHA와 같아도 서비스 복구 성공으로 볼 수 없습니다. 복구 실패 상태로 보고하고 서비스 진단과 승인된 복구 조치를 우선합니다.'}[scenario]
                messages.append({'role':'assistant','content':f"격리 시험 결과: {explanation}\n상태 `{status['status']}`, 현재 SHA256 `{after['sha256']}`. 실제 운영 장비에 적용하거나 채팅을 게시한 것은 아닙니다."})
                proof = {'kind':'actual_local_executor_with_mock_broker_and_device','scenario':scenario,
                         'actual_status':status['status'],'approval_consumes':harness.broker.consumes,
                         'current_file_sha256':file_digest,'code_sha256':code_hashes,
                         'external_approval_fixture':True,'production_write_performed':False,
                         'device_engine_test_executed':False,'actual_temporary_file_write':expected_consumes>0}
                examples.append({'id':'operator-outcome-'+kind+'-'+scenario,'source':'project_isolated_executor',
                                 'messages':messages,'tools':[tool(catalog,read_prefix+'get_rule_change_status'),tool(catalog,read_prefix+'get_rule_change_target')],
                                 'provenance':proof})
                proofs.append({'id':examples[-1]['id'],**proof,'events':events})
            finally:
                harness.tearDown()
    return examples, proofs


def build(output):
    output = Path(output)
    if output.exists() or not output.name.startswith('data-'):
        raise ValueError('Use a new ignored data-* directory')
    catalog = json.loads((ROOT/'mcp_contract.20261101.json').read_text())
    path = ROOT/'data-soc-ready-20261101-r4/live-mcp-capture.json'
    if sha(path.read_bytes()) != catalog['capture_sha256']:
        raise ValueError('Original live capture changed')
    live = live_examples(json.loads(path.read_text()),catalog)
    controlled, proofs = isolated_examples(catalog)
    candidates = live+controlled
    audit = audit_rows(candidates,catalog)
    if audit['counts']['schema_valid_calls'] != audit['counts']['calls']:
        raise ValueError('Generated trajectory does not match current MCP schemas')
    output.mkdir()
    dump(output/'candidates.jsonl',candidates)
    dump(output/'execution-evidence.jsonl',proofs)
    report = {'status':'locally_executed_waiting_token_and_review','live_read_dialogues':len(live),
              'isolated_contract_dialogues':len(controlled),'isolated_outcome_executions':len(proofs),
              'schema_audit':audit,'source_catalog_sha256':sha((ROOT/'mcp_contract.20261101.json').read_bytes()),
              'actual_production_mutations':0,'chat_posts':0,'model_calls':0,'cleansing_location':'local',
              'ready_for_gpu_training':False,'training_admitted':False,
              'files':{p.name:sha(p.read_bytes())for p in output.iterdir()if p.is_file()}}
    (output/'composition.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(build(args.output),ensure_ascii=False,indent=2))
