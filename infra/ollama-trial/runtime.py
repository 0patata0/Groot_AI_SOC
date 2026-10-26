#!/usr/bin/env python3
"""Bounded SOC MCPAgent using remote Ollama; root configuration controls access.

JSON request on stdin; JSON result on stdout. Installed root-owned, run as the
dedicated unprivileged user. The benchmark may select a subset of read tools.
"""
import argparse
import contextlib
import asyncio
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from datetime import datetime, timezone, timedelta

# Set before importing third-party modules; no cloud tracing or telemetry.
os.environ.update(MCP_USE_ANONYMIZED_TELEMETRY='false', DO_NOT_TRACK='1',
                  SCARF_NO_ANALYTICS='true', LANGSMITH_TRACING='false',
                  LANGCHAIN_TRACING_V2='false', MCP_USE_DEBUG='0',
                  PYTHONDONTWRITEBYTECODE='1', TZ='Asia/Seoul')
sys.path.insert(0, str(Path(__file__).resolve().parent))
from policy import PROFILES, Budget, alias, capabilities, filter_catalog, protected, require, validate_call, validate_endpoint, validate_model
import harness
SYSTEM_PROMPT = harness.SYSTEM_PROMPT


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def load_config(path):
    p = Path(path)
    require(p.is_absolute() and not p.is_symlink(), 'config_path')
    st = p.stat()
    require(st.st_uid == 0 and not st.st_mode & 0o022 and st.st_size < 65536, 'config_ownership')
    c = json.loads(p.read_text())
    require(c.get('schema') == 1 and set(c['mcpServers']) == set(capabilities(c.get('access_mode', 'read-only'))), 'config_servers')
    validate_endpoint(c['base_url']); validate_model(c['model'])
    for name, profile in c['mcpServers'].items():
        require(profile['command'] == '/usr/bin/ssh' and
                profile['args'][:3] == ['-T', '-F', '/etc/capstone-ollama-trial/ssh/config'],
                'fixed_ssh_required')
        require(profile['args'][3:] == PROFILES[name], 'fixed_ssh_target')
    return c


async def run(config, request, *, on_protected_start=None):
    from mcp_use import MCPClient, MCPAgent
    from mcp_use.agents.adapters.langchain_adapter import LangChainAdapter
    from langchain_ollama import ChatOllama
    from langchain_core.tools import StructuredTool
    from langchain_core.callbacks import AsyncCallbackHandler
    from jsonschema import Draft202012Validator, ValidationError

    started = time.perf_counter()
    report = {'at_kst': datetime.now(timezone(timedelta(hours=9))).isoformat(),
              'engine': 'mcp-use/ChatOllama', 'model': config['model'],
              'calls': [], 'model_calls': [], 'chat_posts': 0, 'protected_calls': 0,
              'network_mode': 'host_process', 'telemetry_enabled': False}
    mode = config.get('access_mode', 'read-only')
    available = capabilities(mode)
    question = request.get('question', '')
    current = request.get('current_question', question)
    require(isinstance(current, str) and len(current) <= 16000, 'current_question')
    report['access_mode'] = mode
    read_plan = harness.read_plan(current)
    cached = harness.prior_inventory(current, request.get('prior_evidence'))
    if cached and not request.get('discover_only'):
        report.update(status='completed', final_response=cached, evidence_reused=True,
                      evidence=request['prior_evidence'], total_seconds=time.perf_counter() - started)
        return report
    if harness.reuse_only(current) and not request.get('discover_only'):
        report.update(status='partial', final_response='같은 스레드에서 검증된 이전 규칙 조회 근거를 찾지 못했습니다. 요청에 따라 추가 조회는 하지 않았습니다.', total_seconds=time.perf_counter() - started)
        return report
    chosen = request.get('tools')
    if chosen is None and not request.get('discover_only'):
        scope = harness.tool_scope(current)
        if scope:
            chosen = sorted(scope)
    if chosen is not None:
        require(isinstance(chosen, list) and len(chosen) == len(set(chosen)) and
                set(chosen) <= {alias(s, t) for s, names in available.items() for t in names},
                'invalid_tool_subset')
    budget = Budget(request.get('max_tool_calls', harness.CONTRACT.TOOL_CALLS))
    lock = asyncio.Lock()
    protected_attempts = {}
    selection_active = False
    steps = request.get('max_steps', harness.CONTRACT.MODEL_STEPS)
    require(type(steps) is int and 1 <= steps <= 16, 'model_step_budget')

    class Meter(AsyncCallbackHandler):
        raise_error = True
        def __init__(self):
            self.starts = {}
            self.used = 0

        async def on_chat_model_start(self, serialized, messages, *, run_id, **kwargs):
            require(self.used < steps, 'model_budget_exhausted')
            self.used += 1
            self.starts[run_id] = time.perf_counter()

        async def on_llm_end(self, response, *, run_id, **kwargs):
            entry = {'seconds': time.perf_counter() - self.starts.pop(run_id)}
            if response.generations and response.generations[0]:
                message = response.generations[0][0].message
                entry['usage'] = getattr(message, 'usage_metadata', None)
                meta = getattr(message, 'response_metadata', {})
                entry['ollama'] = {k: meta[k] for k in ('total_duration', 'load_duration',
                    'prompt_eval_count', 'prompt_eval_duration', 'eval_count', 'eval_duration') if k in meta}
            report['model_calls'].append(entry)

    active_servers = {s: p for s, p in config['mcpServers'].items()
                      if chosen is None or any(alias(s, n) in chosen for n in available[s])}
    client = MCPClient(config={'mcpServers': active_servers}, code_mode=False,
                       sandbox=False, sampling_callback=None, elicitation_callback=None)

    class ReadAdapter(LangChainAdapter):
        async def create_all(self, current_client):
            self.tools, self.resources, self.prompts = [], [], []
            catalog = []
            report['_policy_tools'] = []
            for server, session in current_client.get_all_active_sessions().items():
                connector = session.connector
                tools = await connector.list_tools()
                # Mixed catalogs are validated before their write tools are hidden.
                for tool in filter_catalog(server, tools, mode):
                    name = alias(server, tool.name)
                    report['_policy_tools'].append({'function': {'name': name, 'description': tool.description or ''}})
                    schema = json.loads(json.dumps(tool.inputSchema))
                    Draft202012Validator.check_schema(schema)
                    catalog.append({'server': server, 'name': tool.name, 'alias': name,
                                    'schema_sha256': digest(schema)})
                    if name == 'mcp__system_diagnostics__get_system_diagnostics':
                        report['diagnostic_targets'] = schema['properties']['target']['enum']
                    if chosen is not None and name not in chosen:
                        continue
                    schema = harness.CONTRACT.normalized_schema(name, schema)
                    if harness.tool_scope(current) == {'mcp__rule_a__get_service_action_target'}:
                        schema['properties']['target']['enum'] = ['a:suricata']

                    def make_call(backend, bare_name, connection, input_schema):
                        async def call(**arguments):
                            async with lock:
                                validate_call(backend, bare_name, arguments, mode)
                                budget.take()
                                try:
                                    Draft202012Validator(input_schema).validate(arguments)
                                except ValidationError as exc:
                                    # This is before any MCP call or protected-start
                                    # callback. Let the model correct schema input;
                                    # never replay a call whose outcome is unknown.
                                    rejection = {'server': backend, 'name': bare_name,
                                        'error': 'tool_input_schema_validation_failed',
                                        'validator': str(exc.validator), 'executed': False}
                                    report.setdefault('input_rejections', []).append(rejection)
                                    return canonical({**rejection, 'expected_schema': input_schema})
                                if read_plan and read_plan['kind'] in ('wazuh', 'multi') and 'agent_id' in arguments:
                                    expected = harness.READ.verified_ids(read_plan, report['calls'])
                                    if arguments['agent_id'] not in expected:
                                        report.setdefault('rejected_calls', []).append({'server': backend,
                                            'name': bare_name, 'arguments': arguments, 'reason': 'agent_identity_not_verified',
                                            'mcp_executed': False})
                                        return json.dumps({'error': 'agent_identity_not_verified',
                                            'required': 'get_wazuh_agents로 대상 이름과 ID를 먼저 확인',
                                            'observed_agent_id': expected}, ensure_ascii=False)
                                tick = time.perf_counter()
                                event = {'server': backend, 'name': bare_name, 'arguments': arguments,
                                         'via': 'structured_read_selection' if selection_active else 'native_tool_call'}
                                is_protected = protected(backend, bare_name)
                                if is_protected:
                                    fingerprint = digest([backend, bare_name, arguments])
                                    if fingerprint in protected_attempts:
                                        return protected_attempts[fingerprint]
                                    protected_attempts[fingerprint] = json.dumps({'error': 'protected_attempt_outcome_unknown_do_not_repeat'})
                                    if on_protected_start is not None:
                                        on_protected_start()
                                    report['protected_calls'] += 1
                                try:
                                    timeout = harness.CONTRACT.PROTECTED_TIMEOUT if is_protected else harness.CONTRACT.READ_TIMEOUT
                                    result = await asyncio.wait_for(connection.call_tool(bare_name, arguments,
                                        read_timeout_seconds=timedelta(seconds=timeout)), timeout + 5)
                                    text = '\n'.join(c.text for c in result.content if getattr(c, 'type', None) == 'text')
                                    event['result_bytes'] = len(text.encode())
                                    limit = harness.READ.MAX_VULNERABILITY_BYTES if bare_name == 'get_wazuh_vulnerability_summary' else 2097152
                                    require(event['result_bytes'] <= limit, 'mcp_result_too_large')
                                    event.update(is_error=bool(result.isError), result_sha256=hashlib.sha256(text.encode()).hexdigest(),
                                                 result=text)
                                    if is_protected:
                                        protected_attempts[fingerprint] = text
                                    return harness.model_view(backend, bare_name, text)
                                except Exception as exc:
                                    event.update(is_error=True, error_type=type(exc).__name__)
                                    # Let the model report/correct a failed read; never retry a protected request.
                                    return json.dumps({'error': type(exc).__name__, 'executed': 'unknown' if is_protected else False})
                                finally:
                                    event['seconds'] = time.perf_counter() - tick
                                    report['calls'].append(event)
                        return call
                    call = make_call(server, tool.name, connector, schema)
                    self.tools.append(StructuredTool(name=name, description=tool.description or name,
                        args_schema=schema, coroutine=call,
                        return_direct=bool(read_plan or harness.inventory_question(current) and tool.name == 'get_rule_change_target')))
            require(len(catalog) == sum(len(available[s]) for s in active_servers), 'catalog_count')
            report['catalog'] = sorted(catalog, key=lambda x: x['alias'])
            report['exposed_tools'] = [t.name for t in self.tools]

    meter = Meter()
    llm = ChatOllama(model=config['model'], base_url=config['base_url'], reasoning=harness.CONTRACT.REASONING,
                     temperature=harness.CONTRACT.TEMPERATURE, top_p=harness.CONTRACT.TOP_P, num_predict=harness.CONTRACT.OUTPUT_TOKENS, client_kwargs={'timeout': 90},
                     callbacks=[meter])
    agent = MCPAgent(llm=llm, client=client, max_steps=steps, memory_enabled=True,
                     system_prompt=SYSTEM_PROMPT + harness.guidance(current), use_server_manager=False, verbose=False,
                     callbacks=[], retry_on_error=False)
    # Graph middleware nodes are not model turns. Keep the model and tool caps
    # independent, including across the one grounding repair below.
    agent.recursion_limit = steps * 8 + 16
    agent.adapter = ReadAdapter()
    agent.adapter._record_telemetry = False
    try:
        await agent.initialize()
        report['initialization_seconds'] = time.perf_counter() - started
        if request.get('discover_only'):
            report['status'] = 'discovered'
        else:
            require(isinstance(question, str) and 0 < len(question) <= 16000, 'question_required')
            tick = time.perf_counter()
            structured = harness.structured_read(current)
            policy_answer = harness.policy_explanation(current, report['_policy_tools'])
            if policy_answer:
                report['policy_definition_rendered'] = True
                final = policy_answer
            elif structured:
                final = ''  # The same model selects actual reads below.
            else:
                final = await asyncio.wait_for(agent.run(question), harness.CONTRACT.TURN_TIMEOUT if mode == 'hermes-parity' else 180)
            if not report['protected_calls']:
                missing = (harness.inventory(current, report['calls'], missing_targets=True) or
                           harness.missing_reads(current, report['calls'], report.get('diagnostic_targets', ())))
                literal = (harness.read_report(current, report['calls']) or harness.inventory(current, report['calls']) or
                           harness.service_report(current, report['calls']) or
                           harness.diagnostic_report(current, report['calls'], report.get('diagnostic_targets', ())) or
                           harness.event_report(current, report['calls']))
                issues = [] if literal else harness.violations(current, str(final), report['calls'])
                repair_passes = 0
                gap = harness.preparation_gap(current, report['calls'])
                preparation_used = False
                while (missing or issues or (gap and not preparation_used)) and not harness.action_claim_violations(current, str(final), report['calls']) and meter.used < steps and repair_passes < harness.CONTRACT.REPAIR_PASSES + int(structured):
                    repair_passes += 1
                    report['repair'] = {'missing_targets': missing, 'issues': issues}
                    instruction = ('현재 질문: ' + current + '\n조회 근거 점검 결과: ' + json.dumps(report['repair'], ensure_ascii=False) +
                        '\n누락된 실제 조회를 마치고 근거에 맞춰 최종 답변을 정정하세요. 이미 성공한 조회는 반복하지 마세요. '
                        '이 안내는 변경이나 승인이 아닙니다.\n' + harness.EVIDENCE.literal_evidence_summary(harness.facts_for(report['calls'])))
                    if gap:
                        preparation_used = True
                        report['write_preparation_attempts'] = 1
                        report['repair']['missing_write_targets'] = gap
                        instruction = '현재 질문: ' + current + '\n' + harness.preparation_instruction(gap)
                    read_scope = harness.tool_scope(current, report['calls'])
                    if read_scope and not gap and budget.used < budget.limit:
                        # The same LLM selects real read calls in constrained JSON
                        # when native tool calling stalls. No fixed fallback reads,
                        # protected tools, inferred approvals or incident decisions.
                        selected_tools = {t.name: t for t in agent.adapter.tools if t.name in read_scope}
                        schemas = {name: json.loads(json.dumps(tool.args_schema)) for name, tool in selected_tools.items()}
                        schemas = harness.refine_read_schemas(current, schemas, report['calls'], report.get('diagnostic_targets', ()))
                        if not schemas:
                            break  # Report a verified terminal failure; no blind repeat.
                        schema = harness.selection_schema(schemas, budget.limit - budget.used)
                        report['repair']['method'] = 'structured_read_selection'
                        selector = llm.with_structured_output(schema, method='json_schema')
                        plan = await asyncio.wait_for(selector.ainvoke([
                            ('system', SYSTEM_PROMPT + '\n조회 호출 선택 단계입니다. 결과 문장 대신 실제 읽기 도구와 인자를 선택하세요. '
                             '절대 구간이 미지원이어도 사용자 요청에 따라 지원되는 최근 상대 구간의 표본을 조회하세요. '
                             '요청한 장비/대상을 빠짐없이 포함하고 이미 성공한 조회를 반복하지 마세요. 요청구간을 지원한다고 꾸미지 마세요.' + harness.guidance(current)),
                            ('human', instruction + '\n허용된 도구와 정확한 선택 JSON Schema:\n' + canonical(schema))]), 90)
                        report.setdefault('read_selections', []).append(plan)
                        plan, removed = harness.validated_selection(plan, schema)
                        report['deduplicated_read_selections'] = report.get('deduplicated_read_selections', 0) + removed
                        selection_active = True
                        try:
                            for choice in plan['calls']:
                                await selected_tools[choice['tool']].ainvoke(choice['arguments'])
                        finally:
                            selection_active = False
                        final = ''  # Only observed facts can render this bounded read path.
                    else:
                        final = await asyncio.wait_for(agent.run(instruction), 180)
                    if report['protected_calls'] or preparation_used:
                        break
                    gap = harness.preparation_gap(current, report['calls'])
                    missing = harness.missing_reads(current, report['calls'], report.get('diagnostic_targets', ()))
                    issues = [] if harness.read_report(current, report['calls']) else harness.violations(current, str(final), report['calls'])
                rendered = (harness.read_report(current, report['calls']) or harness.inventory(current, report['calls']) or
                            harness.service_report(current, report['calls']) or
                            harness.diagnostic_report(current, report['calls'], report.get('diagnostic_targets', ())) or
                            harness.event_report(current, report['calls']))
                issues = harness.violations(current, str(final), report['calls'])
                still_missing = harness.missing_reads(current, report['calls'], report.get('diagnostic_targets', ()))
                if still_missing:
                    report['unqueried'] = still_missing
                    issues.append('requested_read_scope_incomplete')
                if rendered:
                    final = rendered
                elif issues:
                    report['remaining_issues'] = issues
                    final = (harness.action_fallback(current, report['calls']) if
                             harness.action_claim_violations(current, str(final), report['calls']) else
                             harness.fallback(current, report['calls']))
                    if still_missing:
                        final += '\n미확인 대상: ' + ', '.join(still_missing)
            action_issues = harness.action_claim_violations(current, str(final), report['calls'])
            if action_issues:
                report['remaining_issues'] = sorted(set(report.get('remaining_issues', []) + action_issues))
                final = harness.action_fallback(current, report['calls'])
            progress = harness.write_progress(current, report['calls'])
            if progress:
                report['write_progress'] = progress
                final = harness.write_report(final, progress)
            final = harness.EVIDENCE.kst_display(harness.footer_free(str(final)))
            report['chat_contract'] = {'version': harness.CONTRACT.VERSION, 'system_sha256': harness.CONTRACT.fingerprint(), 'model_steps': steps, 'tool_calls': budget.limit}
            report.update(status='partial' if (progress and not progress['complete']) or report.get('unqueried') or report.get('remaining_issues') else 'completed', final_response=final,
                          conversation_seconds=time.perf_counter() - tick)
            if not report['protected_calls'] and harness.inventory(current, report['calls'], verified_targets=True):
                report['evidence'] = {'question': current, 'at_kst': report['at_kst'], 'calls': report['calls']}
    except Exception as exc:
        report.update(status='failed', error_type=type(exc).__name__)
        progress = harness.write_progress(current, report['calls'])
        if progress:
            report.update(status='partial', write_progress=progress,
                          final_response='실행이 중단되었습니다. 아래는 중단 전 확인된 제출 근거이며 요청 전체 완료가 아닙니다.\n\n' + progress['text'])
        elif report['calls'] and not report['protected_calls']:
            report.update(status='partial', final_response=harness.fallback(current, report['calls']))
    finally:
        report.pop('_policy_tools', None)
        await client.close_all_sessions()
        report['total_seconds'] = time.perf_counter() - started
    return report


def main():
    require(os.geteuid() != 0, 'unprivileged_user_required')
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='/etc/capstone-ollama-trial/config.json')
    args = parser.parse_args()
    request = json.loads(sys.stdin.read(65537))
    require(isinstance(request, dict), 'request_object_required')
    with contextlib.redirect_stdout(sys.stderr):
        result = asyncio.run(run(load_config(args.config), request))
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result['status'] in ('completed', 'discovered') else 1


if __name__ == '__main__':
    sys.exit(main())
