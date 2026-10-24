#!/usr/bin/env python3
"""Isolated Hermes SDK arm of the comparison; no live gateway/history writes.

The operator supplies a private HERMES_HOME and a request file. Only configured
read tools may execute. The API system prompt/temperature/thinking/output cap
are normalized to the candidate arm; this is not the production chat path.
"""
import hashlib
import importlib
from functools import wraps
import json
import os
from pathlib import Path
import signal
import sys
import threading
import time
from datetime import datetime, timezone, timedelta

sys.path.insert(0, str(Path(__file__).resolve().parent))
from policy import Budget, alias, validate_call, require
from runtime import SYSTEM_PROMPT, canonical


def main():
    started = time.perf_counter()
    home = Path(os.environ['HERMES_HOME'])
    require(os.getuid() == 995 and str(home).startswith('/tmp/capstone-ollama-comparison-'), 'private_benchmark_only')
    request = json.loads(Path(sys.argv[1]).read_text())
    public = os.dup(1)
    log = os.open(home / 'benchmark.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.dup2(log, 1); os.dup2(log, 2); os.close(log)
    signal.alarm(210)
    report = {'engine': 'Hermes SDK', 'at_kst': datetime.now(timezone(timedelta(hours=9))).isoformat(),
              'calls': [], 'model_calls': [], 'api_requests': [], 'chat_posts': 0, 'protected_calls': 0,
              'normalized_system_prompt': True, 'production_plugins_enabled': False}
    agent = None
    shutdown = None
    try:
        sys.path.insert(0, '/opt/hermes')
        from tools.registry import registry
        from mcp import ClientSession
        from jsonschema import Draft202012Validator
        from openai.resources.chat.completions import Completions
        from tools.mcp_tool import discover_mcp_tools, shutdown_mcp_servers
        shutdown = shutdown_mcp_servers
        discover_mcp_tools()
        from run_agent import AIAgent
        agent = AIAgent(provider='custom', base_url='http://211.170.162.111:11434/v1',
                        model='qwen3.6:35b', api_mode='chat_completions', api_key='not-needed',
                        enabled_toolsets=['mcp-rule-a', 'mcp-rule-b', 'mcp-system-diagnostics'],
                        max_iterations=5, max_tokens=2048, reasoning_config={'enabled': False},
                        skip_context_files=True, skip_memory=True, skip_background_review=True,
                        session_db=None, save_trajectories=False, quiet_mode=True,
                        cwd=str(home.parent / 'work'), fallback_model=None, run_budget_seconds=180)
        require(set(agent.valid_tool_names) == set(request['tools']), 'baseline_tool_subset_mismatch')
        schemas = {t['function']['name']: t['function']['parameters'] for t in agent.tools}
        lookup = {}
        for server, names in [('rule-a', ['get_rule_change_target', 'get_service_action_target']),
                              ('rule-b', ['get_rule_change_target', 'get_service_action_target']),
                              ('system-diagnostics', ['calculate_time'])]:
            for name in names:
                lookup[alias(server, name)] = (server, name)
        budget = Budget(8)
        lock = threading.Lock()
        dispatch = registry.dispatch
        wire = ClientSession.call_tool
        create = Completions.create
        api_module = importlib.import_module('agent.turn_api_call')
        loop_module = importlib.import_module('agent.conversation_loop')
        perform = api_module.perform_api_call
        require(loop_module.perform_api_call is perform, 'api_alias_mismatch')

        def gated_dispatch(name, args, **kwargs):
            require(name in lookup and name in schemas, 'unexpected_dispatch')
            server, bare = lookup[name]
            validate_call(server, bare, args)
            Draft202012Validator(schemas[name]).validate(args)
            return dispatch(name, args, **kwargs)

        async def gated_wire(self, name, arguments=None, *args, **kwargs):
            require(name in {'get_rule_change_target', 'get_service_action_target', 'calculate_time'},
                    'unexpected_wire_call')
            with lock:
                budget.take()
            tick = time.perf_counter()
            server = 'system-diagnostics' if name == 'calculate_time' else 'rule-' + arguments.get('target', '?')[0]
            validate_call(server, name, arguments)
            event = {'server': server, 'name': name, 'arguments': arguments}
            try:
                result = await wire(self, name, arguments, *args, **kwargs)
                content = '\n'.join(c.text for c in result.content if getattr(c, 'type', None) == 'text')
                error = bool(getattr(result, 'is_error', getattr(result, 'isError', False)))
                event.update(result=content, is_error=error, result_sha256=hashlib.sha256(content.encode()).hexdigest())
                require(not error, 'mcp_read_error')
                return result
            finally:
                event['seconds'] = time.perf_counter() - tick
                report['calls'].append(event)

        def measured_create(self, *args, **kwargs):
            require(len(report['api_requests']) < 5, 'model_budget_exhausted')
            messages = [m for m in kwargs['messages'] if m.get('role') != 'system']
            kwargs['messages'] = [{'role': 'system', 'content': SYSTEM_PROMPT}] + messages
            kwargs.update(temperature=0, top_p=0.95, max_tokens=2048, reasoning_effort='none')
            report['system_sha256'] = hashlib.sha256(SYSTEM_PROMPT.encode()).hexdigest()
            report['tool_schema_sha256'] = hashlib.sha256(canonical(kwargs.get('tools', [])).encode()).hexdigest()
            report['api_requests'].append({'stream': bool(kwargs.get('stream'))})
            return create(self, *args, **kwargs)

        @wraps(perform)
        def measured_perform(*args, **kwargs):
            # create() returns streaming headers before generation is complete.
            # Time the SDK's full API step, including stream consumption.
            tick = time.perf_counter()
            usage = None
            try:
                result = perform(*args, **kwargs)
                response = getattr(result, 'response', None)
                usage = getattr(response, 'usage', None)
                return result
            finally:
                report['model_calls'].append({'seconds': time.perf_counter() - tick,
                                               'scope': 'complete_api_step',
                                               'usage': usage.model_dump() if usage else None})

        registry.dispatch = gated_dispatch
        ClientSession.call_tool = gated_wire
        Completions.create = measured_create
        api_module.perform_api_call = loop_module.perform_api_call = measured_perform
        report['initialization_seconds'] = time.perf_counter() - started
        report['exposed_tools'] = sorted(agent.valid_tool_names)
        tick = time.perf_counter()
        result = agent.run_conversation(user_message=request['question'], system_message=SYSTEM_PROMPT,
                                        conversation_history=[])
        report.update(conversation_seconds=time.perf_counter() - tick,
                      final_response=result.get('final_response'),
                      completed=result.get('completed'), api_calls=result.get('api_calls'))
        require(result.get('completed') and not any(result.get(k) for k in ('failed', 'partial', 'interrupted')),
                'conversation_incomplete')
        report['status'] = 'completed'
    except BaseException as exc:
        report.update(status='failed', error_type=type(exc).__name__, error_code=str(exc)[:200])
    finally:
        signal.alarm(20)
        if agent is not None:
            agent.close()
        if shutdown is not None:
            shutdown()
        report['total_seconds'] = time.perf_counter() - started
        signal.alarm(0)
        with os.fdopen(public, 'w') as out:
            json.dump(report, out, ensure_ascii=False); out.write('\n')
    return 0 if report.get('status') == 'completed' else 1


if __name__ == '__main__':
    sys.exit(main())
