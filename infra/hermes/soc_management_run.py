#!/usr/bin/env python3
"""Restricted entry point around the installed Hermes CLI, not another agent.

The host controller selects manage/verify. Neither the prompt nor model can
change that selection. Both dispatch layers refuse non-SOC tools. Native MCP
approval and evidence checks remain authoritative for every physical action.
"""
import asyncio
import functools
import json
import os
import sys
import threading
import time

READ = frozenset({'get_rule_change_target', 'get_rule_change_status',
                  'get_service_action_target', 'get_operation_status'})
WRITE = frozenset({'propose_rule_edit', 'propose_rule_change',
                   'propose_service_action', 'temporarily_contain_ip'})
EVENT_READ = frozenset({'search_suricata_alerts', 'search_modsecurity_alerts'})
DIAGNOSTIC_READ = frozenset({'get_system_diagnostics'})


def allowed(name, mode):
    if mode not in {'manage', 'verify'} or not isinstance(name, str):
        return False
    if name.startswith('mcp__wazuh_ro__'):
        return name.removeprefix('mcp__wazuh_ro__').startswith(('get_wazuh_', 'search_wazuh_'))
    if name.startswith('mcp__security_events__'):
        return name.removeprefix('mcp__security_events__') in EVENT_READ
    if name.startswith('mcp__system_diagnostics__'):
        return name.removeprefix('mcp__system_diagnostics__') in DIAGNOSTIC_READ
    if name == 'mcp__resp__list_blocks':
        return True
    for server in ('rule_a', 'rule_b'):
        prefix = 'mcp__' + server + '__'
        if name.startswith(prefix):
            bare = name.removeprefix(prefix)
            return bare in READ or (mode == 'manage' and bare in WRITE and
                                   (bare != 'temporarily_contain_ip' or server == 'rule_a'))
    return False


def wire_allowed(name, mode):
    return mode in {'manage', 'verify'} and isinstance(name, str) and (name.startswith(('get_wazuh_', 'search_wazuh_')) or
        name in READ | EVENT_READ | DIAGNOSTIC_READ | {'list_blocks'} or (mode == 'manage' and name in WRITE))


def compact_target_receipt(value):
    """Audit metadata only; the model still receives the complete MCP result."""
    try:
        outer = json.loads(value)
        if not isinstance(outer, dict) or outer.get('error') or outer.get('isError'):
            return value
        payload = json.loads(outer['result'])
        if (not isinstance(payload, dict) or payload.get('error') or payload.get('isError')
                or not {'target', 'sha256', 'runtime'} <= payload.keys()):
            return value
        kept = {k: payload[k] for k in ('target', 'sha256', 'runtime', 'related_hashes') if k in payload}
        return json.dumps({'result': json.dumps(kept, ensure_ascii=False)}, ensure_ascii=False)
    except (ValueError, KeyError, TypeError):
        return value


def main():
    mode = os.environ.get('CAPSTONE_MANAGEMENT_MODE')
    if (os.getuid(), os.getgid(), os.geteuid(), os.getegid()) != (995, 986, 995, 986) or mode not in {'manage', 'verify'}:
        raise SystemExit('management_identity_or_mode_invalid')
    if os.environ.get('HERMES_HOME') != '/opt/data/management':
        raise SystemExit('management_home_invalid')
    if any(x in sys.argv for x in ('--yolo', '--safe-mode', '--ignore-user-config', '-z')):
        raise SystemExit('management_cli_override_refused')
    structured_stdout = sys.stdout
    sys.stdout = sys.stderr
    sys.path.insert(0, '/opt/hermes')
    from tools.registry import registry
    from mcp import ClientSession
    from run_agent import AIAgent
    from hermes_cli.stream_json import StreamJsonEmitter
    import capstone_korean_output_guard as guard
    dispatch, wire, init = registry.dispatch, ClientSession.call_tool, AIAgent.__init__
    original_result = StreamJsonEmitter.emit_result
    original_progress = StreamJsonEmitter.on_tool_progress
    evidence = []
    output_lock = threading.Lock()

    def structured_emit(self, value):
        # CLI startup notices are diagnostics. Only native emitter events reach
        # the controller's structured stdout, never model-controlled raw text.
        with output_lock:
            structured_stdout.write(json.dumps(dict(value, timestamp=int(time.time()*1000)), ensure_ascii=False) + '\n')
            structured_stdout.flush()

    def gated_dispatch(name, args, **kwargs):
        if not allowed(name, mode):
            raise PermissionError('management_tool_not_allowed')
        return dispatch(name, args, **kwargs)

    async def gated_wire(self, name, arguments=None, *args, **kwargs):
        if not wire_allowed(name, mode):
            raise PermissionError('management_wire_tool_not_allowed')
        result = await wire(self, name, arguments, *args, **kwargs)
        # Keep only real MCP text, bounded in memory, for literal-evidence checks.
        for item in getattr(result, 'content', [])[:20]:
            value = getattr(item, 'text', None)
            if isinstance(value, str):
                evidence.append({'role': 'tool', 'content': value[:16000]})
        del evidence[:-32]
        return result

    @functools.wraps(init)
    def restricted_init(self, *args, **kwargs):
        init(self, *args, **kwargs)
        self.tools = [tool for tool in self.tools
                      if allowed(tool.get('function', {}).get('name'), mode)]
        self.valid_tool_names = {t['function']['name'] for t in self.tools}
        if not self.valid_tool_names:
            raise RuntimeError('management_tools_unavailable')

    def guarded_result(self, result, session_id='', exit_code=0):
        data = dict(result) if isinstance(result, dict) else {'final_response': str(result or '')}
        guard.begin_turn('SOC 사건 판단과 검증 결과를 한국어로 보고한다.')
        guard.set_turn_evidence([{'role': 'user', 'content': '한국어 SOC 보고'}] + evidence)
        text = data.get('final_response') or ''
        data['final_response'] = str(asyncio.run(guard.guard_text(text)))
        return original_result(self, data, session_id, exit_code)

    def receipt_progress(self, event_type, tool_name=None, preview=None, args=None, **kwargs):
        if event_type == 'tool.completed' and isinstance(tool_name, str) and tool_name.endswith('__get_rule_change_target'):
            kwargs['result'] = compact_target_receipt(kwargs.get('result', ''))
        return original_progress(self, event_type, tool_name, preview, args, **kwargs)

    registry.dispatch, ClientSession.call_tool = gated_dispatch, gated_wire
    AIAgent.__init__, StreamJsonEmitter.emit_result = restricted_init, guarded_result
    StreamJsonEmitter.on_tool_progress = receipt_progress
    StreamJsonEmitter._emit = structured_emit
    # Register the configured MCP toolsets before native CLI validates -t.
    # Imports performed for the gates precede the CLI's background discovery.
    from tools.mcp_tool import discover_mcp_tools
    discover_mcp_tools()
    from hermes_cli.main import main as native_main
    native_main()


if __name__ == '__main__':
    main()
