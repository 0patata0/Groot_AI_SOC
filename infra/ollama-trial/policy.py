"""Fixed SOC capabilities; root configuration selects read-only or Hermes parity."""
import re
from urllib.parse import urlsplit

RULE_READS = {'get_rule_change_target', 'get_rule_change_status',
              'get_service_action_target', 'get_operation_status'}
READ_TOOLS = {
    'rule-a': RULE_READS, 'rule-b': RULE_READS,
    'security-events': {'search_suricata_alerts', 'search_modsecurity_alerts'},
    'system-diagnostics': {'get_system_diagnostics', 'calculate_time'},
    'wazuh-ro': {'get_wazuh_agents', 'get_wazuh_cluster_nodes',
                'get_wazuh_critical_vulnerabilities', 'get_wazuh_manager_error_logs',
                'get_wazuh_vulnerability_summary', 'get_wazuh_agent_processes',
                'get_wazuh_alert_summary', 'get_wazuh_rules_summary',
                'search_wazuh_manager_logs', 'get_wazuh_cluster_health',
                'get_wazuh_remoted_stats', 'get_wazuh_agent_ports',
                'get_wazuh_log_collector_stats', 'get_wazuh_weekly_stats'},
}
PROTECTED_TOOLS = {
    'rule-write-a': {'propose_rule_edit', 'propose_rule_change',
                     'propose_service_action', 'temporarily_contain_ip'},
    'rule-write-b': {'propose_rule_edit', 'propose_rule_change', 'propose_service_action'},
    'resp': {'block_ip', 'unblock_ip'},
}
PARITY_TOOLS = {**READ_TOOLS, **PROTECTED_TOOLS, 'resp': {'list_blocks', 'block_ip', 'unblock_ip'}}
PROFILES = {'rule-a': ['rule-a'], 'rule-b': ['rule-b'],
            'rule-write-a': ['rule-write-a'], 'rule-write-b': ['rule-write-b'], 'resp': ['resp-a'],
            'security-events': ['mcp-b', 'security-events'],
            'system-diagnostics': ['mcp-b', 'system-diagnostics'], 'wazuh-ro': ['mcp-b']}


def capabilities(mode='read-only'):
    require(mode in ('read-only', 'hermes-parity'), 'invalid_access_mode')
    return PARITY_TOOLS if mode == 'hermes-parity' else READ_TOOLS


def protected(server, name):
    return name in PROTECTED_TOOLS.get(server, ())


def require(value, code):
    if not value:
        raise ValueError(code)


def alias(server, name):
    require(server in PARITY_TOOLS and name in PARITY_TOOLS[server], 'tool_not_allowed')
    return 'mcp__' + server.replace('-', '_') + '__' + name


def validate_call(server, name, arguments, mode='read-only'):
    alias(server, name)
    require(name in capabilities(mode).get(server, ()), 'tool_not_authorized')
    require(type(arguments) is dict, 'arguments_not_object')
    if server.startswith('rule-') and 'target' in arguments:
        require(isinstance(arguments['target'], str) and
                arguments['target'].startswith(server[-1] + ':'), 'cross_host_target')


def validate_endpoint(url):
    p = urlsplit(url)
    require(p.scheme in ('http', 'https') and p.hostname and not p.username and
            not p.password and not p.query and not p.fragment and p.path in ('', '/'),
            'native_endpoint_required')
    return url.rstrip('/')


def validate_model(model):
    require(isinstance(model, str) and re.fullmatch(r'[A-Za-z0-9_./:-]{1,128}', model),
            'invalid_model')
    return model


class Budget:
    def __init__(self, limit=32):
        require(type(limit) is int and 1 <= limit <= 40, 'invalid_tool_budget')
        self.limit, self.used = limit, 0

    def take(self):
        require(self.used < self.limit, 'tool_budget_exhausted')
        self.used += 1
