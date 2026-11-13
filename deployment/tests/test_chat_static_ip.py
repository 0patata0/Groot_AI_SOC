"""Fixed chat-network addresses for the approval-card callback source.

The approval broker trusts exactly the Mattermost container address for card
button callbacks. On B (2026-11-12) a reboot swapped the dynamic addresses of
Mattermost and Postgres and every card was refused. Fresh installs now pin the
chat network; the existing B compose has a matching candidate.
"""
import ast
import ipaddress
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SIEM = (ROOT / 'deployment/roles/siem.sh').read_text()
BODY = SIEM.split("<<'PY'\n", 1)[1].rsplit('\nPY\n', 1)[0]


class Refused(Exception):
    pass


def need(ok, reason):
    if not ok:
        raise Refused(reason)


def load(ip='192.0.2.20', subnet='172.30.248.0/28', outputs=None):
    tree = ast.parse(BODY)
    wanted = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in ('chat_addresses', 'chat_conflicts')]
    assert len(wanted) == 2
    calls = []
    def run(argv, timeout=30, data=None):
        calls.append(argv)
        return outputs[' '.join(argv[:4])]
    ns = {'ipaddress': ipaddress, 'need': need, 'Refused': Refused, 'IP': ip, 'CHAT_SUBNET': subnet,
          'PROJECT': 'capstone-siem', 'run': run, 'parse': json.loads}
    exec(compile(ast.Module(body=wanted, type_ignores=[]), 'siem-chat', 'exec'), ns)
    return ns, calls


def system(networks=(), addresses=(), routes=()):
    ids = [str(i).rjust(64, '0') for i in range(len(networks))]
    out = {'docker network ls -q': ('\n'.join(ids) + '\n').encode()}
    for nid, net in zip(ids, networks):
        out['docker network inspect ' + nid] = json.dumps([net]).encode()
    out['ip -j address show'] = json.dumps(list(addresses)).encode()
    out['ip -j route show'] = json.dumps(list(routes)).encode()
    return out


class ChatAddresses(unittest.TestCase):
    def test_default_layout(self):
        ns, _ = load()
        self.assertEqual(ns['chat_addresses'](), {'subnet': '172.30.248.0/28', 'gateway': '172.30.248.1',
                         'mattermost': '172.30.248.2', 'postgres': '172.30.248.3', 'hermes': '172.30.248.4'})
        self.assertIn("CHAT_SUBNET = os.environ.get('CHAT_SUBNET', '172.30.248.0/28')", SIEM)

    def test_invalid_subnets_refused(self):
        for value in ('8.8.8.0/28', '172.30.248.0/30', '172.30.0.0/16', '172.30.248.1/28', 'x', '192.0.2.16/28'):
            with self.subTest(value=value), self.assertRaises(Refused):
                load(ip='192.0.2.20')[0]['chat_addresses'](value)

    def test_siem_host_inside_subnet_refused(self):
        with self.assertRaisesRegex(Refused, 'SIEM_HOST_overlaps_CHAT_SUBNET'):
            load(ip='10.9.9.5', subnet='10.9.9.0/28')[0]['chat_addresses']()


class ChatConflicts(unittest.TestCase):
    def check(self, **kw):
        ns, _ = load(outputs=system(**kw))
        ns['chat_conflicts'](ns['chat_addresses']())

    def test_free_subnet_passes(self):
        self.check(networks=[{'Name': 'bridge', 'IPAM': {'Config': [{'Subnet': '172.17.0.0/16'}]}}],
                   addresses=[{'ifname': 'ens18', 'addr_info': [{'family': 'inet', 'local': '192.0.2.20', 'prefixlen': 24}]}],
                   routes=[{'dst': 'default'}, {'dst': '192.0.2.0/24', 'dev': 'ens18'}])

    def test_own_network_and_its_bridge_are_allowed_on_rerun(self):
        own = {'Name': 'capstone-siem_chat', 'IPAM': {'Config': [{'Subnet': '172.30.248.0/28'}]},
               'Options': {'com.docker.network.bridge.name': 'br-chat'}}
        self.check(networks=[own],
                   addresses=[{'ifname': 'br-chat', 'addr_info': [{'family': 'inet', 'local': '172.30.248.1', 'prefixlen': 28}]}],
                   routes=[{'dst': '172.30.248.0/28', 'dev': 'br-chat'}])

    def test_other_docker_network_interface_or_route_overlap_refused(self):
        cases = [
            dict(networks=[{'Name': 'other', 'IPAM': {'Config': [{'Subnet': '172.30.0.0/16'}]}}]),
            dict(networks=[{'Name': 'capstone-siem_chat', 'IPAM': {'Config': [{'Subnet': '172.30.248.0/27'}]}}]),
            dict(addresses=[{'ifname': 'vpn0', 'addr_info': [{'family': 'inet', 'local': '172.30.248.9', 'prefixlen': 30}]}]),
            dict(routes=[{'dst': '172.30.248.0/24', 'dev': 'tun0'}]),
        ]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(Refused):
                self.check(**case)


class Wiring(unittest.TestCase):
    def test_preflight_checks_and_compose_pins_all_chat_services(self):
        self.assertIn("    chat_conflicts(chat_addresses())\n", SIEM)
        self.assertIn("'ipam':{'config':[{'subnet':chat['subnet'],'gateway':chat['gateway']}]}", SIEM)
        for service in ('postgres', 'mattermost'):
            self.assertIn("'networks':{'chat':{'ipv4_address':chat['" + service + "']}}", SIEM)
        self.assertIn("'networks':{'chat':{'ipv4_address':chat_addresses()['hermes']}}", SIEM)
        self.assertNotIn("'networks':['chat']", SIEM)

    def test_single_entrypoint_forwards_chat_subnet(self):
        deploy = (ROOT / 'deploy.sh').read_text()
        self.assertIn('\nCHAT_SUBNET=172.30.248.0/28\n', deploy)
        self.assertIn('|CHAT_SUBNET|', deploy)
        self.assertIn(' CHAT_SUBNET ', deploy)
        self.assertIn('\nCHAT_SUBNET=172.30.248.0/28\n', (ROOT / 'deployment/config.example.conf').read_text())


class GrootCandidate(unittest.TestCase):
    CURRENT = (ROOT / 'infra/validation/chat-static-ip/mattermost-compose.before.yml').read_text()  # pre-apply live
    LIVE_SYNCED = (ROOT / 'infra/groot-b/mattermost-compose.yml').read_text()  # applied 2026-11-13 09:17
    CANDIDATE = (ROOT / 'infra/validation/chat-static-ip/mattermost-compose.candidate.yml').read_text()

    def test_pins_current_live_addresses_and_keeps_gateway(self):
        c = self.CANDIDATE
        self.assertIn('        ipv4_address: 172.19.0.2\n', c)   # mm-app = broker RULE_MM_SOURCE_CIDRS
        self.assertIn('        ipv4_address: 172.19.0.3\n', c)   # mm-postgres
        self.assertIn('        - subnet: 172.19.0.0/16\n          gateway: 172.19.0.1\n', c)
        dynamic = ipaddress.ip_network('172.19.128.0/17')
        self.assertIn('          ip_range: 172.19.128.0/17\n', c)
        for fixed in ('172.19.0.2', '172.19.0.3', '172.19.0.1'):
            self.assertNotIn(ipaddress.ip_address(fixed), dynamic)

    def test_only_network_definitions_change(self):
        c = self.CANDIDATE
        c = c.replace('    networks:\n      mm-net:\n        ipv4_address: 172.19.0.3\n', '    networks: [mm-net]\n', 1)
        start = c.index('    networks:\n      mm-net:\n        # 승인 브로커')
        end = c.index('        ipv4_address: 172.19.0.2\n') + len('        ipv4_address: 172.19.0.2\n')
        c = c[:start] + '    networks: [mm-net]\n' + c[end:]
        c = c[:c.index('    ipam:\n')] if c.rstrip().endswith('ip_range: 172.19.128.0/17') else c
        self.assertEqual(c, self.CURRENT)


    def test_repo_compose_equals_the_applied_candidate(self):
        self.assertEqual(self.LIVE_SYNCED, self.CANDIDATE)

    def test_apply_script_pins_the_reviewed_files_and_addresses(self):
        import hashlib, re
        script = (ROOT / 'infra/validation/chat-static-ip/apply_b.py').read_text()
        cur = re.search(r"CURRENT_SHA = '([0-9a-f]{64})'", script)[1]
        cand = re.search(r"CANDIDATE_SHA = '([0-9a-f]{64})'", script)[1]
        self.assertEqual(cur, hashlib.sha256(self.CURRENT.encode()).hexdigest())
        self.assertEqual(cand, hashlib.sha256(self.CANDIDATE.encode()).hexdigest())
        self.assertIn("WANT = {'mm-app': '172.19.0.2', 'mm-postgres': '172.19.0.3'}", script)
        self.assertIn("'RULE_MM_SOURCE_CIDRS=172.19.0.2/32\\n' in env", script)

if __name__ == '__main__':
    unittest.main()
