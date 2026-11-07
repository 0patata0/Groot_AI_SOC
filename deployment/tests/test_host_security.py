import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('guard', Path(__file__).parents[1] / 'host_security.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class Policy(unittest.TestCase):
    def test_named_admin_threshold_does_not_exempt_other_rules_or_old_network(self):
        text = m.management_ssh_thresholds(['192.168.16.231/32'])
        active = [line for line in text.splitlines() if not line.startswith('#')]
        self.assertEqual(active, ['suppress gen_id 1, sig_id 2001219, track by_src, ip 192.168.16.231/32'])
        self.assertNotIn('192.168.10.0', text)
        self.assertNotIn('sig_id 0', text)

    def test_threshold_refuses_global_ipv6_noncanonical_and_injected_sources(self):
        for value in ('0.0.0.0/0', '::/0', '192.168.16.231/24', '192.168.16.231/32\nsuppress gen_id 1, sig_id 0', 231):
            with self.subTest(value=value), self.assertRaises(ValueError):
                m.management_ssh_thresholds([value])

    def test_other_ssh_port_and_empty_management_have_no_ssh22_exception(self):
        for cidrs, port in (([], 22), (['192.168.16.231/32'], 2222)):
            self.assertFalse(any(line.startswith('suppress ') for line in m.management_ssh_thresholds(cidrs, port).splitlines()))
        for port in (True, 0, 65536, '22'):
            with self.assertRaises(ValueError):m.management_ssh_thresholds([], port)

    def config(self, role='siem'):
        return {'schema':1,'role':role,'security_host':'10.200.10.1','siem_host':'10.200.10.10',
                'service_host':'10.200.10.20','interface':'ens160','ssh_port':22,'web_port':80,
                'legacy_bridge':'docker0','allow_legacy_management_http':False}

    def test_legacy_container_initiated_connections_drop_before_generic_established(self):
        text = m.rules(self.config('service'))
        for chain in text.split(' chain ')[1:]:
            self.assertLess(chain.index('iifname "docker0" drop'), chain.index('iifname "ens160" ct state established'))
            self.assertIn('ct direction reply accept', chain)
        self.assertNotIn('flush ruleset', text)

    def test_siem_only_agent_ports_allow_service_host(self):
        text = m.rules(self.config())
        c_lines = [x for x in text.splitlines() if 'ip saddr 10.200.10.20' in x]
        self.assertEqual(len(c_lines), 1)
        self.assertIn('ct original proto-dst { 1514, 1515 }', c_lines[0])
        self.assertNotIn('8065', text); self.assertNotIn('8090', text)

    def test_dashboard_acl_checks_original_dnat_port_and_vpn_deny_first(self):
        c = self.config(); c.update(dashboard_cidrs=['192.168.0.0/16'],dashboard_denied_cidrs=['192.168.15.0/24'])
        text = m.rules(c)
        forward = text.split(' chain forward ')[1]
        self.assertIn('ct original proto-dst 443 accept', forward)
        self.assertLess(forward.index('192.168.15.0/24'), forward.index('ct state established'))

    def test_ssh_management_exemption_does_not_grant_broker_or_dashboard(self):
        c = self.config(); c['management_cidrs'] = ['192.168.10.0/24']
        matches = [x for x in m.rules(c).splitlines() if '192.168.10.0/24' in x]
        self.assertEqual(len(matches),1); self.assertIn('tcp dport 22 accept',matches[0])

    def test_world_or_injected_sources_refused(self):
        for value in ('0.0.0.0/0','192.168.10.1/24','10.0.0.0/8; accept'):
            c = self.config(); c['chat_cidrs']=[value]
            with self.assertRaises(ValueError): m.configuration(c)

    def test_block_protection_networks_do_not_implicitly_grant_ssh(self):
        env={'SECURITY_HOST':'10.200.10.1','SIEM_HOST':'10.200.10.10','SERVICE_HOST':'10.200.10.20',
             'ADMIN_PROTECTED_CIDRS':'198.51.100.0/24','MANAGEMENT_ALLOWED_CIDRS':'192.168.12.0/24'}
        with patch.dict(m.os.environ,env,clear=True),patch.object(m,'run',return_value='[{"dev":"ens160"}]'),\
                patch.object(m,'authenticated_ssh_peer',return_value='10.200.10.1/32'):
            c=m.from_environment('siem')
        self.assertEqual(c['management_cidrs'],['10.200.10.1/32','192.168.12.0/24'])

    def test_security_ssh_covers_all_interfaces_and_ipv6_before_established(self):
        c=self.config('security');c['management_cidrs']=['192.168.16.231/32']
        text=m.rules(c);incoming=text.split(' chain input ')[1].split(' chain forward ')[0]
        self.assertIn('192.168.16.231/32',incoming)
        self.assertIn('10.200.10.10/32',incoming)
        self.assertIn('tcp dport 22 drop',incoming)
        self.assertNotIn('ct state established',incoming)
        self.assertNotIn('iifname "ens160"',incoming)
        self.assertNotIn('8090',text)


if __name__ == '__main__': unittest.main()
