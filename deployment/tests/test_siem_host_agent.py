import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

spec = importlib.util.spec_from_file_location('host_agent', Path(__file__).parents[1] / 'siem_host_agent.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
RAW = b'''<!-- preserve -->\n<ossec_config>
<client><server><address>MANAGER_IP</address></server></client>
<sca><enabled>yes</enabled><scan_on_start>yes</scan_on_start></sca>
<wodle name="syscollector"><disabled>no</disabled></wodle>
<syscheck><disabled>no</disabled></syscheck>
<active-response><disabled>no</disabled><ca_store>etc/wpk_root.pem</ca_store></active-response>
</ossec_config><ossec_config><localfile><log_format>journald</log_format>
<location>journald</location></localfile></ossec_config>'''
OLD = b'001 existing any ' + b'a' * 64 + b'\n'
NEW = b'007 capstone-siem-host any ' + b'b' * 64 + b'\n'


class HostAgent(unittest.TestCase):
    def test_config_retains_collections_and_disables_enrollment_and_response(self):
        changed = m.candidate(RAW)
        root = ET.fromstring(b'<root>' + changed + b'</root>')
        self.assertEqual(root.findtext('ossec_config/client/server/address'), '127.0.0.1')
        self.assertEqual(root.findtext('ossec_config/client/enrollment/enabled'), 'no')
        self.assertEqual(root.findtext('ossec_config/active-response/disabled'), 'yes')
        self.assertIn(b'<!-- preserve -->', changed)
        for name in ('sca', 'syscheck', 'wodle', 'localfile'):
            original = ET.fromstring(b'<root>' + RAW + b'</root>').find('ossec_config/' + name)
            self.assertEqual(ET.tostring(original), ET.tostring(root.find('ossec_config/' + name)))

    def test_reject_existing_or_duplicate_clients(self):
        for bad in (RAW.replace(b'MANAGER_IP', b'192.0.2.10'), RAW + RAW,
                    RAW.replace(b'<disabled>no</disabled><ca_store>', b'<ca_store>')):
            with self.subTest(bad=bad), self.assertRaises(ValueError): m.candidate(bad)

    def test_collection_gap_is_rejected(self):
        for bad in (RAW.replace(b'<enabled>yes', b'<enabled>no'),
                    RAW.replace(b'<log_format>journald', b'<log_format>syslog'),
                    RAW.replace(b'<scan_on_start>yes', b'<scan_on_start>no')):
            with self.subTest(bad=bad), self.assertRaises(ValueError): m.candidate(bad)

    def test_actual_new_id_not_assumed(self):
        self.assertEqual(m.new_key(OLD, OLD + NEW, 'capstone-siem-host'), ('007', NEW))

    def test_manager_key_changes_fail_closed_without_exposing_key(self):
        for after in (NEW, OLD + NEW + NEW, OLD, OLD + NEW.replace(b'007', b'000'),
                      OLD + NEW.replace(b'capstone-siem-host', b'other')):
            with self.subTest(after=after), self.assertRaises(ValueError) as caught:
                m.new_key(OLD, after, 'capstone-siem-host')
            self.assertNotIn('a' * 64, str(caught.exception))
            self.assertNotIn('b' * 64, str(caught.exception))

    def test_partial_install_is_not_automatically_registered_again(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(m, 'STATE', Path(directory)), \
                patch.object(m, 'verify', side_effect=ValueError('incomplete')), patch.object(m, 'check') as check:
            with self.assertRaisesRegex(ValueError, 'incomplete'): m.install('fresh')
            check.assert_not_called()

    def test_syntax_failure_stops_before_registration_and_disables_new_service(self):
        calls = []
        def run(args, **kw):
            calls.append(args)
            if args[-1] == '-t': raise ValueError('syntax_failed')
            return types.SimpleNamespace(returncode=0, stdout=b'')
        with tempfile.TemporaryDirectory() as directory, patch.object(m, 'STATE', Path(directory)/'state'), \
                patch.object(m, 'check', return_value=RAW), patch.object(m, 'manager', return_value=('cid', 17)), \
                patch.object(m, 'manager_endpoint', return_value='127.0.0.1'), \
                patch.object(m, 'manager_keys', return_value=OLD), patch.object(m, 'trusted'), \
                patch.object(m, 'atomic'), patch.object(m.grp, 'getgrnam', return_value=types.SimpleNamespace(gr_gid=999)), \
                patch.object(m, 'read', side_effect=lambda p: RAW if p.name == 'ossec.conf' else b''), \
                patch.object(m, 'run', side_effect=run):
            with self.assertRaisesRegex(ValueError, 'syntax_failed'): m.install('fresh')
        self.assertFalse(any('manage_agents' in ' '.join(a) for a in calls))
        self.assertIn(['systemctl', 'disable', '--now', 'wazuh-agent'], calls)

    def test_command_failure_does_not_leak_output_or_argv(self):
        with patch.object(m.subprocess, 'run', return_value=types.SimpleNamespace(returncode=1, stdout=NEW, stderr=OLD)):
            with self.assertRaisesRegex(ValueError, '^host_agent_command_failed:docker$'):
                m.run(['docker', 'private-value'])

    def test_fresh_manager_only_binds_its_local_private_ip(self):
        outputs = [json.dumps([{'NetworkSettings': {'Ports': {'1514/tcp': [
            {'HostIp': '192.0.2.20', 'HostPort': '1514'}]}}}]),
            json.dumps([{'addr_info': [{'local': '192.0.2.20'}]}])]
        with patch.object(m, 'run', side_effect=[types.SimpleNamespace(stdout=s.encode()) for s in outputs]):
            self.assertEqual(m.manager_endpoint('cid'), '192.0.2.20')
        self.assertIn(b'<address>192.0.2.20</address>', m.candidate(RAW, '192.0.2.20'))

    def test_nonlocal_manager_binding_is_rejected(self):
        outputs = [json.dumps([{'NetworkSettings': {'Ports': {'1514/tcp': [
            {'HostIp': '192.0.2.20', 'HostPort': '1514'}]}}}]), '[]']
        with patch.object(m, 'run', side_effect=[types.SimpleNamespace(stdout=s.encode()) for s in outputs]):
            with self.assertRaisesRegex(ValueError, 'ambiguous'): m.manager_endpoint('cid')

    def test_initial_entrypoint_links_package_gate_install_and_verify(self):
        role = (Path(__file__).parents[1] / 'roles/siem.sh').read_text()
        for action in ('check', 'install', 'verify'):
            self.assertIn("str(SOURCE/'deployment/siem_host_agent.py'),'" + action + "'", role)
        self.assertLess(role.index("phase='core_health';"), role.index("phase='siem_host_agent'"))
        self.assertIn("'deployment/ssh_macs.py','deployment/siem_host_agent.py'", role)


if __name__ == '__main__': unittest.main()
