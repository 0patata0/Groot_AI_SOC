import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('management_access', ROOT / 'deployment/management_access.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class ManagementPolicy(unittest.TestCase):
    def test_proxy_only_exact_management_servers(self):
        original = (ROOT / 'infra/groot-a/chatproxy.nginx.conf').read_text()
        changed = m.proxy_policy(original)
        for domain in m.DOMAINS:
            prefix = changed[changed.index('server_name ' + domain):]
            prefix = prefix[:prefix.index('location / {')]
            self.assertIn('allow 192.168.16.231;', prefix)
            self.assertNotIn('/24;', prefix)
        # Non-management regions, certificates and upstream security are intact.
        def public(text):
            import re
            return re.sub(r'server_name wazuh[^;]+;.*?(?=location / \{)', 'WAZUH_ACL', text, flags=re.S)
        self.assertEqual(public(original), public(changed))
        self.assertEqual(m.proxy_policy(changed), changed)

    def test_ambiguous_or_missing_server_fails_closed(self):
        text = (ROOT / 'infra/groot-a/chatproxy.nginx.conf').read_text()
        for altered in (text.replace('server_name wazuh.groot.lab;', 'server_name other;'),
                        text + '\nserver_name wazuh.groot.lab;'):
            with self.assertRaises(ValueError): m.proxy_policy(altered)

    def test_no_global_firewall_or_ttl_mutation(self):
        rows = [ {'rule': {'family':'inet','table':'capstone_fw','chain':'prerouting_block','handle':42,
                  'expr':[{'match': {'op':'==','left':{'payload':{'protocol':'ip','field':'saddr'}},'right':'@never_block'}},{'accept':None}]}},
                 {'rule': {'family':'ip','table':'capstone_fwd','chain':'prerouting','handle':3,'expr':[{'port':10443}]}} ]
        txn = m.kernel_change(rows, m.ADMIN + '/32', [m.ADMIN])
        self.assertNotIn('agent_block', txn)
        self.assertNotIn('flush ruleset', txn)
        self.assertNotIn('delete table', txn)
        self.assertEqual(txn.count('insert rule'),4)
        self.assertIn('position 42', txn)
        self.assertIn('ipv6 tcp dport',txn)

    def test_containment_exemptions_and_management_access_are_separate(self):
        fw = (ROOT/'infra/groot-a/fw-v2/capstone-fw.nft').read_text()
        # Guard placement precedes the exemption and all established accepts.
        self.assertLess(fw.index('capstone-management-ext4'),fw.index('ip saddr @never_block accept'))
        self.assertIn('211.170.162.0/24',fw.split('set mgmt_src')[0])
        management = fw.split('set mgmt_src {')[1].split('set spoof_src_ext')[0]
        self.assertNotIn('211.170.162.0/24', management)
        self.assertIn('elements = { 192.168.16.231 }', management)

    def test_forward_rule_match_includes_destination_and_interfaces(self):
        old = '-A CAPSTONE-FWD -s 192.168.16.0/25 -d 10.200.10.10/32 -i ens192 -o ens160 -p tcp -m tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT\n'
        with patch.object(m,'run',return_value=old): self.assertEqual(m.forward_index(m.OLD_SOURCE),1)
        for bad in (old+old,old.replace('10.200.10.10/32','10.200.10.20/32'),old.replace('ens160','ens161')):
            with patch.object(m,'run',return_value=bad),self.assertRaises(ValueError): m.forward_index(m.OLD_SOURCE)

    def test_noop_rollback_never_reloads_or_reapplies(self):
        with tempfile.TemporaryDirectory() as root:
            paths={k:Path(root)/k for k in m.PATHS}
            for p in paths.values(): p.write_bytes(b'before');p.chmod(0o600)
            meta={'files':{k:{'before':m.sha(b'before'),'after':m.sha(b'after')} for k in paths}}
            with patch.object(m,'PATHS',paths),patch.object(m,'checked_file',side_effect=lambda p:p.read_bytes()),patch.object(m,'load',return_value=meta),patch.object(m,'nft_json',return_value=[]),patch.object(m,'run') as run:
                self.assertEqual(m.rollback(Path(root))['status'],'already_original')
                run.assert_not_called()

    def test_rollback_refuses_unrelated_manual_changes(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)/'firewall';p.write_bytes(b'someone else');p.chmod(0o600)
            meta={'files':{'firewall':{'before':m.sha(b'before'),'after':m.sha(b'after')}}}
            with patch.object(m,'PATHS',{'firewall':p}),patch.object(m,'checked_file',side_effect=lambda p:p.read_bytes()),patch.object(m,'load',return_value=meta),patch.object(m,'run') as run:
                with self.assertRaisesRegex(ValueError,'recovery_source_conflict'): m.rollback(Path(root))
                run.assert_not_called()


if __name__ == '__main__': unittest.main()
