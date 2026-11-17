"""Do not let a global CIDR change bypass public inspection or delete ownership.

These are candidate-file counterexamples, not operating load/route evidence.
"""
from pathlib import Path
import importlib.util
import json
import unittest

ROOT = Path(__file__).parents[2]
spec = importlib.util.spec_from_file_location('management_device_file_test', ROOT / 'deployment/management_policy_render.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
OLD = ['192.168.16.231/32']
NEW = ['192.0.2.20/32', '198.51.100.15/32']
FW = b'''# never_block and mgmt_src in comments are not declarations.
table inet capstone_fw {
 set never_block {
  type ipv4_addr
  flags interval
  comment "not a declaration: elements = { 0.0.0.0/0 }"
  elements = { 10.200.10.0/24, 127.0.0.0/8, 192.168.16.231 }
 }
 set mgmt_src {
  type ipv4_addr
  flags interval
  elements = { 192.168.16.231 }
 }
 set agent_block { type ipv4_addr; flags timeout; elements = { 203.0.113.80 timeout 10m } }
 chain input { type filter hook input priority 0; policy drop; ip saddr @mgmt_src accept; }
}
'''
INFRA = ['10.200.10.0/24', '127.0.0.0/8']


def proxy_source():
    servers = []
    for name in sorted(m.WAZUH_NAMES):
        servers.append(''' server {
  server_name ''' + name + ''';
  # Quoted/comment braces must never confuse server boundaries: { }
  add_header X-Description "not a brace: } # ; {";
  allow 192.168.16.231; # named administrator only
  deny all;
  location / { proxy_pass https://10.200.10.10:443; }
 }
''')
    public = ''' server {
  server_name log4shell.grootlab.duckdns.org;
  allow all; deny all;
  modsecurity on;
  location / { proxy_pass http://waf; }
 }
'''
    return ('events { worker_connections 1024; }\nhttp {\n' + ''.join(servers) + public + '}\n').encode()


class DeviceFileTests(unittest.TestCase):
    def test_protected_roles_preserved_and_dynamic_ttl_bytes_untouched(self):
        result = m.firewall(FW, OLD, NEW, INFRA)
        parsed = m.firewall_sets(result)
        self.assertEqual(parsed['mgmt_src']['cidrs'], NEW)
        self.assertEqual(set(parsed['never_block']['cidrs']), set(INFRA + NEW))
        self.assertIn(b'set agent_block { type ipv4_addr; flags timeout; elements = { 203.0.113.80 timeout 10m } }', result)
        self.assertIn(b'chain input { type filter hook input priority 0; policy drop; ip saddr @mgmt_src accept; }', result)
        self.assertEqual(m.firewall(result, NEW, NEW, INFRA), result)

    def test_reversible_administrator_change_restores_effective_roles(self):
        changed = m.firewall(FW, OLD, NEW, INFRA)
        reverted = m.firewall(changed, NEW, OLD, INFRA)
        for name in ('mgmt_src', 'never_block'):
            self.assertEqual(m.firewall_sets(reverted)[name]['cidrs'], m.firewall_sets(FW)[name]['cidrs'])

    def test_foreign_protection_edit_cannot_be_erased(self):
        changed = FW.replace(b'10.200.10.0/24,', b'203.0.113.8, 10.200.10.0/24,')
        with self.assertRaisesRegex(ValueError, 'baseline_changed'):
            m.firewall(changed, OLD, NEW, INFRA)

    def test_missing_infrastructure_or_wrong_old_admin_refused(self):
        for old, infra in [(['192.0.2.1/32'], INFRA), (OLD, INFRA[:1])]:
            with self.subTest(old=old, infra=infra), self.assertRaisesRegex(ValueError, 'baseline_changed'):
                m.firewall(FW, old, NEW, infra)

    def test_ownership_overlap_refused(self):
        with self.assertRaisesRegex(ValueError, 'ownership_overlap'):
            m.firewall(FW, OLD, NEW, INFRA + OLD)

    def test_shared_larger_infrastructure_range_is_not_removed(self):
        raw = FW.replace(b'10.200.10.0/24,', b'192.168.16.0/24, 10.200.10.0/24,')
        result = m.firewall(raw, OLD, NEW, INFRA + ['192.168.16.0/24'])
        self.assertIn('192.168.16.0/24', m.firewall_sets(result)['never_block']['cidrs'])
        # Retaining a shared role can still protect the previous address; it
        # must not be reported as an all-role removal by the later worker.
        self.assertNotIn('192.168.16.231/32', m.firewall_sets(result)['mgmt_src']['cidrs'])

    def test_duplicate_or_wrong_family_table_set_refused(self):
        for raw in (FW + FW, FW.replace(b'table inet', b'table ip'),
                    FW.replace(b'type ipv4_addr', b'type ipv6_addr', 1)):
            with self.subTest(raw=raw[:70]), self.assertRaises(ValueError):
                m.firewall(raw, OLD, NEW, INFRA)

    def test_named_set_in_other_table_does_not_replace_fixed_policy(self):
        unrelated = b'table inet other { set mgmt_src { type ipv4_addr; elements = { 203.0.113.1 }; } }\n'
        result = m.firewall(unrelated + FW, OLD, NEW, INFRA)
        self.assertTrue(result.startswith(unrelated))

    def test_no_administrator_text_injection_or_all_sources(self):
        for new in (['0.0.0.0/0'], ['192.0.2.1; accept'], ['::1'], ['192.0.2.1\n']):
            with self.subTest(new=new), self.assertRaises(ValueError):
                m.firewall(FW, OLD, new, INFRA)

    def test_real_source_preserves_unowned_sets_and_chains(self):
        raw = (ROOT / 'infra/groot-a/fw-v2/capstone-fw.nft').read_bytes()
        before = m.firewall_sets(raw)
        infrastructure = [x for x in before['never_block']['cidrs'] if x not in OLD]
        after = m.firewall(raw, OLD, NEW, infrastructure)
        def masked(value):
            text = value.decode()
            for span in sorted((x['span'] for x in m.firewall_sets(value).values()), reverse=True):
                text = text[:span[0]] + '<managed-elements>' + text[span[1]:]
            return text
        self.assertEqual(masked(raw), masked(after))

    def test_proxy_changes_both_management_names_preserves_public_waf(self):
        raw = proxy_source()
        result = m.proxy(raw, OLD, NEW)
        for address in NEW:
            self.assertEqual(result.count(('allow ' + address + ';').encode()), 2)
        public = raw[raw.index(b' server {\n  server_name log4shell'):]
        self.assertTrue(result.endswith(public))
        self.assertEqual(m.proxy(result, NEW, NEW), result)

    def test_proxy_false_allow_all_before_deny_not_a_management_acl(self):
        with self.assertRaises(ValueError):
            m.proxy(proxy_source().replace(b'allow 192.168.16.231;', b'allow all;', 1), OLD, NEW)

    def test_proxy_deny_order_or_missing_deny_refused(self):
        for replacement in (b'deny all; allow 192.168.16.231;', b'allow 192.168.16.231;'):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                m.proxy(proxy_source().replace(b'allow 192.168.16.231; # named administrator only\n  deny all;', replacement, 1), OLD, NEW)

    def test_proxy_unknown_nested_acl_include_and_satisfy_refused(self):
        for change in (b'allow all; ', b'include extra.conf; ', b'satisfy any; ', b'limit_except GET { deny all; } '):
            raw = proxy_source().replace(b'location / { proxy_pass', b'location / { ' + change + b'proxy_pass', 1)
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'acl_override'):
                m.proxy(raw, OLD, NEW)

    def test_proxy_missing_or_alias_duplicate_management_name_refused(self):
        for raw in (proxy_source().replace(b'wazuh.groot.lab', b'other.lab'),
                    proxy_source().replace(b'wazuh.groot.lab;', b'wazuh.groot.lab other.lab;'),
                    proxy_source().replace(b'wazuh.grootlab.duckdns.org', b'wazuh.groot.lab')):
            with self.subTest(raw=raw[:50]), self.assertRaises(ValueError):
                m.proxy(raw, OLD, NEW)

    def test_proxy_cannot_drop_intervening_non_acl_directive(self):
        raw = proxy_source().replace(b'deny all;', b'proxy_read_timeout 300s; deny all;', 1)
        with self.assertRaisesRegex(ValueError, 'not_contiguous'):
            m.proxy(raw, OLD, NEW)

    def test_proxy_real_template_is_supported(self):
        raw = (ROOT / 'infra/groot-a/chatproxy.nginx.conf').read_bytes()
        result = m.proxy(raw, OLD, NEW)
        self.assertIn(b'server_name log4shell.grootlab.duckdns.org;', result)
        self.assertEqual(raw.count(b'modsecurity'), result.count(b'modsecurity'))

    def test_threshold_only_selected_signature_source_and_unrelated_rules_unchanged(self):
        original = (b'# suppress gen_id 1, sig_id 2001219, track by_src, ip 0.0.0.0/0\n'
                    b'suppress gen_id 1, sig_id 2001219, track by_src, ip 192.168.16.231/32\n'
                    b'threshold gen_id 1, sig_id 1000090, type both, track by_src, count 10, seconds 60\n')
        result = m.threshold(original, OLD, NEW)
        self.assertTrue(result.startswith(original.splitlines(keepends=True)[0]))
        self.assertTrue(result.endswith(original.splitlines(keepends=True)[2]))
        self.assertEqual(result.count(b'sig_id 2001219, track by_src, ip '), 3)
        self.assertEqual(m.threshold(result, NEW, NEW), result)

    def test_threshold_wrong_old_or_missing_policy_refused(self):
        for raw in (b'', b'suppress gen_id 1, sig_id 2001219, track by_src, ip 192.0.2.1/32\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                m.threshold(raw, OLD, NEW)

    def test_threshold_duplicate_and_unknown_policy_not_silently_kept(self):
        raw = b'suppress gen_id 1, sig_id 2001219, track by_src, ip 192.168.16.231/32\n'
        for suffix in (raw, b'suppress gen_id 1, sig_id 2001219, track by_dst, ip 192.0.2.0/24\n'):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                m.threshold(raw + suffix, OLD, NEW)

    def test_lab_missing_assignment_can_replace_implicit_default_without_secret_changes(self):
        raw = b'# configuration\nTOKEN_FILE=/root/private.key\nOPAQUE_VALUE=must-stay-byte-identical\n'
        result = m.lab_environment(raw, NEW)
        self.assertTrue(result.startswith(raw))
        self.assertTrue(result.endswith(('OFFLINE_LABS_ADMIN_CIDRS=' + ','.join(NEW) + '\n').encode()))
        self.assertEqual(m.lab_environment(result, NEW), result)

    def test_lab_duplicate_export_or_shell_prefix_refused(self):
        for raw in (b'OFFLINE_LABS_ADMIN_CIDRS=192.0.2.1/32\nexport OFFLINE_LABS_ADMIN_CIDRS=192.0.2.2/32\n',
                    b'export OFFLINE_LABS_ADMIN_CIDRS=192.0.2.1/32\n',
                    b' OFFLINE_LABS_ADMIN_CIDRS=192.0.2.1/32\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                m.lab_environment(raw, NEW)

    def test_lab_existing_assignment_only_is_changed(self):
        raw = b'TOKEN_FILE=/root/key\nOFFLINE_LABS_ADMIN_CIDRS=192.0.2.1/32\nOTHER=123\n'
        result = m.lab_environment(raw, NEW)
        self.assertEqual(result.splitlines()[0], raw.splitlines()[0])
        self.assertEqual(result.splitlines()[-1], raw.splitlines()[-1])
        self.assertEqual(m.lab_environment(result, OLD).splitlines()[1], b'OFFLINE_LABS_ADMIN_CIDRS=192.168.16.231/32')

    def test_sources_malformed_quote_brace_bytes_and_excess_nesting_refused(self):
        for raw in (b'\xff', b'x\x00y', b'x\ry', b'http {', b'http }', b'"unterminated', b'x{' * 65 + b'}' * 65):
            with self.subTest(raw=raw[:40]), self.assertRaises((ValueError, UnicodeError)):
                m.proxy(raw, OLD, NEW)

    def host_config(self, host):
        return {'schema': 1, 'role': {'a': 'security', 'b': 'siem', 'c': 'service'}[host],
                'security_host': '10.200.10.1', 'siem_host': '10.200.10.10', 'service_host': '10.200.10.20',
                'interface': 'ens160', 'ssh_port': 22, 'web_port': 80, 'legacy_bridge': 'docker0',
                'allow_legacy_management_http': False, 'management_cidrs': [],
                'dashboard_cidrs': ['198.51.100.0/24'], 'chat_cidrs': [],
                'dashboard_denied_cidrs': ['203.0.113.0/24']}

    def test_host_downstream_uses_gateway_peer_not_raw_administrator(self):
        for host in 'bc':
            original = self.host_config(host)
            result = m.host_guard(json.dumps(original).encode(), host, NEW)
            changed = json.loads(result)
            self.assertEqual(changed.pop('management_cidrs'), ['10.200.10.1/32'])
            original.pop('management_cidrs')
            self.assertEqual(changed, original)
            self.assertEqual(m.host_guard(result, host, NEW), result)

    def test_host_gateway_policy_preserves_dashboard_chat_and_bridge(self):
        original = self.host_config('a')
        changed = json.loads(m.host_guard(json.dumps(original).encode(), 'a', NEW))
        self.assertEqual(changed.pop('management_cidrs'), NEW)
        original.pop('management_cidrs')
        self.assertEqual(original, changed)

    def test_host_role_confusion_unknown_fields_and_duplicate_peer_refused(self):
        original = self.host_config('b')
        for host, value in [('c', original), ('d', original), ('b', {**original, 'sudo': True}),
                            ('b', {**original, 'siem_host': original['security_host']})]:
            with self.subTest(host=host, value=value), self.assertRaises(ValueError):
                m.host_guard(json.dumps(value).encode(), host, NEW)
        with self.assertRaisesRegex(ValueError, 'duplicate_field'):
            m.host_guard(json.dumps(original).replace('"schema": 1', '"schema": 1, "schema": 1').encode(), 'b', NEW)

    def test_wazuh_preserves_unmanaged_safeguards_and_other_configuration_bytes(self):
        original = (b'<ossec_config>\n  <global>\n    <white_list>127.0.0.1</white_list>\n'
                    b'    <white_list>^localhost$</white_list>\n    <email_notification>no</email_notification>\n  </global>\n'
                    b'  <active-response><command>fixed</command></active-response>\n</ossec_config>\n')
        result = m.wazuh_whitelist(original, NEW)
        self.assertEqual(result.count(b'<white_list>'), 4)
        self.assertIn(b'<white_list>127.0.0.1</white_list>', result)
        self.assertIn(b'<white_list>^localhost$</white_list>', result)
        self.assertIn(b'<email_notification>no</email_notification>', result)
        self.assertTrue(result.endswith(original[original.index(b'  <active-response>'):]))
        self.assertEqual(m.wazuh_whitelist(result, NEW), result)
        reverted = m.wazuh_whitelist(result, OLD)
        self.assertNotIn(b'<white_list>192.0.2.20/32</white_list>', reverted)

    def test_wazuh_fake_global_tags_in_comments_do_not_change_scope(self):
        raw = b'<!-- <global><white_list>all</white_list></global> --><ossec_config><global></global></ossec_config>'
        result = m.wazuh_whitelist(raw, NEW)
        self.assertTrue(result.startswith(raw[:raw.index(b'<ossec_config>')]))

    def test_wazuh_real_two_global_layout_targets_only_whitelist_fragment(self):
        settings = b'<global><jsonout_output>yes</jsonout_output><alerts_log>yes</alerts_log></global>\n'
        raw = b'<ossec_config>\n' + settings + b'<global><white_list>127.0.0.1</white_list><white_list>^localhost$</white_list></global>\n</ossec_config>'
        result = m.wazuh_whitelist(raw, NEW)
        self.assertIn(settings, result)
        self.assertLess(result.index(b'</global>'), result.index(m.WAZUH_BEGIN.encode()))
        self.assertEqual(m.wazuh_whitelist(result, NEW), result)

    def test_wazuh_several_unowned_whitelist_fragments_need_explicit_migration(self):
        raw = b'<ossec_config><global><white_list>127.0.0.1</white_list></global><global><white_list>192.0.2.1</white_list></global></ossec_config>'
        with self.assertRaisesRegex(ValueError, 'unique_global'):
            m.wazuh_whitelist(raw, NEW)

    def test_wazuh_external_entities_duplicate_or_missing_global_refused(self):
        for raw in (b'<!DOCTYPE ossec_config [<!ENTITY secret SYSTEM "file:///root/secret">]><ossec_config><global/></ossec_config>',
                    b'<ossec_config><global></global><global></global></ossec_config>',
                    b'<ossec_config/>', b'<wrong><global></global></wrong>', b'<ossec_config><global>'):
            with self.subTest(raw=raw[:80]), self.assertRaises(ValueError):
                m.wazuh_whitelist(raw, NEW)
        with self.assertRaisesRegex(ValueError, 'empty_global_syntax'):
            m.wazuh_whitelist(b'<ossec_config><global/></ossec_config>', NEW)

    def test_wazuh_marker_outside_global_or_wrong_order_refused(self):
        for raw in ((m.WAZUH_BEGIN + m.WAZUH_END + '<ossec_config><global></global></ossec_config>').encode(),
                    ('<ossec_config><global>' + m.WAZUH_END + m.WAZUH_BEGIN + '</global></ossec_config>').encode()):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                m.wazuh_whitelist(raw, NEW)

    def test_wazuh_unknown_owned_block_content_not_deleted(self):
        for body in ('<white_list>0.0.0.0/0</white_list>', '<other>do-not-delete</other>',
                     '<white_list a="1">192.0.2.1/32</white_list>', 'text<white_list>192.0.2.1/32</white_list>'):
            raw = ('<ossec_config><global>' + m.WAZUH_BEGIN + body + m.WAZUH_END + '</global></ossec_config>').encode()
            with self.subTest(body=body), self.assertRaises(ValueError):
                m.wazuh_whitelist(raw, NEW)


if __name__ == '__main__':
    unittest.main()
