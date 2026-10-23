"""Offline inventories from actual rule fixtures; fake Docker/broker for read linkage."""
import hashlib
from pathlib import Path
import unittest
from unittest import mock

import test_rule_change_executor as executor_fixtures


MOD = executor_fixtures.MOD
ROOT = Path(__file__).resolve().parents[2]
WAF_IDS = [10100, 10101, 10200, 10300, 10400, 10500, 10501, 10600, 10601, 10602]
SURICATA_IDS = [1000000, 1000001, 1000002, 1000010, 1000030, 1000031, 1000032,
                1000033, 1000050, 1000051, 1000070, 1000071, 2034802, 2034806]
WAZUH_IDS = [100100, 100101, 100102, 100103, 100110, 100111, 100112,
             100120, 100121, 100122, 100123, 100124, 100125, 100126,
             100127, 100128, 100129, 100130, 100131]
WAF = b'SecRuleEngine DetectionOnly\nSecRule ARGS "@rx test" "id:10100,phase:2,pass,log"\n'
SURICATA = b'alert tcp any any -> any any (msg:"fixture"; sid:1000001; rev:1;)\n'
WAZUH = b'<group name="fixture,"><rule id="100100" level="0"><description>base</description></rule></group>\n'


def sha(data):
    return hashlib.sha256(data).hexdigest()


class InventoryTests(unittest.TestCase):
    def complete(self, kind, data, ids, count=None):
        before = bytes(data)
        result = MOD.rule_inventory(kind, data)
        self.assertEqual(data, before)
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(result['schema_version'], 1)
        self.assertEqual(result['kind'], kind)
        self.assertEqual(result['scope'], 'target_file_definitions')
        self.assertEqual(result['source_sha256'], sha(data))
        self.assertIs(result['runtime_load_verified'], False)
        self.assertEqual(result['ids'], sorted(set(ids)))
        self.assertEqual(result['declared_count'], len(ids) if count is None else count)
        self.assertEqual(result['unique_id_count'], len(set(ids)))
        return result

    def unavailable(self, kind, data):
        result = MOD.rule_inventory(kind, data)
        self.assertEqual(result['status'], 'unavailable')
        self.assertEqual(result['source_sha256'], sha(data))
        self.assertEqual(result['scope'], 'target_file_definitions')
        self.assertIsNone(result['declared_count'])
        self.assertIsNone(result['unique_id_count'])
        self.assertEqual(result['ids'], [])
        self.assertEqual(result['duplicate_ids'], [])
        self.assertEqual(result['contiguous_id_groups'], [])
        self.assertEqual(result['details'], {})
        self.assertEqual(result['error'], 'syntax_or_scope_unsupported')
        self.assertIs(result['runtime_load_verified'], False)
        return result

    def test_actual_waf_has_ten_ids_twelve_directives_and_two_chain_conditions(self):
        data = (ROOT / 'new_rule/GROOT_A_WAF.conf').read_bytes()
        result = self.complete('waf', data, WAF_IDS)
        self.assertEqual(result['details']['secrule_directives'], 12)
        self.assertEqual(result['details']['secaction_directives'], 0)
        self.assertEqual(result['details']['chain_continuations'], 2)
        self.assertNotIn(10010, result['ids'])
        self.assertEqual(result['duplicate_ids'], [])

    def test_actual_suricata_is_twelve_local_plus_two_et_overrides(self):
        data = (ROOT / 'new_rule/GROOT_A_local.rules').read_bytes()
        result = self.complete('suricata', data, SURICATA_IDS)
        self.assertEqual(result['details']['local_sid_count'], 12)
        self.assertEqual(result['details']['et_override_count'], 2)
        self.assertEqual(result['details']['other_sid_count'], 0)
        self.assertEqual(result['details']['noalert_count'], 1)
        self.assertEqual(result['duplicate_ids'], [])

    def test_actual_wazuh_includes_level_zero_base_in_nineteen_definitions(self):
        data = (ROOT / 'infra/groot-b/local_rules.xml').read_bytes()
        result = self.complete('wazuh', data, WAZUH_IDS)
        self.assertEqual(result['details']['level0_count'], 1)
        self.assertEqual(result['details']['level_counts'], {
            '0': 1, '1': 2, '3': 1, '4': 2, '5': 2, '6': 3,
            '7': 1, '8': 1, '9': 1, '10': 2, '12': 3})
        self.assertEqual(result['duplicate_ids'], [])

    def test_id_groups_never_fill_gaps_between_sparse_ids(self):
        result = self.complete('wazuh', (ROOT / 'infra/groot-b/local_rules.xml').read_bytes(), WAZUH_IDS)
        self.assertEqual(result['contiguous_id_groups'], [
            {'start': 100100, 'end': 100103}, {'start': 100110, 'end': 100112},
            {'start': 100120, 'end': 100131}])
        expanded = [number for group in result['contiguous_id_groups']
                    for number in range(group['start'], group['end'] + 1)]
        self.assertEqual(expanded, WAZUH_IDS)
        self.assertNotIn(100104, expanded)
        self.assertNotIn(100113, expanded)

    def test_waf_comment_and_quoted_id_mentions_are_not_rules(self):
        data = (b'# SecAction "id:10010,phase:1,pass"\n'
                b'# Reserved id:19999; chain\n'
                b'SecRuleEngine DetectionOnly\n'
                b'SecRule ARGS "@rx id:18888" "id:10100,phase:2,pass,msg:\'text id:17777, chain\',logdata:\'id:16666\'"\n')
        result = self.complete('waf', data, [10100])
        self.assertEqual(result['details']['secrule_directives'], 1)
        self.assertEqual(result['details']['chain_continuations'], 0)

    def test_waf_multiline_chain_is_one_id_with_two_condition_directives(self):
        data = (b'SecRuleEngine DetectionOnly\n'
                b'SecRule ARGS "@contains fixture" \\\n'
                b' "id:10100,phase:2,chain,\\\n'
                b' msg:\'fixture\'"\n'
                b' SecRule MATCHED_VARS "@rx test" "t:none"\n')
        result = self.complete('waf', data, [10100])
        self.assertEqual(result['details']['secrule_directives'], 2)
        self.assertEqual(result['details']['chain_continuations'], 1)

    def test_waf_secaction_definition_has_its_own_identifier(self):
        data = WAF + b'SecAction "id:10001,phase:1,pass,nolog,setvar:\'tx.fixture=1\'"\n'
        result = self.complete('waf', data, [10001, 10100])
        self.assertEqual(result['details']['secrule_directives'], 1)
        self.assertEqual(result['details']['secaction_directives'], 1)

    def test_waf_escaped_quotes_and_quoted_identifier_keep_payload_ids_out(self):
        data = (br'''SecRule ARGS "@rx \"id:17777\"" "id:'10100',phase:2,pass,msg:'escaped \' quote, id:18888'"''' + b'\n')
        result = self.complete('waf', data, [10100])
        self.assertEqual(result['details']['secrule_directives'], 1)

    def test_waf_removal_directives_do_not_turn_file_definitions_into_runtime_counts(self):
        data = (WAF + b'SecRuleRemoveById 10100\n'
                b'SecRuleUpdateTargetById 10100 "!ARGS:fixture"\n')
        result = self.complete('waf', data, [10100])
        self.assertEqual(result['scope'], 'target_file_definitions')
        self.assertIs(result['runtime_load_verified'], False)

    def test_waf_orphan_chain_member_and_unclosed_chain_are_unavailable(self):
        for data in (b'SecRule ARGS "@rx test" "t:none"\n',
                     b'SecRule ARGS "@rx test" "id:10100,chain,phase:1"\n'):
            with self.subTest(data=data):
                self.unavailable('waf', data)

    def test_waf_include_and_conditional_scope_are_not_reported_as_exact(self):
        for data in (WAF + b'Include /does/not/read/external.conf\n',
                     b'<IfModule mod_security2.c>\n' + WAF + b'</IfModule>\n'):
            with self.subTest(data=data[:40]):
                self.unavailable('waf', data)

    def test_waf_invalid_action_boundary_and_chain_child_id_discard_partial_counts(self):
        invalid_rules = (
            b'SecRule ARGS "@rx test" "id:10101,id:10102,phase:2,pass"\n',
            b'SecRule ARGS "@rx test" "id:10101,phase:2,msg:\'unclosed"\n',
            b'SecRule ARGS "@rx test" "id:10101,chain,phase:2"\n'
            b'SecRule MATCHED_VARS "@rx test" "id:10102,pass"\n',
            b'SecDefaultAction "phase:2,pass,log"\n',
        )
        for suffix in invalid_rules:
            with self.subTest(suffix=suffix):
                self.unavailable('waf', WAF + suffix)

    def test_suricata_comments_and_option_like_payload_are_not_ids(self):
        data = (b'# alert tcp any any -> any any (sid:1000099; rev:1;)\n'
                b'alert tcp any any -> any any (msg:"quoted sid:1000088; rev:999;"; '
                b'content:"sid:1000077;"; sid:1000001; rev:1;)\n')
        self.complete('suricata', data, [1000001])

    def test_suricata_continuation_and_noalert_marker_are_counted_once(self):
        data = (b'alert tcp any any -> any any ( \\\n'
                b' msg:"marker"; flowbits:set,fixture; \\\n'
                b' flowbits:noalert; sid:1000000; rev:1;)\n')
        result = self.complete('suricata', data, [1000000])
        self.assertEqual(result['details']['local_sid_count'], 1)
        self.assertEqual(result['details']['noalert_count'], 1)

    def test_suricata_unterminated_rule_missing_sid_and_indentation_are_unavailable(self):
        for data in (b'alert tcp any any -> any any (msg:"unterminated; sid:1000001;)\n',
                     b'alert tcp any any -> any any (msg:"missing"; rev:1;)\n',
                     b' ' + SURICATA):
            with self.subTest(data=data):
                self.unavailable('suricata', data)

    def test_suricata_duplicate_sid_options_and_nondefault_generator_discard_partial_counts(self):
        invalid_rules = (
            b'alert tcp any any -> any any (sid:1000002; sid:1000003; rev:1;)\n',
            b'alert tcp any any -> any any (gid:2; sid:1000002; rev:1;)\n',
            b'alert tcp any any -> any any (gid:1; gid:1; sid:1000002; rev:1;)\n',
            b'alert tcp any any -> any any (sid:4294967296; rev:1;)\n',
            b'pass tcp any any -> any any (sid:1000002; rev:1;)\n',
        )
        for suffix in invalid_rules:
            with self.subTest(suffix=suffix):
                self.unavailable('suricata', SURICATA + suffix)

    def test_suricata_other_sid_category_and_default_gid_are_explicit(self):
        data = SURICATA + b'alert tcp any any -> any any (gid:1; sid:3000001; rev:1;)\n'
        result = self.complete('suricata', data, [1000001, 3000001])
        self.assertEqual(result['details'], {
            'local_sid_count': 1, 'et_override_count': 0,
            'other_sid_count': 1, 'noalert_count': 0})

    def test_wazuh_multiple_groups_comments_and_other_id_fields(self):
        data = (b'<!-- <rule id="199999" level="15"/> -->\n' + WAZUH +
                b'<group name="second,"><rule id="100110" level="9"><if_sid>86601</if_sid>'
                b'<mitre><id>T1190</id></mitre><description><![CDATA[<rule id="188888"/>]]></description>'
                b'</rule></group>\n')
        result = self.complete('wazuh', data, [100100, 100110])
        self.assertEqual(result['details']['level_counts'], {'0': 1, '9': 1})

    def test_wazuh_doctype_entities_and_malformed_xml_are_unavailable(self):
        for data in (b'<!DOCTYPE rules [<!ENTITY x SYSTEM "file:///never-read">]>' + WAZUH,
                     b'<!ENTITY x "fixture">' + WAZUH,
                     b'<group name="x,"><rule id="100100" level="0"></group>'):
            with self.subTest(data=data[:30]):
                self.unavailable('wazuh', data)

    def test_wazuh_namespace_nested_rules_and_outside_text_discard_partial_counts(self):
        unsupported = (
            b'<group xmlns="urn:fixture" name="x,"><rule id="100101" level="3"/></group>',
            b'<group name="x,"><rule id="100101" level="3"><rule id="100102" level="5"/></rule></group>',
            b'<group name="x,"><rule id="100101" level="3"><x:description xmlns:x="urn:fixture"/></rule></group>',
            b'<group name="x,"><rule id="100101" level="99"/></group>',
            b'<group name="x,"><rule id="100101" level="3"/></group>unparsed tail',
        )
        for suffix in unsupported:
            with self.subTest(suffix=suffix):
                self.unavailable('wazuh', WAZUH + suffix)

    def test_duplicate_declarations_are_exposed_without_claiming_engine_validity(self):
        fixtures = [('waf', WAF + WAF, 10100),
                    ('suricata', SURICATA + SURICATA, 1000001),
                    ('wazuh', WAZUH + WAZUH, 100100)]
        for kind, data, rid in fixtures:
            with self.subTest(kind=kind):
                result = self.complete(kind, data, [rid], count=2)
                self.assertEqual(result['duplicate_ids'], [rid])
                self.assertIs(result['runtime_load_verified'], False)

    def test_unsupported_kind_and_invalid_utf8_do_not_claim_zero_rules(self):
        self.unavailable('unknown', WAF)
        for kind in ('waf', 'suricata', 'wazuh'):
            with self.subTest(kind=kind):
                self.unavailable(kind, b'\xff\xfe')

    def test_bounded_and_control_character_inputs_never_return_partial_counts(self):
        for kind, valid in (('waf', WAF), ('suricata', SURICATA), ('wazuh', WAZUH)):
            invalid = (valid + b'\x00', valid.replace(b'\n', b'\r\n'),
                       valid + '\u202e'.encode(), b' ' * (MOD.MAX_CANDIDATE + 1))
            for data in invalid:
                with self.subTest(kind=kind, length=len(data), suffix=data[-8:]):
                    self.unavailable(kind, data)

    def test_inventory_never_opens_referenced_paths_or_calls_external_commands(self):
        with mock.patch('builtins.open', side_effect=AssertionError('unexpected file access')), \
                mock.patch.object(MOD.subprocess, 'run', side_effect=AssertionError('unexpected command')):
            self.complete('waf', WAF, [10100])
            self.complete('suricata', SURICATA, [1000001])
            self.complete('wazuh', WAZUH, [100100])
            self.unavailable('waf', WAF + b'Include /does/not/read/external.conf\n')
            self.unavailable('wazuh', b'<!DOCTYPE rules SYSTEM "file:///does/not/read/external.xml">' + WAZUH)


class TargetInventoryLinkageTests(unittest.TestCase):
    def setUp(self):
        self.fixture = executor_fixtures.ExecutorTests('runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)

    def test_get_target_metadata_matches_same_content_and_sha_on_all_three_targets(self):
        for kind in ('waf', 'suricata', 'wazuh'):
            with self.subTest(kind=kind):
                engine, runner, target, current = self.fixture.engine(kind)
                path = Path(engine.targets[target]['path'])
                before = path.read_bytes()
                result = engine.get_target(target)
                inventory = result['rule_inventory']
                self.assertEqual(result['content'].encode(), current)
                self.assertEqual(result['sha256'], sha(current))
                self.assertEqual(inventory['source_sha256'], result['sha256'])
                self.assertEqual(inventory, MOD.rule_inventory(kind, current))
                self.assertEqual(path.read_bytes(), before)
                self.assertEqual(runner.restart_count, 0)
                self.assertEqual(self.fixture.broker.rows, {})
                self.assertFalse(any(command[1] in ('restart', 'cp', 'stop', 'start') for command in runner.commands))

    def test_metadata_uses_snapshot_bytes_instead_of_rereading_target_file(self):
        engine, runner, target, current = self.fixture.engine('waf')
        path = Path(engine.targets[target]['path'])
        stat = path.stat()
        changed = current + b'SecRule ARGS "@rx second" "id:10101,phase:2,pass"\n'
        path.write_bytes(changed)
        with mock.patch.object(engine, '_snapshot', return_value=(current, stat, {})):
            result = engine.get_target(target)
        self.assertEqual(result['sha256'], sha(current))
        self.assertEqual(result['rule_inventory']['source_sha256'], sha(current))
        self.assertEqual(result['rule_inventory']['ids'], [10100])
        self.assertEqual(path.read_bytes(), changed)
        self.assertEqual(self.fixture.broker.rows, {})

    def test_unsupported_inventory_preserves_readable_content_and_original_sha(self):
        engine, _, target, _ = self.fixture.engine('waf')
        unsupported = WAF + b'Include /never-opened/by-inventory.conf\n'
        Path(engine.targets[target]['path']).write_bytes(unsupported)
        result = engine.get_target(target)
        self.assertEqual(result['content'].encode(), unsupported)
        self.assertEqual(result['sha256'], sha(unsupported))
        self.assertEqual(result['rule_inventory']['status'], 'unavailable')
        self.assertIsNone(result['rule_inventory']['unique_id_count'])
        self.assertEqual(self.fixture.broker.rows, {})

    def test_existing_fixed_target_and_host_restrictions_are_unchanged(self):
        engine, runner, _, _ = self.fixture.engine('waf')
        for target in ('b:wazuh-local-rules', '/etc/passwd', 'a:other-rules'):
            with self.subTest(target=target):
                with self.assertRaises(MOD.RuleChangeError):
                    engine.get_target(target)
        self.assertEqual(runner.commands, [])
        self.assertEqual(self.fixture.broker.rows, {})


if __name__ == '__main__':
    unittest.main()
