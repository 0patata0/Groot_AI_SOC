"""Offline fixture/policy checks; installed Wazuh native suite remains required."""
import hashlib
import json
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


class EvidenceContractTests(unittest.TestCase):
    def setUp(self):
        self.text = (ROOT / 'capstone_vector_rules.xml').read_text()
        self.rules = {r.attrib['id']: r for r in ET.fromstring('<root>' + self.text + '</root>').iter('rule')}

    def test_previous_complete_rule_tree_bytes_preserved(self):
        prefix = self.text.split('<!-- Indexable metadata observations only.', 1)[0]
        prefix = prefix.replace('The ready lane remains no_log. Operational', 'Real attack inputs remain no_log. Operational')
        # Appended section has one separating newline; the old file is exact.
        self.assertEqual(hashlib.sha256(prefix.rstrip('\n').encode() + b'\n').hexdigest(),
                         'b693dbec37f1a1cd497390e0a36513a97bba37ef62c3798b18d1b2cc7229eaf2')

    def test_independent_leaf_has_indexing_options_and_no_correlation_state(self):
        self.assertEqual(self.rules['100260'].findtext('options'), 'no_log')
        for rid in ('100261', '100262'):
            rule = self.rules[rid]
            self.assertEqual(rule.attrib, {'id': rid, 'level': '3'})
            self.assertEqual(rule.findtext('if_sid'), '100260')
            self.assertIsNone(rule.find('if_matched_sid'))
            self.assertEqual({x.text for x in rule.findall('options')}, {'no_email_alert', 'no_full_log'})

    def test_fixture_patterns_and_expected_decoder_limit_are_consistent(self):
        def match(rule, norm):
            for item in rule.findall('field'):
                key = item.attrib['name'].removeprefix('capstone_norm.')
                if key not in norm:
                    return False
                value = norm[key]
                # Mirror documented *stringification only* for offline patterns,
                # not the native matcher. Native tests must confirm real behavior.
                if not isinstance(value, str):
                    value = json.dumps(value, separators=(',', ':'))
                if not re.search(item.text.replace('\\z', '\\Z'), value):
                    return False
            return True
        cases = 0
        for row in (ROOT / 'fixtures/evidence/expected.tsv').read_text().splitlines():
            if not row or row.startswith('#'):
                continue
            name, location, expected = row.split('|')
            norm = json.loads((ROOT / 'fixtures/evidence' / (name + '.jsonl')).read_text())['capstone_norm']
            matches = [rid for rid in ('100261', '100262')
                       if location == 'evidence' and match(self.rules['100260'], norm)
                       and match(self.rules[rid], norm)]
            self.assertEqual(matches, [] if expected == 'reject' else [expected], name)
            cases += 1
        self.assertGreaterEqual(cases, 50)

    def test_ip_regex_accepts_real_compression_and_rejects_invalid_addresses(self):
        rule = self.rules['100261']
        expression = next(x.text for x in rule.findall('field') if x.attrib['name'].endswith('.source_ip')).replace('\\z', '\\Z')
        for ip in ('::', '::1', '2001:db8::', '1:2:3:4:5:6:7:8', '1:2::3:192.0.2.40',
                   '1:2:3:4:5:6:192.0.2.40', '::192.0.2.40', '198.18.0.1'):
            self.assertIsNotNone(re.search(expression, ip), ip)
        for ip in ('211.170.162.110', '211.170.162.111', '1:2:3:4:5:6:7', '1:::2',
                   '1:2:3:4:5:6::192.0.2.40', '::ffff:999.1.1.1', 'fe80::1%eth0', '192.0.2.40\n'):
            self.assertIsNone(re.search(expression, ip), ip)

    def test_localfiles_remain_distinct_and_unchanged_ready_resume_policy(self):
        tree = ET.fromstring('<root>' + (ROOT / 'agent-localfile.xml').read_text() + '</root>')
        rows = {x.findtext('location'): x for x in tree.iter('localfile')}
        self.assertEqual(len(rows), 3)
        for lane in ('ready', 'evidence'):
            row = rows['/var/log/capstone-vector/' + lane + '/normalized.jsonl']
            self.assertEqual(row.findtext('log_format'), 'json')
            self.assertEqual(row.findtext('only-future-events'), 'no')
            self.assertEqual(row.find('only-future-events').attrib['max-size'], '2GB')
        self.assertEqual(rows['/var/log/capstone-vector/canary/normalized.jsonl'].findtext('only-future-events'), 'yes')

    def test_manager_native_suite_runs_before_and_after_restart(self):
        tasks = json.loads((ROOT / 'apply-b.yml').read_text())[0]['tasks']
        block = next(x['block'] for x in tasks if x['name'] == 'Install dedicated shadow evidence and canary rules with rollback')
        test_indexes = [i for i, x in enumerate(block) if x['name'] == 'Test independent indexable evidence boundary without live injection']
        restart_index = next(i for i, x in enumerate(block) if x['name'].startswith('Restart the same'))
        self.assertEqual(len(test_indexes), 2)
        self.assertLess(test_indexes[0], restart_index)
        self.assertGreater(test_indexes[1], restart_index)


if __name__ == '__main__':
    unittest.main()
