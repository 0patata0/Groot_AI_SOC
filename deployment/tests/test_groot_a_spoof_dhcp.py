"""A anti-spoof: benign DHCP client broadcasts are dropped without a SPOOF log.

Live A (2026-11-13): 100% of SPOOF kernel lines were one device's DHCP
DISCOVER broadcasts (ens192 0.0.0.0:68 -> 255.255.255.255:67), ~8,600/day,
filling the history-auto store. The candidate keeps dropping them but stops
logging only that exact pattern; every other spoofed source is still logged.
"""
import hashlib
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
CURRENT = (ROOT / 'infra/groot-a/fw-v2/capstone-fw.nft').read_text()
CANDIDATE = (ROOT / 'infra/validation/spoof-dhcp/capstone-fw.candidate.nft').read_text()
APPLY = (ROOT / 'infra/validation/spoof-dhcp/apply_a.py').read_text()
RULE = ('        iifname "ens192" ip saddr 0.0.0.0 ip daddr 255.255.255.255 udp sport 68 udp dport 67 counter drop '
        'comment "DHCP client broadcast from 0.0.0.0 (RFC 2131); A serves no DHCP on ens192 - never logged"\n')
SPOOF_LOG = ('        iifname "ens192" ip saddr @spoof_src_ext update @spoof_meter { ip saddr limit rate 6/minute burst 3 packets } '
             'log prefix "SPOOF " level notice\n')


def chain(text):
    body = text.split('chain prerouting_block {', 1)[1].split('\n    }', 1)[0]
    return [l for l in body.splitlines(True) if l.strip() and not l.strip().startswith('#')]


class Candidate(unittest.TestCase):
    def test_one_narrow_drop_rule_directly_before_the_spoof_log(self):
        rules = chain(CANDIDATE)
        self.assertEqual(rules.count(RULE), 1)
        self.assertEqual(rules.index(RULE) + 1, rules.index(SPOOF_LOG))
        self.assertIn(' drop ', RULE)
        self.assertNotIn(' log ', RULE)
        self.assertNotIn('accept', RULE)

    def test_exemption_matches_only_the_dhcp_broadcast_pattern(self):
        # source exactly 0.0.0.0 (not /8), limited broadcast, client->server ports, external NIC only
        for token in ('iifname "ens192"', 'ip saddr 0.0.0.0 ', 'ip daddr 255.255.255.255', 'udp sport 68', 'udp dport 67'):
            self.assertIn(token, RULE)
        self.assertNotIn('0.0.0.0/8', RULE)

    def test_everything_else_is_unchanged(self):
        removed = CANDIDATE.replace(RULE, '', 1)
        removed = re.sub(r'#      2026-11-13: .*\n#      SPOOF 로그의 .*\n', '', removed, count=1)
        self.assertEqual(removed, CURRENT)
        # the remaining SPOOF logging (ens192 other sources, ens160 non-internal) still exists
        self.assertEqual(chain(CANDIDATE).count(SPOOF_LOG), 1)
        self.assertEqual(sum('log prefix "SPOOF "' in r for r in chain(CANDIDATE)), 2)
        self.assertIn('0.0.0.0/8', CANDIDATE.split('set spoof_src_ext {', 1)[1].split('}', 1)[0])


class ApplyScript(unittest.TestCase):
    def test_pins_reviewed_files_and_exact_rule(self):
        cur = re.search(r"CURRENT_SHA = '([0-9a-f]{64})'", APPLY)[1]
        cand = re.search(r"CANDIDATE_SHA = '([0-9a-f]{64})'", APPLY)[1]
        self.assertEqual(cur, hashlib.sha256(CURRENT.encode()).hexdigest())
        self.assertEqual(cand, hashlib.sha256(CANDIDATE.encode()).hexdigest())
        self.assertIn(RULE.strip().replace('        ', ''), APPLY.replace("'\n        '", ''))

    def test_live_change_is_a_single_insert_without_table_reload(self):
        self.assertIn("'nft', 'insert', 'rule', 'inet', 'capstone_fw', 'prerouting_block', 'handle'", APPLY)
        self.assertNotIn("'nft', '-f'", APPLY)
        self.assertIn('delete table inet capstone_fw', APPLY)   # only inside the nft -c check transaction
        self.assertIn("['nft', '-c', '-f', tx]", APPLY)


if __name__ == '__main__':
    unittest.main()
