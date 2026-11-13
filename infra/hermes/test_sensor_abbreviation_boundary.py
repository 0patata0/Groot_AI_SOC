"""Latin sensor abbreviations are standalone tokens (2026-11-14 00:01 joint-channel run).

The second, otherwise consistent Hermes draft fell back because the checker
read the Wazuh field name "sensor_rule_ids" as an uncalled IDS (pattern
Suricata|IDS, case-insensitive, no boundary). The same unbounded names decide
the sensor in three more checks, and Python's Unicode \\b misses "SID가" and
"TLS가". One shared token rule now covers all of them.
"""
import re
import unittest

import soc_management_run as m

FACTS = [{'kind': 'events', 'source': 'modsecurity', 'returned_count': 0, 'indexed_window_total_count': None},
         {'kind': 'events', 'source': 'wazuh', 'returned_count': 10, 'indexed_window_total_count': None}]
WAZUH_ONLY = [{'kind': 'events', 'source': 'wazuh', 'returned_count': 10, 'indexed_window_total_count': None}]
SURICATA = 'unobserved_event_source:suricata'
MODSECURITY = 'unobserved_event_source:modsecurity'
OK_READS = {'mcp__security_events__search_modsecurity_alerts', 'mcp__security_events__search_wazuh_alerts'}

# The two lines rejected in the live run (verbatim) and the whole second draft.
LIVE_LINES = (
    '| **Wazuh 경보 상세** | 규칙 ID: 5501, 5715 · level: 3 | sensor_rule_ids 모두 null/미기재. timestamp_kst는 모두 '
    '2026-11-14T00:01:54경 (±초 단위). source_ip 일부는 `172.17.0.2`, others null/dst_ip null. PAM(sshd) 로그가 '
    '수집되었으나 표본 10건만으로 행위자·공격 여부 확정 불가. |',
    '- **Wazuh (search_wazuh_alerts)**: `returned_count=10`, `indexed_window_total_count=null`. 10건의 표본 시각은 모두 '
    '`2026-11-14T00:01:54` 초 단위입니다. Wazuh 규칙 ID는 5501과 5715이며, 모든 행의 `sensor_rule_ids` 필드가 비어 '
    '있습니다. PAM/SSH 로그가 수집 에이전트 groot-siem-host(172.17.0.x 대역 포함)에서 포착되었으나, 표본 내 '
    'sensor_rule_ids 부재와 제한된 수량으로 이 이벤트가 실제 네트워크 공격 흐름인지 아니면 서비스 간 내부 인증인지를 '
    '확정할 증거가 **현재 조회 결과에 없음**.')
LIVE_DISPOSITION = (
    'INCIDENT_DISPOSITION: {"assessment": "unresolved", "basis": "ModSecurity와 Wazuh 제한 표본 결과 각각 returned_count 0/10 '
    '(전체 구간 건수 indexed_window_total_count 모두 null 미확인). Wazuh 반환 10건은 sensor_rule_ids가 모두 비어 있고 '
    'timestamp_kst가 2026-11-14T00:01:54KST로 동일 초에만 발생하여 전체 표본의 범위가 제한됨. source_ip 일부는 172.17.0.2이나 '
    'dst_ip null로 목적지 추적 불가. 표본으로 행위자·공격/정상 확정 불가.", "evidence_tools": '
    '["mcp__security_events__search_modsecurity_alerts", "mcp__security_events__search_wazuh_alerts"]}')


class UnobservedSourceNames(unittest.TestCase):
    def test_live_field_name_lines_are_not_ids_claims(self):
        for line in LIVE_LINES:
            with self.subTest(line=line[:40]):
                self.assertNotIn(SURICATA, m.evidence_claim_violations(line, FACTS, OK_READS))
        report = '\n'.join(LIVE_LINES) + '\n\n' + LIVE_DISPOSITION + '\nMANAGEMENT_STATUS: needs_review'
        self.assertEqual(m.evidence_claim_violations(report, FACTS, OK_READS), [])
        self.assertEqual(m.rejected_report_lines(report, FACTS, OK_READS, [SURICATA]), [])

    def test_identifiers_and_host_ids_are_not_suricata(self):
        for line in ('HIDS(Wazuh) 경보 10건 반환', 'Wazuh rule ids 5501, 5715 경보 10건', 'agent_ids 003 경보 10건',
                     'wazuh_rule_ids 5501 경보 10건'):
            with self.subTest(line=line):
                self.assertNotIn(SURICATA, m.evidence_claim_violations(line, FACTS))

    def test_real_suricata_claims_are_still_rejected(self):
        for line in ('Suricata 경보 0건', 'IDS 탐지 없음', 'IDS가 경보 10건을 탐지했다', 'NIDS 경보 없음',
                     '웹/WAF(Suricata/ModSecurity) 위주 외부 경보 | 현재 30분 구간 내 위협탐지 없음',
                     '| **Wazuh IDS/상관 경보** | **표본 반환 10건 · 전체 건수 미확인** |'):
            with self.subTest(line=line):
                self.assertIn(SURICATA, m.evidence_claim_violations(line, FACTS))
        self.assertNotIn(SURICATA, m.evidence_claim_violations('Suricata 경보는 이번에 조회하지 않음', FACTS))

    def test_modsecurity_names_keep_target_spelling_but_not_field_names(self):
        self.assertIn(MODSECURITY, m.evidence_claim_violations('a:waf 경보 0건', WAZUH_ONLY))
        self.assertIn(MODSECURITY, m.evidence_claim_violations('WAF는 경보가 없었음', WAZUH_ONLY))
        self.assertNotIn(MODSECURITY, m.evidence_claim_violations('waf_action 필드 이벤트 10건', WAZUH_ONLY))


class SensorAttribution(unittest.TestCase):
    SURICATA_FACTS = [{'kind': 'events', 'source': 'suricata', 'returned_count': 2, 'indexed_window_total_count': None,
                       'sensor_rule_ids': ['2100498'], 'wazuh_rule_ids': ['86601']}]

    def test_wazuh_rule_field_is_not_a_sensor_label(self):
        issue = 'wazuh_rule_mislabelled_as_sensor:suricata'
        self.assertNotIn(issue, m.event_field_violations('wazuh_rule_ids: 86601', self.SURICATA_FACTS))
        for line in ('IDS 규칙 86601', 'SID 86601', 'Suricata SID: 86601'):
            with self.subTest(line=line):
                self.assertIn(issue, m.event_field_violations(line, self.SURICATA_FACTS))
        self.assertNotIn(issue, m.event_field_violations('Suricata SID 2100498', self.SURICATA_FACTS))

    def test_sid_with_a_korean_particle_is_a_sid(self):
        facts = [{'kind': 'events', 'source': 'modsecurity', 'returned_count': 1, 'indexed_window_total_count': None,
                  'sensor_rule_ids': ['942100'], 'wazuh_rule_ids': []}]
        issue = 'modsecurity_rule_id_mislabelled_as_sid'
        self.assertIn(issue, m.event_field_violations('WAF 경보의 SID가 942100', facts))
        self.assertIn(issue, m.event_field_violations('ModSecurity SID 942100 (sensor_rule_ids 필드)', facts))
        self.assertNotIn(issue, m.event_field_violations('ModSecurity 규칙 942100, Suricata SID와 다름', facts))

    def test_named_source_before_a_denial(self):
        names = re.compile(m.MODSECURITY_NAMES + '|' + m.SURICATA_NAMES, re.I)
        found = [x.group() for x in names.finditer('ModSecurity 경보, sensor_rule_ids 비어 있음, rule ids 없음')]
        self.assertEqual(found, ['ModSecurity'])
        self.assertEqual([x.group() for x in names.finditer('WAF와 IDS가 탐지')], ['WAF', 'IDS'])

    def test_tokens_accept_korean_particles_not_identifiers(self):
        for pattern, yes, no in ((m.TLS_TERM, ('TLS가', 'TLS/SSL', '(TLS)'), ('mTLS', 'tls_version')),
                                 (m.SID_TERM, ('SID가', 'sid:2100498', 'SIDs'), ('inside', 'rule_sid')),
                                 (m.IDS_TERM, ('IDS가', 'NIDS', 'Suricata/IDS'), ('HIDS', 'rule_ids', 'ids'))):
            for text in yes:
                self.assertTrue(re.search(pattern, text, re.I), (pattern, text))
            for text in no:
                self.assertFalse(re.search(pattern, text, re.I), (pattern, text))


if __name__ == '__main__':
    unittest.main()
