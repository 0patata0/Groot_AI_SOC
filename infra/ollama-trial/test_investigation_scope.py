"""Alert investigations that name their sensors start with those alert reads.

2026-11-13 22:47: Hermes added an unasked get_wazuh_cluster_nodes read with an
invalid node_type (Wazuh API 400, failed answer) and the peer read agents
instead of alerts. The shared harness rule binds only the first selection.
"""
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent / 'hermes')]
import harness as h

MOD, SUR, WAZ = ('mcp__security_events__search_' + k + '_alerts' for k in ('modsecurity', 'suricata', 'wazuh'))


class InvestigationFirstScope(unittest.TestCase):
    def test_named_alert_sensors_bind_the_first_read(self):
        for question, scope in (
                ('최근 30분 ModSecurity와 Wazuh 경보를 조사해서 지금 대응이 필요한 위험이 있는지 근거와 함께 판단해줘. 설정은 바꾸지 마.', {MOD, WAZ}),
                ('최근 1시간 Suricata와 Wazuh 경보를 조사해서 지금 대응이 필요한 위험이 있는지 근거와 함께 판단해줘.', {SUR, WAZ}),
                ('WAF 경보 원인 분석해줘', {MOD}), ('ModSecurity 경보가 왜 떴는지 알려줘', {MOD}),
                ('IDS 로그 보고 위험한지 판단해줘', {SUR})):
            with self.subTest(question=question):
                self.assertEqual(h.investigation_first_scope(question), frozenset(scope))

    def test_other_subjects_listings_and_changes_keep_existing_behaviour(self):
        for question in ('IDS 경보와 방화벽 차단 상태를 조사해줘', 'Wazuh 에이전트 경보 조사해줘', 'Wazuh 클러스터 노드와 경보를 분석해줘',
                         'DVWA 공격이었나? 탐지 규칙과 근거를 조사하고 위험을 판단해줘.', '경보 조사해줘', '최근 30분 Wazuh 경보 보여줘',
                         'WAF 룰 변경해줘', 'WAF 경보 조사하고 차단해줘', 'systemd 서비스 실패 경보 원인 조사', 'Wazuh 수집 지연 경보 분석'):
            with self.subTest(question=question):
                self.assertIsNone(h.investigation_first_scope(question))

    def test_word_boundaries(self):
        self.assertIsNone(h.investigation_first_scope('BIDSX 경보 조사해줘'))
        self.assertEqual(h.investigation_first_scope('IDS 경보 조사해줘'), frozenset({SUR}))


if __name__ == '__main__':
    unittest.main()
