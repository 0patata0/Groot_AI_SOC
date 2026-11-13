"""Report repair says what failed (2026-11-13 23:12 joint-channel run).

Two corrected reports failed only because "(10건 중)" was read as "0건" and
because MANAGEMENT_STATUS came before INCIDENT_DISPOSITION; the model was told
only the issue codes, believed the status line was missing and repeated the
same order. The checker now needs a digit boundary and the repair names the
rejected lines and the exact status-line problem.
"""
import json
import types
import unittest

import test_soc_management_grounding as grounding_fixtures
import soc_management_run as m

FACTS = [{'kind': 'events', 'source': 'modsecurity', 'returned_count': 0, 'indexed_window_total_count': None},
         {'kind': 'events', 'source': 'wazuh', 'returned_count': 10, 'indexed_window_total_count': None}]
DISP = 'INCIDENT_DISPOSITION: ' + json.dumps({'assessment': 'benign', 'basis': '반환 표본 기준 판단이며 전체 건수는 미확인입니다.',
                                               'evidence_tools': ['mcp__security_events__search_wazuh_alerts']}, ensure_ascii=False)
ZERO = 'sample_zero_presented_as_absence'


class ZeroSampleBoundary(unittest.TestCase):
    def test_counts_that_contain_a_zero_digit_are_not_zero(self):
        for line in ('### Wazuh 경보 상세 (10건 중)', 'Wazuh 경보 20건 표시', '이벤트 100건 가운데 일부'):
            with self.subTest(line=line):
                self.assertNotIn(ZERO, m.evidence_claim_violations(line, FACTS))

    def test_real_absence_claims_are_still_rejected(self):
        for line in ('WAF(ModSecurity)는 최근 30분 경보가 없었음.', 'ModSecurity 경보 0건, 정상 관리 활동뿐'):
            with self.subTest(line=line):
                self.assertIn(ZERO, m.evidence_claim_violations(line, FACTS))
        self.assertNotIn(ZERO, m.evidence_claim_violations('ModSecurity 반환 표본 0건(전체 구간 건수 미확인)', FACTS))


class StatusDiagnosis(unittest.TestCase):
    def test_exact_reason_for_each_rejection(self):
        body = '보고서 본문입니다.'
        for text, needle in ((body, '없습니다'),
                             (body + '\nMANAGEMENT_STATUS: resolved\nMANAGEMENT_STATUS: monitor', '2개입니다'),
                             (body + '\nMANAGEMENT_STATUS: ok', '중 하나가 아닙니다'),
                             (body + '\nMANAGEMENT_STATUS: resolved\n\n' + DISP, '뒤에 INCIDENT_DISPOSITION 줄'),
                             (body + '\nMANAGEMENT_STATUS: resolved\n추가 설명', '뒤에 다른 내용')):
            with self.subTest(needle=needle):
                self.assertIn(needle, m.management_status_problem(text))
        self.assertIsNone(m.management_status_problem(body + '\n' + DISP + '\nMANAGEMENT_STATUS: resolved'))
        self.assertIsNone(m.management_status_problem(None))


class RejectedLines(unittest.TestCase):
    def test_only_lines_that_alone_reproduce_the_issue_bounded(self):
        text = '\n'.join(['### Wazuh 경보 상세 (10건 중)', 'WAF는 최근 30분 경보가 없었음.', 'Wazuh 반환 표본 10건',
                          'ModSecurity 경보 0건.', '이벤트가 없었다', '오류 0건', 'MANAGEMENT_STATUS: resolved'])
        rows = m.rejected_report_lines(text, FACTS, None, [ZERO], limit=3)
        self.assertEqual([r['line'] for r in rows], ['WAF는 최근 30분 경보가 없었음.', 'ModSecurity 경보 0건.', '이벤트가 없었다'])
        self.assertEqual(m.rejected_report_lines(text, FACTS, None, []), [])


class RepairMessage(unittest.TestCase):
    def test_repair_names_the_lines_and_the_status_order(self):
        draft = ('## 결과\n- WAF(ModSecurity)는 최근 30분 경보가 없었음.\n### Wazuh 경보 상세 (10건 중)\n\n'
                 'MANAGEMENT_STATUS: resolved\n\n' + DISP)
        h = grounding_fixtures.Grounding(); h.setUp(); h.completed.append('search_wazuh_alerts')
        h.kw['assistant_message'].content = draft
        call = m.grounding_wrapper(lambda agent, **kw: 'original', types.SimpleNamespace(FinalResponseVerdict=types.SimpleNamespace),
                                   lambda rows, row: rows.append(row), lambda rows, user: 0, h.completed, FACTS,
                                   successful_reads={'mcp__security_events__search_wazuh_alerts'})
        result = call(h.agent, **h.kw)
        self.assertEqual(result.action, 'continue')
        nudge = h.kw['messages'][-1]['content']
        self.assertIn('이번 정정에서 고칠 곳', nudge)
        self.assertIn('MANAGEMENT_STATUS 줄 뒤에 INCIDENT_DISPOSITION 줄이 있습니다', nudge)
        self.assertIn('WAF(ModSecurity)는 최근 30분 경보가 없었음.', nudge)
        self.assertNotIn('(10건 중)', nudge.split('이번 정정에서 고칠 곳', 1)[1])
        self.assertIn('정정 경위나 오류 코드 설명 없이', nudge)


if __name__ == '__main__':
    unittest.main()
