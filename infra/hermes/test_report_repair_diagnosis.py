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



class FormattedControlLines(unittest.TestCase):
    """11-13 23:35: both drafts wrapped the control lines in backticks and the
    diagnosis said only "line missing". Exact syntax stays required."""

    def test_formatted_status_line_is_named(self):
        body = '보고서 본문입니다.'
        for line in ('`MANAGEMENT_STATUS`: monitor', '`MANAGEMENT_STATUS: needs_review`', '**MANAGEMENT_STATUS: resolved**',
                     '> MANAGEMENT_STATUS: monitor', '"MANAGEMENT_STATUS: monitor"'):
            with self.subTest(line=line):
                text = body + '\n' + DISP + '\n' + line
                self.assertIsNone(m.management_status(text))
                problem = m.management_status_problem(text)
                self.assertIn('서식', problem); self.assertIn(json.dumps(line.strip(), ensure_ascii=False), problem); self.assertIn('줄 맨 앞부터', problem)
        self.assertIn('뒤에 INCIDENT_DISPOSITION 줄', m.management_status_problem(body + '\nMANAGEMENT_STATUS: monitor\n`' + DISP + '`'))

    def test_example_keeps_the_models_own_status_value(self):
        problem = m.management_status_problem('본문\n' + DISP + '\n`MANAGEMENT_STATUS: needs_review`')
        self.assertIn('줄 맨 앞부터 MANAGEMENT_STATUS: needs_review 형식', problem)
        self.assertNotIn('monitor 형식', problem)
        self.assertIn('중 실제 판단 하나', m.management_status_problem('본문\n`MANAGEMENT_STATUS: ok`'))

    def test_formatted_disposition_line_is_named(self):
        self.assertIn('서식', m.disposition_line_problem('본문\n`' + DISP + '`\nMANAGEMENT_STATUS: monitor'))
        self.assertIsNone(m.disposition_line_problem('본문\n' + DISP + '\nMANAGEMENT_STATUS: monitor'))
        self.assertIsNone(m.disposition_line_problem('본문\nMANAGEMENT_STATUS: monitor'))
        self.assertIsNone(m.disposition_line_problem(None))

    def test_repair_names_both_formatted_lines(self):
        draft = ('## 결과\nWAF 반환 표본 0건(전체 구간 건수 미확인)\n\n`' + DISP + '`\n\n`MANAGEMENT_STATUS: needs_review`')
        h = grounding_fixtures.Grounding(); h.setUp(); h.completed.append('search_wazuh_alerts')
        h.kw['assistant_message'].content = draft
        call = m.grounding_wrapper(lambda agent, **kw: 'original', types.SimpleNamespace(FinalResponseVerdict=types.SimpleNamespace),
                                   lambda rows, row: rows.append(row), lambda rows, user: 0, h.completed, FACTS,
                                   successful_reads={'mcp__security_events__search_wazuh_alerts'})
        call(h.agent, **h.kw)
        nudge = h.kw['messages'][-1]['content'].split('이번 정정에서 고칠 곳', 1)[1]
        self.assertIn('MANAGEMENT_STATUS 줄에 서식', nudge)
        self.assertIn('INCIDENT_DISPOSITION 줄에 서식', nudge)

    def test_skill_states_the_rule_without_formatting_the_names(self):
        import workflow_contract
        body = workflow_contract.policy(('soc-investigate',))
        line = next(l for l in body.splitlines() if '제어 줄이 모두 필요하면' in l)
        self.assertNotIn('`INCIDENT_DISPOSITION`', line); self.assertNotIn('`MANAGEMENT_STATUS`', line)
        self.assertIn('백틱', line); self.assertIn('줄 맨 앞부터', line)


class DispositionStatusConflict(unittest.TestCase):
    """11-13 23:50: assessment unresolved with MANAGEMENT_STATUS resolved; the
    controller checks this only after a sensor-incident run, so the model never
    got a chance to fix it. The draft was also wrapped in a code block."""

    @staticmethod
    def report(assessment, status):
        disp = 'INCIDENT_DISPOSITION: ' + json.dumps({'assessment': assessment, 'basis': '반환 표본 기준 판단이며 전체 건수는 미확인입니다.',
                                                      'evidence_tools': ['mcp__security_events__search_wazuh_alerts']}, ensure_ascii=False)
        return '보고서 본문입니다.\n' + disp + '\nMANAGEMENT_STATUS: ' + status

    def test_only_unresolved_with_resolved_conflicts(self):
        self.assertTrue(m.disposition_status_conflict(self.report('unresolved', 'resolved')))
        for assessment, status in (('unresolved', 'monitor'), ('unresolved', 'needs_review'), ('benign', 'resolved'), ('remediated', 'resolved')):
            with self.subTest(assessment=assessment, status=status):
                self.assertFalse(m.disposition_status_conflict(self.report(assessment, status)))
        self.assertFalse(m.disposition_status_conflict('본문\nMANAGEMENT_STATUS: resolved'))
        self.assertIn('unresolved_disposition_marked_resolved', m.LITERAL_REPAIR_ISSUES)

    def test_code_block_wrapping_is_named(self):
        fenced = '```text\n' + self.report('unresolved', 'resolved') + '\n```'
        self.assertIn('코드 블록', m.management_status_problem(fenced))
        self.assertFalse(m.disposition_status_conflict(fenced))

    def test_repair_names_the_conflict(self):
        h = grounding_fixtures.Grounding(); h.setUp(); h.completed.append('search_wazuh_alerts')
        h.kw['assistant_message'].content = self.report('unresolved', 'resolved')
        call = m.grounding_wrapper(lambda agent, **kw: 'original', types.SimpleNamespace(FinalResponseVerdict=types.SimpleNamespace),
                                   lambda rows, row: rows.append(row), lambda rows, user: 0, h.completed, FACTS,
                                   successful_reads={'mcp__security_events__search_wazuh_alerts'})
        result = call(h.agent, **h.kw)
        self.assertEqual(result.action, 'continue')
        nudge = h.kw['messages'][-1]['content']
        self.assertIn('unresolved_disposition_marked_resolved', nudge)
        self.assertIn('assessment가 unresolved인데 MANAGEMENT_STATUS가 resolved', nudge)
        self.assertIn('실제 근거가 있어야', nudge)

    def test_consistent_report_is_not_repaired_for_this(self):
        h = grounding_fixtures.Grounding(); h.setUp(); h.completed.append('search_wazuh_alerts')
        h.kw['assistant_message'].content = self.report('unresolved', 'needs_review')
        call = m.grounding_wrapper(lambda agent, **kw: 'original', types.SimpleNamespace(FinalResponseVerdict=types.SimpleNamespace),
                                   lambda rows, row: rows.append(row), lambda rows, user: 0, h.completed, FACTS,
                                   successful_reads={'mcp__security_events__search_wazuh_alerts'})
        call(h.agent, **h.kw)
        self.assertFalse(any('unresolved_disposition_marked_resolved' in str(x.get('content', '')) for x in h.kw['messages']))

    def test_skill_states_both_rules(self):
        import workflow_contract
        line = next(l for l in workflow_contract.policy(('soc-investigate',)).splitlines() if '제어 줄이 모두 필요하면' in l)
        self.assertIn('코드 블록으로 감싸지 않는다', line)
        self.assertIn('unresolved이면 MANAGEMENT_STATUS를 resolved로 쓰지 않는다', line)

if __name__ == '__main__':
    unittest.main()
