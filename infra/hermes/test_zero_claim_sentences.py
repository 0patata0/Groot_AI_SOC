"""Zero-sample claims are judged per sentence, with the qualifier attached to it (2026-11-14 01:02).

The first Hermes draft wrote "공격 또는 오류 경보 없음. (반환 10건, 제한 반환)" in a table
cell: the check split at the period and missed the parenthetical qualifier, the
repair quoted the whole row (qualifier included), and the draft's one real
unqualified claim, "WAF의 경우 경보가 없으며", was not seen at all because only
final endings (없음/없다/...) counted. Now a parenthetical directly after a
sentence belongs to it, connective endings count, a period between digits does
not end a sentence, and the repair quotes the sentence that failed.
"""
import unittest

import test_soc_management_grounding  # noqa: F401  (loads importlib.util for the runner's contracts)
import soc_management_run as m

FACTS = [{'kind': 'events', 'source': 'modsecurity', 'returned_count': 0, 'indexed_window_total_count': None},
         {'kind': 'events', 'source': 'wazuh', 'returned_count': 10, 'indexed_window_total_count': None}]
ZERO = 'sample_zero_presented_as_absence'
MODSEC_ROW = ('| **ModSecurity (WAF)** | 00:32 ~ 01:02 | 경보 0건 | Wazuh 인덱스 기준 WAF 경고가 없음. (전체 건수 미확인, 표본 반환) '
              '| 필요 시 원시 로그 또는 더 긴 구간 조사 |')
WAZUH_ROW = ('| **Wazuh (호스트/시스템)** | 00:32 ~ 01:02 | 정상 로그인 10건 | sshd/sudo PAM 세션 열림/닫힘 기록. 공격 또는 오류 경보 없음. '
             '(반환 10건, 제한 반환) | 필요 시 다른 에이전트 또는 그룹화 검색 |')
CONCLUSION = ('**판단:** 최근 30분간 현재 확인되는 긴급 대응이 필요한 위험은 없습니다. WAF의 경우 경보가 없으며, Wazuh 관측 범위 내에서는 '
              '정상적인 SSH/Sudo 로그인 접근만 확인되었습니다.')
DRAFT_0102 = ('### 최근 30분 보안 경보 조사 결과 (2026-11-14 00:32 KST 기준)\n\n'
              '| 점검 대상 | 조회 구간 (KST) | 결과 | 근거 및 판단 | 미확인/다음 조치 |\n| :--- | :--- | :--- | :--- | :--- |\n'
              + MODSEC_ROW + '\n' + WAZUH_ROW + '\n\n' + CONCLUSION + '\n\nMANAGEMENT_STATUS: resolved')


def rejected(text):
    return ZERO in m.evidence_claim_violations(text, FACTS)


class AttachedQualifier(unittest.TestCase):
    def test_live_rows_with_a_parenthetical_qualifier_pass(self):
        self.assertFalse(rejected(MODSEC_ROW))
        self.assertFalse(rejected(WAZUH_ROW))
        self.assertFalse(rejected('공격 경보 없음. (반환 표본 기준, 전체 미확인)'))

    def test_qualifier_must_belong_to_the_claim(self):
        for text in ('공격 경보 없음. (참고: Wazuh 정상)',          # parenthetical without a qualifier
                     '반환 표본 0건입니다. 공격은 없었습니다.',       # qualifier in another sentence
                     '공격 경보 없음.\n(반환 10건)',                 # parenthetical on the next line
                     '공격 경보 없음. 반환 10건 기준이다.'):         # plain next sentence
            with self.subTest(text=text):
                self.assertTrue(rejected(text))


class ConnectiveEndings(unittest.TestCase):
    def test_connective_absence_is_a_claim(self):
        for text in (CONCLUSION, '공격 경보가 없어 정상', '조회한 경보가 없으므로 종결', '경보가 없고 정상입니다'):
            with self.subTest(text=text):
                self.assertTrue(rejected(text))
        self.assertFalse(rejected('WAF 경보가 없고 반환 표본 기준입니다'))
        self.assertFalse(rejected('경보가 없으나 반환 표본 0건이라 전체는 미확인'))


class SentenceSplit(unittest.TestCase):
    def test_periods_between_digits_do_not_end_a_sentence(self):
        sentences = [s for s, _ in m.claim_sentences('| 22:22:30.915 | 172.17.0.2 | 공격성 없음. | 다음. 끝')]
        self.assertEqual(sentences, ['| 22:22:30.915 | 172.17.0.2 | 공격성 없음', ' | 다음', ' 끝'])
        self.assertEqual(list(m.claim_sentences('경보 없음. (반환 10건) 이후'))[0], ('경보 없음', '경보 없음 (반환 10건)'))
        self.assertEqual(list(m.claim_sentences('경보 없음.\n(반환 10건)'))[0], ('경보 없음', '경보 없음'))


class RepairQuote(unittest.TestCase):
    def test_live_draft_quotes_only_the_unqualified_sentence(self):
        self.assertIn(ZERO, m.evidence_claim_violations(DRAFT_0102, FACTS))
        rows = m.rejected_report_lines(DRAFT_0102, FACTS, None, [ZERO])
        self.assertEqual([r['line'] for r in rows],
                         ['WAF의 경우 경보가 없으며, Wazuh 관측 범위 내에서는 정상적인 SSH/Sudo 로그인 접근만 확인되었습니다'])

    def test_multi_sentence_row_quotes_the_failing_sentence_single_sentence_keeps_the_line(self):
        rows = m.rejected_report_lines('| Wazuh | 10건 | PAM 기록. 공격 또는 오류 경보 없음. 반환 10건 기준 |', FACTS, None, [ZERO])
        self.assertEqual([r['line'] for r in rows], ['공격 또는 오류 경보 없음'])
        rows = m.rejected_report_lines('WAF는 최근 30분 경보가 없었음.', FACTS, None, [ZERO])
        self.assertEqual([r['line'] for r in rows], ['WAF는 최근 30분 경보가 없었음.'])


if __name__ == '__main__':
    unittest.main()
