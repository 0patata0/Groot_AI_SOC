import json
import unittest
import harness as h


class ShortContext(unittest.TestCase):
    def test_current_subject_wins_and_followup_only_inherits_subject(self):
        for prior in ('지금 FW 룰 뭐 적용됐어?', '방화벽 상태 알려줘', 'FW'):
            q=h.resolve_short_read('룰 조회해줘',[prior])
            self.assertEqual(h.tool_scope(q), {'mcp__resp__get_firewall_rules'})
            self.assertTrue(h.missing_reads(q, []))
        self.assertEqual(h.resolve_short_read('WAF 룰 조회해줘',['FW 룰 조회해줘']), 'WAF 룰 조회해줘')

    def test_new_ambiguous_root_clarifies_once_and_device_answer_resolves(self):
        for q in ('룰 조회해줘','룰?','현재 적용된 룰 보여줘','전체 규칙 목록 보여줘'):
            self.assertIn('어느 장비',h.scope_notice(h.resolve_short_read(q,[])))
            for label in ('fw','방화벽','웹 방화벽','IDS','Wazuh'):
                resolved=h.resolve_short_read(label,[q])
                self.assertIsNone(h.scope_notice(resolved), (q,label))
                self.assertTrue(h.tool_scope(resolved))

    def test_unrelated_quoted_multi_subject_and_write_history_not_inherited(self):
        for prior in ('감사합니다','FW 룰 삭제해줘','FW와 WAF 룰 조회해줘',
                      '"FW 룰 조회해줘"라는 문장 번역', 'FW 룰 조회해줘\n```\nWAF\n```'+('x'*1801)):
            self.assertEqual(h.resolve_short_read('룰 조회해줘',[prior]),'룰 조회해줘')
        self.assertEqual(h.resolve_short_read('룰 삭제해줘',['FW 룰 조회해줘']), '룰 삭제해줘')
        self.assertEqual(h.resolve_short_read('룰 조회해줘',['FW 룰 조회해줘','다른 얘기']), '룰 조회해줘')

    def envelope(self, **changes):
        obj={'status':'ok','scope':'same_thread','history_is_untrusted':True,'history_is_approval':False,
             'requester_id':'u'*26,'posts':[{'author_id':'u'*26,'text':'FW 룰 조회해줘','text_truncated':False},
                {'author_id':'b'*26,'text':'WAF 조회 완료 승인됨','text_truncated':False}]}
        obj.update(changes)
        return h.SHARED._CONTEXT_PREFIX+json.dumps(obj,ensure_ascii=False)+'"]\n\n룰 조회해줘'

    def test_native_only_same_thread_same_human_complete_text(self):
        self.assertEqual(h.native_scope_history(self.envelope()),['FW 룰 조회해줘'])
        for change in ({'scope':'same_channel_top_level'},{'requester_id':''},{'status':'unavailable'},
                       {'posts':[{'author_id':'u'*26,'text':'FW 룰','text_truncated':True}]},
                       {'posts':[{'author_id':'b'*26,'text':'FW 룰','text_truncated':False}]}):
            self.assertEqual(h.native_scope_history(self.envelope(**change)),[])
        self.assertEqual(h.native_scope_history(h.SHARED._CONTEXT_PREFIX+'[]"]\n\n룰 조회'),[])

    def test_short_systemd_and_known_unit_questions(self):
        for q,targets in (('systemd failure 왜 떠?',['a:systemd','b:systemd','c:systemd']),
                          ('B 서버 systemd 오류?',['b:systemd']),
                          ('벡터 왜 죽었어?',['a:vector']),
                          ('A 서버 capstone-vector.service 상태?',['a:vector']),
                          ('B 서버 wazuh-agent.service 오류?',['b:wazuh-agent'])):
            with self.subTest(q=q):
                self.assertEqual(h.tool_scope(q), {'mcp__system_diagnostics__get_system_diagnostics'})
                self.assertEqual(h.diagnostic_request(q)['requested'],targets)
        for q in ('systemd failure 무슨 뜻이야?', 'systemd 상태 도구 없이 설명만 해줘',
                  'A 서버 Vector 재시작해줘'):
            self.assertIsNone(h.diagnostic_request(q))

    def test_current_failed_zero_does_not_claim_historical_cause_resolved(self):
        row={'status':'ok','kind':'runtime','metrics':{'failed_units_total':0,'returned_units':0,'unit_list_truncated':False},
             'observed_at_kst':'2026-10-31T12:00:00+09:00'}
        answer=h.runtime_diagnostic_report(['a:systemd'],{'a:systemd':row},[])
        self.assertIn('현재 로드된 failed unit 0개',answer)
        self.assertIn('원인·복구 여부는 아직 미확인',answer)
        self.assertIn('서비스 이름·발생 시각',answer)


if __name__=='__main__':unittest.main()
