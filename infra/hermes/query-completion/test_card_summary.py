"""Native context boundaries and the production card routing regression."""
import copy
from dataclasses import dataclass
import hashlib
import json
from types import SimpleNamespace
import unittest
import alignment
from test_completion import PLUGIN, hydrated

H=alignment.load_harness()

def user(text, root='r'*26, actor='u'*26):
    return hydrated(text, status='ok',scope='same_thread',requester_id=actor,
        posts=[{'kind':'root','post_id':root,'text':'탐지 규칙(상위): DNS / SSH / Systemd failure'}])

def diagnostic():
    raw=json.dumps({'schema':1,'kind':'runtime','target':'b:systemd','status':'ok','codes':[],
                    'metrics':{'failed_units_total':0},'observed_at_kst':'2026-10-31T14:02:00+09:00'})
    return dict(server='system-diagnostics',name='get_system_diagnostics',arguments={'target':'b:systemd'},
                result=raw,result_sha256=hashlib.sha256(raw.encode()).hexdigest())

@dataclass
class Request:
    api_kwargs:object
    api_messages:object=None
    _original_api_kwargs:object=None

class CardSummary(unittest.TestCase):
    def test_actual_card_heading_does_not_narrow_to_rule_or_system_health_tools(self):
        for q in ('지금 태그한 카드에서 탐지규칙(상위)가 뭐가 문제인건지 한번 확인해볼래?',
                  '룰 말고 탐지된거\nSystemd: Service exited due to a failure.\n무슨 로그인지 알고싶은데'):
            current=user(q);rows=[{'role':'user','content':current}]
            agent=SimpleNamespace(platform='mattermost',model='qwen3.6:35b',provider='custom',max_iterations=12,_current_turn_id='t')
            source={'messages':rows,'tools':[]}
            alignment.request_wrapper(lambda *a,**k:Request(copy.deepcopy(source)),PLUGIN,H)(
                agent,original_user_message=current,turn_id='t',messages=rows)
            self.assertEqual(H.request_kind(PLUGIN.current_request_text(current)),'investigation')
            self.assertIsNone(getattr(agent,'_capstone_query_completion_local_format',None))
            self.assertIsNone(H.diagnostic_request(PLUGIN.current_request_text(current)))

    def test_summary_uses_linked_tool_facts_and_keeps_incomplete_investigation_partial(self):
        prior=user('무슨 로그인지 알고싶은데');current=user('좀 요약해서 보여줄래')
        rows=[{'role':'user','content':prior}]+H.linked_rows([diagnostic()])+[{'role':'user','content':current}]
        report=alignment.prior_read_report('좀 요약해서 보여줄래',rows,len(rows)-1,PLUGIN,H)
        self.assertTrue(report.reused);self.assertTrue(report.partial)
        self.assertIn('failed unit 0개',report);self.assertIn('원인 조사는 미완료',report)
        agent=SimpleNamespace(platform='mattermost',model='qwen3.6:35b',provider='custom',max_iterations=12,_current_turn_id='t')
        alignment.request_wrapper(lambda *a,**k:Request({'messages':rows,'tools':[]}),PLUGIN,H)(
            agent,original_user_message=current,turn_id='t',messages=rows)
        self.assertIsNone(getattr(agent,'_capstone_query_completion_local_format',None))
        self.assertIn('빠진 근거',agent._capstone_proposal_context[1])
        self.assertEqual(H.request_kind(agent._capstone_proposal_context[1]),'investigation')

    def test_different_root_actor_and_intervening_topic_do_not_reuse_older_evidence(self):
        for current in (user('요약해줘',root='s'*26),user('요약해줘',actor='v'*26)):
            rows=[{'role':'user','content':user('B 서버 systemd 상태')}]+H.linked_rows([diagnostic()])+[{'role':'user','content':current}]
            report=alignment.prior_read_report('요약해줘',rows,len(rows)-1,PLUGIN,H)
            self.assertFalse(report.reused);self.assertTrue(report.partial)
        rows=[{'role':'user','content':user('B 서버 systemd 상태')}]+H.linked_rows([diagnostic()])+[
            {'role':'user','content':user('FW 상태도 확인해줘')},{'role':'user','content':user('요약해줘')}]
        self.assertFalse(alignment.prior_read_report('요약해줘',rows,len(rows)-1,PLUGIN,H).reused)

    def test_bad_context_is_not_a_reuse_identity(self):
        bad=H.SHARED._CONTEXT_PREFIX+'[]"]\n\n요약해줘'
        self.assertFalse(alignment.same_summary_conversation(bad,bad,H))

if __name__=='__main__':unittest.main()
