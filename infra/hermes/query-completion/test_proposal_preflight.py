"""Model-authored edits are checked before wire dispatch; no replacement candidates."""
import copy
import hashlib
import json
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

import alignment
from test_alignment import H, proposal

Q = 'WAF 맨 끝에 # PREFLIGHT-NOTE 주석 한 줄을 추가하는 승인안을 만들어줘. 기존 내용과 모드는 유지해줘.'
CONTENT = '# repeated\n# preserve\n# repeated\n'
TARGET = 'a:modsecurity-custom'

def sha(text): return hashlib.sha256(text.encode()).hexdigest()
def read(content=CONTENT, **change):
    data=dict(target=TARGET,content=content,sha256=sha(content));data.update(change)
    raw=json.dumps(data)
    return dict(server='rule-a',name='get_rule_change_target',arguments={'target':TARGET},result=raw,result_sha256=sha(raw))
def args():
    return dict(target=TARGET,base_sha256=sha(CONTENT),edits=[{'old_text':'# preserve\n# repeated\n','new_text':'# preserve\n# repeated\n# PREFLIGHT-NOTE\n'}],reason='user requested comment')
def check(arguments=None,calls=None,question=Q,name='propose_rule_edit',server='rule-write-a'):
    return H.proposal_preflight(question,[read()] if calls is None else calls,server,name,args() if arguments is None else arguments)

class Preflight(unittest.TestCase):
    def test_exact_candidate_is_accepted_and_arguments_are_not_rewritten(self):
        for content in (CONTENT,CONTENT.replace('\n','\r\n')):
            a=args();a['base_sha256']=sha(content)
            if '\r' in content:
                a['edits']=[{k:v.replace('\n','\r\n') for k,v in a['edits'][0].items()}]
            saved=copy.deepcopy(a)
            self.assertIsNone(check(a,[read(content)]));self.assertEqual(a,saved)
    def test_missing_or_latest_failed_read_never_uses_an_older_success(self):
        for calls in ([],[read(),dict(read(),is_error=True)],[dict(read(),result_sha256='0'*64)]):
            self.assertEqual(check(calls=calls)['error'],'proposal_preflight_read_required')
        self.assertEqual(check(calls=[read(content='tampered',sha256=sha(CONTENT))])['error'],'proposal_preflight_source_invalid')
        a=args();a['base_sha256']='0'*64
        self.assertEqual(check(a)['error'],'proposal_preflight_base_mismatch')
    def test_original_omission_blank_line_and_wrong_position_are_blocked(self):
        for replacement in ('# repeated\n# PREFLIGHT-NOTE\n',
                            '# preserve\n# repeated\n\n# PREFLIGHT-NOTE\n',
                            '# preserve\n# PREFLIGHT-NOTE\n# repeated\n'):
            a=args();a['edits'][0]['new_text']=replacement
            r=check(a);self.assertEqual(r['error'],'proposal_preflight_scope_mismatch');self.assertFalse(r['executed'])
            self.assertNotIn('candidate_content',r);self.assertNotIn('new_text',r['edit_anchors']['file_end'])
    def test_invalid_anchors_overlaps_limits_and_utf8_are_blocked(self):
        variants=[[],[{'old_text':'# repeated\n','new_text':'x\n'}],
                  [{'old_text':'# preserve\n','new_text':'a\n'},{'old_text':'preserve','new_text':'b'}],
                  [{'old_text':CONTENT,'new_text':'x'*131073+'\n'}],
                  [{'old_text':CONTENT,'new_text':'bad\ud800\n'}],
                  [{'old_text':CONTENT,'new_text':CONTENT}],
                  [{'old_text':CONTENT,'new_text':'no newline'}]]
        for edits in variants:
            a=args();a['edits']=edits
            self.assertEqual(check(a)['error'],'proposal_preflight_edit_invalid')
    def test_whole_file_cannot_bypass_same_scope_check(self):
        a={k:v for k,v in args().items() if k!='edits'};a['candidate_content']=CONTENT+'# PREFLIGHT-NOTE\n'
        self.assertIsNone(check(a,name='propose_rule_change'))
        a['candidate_content']=CONTENT+'\n# PREFLIGHT-NOTE\n'
        self.assertEqual(check(a,name='propose_rule_change')['error'],'proposal_preflight_scope_mismatch')
    def test_generic_multi_edit_is_validated_without_inventing_semantic_scope(self):
        a=args();a['edits']=[{'old_text':'# preserve','new_text':'# changed'},{'old_text':'# repeated\n# preserve','new_text':'# overlap'}]
        self.assertIsNotNone(check(a,question='WAF 규칙 내용을 수정해줘'))
        a['edits']=[{'old_text':'preserve','new_text':'reviewed'}]
        self.assertIsNone(check(a,question='WAF 주석 내용을 수정해줘'))
        self.assertIsNone(check(name='get_rule_change_target',server='rule-a'))
    def test_duplicate_and_unknown_outcome_are_not_resent(self):
        good=proposal(TARGET,before_sha256=sha(CONTENT),after_sha256=sha(CONTENT+'# PREFLIGHT-NOTE\n'))
        self.assertEqual(check(calls=[read(),good])['error'],'proposal_preflight_duplicate')
        unknown=dict(good,result='unknown',result_sha256=sha('unknown'),is_error=True)
        self.assertEqual(check(calls=[read(),unknown])['error'],'proposal_preflight_outcome_unknown')
        refused=proposal(TARGET,error='edit 1 old_text must match exactly once in the original file')
        self.assertIsNone(check(calls=[read(),refused]))
    def test_local_rejection_is_reported_and_is_not_an_executed_protected_attempt(self):
        bad=args();bad['edits'][0]['new_text']='# preserve\n# PREFLIGHT-NOTE\n# repeated\n'
        r=check(bad);history=H.proposal_history([read()],[{'server':'rule-write-a','name':'propose_rule_edit','arguments':bad,'after_call_count':1,'rejection':r}])
        self.assertEqual(H.preparation_gap(Q,history),[TARGET])
        self.assertIn('MCP 미호출',H.write_progress(Q,history)['text'])
        unknown={'server':'rule-write-a','name':'propose_rule_edit','arguments':args(),'error_type':'TimeoutError'}
        self.assertEqual(H.preparation_gap(Q,history+[unknown]),[])
        self.assertIsNone(H.preproposal_rejection(json.dumps({'error':'proposal_preflight_scope_mismatch','executed':True,'stage':'before_mcp'})))

class NativeBoundary(unittest.TestCase):
    def agent(self, turn='t1',calls=None):
        return SimpleNamespace(platform='mattermost',model='qwen3.6:35b',provider='custom',api_mode='chat_completions',
                               _current_turn_id=turn,_capstone_proposal_context=('t1',Q,[read()] if calls is None else calls,threading.Lock(),set()))
    def ref(self, arguments=None):
        return SimpleNamespace(name='mcp__rule_write_a__propose_rule_edit',args=args() if arguments is None else arguments,call_id='call_test')
    def test_native_preserves_prior_blocks_and_hook_argument_modifications(self):
        a=self.agent();r=self.ref();original=Mock(return_value=('original policy block',r.args))
        block,result=alignment.proposal_input_wrapper(original,H,'test')(a,r)
        self.assertEqual(block,'original policy block');self.assertIs(result,r.args)
        changed=args();changed['edits'][0]['new_text']='# repeated\n# PREFLIGHT-NOTE\n'
        original.return_value=(None,changed)
        block,result=alignment.proposal_input_wrapper(original,H,'test')(a,r)
        self.assertEqual(json.loads(block)['error'],'proposal_preflight_scope_mismatch');self.assertIs(result,changed)
    def test_stale_context_other_conversation_and_success_use_distinct_paths(self):
        original=lambda agent,ref:(None,ref.args);wrapped=alignment.proposal_input_wrapper(original,H,'test');r=self.ref()
        self.assertIsNone(wrapped(self.agent(),r)[0])
        self.assertEqual(json.loads(wrapped(self.agent('t2'),r)[0])['error'],'proposal_preflight_context_unavailable')
        self.assertEqual(json.loads(wrapped(self.agent(calls=[read('# another file\n')]),r)[0])['error'],'proposal_preflight_base_mismatch')
        other=self.agent();other.platform='cli';self.assertIsNone(wrapped(other,r)[0])

    def test_same_batch_cannot_submit_same_target_twice(self):
        wrapped=alignment.proposal_input_wrapper(lambda agent,ref:(None,ref.args),H,'test')
        agent=self.agent();ref=self.ref()
        self.assertIsNone(wrapped(agent,ref)[0])
        self.assertEqual(json.loads(wrapped(agent,ref)[0])['error'],'proposal_preflight_outcome_unknown')
        other=self.agent();self.assertIsNone(wrapped(other,ref)[0])

class Recovery(unittest.TestCase):
    def failed(self, new_text=None):
        a=args();a['edits'][0]['new_text']=new_text or '# preserve\n# repeated\n\n# PREFLIGHT-NOTE\n'
        r=check(a)
        return H.proposal_history([], [dict(server='rule-write-a',name='propose_rule_edit',arguments=a,after_call_count=0,rejection=r)])[0]

    def test_scope_feedback_distinguishes_blank_line_from_wrong_position(self):
        a=args();a['edits'][0]['new_text']='# preserve\n# repeated\n\n# PREFLIGHT-NOTE\n'
        r=check(a);self.assertEqual(r['scope']['diagnostic'],{'extra_blank_lines':1})
        self.assertIn('빈 줄 1개',r['detail']);self.assertIn('기준은 원문에 일치',r['detail'])
        a['edits'][0]['new_text']='# preserve\n# PREFLIGHT-NOTE\n# repeated\n'
        r=check(a);self.assertEqual(r['scope']['diagnostic'],{'wrong_position':True})
        self.assertIn('삽입 위치',r['detail'])
        # Only a matching candidate hash may support a diagnostic.
        scope=H.exact_comment_scope(Q,dict(content=CONTENT),dict(before_sha256=sha(CONTENT),after_sha256='0'*64),candidate_content=CONTENT)
        self.assertNotIn('diagnostic',scope)

    def test_three_identical_local_candidates_stop_without_hiding_other_work(self):
        bad=self.failed()
        self.assertFalse(H.proposal_recovery(Q,[read(),bad,bad]))
        self.assertTrue(H.proposal_recovery(Q,[read(),bad,bad,bad]))
        different=self.failed('# preserve\n# PREFLIGHT-NOTE\n# repeated\n')
        self.assertFalse(H.proposal_recovery(Q,[read(),bad,bad,different]))
        self.assertFalse(H.proposal_recovery(Q+' IDS도 변경안을 만들어줘',[read(),bad,bad,bad]))
        success=proposal(TARGET,before_sha256=sha(CONTENT),after_sha256=sha(CONTENT+'# PREFLIGHT-NOTE\n'))
        self.assertFalse(H.proposal_recovery(Q,[read(),bad,bad,bad,success]))
        forged=dict(bad,result_sha256='0'*64)
        self.assertFalse(H.proposal_recovery(Q,[read(),forged,forged,forged]))

    def test_final_refusal_cannot_invent_json_or_server_failure(self):
        progress=H.write_progress(Q,[read(),self.failed()])
        rendered=H.write_report('JSON 인코딩 문제로 실행 불가. 서버가 거부했습니다.',progress)
        self.assertNotIn('JSON 인코딩',rendered);self.assertNotIn('서버가 거부',rendered)
        self.assertIn('빈 줄 1개',rendered);self.assertIn('MCP 미호출',rendered)

    def test_native_request_terminal_keeps_transcript_and_skips_provider(self):
        from dataclasses import dataclass
        from test_alignment import PLUGIN, Harness
        @dataclass
        class Request:
            api_kwargs: object
            api_messages: object = None
            _original_api_kwargs: object = None
        h=Harness(request=Q);h.agent.model='qwen3.6:35b';h.agent.provider='custom'
        rows=[{'role':'user','content':Q}]+H.linked_rows([dict(c,is_error=False) for c in [read(),self.failed(),self.failed(),self.failed()]])
        before=copy.deepcopy(rows);result=Request({'messages':rows})
        alignment.request_wrapper(lambda *a,**kw:result,PLUGIN,H)(h.agent,
            original_user_message=Q,turn_id=h.agent._current_turn_id,messages=rows)
        self.assertEqual(rows,before);self.assertTrue(h.agent._capstone_proposal_terminal[1])
        self.assertIn('3회',h.agent._capstone_query_completion_local_format[1])
        provider=Mock(side_effect=AssertionError('unexpected provider call'))
        native=SimpleNamespace(ApiCallVerdict=lambda **kw:SimpleNamespace(**kw),stop_thinking_spinner=lambda *a:None)
        wrapped=PLUGIN.make_call_wrapper(provider,native,response_factory=lambda text,turn:SimpleNamespace(content=text))
        verdict=wrapped(h.agent,turn_id=h.agent._current_turn_id)
        self.assertIn('MCP 미호출',verdict.response.content);provider.assert_not_called()
        h.kw['messages']=rows
        h.wrapper=alignment.final_wrapper(h.wrapper,h.original,h.native,h.append,h.reanchor,PLUGIN,H)
        verdict=h.call()
        self.assertNotEqual(verdict.action,'continue');self.assertIn('3회',verdict.final_response)
        self.assertTrue(h.agent._capstone_alignment_partial)

    def budget_fixture(self):
        from test_alignment import PLUGIN, Harness
        h=Harness(request=Q);h.agent.model='qwen3.6:35b';h.agent.provider='custom'
        h.agent._capstone_proposal_user=(h.agent._current_turn_id,Q)
        rows=[{'role':'user','content':Q}]+H.linked_rows([dict(c,is_error=False) for c in [read(),self.failed()]])
        kw=dict(final_response=None,api_call_count=h.agent.max_iterations,interrupted=False,failed=False,
            messages=rows,_turn_exit_reason='unknown',_pending_verification_response=None,
            _pending_verification_response_previewed=False,logger=None)
        original=Mock(side_effect=lambda agent,**kw:kw)
        return h,kw,original,alignment.budget_fallback_wrapper(original,PLUGIN,H,h.reanchor)

    def test_budget_summary_is_grounded_before_native_finalizer_runs(self):
        h,kw,original,wrapped=self.budget_fixture();before=copy.deepcopy(kw['messages'])
        result=wrapped(h.agent,**kw)
        self.assertIn('빈 줄 1개',result['_pending_verification_response'])
        self.assertIn('MCP 미호출',result['_pending_verification_response'])
        self.assertIsNone(result['final_response']);self.assertEqual(kw['messages'],before)
        self.assertTrue(h.agent._capstone_alignment_partial);original.assert_called_once()

    def test_budget_keeps_interrupt_failure_existing_pending_and_foreign_turn_native(self):
        for change in ({'interrupted':True},{'failed':True},{'final_response':'existing'},
                       {'_pending_verification_response':'existing'}, {'_turn_exit_reason':'transport_error'},
                       {'api_call_count':1}):
            h,kw,original,wrapped=self.budget_fixture();kw.update(change)
            self.assertEqual(wrapped(h.agent,**kw),kw)
        h,kw,original,wrapped=self.budget_fixture();h.agent._capstone_proposal_user=('foreign',Q)
        self.assertEqual(wrapped(h.agent,**kw),kw)
        h,kw,original,wrapped=self.budget_fixture();h.agent.platform='cli'
        self.assertEqual(wrapped(h.agent,**kw),kw)

if __name__=='__main__':unittest.main()
