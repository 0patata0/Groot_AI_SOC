"""Incident completion requirements persist without choosing a risk verdict."""
import asyncio,copy,json,os,tempfile,types,unittest
from pathlib import Path
from unittest import mock
import soc_management_controller as controller
import soc_management_run as gate
import workflow_contract

READ='mcp__wazuh_ro__get_wazuh_alert_summary'

def report(assessment='unresolved',status='needs_review',tools=(READ,)):
    return ('실제 반환 표본만 확인했으며 전체 영향은 아직 미확인입니다.\nINCIDENT_DISPOSITION: '+
        json.dumps({'assessment':assessment,'basis':'실제 도구의 반환 표본과 현재 확인할 수 없는 전체 영향 범위를 구분한 판단입니다.',
                    'evidence_tools':list(tools)},ensure_ascii=False)+'\nMANAGEMENT_STATUS: '+status)

class DurableRequirement(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.store=controller.Store(self.tmp.name);self.addCleanup(self.store.close)
        self.cid=self.store.new_case('human-investigation','verify');self.store.db.commit()

    def test_requirement_survives_reopen_and_cannot_be_cleared_by_later_lookup(self):
        self.store.set_meta('unrelated','preserved');self.store.db.commit()
        self.store.require_incident_disposition(self.cid,'chat_investigation')
        later=controller.Store(self.tmp.name);self.addCleanup(later.close)
        prepared=controller.verification_case(later,{'id':self.cid,'mode':'verify','session_id':None,
            'incident_disposition_required':False})
        self.assertTrue(prepared['incident_disposition_required'])
        self.assertIn('CAPSTONE_INCIDENT_DISPOSITION_REQUIRED=1',controller.command_for(prepared))
        self.assertEqual(later.meta('unrelated'),'preserved')
        self.assertEqual(later.db.execute("SELECT count(*) FROM meta WHERE key LIKE 'incident_completion/%'").fetchone()[0],1)

    def test_plain_lookup_keeps_existing_completion_and_no_root_flag(self):
        case=controller.verification_case(self.store,{'id':self.cid,'mode':'verify','session_id':None})
        self.assertFalse(case['incident_disposition_required'])
        self.assertNotIn('CAPSTONE_INCIDENT_DISPOSITION_REQUIRED=1',controller.command_for(case))

    def test_contract_is_case_bound_and_not_shared_by_another_request(self):
        other=self.store.new_case('another-human-lookup','verify');self.store.db.commit()
        self.store.require_incident_disposition(self.cid,'chat_investigation')
        self.assertFalse(self.store.requires_incident_disposition(other))

    def test_corrupt_or_forged_contract_fails_closed_without_overwriting(self):
        for raw in ('{}','{"required":false}',controller.canonical({'version':True,'required':True,'origin':'chat_investigation'}),
                    '{"version":1,"required":true,"required":false,"origin":"chat_investigation"}'):
            with self.subTest(raw=raw):
                self.store.set_meta('incident_completion/'+self.cid,raw);self.store.db.commit()
                with self.assertRaisesRegex(controller.ControllerError,'contract_invalid'):
                    self.store.require_incident_disposition(self.cid,'chat_investigation')
                self.assertEqual(self.store.meta('incident_completion/'+self.cid),raw)

    def test_unknown_case_origin_and_non_boolean_flag_are_rejected(self):
        with self.assertRaisesRegex(controller.ControllerError,'case_missing'):
            self.store.require_incident_disposition('f'*32,'chat_investigation')
        with self.assertRaisesRegex(controller.ControllerError,'origin_invalid'):
            self.store.require_incident_disposition(self.cid,'model_text')
        for flag in ('1',1,None,[],{}):
            with self.subTest(flag=flag),self.assertRaisesRegex(controller.ControllerError,'flag_invalid'):
                controller.command_for({'mode':'verify','session_id':None,'incident_disposition_required':flag})

    def test_missing_judgment_cannot_complete_a_durable_investigation(self):
        self.store.require_incident_disposition(self.cid,'chat_investigation')
        case=dict(self.store.db.execute('SELECT * FROM cases WHERE id=?',(self.cid,)).fetchone())
        rid=self.store.start(case);trace=controller.Trace(self.store,case,rid)
        trace.accept({'type':'system','subtype':'init','session_id':'fixture'})
        trace.accept({'type':'tool_use','name':READ,'input':{}})
        trace.accept({'type':'tool_result','name':READ,'output':'{"alerts": []}','is_error':False})
        trace.accept({'type':'result','session_id':'fixture','exit_code':0,'text':'표본 조회 자료를 확인했습니다.\nMANAGEMENT_STATUS: resolved'})
        result=trace.finish(0)
        self.assertEqual(result['state'],'needs_review')
        row=self.store.db.execute('SELECT detail,final_text FROM cases WHERE id=?',(self.cid,)).fetchone()
        self.assertEqual(row['detail'],'incident_disposition_missing')
        self.assertNotIn('MANAGEMENT_STATUS: resolved',row['final_text'])

    def test_valid_model_choice_is_not_changed_by_the_contract(self):
        self.store.require_incident_disposition(self.cid,'chat_investigation')
        case=dict(self.store.db.execute('SELECT * FROM cases WHERE id=?',(self.cid,)).fetchone())
        rid=self.store.start(case);trace=controller.Trace(self.store,case,rid)
        trace.accept({'type':'system','subtype':'init','session_id':'fixture'})
        trace.accept({'type':'tool_use','name':READ,'input':{}})
        trace.accept({'type':'tool_result','name':READ,'output':'{"alerts": []}','is_error':False})
        chosen=report('unresolved','monitor')
        trace.accept({'type':'result','session_id':'fixture','exit_code':0,'text':chosen})
        self.assertEqual(trace.finish(0)['state'],'monitor')
        self.assertEqual(self.store.db.execute('SELECT final_text FROM cases WHERE id=?',(self.cid,)).fetchone()[0],chosen)

class CompletionGuard(unittest.TestCase):
    def test_only_root_flag_enables_the_requirement_and_malformed_flags_fail(self):
        text='CAPSTONE_INCIDENT_DISPOSITION_REQUIRED=1\nMANAGEMENT_STATUS: resolved'
        with mock.patch.dict(os.environ,{},clear=True):
            self.assertIsNone(gate.incident_completion_error(text,{READ}))
        with mock.patch.dict(os.environ,{'CAPSTONE_INCIDENT_DISPOSITION_REQUIRED':'1'},clear=True):
            self.assertEqual(gate.incident_completion_error(text,{READ}),'incident_disposition_missing')
        for flag in ('0','true','yes',''):
            with mock.patch.dict(os.environ,{'CAPSTONE_INCIDENT_DISPOSITION_REQUIRED':flag},clear=True):
                with self.assertRaisesRegex(RuntimeError,'flag_invalid'):gate.incident_completion_required()

    def test_lookup_and_non_closing_reports_do_not_require_a_fabricated_judgment(self):
        for status in ('monitor','needs_review','awaiting_approval'):
            self.assertIsNone(gate.incident_completion_error('본문\nMANAGEMENT_STATUS: '+status,{READ},required=True))
        self.assertIsNone(gate.incident_completion_error('조회 완료\nMANAGEMENT_STATUS: resolved',{READ},required=False))

    def test_closing_judgment_must_be_unique_valid_and_use_this_runs_receipts(self):
        self.assertEqual(gate.incident_completion_error(report(status='resolved'),{READ},required=True),'unresolved_disposition_marked_resolved')
        self.assertEqual(gate.incident_completion_error(report('benign','resolved'),set(),required=True),'incident_disposition_evidence_missing')
        self.assertIsNone(gate.incident_completion_error(report('benign','resolved'),{READ},required=True))
        duplicated=report('benign','resolved')+'\n'+report('benign','resolved')
        self.assertIsNone(gate.management_status(duplicated))
        self.assertEqual(gate.parse_incident_disposition(duplicated,{READ})[1],'incident_disposition_missing')

    def test_repair_uses_shared_skill_without_forcing_a_tool_or_choosing_benign(self):
        import test_soc_management_grounding as fixture
        h=fixture.Grounding();h.setUp();h.completed.append(READ)
        h.kw['assistant_message'].content='반환 표본만 확인했습니다.\nMANAGEMENT_STATUS: resolved'
        callback=gate.grounding_wrapper(lambda agent,**kw:'original',
            types.SimpleNamespace(FinalResponseVerdict=types.SimpleNamespace),lambda rows,row:rows.append(row),
            lambda rows,user:0,h.completed,successful_reads={READ})
        with mock.patch.dict(os.environ,{'CAPSTONE_INCIDENT_DISPOSITION_REQUIRED':'1'}):
            result=callback(h.agent,**h.kw)
            self.assertEqual(result.action,'continue')
            nudge=h.kw['messages'][-1]['content']
            self.assertIn('## 사건 조사 완료',nudge)
            self.assertIn('형식을 맞추려고 benign/remediated를 선택하지 않는다',nudge)
            self.assertEqual(h.agent._build_api_kwargs()['tool_choice'],'auto')
            self.assertNotIn('incident_disposition_missing',gate.LITERAL_REPAIR_ISSUES)
            h.kw['codex_ack_continuations']=1
            self.assertEqual(callback(h.agent,**h.kw),'original')
        self.assertEqual(h.completed,[READ])

    def test_final_emitter_keeps_real_facts_if_repair_budget_was_exhausted(self):
        from test_soc_management_run import Harness
        h=Harness();data={'target':'c:apache','observed_at_kst':'2026-11-06T00:12:40+09:00',
            'properties':{'ActiveState':'active','SubState':'running'}}
        def check(fake):
            os.environ['CAPSTONE_INCIDENT_DISPOSITION_REQUIRED']='1'
            asyncio.run(fake.ClientSession([types.SimpleNamespace(text=json.dumps(data))]).call_tool(
                'get_system_diagnostics',{'target':'c:apache'}))
            fake.Emitter().emit_result({'final_response':'현재 자료를 확인했습니다.\nMANAGEMENT_STATUS: resolved'})
        h.run(check,'verify');out=h.emissions[0][0]['final_response']
        self.assertEqual(gate.management_status(out),'needs_review');self.assertIn('c:apache',out)
        self.assertNotIn('INCIDENT_DISPOSITION:',out)

    def test_skill_section_is_shared_and_not_a_new_permission(self):
        section=workflow_contract.section_policy(('soc-investigate',),'incident-completion')
        self.assertIn('도구·쓰기·승인 권한을 늘리지 않는다',section)
        self.assertIn(section.split('\n',2)[2],workflow_contract.policy(('soc-investigate',)))

    def test_completed_opaque_read_is_not_a_closing_judgment(self):
        from test_soc_management_run import Harness
        h=Harness()
        def check(fake):
            os.environ['CAPSTONE_INCIDENT_DISPOSITION_REQUIRED']='1'
            asyncio.run(fake.ClientSession([types.SimpleNamespace(text='{"opaque_observation":"returned"}')]).call_tool(
                'get_wazuh_alert_summary',{}))
            fake.Emitter().emit_result({'final_response':'최종 조사를 완료했습니다.\nMANAGEMENT_STATUS: resolved'})
        h.run(check,'verify');out=h.emissions[0][0]['final_response']
        self.assertEqual(len(h.wire_calls),1)
        self.assertEqual(gate.management_status(out),'needs_review')
        self.assertIn('구조화해 표시할 근거 미확인',out)
        self.assertNotIn('MANAGEMENT_STATUS: resolved',out)

class SDKJudgment(unittest.TestCase):
    def setUp(self):
        # Native worker fixtures deliberately add /opt paths on B. Bind this
        # contract test to the frozen SDK file, never the installed old module.
        import importlib.util
        path=Path(__file__).resolve().parents[1]/'ollama-trial/harness.py'
        spec=importlib.util.spec_from_file_location('_incident_completion_subject',path)
        self.harness=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.harness)

    def test_explicit_unresolved_judgment_cannot_carry_a_resolved_status(self):
        harness=self.harness
        from test_incident_closure import sensor
        text=report(status='resolved',tools=('mcp__security_events__search_modsecurity_alerts',))
        self.assertIn('unresolved_disposition_marked_resolved',harness.incident_completion_issues(
            '실제 탐지 사건의 영향을 조사해줘',text,[sensor()]))

    def test_general_wazuh_investigation_needs_judgment_but_plain_lookup_does_not(self):
        harness=self.harness
        from test_incident_closure import call
        receipt=call('wazuh-ro','get_wazuh_alert_summary',{}, {'alerts':[]})
        q='최근 Wazuh 경보를 조사하고 미확인 영향을 설명해줘'
        self.assertIn('incident_disposition_missing',harness.incident_completion_issues(q,'표본을 조회했습니다.',[receipt]))
        self.assertEqual(harness.incident_completion_issues('Wazuh 경보 목록 보여줘','표본을 조회했습니다.',[receipt]),[])
        self.assertEqual(harness.incident_completion_issues(q,report(),[receipt]),[])

if __name__=='__main__':unittest.main()
