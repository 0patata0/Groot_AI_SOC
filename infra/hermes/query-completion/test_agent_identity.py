"""Identity/status reads must execute and render observed, nonconstant IDs."""
import copy
import unittest
from test_alignment import H
from test_expanded_reads import call
from test_repeated_reads import schemas


def observed(name='groot-siem-host', agent_id='073', state='active', ip='127.0.0.1'):
    return call('get_wazuh_agents', f'Agent ID: {agent_id}\nName: {name}\nIP: {ip}\nStatus: {state.upper()}\nLast Keep Alive: 2026-10-27T04:00:00+00:00\n', {'status':state})


def empty(state):
    return call('get_wazuh_agents','No Wazuh agents matching the criteria found.',{'status':state})


class Identity(unittest.TestCase):
    def test_short_and_full_prompts_share_the_observed_target(self):
        for q in ['B 호스트 ID와 상태','B 호스트(Wazuh 에이전트)의 ID와 현재 연결 상태를 실제 조회하고 서로 검증해줘.',
                  '[socadmin] @hermes B 서버의 에이전트 연결 상태', 'SIEM 호스트 등록 ID 확인']:
            with self.subTest(q=q):
                p=H.read_plan(q);self.assertEqual(p['kind'],'agent_identity');self.assertEqual(p['subjects'][0]['agent_name'],'groot-siem-host')
                self.assertTrue(H.structured_read(q));self.assertEqual(H.tool_scope(q),{H.READ.AGENTS})
                self.assertTrue(H.missing_reads(q,[]));self.assertEqual(H.missing_reads(q,[observed()]),[])
                answer=H.read_report(q,[observed()]);self.assertIn('| 073 | groot-siem-host | 127.0.0.1 | ACTIVE |',answer)
                self.assertIn('13:00:00',answer);self.assertNotIn('003',answer)

    def test_host_and_manager_keep_distinct_names_even_with_same_ip(self):
        q='B 호스트와 Wazuh Manager ID와 상태를 비교해줘'
        a=observed();a['result']+=observed('wazuh.manager','007')['result']
        import hashlib
        a['result_sha256']=hashlib.sha256(a['result'].encode()).hexdigest()
        self.assertEqual(H.missing_reads(q,[a]),[]);v=H.read_report(q,[a])
        self.assertIn('| 073 | groot-siem-host',v);self.assertIn('| 007 | wazuh.manager',v);self.assertIn('레코드: 2개',v)
        p=H.read_plan('B 서버의 Wazuh Manager 연결 상태');self.assertEqual(p['subjects'],[{'agent_name':'wazuh.manager','agent_id':None}])

    def test_inactive_target_is_found_without_claiming_unregistered(self):
        q='C 호스트 연결 상태';p=H.read_plan(q)
        self.assertEqual(H.READ.identity_states(p,[]),['active'])
        self.assertEqual(H.READ.identity_states(p,[empty('active')]),['disconnected','pending','never_connected'])
        calls=[empty('active'),observed('groot-web','081','disconnected')]
        self.assertEqual(H.missing_reads(q,calls),[]);self.assertIn('DISCONNECTED',H.read_report(q,calls))

    def test_all_agents_need_all_states_and_count_actual_returned_rows(self):
        q='Wazuh 에이전트 전체 목록';p=H.read_plan(q)
        self.assertEqual(set(H.READ.identity_states(p,[])),set(H.READ.STATES))
        calls=[observed(),empty('disconnected'),empty('pending'),empty('never_connected')]
        self.assertEqual(H.missing_reads(q,calls),[]);self.assertIn('레코드: 1개',H.read_report(q,calls))
        self.assertTrue(H.missing_reads(q,calls[:-1]))

    def test_unknown_duplicate_conflicting_id_and_hash_failure_remain_unverified(self):
        for q,calls in [('B 호스트 상태',[observed('wazuh.manager','000')]),
                        ('B 호스트 상태',[observed(),observed('capstone-siem-host','074','disconnected')]),
                        ('B 호스트 ID 000 상태',[observed()])]:
            self.assertTrue(H.missing_reads(q,calls))
        bad=observed();bad['result_sha256']='0'*64
        self.assertTrue(H.missing_reads('B 호스트 상태',[bad]));self.assertNotIn('| 073 |',H.read_report('B 호스트 상태',[bad]))

    def test_native_exact_name_reads_satisfy_only_the_matching_requested_assets(self):
        q='B 호스트와 Wazuh Manager 연결 상태';host=observed();host['arguments']['name']='groot-siem-host'
        manager=observed('wazuh.manager','007');manager['arguments']['name']='wazuh.manager'
        self.assertTrue(H.missing_reads(q,[host]));self.assertEqual(H.missing_reads(q,[host,manager]),[])
        self.assertIn('레코드: 2개',H.read_report(q,[host,manager,observed()]))
        self.assertTrue(H.missing_reads('Wazuh 에이전트 전체 목록',[host,manager]))
        host['arguments']['name']='B';self.assertTrue(H.missing_reads('B 호스트 상태',[host]))

    def test_native_wazuh_status_icons_do_not_hide_observed_agents(self):
        q='B 호스트 연결 상태';c=observed();c['result']=c['result'].replace('Status: ACTIVE','Status: 🟢 ACTIVE')
        import hashlib
        c['result_sha256']=hashlib.sha256(c['result'].encode()).hexdigest()
        self.assertEqual(H.missing_reads(q,[c]),[]);self.assertIn('🟢 ACTIVE',H.read_report(q,[c]))
        c['result']=c['result'].replace('🟢 ACTIVE','ACTIVE but disconnected');c['result_sha256']=hashlib.sha256(c['result'].encode()).hexdigest()
        self.assertTrue(H.missing_reads(q,[c]))

    def comparison(self, q, answer, calls, truncated=False):
        import json
        envelope='peer task\nUNTRUSTED_REVIEW_DATA\n'+json.dumps({'other_agent_answer':answer,'other_answer_truncated':truncated})
        return H.READ.identity_comparison(H.read_plan(q),envelope,calls,H.EVIDENCE)

    def test_peer_compares_dynamic_identity_fields_without_inventing_asset_disagreement(self):
        q='B 호스트 ID와 연결 상태';c=observed();other=H.read_report(q,[c])
        result=self.comparison(q,other,[c]);self.assertTrue(result['complete']);self.assertEqual(result['verdict'],'matching_observed_fields')
        self.assertIn('073',result['text']);self.assertNotIn('B 호스트와 다른',result['text'])

    def test_peer_reports_differences_and_does_not_turn_them_into_attack_or_cause(self):
        q='B 호스트 연결 상태';other=H.read_report(q,[observed()]);fresh=[empty('active'),observed(state='disconnected')]
        result=self.comparison(q,other,fresh);self.assertTrue(result['complete']);self.assertEqual(result['verdict'],'observed_difference')
        self.assertIn('관측 시점 차이인지',result['text']);self.assertIn('active | disconnected',result['text'])

    def test_peer_missing_truncated_and_duplicate_claims_are_not_verified(self):
        q='B 호스트 연결 상태';c=observed();other=H.read_report(q,[c]);row=next(l for l in other.splitlines() if l.startswith('| 073 |'))
        for text, calls, cut in [('B는 정상',[c],False),(other,[],False),(other,[c],True),(other.replace(row,row+'\n'+row),[c],False)]:
            self.assertFalse(self.comparison(q,text,calls,cut)['complete'])

    def test_failed_read_is_not_success_and_not_repeated_by_selector(self):
        q='B 호스트 상태';bad=call('get_wazuh_agents','Error: unavailable',{'status':'active'});bad['is_error']=True
        self.assertTrue(H.missing_reads(q,[bad]));self.assertEqual(H.refine_read_schemas(q,schemas(),[bad]),{})

    def test_model_selection_is_readonly_and_cannot_guess_name_filter(self):
        q='B 호스트 상태';s=H.refine_read_schemas(q,schemas(),[])
        self.assertEqual(set(s),{H.READ.AGENTS});self.assertEqual(set(s[H.READ.AGENTS]['properties']),{'status'})
        self.assertEqual(s[H.READ.AGENTS]['properties']['status']['enum'],['active']);self.assertFalse(s[H.READ.AGENTS]['additionalProperties'])
        self.assertEqual(H.refine_read_schemas(q,schemas(),[observed()]),{})

    def test_requests_for_other_meaning_or_changes_are_not_narrowed(self):
        for q in ['B 호스트 상태 확인하고 재시작해줘','B 호스트 연결이 끊긴 원인을 분석해줘','B 호스트 연결 상태라는 문장을 번역해줘',
                  '도구 없이 B 호스트 상태를 설명만 해줘','WAF ID 073 룰 상태','현재 비활성 Wazuh 에이전트 목록을 보여줘','Wazuh IP 10.0.0.9 상태','Wazuh linux 그룹 목록']:
            p=H.read_plan(q);self.assertFalse(p and p['kind']=='agent_identity',q)

    def test_explicit_status_or_excluded_host_is_preserved(self):
        p=H.read_plan('B 호스트 disconnected 상태를 확인해줘');self.assertEqual(p['states'],['disconnected'])
        p=H.read_plan('B 호스트는 빼고 C 호스트 연결 상태');self.assertEqual(len(p['subjects']),1);self.assertEqual(p['subjects'][0]['agent_name'],'groot-web')
        self.assertTrue(H.missing_reads('B 호스트 disconnected 상태',[observed()]))

    def test_malformed_or_wrong_state_payload_does_not_count_as_empty(self):
        for raw in ['Agent ID: 073\nName: groot-siem-host\nIP: x\n',observed(state='disconnected')['result']]:
            c=call('get_wazuh_agents',raw,{'status':'active'})
            self.assertTrue(H.missing_reads('B 호스트 상태',[c]))

if __name__=='__main__':unittest.main()
