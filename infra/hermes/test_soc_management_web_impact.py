import copy,json,unittest
from unittest.mock import patch
from test_soc_management_run import wrapper as m,definition

class WebImpactNavigation(unittest.TestCase):
    def setUp(self):
        self.plan=[{'tool':'mcp__security_events__search_modsecurity_alerts','arguments':{
            'source_ip':'192.0.2.20','since_kst':'2026-10-30T11:00:00+09:00',
            'until_kst':'2026-10-30T11:00:59.999999+09:00','limit':50}}]
        self.events={'kind':'events','source':'modsecurity','observations':[{'request_path':'/dvwa/login.php','timestamp_kst':'2026-10-30T11:00:20+09:00','source_ip':'192.0.2.20','sensor_agent':'collector-sec','sensor_rule_ids':['942100']}]}
        self.target={'kind':'web_service','target':'c:dvwa','agent':{'id':'007','name':'test-web'},
            'service':{'configured_in_file_snapshot':True,'request_path_prefix':'/dvwa/','frontend_binding_verified':False}}
        self.request={'tools':[definition('mcp__security_events__'+n) for n in
            ('get_web_service_target','search_web_access','search_wazuh_alerts')]+[definition('mcp__rule_write_a__temporarily_contain_ip')]}
        props={k:{'type':'string'} for k in ('target','agent_id','since_kst','until_kst')};props['limit']={'type':'integer'}
        for t in self.request['tools']:t['function']['parameters']={'type':'object','properties':props}
        self.env=patch.dict(m.os.environ,{'CAPSTONE_MANAGEMENT_MODE':'verify','CAPSTONE_WEB_IMPACT_REVIEW':'1'});self.env.start();self.addCleanup(self.env.stop)
    def names(self,r):return [t['function']['name'] for t in r['tools']]
    def test_discovery_needs_real_web_path_and_does_not_choose_an_asset_or_dispatch(self):
        before=copy.deepcopy(self.request);r=m.web_impact_review_request(self.request,[self.events],[],self.plan)
        self.assertEqual(self.names(r),['mcp__security_events__get_web_service_target']);self.assertEqual(r['tool_choice'],'required')
        self.assertNotIn('arguments',r);self.assertEqual(self.request,before)
        self.assertIs(m.web_impact_review_request(self.request,[],[],self.plan),self.request)
    def test_candidate_reads_use_only_observed_registration_and_exact_incident_bounds(self):
        r=m.web_impact_review_request(self.request,[self.events,self.target],['get_web_service_target'],self.plan)
        self.assertEqual(set(self.names(r)),{'mcp__security_events__search_web_access','mcp__security_events__search_wazuh_alerts'})
        for t in r['tools']:
            p=t['function']['parameters'];self.assertNotIn('source_ip',p['properties']);self.assertNotIn('wazuh_rule_id',p['properties'])
            self.assertEqual(p['properties']['since_kst']['enum'],[self.plan[0]['arguments']['since_kst']])
            self.assertFalse(p['additionalProperties']);self.assertIn('목적지 확정',t['function']['description'])
        host=next(t for t in r['tools'] if t['function']['name'].endswith('search_wazuh_alerts'))
        self.assertEqual(host['function']['parameters']['properties']['agent_id']['enum'],['007'])
        self.assertFalse(self.target['service']['frontend_binding_verified'])
    def test_wrong_path_unconfigured_and_invalid_registration_never_supply_a_host_id(self):
        for change in ({'request_path_prefix':'/other/'},{'configured_in_file_snapshot':False}):
            bad=dict(self.target,service=dict(self.target['service'],**change))
            self.assertIs(m.web_impact_review_request(self.request,[self.events,bad],['get_web_service_target'],self.plan),self.request)
        bad=dict(self.target,agent={'id':7});self.assertIs(m.web_impact_review_request(self.request,[self.events,bad],['get_web_service_target'],self.plan),self.request)
    def test_attempts_finish_navigation_but_are_not_success_or_security_clearance(self):
        facts=[self.events,self.target];r=m.web_impact_review_request(self.request,facts,['search_web_access'],self.plan)
        self.assertEqual(self.names(r),['mcp__security_events__search_wazuh_alerts'])
        self.assertIs(m.web_impact_review_request(self.request,facts,['search_web_access','search_wazuh_alerts'],self.plan),self.request)
        self.assertIs(m.web_impact_review_request(self.request,[self.events],['get_web_service_target'],self.plan),self.request)
    def test_final_stop_requires_each_missing_web_stage_once_and_preserves_model_execution(self):
        import types
        import test_soc_management_grounding as fixtures
        g=fixtures.Grounding('test_zero_calls_retry_offers_reads_once_without_selecting_tool_or_arguments');g.setUp()
        g.agent.tools=self.request['tools'];g.agent._build_api_kwargs=lambda:copy.deepcopy(self.request)
        g.kw['assistant_message'].content='실제 영향은 미확인입니다.\nMANAGEMENT_STATUS: needs_review'
        facts=[self.events];attempted=[];a=self.plan[0]['arguments'];receipts=[{'tool':self.plan[0]['tool'],
            'source_ip':a['source_ip'],'since':m.parse_instant(a['since_kst']),'until':m.parse_instant(a['until_kst'])}]
        call=m.grounding_wrapper(lambda agent,**kw:'original',types.SimpleNamespace(FinalResponseVerdict=types.SimpleNamespace),
            lambda rows,row:rows.append(row),lambda rows,user:0,['get_operation_status','search_modsecurity_alerts'],facts,
            sensor_requirements=self.plan,sensor_receipts=receipts,attempted_reads=attempted)
        v=call(g.agent,**g.kw);self.assertEqual(v.action,'continue');self.assertEqual(v.codex_ack_continuations,1)
        self.assertIn('candidate_backend_reads',g.kw['messages'][-1]['content'])
        self.assertEqual(self.names(g.agent._build_api_kwargs()),['mcp__security_events__get_web_service_target'])
        g.kw['codex_ack_continuations']=1;self.assertEqual(call(g.agent,**g.kw),'original')
        attempted.append('get_web_service_target');facts.append(self.target)
        v=call(g.agent,**g.kw);self.assertEqual(v.codex_ack_continuations,2)
        self.assertEqual(set(self.names(g.agent._build_api_kwargs())),{'mcp__security_events__search_web_access','mcp__security_events__search_wazuh_alerts'})
        g.kw['codex_ack_continuations']=2;self.assertEqual(call(g.agent,**g.kw),'original')
        attempted.extend(['search_web_access','search_wazuh_alerts'])
        self.assertEqual(call(g.agent,**g.kw),'original')

    def test_manage_and_unrelated_readonly_requests_and_missing_tool_fail_closed(self):
        with patch.dict(m.os.environ,{'CAPSTONE_MANAGEMENT_MODE':'manage'}):
            self.assertIs(m.web_impact_review_request(self.request,[self.events],[],self.plan),self.request)
        with patch.dict(m.os.environ,{'CAPSTONE_WEB_IMPACT_REVIEW':'0'}):
            self.assertIs(m.web_impact_review_request(self.request,[self.events],[],self.plan),self.request)
        with self.assertRaisesRegex(RuntimeError,'web_impact_read_tools_unavailable'):
            m.web_impact_review_request({'tools':[]},[self.events],[],self.plan)
