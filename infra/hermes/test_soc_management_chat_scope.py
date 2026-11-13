"""Regression: final Native schema loss, fabricated filters and double KST conversion."""
import copy,json,itertools,unittest
from types import SimpleNamespace as NS
from dataclasses import dataclass
from unittest.mock import patch
from pathlib import Path
from jsonschema import Draft202012Validator as V
import soc_management_run as w

@dataclass
class Prepared:
    action:str
    api_kwargs:dict
    api_messages:list
    _original_api_kwargs:dict

class Conditions(unittest.TestCase):
    def setUp(self):
        from test_event_time_contract import server,load
        diagnostic=load('_chat_contract_diag','infra/mcp/system-diagnostics-mcp.py')
        diagnostic._library=load('_chat_scope_core','infra/mcp/system_diagnostics.py')
        rows=[{'name':t['name'],'converted':t['inputSchema']} for t in diagnostic.tools()+server.TOOLS if t['name']=='get_system_diagnostics' or t['name'].startswith('search_')]
        self.catalog={'mcp__'+('system_diagnostics' if r['name']=='get_system_diagnostics' else 'security_events')+'__'+r['name']:r['converted'] for r in rows}
        self.a=NS(provider='custom',model='qwen3.6:35b',api_mode='chat_completions',base_url='http://10.200.10.10:11435/v1',_current_turn_id='one',valid_tool_names=set(self.catalog),_interrupt_requested=False,_capstone_registered_read_conditions=('one',self.catalog),_capstone_management_pending_read=('one',True))
        self.env={'CAPSTONE_MANAGEMENT_MODE':'verify','CAPSTONE_CHAT_READ_JSON':json.dumps({'request':'과거 장애와 현재 상태를 확인해줘','background':'','tools':None,'requested_at_kst':'2026-11-06T19:00:00+09:00'})}
        self.r={'model':'qwen3.6:35b','tool_choice':'required','max_tokens':1024,'reasoning_effort':'none','messages':[{'role':'user','content':'native'}],'tools':[{'type':'function','function':{'name':n,'parameters':{k:copy.deepcopy(v) for k,v in s.items() if k not in ('allOf','dependentRequired')}}} for n,s in self.catalog.items()]}
    def test_final_native_builder_restores_all_40_time_combinations(self):
        before=copy.deepcopy(self.r)
        original=lambda a,**kw:Prepared('fallthrough',self.r,self.r['messages'],copy.deepcopy(self.r))
        with patch.dict(w.os.environ,self.env,clear=True):out=w.management_selection_request_wrapper(original)(self.a,turn_id='one')
        lease=self.a._capstone_management_selection;schema=out.api_kwargs['response_format']['json_schema']['schema'];V.check_schema(schema)
        times={'since_kst':'2026-11-06T00:00:00+09:00','until_kst':'2026-11-06T19:00:00+09:00','lookback_minutes':60}
        for n,s in self.catalog.items():
            for bits in itertools.product((False,True),repeat=3):
                args={k:v for (k,v),b in zip(times.items(),bits) if b}
                if 'diagnostics' in n:args['target']='a:systemd'
                elif 'web_access' in n:args['target']='c:dvwa'
                with self.subTest(tool=n,args=args):self.assertEqual(V(s).is_valid(args),V(schema).is_valid({'request_nonce':lease['nonce'],'calls':[{'tool':n,'arguments':args}]}))
        self.assertEqual(self.r,before)
    def test_named_alert_investigation_binds_only_the_first_selection(self):
        """2026-11-13 22:47: an unasked get_wazuh_cluster_nodes read with an
        invalid value failed the whole answer; the first selection now offers
        only the alert reads the question names."""
        q='최근 30분 ModSecurity와 Wazuh 경보를 조사해서 지금 대응이 필요한 위험이 있는지 근거와 함께 판단해줘. 설정은 바꾸지 마.'
        env=dict(self.env,CAPSTONE_CHAT_READ_JSON=json.dumps({'request':q,'background':'','tools':None,'requested_at_kst':'2026-11-13T22:47:28+09:00'}))
        def offered(agent):
            original=lambda a,**kw:Prepared('fallthrough',self.r,self.r['messages'],copy.deepcopy(self.r))
            with patch.dict(w.os.environ,env,clear=True):out=w.management_selection_request_wrapper(original)(agent,turn_id='one')
            schema=out.api_kwargs['response_format']['json_schema']['schema']
            return {b['properties']['tool']['const'] for b in schema['properties']['calls']['items']['anyOf']}
        first=copy.copy(self.a)
        self.assertEqual(offered(first),{'mcp__security_events__search_modsecurity_alerts','mcp__security_events__search_wazuh_alerts'})
        later=copy.copy(self.a);later._capstone_chat_selection_turn='one'
        self.assertTrue({'mcp__system_diagnostics__get_system_diagnostics','mcp__security_events__search_suricata_alerts'}<=offered(later))
        other=copy.copy(self.a)
        env['CAPSTONE_CHAT_READ_JSON']=json.dumps({'request':'IDS 경보와 방화벽 차단 상태를 조사해줘','background':'','tools':None,'requested_at_kst':'2026-11-13T22:47:28+09:00'})
        self.assertIn('mcp__system_diagnostics__get_system_diagnostics',offered(other))

    def test_api_target_narrowing_extra_condition_and_tool_set_preserved(self):
        self.r['tools']=self.r['tools'][:1];t=self.r['tools'][0]['function'];t['parameters']['properties']['target']['enum']=['b:systemd'];t['parameters']['allOf']=[{'required':['limit']}]
        out=w.restore_registered_read_conditions(self.r,self.a);p=out['tools'][0]['function']['parameters']
        self.assertEqual(len(out['tools']),1);self.assertEqual(p['properties']['target']['enum'],['b:systemd']);self.assertIn({'required':['limit']},p['allOf']);self.assertEqual(self.r['tools'][0]['function']['parameters']['allOf'],[{'required':['limit']}])
        self.assertIs(w.chat_read_schema(t['name'],p),p)
    def test_current_systemd_metrics_keep_snapshot_scope(self):
        value={'target':'b:systemd','lookback_scope':'latest_snapshot_only_not_requested_history','observed_at_kst':'2026-11-06T20:00:00+09:00','metrics':{'failed_units_total':0,'returned_units':0,'unit_list_truncated':False,'unknown':8}}
        facts=w.observation_facts('get_system_diagnostics',NS(isError=False,content=[NS(text=json.dumps(value))]),{'target':'b:systemd'})
        row=next(r for r in facts if r.get('kind')=='diagnostics')
        self.assertEqual(row['metrics'],{'failed_units_total':0,'returned_units':0,'unit_list_truncated':False})
        text=w.literal_evidence_summary([row]);self.assertIn('현재 로드된 failed unit 0개',text);self.assertIn('과거 journal 조회나 전체 서비스 정상 판정이 아닙니다',text)
        value['metrics']['failed_units_total']=False
        facts=w.observation_facts('get_system_diagnostics',NS(isError=False,content=[NS(text=json.dumps(value))]),{'target':'b:systemd'})
        self.assertNotIn('failed_units_total',next(r for r in facts if r.get('kind')=='diagnostics')['metrics'])
    def test_stale_binding_fails_closed(self):
        self.a._current_turn_id='two'
        with self.assertRaisesRegex(RuntimeError,'turn_mismatch'):w.restore_registered_read_conditions(self.r,self.a)
    def test_no_metadata_does_not_add_authority(self):
        del self.a._capstone_registered_read_conditions
        self.assertIs(w.restore_registered_read_conditions(self.r,self.a),self.r)
    def test_optional_ids_only_from_explicit_labels_not_time_or_count(self):
        n='mcp__security_events__search_wazuh_alerts';s=self.catalog[n];old=copy.deepcopy(s)
        for q in ('오늘 systemd 경보','60분 동안 10건','27100','11월 6일'):
            self.assertNotIn('wazuh_rule_id',w.initial_event_filter_schema(n,s,q)['properties'])
        for q in ('규칙 100120','wazuh_rule_id:100120','룰 ID 100120'):
            self.assertEqual(w.initial_event_filter_schema(n,s,q)['properties']['wazuh_rule_id']['enum'],['100120'])
        self.assertEqual(s,old)
    def test_only_literal_addresses_and_explicit_agents_can_be_first_filters(self):
        n='mcp__security_events__search_wazuh_alerts';s=self.catalog[n]
        for q in ('systemd 원인 조사','에이전트 상태 50건','192.168.999.1','11:30부터'):
            out=w.initial_event_filter_schema(n,s,q)
            self.assertNotIn('source_ip',out['properties']);self.assertNotIn('agent_id',out['properties'])
        out=w.initial_event_filter_schema(n,s,'출발지 192.0.2.44 agent ID 007 확인')
        self.assertEqual(out['properties']['source_ip']['enum'],['192.0.2.44']);self.assertEqual(out['properties']['agent_id']['enum'],['007'])
        out=w.initial_event_filter_schema(n,s,'source_ip=2001:db8::1 확인')
        self.assertEqual(out['properties']['source_ip']['enum'],['2001:db8::1'])
    def test_today_uses_kst_midnight_and_request_time_without_model_arithmetic(self):
        n='mcp__security_events__search_wazuh_alerts';s=self.catalog[n];now='2026-11-06T20:00:00.123456+09:00'
        out=w.initial_event_filter_schema(n,s,'오늘 systemd 경보와 현재 상태',now)
        valid={'since_kst':'2026-11-06T00:00:00+09:00','until_kst':now}
        self.assertTrue(V(out).is_valid(valid));self.assertFalse(V(out).is_valid({}))
        for changes in ({'since_kst':'2026-11-06T11:00:00+09:00'},{'lookback_minutes':60},{'until_kst':'2026-11-06T19:00:00+09:00'}):
            self.assertFalse(V(out).is_valid(dict(valid,**changes)))
        for q in ('오늘 11시부터','어제부터 오늘까지','오늘 10:30 이후'):
            other=w.initial_event_filter_schema(n,s,q,now)
            self.assertIn('lookback_minutes',other['properties']);self.assertNotIn('enum',other['properties']['since_kst'])
        # 2026-11-13: an explicit recent window is pinned to its own length, not to today.
        other=w.initial_event_filter_schema(n,s,'오늘 최근 1시간',now)
        self.assertEqual(other['properties']['lookback_minutes']['enum'],[60]);self.assertNotIn('since_kst',other['properties'])
        for now2 in (None,'2026-11-06T11:00:00Z','invalid'):
            other=w.initial_event_filter_schema(n,s,'오늘 경보',now2)
            self.assertIn('lookback_minutes',other['properties'])
    def test_today_never_overwrites_controller_bound_interval(self):
        n='mcp__security_events__search_wazuh_alerts';s=copy.deepcopy(self.catalog[n]);s.setdefault('required',[]).extend(['since_kst','until_kst'])
        out=w.initial_event_filter_schema(n,s,'오늘 경보','2026-11-06T20:00:00+09:00')
        self.assertNotIn('enum',out['properties']['since_kst'])
    def test_required_controller_filter_preserved(self):
        n='mcp__security_events__search_wazuh_alerts';s=copy.deepcopy(self.catalog[n]);s.setdefault('required',[]).append('wazuh_rule_id')
        before=copy.deepcopy(s);out=w.initial_event_filter_schema(n,s,'오늘 경보')
        self.assertEqual(out['properties']['wazuh_rule_id'],s['properties']['wazuh_rule_id']);self.assertEqual(out['required'],s['required']);self.assertEqual(s,before)

if __name__=='__main__':unittest.main(verbosity=2)
