"""Actual component provenance and closure boundaries; no network/model calls."""
import asyncio
from contextlib import closing
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch
from test_soc_management_run import wrapper as w, Harness
import soc_management_controller as controller

spec=importlib.util.spec_from_file_location('bundle_producer',Path(__file__).parents[1]/'mcp/incident_evidence.py')
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
WINDOW={'since_kst':'2026-11-05T19:11:00+09:00','until_kst':'2026-11-05T19:11:59.999999+09:00','limit':50}
STAMP='2026-11-05T19:11:01+09:00'
IP='192.0.2.12'

def args():
    return {'events':[{'sensor':'modsecurity','arguments':{**WINDOW,'source_ip':IP}}],
        'diagnostics':[{'target':'c:apache'}],'web_context':dict(WINDOW)}

def read(name,params):
    interval={k:params[k] for k in ('since_kst','until_kst') if k in params}
    if name in ('search_modsecurity_alerts','search_suricata_alerts','search_wazuh_alerts'):
        source=name.removeprefix('search_').removesuffix('_alerts')
        rows=[{'timestamp':STAMP,'source_ip':IP,'wazuh_rule_id':'100102','request_path':'/dvwa/login.php','http_status':403}] if source=='modsecurity' else []
        return {'source':source,'source_scope':'wazuh_indexed_alerts','alerts':rows,'returned_count':len(rows),
            **{'requested_'+k:v for k,v in interval.items()},'indexed_window_total_count':None}
    if name=='get_system_diagnostics':
        return {'target':params['target'],'schema':1,'observed_at_kst':'2026-11-06T14:00:00+09:00',
            'properties':{'ActiveState':'active','SubState':'running','Result':'success','Type':'simple'}}
    service={'configured_in_file_snapshot':True,'request_path_prefix':b.PREFIXES[params['target']]}
    return {'target':params['target'],'source':'c_apache_access_snapshot','service':service,'agent':{'id':'017'},
        'returned_count':0,'actual_request_total_count':None,**{'requested_'+k:v for k,v in interval.items()}}

def fixture(value=None,reader=None):
    return b.collect(args() if value is None else value,reader or read,lambda *_:None,clock=lambda:'2026-11-06T14:00:00+09:00')

def wire(value):return NS(isError=False,content=[NS(type='text',text=json.dumps(value,ensure_ascii=False))])

def rehash(part):part['result_sha256']=hashlib.sha256(b.encoded(part['result'])).hexdigest()

class Provenance(unittest.TestCase):
    def test_model_view_restores_every_nested_web_row_field_and_original_checksum(self):
        from test_soc_management_web_view import evidence,restore
        def reader(name,params):
            value=read(name,params)
            if name=='search_web_access':value.update(evidence())
            return value
        value=fixture(reader=reader)
        for wrapped in (False,True):
            raw=json.dumps(value,ensure_ascii=False)
            if wrapped:raw=json.dumps({'result':raw},ensure_ascii=False)
            packed=w.incident_bundle_view(raw);self.assertLess(len(packed.encode()),len(raw.encode())*.9)
            shown=json.loads(json.loads(packed)['result']) if wrapped else json.loads(packed)
            self.assertEqual(shown.pop('model_view')['original_wire_sha256'],hashlib.sha256(raw.encode()).hexdigest())
            for part in shown['components']:
                if part['tool']=='search_web_access':part['result']=restore(part['result'])
                self.assertEqual(part['result_sha256'],hashlib.sha256(b.encoded(part['result'])).hexdigest())
            self.assertEqual(shown,value)
            self.assertEqual(w.incident_bundle_view(packed),packed)

    def test_model_view_rejects_invalid_provenance_and_keeps_errors(self):
        for change in (lambda v:v['components'][0].update(result_sha256='0'*64),
                       lambda v:v.update(mutation_performed=True)):
            value=fixture();change(value);raw=json.dumps(value)
            self.assertEqual(w.incident_bundle_view(raw),raw)
        raw=json.dumps({'result':json.dumps(fixture()),'isError':True})
        self.assertEqual(w.incident_bundle_view(raw),raw)

    def test_valid_bundle_preserves_scope_and_individual_facts_without_dispatch(self):
        a=args();v=fixture(a);before=copy.deepcopy((a,v));parts=w.incident_bundle_reads(a,v)
        self.assertEqual(parts,v['components']);self.assertEqual(before,(a,v))
        facts=w.observation_facts('collect_incident_evidence',wire(v),a)
        self.assertTrue(any(f.get('kind')=='events' for f in facts))
        self.assertTrue(any(f.get('kind')=='web_service' for f in facts))
        self.assertTrue(any(f.get('kind')=='diagnostics' for f in facts))
        self.assertTrue(all(f['bundle_component']['transport_tool']==w.BUNDLE_TOOL for f in facts))
        self.assertEqual(w.observation_facts('collect_incident_evidence',wire(v)),[])

    def test_request_result_index_hash_time_and_mutation_tampering_refused(self):
        changes=[lambda v:v['request']['events'][0]['arguments'].update(source_ip='192.0.2.99'),
            lambda v:v['components'][0]['arguments'].update(source_ip='192.0.2.99'),
            lambda v:v['components'][0].update(index=1),
            lambda v:v['components'][0].update(tool='unblock_ip'),
            lambda v:v['components'][0]['result'].update(returned_count=0),
            lambda v:v['components'][0].update(completed_at_kst='2026-11-06T15:00:00+09:00'),
            lambda v:v.update(mutation_performed=True),lambda v:v['components'].pop(),
            lambda v:v.update(execution_complete=False),lambda v:v.update(web_lookup='all_hosts_healthy')]
        for change in changes:
            v=fixture();change(v)
            with self.subTest(change=change):self.assertIsNone(w.incident_bundle_reads(args(),v))

    def test_forged_agent_filter_or_unrelated_target_refused_even_with_hashes(self):
        for change in ('agent','source_ip','target','extra_read'):
            v=fixture()
            if change=='agent':v['components'][-1]['arguments']['agent_id']='999'
            elif change=='source_ip':v['components'][-1]['arguments']['source_ip']=IP
            elif change=='target':v['components'][-2]['arguments']['target']='c:lab-java'
            else:
                part=copy.deepcopy(v['components'][-1]);part['index']=len(v['components']);v['components'].append(part)
            self.assertIsNone(w.incident_bundle_reads(args(),v),change)

    def test_partial_failure_is_valid_partial_evidence_not_zero_or_health(self):
        def fail(name,params):
            if name=='get_system_diagnostics':raise OSError('secret endpoint')
            return read(name,params)
        v=fixture(reader=fail);parts=w.incident_bundle_reads(args(),v)
        self.assertIsNotNone(parts);self.assertFalse(v['execution_complete'])
        facts=w.observation_facts('collect_incident_evidence',wire(v),args())
        self.assertFalse(any(f.get('kind')=='diagnostics' for f in facts))
        self.assertNotIn('secret endpoint',json.dumps(v))

    def test_all_fixed_paths_follow_actual_configuration_and_registered_agent(self):
        for target,prefix in b.PREFIXES.items():
            def reader(name,params):
                value=read(name,params)
                if name=='search_modsecurity_alerts':value['alerts'][0]['request_path']=prefix+'index'
                return value
            v=fixture(reader=reader);self.assertIsNotNone(w.incident_bundle_reads(args(),v),target)

    def test_impact_citation_requires_host_evidence_inside_cited_bundle(self):
        stamp=w.parse_instant(STAMP).timestamp();requirements={('modsecurity',IP,stamp,'100102')}
        decision={'assessment':'remediated','evidence_tools':[w.BUNDLE_TOOL]}
        self.assertTrue(w.incident_impact_missing(decision,requirements,{stamp},True))
        self.assertFalse(w.incident_impact_missing(decision,requirements,{stamp},True,{stamp}))
        self.assertTrue(w.incident_impact_missing(decision,requirements,{stamp},True,{stamp+1}))

    @unittest.skipUnless(importlib.util.find_spec('jsonschema'),'existing server jsonschema required')
    def test_status_and_bundle_options_reduce_wire_calls_and_failure_restores_individual_choices(self):
        sensor={'tool':'mcp__security_events__search_modsecurity_alerts','arguments':args()['events'][0]['arguments']}
        status={'tool':'mcp__rule_a__get_operation_status','arguments':{'request_id':'a'*32}}
        schema=b.tool()['inputSchema']
        catalog=[{'type':'function','function':{'name':o['tool'],'parameters':{'type':'object'}}} for o in (status,sensor)]
        catalog.append({'type':'function','function':{'name':w.BUNDLE_TOOL,'parameters':schema}})
        with patch.object(w,'readonly_incident_review',return_value=True),patch.object(w,'operator_diagnostic_options',return_value=[]),patch.dict(w.os.environ,{'CAPSTONE_WEB_IMPACT_REVIEW':'1'}):
            result,options=w.required_read_bundle({'tools':catalog},[{'target':'a:incident-ip','proposal_id':'a'*32}],[],[sensor],[])
            self.assertEqual(len(options),2);self.assertEqual(options[0],status)
            self.assertEqual(options[1]['tool'],w.BUNDLE_TOOL)
            self.assertEqual(options[1]['arguments']['events'],args()['events'])
            self.assertEqual(options[1]['arguments']['web_context'],WINDOW)
            result,options=w.required_read_bundle({'tools':catalog},[],[],[sensor],[],attempted=['collect_incident_evidence'])
            self.assertEqual(options,[sensor])

    def test_controller_records_one_wire_call_and_attests_nested_events(self):
        with tempfile.TemporaryDirectory() as root, closing(controller.Store(root)) as store:
            cid=store.new_case('bundle-boundary')
            case=dict(store.db.execute('select * from cases where id=?',(cid,)).fetchone(),mode='verify')
            trace=controller.Trace(store,case,store.start(case))
            trace.accept({'type':'tool_use','name':w.BUNDLE_TOOL,'input':args()})
            trace.accept({'type':'tool_result','name':w.BUNDLE_TOOL,'is_error':False,'output':json.dumps({'content':[{'type':'text','text':json.dumps(fixture())}],'isError':False})})
            self.assertFalse(trace.protocol_error);self.assertFalse(trace.tool_error)
            self.assertEqual(store.db.execute('select count(*) from tool_calls').fetchone()[0],1)
            self.assertEqual(len(trace.bundle_sensor_receipts),1)
            wanted={('modsecurity',IP,w.parse_instant(STAMP).timestamp(),'100102')}
            self.assertEqual(trace.bundle_sensor_receipts,wanted)

    def test_gate_argument_stays_bounded_and_preserves_exact_source(self):
        value=controller.management_gate_argument(Path(w.__file__).read_bytes())
        self.assertLess(len(value.encode()),98304)
        self.assertIn('b85decode',value)

    def test_native_wire_audit_and_guard_keep_full_bundle_without_fake_calls(self):
        def reader(name,params):
            result=read(name,params)
            if name=='search_modsecurity_alerts':result['alerts'][0]['signature']='untrusted sensor sample '*1100
            return result
        value=fixture(reader=reader);raw=json.dumps(value,ensure_ascii=False);self.assertGreater(len(raw),16000)
        outer=json.dumps({'result':raw},ensure_ascii=False)
        def check(h):
            actual=asyncio.run(h.ClientSession(wire(value).content).call_tool('collect_incident_evidence',args()))
            self.assertFalse(actual.is_error)
            h.Emitter().on_tool_progress('tool.completed',w.BUNDLE_TOOL,result=outer,tool_call_id='bundle-wire',duration=0.25)
            h.Emitter().emit_result({'final_response':'영향 미확인\nMANAGEMENT_STATUS: needs_review'})
        harness=Harness();harness.run(check,'verify')
        self.assertEqual(len(harness.wire_calls),1)
        emitted=[json.loads(x) for x in harness.stdout.getvalue().splitlines()]
        self.assertEqual(len(emitted),1);self.assertEqual(controller.tool_payload(emitted[0]['output']),value)
        self.assertEqual(harness.guard_evidence[0][1]['content'],raw)

    def test_native_rejects_mismatched_bundle_before_counting_it_as_evidence(self):
        value=fixture();value['components'][0]['arguments']['source_ip']='192.0.2.99'
        def check(h):
            result=asyncio.run(h.ClientSession(wire(value).content).call_tool('collect_incident_evidence',args()))
            self.assertTrue(result.is_error)
            self.assertEqual(json.loads(result.content[0].text)['stage'],'after_mcp')
            h.Emitter().emit_result({'final_response':'조사 완료'})
        harness=Harness();harness.run(check,'verify')
        self.assertEqual(harness.emissions[0][0]['final_response'],w.NO_OBSERVATION_REPORT)
