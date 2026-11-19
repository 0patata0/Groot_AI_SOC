"""Native service phases preserve missing identity through reads and reports."""
import copy
from datetime import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator
import test_gateway_evidence as base
import test_service_catalog_phase as service_base

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'infra/mcp').is_dir())
spec=importlib.util.spec_from_file_location('native_phase_identity_fixture',
    ROOT/'infra/hermes/test_service_identity_discovery.py')
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
DIAG=fixture.DIAG;INV=fixture.INV

class ServiceIdentityPhase(unittest.TestCase):
    setUp=base.GatewayEvidence.setUp
    build=base.GatewayEvidence.build
    respond=base.GatewayEvidence.respond
    options=service_base.ServiceCatalogPhase.options
    initial=service_base.ServiceCatalogPhase.initial

    def prepare(self,question='B 서버 Vector 현재 상태 보여줘'):
        self.at=datetime.now(base.H.EVIDENCE.KST).isoformat()
        tools=fixture.catalog()['tools']
        for t in tools:t['type']='function'
        with patch.object(base,'catalog',return_value=tools):
            return base.GatewayEvidence.prepare(self,question=question,at=self.at)

    def observations(self,loaded=False):
        phase=self.h.agent._capstone_gateway_phase
        self.assertIsNotNone(phase)
        calls=[]
        for option in phase['service_plan']['requirements']:
            args=option['arguments'];target=args['target']
            data={'schema':1,'host':'b','target':target,'mutation_performed':False,
                  'status':'observed','observed_at_kst':self.at,'age_seconds':0}
            if target=='b:vector':
                data.update(unit='capstone-vector.service',properties={
                    'Type':'oneshot' if loaded else None,
                    'LoadState':'loaded' if loaded else 'not-found',
                    'ActiveState':'inactive','SubState':'dead','Result':'success'})
            else:data.update(kind='runtime',status='ok',metrics={},codes=[],limits=[],
                             lookback_scope='latest_snapshot_only_not_requested_history')
            calls.append(self.call(DIAG,args,data))
        self.calls=calls;self.rows();return calls

    @staticmethod
    def call(name,args,data,error=False):
        raw=json.dumps(data,ensure_ascii=False)
        return {'server':'system-diagnostics','name':name.split('__')[-1],
            'arguments':copy.deepcopy(args),'result':raw,
            'result_sha256':hashlib.sha256(raw.encode()).hexdigest(),'is_error':error}

    def rows(self):
        self.h.kw['messages']=self.h.kw['messages'][:2]+base.H.linked_rows(self.calls)

    def discovery(self,failed=False):
        self.build();options=self.options();self.assertEqual(len(options),2)
        self.respond(self.initial())
        for i,option in enumerate(options):
            row=fixture.inventory(option['arguments'],at=self.at)
            self.calls.append(self.call(INV,option['arguments'],row['data'],failed and i==0))
        self.rows();return self.build()

    def report(self):
        phase=self.h.agent._capstone_gateway_phase
        return {'request_nonce':phase['nonce'],'more_evidence':False,'report':{
            'scope':'unresolved_service_lookup','assessment':'unresolved',
            'status':'needs_review','evidence_indexes':list(range(len({
                row['tool']for row in phase['context']['untrusted_completed_reads']})))}}

    def test_missing_unit_selects_same_host_existing_inventory(self):
        self.prepare();self.respond(self.initial());self.observations();self.build()
        phase=self.h.agent._capstone_gateway_phase
        self.assertEqual(phase['kind'],'initial')
        self.assertEqual({x['arguments']['view']for x in self.options()},{'services','containers'})
        self.assertTrue(all(x['tool']==INV and x['arguments']['host']=='b'for x in self.options()))
        result=self.respond(self.initial())
        self.assertTrue(all(x.function.name==INV for x in result.response.choices[0].message.tool_calls))

    def test_completed_lists_require_unresolved_service_report(self):
        self.prepare();self.respond(self.initial());self.observations();self.discovery()
        phase=self.h.agent._capstone_gateway_phase
        self.assertEqual(phase['kind'],'service');self.assertTrue(phase['context']['lookup_incomplete'])
        validator=Draft202012Validator(phase['schema']);validator.validate(self.report())
        bad=self.report();bad['report'].update(scope='verified_service_lookup',assessment='observed',status='resolved')
        self.assertFalse(validator.is_valid(bad))
        result=self.respond(self.report());text=result.response.choices[0].message.content
        self.assertIn('MANAGEMENT_STATUS: needs_review',text)
        self.assertIn('capstone-vector.service',text)
        self.assertNotIn('MANAGEMENT_STATUS: resolved',text)
        self.assertTrue(self.h.agent._capstone_alignment_partial)
        final=self.h.call(assistant_message=result.response.choices[0].message)
        self.assertEqual(final.action,'break');self.assertIn('MANAGEMENT_STATUS: needs_review',final.final_response)

    def test_inventory_failure_never_admits_verified_lookup(self):
        self.prepare();self.respond(self.initial());self.observations();self.discovery(failed=True)
        phase=self.h.agent._capstone_gateway_phase
        self.assertEqual(phase['kind'],'service');self.assertTrue(phase['context']['lookup_incomplete'])
        self.assertTrue(phase['context']['service_identity_discovery']['incomplete'])
        result=self.respond(self.report())
        self.assertIn('MANAGEMENT_STATUS: needs_review',result.response.choices[0].message.content)
        self.assertTrue(self.h.agent._capstone_alignment_partial)

    def test_loaded_inactive_oneshot_does_not_escalate_inventory(self):
        self.prepare();self.respond(self.initial());self.observations(loaded=True);self.build()
        phase=self.h.agent._capstone_gateway_phase
        self.assertEqual(phase['kind'],'service');self.assertTrue(phase['context']['lookup_only'])
        self.assertNotIn('service_identity_discovery',phase['context'])

    def test_explicit_unit_query_does_not_substitute_component(self):
        self.prepare('B 서버 capstone-vector.service 현재 상태 보여줘')
        self.respond(self.initial());self.observations();self.build()
        phase=self.h.agent._capstone_gateway_phase
        self.assertEqual(phase['kind'],'service');self.assertTrue(phase['context']['lookup_only'])
        self.assertNotIn('service_identity_discovery',phase['context'])

if __name__=='__main__':unittest.main()
