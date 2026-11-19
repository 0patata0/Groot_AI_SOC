"""Native completion must preserve unverified component identity after reads."""
from datetime import datetime, timezone, timedelta
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
f=load('native_identity_fixture',ROOT/'infra/hermes/test_service_identity_discovery.py')
w=load('native_identity_completion',ROOT/'infra/hermes/soc_management_run.py')

class NativeIdentityCompletion(unittest.TestCase):
    def setUp(self):
        self.at=datetime.now(timezone(timedelta(hours=9))).isoformat()
        self.previous=f.AT;f.AT=self.at
        self.addCleanup(setattr,f,'AT',self.previous)
        self.chat={'request':'B 서버 Vector 오류랑 지금 상태 확인해줘',
                   'background':'','requested_at_kst':self.at}
    def state(self,rows,chat=True):
        with patch.object(w,'diagnostic_contract',return_value=f.c), \
             patch.object(w,'chat_read_context',return_value=self.chat if chat else None):
            return w.chat_diagnostic_state(f.catalog(),rows)
    def all_reads(self):
        rows=[f.missing()]
        identity=f.c.service_identity_state(f.catalog(),self.chat['request'],rows)
        rows.extend(f.inventory(r['arguments'],at=self.at)for r in identity['pending'])
        return rows
    def test_completed_inventory_does_not_resolve_component(self):
        state=self.state(self.all_reads())
        self.assertEqual(state['pending'],[])
        self.assertIn('service_identity:b:vector:component_unverified',state['incomplete'])
    def test_pending_inventory_and_identity_are_distinct_requirements(self):
        state=self.state([f.missing()])
        self.assertEqual(len(state['pending']),2)
        self.assertIn('service_identity:b:vector:component_unverified',state['incomplete'])
    def test_loaded_inactive_oneshot_keeps_normal_scope(self):
        row=f.missing();row['data']['properties'].update(LoadState='loaded',Type='oneshot')
        state=self.state([row]);self.assertEqual(state['pending'],[])
        self.assertEqual(state['incomplete'],[])
    def test_explicit_unit_lookup_is_not_a_logical_identity_request(self):
        self.chat['request']='B 서버 capstone-vector.service 상태 확인해줘'
        state=self.state([f.missing()])
        self.assertEqual(state['pending'],[{'tool':f.DIAG,
            'arguments':{'target':'b:collection'}}])
        self.assertNotIn('service_identity:b:vector:component_unverified',state['incomplete'])
    def test_other_explicit_unit_does_not_exempt_vector(self):
        self.chat['request']='B 서버 Vector와 docker.service 상태 확인해줘'
        self.assertIn('service_identity:b:vector:component_unverified',
                      self.state([f.missing()])['incomplete'])
    def test_non_chat_path_is_unchanged(self):
        state=self.state([f.missing()],chat=False)
        self.assertEqual(state['pending'],[]);self.assertEqual(state['incomplete'],[])
    def test_existing_final_fallback_cannot_claim_resolved(self):
        state=self.state(self.all_reads());self.assertTrue(state['incomplete'])
        text=w.factual_review_report([])
        self.assertIn('MANAGEMENT_STATUS: needs_review',text)
        self.assertNotIn('MANAGEMENT_STATUS: resolved',text)

if __name__=='__main__':unittest.main()
