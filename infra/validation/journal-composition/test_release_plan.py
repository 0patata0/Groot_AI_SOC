"""Exact helper/source/control binding and protected-state refusal cases."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

HERE=Path(__file__).parent
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=load('release_plan_tested','release_plan.py')
fixture=load('release_plan_fixture','test_release_lifecycle.py')


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixture.LifecycleTests(methodName='runTest');self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.ctl=self.fixture.b;self.value=copy.deepcopy(self.ctl.plan);self.plan=m.Plan(self.value)

    def test_full_bundle_binds_all_payloads_helpers_and_generated_controls(self):
        bundle=self.plan.bundle();self.assertEqual(sum(map(len,bundle['payloads'].values())),50)
        self.assertEqual(len(bundle['helpers']),19);self.assertEqual(sum(map(len,bundle['controls'].values())),39)
        self.assertEqual(bundle['plan_sha256'],self.plan.sha256);proof=self.plan.verify(self.ctl.files)
        self.assertTrue(proof['isolated_filesystem']);self.assertEqual(proof['helpers_verified'],19)

    def test_unknown_or_missing_helper_is_rejected(self):
        for name in ('../outside.py','unregistered.py','/etc/shadow'):
            changed=copy.deepcopy(self.value);changed['helpers'][name]='a'*64
            with self.assertRaisesRegex(ValueError,'plan_helper_set'):m.Plan(changed)
        changed=copy.deepcopy(self.value);changed['helpers'].pop('release_lifecycle.py')
        with self.assertRaisesRegex(ValueError,'plan_helper_set'):m.Plan(changed)

    def test_row_or_cohort_binding_cannot_be_substituted(self):
        changed=copy.deepcopy(self.value);changed['hosts']['a']['rows'][0]['after_sha256']='b'*64
        with self.assertRaisesRegex(ValueError,'plan_source_cohort'):m.Plan(changed)

    def test_boolean_schema_account_and_unsafe_barrier_modes_are_refused(self):
        changed=copy.deepcopy(self.value);changed['schema']=True
        with self.assertRaisesRegex(ValueError,'plan_shape'):m.Plan(changed)
        changed=copy.deepcopy(self.value);changed['hosts']['b']['reader_uid']=True
        with self.assertRaisesRegex(ValueError,'plan_machine_account'):m.Plan(changed)
        changed=copy.deepcopy(self.value)
        next(r for r in changed['hosts']['b']['rows']if r['target']==m.source.READER)['mode']=0o777
        with self.assertRaisesRegex(ValueError,'plan_barrier_metadata'):m.Plan(changed)

    def test_other_host_cannot_adopt_container_or_mcp_identity(self):
        changed=copy.deepcopy(self.value);changed['hosts']['a']['container']=copy.deepcopy(changed['hosts']['b']['container'])
        with self.assertRaisesRegex(ValueError,'plan_container_host'):m.Plan(changed)

    def test_protected_scope_and_required_presence_are_fixed(self):
        changed=copy.deepcopy(self.value);changed['hosts']['b']['protected']['/etc/shadow']=None
        with self.assertRaisesRegex(ValueError,'plan_protected_set'):m.Plan(changed)
        changed=copy.deepcopy(self.value);changed['hosts']['b']['protected']['/opt/hermes-data/.env']=None
        with self.assertRaisesRegex(ValueError,'plan_required_protected_file'):m.Plan(changed)

    def test_model_configuration_drift_blocks_forward_but_not_restore_inspection(self):
        path=self.ctl.files.root/'opt/hermes-data/config.yaml';path.write_bytes(b'external fixture configuration')
        with self.assertRaisesRegex(ValueError,'protected_state_changed'):self.plan.verify(self.ctl.files)
        self.plan.verify(self.ctl.files,protected=False);self.assertEqual(path.read_bytes(),b'external fixture configuration')

    def test_operator_code_change_or_permissions_are_refused(self):
        path=self.ctl.files.storage/'release_lifecycle.py';before=path.read_bytes();path.write_bytes(b'unapproved helper')
        with self.assertRaisesRegex(ValueError,'operator_helper_changed'):self.plan.verify(self.ctl.files)
        path.write_bytes(before);path.chmod(0o660)
        with self.assertRaisesRegex(ValueError,'operator_helper_changed'):self.plan.verify(self.ctl.files)

    def test_machine_reassignment_is_refused(self):
        (self.ctl.files.root/'etc/machine-id').write_bytes(b'e'*32+b'\n')
        with self.assertRaisesRegex(ValueError,'operator_machine_changed'):self.plan.verify(self.ctl.files)

    def test_mutated_bundle_is_not_authorized_even_if_its_hash_is_relabelled(self):
        bundle=self.ctl.store.read('bundle.json');bundle['controls']['b'].pop(next(iter(bundle['controls']['b'])))
        path=self.ctl.files.storage/'bundle.json';path.write_bytes(m.c.canonical(bundle))
        approval=self.ctl.store.read('approval.json');approval['bundle_sha256']=m.digest(bundle)
        (self.ctl.files.storage/'approval.json').write_bytes(m.c.canonical(approval))
        with self.assertRaisesRegex(ValueError,'approval_bundle_changed'):self.ctl.execute('arm')
        self.assertTrue(self.ctl.core_is('before_sha256'))

    def test_b_prepared_only_provenance_is_preserved_but_missing_both_is_refused(self):
        self.assertIsNone(self.value['hosts']['b']['protected'][m.ACTIVE_PROTECTED])
        self.assertIsNotNone(self.value['hosts']['b']['protected'][m.OPTIONAL_PROTECTED])
        self.plan.verify(self.ctl.files)
        changed=copy.deepcopy(self.value);changed['hosts']['b']['protected'][m.OPTIONAL_PROTECTED]=None
        with self.assertRaisesRegex(ValueError,'installation_provenance_missing'):m.Plan(changed)

    def test_a_and_c_cannot_treat_active_receipt_as_optional(self):
        for host in ('a','c'):
            changed=copy.deepcopy(self.value);changed['hosts'][host]['protected'][m.ACTIVE_PROTECTED]=None
            with self.assertRaisesRegex(ValueError,'plan_required_protected_file'):m.Plan(changed)


if __name__=='__main__':unittest.main()
