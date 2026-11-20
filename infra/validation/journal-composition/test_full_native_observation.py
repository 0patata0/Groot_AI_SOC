"""Do not discard an in-flight recovery or accept a failed status as proof."""
import importlib.util
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('full_native_observation',
                                          Path(__file__).with_name('validate_full_native.py'))
native=importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


class RecoveryObservation(unittest.TestCase):
    def reply(self,code=1,**values):
        return {'returncode':code,'reply':{'schema':1,'status':'unavailable',
                'reason':'control_observation_changed','completion_verified':False,**values}}

    def test_changed_read_remains_a_failure_to_be_observed_again(self):
        reply=self.reply()
        self.assertTrue(native.retryable_status_observation(reply))
        self.assertEqual(reply['returncode'],1)
        self.assertFalse(reply['reply']['completion_verified'])

    def test_busy_host_is_pending(self):
        self.assertTrue(native.retryable_status_observation(
            self.reply(75,status='deferred',reason='host_operation_busy')))

    def test_busy_operation_is_pending(self):
        self.assertTrue(native.retryable_status_observation(
            self.reply(75,status='deferred',reason='operation_busy')))

    def test_other_runtime_failure_is_not_hidden(self):
        self.assertFalse(native.retryable_status_observation(self.reply(reason='operator_helper_changed')))

    def test_wrong_code_is_not_pending(self):
        self.assertFalse(native.retryable_status_observation(self.reply(0)))

    def test_success_claim_cannot_be_treated_as_a_changing_read(self):
        self.assertFalse(native.retryable_status_observation(self.reply(completion_verified=True)))

    def test_schema_and_response_type_must_match(self):
        self.assertFalse(native.retryable_status_observation(self.reply(schema=True)))
        self.assertFalse(native.retryable_status_observation({'returncode':1,'reply':None}))

    def test_deferred_code_requires_the_declared_deferred_reason(self):
        self.assertFalse(native.retryable_status_observation(self.reply(75)))
        self.assertFalse(native.retryable_status_observation(self.reply(75,status='deferred',reason='unavailable')))


class OperationOutcomeObservation(unittest.TestCase):
    def test_transient_proof_reads_can_repeat_but_mutations_cannot(self):
        reply={'returncode':75,'reply':{'schema':1,'status':'deferred','reason':'host_operation_busy','completion_verified':False}}
        for operation in ('status','completion_status','current'):
            self.assertTrue(native.proof_read_retry(operation,reply))
        for operation in ('backup','apply','resume','confirm','cleanup','completion_prepare','peers','unknown'):
            self.assertFalse(native.proof_read_retry(operation,reply))

    def snapshot(self,phase='quiesced',pending=None,facts=None):
        state={'schema':1,'host':'b','release_id':'1'*32,'plan_sha256':'2'*64,
               'phase':phase,'pending':pending,'facts':facts or {},'sequence':6}
        return self.seal({'state':state,'cache_sha256':'3'*64,'core_before':True,'backup_receipts':[]})

    def seal(self,value):
        value['state_sha256']=hashlib.sha256(json.dumps(value['state'],sort_keys=True,
            separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
        return value

    def record(self,scenario):
        before=self.snapshot();after=copy.deepcopy(before)
        attempt={'returncode':75,'reply':{'schema':1,'status':'deferred','reason':'host_operation_busy',
                                        'completion_verified':False}}
        result={'scope':'owned-root-backup-outcome','write_requests':1,'scenario':scenario,
                'before':before,'after':after,'attempt':attempt}
        if scenario=='lost_ack':
            after=self.snapshot('backed_up',facts={'source_backup':True,'cache_backup':True})
            after['backup_receipts']=[{'nonce':'4'*32,'sha256':'5'*64,'operation':'backup'}]
            result.update(after=after,ack_loss_simulated=True,
                          attempt={'returncode':0,'reply':{'operation':'backup','result':after['state']}})
        elif scenario=='interrupted_intent':
            pending={'name':'backup','nonce':'4'*32,'from_phase':'quiesced','to_phase':'backed_up'}
            result.update(after=self.snapshot(pending=pending),fault_nonce='4'*32,
                          attempt={'returncode':-9,'reply':None})
        return result

    def test_busy_does_not_become_success_or_grant_a_retry(self):
        value=self.record('host_busy');before=copy.deepcopy(value)
        self.assertEqual(native.operation_outcome_observation(value),
                         {'outcome':'not_started_observed','write_retry_authorized':False})
        self.assertEqual(value,before)
        self.assertEqual(value['attempt']['returncode'],75)

    def test_busy_response_does_not_excuse_a_changed_durable_state(self):
        value=self.record('host_busy');value['after']['state']['sequence']+=1;self.seal(value['after'])
        self.assertEqual(native.operation_outcome_observation(value)['outcome'],'unverified')

    def test_completed_backup_uses_receipt_and_both_flags_without_repetition(self):
        value=self.record('lost_ack')
        self.assertEqual(native.operation_outcome_observation(value),
                         {'outcome':'completion_recorded_do_not_repeat','write_retry_authorized':False})
        for key in ('source_backup','cache_backup'):
            wrong=copy.deepcopy(value);wrong['after']['state']['facts'].pop(key);self.seal(wrong['after'])
            self.assertEqual(native.operation_outcome_observation(wrong)['outcome'],'unverified')
        value['after']['backup_receipts']=[]
        self.assertEqual(native.operation_outcome_observation(value)['outcome'],'unverified')

    def test_killed_pending_intent_requires_recovery_with_its_original_nonce(self):
        value=self.record('interrupted_intent')
        self.assertEqual(native.operation_outcome_observation(value),
                         {'outcome':'pending_requires_recovery','write_retry_authorized':False})
        value['fault_nonce']='5'*32
        self.assertEqual(native.operation_outcome_observation(value)['outcome'],'unverified')

    def test_a_different_host_release_or_plan_cannot_complete_an_observation(self):
        for key,replacement in (('host','a'),('release_id','6'*32),('plan_sha256','7'*64)):
            value=self.record('lost_ack');value['after']['state'][key]=replacement;self.seal(value['after'])
            with self.subTest(key=key):
                self.assertEqual(native.operation_outcome_observation(value)['outcome'],'unverified')

    def test_changed_or_unbound_journal_and_cache_are_not_completed(self):
        for mutate in (lambda v:v['after']['state'].update(sequence=99),
                       lambda v:v['after'].update(cache_sha256='8'*64),
                       lambda v:v['after'].update(core_before=False)):
            value=self.record('lost_ack');mutate(value)
            self.assertEqual(native.operation_outcome_observation(value)['outcome'],'unverified')

    def test_unverified_or_multiple_requests_never_authorize_a_retry(self):
        for count in (0,2,True,None):
            value=self.record('lost_ack');value['write_requests']=count
            with self.subTest(count=count):
                self.assertEqual(native.operation_outcome_observation(value),
                                 {'outcome':'unverified','write_retry_authorized':False})

    def test_unrelated_reply_and_unstated_ack_loss_do_not_prove_completion(self):
        value=self.record('lost_ack');value['attempt']['reply']['operation']='apply'
        self.assertEqual(native.operation_outcome_observation(value)['outcome'],'unverified')
        value=self.record('lost_ack');value['ack_loss_simulated']=False
        self.assertEqual(native.operation_outcome_observation(value)['outcome'],'unverified')
        value=self.record('host_busy');value['before']['state']['pending']={'name':'backup'}
        self.seal(value['before'])
        self.assertEqual(native.operation_outcome_observation(value)['outcome'],'unverified')


class OwnedCaseIdentity(unittest.TestCase):
    def fixture(self,root,case):
        code=root/'code';code.mkdir();raw=b'owned validator source\n'
        (code/'validate_full_native.py').write_bytes(raw)
        return {'schema':1,'case':case,'validator_sha256':hashlib.sha256(raw).hexdigest()}

    def test_registered_outcome_case_survives_ownership_validation(self):
        with tempfile.TemporaryDirectory()as d:
            root=Path(d);owner=self.fixture(root,'operation-outcomes')
            with patch.object(native.base,'own_root',return_value=(root,owner)):
                self.assertEqual(native.own(root),(root,owner))

    def test_unknown_case_cannot_adopt_an_owned_workspace(self):
        with tempfile.TemporaryDirectory()as d:
            root=Path(d);owner=self.fixture(root,'unknown')
            with patch.object(native.base,'own_root',return_value=(root,owner)):
                with self.assertRaisesRegex(RuntimeError,'owned_full_test_identity'):native.own(root)

    def test_registered_case_still_rejects_a_changed_validator(self):
        with tempfile.TemporaryDirectory()as d:
            root=Path(d);owner=self.fixture(root,'operation-outcomes');owner['validator_sha256']='0'*64
            with patch.object(native.base,'own_root',return_value=(root,owner)):
                with self.assertRaisesRegex(RuntimeError,'owned_validator_changed'):native.own(root)


if __name__=='__main__':
    unittest.main()
