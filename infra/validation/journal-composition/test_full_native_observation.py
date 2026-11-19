"""Do not discard an in-flight recovery or accept a failed status as proof."""
import importlib.util
from pathlib import Path
import unittest

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


if __name__=='__main__':
    unittest.main()
