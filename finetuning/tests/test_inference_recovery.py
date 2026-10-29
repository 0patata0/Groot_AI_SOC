import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('inference_recovery',Path(__file__).parents[1]/'training_window.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class RecoveryProbe(unittest.TestCase):
    def test_preserves_shared_runner_context_and_requires_real_generation(self):
        calls=[]
        def api(path,payload=None,timeout=0):
            calls.append((path,payload,timeout))
            if path=='ps':return {'models':[{'name':'base','digest':'sha','context_length':262144}]}
            return {'model':'base','done':True,'eval_count':1}
        result=m.verify_generation(api,'base','sha')
        self.assertTrue(result['generation_verified'])
        payload=calls[1][1]
        self.assertEqual(payload['options']['num_ctx'],262144)
        self.assertEqual(payload['options']['num_predict'],1)
        self.assertIs(payload['stream'],False)

    def test_residency_is_not_enough_and_wrong_digest_refused(self):
        for response in ({'done':True,'model':'base'},{'done':True,'model':'other','eval_count':1}):
            with self.assertRaises(RuntimeError):
                m.verify_generation(lambda path,*a,**kw: {'models':[]} if path=='ps' else response,'base','sha')
        with self.assertRaises(ValueError):
            m.verify_generation(lambda *a,**kw:{'models':[{'name':'base','digest':'wrong'}]},'base','sha')

    def test_queue_timeout_is_recorded_and_retry_can_succeed(self):
        attempts=[];count=0
        def api(path,payload=None,timeout=0):
            nonlocal count
            if path=='ps':return {'models':[]}
            count+=1
            if count==1:raise TimeoutError()
            return {'done':True,'model':'base','eval_count':1}
        result=m.verify_generation(api,'base','sha',record=attempts.append)
        self.assertEqual(len(attempts),2)
        self.assertEqual(result['attempts'][0]['error_type'],'TimeoutError')

    def test_retries_and_time_budget_are_bounded(self):
        t=[0.];calls=[]
        def api(path,payload=None,timeout=0):
            if path=='ps':return {'models':[]}
            calls.append(timeout);t[0]+=timeout;raise TimeoutError()
        with self.assertRaises(TimeoutError):
            m.verify_generation(api,'base','sha',clock=lambda:t[0],budget_seconds=75)
        self.assertEqual(calls,[60,15])
        with self.assertRaises(ValueError):m.verify_generation(api,'base','sha',budget_seconds=181)


if __name__=='__main__':unittest.main()
