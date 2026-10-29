import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).parents[1]))
import train


class DeterministicProfile(unittest.TestCase):
    def fake_torch(self,initialized=False):
        state={'enabled':False}
        return SimpleNamespace(cuda=SimpleNamespace(is_initialized=lambda:initialized),
            use_deterministic_algorithms=lambda enabled:state.update(enabled=enabled),
            are_deterministic_algorithms_enabled=lambda:state['enabled'],
            backends=SimpleNamespace(cudnn=SimpleNamespace(benchmark=True,deterministic=False,allow_tf32=True),
                                     cuda=SimpleNamespace(matmul=SimpleNamespace(allow_tf32=True))))

    def test_explicit_profile_is_configured_before_cuda_and_reported(self):
        torch=self.fake_torch()
        with patch.dict(os.environ,{},clear=True):
            record=train.configure_determinism({'deterministic_training':True},torch)
            self.assertEqual(os.environ['CUBLAS_WORKSPACE_CONFIG'],':4096:8')
        self.assertTrue(record['algorithms_enabled'])
        self.assertTrue(record['cudnn_deterministic'])
        self.assertFalse(record['matmul_tf32'])
        self.assertFalse(record['cudnn_benchmark'])

    def test_default_keeps_existing_profile_and_non_boolean_refused(self):
        torch=self.fake_torch()
        with patch.dict(os.environ,{},clear=True):
            self.assertFalse(train.configure_determinism({},torch)['requested'])
            self.assertNotIn('CUBLAS_WORKSPACE_CONFIG',os.environ)
        for invalid in ('true',1,None):
            with self.assertRaises(ValueError):train.deterministic_training_enabled({'deterministic_training':invalid})

    def test_late_workspace_change_is_refused(self):
        with patch.dict(os.environ,{},clear=True):
            with self.assertRaises(RuntimeError):
                train.configure_determinism({'deterministic_training':True},self.fake_torch(True))


if __name__=='__main__':unittest.main()
