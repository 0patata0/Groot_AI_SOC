"""Mappings must not outlive materialization, including errors and context exit."""
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from bounded_loading import ReopeningFile, checkpoint_loading


class MappingTests(unittest.TestCase):
    def test_metadata_retains_no_mapping_and_reads_reopen(self):
        state={'active':0,'opens':0}
        class Slice:
            def get_shape(self):return [2]
            def get_dtype(self):return 'BF16'
            def __getitem__(self,item):
                self_test.assertEqual(state['active'],1)
                if item == 'bad':raise ValueError('read failure')
                return [1,2]
        class File:
            def __enter__(self):state['active']+=1;state['opens']+=1;return self
            def __exit__(self,*args):state['active']-=1
            def metadata(self):return {'format':'pt'}
            def keys(self):return ['weight']
            def get_slice(self,key):return Slice()
        self_test=self
        file=ReopeningFile(lambda *a,**kw:File(),'fixture','pt')
        self.assertEqual(state,{'active':0,'opens':1})
        self.assertEqual(file.get_slice('weight').get_shape(),[2])
        self.assertEqual(file.get_tensor('weight'),[1,2])
        self.assertEqual(state,{'active':0,'opens':2})
        with self.assertRaises(ValueError):file.get_slice('weight')['bad']
        self.assertEqual(state,{'active':0,'opens':3})

    def test_context_restores_loader_and_environment_after_failure(self):
        original=object();modeling=SimpleNamespace(safe_open=original)
        package=SimpleNamespace(__version__='5.4.0',modeling_utils=modeling)
        with patch.dict(sys.modules,{'transformers':package,'transformers.modeling_utils':modeling}), \
             patch.dict(os.environ,{'HF_DEACTIVATE_ASYNC_LOAD':'0'}):
            with self.assertRaisesRegex(RuntimeError,'fixture'):
                with checkpoint_loading({'model_kind':'qwen3_5_moe'}):
                    self.assertIsNot(modeling.safe_open,original)
                    self.assertEqual(os.environ['HF_DEACTIVATE_ASYNC_LOAD'],'1')
                    raise RuntimeError('fixture')
            self.assertIs(modeling.safe_open,original)
            self.assertEqual(os.environ['HF_DEACTIVATE_ASYNC_LOAD'],'0')


if __name__=='__main__':unittest.main()
