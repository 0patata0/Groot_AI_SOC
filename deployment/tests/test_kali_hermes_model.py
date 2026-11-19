"""The context alias must preserve the existing model and its actual weight blob."""
import copy
import json
import unittest
from unittest.mock import patch

from deployment.kali_hermes_model import ensure_alias

SOURCE='lab-model:latest'
ALIAS='lab-model:hermes-64k'


class Reply:
    status=200
    def __init__(self,value):
        self.value=value
    def __enter__(self):
        return self
    def __exit__(self,*args):
        return False
    def read(self,limit):
        return json.dumps(self.value).encode()


class AliasAdmission(unittest.TestCase):
    def fixture(self):
        original={'parameters':'num_ctx 32768\ntemperature 1','modelfile':'FROM /blobs/sha256-'+'a'*64,
                  'details':{'parent_model':'source.gguf','quantization_level':'Q8_0'},
                  'template':'fixed template','system':'fixed system',
                  'model_info':{'general.parameter_count':39100000000},'capabilities':['completion','tools']}
        alias=copy.deepcopy(original)
        alias['parameters']='temperature 1\nnum_ctx 65536'
        alias['details']['parent_model']=SOURCE
        requests=[]
        def open_request(request,timeout):
            requests.append(request.full_url)
            if request.full_url.endswith('/api/tags'):
                return Reply({'models':[{'name':SOURCE,'digest':'b'*64},{'name':ALIAS,'digest':'c'*64}]})
            if request.full_url.endswith('/api/show'):
                return Reply(original if json.loads(request.data)['model']==SOURCE else alias)
            self.fail('existing alias must never be overwritten')
        return original,alias,requests,open_request

    def invoke(self,opener,address='192.168.16.231',digest='b'*64):
        addresses=json.dumps([{'addr_info':[{'local':address}]}])
        with patch('deployment.kali_hermes_model.subprocess.check_output',return_value=addresses),\
             patch('deployment.kali_hermes_model.urllib.request.build_opener')as client:
            client.return_value.open=opener
            return ensure_alias('http://example.invalid:11434/v1',SOURCE,digest,ALIAS,65536)

    def test_parent_provenance_change_allowed_when_weights_and_other_metadata_match(self):
        original,alias,requests,opener=self.fixture()
        result=self.invoke(opener)
        self.assertFalse(result['created'])
        self.assertEqual(result['same_weight_blob_sha256'],'a'*64)
        self.assertTrue(result['existing_model_digests_unchanged'])
        self.assertFalse(any(path.endswith('/api/create')for path in requests))

    def test_existing_alias_with_different_weight_is_rejected_without_overwrite(self):
        original,alias,requests,opener=self.fixture()
        alias['modelfile']='FROM /blobs/sha256-'+'d'*64
        with self.assertRaisesRegex(ValueError,'alias_weights_mismatch'):
            self.invoke(opener)

    def test_source_digest_change_rejected_before_model_creation(self):
        original,alias,requests,opener=self.fixture()
        with self.assertRaisesRegex(ValueError,'source_model_digest_mismatch'):
            self.invoke(opener,digest='e'*64)
        self.assertEqual(len(requests),1)

    def test_other_host_rejected_before_any_api_request(self):
        original,alias,requests,opener=self.fixture()
        with self.assertRaisesRegex(ValueError,'administrator231_required'):
            self.invoke(opener,address='192.168.16.232')
        self.assertEqual(requests,[])


if __name__=='__main__':
    unittest.main()
