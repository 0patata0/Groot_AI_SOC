import sys
from pathlib import Path
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from register_soc import parameters,verify_runtime,candidate_name
from soc_evaluate import select_cases


class CandidateTests(unittest.TestCase):
    def test_blob_upload_uses_selected_local_daemon_for_head_and_stream(self):
        import register_soc as r
        import tempfile
        from unittest.mock import patch, MagicMock
        from urllib.error import HTTPError
        previous=r.API_BASE_URL
        try:
            r.set_api_base_url('http://127.0.0.1:11435')
            with tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'test.gguf';path.write_bytes(b'local fixture')
                response=MagicMock();response.status=201;response.read.return_value=b''
                connection=MagicMock();connection.getresponse.return_value=response
                with patch.object(r.request,'urlopen',side_effect=HTTPError('fixture',404,'missing',{},None)) as head, patch.object(r.http.client,'HTTPConnection',return_value=connection) as client:
                    r.upload(path,'a'*64)
                self.assertEqual(head.call_args.args[0].full_url,'http://127.0.0.1:11435/api/blobs/sha256:'+'a'*64)
                client.assert_called_once_with('127.0.0.1',11435,timeout=1200)
                connection.send.assert_called_once_with(b'local fixture')
                connection.close.assert_called_once()
        finally:r.set_api_base_url(previous)

    def test_operator_endpoint_is_fixed_loopback_and_legacy_default_is_preserved(self):
        import register_soc as r
        previous=r.API_BASE_URL
        try:
            r.set_api_base_url('http://127.0.0.1:11435')
            self.assertEqual(r.API_BASE_URL,'http://127.0.0.1:11435')
            for url in ('http://example.org:11434','http://127.0.0.1:8090','http://user:secret@127.0.0.1:11435','http://127.0.0.1:11435/v1'):
                with self.assertRaises(ValueError):r.set_api_base_url(url)
        finally:r.set_api_base_url(previous)

    def test_checkpoint_models_have_distinct_names_and_cannot_replace_original(self):
        names={candidate_name(v) for v in ('base','main','v2-step24','v2-step48')}
        self.assertEqual(len(names),4);self.assertNotIn('qwen3.6:35b',names)
        self.assertTrue(candidate_name('v2-step24').endswith('20261028'))
        with self.assertRaises(ValueError):candidate_name('../arbitrary')
    def test_runtime_options_preserve_numbers_and_repeated_stops(self):
        value=parameters('temperature 0.6\ndraft_num_predict 2\nstop "<|im_end|>"\nstop "a\\nb"\n')
        self.assertEqual(value,{'temperature':0.6,'draft_num_predict':2,'stop':['<|im_end|>','a\nb']})
        with self.assertRaises(ValueError):parameters('temperature 0.6\ntemperature 0\n')

    def test_full_evaluation_includes_each_test_variant_without_train_or_validation(self):
        cases=[{'id':i,'split':split,'scenario_group':'one'} for i,split in enumerate(['train','test','validation','test'])]
        self.assertEqual([c['id'] for c in select_cases(cases,8)],[1])
        self.assertEqual([c['id'] for c in select_cases(cases,8,all_cases=True)],[1,3])

    def test_native_hf_template_and_exact_weight_blobs_are_required(self):
        original={'template':'{{ .Prompt }}','parameters':'temperature 1','details':{'runner':'llamacpp'},'capabilities':['tools','vision']}
        files={'text':'sha256:'+'a'*64,'projector':'sha256:'+'b'*64}
        show={**original,'template':'pinned HF Jinja','details':{'runner':'llamacpp','quantization_level':'Q4_K_M'},'projector_info':{'present':True},
              'modelfile':'FROM /models/blobs/sha256-'+'a'*64+'\nFROM /models/blobs/sha256-'+'b'*64+'\n'}
        result=verify_runtime(original,show,'pinned HF Jinja',files)
        self.assertTrue(result['chat_template_matches_hf']);self.assertFalse(result['chat_template_matches_original'])
        for change in [{'template':'different HF'},{'parameters':'temperature 0'},{'capabilities':['tools']},{'modelfile':'FROM unrelated'}]:
            with self.assertRaises(ValueError):verify_runtime(original,{**show,**change},'pinned HF Jinja',files)


if __name__=='__main__':unittest.main()
