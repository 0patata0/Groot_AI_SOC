import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import prepare_operator_release as release
from prepare_operator_sources import dump,sha
from prepare_operator_evaluation import select


def row(identifier='r1',family='one'):
    return {'id':identifier,'source':'wazuh','provenance':{'split_group':family},
        'messages':[{'role':'user','content':'event '+identifier},{'role':'assistant','content':'expected'}]}


class AdmissionTests(unittest.TestCase):
    def run_admission(self, change):
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp);data=root/'mixture';data.mkdir()
            dump(data/'train.candidates.jsonl',[row()]);dump(data/'fallback.candidates.jsonl',[])
            for name in ('validation','test'):dump(data/(name+'.jsonl'),[])
            dump(data/'token-input.jsonl',[{'split':'train','row':row()}])
            composition={'token_input_sha256':sha((data/'token-input.jsonl').read_bytes()),'validation_rows':0,'test_rows':0,
                         'files':{p.name:sha(p.read_bytes())for p in data.iterdir()}}
            (data/'composition.json').write_text(json.dumps(composition))
            prior=root/'data-joint-sft-20261101-r3';prior.mkdir();(prior/'token-review.json').write_text('{"artifacts":{"tokenizer":"pinned"}}')
            result={'input_sha256':composition['token_input_sha256'],'max_length':4096,'truncation':False,'weights_loaded':False,
                'gpu_training_started':False,'artifacts':{'tokenizer':'pinned'},'records':[{'split':'train','id':'r1','reason':None,'tokens':42}]}
            change(result);receipt=data/'token-review.json';receipt.write_text(json.dumps(result))
            with patch.object(release,'ROOT',root):return release.admit(data,receipt)

    def test_bound_receipt_preserves_full_input(self):
        report=self.run_admission(lambda x:None)
        self.assertEqual(report['train_rows'],1);self.assertFalse(report['ready_for_gpu_training'])

    def test_receipt_mismatch_missing_duplicate_length_and_tokenizer_are_rejected(self):
        changes=[lambda x:x.update(input_sha256='changed'),lambda x:x.update(records=[]),
            lambda x:x['records'].append(copy.deepcopy(x['records'][0])),lambda x:x['records'][0].update(tokens=4097),
            lambda x:x['artifacts'].update(tokenizer='different')]
        for change in changes:
            with self.subTest(change=change),self.assertRaises(ValueError):self.run_admission(change)

    def test_source_family_isolation_is_stricter_than_different_prompts(self):
        with self.assertRaisesRegex(ValueError,'overlaps'):select([row('different','same')],[row('original','same')])
        selected,_=select([row('different','reserved')],[row('original','train')])
        self.assertTrue(selected[0]['provenance']['reserved_for_quality_evaluation'])

    def test_privacy_holds_structured_credentials(self):
        item=row();item['messages'][0]['content']=json.dumps({'secretAccessKey':'fixture'})
        selected,held=select([item],[])
        self.assertEqual(selected,[]);self.assertEqual(len(held),1)


if __name__=='__main__':unittest.main()
