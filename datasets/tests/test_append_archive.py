import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'finetuning'))
from verified_archive import build,digest,MANIFEST
spec=importlib.util.spec_from_file_location('append_archive',ROOT/'datasets/append_cleaned_archive.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class AppendTests(unittest.TestCase):
    def setup_store(self,tmp):
        root=Path(tmp).resolve();store=root/'archives';store.mkdir()
        source=root/'old.json';source.write_text('{"old":true}');source.chmod(0o640)
        receipts={kind:build(store/(kind+'.tar.gz'),{'finetuning/data-old/old.json':source},kind) for kind in ('original','cleaned')}
        catalog={'schema':'groot-two-archive-catalog-v1','archives':receipts,'plan_sha256':'a'*64,'full_restore_verified':True}
        (store/'catalog.json').write_text(json.dumps(catalog))
        new=root/'new.json';new.write_text('{"new":true}')
        plan={'schema':'groot-cleaned-append-v1','parent_catalog_sha256':digest(store/'catalog.json'),
            'members':[{'member':'finetuning/data-new/new.json','source':str(new),'bytes':new.stat().st_size,'sha256':digest(new)}]}
        path=root/'plan.json';path.write_text(json.dumps(plan))
        return root,store,path,catalog

    def test_append_preserves_old_bytes_metadata_and_original_archive(self):
        with tempfile.TemporaryDirectory()as tmp:
            root,store,plan,old=self.setup_store(tmp)
            result=module.append(plan,store,root/'stage')
            self.assertEqual(result['added_files'],1)
            self.assertEqual(digest(store/'original.tar.gz'),old['archives']['original']['sha256'])
            a=json.loads((root/'stage/previous-cleaned'/MANIFEST).read_text())['members'][0]
            members=json.loads((root/'stage/verified-new-cleaned'/MANIFEST).read_text())['members']
            self.assertEqual(next(r for r in members if r['path']==a['path']),a)
            self.assertEqual(len(list(store.glob('*.tar.gz'))),2)

    def test_catalog_swap_failure_restores_the_verified_previous_pair(self):
        with tempfile.TemporaryDirectory()as tmp:
            root,store,plan,old=self.setup_store(tmp);old_catalog=(store/'catalog.json').read_bytes()
            replace=module.os.replace;failed=[False]
            def fail_once(source,target):
                if Path(target)==store/'catalog.json' and not failed[0]:
                    failed[0]=True;raise OSError('simulated catalog swap failure')
                return replace(source,target)
            with patch.object(module.os,'replace',side_effect=fail_once),self.assertRaises(OSError):
                module.append(plan,store,root/'stage')
            self.assertEqual(digest(store/'cleaned.tar.gz'),old['archives']['cleaned']['sha256'])
            self.assertEqual((store/'catalog.json').read_bytes(),old_catalog)

    def test_existing_version_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory()as tmp:
            root,store,plan,old=self.setup_store(tmp);value=json.loads(plan.read_text())
            value['members'][0]['member']='finetuning/data-old/old.json';plan.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError,'overwritten'):module.append(plan,store,root/'stage')
            self.assertEqual(digest(store/'cleaned.tar.gz'),old['archives']['cleaned']['sha256'])


if __name__=='__main__':unittest.main()
