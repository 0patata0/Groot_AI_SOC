import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ENTRY=Path(__file__).resolve().parents[1]/'driver-diagnostics/check.py'
SPEC=importlib.util.spec_from_file_location('driver_diagnostics_check',ENTRY)
DIAG=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DIAG)


class DriverDiagnosticsTests(unittest.TestCase):
    def fixture(self,root):
        tool=root/'tool';source=root/'source';tool.mkdir();source.mkdir()
        data=b'pinned source\n';patch_bytes=b'reviewed diagnostic patch\n'
        (tool/'nvidia-595.78-allocation.patch').write_bytes(patch_bytes)
        files=[]
        for name in sorted(DIAG.FILES):
            target=source/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
            files.append({'path':name,'before_sha256':hashlib.sha256(data).hexdigest(),
                          'after_sha256':hashlib.sha256(data+b'changed\n').hexdigest()})
        manifest={'schema':1,'driver':'595.78','commit':'76b260e5967dfe9815b9054a4a4642f10672a763',
                  'files':files,'patch_sha256':hashlib.sha256(patch_bytes).hexdigest()}
        (tool/'manifest.json').write_text(json.dumps(manifest))
        return tool,source,manifest

    def test_original_and_patched_tree_are_distinct_and_check_does_not_write(self):
        with tempfile.TemporaryDirectory() as d:
            tool,source,manifest=self.fixture(Path(d))
            with patch.object(DIAG,'ROOT',tool):
                before={p:p.read_bytes() for p in source.rglob('*') if p.is_file()}
                self.assertEqual(DIAG.check(source)['tree'],'original')
                self.assertEqual(before,{p:p.read_bytes() for p in before})
                with self.assertRaisesRegex(ValueError,'checksum'):DIAG.check(source,True)
                for p,b in before.items():p.write_bytes(b+b'changed\n')
                self.assertEqual(DIAG.check(source,True)['tree'],'patched')
                with self.assertRaisesRegex(ValueError,'checksum'):DIAG.check(source)

    def test_source_or_patch_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            tool,source,manifest=self.fixture(Path(d))
            with patch.object(DIAG,'ROOT',tool):
                target=source/manifest['files'][0]['path'];data=target.read_bytes();target.write_bytes(data+b'x')
                with self.assertRaisesRegex(ValueError,'checksum'):DIAG.check(source)
                target.write_bytes(data)
                (tool/'nvidia-595.78-allocation.patch').write_bytes(b'changed patch')
                with self.assertRaisesRegex(ValueError,'patch checksum'):DIAG.check(source)

    def test_file_and_parent_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);tool,source,manifest=self.fixture(root)
            with patch.object(DIAG,'ROOT',tool):
                target=source/manifest['files'][0]['path'];data=target.read_bytes()
                outside=root/'external';outside.write_bytes(data);target.unlink();target.symlink_to(outside)
                with self.assertRaisesRegex(ValueError,'symlink'):DIAG.check(source)
                target.unlink();target.write_bytes(data)
                parent=target.parent;renamed=root/'moved-parent';parent.rename(renamed);parent.symlink_to(renamed,target_is_directory=True)
                with self.assertRaisesRegex(ValueError,'symlink'):DIAG.check(source)

    def test_wrong_release_and_unexpected_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            tool,source,manifest=self.fixture(Path(d))
            with patch.object(DIAG,'ROOT',tool):
                for field,value in [('driver','other'),('commit','other')]:
                    wrong={**manifest,field:value};(tool/'manifest.json').write_text(json.dumps(wrong))
                    with self.assertRaisesRegex(ValueError,'manifest'):DIAG.check(source)
                manifest['files'][0]['path']='../../external'
                (tool/'manifest.json').write_text(json.dumps(manifest))
                with self.assertRaisesRegex(ValueError,'manifest'):DIAG.check(source)


if __name__=='__main__':unittest.main()
