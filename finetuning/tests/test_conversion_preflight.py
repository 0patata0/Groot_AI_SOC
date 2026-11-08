import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import convert_soc as c


class ProjectorPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.folder=self.root/'exports/qwen36-soc-base-gguf';self.folder.mkdir(parents=True)
        self.projector=self.folder/'mmproj-qwen36-soc-f16.gguf';self.projector.write_bytes(b'GGUF fixture')
        self.record=self.folder/'conversion-status.json'
        self.manifest={'status':'completed','variant':'base','llama_cpp_revision':c.REVISION,
            'artifacts':[{'path':self.projector.name,'bytes':self.projector.stat().st_size,
                          'sha256':hashlib.sha256(self.projector.read_bytes()).hexdigest()}]}
        self.save()

    def save(self):self.record.write_text(json.dumps(self.manifest))

    def test_verified_projector_is_reusable_without_base_text_weights(self):
        self.assertEqual(c.verified_base_projector(self.root),self.projector)
        self.assertEqual(len(list(self.folder.iterdir())),2)

    def test_missing_manifest_fails_before_text_conversion_or_output_creation(self):
        self.record.unlink()
        tools=self.root/'tools';(tools/'llama.cpp/build-cpu/bin').mkdir(parents=True)
        quantizer=tools/'llama.cpp/build-cpu/bin/llama-quantize';quantizer.write_bytes(b'cpu fixture')
        (tools/'conversion-manifest.json').write_text(json.dumps({'artifacts':[
            {'path':'llama-quantize','sha256':c.digest(quantizer)}]}))
        model=self.root/'exports/qwen36-soc-main-hf';model.mkdir()
        (model/'merge-status.json').write_text(json.dumps({'status':'completed',
            'base_revision':'995ad96eacd98c81ed38be0c5b274b04031597b0','verified_tensors':1045,
            'target_modules':190,'preserved_mtp_tensors':19,'files':[]}))
        with patch.object(c.subprocess,'check_output',return_value=c.REVISION),patch.object(c.subprocess,'run') as run:
            with self.assertRaises(FileNotFoundError):c.convert(self.root,'main',tools)
        self.assertEqual(run.call_count,1)  # git cleanliness only; no converter/quantizer.
        self.assertFalse((self.root/'exports/qwen36-soc-main-gguf').exists())

    def test_changed_bytes_even_at_same_size_are_rejected(self):
        self.projector.write_bytes(b'GGUF changed')
        with self.assertRaisesRegex(ValueError,'hash or size'):c.verified_base_projector(self.root)

    def test_unverified_or_wrong_converter_and_duplicate_artifact_are_rejected(self):
        for key,value in [('status','failed'),('variant','main'),('llama_cpp_revision','0'*40)]:
            with self.subTest(key=key):
                original=self.manifest[key];self.manifest[key]=value;self.save()
                with self.assertRaises(ValueError):c.verified_base_projector(self.root)
                self.manifest[key]=original
        self.manifest['artifacts']*=2;self.save()
        with self.assertRaises(ValueError):c.verified_base_projector(self.root)

    def test_symlink_projector_is_rejected(self):
        target=self.root/'other.gguf';self.projector.rename(target);self.projector.symlink_to(target)
        with self.assertRaises(ValueError):c.verified_base_projector(self.root)


if __name__=='__main__':unittest.main()
