"""The fresh-install source bundle must import without repository fallbacks."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('ollama_source_bundle',HERE/'ollama_trial.py')
installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)

class SourceBundle(unittest.TestCase):
    def test_standalone_harness_has_formatter_and_pinned_grounding(self):
        with patch.object(installer,'safe',side_effect=lambda p:Path(p)):
            files=installer.source_files(HERE.parent/'infra/ollama-trial')
        self.assertIn('chat_markdown.py',files)
        with tempfile.TemporaryDirectory() as root:
            for name,path in files.items():(Path(root)/name).write_bytes(path.read_bytes())
            code="import sys;sys.path.insert(0,sys.argv[1]);import harness;assert harness.security_inventory_request('WAF 룰 각각 표로 보여줘')['view']=='details'"
            result=subprocess.run([sys.executable,'-I','-B','-c',code,root],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)

if __name__=='__main__':unittest.main()
