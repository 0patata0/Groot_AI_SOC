"""A memory breach must kill the training group, without killing unrelated work."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import guarded_process


class GuardTests(unittest.TestCase):
    def test_reserve_breach_kills_child_but_not_unrelated_process(self):
        with tempfile.TemporaryDirectory() as directory, open(os.devnull,'w') as log:
            other=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])
            try:
                report=Path(directory)/'guard.json'
                with patch('guarded_process.available_bytes',side_effect=[100,100,5]):
                    with self.assertRaisesRegex(RuntimeError,'reserve exhaustion'):
                        guarded_process.run([sys.executable,'-c','import time;time.sleep(30)'],
                            log=log,cwd=directory,env=os.environ.copy(),report=report,
                            reserve_bytes=10,poll_seconds=0.01)
                result=json.loads(report.read_text())
                self.assertEqual(result['status'],'memory_reserve_abort')
                self.assertLess(result['returncode'],0)
                self.assertIsNone(other.poll())
            finally:other.terminate();other.wait(timeout=5)

    def test_guard_read_failure_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory, open(os.devnull,'w') as log:
            report=Path(directory)/'guard.json'
            with patch('guarded_process.available_bytes',side_effect=[100,OSError('unreadable')]):
                with self.assertRaises(OSError):
                    guarded_process.run([sys.executable,'-c','import time;time.sleep(30)'],
                        log=log,cwd=directory,env=os.environ.copy(),report=report,reserve_bytes=10)
            result=json.loads(report.read_text())
            self.assertEqual(result['status'],'guard_error')
            self.assertLess(result['returncode'],0)

    def test_nonzero_child_is_not_reported_successful(self):
        with tempfile.TemporaryDirectory() as directory, open(os.devnull,'w') as log:
            report=Path(directory)/'guard.json'
            with patch('guarded_process.available_bytes',return_value=100):
                with self.assertRaises(subprocess.CalledProcessError):
                    guarded_process.run([sys.executable,'-c','raise SystemExit(7)'],
                        log=log,cwd=directory,env=os.environ.copy(),report=report,
                        reserve_bytes=10,poll_seconds=0.01)
            self.assertEqual(json.loads(report.read_text())['returncode'],7)


if __name__=='__main__':unittest.main()
