"""No service/network calls: protect the outage prerequisite and recovery boundaries."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import training_window as window


class WindowTests(unittest.TestCase):
    def memory_mode(self):
        return patch.multiple(window,MODE=window.MODE,STAGES=window.STAGES,STATE=window.STATE,
                              LIMIT_SECONDS=window.LIMIT_SECONDS,RESTORE_MINUTES=window.RESTORE_MINUTES,
                              RESTORE_UNIT=window.RESTORE_UNIT)

    def test_memory_repro_is_one_new_stage_with_its_own_short_recovery_timer(self):
        with self.memory_mode():
            window.select_mode('memory-repro')
            self.assertEqual(window.STAGES,('soc-memory-smoke',))
            self.assertEqual(window.LIMIT_SECONDS,360)
            self.assertNotEqual(window.STATE,Path('/var/lib/capstone-training-v2-window'))
            args=window.restore_command('/usr/local/libexec/inspected.py','/training')
            self.assertIn('--on-active=8m',args);self.assertIn('memory-repro',args)
            self.assertIn('--property=Type=oneshot',args);self.assertIn('--property=TimeoutStartSec=6min',args)
            self.assertLess(window.RESTORE_MINUTES+6,15)

    def test_memory_repro_keeps_existing_v2_results_and_rejects_its_own_retry(self):
        with tempfile.TemporaryDirectory() as d,self.memory_mode():
            root=Path(d);digests=self.fixture(root)
            (root/'soc-v2-smoke-status.json').write_text('{"status":"completed"}')
            (root/'outputs/soc-v2-pilot').mkdir(parents=True)
            window.select_mode('memory-repro')
            with patch.object(window,'DATA_HASHES',digests):
                window.verify_ready(root)
                (root/'soc-memory-smoke-status.json').write_text('{"status":"failed"}')
                with self.assertRaisesRegex(ValueError,'automatic retry'):window.verify_ready(root)

    def test_unknown_operator_mode_is_rejected_and_v2_defaults_stay_reviewed(self):
        with self.memory_mode():
            with self.assertRaises(ValueError):window.select_mode('arbitrary')
            window.select_mode('memory-repro');window.select_mode('v2')
            self.assertEqual(window.STAGES,('soc-v2-smoke','soc-v2-pilot'))
            self.assertEqual(window.LIMIT_SECONDS,45*60);self.assertEqual(window.RESTORE_MINUTES,50)

    def fixture(self,root):
        (root/'finetuning/data-soc-v2-r2').mkdir(parents=True)
        config=Path(__file__).resolve().parents[1]/'config.qwen36-soc-v2.json'
        (root/'finetuning/config.qwen36-soc-v2.json').write_bytes(config.read_bytes())
        digests={}
        for split in ('train','validation','test'):
            p=root/'finetuning/data-soc-v2-r2'/(split+'.jsonl');p.write_text(split+'\n');digests[split]=hashlib.sha256(p.read_bytes()).hexdigest()
        (root/'soc-v2-tokenization').mkdir()
        report={s:{'kept':1,'candidate_turns':1} for s in digests};report.update(max_length=2048,require_all_prefixes=True)
        (root/'soc-v2-tokenization/tokenization_report.json').write_text(json.dumps(report))
        (root/'soc-v2-tokenization/data_check.json').write_text(json.dumps({'sha256':digests}))
        (root/'soc-v2-evaluation').mkdir()
        (root/'soc-v2-evaluation/base-development-r2-job.json').write_text(json.dumps({'status':'completed','original_warm_done':True,'source_sha256':window.BASELINE_INPUTS}))
        return digests

    def test_successful_checks_do_not_control_services_and_stale_proof_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);digests=self.fixture(root)
            with patch.object(window,'DATA_HASHES',digests),patch.object(window,'run',side_effect=AssertionError('No service action')):
                window.verify_ready(root)
                p=root/'soc-v2-tokenization/data_check.json';p.write_text('{"sha256":{}}')
                with self.assertRaisesRegex(ValueError,'different corpus'):window.verify_ready(root)

    def test_changed_profile_and_prior_training_cannot_be_reused(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);digests=self.fixture(root)
            with patch.object(window,'DATA_HASHES',digests):
                (root/'soc-v2-smoke-status.json').write_text('{"status":"failed"}')
                with self.assertRaisesRegex(ValueError,'automatic retry'):window.verify_ready(root)
                p=root/'finetuning/config.qwen36-soc-v2.json';p.write_text(p.read_text()+' ')
                with self.assertRaisesRegex(ValueError,'checksum'):window.verify_ready(root)

    def test_independent_timer_is_outside_the_supervisor_and_before_approved_limit(self):
        args=window.restore_command('/usr/local/libexec/inspected.py','/training')
        self.assertIn('--on-active=50m',args);self.assertIn('restore',args)
        self.assertLess(window.LIMIT_SECONDS,window.RESTORE_MINUTES*60)
        self.assertLess(window.RESTORE_MINUTES,60)

    def test_other_gpu_process_cannot_be_accepted_only_by_its_name(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for pid,parent in ((20,10),(10,1),(30,1)):
                (root/str(pid)).mkdir();(root/str(pid)/'status').write_text('PPid:\t'+str(parent)+'\n')
            self.assertTrue(window.process_belongs_to(20,10,root))
            self.assertFalse(window.process_belongs_to(30,10,root))

    def test_failed_stage_still_restores_and_timer_precedes_service_stop(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);calls=[]
            def command(args,**kwargs):
                calls.append([str(a) for a in args])
                if args[0]=='runuser':raise RuntimeError('stage launch failed')
                stdout='10' if 'MainPID' in args else 'active' if 'is-active' in args else ''
                return SimpleNamespace(returncode=0,stdout=stdout)
            tags={'models':[{'name':window.ORIGINAL,'digest':window.ORIGINAL_DIGEST}]}
            with patch.object(window,'STATE',root),patch.object(window,'verify_ready'),patch.object(window,'api',return_value=tags), \
                 patch.object(window,'run',side_effect=command),patch.object(window,'restore') as recovery, \
                 patch('training_window.pwd.getpwuid',return_value=SimpleNamespace(pw_name='fixture')):
                with self.assertRaises(RuntimeError):window.window(root,Path('/root/inspected.py'))
                recovery.assert_called_once_with(root)
            timer=next(i for i,a in enumerate(calls) if a[0]=='systemd-run')
            stop=calls.index(['systemctl','stop','ollama']);self.assertLess(timer,stop)
            self.assertEqual(json.loads((root/'window.json').read_text())['status'],'training_failed_restored')

    def test_failed_warmup_leaves_independent_timer_available(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);tags={'models':[{'name':window.ORIGINAL,'digest':window.ORIGINAL_DIGEST}]}
            with patch.object(window,'STATE',root),patch.object(window,'run',return_value=SimpleNamespace(returncode=1,stdout='')) as command, \
                 patch.object(window,'api',side_effect=[tags,{'done':False}]):
                with self.assertRaises(RuntimeError):window.restore(root)
            self.assertFalse(any(c.args[0]==['systemctl','stop',window.RESTORE_UNIT+'.timer'] for c in command.call_args_list))
            self.assertEqual(json.loads((root/'restore.json').read_text())['status'],'restore_failed')


if __name__=='__main__':unittest.main()
