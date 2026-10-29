import hashlib,json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).parents[1]))
import training_window as w

class R8Safety(unittest.TestCase):
    def mode(self):
        return patch.multiple(w,MODE=w.MODE,STAGES=w.STAGES,STATE=w.STATE,LIMIT_SECONDS=w.LIMIT_SECONDS,
                              RESTORE_MINUTES=w.RESTORE_MINUTES,RESTORE_UNIT=w.RESTORE_UNIT)

    def test_full_only_window_has_distinct_state_and_independent_restore(self):
        with self.mode():
            w.select_mode('v5-r8')
            self.assertEqual(w.STAGES,('soc-v5-train',))
            self.assertEqual(w.LIMIT_SECONDS,340*60)
            self.assertEqual(w.RESTORE_MINUTES,345)
            self.assertIn('r8',str(w.STATE))
            args=w.restore_command('/root/operator.py','/training')
            self.assertIn('--on-active=345m',args)
            self.assertIn('--property=TimeoutStartSec=6min',args)
            self.assertEqual(args[-1],'v5-r8')

    def test_unapproved_larger_window_stops_before_service_calls(self):
        with tempfile.TemporaryDirectory() as d,self.mode():
            root=Path(d);(root/'finetuning').mkdir()
            (root/'finetuning/V5_TRAINING_INPUTS.json').write_text(json.dumps({
                'total_planned_outage_seconds':21060,'total_approved_outage_seconds':16200}))
            w.select_mode('v5-r8')
            with patch.object(w,'verify_ready'),patch.object(w,'run',side_effect=AssertionError('No service call')):
                with self.assertRaisesRegex(ValueError,'not been approved'):w.window(root,Path('/root/operator.py'))

    def test_progress_check_records_status_without_triggering_training(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);state=root/'state';state.mkdir();(state/'window.json').write_text('{"status":"training"}')
            with patch.object(w,'STATE',state),patch.object(w,'run',return_value=SimpleNamespace(stdout='inactive\n')) as run:
                result=w.progress_snapshot(root)
            self.assertEqual(result['window']['status'],'training')
            self.assertTrue((state/'scheduled-progress-check.json').exists())
            run.assert_called_once_with(['systemctl','is-active','ollama'],check=False)

    def test_mutated_reference_is_rejected_before_reading_other_artifacts(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);p=root/'proof.json';p.write_bytes(b'changed')
            frozen={'reproducibility_reference':{'files_sha256':{'proof.json':hashlib.sha256(b'original').hexdigest()}}}
            with self.assertRaisesRegex(ValueError,'checksum'):
                w.verify_deterministic_reference(root,frozen,{'max_train_samples':0,'max_eval_samples':0,'per_device_train_batch_size':1,'gradient_accumulation_steps':2})

if __name__=='__main__':unittest.main()
