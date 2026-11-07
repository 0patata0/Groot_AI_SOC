import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import training_quality as q


class QualityTests(unittest.TestCase):
    def test_best_loss_and_patience_anchor_are_distinct(self):
        tracker = q.Tracker({'patience': 2, 'min_delta': 0.01})
        self.assertTrue(tracker.observe(2, 1.0))
        self.assertTrue(tracker.observe(4, 0.995))
        self.assertEqual(tracker.state['bad_evaluations'], 1)
        self.assertTrue(tracker.observe(6, 0.98))
        self.assertEqual(tracker.state['bad_evaluations'], 0)
        tracker.observe(8, 1.1); tracker.observe(10, 1.2)
        self.assertTrue(tracker.state['stop_requested'])
        self.assertEqual(tracker.state['best_step'], 6)

    def test_repeated_final_evaluation_does_not_consume_patience(self):
        tracker = q.Tracker({'patience': 2, 'min_delta': 0.01})
        tracker.observe(2, 1.0); tracker.observe(4, 1.1)
        self.assertFalse(tracker.observe(4, 1.1))
        self.assertEqual(tracker.state['bad_evaluations'], 1)
        for step, loss in ((4, 1.2), (3, 1.0), (5, float('nan')), (5, float('inf'))):
            with self.subTest(step=step, loss=loss), self.assertRaises(ValueError): tracker.observe(step, loss)

    def test_configuration_requires_intermediate_evaluation_and_checkpoint(self):
        base = {'quality_control': {'patience': 3, 'min_delta': 0.001}, 'eval_steps': 32, 'save_steps': 4}
        self.assertEqual(q.policy(base)['patience'], 3)
        for change in ({'final_eval_only': True}, {'eval_steps': 3}, {'save_steps': True},
                       {'quality_control': {'patience': 1, 'min_delta': 0.001}},
                       {'quality_control': {'patience': 3, 'min_delta': float('nan')}}):
            with self.subTest(change=change), self.assertRaises(ValueError): q.policy({**base, **change})

    def test_best_adapter_survives_checkpoint_rotation_and_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); old = root/'old'; old.mkdir()
            c = {'quality_control': {'patience': 2, 'min_delta': 0.01}, 'eval_steps': 2, 'save_steps': 1}
            callback = q.callback_class(object)(c, old)
            class Model:
                def save_pretrained(self, path, **kwargs):
                    for name in q.WEIGHTS: (path/name).write_bytes(b'reviewed adapter')
            control = SimpleNamespace(should_training_stop=False, should_save=False)
            callback.on_evaluate(None, SimpleNamespace(global_step=2), control, metrics={'eval_loss': 0.8}, model=Model())
            callback.on_evaluate(None, SimpleNamespace(global_step=4), control, metrics={'eval_loss': 0.9}, model=Model())
            checkpoint = old/'checkpoint-4'; checkpoint.mkdir()
            (checkpoint/'trainer_state.json').write_text(json.dumps({'global_step': 4}))
            callback.on_save(None, SimpleNamespace(global_step=4), control)
            new = root/'new'; new.mkdir()
            resumed = q.callback_class(object)({**c, 'resume_from_checkpoint': str(checkpoint)}, new)
            self.assertEqual(resumed.tracker.state['best_step'], 2)
            self.assertTrue((new/'quality-best/step-000000002/adapter_model.safetensors').is_file())
            resumed.on_evaluate(None, SimpleNamespace(global_step=6), control, metrics={'eval_loss': 1.0}, model=Model())
            self.assertTrue(control.should_training_stop)
            self.assertFalse(resumed.finish()['production_promotion_allowed'])
            (old/'quality-best/step-000000002/adapter_model.safetensors').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'changed'): q.verify_checkpoint_state(old, checkpoint)


if __name__ == '__main__': unittest.main()
