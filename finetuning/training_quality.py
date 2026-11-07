"""Opt-in intermediate validation, bounded patience, and retained LoRA selection.

Validation loss selects a candidate, never grants SOC/production promotion.
Best adapters are stored separately from rotating recovery checkpoints. Their
hashes and patience state are bound into each complete recovery checkpoint.
"""
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import shutil

STATE = 'quality-control.json'
WEIGHTS = ('adapter_config.json', 'adapter_model.safetensors')


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024*1024), b''): h.update(chunk)
    return h.hexdigest()


def write(path, value):
    path = Path(path); temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2)+'\n')
    temporary.replace(path)


def policy(config):
    value = config.get('quality_control')
    if value is None: return None
    if not isinstance(value, dict) or set(value) != {'patience', 'min_delta'}:
        raise ValueError('Require explicit validation patience/min_delta')
    if type(value['patience']) is not int or not 2 <= value['patience'] <= 10:
        raise ValueError('Validation patience must be 2..10 evaluations')
    if type(value['min_delta']) not in (int, float) or not math.isfinite(value['min_delta']) or not 0 <= value['min_delta'] <= 0.1:
        raise ValueError('Invalid validation min_delta')
    if config.get('final_eval_only', False):
        raise ValueError('Quality control requires intermediate evaluation')
    for key in ('eval_steps', 'save_steps'):
        if type(config.get(key)) is not int or config[key] <= 0:
            raise ValueError('Require positive explicit eval/save intervals')
    if config['eval_steps'] % config['save_steps']:
        raise ValueError('Each intermediate evaluation needs a recovery checkpoint')
    return dict(value)


class Tracker:
    def __init__(self, rules):
        self.state = {'policy': dict(rules), 'last_evaluation_step': -1, 'best_loss': None,
            'best_step': None, 'anchor_loss': None, 'bad_evaluations': 0,
            'stop_requested': False, 'best_directory': None, 'files': {}}

    def observe(self, step, loss):
        s = self.state
        if type(step) is not int or step < 0 or type(loss) not in (int, float) or not math.isfinite(loss) or loss < 0:
            raise ValueError('Require a finite validation loss at a valid step')
        if step < s['last_evaluation_step']: raise ValueError('Validation moved backwards')
        if step == s['last_evaluation_step']:
            if loss != s['last_loss']: raise ValueError('Conflicting evaluation at the same step')
            return False
        improved = s['best_loss'] is None or loss < s['best_loss']
        if improved: s.update(best_loss=loss, best_step=step)
        if s['anchor_loss'] is None or loss < s['anchor_loss']-s['policy']['min_delta']:
            s.update(anchor_loss=loss, bad_evaluations=0)
        else: s['bad_evaluations'] += 1
        s.update(last_evaluation_step=step, last_loss=loss,
                 stop_requested=s['bad_evaluations'] >= s['policy']['patience'])
        return improved


def verify_checkpoint_state(output, checkpoint, expected_policy=None):
    output, checkpoint = Path(output), Path(checkpoint)
    p = checkpoint/STATE
    if p.is_symlink(): raise ValueError('Symlink quality state')
    state = json.loads(p.read_text())
    if expected_policy is not None and state['policy'] != expected_policy:
        raise ValueError('Quality policy changed across resume')
    trainer = json.loads((checkpoint/'trainer_state.json').read_text())
    if not -1 <= state['last_evaluation_step'] <= trainer['global_step']:
        raise ValueError('Quality state is ahead of checkpoint')
    if state['best_directory'] is None:
        if state['files'] or state['best_loss'] is not None: raise ValueError('Incomplete best state')
        return state
    rel = state['best_directory']
    if not isinstance(rel, str) or not re.fullmatch(r'quality-best/step-[0-9]{9}', rel):
        raise ValueError('Unsafe retained adapter path')
    if (type(state['best_step']) is not int or state['best_step'] > state['last_evaluation_step']
            or rel != f"quality-best/step-{state['best_step']:09d}" or not math.isfinite(state['best_loss'])):
        raise ValueError('Invalid best validation metadata')
    directory = output/PurePosixPath(rel)
    if directory.is_symlink() or not directory.resolve().is_relative_to(output.resolve()):
        raise ValueError('Best adapter escapes run output')
    if set(state['files']) != set(WEIGHTS): raise ValueError('Incomplete best adapter manifest')
    for name, expected in state['files'].items():
        p = directory/name
        if p.is_symlink() or not p.is_file() or digest(p) != expected:
            raise ValueError('Retained best adapter changed')
    return state


def callback_class(base):
    class ValidationQuality(base):
        def __init__(self, config, output):
            self.config = config; self.output = Path(output)
            self.tracker = Tracker(policy(config))
            checkpoint = config.get('resume_from_checkpoint')
            if checkpoint:
                checkpoint = Path(checkpoint)
                state = verify_checkpoint_state(checkpoint.parent, checkpoint, self.tracker.state['policy'])
                self.tracker.state = state
                if state['best_directory']:
                    source = checkpoint.parent/state['best_directory']
                    destination = self.output/state['best_directory']
                    destination.mkdir(parents=True, exist_ok=False)
                    for name in WEIGHTS: shutil.copyfile(source/name, destination/name)
                    for name, expected in state['files'].items():
                        if digest(destination/name) != expected: raise ValueError('Retained best copy changed')

        def on_evaluate(self, args, state, control, metrics=None, model=None, **kwargs):
            if not metrics or 'eval_loss' not in metrics: raise ValueError('Validation loss is missing')
            improved = self.tracker.observe(state.global_step, metrics['eval_loss'])
            if improved:
                relative = f'quality-best/step-{state.global_step:09d}'
                destination = self.output/relative
                destination.mkdir(parents=True, exist_ok=False)
                model.save_pretrained(destination, safe_serialization=True)
                files = {}
                for name in WEIGHTS:
                    p = destination/name
                    if p.is_symlink() or not p.is_file(): raise ValueError('Best LoRA export is incomplete')
                    files[name] = digest(p)
                self.tracker.state.update(best_directory=relative, files=files)
            write(self.output/STATE, self.tracker.state)
            if self.tracker.state['stop_requested']:
                control.should_training_stop = True
                control.should_save = True
            return control

        def on_save(self, args, state, control, **kwargs):
            checkpoint = self.output/f'checkpoint-{state.global_step}'
            write(checkpoint/STATE, self.tracker.state)
            verify_checkpoint_state(self.output, checkpoint, self.tracker.state['policy'])
            return control

        def finish(self):
            state = self.tracker.state
            result = {**state, 'selection_basis': 'lowest observed validation loss only',
                'soc_quality_verified': False, 'production_promotion_allowed': False}
            write(self.output/'quality-selection.json', result)
            return result
    return ValidationQuality
