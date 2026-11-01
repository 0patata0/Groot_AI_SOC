"""Verify an explicit, immutable Trainer checkpoint before resuming a new run."""
import hashlib
import json
from pathlib import Path
import re

REQUIRED = {'adapter_model.safetensors', 'adapter_config.json', 'trainer_state.json',
            'optimizer.pt', 'scheduler.pt', 'rng_state.pth', 'training_args.bin'}
RUNTIME_FIELDS = {'data_dir', 'output_dir', 'training_deadline_epoch',
                  'base_artifact_manifest', 'resume_from_checkpoint', 'resume_manifest'}
COMPLETION_MARKER='checkpoint-complete.json'


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def make_receipt(prior_output, checkpoint):
    prior_output, checkpoint = Path(prior_output), Path(checkpoint)
    if checkpoint.parent != prior_output or not re.fullmatch(r'checkpoint-[1-9][0-9]*', checkpoint.name):
        raise ValueError('Require a named checkpoint directly inside the prior run output')
    if checkpoint.is_symlink() or prior_output.is_symlink():
        raise ValueError('Checkpoint paths must not be symlinks')
    files = {}
    for p in checkpoint.iterdir():
        if not p.is_file() or p.is_symlink():
            raise ValueError('Checkpoint must contain regular files only')
        if p.name==COMPLETION_MARKER:continue
        files[p.name] = digest(p)
    if not REQUIRED <= files.keys():
        raise ValueError('Incomplete optimizer/RNG/adapter checkpoint')
    state = json.loads((checkpoint/'trainer_state.json').read_text())
    if (type(state['global_step']) is not int or type(state['max_steps']) is not int
            or not 0 < state['global_step'] < state['max_steps']
            or checkpoint.name != 'checkpoint-'+str(state['global_step'])):
        raise ValueError('Require a partial checkpoint with matching step')
    prior = json.loads((prior_output/'run_manifest.json').read_text())
    return {'schema': 1, 'checkpoint': checkpoint.name, 'files': files,
            'step': state['global_step'], 'max_steps': state['max_steps'],
            'config': prior['config'], 'data': prior['data'],
            'base_artifact_manifest': prior['base_artifact_manifest'],
            'prior_run_manifest_sha256': digest(prior_output/'run_manifest.json')}


def mark_completed(prior_output, checkpoint):
    # Called only after Trainer._save_checkpoint returns (optimizer/RNG/state saved).
    # Full-plan checkpoints remain preserved, but automatic retries use a partial
    # checkpoint so Trainer never accidentally performs an extra optimizer step.
    checkpoint=Path(checkpoint)
    state=json.loads((checkpoint/'trainer_state.json').read_text())
    if state['global_step']==state['max_steps']:return
    receipt=make_receipt(prior_output,checkpoint)
    temp=checkpoint/(COMPLETION_MARKER+'.tmp')
    temp.write_text(json.dumps(receipt,sort_keys=True)+'\n')
    temp.replace(checkpoint/COMPLETION_MARKER)


def verified_completion(prior_output, checkpoint):
    marker=Path(checkpoint)/COMPLETION_MARKER
    if marker.is_symlink():raise ValueError('Completion marker cannot be a symlink')
    expected=json.loads(marker.read_text())
    actual=make_receipt(prior_output,checkpoint)
    if actual!=expected:raise ValueError('Completed checkpoint bytes changed')
    return actual


def validate_resume(config, checks):
    path, receipt_path = config.get('resume_from_checkpoint'), config.get('resume_manifest')
    if path is None and receipt_path is None:
        return None
    if not isinstance(path, str) or not isinstance(receipt_path, str):
        raise ValueError('Resume requires an explicit checkpoint and receipt')
    checkpoint = Path(path)
    if not checkpoint.is_absolute() or checkpoint.is_symlink():
        raise ValueError('Use an absolute regular checkpoint directory')
    receipt = json.loads(Path(receipt_path).read_text())
    if receipt['schema'] != 1 or checkpoint.name != receipt['checkpoint']:
        raise ValueError('Checkpoint identity differs')
    actual = make_receipt(checkpoint.parent, checkpoint)
    if actual != receipt:
        raise ValueError('Checkpoint bytes or prior provenance changed')
    old = {k: v for k, v in receipt['config'].items() if k not in RUNTIME_FIELDS}
    new = {k: v for k, v in config.items() if k not in RUNTIME_FIELDS}
    if old != new:
        raise ValueError('Resume training configuration differs')
    if checks['records'] != receipt['data']['records'] or checks['sha256'] != receipt['data']['sha256']:
        raise ValueError('Resume dataset differs')
    if config.get('base_artifact_manifest') != receipt['base_artifact_manifest']:
        raise ValueError('Resume base artifact differs')
    return receipt


def remaining_seconds(elapsed, step, maximum, initial_step=0):
    completed = step-initial_step
    return round(elapsed/completed*(maximum-step), 1) if completed > 0 else None
