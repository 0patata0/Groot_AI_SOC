"""Build an isolated DGX-trained candidate; never change an operational model.

Enter through deploy.sh --model-candidate. CPU export uses the exact recorded
base; registration retains existing model digests and the current bot selection.
"""
import argparse
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import shutil
import sys
import time
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parent))
VARIANT = 'dgx-guide'
MODEL = 'soc-qwen36:35b-dgx-guide-q4km-20261101'
NOTICES = ('SOURCE_NOTICE.txt', 'GUIDE_LICENSE.txt', 'MITRE-ATTACK-LICENSE.txt',
           'AIT_NOTICE.txt', 'LINUX_APT_NOTICE.txt', 'REVIEWED_V4_SOURCE_NOTICE.txt',
           'REVIEWED_V4_AIT_NOTICE.txt', 'V5_SOURCE_ATTRIBUTION.json')


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(8*1024*1024), b''): value.update(block)
    return value.hexdigest()


def read(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file(): raise ValueError('Require a regular input file')
    return json.loads(path.read_text())


def candidate_profile(root):
    path = Path(root)/'candidate-profile.json'
    if path.is_symlink(): raise ValueError('Candidate profile must not be a symlink')
    if not path.exists(): return None  # Preserve historical candidate receipts.
    value = read(path)
    if (set(value) != {'schema', 'model', 'adapter_sha256', 'run_manifest_sha256', 'source_notices'}
            or type(value['schema']) is not int or value['schema'] != 1
            or not isinstance(value['model'], str)
            or not re.fullmatch(r'soc-qwen36:35b-[a-z0-9][a-z0-9-]{1,79}', value['model'])
            or any(not isinstance(value[k], str) or not re.fullmatch(r'[0-9a-f]{64}', value[k])
                   for k in ('adapter_sha256', 'run_manifest_sha256'))
            or not isinstance(value['source_notices'], dict) or not value['source_notices']
            or any(not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', name)
                   or not isinstance(sha, str) or not re.fullmatch(r'[0-9a-f]{64}', sha)
                   for name, sha in value['source_notices'].items())):
        raise ValueError('Invalid immutable candidate profile')
    return value


def model_name(root):
    profile = candidate_profile(root)
    return profile['model'] if profile else MODEL


def metadata(output, base_manifest, data, expected_adapter, *, model=MODEL):
    output, data = Path(output), Path(data)
    progress, state = read(output/'progress.json'), read(output/'trainer_state.json')
    if (progress.get('status') != 'completed' or type(state.get('global_step')) is not int
            or not 0 < state['global_step'] == state.get('max_steps') == progress.get('step') == progress.get('max_steps')):
        raise ValueError('Full training and final validation must be complete')
    metrics, manifest = read(output/'eval_results.json'), read(output/'run_manifest.json')
    if not math.isfinite(metrics['eval_loss']): raise ValueError('Nonfinite validation loss')
    if digest(output/'adapter/adapter_model.safetensors') != expected_adapter:
        raise ValueError('Final adapter differs from the selected candidate')
    if digest(output/f'checkpoint-{state["global_step"]}/adapter_model.safetensors') != expected_adapter:
        raise ValueError('Final checkpoint differs from exported adapter')
    base = read(base_manifest)
    provenance = manifest['base_artifact_manifest']
    if (not base.get('verified') or base['model'] != provenance['model']
            or base['revision'] != provenance['revision']
            or digest(base_manifest) != provenance['manifest_sha256']
            or manifest['config']['base_artifact_manifest'] != provenance):
        raise ValueError('Training base provenance mismatch')
    token = read(output/'tokenization_report.json')
    for split in ('train', 'validation', 'test'):
        path = data/(split+'.jsonl')
        if digest(path) != manifest['data']['sha256'][split]: raise ValueError('Training split changed')
        count = sum(bool(line.strip()) for line in path.read_bytes().splitlines())
        if count != manifest['data']['records'][split]: raise ValueError('Training record count mismatch')
        if split != 'test' and token[split]['kept'] != count: raise ValueError('Token coverage incomplete')
    return {'schema': 1, 'status': 'metadata_verified', 'at_kst': datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),
            'model': model, 'steps': state['global_step'], 'records': manifest['data']['records'],
            'adapter_sha256': expected_adapter, 'base_revision': base['revision'],
            'base_manifest_sha256': digest(base_manifest), 'run_manifest_sha256': digest(output/'run_manifest.json'),
            'data_sha256': manifest['data']['sha256'], 'eval_loss': metrics['eval_loss'],
            'quality_passed': False, 'automatic_promotion': False}


def verify(output, root, data, expected_adapter):
    import torch
    from safetensors.torch import load_file
    from merge_adapter import inspect_adapter
    from merge_streaming import plan_lora
    output, root = Path(output), Path(root)
    result = metadata(output, root/'base-manifest.json', data, expected_adapter, model=model_name(root))
    profile = candidate_profile(root)
    if profile:
        if (profile['adapter_sha256'] != result['adapter_sha256'] or
                profile['run_manifest_sha256'] != result['run_manifest_sha256']):
            raise ValueError('Candidate profile differs from selected completed training')
        result['candidate_profile_sha256'] = digest(root/'candidate-profile.json')
    info = inspect_adapter(output/'adapter')
    index = read(Path(info['base_model_name_or_path'])/'model.safetensors.index.json')['weight_map']
    peft = read(output/'adapter/adapter_config.json')
    weights = load_file(output/'adapter/adapter_model.safetensors', device='cpu')
    pairs, _ = plan_lora(weights, index, peft, info['training_config'])
    if any(not torch.isfinite(t).all() for t in weights.values()): raise ValueError('Nonfinite adapter tensor')
    if any(not torch.count_nonzero(weights[p['B']]) for p in pairs.values()): raise ValueError('Untrained LoRA target')
    result.update(status='verified', finite_tensors=len(weights), lora_pairs=len(pairs), device='cpu')
    return result


def verified_receipt(root, merge=None):
    root = Path(root)
    receipt = read(root/'training-verification.json')
    if (receipt.get('status') != 'verified' or receipt.get('finite_tensors') != 380
            or receipt.get('lora_pairs') != 190 or receipt.get('automatic_promotion') is not False
            or receipt.get('model') != model_name(root)): raise ValueError('Verified candidate training receipt required')
    profile = candidate_profile(root)
    if profile and (receipt.get('candidate_profile_sha256') != digest(root/'candidate-profile.json')
            or receipt.get('adapter_sha256') != profile['adapter_sha256']
            or receipt.get('run_manifest_sha256') != profile['run_manifest_sha256']):
        raise ValueError('Candidate profile or selected training changed')
    if merge and merge['adapter_sha256'] != receipt['adapter_sha256']: raise ValueError('Merged candidate differs from selected adapter')
    return receipt


def source_notice(root):
    root = Path(root); receipt = verified_receipt(root)
    files = receipt['source_notices']
    profile = candidate_profile(root)
    expected = profile['source_notices'] if profile else {name: None for name in NOTICES}
    if set(files) != set(expected): raise ValueError('Complete training-source notices required')
    chunks = ['SOC DGX candidate training sources; provenance is not institutional certification.']
    for name in sorted(expected):
        path = root/'source-notices'/name
        if digest(path) != files[name] or (profile and files[name] != expected[name]):
            raise ValueError('Training-source notice changed')
        chunks += [name, path.read_text()]
    return '\n\n'+'\n\n'.join(chunks)


def verify_conversion(root, conversion):
    receipt = verified_receipt(root)
    if (conversion.get('training_verification_sha256') != digest(Path(root)/'training-verification.json')
            or conversion.get('adapter_sha256') != receipt['adapter_sha256']):
        raise ValueError('Conversion does not bind the selected training receipt')
    return receipt


def memory_snapshot():
    values = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        name, rest = line.split(':', 1)
        if name in ('MemTotal', 'MemFree', 'MemAvailable', 'Cached', 'SReclaimable', 'Unevictable', 'CmaFree'):
            values[name] = int(rest.split()[0]) * 1024
    if values.get('MemAvailable', -1) < 0: raise ValueError('Memory availability unknown')
    return values


def readiness(root, *, warm=False, api_fn=None, memory_fn=memory_snapshot):
    """Opt-in preparation gate; no eviction, service changes, retry or promotion.

    64 GiB is a conservative admission policy for this 35B candidate, not proof
    that the NVIDIA allocator will succeed. External API callers can race this
    check; the final loaded-model check catches overlap but cannot prevent it.
    Once this exact model is fully on GPU, retain a separate 32 GiB reserve;
    allocated model memory must not count against the admission margin twice.
    """
    import fcntl
    from register_soc import api
    root = Path(root); api_fn = api_fn or api
    model = model_name(root)
    registration = read(root/f'exports/qwen36-soc-{VARIANT}-gguf/registration-status.json')
    if registration.get('status') != 'completed' or registration.get('model') != model:
        raise ValueError('Completed candidate registration required')
    receipt = {'at_kst': datetime.now(ZoneInfo('Asia/Seoul')).isoformat(), 'model': model,
               'status': 'checking', 'warm_requested': warm, 'model_posts': 0,
               'minimum_available_bytes': 64*1024**3, 'automatic_promotion': False,
               'minimum_loaded_available_bytes': 32*1024**3,
               'automatic_retry': False, 'driver_fix_proven': False}
    directory = root/'inference-readiness'; directory.mkdir(exist_ok=True)
    lock = directory/'gate.lock'
    if lock.is_symlink(): raise ValueError('Unsafe readiness lock')
    with lock.open('a') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        record = directory/(datetime.now(ZoneInfo('Asia/Seoul')).strftime('%Y%m%dT%H%M%S%f')+'.json')
        def inspect():
            tags = {m['name']: m['digest'] for m in api_fn('/api/tags')['models']}
            loaded = api_fn('/api/ps')['models']
            memory = memory_fn()
            reasons = []
            if tags.get(model) != registration['digest']: reasons.append('candidate_digest_changed')
            if tags.get('qwen3.6:35b') != registration['original_digest']: reasons.append('original_digest_changed')
            if any(m['name'] != model for m in loaded): reasons.append('other_models_loaded')
            minimum = (receipt['minimum_loaded_available_bytes'] if on_gpu({'loaded': loaded})
                       else receipt['minimum_available_bytes'])
            if memory['MemAvailable'] < minimum: reasons.append('insufficient_memory_margin')
            return {'loaded': loaded, 'memory': memory, 'minimum_available_bytes': minimum, 'reasons': reasons}
        def on_gpu(snapshot):
            return any(m['name'] == model and m.get('digest') == registration['digest']
                       and m.get('size', 0) > 0 and m.get('size_vram', 0) >= m['size'] * 0.99
                       and m.get('context_length') == 262144
                       for m in snapshot['loaded'])
        started = time.monotonic()
        try:
            receipt['before'] = inspect()
            if receipt['before']['reasons']:
                receipt['status'] = 'blocked'
            elif not warm:
                receipt['status'] = 'preflight_passed'
            else:
                # Recheck immediately before allocation; never unload someone else's model.
                receipt['admission'] = inspect()
                if receipt['admission']['reasons']:
                    receipt['status'] = 'blocked'
                else:
                    receipt['model_posts'] = 1
                    result = api_fn('/api/generate', {'model': model, 'prompt': '준비 완료라고만 답하세요.',
                        'stream': False, 'think': False, 'keep_alive': '5m',
                        'options': {'temperature': 0, 'num_predict': 16, 'num_ctx': 262144}}, timeout=90)
                    receipt['after'] = inspect()
                    if (not result.get('done') or not result.get('response', '').strip()
                            or receipt['after']['reasons'] or not on_gpu(receipt['after'])):
                        raise ValueError('Candidate GPU readiness not established')
                    receipt.update(status='ready', load_duration_ns=result.get('load_duration'),
                                   total_duration_ns=result.get('total_duration'))
        except Exception as error:
            receipt.update(status='failed', error_type=type(error).__name__)
        receipt['seconds'] = time.monotonic() - started
        record.write_text(json.dumps(receipt, ensure_ascii=False, indent=2)+'\n')
        return receipt


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--phase', choices=('check', 'merge', 'convert', 'register', 'preflight', 'warmup'), required=True)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--training-output', type=Path)
    p.add_argument('--data', type=Path)
    p.add_argument('--adapter-sha256')
    p.add_argument('--tools', type=Path)
    p.add_argument('--api-base-url', choices=('http://127.0.0.1:11434', 'http://127.0.0.1:11435'),
                   default='http://127.0.0.1:11434')
    a = p.parse_args()
    if a.api_base_url != 'http://127.0.0.1:11434' and a.phase not in ('register','preflight','warmup'):
        p.error('An isolated inference endpoint is only used for registration/readiness')
    from register_soc import set_api_base_url
    set_api_base_url(a.api_base_url)
    if a.phase in ('check', 'merge'):
        if not all((a.training_output, a.data, a.adapter_sha256)): p.error('Training output, data and selected adapter SHA required')
        result = verify(a.training_output, a.root, a.data, a.adapter_sha256)
        if a.phase == 'merge':
            receipt = a.root/'training-verification.json'
            if receipt.exists(): raise ValueError('Use a new candidate export directory')
            notices = a.root/'source-notices'; notices.mkdir(exist_ok=False)
            profile = candidate_profile(a.root)
            selected = profile['source_notices'] if profile else {name: None for name in NOTICES}
            for name, expected in selected.items():
                source = a.data/'licenses'/name if profile else a.data/name
                if expected is not None and digest(source) != expected:
                    raise ValueError('Pinned training source notice differs')
                shutil.copyfile(source, notices/name)
            result['source_notices'] = {name: digest(notices/name) for name in selected}
            receipt.write_text(json.dumps(result, indent=2)+'\n')
            from merge_streaming import merge
            result = merge(a.training_output/'adapter', a.root/f'exports/qwen36-soc-{VARIANT}-hf', a.root/'base-manifest.json')
    elif a.phase == 'convert':
        from convert_soc import convert
        result = convert(a.root, VARIANT, tools_root=a.tools)
    elif a.phase == 'register':
        from register_soc import register
        result = register(a.root, VARIANT)
    else:
        if sys.platform != 'linux': raise SystemExit('Readiness must run on the Thor host')
        result = readiness(a.root, warm=a.phase == 'warmup')
    print(json.dumps(result, ensure_ascii=False))
    if result.get('status') in ('blocked', 'failed'): raise SystemExit(2)


if __name__ == '__main__': main()
