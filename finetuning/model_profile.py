"""Explicit model/loading boundaries shared by training and adapter merging."""
import re


def validate_profile(config):
    kind = config.get('model_kind', 'causal_lm')
    if kind not in ('causal_lm', 'qwen3_5_moe'):
        raise ValueError('Unsupported model_kind')
    quantization = config.get('quantization', 'nf4')
    if quantization not in ('nf4', 'none'):
        raise ValueError('quantization must be nf4 or none')
    if kind == 'qwen3_5_moe':
        if quantization != 'none':
            raise ValueError('35B recipe uses BF16 LoRA: fused MoE expert NF4 training is not validated')
        if not re.fullmatch(r'[0-9a-f]{40}', config.get('revision', '')):
            raise ValueError('Pin the 35B Hugging Face base revision to a commit')
        if not isinstance(config.get('target_modules'), str) or not config['target_modules'].startswith(r'model\.language_model\.layers\.'):
            raise ValueError('35B LoRA must be scoped to language-model layers')
        if config.get('min_available_memory_gib', 0) < 96:
            raise ValueError('35B recipe requires the documented 96 GiB free-memory planning floor')
    return kind


def model_class(config):
    kind = validate_profile(config)
    if kind == 'qwen3_5_moe':
        from transformers import Qwen3_5MoeForConditionalGeneration
        return Qwen3_5MoeForConditionalGeneration
    from transformers import AutoModelForCausalLM
    return AutoModelForCausalLM


def validate_model_config(config, model_config):
    if validate_profile(config) == 'qwen3_5_moe':
        if model_config.model_type != 'qwen3_5_moe' or 'Qwen3_5MoeForConditionalGeneration' not in (model_config.architectures or []):
            raise ValueError('Base architecture does not match the 35B recipe')


def check_lora_targets(config, named_modules):
    """Count actual module paths before adapting; never match vision by suffix."""
    if validate_profile(config) != 'qwen3_5_moe':
        return None
    names = [name for name, _ in named_modules if re.fullmatch(config['target_modules'], name)]
    counts = {'self_attn': sum('.self_attn.' in n for n in names),
              'linear_attn': sum('.linear_attn.' in n for n in names)}
    if counts != config.get('expected_lora_modules') or any('.visual.' in n for n in names):
        raise ValueError(f'Unexpected actual LoRA module coverage: {counts}')
    return {'counts': counts, 'modules': names}


def check_trainable_scope(config, named_parameters):
    if validate_profile(config) != 'qwen3_5_moe':
        return
    trainable = [name for name, p in named_parameters if p.requires_grad]
    if not trainable or any('.model.language_model.layers.' not in name or '.lora_' not in name for name in trainable):
        raise ValueError('35B training escaped the language-only LoRA scope')


def check_training_capacity(config, hardware):
    if validate_profile(config) != 'qwen3_5_moe':
        return
    if not hardware.get('bf16_supported'):
        raise RuntimeError('35B BF16 recipe requires BF16 GPU support')
    if hardware.get('platform') != 'aarch64' or hardware.get('compute_capability') != [11, 0]:
        raise RuntimeError('This profile targets thor-05 / aarch64 / SM110; use a separately reviewed hardware profile')
    available = hardware.get('available_memory_gib')
    if available is None or available < config['min_available_memory_gib']:
        raise RuntimeError('Insufficient free memory for the 35B planning floor. Arrange a training window; do not stop Ollama automatically.')
