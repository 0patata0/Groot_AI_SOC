#!/usr/bin/env python3
"""Single NVIDIA GPU LoRA/NF4 recipes. --check is stdlib-only; --train is explicit.

Expand each dialogue into assistant-turn prefixes, supervising only the last
assistant in each prefix (including tool calls). Never truncate a completion.
"""
from __future__ import annotations

import argparse
from array import array
from collections import Counter
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import sys
import time
import math
from datetime import datetime
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import model_profile
import memory_budget


def write_json(path, value):
    path = Path(path)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n')
    temporary.replace(path)


def kst_now():
    return datetime.now(ZoneInfo('Asia/Seoul')).isoformat()


def read_config(path):
    path = Path(path).resolve()
    config = json.loads(path.read_text(encoding="utf-8"))
    for key in ("data_dir", "output_dir"):
        p = Path(config[key])
        config[key] = str(p if p.is_absolute() else path.parent / p)
    for key in ("max_length", "per_device_train_batch_size", "gradient_accumulation_steps", "lora_r"):
        if not isinstance(config[key], int) or config[key] <= 0:
            raise ValueError(f"{key} must be a positive integer")
    if not config.get("model_name_or_path") or not config.get("target_modules"):
        raise ValueError("Specify a base model and explicit LoRA target_modules")
    if config.get("enable_thinking") is not False:
        raise ValueError("This prepared corpus uses non-thinking targets; enable_thinking must be false")
    model_profile.validate_profile(config)
    return config


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_data(config):
    root = Path(config["data_dir"])
    counts, hashes = {}, {}
    if not (root / "manifest.json").is_file():
        raise ValueError("Prepared data/manifest.json is missing. Run prepare_data.py first.")
    manifest = json.loads((root / "manifest.json").read_text())
    outputs = manifest.get("outputs", {})
    for split in ("train", "validation", "test"):
        path = root / f"{split}.jsonl"
        if not path.is_file():
            raise ValueError(f"Missing {path.name}")
        hashes[split] = sha256_file(path)
        expected = outputs.get(split, {})
        if not expected.get("sha256") or expected["sha256"] != hashes[split]:
            raise ValueError(f"{split} checksum does not match manifest")
        n = 0
        with path.open(encoding="utf-8") as handle:
            for n, line in enumerate(handle, 1):
                row = json.loads(line)
                messages = row.get("messages")
                if not messages or messages[-1].get("role") != "assistant":
                    raise ValueError(f"{split}:{n}: final assistant target missing")
        if not n:
            raise ValueError(f"{split} is empty")
        counts[split] = n
        if expected.get("records") != n:
            raise ValueError(f"{split} count does not match manifest")
    return {"records": counts, "sha256": hashes, "model": config["model_name_or_path"]}


def encode_completion(row, tokenizer, max_length):
    """Template-prefix alignment prevents accidentally supervising input tokens."""
    messages = row["messages"]
    if len(messages) < 2 or messages[-1].get("role") != "assistant":
        return None, "missing_assistant_target"
    kwargs = {"tokenize": False, "add_generation_prompt": False, "enable_thinking": False}
    if row.get("tools"):
        kwargs["tools"] = row["tools"]
    prompt_text = tokenizer.apply_chat_template(messages[:-1], **kwargs)
    full_text = tokenizer.apply_chat_template(messages, **kwargs)
    if not full_text.startswith(prompt_text):
        return None, "template_prefix_mismatch"
    prompt_ids = tokenizer.encode(prompt_text, add_special_tokens=False)
    ids = tokenizer.encode(full_text, add_special_tokens=False)
    if ids[:len(prompt_ids)] != prompt_ids:
        return None, "token_prefix_mismatch"
    if len(ids) > max_length:
        return None, "over_max_length"
    if len(ids) <= len(prompt_ids):
        return None, "empty_target"
    return {"input_ids": array("i", ids), "prompt_length": len(prompt_ids)}, None


def tokenize_split(path, tokenizer, max_length, limit):
    """Expand each dialogue into one completion example per assistant turn.

    Earlier assistant/tool turns remain masked context in later examples. Each
    prefix remains in its source dialogue's split. Limits count accepted prefixes,
    and length filtering rejects a whole prefix rather than cutting a tool call.
    """
    rows, stats = [], Counter()
    with Path(path).open(encoding="utf-8") as handle:
        for line in handle:
            if limit > 0 and len(rows) >= limit:
                break
            stats["read"] += 1
            source = json.loads(line)
            for index, message in enumerate(source["messages"]):
                if limit > 0 and len(rows) >= limit:
                    break
                if message.get("role") != "assistant":
                    continue
                stats["candidate_turns"] += 1
                prefix = {**source, "messages": source["messages"][:index + 1]}
                encoded, reason = encode_completion(prefix, tokenizer, max_length)
                if reason:
                    stats[reason] += 1
                    continue
                stats["kept"] += 1
                stats["tokens"] += len(encoded["input_ids"])
                stats["supervised_tokens"] += len(encoded["input_ids"]) - encoded["prompt_length"]
                rows.append(encoded)
    if not rows:
        raise ValueError(f"No usable examples in {Path(path).name}: {dict(stats)}")
    # A template mismatch indicates implementation/model incompatibility, not bad data.
    if stats["template_prefix_mismatch"] or stats["token_prefix_mismatch"]:
        raise ValueError(f"Chat template prefix mismatch: {dict(stats)}")
    return rows, dict(stats)


def collate_lists(features, pad_token_id):
    width = max(len(item["input_ids"]) for item in features)
    batch = {"input_ids": [], "attention_mask": [], "labels": []}
    for item in features:
        ids = list(item["input_ids"])
        pad = width - len(ids)
        boundary = item["prompt_length"]
        batch["input_ids"].append(ids + [pad_token_id] * pad)
        batch["attention_mask"].append([1] * len(ids) + [0] * pad)
        batch["labels"].append([-100] * boundary + ids[boundary:] + [-100] * pad)
    return batch


def preflight(config=None):
    config = config or {}
    quantized = config.get("quantization", "nf4") == "nf4"
    if platform.system() != "Linux":
        raise RuntimeError("Training requires the target Linux NVIDIA GPU environment; macOS is excluded.")
    import torch
    if not torch.cuda.is_available():
        raise RuntimeError("CUDA GPU not available. Check the GPU driver and CUDA-enabled PyTorch.")
    if torch.cuda.device_count() != 1:
        raise RuntimeError("Expose exactly one GPU with CUDA_VISIBLE_DEVICES=<index> for this single-GPU recipe.")
    if int(os.environ.get("WORLD_SIZE", "1")) != 1:
        raise RuntimeError("This recipe targets one sufficiently large GPU. Multi-GPU/FSDP requires a separate configuration.")
    names = ["torch", "transformers", "peft", "accelerate"] + (["bitsandbytes"] if quantized else [])
    packages = {name: importlib.metadata.version(name) for name in names}
    model_profile.model_class(config)  # Fail before downloading weights when the installed loader is unsupported.
    props = torch.cuda.get_device_properties(0)
    # Exercise forward and backward, not just device discovery or an SM list.
    sample = torch.randn(32, 32, device="cuda", dtype=torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16, requires_grad=True)
    (sample @ sample.T).float().square().mean().backward()
    torch.cuda.synchronize()
    if not torch.isfinite(sample.grad).all():
        raise RuntimeError("CUDA forward/backward kernel test failed")
    if quantized:
        from bitsandbytes.functional import quantize_4bit, dequantize_4bit
        quant, state = quantize_4bit(sample.detach(), quant_type="nf4")
        if not torch.isfinite(dequantize_4bit(quant, state)).all():
            raise RuntimeError("bitsandbytes NF4 kernel test failed")
    mem = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key, value = line.split(':', 1)
        if key in ('MemAvailable', 'MemTotal'): mem[key] = int(value.split()[0]) * 1024 / 2**30
    cuda_free, cuda_total = torch.cuda.mem_get_info()
    hardware = {"packages": packages, "gpu": props.name, "gpu_memory_gib": round(props.total_memory / 2**30, 2),
            "cuda": torch.version.cuda, "bf16_supported": torch.cuda.is_bf16_supported(),
            "nf4_kernel": "passed" if quantized else "not_used", "cuda_forward_backward": "passed",
            "platform": platform.machine(), "compute_capability": list(torch.cuda.get_device_capability()),
            "system_memory_gib": round(mem['MemTotal'], 2)}
    hardware.update(memory_budget.budget(mem['MemAvailable'], cuda_free / 2**30, cuda_total / 2**30,
        platform.machine(), torch.cuda.get_device_capability(), memory_budget.cgroup_headroom()))
    try:
        model_profile.check_training_capacity(config, hardware)
        hardware['capacity_check'] = 'passed_planning_floor_not_peak_memory_guarantee'
    except RuntimeError as exc:
        hardware['capacity_check'] = str(exc)
    return hardware


def prepare_tokens(config, output, include_test=False):
    """Use the actual pinned tokenizer without allocating model weights or CUDA."""
    from transformers import AutoConfig, AutoTokenizer
    load_args = {"revision": config["revision"], "trust_remote_code": False, "local_files_only": config["offline"]}
    base_config = AutoConfig.from_pretrained(config["model_name_or_path"], **load_args)
    model_profile.validate_model_config(config, base_config)
    tokenizer = AutoTokenizer.from_pretrained(config["model_name_or_path"], **load_args)
    if not tokenizer.chat_template:
        raise ValueError("Base tokenizer must provide a chat template")
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"
    datasets, stats = {}, {}
    splits = ('train', 'validation', 'test') if include_test else ('train', 'validation')
    for split in splits:
        limit = config['max_train_samples'] if split == 'train' else config['max_eval_samples']
        datasets[split], stats[split] = tokenize_split(Path(config['data_dir']) / f'{split}.jsonl',
            tokenizer, config['max_length'], limit)
        # A standalone audit must not retain a complete unused test dataset.
        if include_test: datasets[split] = None
    stats.update(loss='each_assistant_turn_as_completion',
                 truncation='disabled; overlength prefixes rejected', checked_at_kst=kst_now())
    write_json(Path(output) / 'tokenization_report.json', stats)
    print(json.dumps(stats, ensure_ascii=False, indent=2), flush=True)
    return tokenizer, datasets


def tokenize_only(config, checks):
    output = Path(config['output_dir'])
    if output.exists() and any(output.iterdir()):
        raise ValueError('Output directory is not empty')
    output.mkdir(parents=True, exist_ok=True)
    prepare_tokens(config, output, include_test=True)
    write_json(output / 'data_check.json', checks)


def run_training(config, checks, hardware):
    os.environ.setdefault("HF_HOME", str(ROOT / ".cache" / "huggingface"))
    os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
    os.environ["TOKENIZERS_PARALLELISM"] = "false"
    import torch
    from transformers import BitsAndBytesConfig, Trainer, TrainerCallback, TrainingArguments, set_seed
    model_profile.check_training_capacity(config, hardware)
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    output = Path(config["output_dir"])
    if output.exists() and any(output.iterdir()):
        raise ValueError("Output directory is not empty. Select a new --output-dir for this run.")
    output.mkdir(parents=True, exist_ok=True)
    set_seed(config["seed"])
    load_args = {"revision": config["revision"], "trust_remote_code": False, "local_files_only": config["offline"]}
    write_json(output / 'progress.json', {'status':'tokenizing', 'at_kst':kst_now()})
    tokenizer, datasets = prepare_tokens(config, output)
    train, val = datasets['train'], datasets['validation']
    # Tokenization takes time; recheck competing allocations immediately before loading.
    hardware = preflight(config)
    model_profile.check_training_capacity(config, hardware)
    write_json(output / 'progress.json', {'status':'loading_model', 'at_kst':kst_now()})
    torch.cuda.reset_peak_memory_stats()
    dtype = torch.bfloat16 if hardware["bf16_supported"] else torch.float16
    quantized = config.get("quantization", "nf4") == "nf4"
    model_args = model_profile.loading_kwargs(config)
    if quantized:
        model_args['quantization_config'] = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_use_double_quant=True, bnb_4bit_compute_dtype=dtype)
    model = model_profile.model_class(config).from_pretrained(config["model_name_or_path"], **load_args, torch_dtype=dtype,
        **model_args, device_map={"": 0}, attn_implementation="sdpa")
    model.config.use_cache = False
    if hasattr(model.config, 'text_config'): model.config.text_config.use_cache = False
    coverage = model_profile.check_lora_targets(config, model.named_modules())
    if quantized:
        model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True,
            gradient_checkpointing_kwargs={"use_reentrant": False})
    else:
        # Preserve frozen BF16 MoE weights: k-bit preparation can upcast them to FP32.
        model.requires_grad_(False)
        model.enable_input_require_grads()
    lora = LoraConfig(task_type="CAUSAL_LM", r=config["lora_r"], lora_alpha=config["lora_alpha"],
        lora_dropout=config["lora_dropout"], target_modules=config["target_modules"], bias="none")
    model = get_peft_model(model, lora)
    model_profile.check_trainable_scope(config, model.named_parameters())
    model.print_trainable_parameters()
    args = TrainingArguments(output_dir=str(output), num_train_epochs=config["num_train_epochs"], max_steps=config["max_steps"],
        per_device_train_batch_size=config["per_device_train_batch_size"], per_device_eval_batch_size=1,
        gradient_accumulation_steps=config["gradient_accumulation_steps"], learning_rate=config["learning_rate"],
        lr_scheduler_type="cosine", warmup_ratio=config["warmup_ratio"], optim="paged_adamw_8bit" if quantized else "adamw_torch",
        logging_steps=config["logging_steps"], eval_strategy="steps", eval_steps=config["eval_steps"],
        save_strategy="steps", save_steps=config["save_steps"], save_total_limit=config["save_total_limit"],
        bf16=hardware["bf16_supported"], fp16=not hardware["bf16_supported"], gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False}, max_grad_norm=1.0, seed=config["seed"], data_seed=config["seed"],
        report_to=[], push_to_hub=False, remove_unused_columns=False, label_names=["labels"],
        prediction_loss_only=True, dataloader_num_workers=0, disable_tqdm=True,
        logging_first_step=True, logging_nan_inf_filter=False)

    def collator(features):
        return {key: torch.tensor(value, dtype=torch.long) for key, value in collate_lists(features, tokenizer.pad_token_id).items()}

    metadata = {"config": config, "data": checks, "hardware": hardware, "base_revision_resolved": getattr(model.config, "_commit_hash", None),
                "tokenizer_class": type(tokenizer).__name__, "lora_coverage": coverage, "trainable_parameters": sum(p.numel() for p in model.parameters() if p.requires_grad)}
    (output / "run_manifest.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n")
    class Progress(TrainerCallback):
        def __init__(self):
            self.started = time.monotonic()
            self.metrics = {}

        def record(self, state, status):
            elapsed = time.monotonic() - self.started
            write_json(output / 'progress.json', {'status':status, 'at_kst':kst_now(),
                'step':state.global_step, 'max_steps':state.max_steps, 'epoch':state.epoch,
                'elapsed_seconds':round(elapsed, 2),
                'estimated_remaining_seconds':round(elapsed / state.global_step * (state.max_steps-state.global_step), 1) if state.global_step else None,
                'peak_cuda_allocated_gib':round(torch.cuda.max_memory_allocated()/2**30, 2),
                'peak_cuda_reserved_gib':round(torch.cuda.max_memory_reserved()/2**30, 2),
                'metrics':self.metrics})

        def on_step_end(self, args, state, control, **kwargs): self.record(state, 'training')

        def on_log(self, args, state, control, logs=None, **kwargs):
            self.metrics.update(logs or {})
            for key, value in (logs or {}).items():
                if isinstance(value, (float, int)) and not math.isfinite(value):
                    raise RuntimeError('Nonfinite training metric: '+key)
            self.record(state, 'training')

    progress = Progress()
    trainer = Trainer(model=model, args=args, train_dataset=train, eval_dataset=val, data_collator=collator,
                      processing_class=tokenizer, callbacks=[progress])
    result = trainer.train()
    trainer.save_model(str(output / "adapter"))
    tokenizer.save_pretrained(str(output / "adapter"))
    trainer.save_metrics("train", result.metrics)
    trainer.save_metrics("eval", trainer.evaluate())
    trainer.save_state()
    progress.record(trainer.state, 'completed')
    print(f"Saved adapter and tokenizer to {output / 'adapter'}. Requires the original base model. No upload performed.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "config.json")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true", help="Verify prepared data using stdlib only; no downloads")
    action.add_argument("--preflight", action="store_true", help="Check target GPU/packages/NF4 kernel; no model downloads")
    action.add_argument("--tokenize-only", action="store_true", help="Audit all splits with the real tokenizer; no model/GPU allocation")
    action.add_argument("--train", action="store_true", help="Explicitly start GPU training (only on the training machine)")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--max-steps", type=int)
    parser.add_argument("--max-length", type=int)
    parser.add_argument("--max-train-samples", type=int)
    parser.add_argument("--max-eval-samples", type=int)
    parser.add_argument("--offline", action="store_true")
    opts = parser.parse_args()
    try:
        config = read_config(opts.config)
        for key in ("output_dir", "max_steps", "max_length", "max_train_samples", "max_eval_samples"):
            value = getattr(opts, key)
            if value is not None:
                config[key] = str(value.resolve()) if isinstance(value, Path) else value
        if config["max_length"] < 32 or config["max_train_samples"] < 0 or config["max_eval_samples"] < 0:
            raise ValueError("Invalid length or sample limits")
        config["offline"] = config["offline"] or opts.offline
        if opts.preflight:
            print(json.dumps(preflight(config), indent=2))
        else:
            checks = check_data(config)
            if opts.check:
                print(json.dumps(checks, indent=2))
                print("Data/configuration check passed. No model was loaded or trained.")
            elif opts.tokenize_only:
                tokenize_only(config, checks)
            else:
                run_training(config, checks, preflight(config))
    except (ValueError, RuntimeError, ImportError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
