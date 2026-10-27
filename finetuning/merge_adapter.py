#!/usr/bin/env python3
"""Optionally merge a finished LoRA adapter into the exact base checkpoint.

Run on the training machine with sufficient RAM/VRAM. --check uses stdlib only.
This saves a Hugging Face model folder; it neither uploads nor converts to GGUF.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import model_profile


def inspect_adapter(adapter):
    adapter = Path(adapter).resolve()
    for name in ("adapter_config.json", "adapter_model.safetensors", "tokenizer_config.json"):
        if not (adapter / name).is_file():
            raise ValueError(f"Missing adapter file: {name}")
    manifest_path = adapter.parent / "run_manifest.json"
    if not manifest_path.is_file():
        raise ValueError("Keep the run_manifest.json beside the adapter folder to identify the exact base model")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    peft_config = json.loads((adapter / "adapter_config.json").read_text(encoding="utf-8"))
    base = manifest["config"]["model_name_or_path"]
    if peft_config.get("base_model_name_or_path") != base:
        raise ValueError("Adapter base model does not match run_manifest.json")
    revision = manifest.get("base_revision_resolved")
    if not revision and not Path(base).is_dir():
        raise ValueError("Exact base revision unavailable. Recover the original local base folder first.")
    return {"adapter": str(adapter), "base_model_name_or_path": base, "revision": revision, "training_config": manifest["config"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--device", choices=("cpu", "cuda:0"), default="cpu")
    parser.add_argument("--dtype", choices=("bfloat16", "float16"), default="bfloat16")
    parser.add_argument("--offline", action="store_true")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true", help="Check artifact metadata only; no model loading")
    action.add_argument("--merge", action="store_true", help="Load the full base model, merge and save shards")
    opts = parser.parse_args()
    try:
        info = inspect_adapter(opts.adapter)
        if opts.check:
            print(json.dumps(info, indent=2))
            return 0
        if opts.output is None:
            raise ValueError("--output is required with --merge")
        output = opts.output.resolve()
        if output.exists():
            raise ValueError("Output already exists; select a new directory")
        os.environ.setdefault("HF_HOME", str(ROOT / ".cache" / "huggingface"))
        os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
        import torch
        from transformers import AutoTokenizer
        from peft import PeftModel
        base = model_profile.model_class(info["training_config"]).from_pretrained(
            info["base_model_name_or_path"], revision=info["revision"],
            local_files_only=opts.offline, trust_remote_code=False,
            torch_dtype=getattr(torch, opts.dtype), device_map={"": opts.device},
            low_cpu_mem_usage=True,
        )
        # Reload the unquantized base: avoid merging into a lossy 4-bit checkpoint.
        model = PeftModel.from_pretrained(base, str(opts.adapter), is_trainable=False)
        model = model.merge_and_unload(safe_merge=True)
        model.config.use_cache = True
        if hasattr(model.config, "text_config"): model.config.text_config.use_cache = True
        model.save_pretrained(str(output), safe_serialization=True, max_shard_size="4GB")
        tokenizer = AutoTokenizer.from_pretrained(str(opts.adapter), local_files_only=True, trust_remote_code=False)
        tokenizer.save_pretrained(str(output))
        (output / "merge_manifest.json").write_text(
            json.dumps({**info, "dtype": opts.dtype, "format": "Hugging Face safetensors", "quantized": False}, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"Merged model saved to {output}. No upload performed.")
    except (ValueError, KeyError, RuntimeError, ImportError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
