#!/usr/bin/env python3
"""Create a portable training bundle from an explicit file allowlist (no weights/secrets)."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile

from train import ROOT, check_data, read_config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "bundles" / "soc-finetuning.tar.gz")
    parser.add_argument("--config", type=Path, default=ROOT / "config.json")
    opts = parser.parse_args()
    config_path = opts.config.resolve()
    if config_path.parent != ROOT or config_path.name not in ('config.json', 'config.qwen36-thor.json','config.qwen36-soc.json','config.qwen36-soc-main.json','config.qwen36-soc-v2.json'):
        parser.error("Choose one of the bundled model profiles")
    raw = json.loads(config_path.read_text(encoding="utf-8"))
    if any(Path(raw[key]).is_absolute() for key in ("data_dir", "output_dir")):
        parser.error("Use relative data_dir/output_dir paths for a portable bundle")
    config = read_config(config_path)
    if Path(config["data_dir"]).resolve() not in (ROOT / "data", ROOT / "data-soc-v1", ROOT / "data-soc-v2-r2"):
        parser.error("Portable bundle requires one of the fixed prepared datasets")
    if not Path(config["output_dir"]).resolve().is_relative_to(ROOT):
        parser.error("Portable bundle requires an output_dir inside finetuning/")
    check_data(config)
    names = [".gitignore", "README.md", "DATA_SOURCES.md", "config.json", "requirements.txt",
             "setup_gpu.sh", "prepare_data.py", "train.py", "merge_adapter.py", "merge_streaming.py", "evaluate.py",
             "pack.py", "model_profile.py", "config.qwen36-thor.json", "requirements.qwen36-thor.txt",
             "setup_thor.sh", "THOR_35B.md", "audit_tools.py", "mcp_contract.json",
             "container_task.py", "thor_container.py", "memory_budget.py", "download_model.py", "guarded_process.py", "bounded_loading.py",
             "soc_dataset.py", "soc_curriculum.py", "soc_evaluate.py", "soc_assessment.py", "training_window.py", "reference_model.py", "register_soc.py", "convert_reference.py", "convert_soc.py", "config.qwen36-soc.json", "config.qwen36-soc-main.json", "config.qwen36-soc-v2.json", "config.foundation-sec-8b.json",
             "preparation_summary.json", "data/manifest.json",
             "data/train.jsonl", "data/validation.jsonl", "data/test.jsonl"]
    if config_path.name in ('config.qwen36-soc.json','config.qwen36-soc-main.json'):
        names += ['data-soc-v1/'+name for name in ('train.jsonl','validation.jsonl','test.jsonl','manifest.json')]
        names += ['data-soc-source-v1/cases.jsonl']
    if config_path.name == 'config.qwen36-soc-v2.json':
        names += ['data-soc-v2-r2/'+name for name in ('train.jsonl','validation.jsonl','test.jsonl','manifest.json','curriculum-audit.json')]
        names += ['data-soc-source-v2-r2/cases.jsonl']
    paths = [ROOT / name for name in names] + sorted((ROOT / "tests").glob("test_*.py"))
    for path in paths:
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(ROOT):
            parser.error(f"Missing or unsafe bundle input: {path.relative_to(ROOT)}")
    output = opts.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation prevents overwriting an earlier handoff.
    with output.open("xb") as handle, tarfile.open(fileobj=handle, mode="w:gz") as archive:
        for path in paths:
            archive.add(path, arcname=str(Path("finetuning") / path.relative_to(ROOT)), recursive=False)
    digest = hashlib.sha256()
    with output.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    print(f"{output}\nSHA256 {digest.hexdigest()}")


if __name__ == "__main__":
    main()
