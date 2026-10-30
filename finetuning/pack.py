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
    if config_path.parent != ROOT or config_path.name not in ('config.json', 'config.qwen36-thor.json','config.qwen36-soc.json','config.qwen36-soc-main.json','config.qwen36-soc-v2.json','config.qwen36-soc-v3.json','config.qwen36-soc-v4.json','config.qwen36-soc-v4-full.json','config.qwen36-soc-v5.json'):
        parser.error("Choose one of the bundled model profiles")
    raw = json.loads(config_path.read_text(encoding="utf-8"))
    if any(Path(raw[key]).is_absolute() for key in ("data_dir", "output_dir")):
        parser.error("Use relative data_dir/output_dir paths for a portable bundle")
    config = read_config(config_path)
    if Path(config["data_dir"]).resolve() not in (ROOT / "data", ROOT / "data-soc-v1", ROOT / "data-soc-v2-r2", ROOT / "data-soc-operator-v3-r1", ROOT / "data-soc-operator-v4-r1", ROOT / "data-soc-evidence-v5-r3"):
        parser.error("Portable bundle requires one of the fixed prepared datasets")
    if not Path(config["output_dir"]).resolve().is_relative_to(ROOT):
        parser.error("Portable bundle requires an output_dir inside finetuning/")
    check_data(config)
    names = [".gitignore", "README.md", "DATA_SOURCES.md", "config.json", "requirements.txt",
             "prepare_ait_evidence.py", "AIT_EVIDENCE_REVIEW.json", "SOC_DATA_CANDIDATES.json",
             "link_ait_labels.py", "AIT_GAP_LINKAGE.json",
             "prepare_ait_case_review.py", "AIT_CASE_REVIEW.json", "SOC_SOURCE_ACCESS_REVIEW.json",
             "inspect_optc_evidence.py", "OPTC_EVIDENCE_REVIEW.json", "SOC_ADDITIONAL_DATA_REVIEW.json",
             "link_dedale_labels.py", "DEDALE_LINKAGE_REVIEW.json",
             "inspect_dedale_network.py", "DEDALE_CORRELATION_REVIEW.json",
             "compare_dedale_clocks.py", "DEDALE_CLOCK_REVIEW.json",
             "inspect_dedale_flows.py", "DEDALE_FLOW_REVIEW.json",
             "inspect_hornet.py", "HORNET_EVIDENCE_REVIEW.json", "SOC_EXTRA_CORPORA_REVIEW.json",
             "audit_beth_splits.py", "BETH_SPLIT_REVIEW.json",
             "prepare_linux_apt.py", "LINUX_APT_SOURCE_SPEC.json", "LINUX_APT_EVIDENCE_REVIEW.json",
             "prepare_linux_apt_cases.py", "LINUX_APT_CASE_REVIEW.json",
             "prepare_soc_observation_inputs.py", "check_soc_observation_tokens.py", "SOC_OBSERVATION_INPUT_REVIEW.json",
             "refine_soc_observation_targets.py", "SOC_OBSERVATION_TARGET_REVIEW.json",
             "audit_soc_observation_history.py", "SOC_OBSERVATION_GATE_REVIEW.json",
             "audit_cam_inputs.py", "CAM_INPUT_REVIEW.json",
             "prepare_cam_benchmark.py", "score_cam_benchmark.py", "check_cam_benchmark_tokens.py", "CAM_BENCHMARK_REVIEW.json",
             "prepare_soc_mixture.py", "check_soc_mixture_tokens.py", "SOC_MIXTURE_REVIEW.json",
             "evidence_groups.py", "cisa_tables.py", "prepare_evidence_v5.py", "audit_evidence_v5.py", "evaluate_evidence_v5.py", "evaluate_evidence_pair.py", "review_evidence_results.py", "verify_evidence_training.py", "V5_EVIDENCE_SPEC.json", "config.qwen36-soc-v5.json",
             "SOC_ROLE_MATRIX.json", "V4_DATA_PREPARATION.json", "V4_DATA_REVIEW.json", "V4_TRAINING_INPUTS.json", "V4_ASSESSMENT_POLICY.json", "config.qwen36-soc-v4.json", "config.qwen36-soc-v4-full.json", "SOURCE_EXPANSION.json", "dialogue_encoding.py", "remote_zip.py", "acquire_institutional.py", "institutional_sources.py", "prepare_institutional.py",
             "setup_gpu.sh", "prepare_data.py", "train.py", "merge_adapter.py", "merge_streaming.py", "evaluate.py",
             "pack.py", "model_profile.py", "config.qwen36-thor.json", "requirements.qwen36-thor.txt",
             "setup_thor.sh", "THOR_35B.md", "R2_RESULTS.md", "QUALITY_RESULTS.md", "TRAINING_PROVENANCE.json", "R3_DATA_PREPARATION.json", "references.bib", "audit_training_provenance.py", "audit_tools.py", "mcp_contract.json",
             "container_task.py", "thor_container.py", "memory_budget.py", "memory_telemetry.py", "completion_loss.py", "download_model.py", "guarded_process.py", "bounded_loading.py",
             "prepare_toolace.py", "prepare_soc_operator.py", "soc_operator_curriculum.py", "operator_rollout.py", "config.qwen36-soc-v3.json", "soc_dataset.py", "soc_curriculum.py", "soc_evaluate.py", "soc_assessment.py", "curriculum_assessment.py", "quality_assessment.py", "training_window.py", "reproduce_evaluation.py", "reproduce_training.py", "EVALUATION_REPRODUCTION.md", "V5_REPRODUCTION_RESULTS.json", "training_lineage.py", "reference_model.py", "register_soc.py", "convert_reference.py", "convert_soc.py", "config.qwen36-soc.json", "config.qwen36-soc-main.json", "config.qwen36-soc-v2.json", "config.foundation-sec-8b.json",
             "preparation_summary.json", "data/manifest.json",
             "data/train.jsonl", "data/validation.jsonl", "data/test.jsonl"]
    if config_path.name in ('config.qwen36-soc.json','config.qwen36-soc-main.json'):
        names += ['data-soc-v1/'+name for name in ('train.jsonl','validation.jsonl','test.jsonl','manifest.json')]
        names += ['data-soc-source-v1/cases.jsonl']
    if config_path.name == 'config.qwen36-soc-v2.json':
        names += ['data-soc-v2-r2/'+name for name in ('train.jsonl','validation.jsonl','test.jsonl','manifest.json','curriculum-audit.json')]
        names += ['data-soc-source-v2-r2/cases.jsonl']
    if config_path.name == 'config.qwen36-soc-v3.json':
        names += ['data-soc-operator-v3-r1/'+name for name in ('train.jsonl','validation.jsonl','test.jsonl','manifest.json','operator-audit.json')]
        names += ['data-soc-source-operator-v3-r1/cases.jsonl']
    if config_path.name in ('config.qwen36-soc-v4.json','config.qwen36-soc-v4-full.json'):
        names += ['SOC_ROLE_MATRIX.json','V4_DATA_PREPARATION.json','V4_TRAINING_INPUTS.json',
                  'V4_ASSESSMENT_POLICY.json','V4_DATA_REVIEW.json','SOURCE_EXPANSION.json','dialogue_encoding.py','remote_zip.py',
                  'acquire_institutional.py','institutional_sources.py','prepare_institutional.py',
                  'config.qwen36-soc-v4.json','config.qwen36-soc-v4-full.json']
        names += ['data-soc-operator-v4-r1/'+name for name in ('train.jsonl','validation.jsonl','test.jsonl','manifest.json','institutional-audit.json')]
        names += ['data-soc-source-operator-v4-r1/cases.jsonl',
                  'data-soc-operator-v3-r1/train.jsonl',
                  'data-soc-operator-v3-r1/validation.jsonl',
                  'data-soc-operator-v3-r1/test.jsonl',
                  'data-soc-source-operator-v3-r1/cases.jsonl']
        # Package exactly the frozen learning inputs. Raw remote archives/caches,
        # credentials and weights are never discovered recursively or bundled.
        frozen=json.loads((ROOT/'V4_TRAINING_INPUTS.json').read_text(encoding='utf-8'))
        expected={frozen['profile']:frozen['profile_sha256'],
                  frozen['source_cases']:frozen['source_cases_sha256'],
                  'mcp_contract.json':frozen['catalog_sha256'],
                  **frozen['source_sha256']}
        expected.update({frozen['data_folder']+'/'+split+'.jsonl':sha
                         for split,sha in frozen['data_sha256'].items()})
        for name,sha in expected.items():
            path=ROOT/name
            if path.is_symlink() or not path.resolve().is_relative_to(ROOT) or hashlib.sha256(path.read_bytes()).hexdigest()!=sha:
                parser.error('Frozen V4 input differs: '+name)
    if config_path.name == 'config.qwen36-soc-v5.json':
        names += ['V5_TRAINING_INPUTS.json','V5_TRAINING_INPUTS_R7.json','V5_DATA_PREPARATION.json','V5_EXECUTION_RESULTS.json','V5_COMPARISON.md','SOURCE_EXPANSION.json']
        names += ['data-soc-evidence-v5-r3/'+name for name in ('train.jsonl','validation.jsonl','test.jsonl','manifest.json',
                  'independent-source-audit.json','evidence-audit.json','MITRE-ATTACK-LICENSE.txt','SOURCE_ATTRIBUTION.json')]
        names += ['data-soc-source-evidence-v5-r3/cases.jsonl']
        frozen=json.loads((ROOT/'V5_TRAINING_INPUTS.json').read_text())
        expected={frozen['profile']:frozen['profile_sha256'],frozen['source_cases']:frozen['source_cases_sha256'],
                  'V5_EVIDENCE_SPEC.json':frozen['spec_file_sha256'],**frozen['source_sha256']}
        expected.update({frozen['data_folder']+'/'+s+'.jsonl':h for s,h in frozen['data_sha256'].items()})
        for name,digest in expected.items():
            path=ROOT/name
            if path.is_symlink() or not path.resolve().is_relative_to(ROOT) or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
                parser.error('Frozen V5 input differs: '+name)
    names += ['driver-diagnostics/'+name for name in ('README.md','NOTICE','check.py','elf_versions.py','manifest.json','gcc132-offline-manifest.json','nvidia-595.78-allocation.patch')]
    paths = [ROOT / name for name in dict.fromkeys(names)] + sorted((ROOT / "tests").glob("test_*.py"))
    for path in paths:
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(ROOT):
            parser.error(f"Missing or unsafe bundle input: {path.relative_to(ROOT)}")
    output = opts.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation prevents overwriting an earlier handoff.
    with output.open("xb") as handle, tarfile.open(fileobj=handle, mode="w:gz") as archive:
        for path in paths:
            archive.add(path, arcname=str(Path("finetuning") / path.relative_to(ROOT)), recursive=False)
        # Pure source projections are required by workflow regression tests.
        # These copies are evidence code, never installed as MCP services.
        for name in ('security-events-mcp.py','system-diagnostics-mcp.py','rule_change_executor.py'):
            path=ROOT.parent/'infra/mcp'/name
            if not path.is_file():path=ROOT/'contract_sources'/name
            if not path.is_file() or path.is_symlink():raise ValueError('Missing contract projection source')
            archive.add(path,arcname='finetuning/contract_sources/'+name,recursive=False)
    digest = hashlib.sha256()
    with output.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    print(f"{output}\nSHA256 {digest.hexdigest()}")


if __name__ == "__main__":
    main()
