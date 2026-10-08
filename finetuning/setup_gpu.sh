#!/usr/bin/env bash
set -euo pipefail
TASK_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$(uname -s)" != Linux ]]; then
  echo "Run setup on the Linux NVIDIA GPU training machine; this script does not install on macOS." >&2
  exit 1
fi
PYTHON_BIN="${PYTHON_BIN:-python3}"
"$PYTHON_BIN" -c 'import sys; assert (3,10) <= sys.version_info[:2] <= (3,12), "Use Python 3.10-3.12 (3.11 recommended)"'
if [[ -e "$TASK_DIR/.venv" ]]; then
  echo "Existing .venv found; use it or explicitly remove your old environment first." >&2
  exit 1
fi
case "${1:-}" in
  --use-system-torch)
    "$PYTHON_BIN" -c 'import torch; assert torch.cuda.is_available(), "Vendor/system PyTorch must support CUDA"'
    "$PYTHON_BIN" -m venv --system-site-packages "$TASK_DIR/.venv"
    ;;
  "")
    if [[ "$(uname -m)" != x86_64 ]]; then
      echo "For ARM64/DGX Spark, first use a compatible vendor CUDA PyTorch environment, then pass --use-system-torch." >&2
      exit 1
    fi
    "$PYTHON_BIN" -m venv "$TASK_DIR/.venv"
    ;;
  *) echo "Usage: bash setup_gpu.sh [--use-system-torch]" >&2; exit 2 ;;
esac
export PIP_CACHE_DIR="$TASK_DIR/.cache/pip"
export HF_HOME="$TASK_DIR/.cache/huggingface"
export HF_HUB_DISABLE_TELEMETRY=1
if [[ "${1:-}" != --use-system-torch ]]; then
  "$TASK_DIR/.venv/bin/python" -m pip install 'torch==2.8.0' --index-url https://download.pytorch.org/whl/cu128
fi
"$TASK_DIR/.venv/bin/python" -m pip install -r "$TASK_DIR/requirements.txt"
"$TASK_DIR/.venv/bin/python" -m pip check
"$TASK_DIR/.venv/bin/python" "$TASK_DIR/train.py" --preflight
echo "Environment ready. No model was downloaded and no training was started."
