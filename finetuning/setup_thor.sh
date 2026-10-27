#!/usr/bin/env bash
set -euo pipefail
TASK_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$(uname -s)" != Linux || "$(uname -m)" != aarch64 ]]; then
  echo "Use the Thor Linux aarch64 training environment; no Mac installation." >&2
  exit 1
fi
PYTHON_BIN="${PYTHON_BIN:-python3}"
export PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
export HF_HUB_DISABLE_TELEMETRY=1
export HF_HOME="$TASK_DIR/.cache/huggingface"
# A generic x86 CUDA wheel is not a Thor build. Validate the selected vendor
# Python before creating anything; do not alter the host Python or Ollama.
"$PYTHON_BIN" -B - <<'PY'
import sys, torch
assert (3,10) <= sys.version_info[:2] <= (3,12), 'Use Python 3.10-3.12'
assert torch.cuda.is_available() and torch.cuda.device_count() == 1, 'Expose one CUDA GPU'
assert torch.cuda.get_device_capability() == (11,0), 'Expected Thor SM110'
assert torch.cuda.is_bf16_supported(), 'BF16 required'
x = torch.randn(32,32,device='cuda',dtype=torch.bfloat16,requires_grad=True)
(x @ x.T).float().square().mean().backward()
torch.cuda.synchronize()
assert torch.isfinite(x.grad).all(), 'CUDA BF16 forward/backward failed'
PY
if [[ -e "$TASK_DIR/.venv-qwen36-thor" ]]; then
  echo "Existing .venv-qwen36-thor found; preserve it and inspect before retrying." >&2
  exit 1
fi
"$PYTHON_BIN" -m venv --system-site-packages "$TASK_DIR/.venv-qwen36-thor"
TASK_PYTHON="$TASK_DIR/.venv-qwen36-thor/bin/python"
"$TASK_PYTHON" -B - "$TASK_DIR/.venv-qwen36-thor/vendor-constraints.txt" <<'PY'
import importlib.metadata as md, sys
from pathlib import Path
pins = []
for name in ('torch','torchvision','torchaudio'):
    try: pins.append(name + '==' + md.version(name))
    except md.PackageNotFoundError: pass
Path(sys.argv[1]).write_text('\n'.join(pins) + '\n')
PY
"$TASK_PYTHON" -m pip install -c "$TASK_DIR/.venv-qwen36-thor/vendor-constraints.txt" -r "$TASK_DIR/requirements.qwen36-thor.txt"
"$TASK_PYTHON" -m pip check
"$TASK_PYTHON" -B "$TASK_DIR/train.py" --config "$TASK_DIR/config.qwen36-thor.json" --preflight
echo "Dependencies checked. Review capacity_check before training; no model download or training performed."
