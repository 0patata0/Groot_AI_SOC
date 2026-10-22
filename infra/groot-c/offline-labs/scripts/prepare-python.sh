#!/usr/bin/env bash
# Connected preparation machine, Python 3.12 + an existing pip required.
# DOWNLOAD ONLY: do not install server dependencies on the administrator's Mac.
# Use the exact checked-in Linux amd64 / CPython 3.12 wheel inventory.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
[[ $# == 1 ]] || { echo 'usage: prepare-python.sh NEW_WHEEL_DIRECTORY' >&2; exit 2; }
ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -m 700 -- "$1"
python3 -m pip --disable-pip-version-check --no-cache-dir download \
  --only-binary=:all: --platform manylinux2014_x86_64 --python-version 3.12 \
  --implementation cp --abi cp312 --dest "$1" -r "$ROOT/requirements.lock"
python3 -B - "$ROOT/wheel-inventory.json" "$1" <<'PY'
from pathlib import Path
import hashlib,json,sys
for r in json.loads(Path(sys.argv[1]).read_text()):
 if hashlib.sha256((Path(sys.argv[2])/r['file']).read_bytes()).hexdigest()!=r['sha256']:
  raise ValueError('Wheel checksum mismatch: '+r['file'])
print('All wheel checksums match the reviewed inventory.')
PY
