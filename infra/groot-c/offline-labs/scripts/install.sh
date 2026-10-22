#!/usr/bin/env bash
# Read-only check or explicit first install; no apt/pip/pull or lab startup.
# Legacy positional WHEEL_DIRECTORY means --apply with loopback origins only.
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PYTHONDONTWRITEBYTECODE=1
umask 027
[[ ! -L "$0" ]] || { echo 'installer_symlink_rejected' >&2; exit 1; }
LAB_SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
exec /usr/bin/python3 -B "$LAB_SCRIPT_DIR/bootstrap.py" "$@"
