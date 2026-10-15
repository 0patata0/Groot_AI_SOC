#!/bin/bash
# Stable manual entrypoint: strict CA/hostname + exact IDs/counts/shards verifier.
# One read-only attempt; a recent run may need another check after indexing.
set -euo pipefail
[[ $# == 1 && $1 =~ ^[0-9a-f]{32}$ ]] || exit 64
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
exec /bin/bash "$project_dir/history-replay-b/verify-retained-canary-b.sh" "$1"
