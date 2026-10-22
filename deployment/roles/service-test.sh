#!/usr/bin/env bash
# Pure schema7 gateway/catalog/lifecycle tests. No host service, Docker or HTTP.
set -euo pipefail
exec python3 -B "$(dirname "$0")/../test_offline_service.py"
