#!/bin/bash
# Synthetic native VRL validation only. No production source or output paths.
set -euo pipefail
[[ $# == 0 && $(uname -s) == Linux ]] || exit 64
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
export VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true
export CAPSTONE_SENSOR=synthetic-a
export WAF_AUDIT_PATH=/synthetic/audit.log
export WAF_INSTANCE_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export WAF_CONFIG_SHA256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
export WAF_DEPLOYMENT_BINDING=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
exec /usr/local/bin/vector test tests-context.toml
