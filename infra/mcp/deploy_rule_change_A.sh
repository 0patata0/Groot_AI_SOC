#!/bin/bash
# Run on Groot_A after the dedicated rule-approval broker is healthy on B.
set -euo pipefail
exec /bin/bash "$(dirname "${BASH_SOURCE[0]}")/deploy_rule_change_common.sh" a "$@"
