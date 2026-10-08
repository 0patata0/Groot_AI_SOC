#!/bin/bash
# Run on Groot_B after the dedicated rule-approval broker is healthy locally.
set -euo pipefail
exec /bin/bash "$(dirname "${BASH_SOURCE[0]}")/deploy_rule_change_common.sh" b "$@"
