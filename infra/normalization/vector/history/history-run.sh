#!/bin/bash
# Internal native worker. Not installed in a sudo rule or exposed through MCP.
set -euo pipefail
PATH=/usr/bin:/bin
export PATH
directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
source "$directory/history-lib.sh"
history_export_inner "$@"
