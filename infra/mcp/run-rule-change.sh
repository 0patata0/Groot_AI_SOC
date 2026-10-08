#!/bin/bash
# Stdio-only entrypoint for the dedicated, unprivileged rule-change SSH user.
# Both sshd ForceCommand and authorized_keys force this exact program.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
exec /usr/bin/python3 /opt/rule-change/rule_change_mcp.py
