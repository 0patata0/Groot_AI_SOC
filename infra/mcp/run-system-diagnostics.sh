#!/bin/sh
# The readonly router receives no Wazuh, broker, model or user environment.
set -eu
[ "$#" -eq 0 ] || exit 2
exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/nonexistent \
  PYTHONDONTWRITEBYTECODE=1 LANG=C LC_ALL=C \
  /usr/bin/python3 -I -B /opt/mcp/system-diagnostics-mcp.py
