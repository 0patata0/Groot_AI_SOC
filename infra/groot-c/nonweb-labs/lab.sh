#!/usr/bin/env bash
# Fixed operator/peer-checked daemon entry point; no arbitrary Docker arguments.
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
[[ $EUID == 0 ]] || { printf '%s\n' 'root_required' >&2; exit 1; }
[[ $# == 2 || $# == 3 ]] || { printf '%s\n' 'usage: lab.sh check|up|status|logs|verify|reset|stop|down|getcontainer redis|samba [installed-image-id]' >&2; exit 1; }
exec /usr/bin/python3 -IB /opt/capstone-nonweb-labs/runtime.py "$@"
