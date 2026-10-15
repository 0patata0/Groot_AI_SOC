#!/bin/bash
set -euo pipefail
[[ $EUID == 0 && $# -ge 4 && $1 == 10.200.10.1 && $2 == rsync && $3 == --server && $4 == --sender ]] || exit 64
exec /usr/bin/ssh -F /dev/null -T -l capstone-hist \
  -i /etc/capstone-history-transfer/id_ed25519 \
  -o IdentitiesOnly=yes -o BatchMode=yes -o PasswordAuthentication=no \
  -o KbdInteractiveAuthentication=no -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=/etc/capstone-history-transfer/known_hosts \
  -o GlobalKnownHostsFile=/dev/null -o HostKeyAlias=capstone-history-source-a \
  -o HostKeyAlgorithms=ssh-ed25519 -o UpdateHostKeys=no -o VerifyHostKeyDNS=no \
  -o ConnectTimeout=5 -o ConnectionAttempts=1 -o ServerAliveInterval=5 \
  -o ServerAliveCountMax=2 -o ClearAllForwardings=yes -o RequestTTY=no \
  -o LogLevel=ERROR -- "$@"
