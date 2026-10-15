#!/usr/bin/env bash
set -euo pipefail
umask 077
stage=${1:?stage}; role=${2:?role}; action=${3:?action}
[[ $# == 3 && $stage =~ ^/var/tmp/capstone-bootstrap-[0-9a-f]{24}$ ]] || exit 64
[[ $role == security || $role == siem || $role == service ]] || exit 64
[[ $action == check || $action == apply || $action == verify ]] || exit 64
[[ $(id -u) == 0 && -d $stage && ! -L $stage ]] || exit 77
for path in "$stage" "$stage/site.env" "$stage/source.tar" "$stage/source"; do
  [[ ! -L $path && $(stat -c %u "$path") == 0 ]] || { echo 'unsafe staging ownership' >&2; exit 77; }
done
source "$stage/site.env"
export TZ=Asia/Seoul
[[ $CAPSTONE_ROOT == /opt/capstone && $CAPSTONE_RELEASE =~ ^[0-9a-f]{64}$ ]] || exit 64
actual=$(sha256sum "$stage/source.tar"); actual=${actual%% *}
[[ $actual == "$CAPSTONE_RELEASE" ]] || { echo 'payload checksum mismatch' >&2; exit 65; }
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo 'Ubuntu 24.04 amd64 required' >&2; exit 69; }
source /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 ]] || { echo 'Ubuntu 24.04 required' >&2; exit 69; }
for tool in bash python3 docker systemctl flock curl openssl jq tar sha256sum; do
  command -v "$tool" >/dev/null || { printf 'missing package command: %s (README)\n' "$tool" >&2; exit 69; }
done
systemctl is-system-running >/dev/null 2>&1 || [[ $(systemctl is-system-running) == degraded ]] || { echo 'running systemd required' >&2; exit 69; }
docker info >/dev/null 2>&1 || { echo 'Docker daemon unavailable' >&2; exit 69; }
docker compose version >/dev/null || exit 69
export CAPSTONE_SOURCE=$stage/source
if [[ $action == apply ]]; then
  exec 9>/run/lock/capstone-bootstrap.lock
  flock -n 9 || { echo 'another deployment holds the host lock' >&2; exit 75; }
  [[ ! -L $CAPSTONE_ROOT ]] || exit 77
  if [[ -e $CAPSTONE_ROOT/role && $(cat "$CAPSTONE_ROOT/role") != "$role" ]]; then
    echo 'host already assigned to a different role' >&2; exit 78
  fi
  # Check before creating persistent deployment state.
  bash "$CAPSTONE_SOURCE/deployment/roles/$role.sh" check
  install -d -m 0700 "$CAPSTONE_ROOT/releases"
  release=$CAPSTONE_ROOT/releases/$CAPSTONE_RELEASE
  if [[ ! -d $release ]]; then
    mkdir -m 0700 "$release"
    tar --no-same-owner -xf "$stage/source.tar" -C "$release"
    chmod -R go-w "$release"
  fi
  export CAPSTONE_SOURCE=$release
  printf '%s\n' "$role" > "$CAPSTONE_ROOT/role"
fi
printf '[%s] %s\n' "$role" "$action"
bash "$CAPSTONE_SOURCE/deployment/roles/$role.sh" "$action"
