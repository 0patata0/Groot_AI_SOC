#!/bin/sh
# Fixed root operator helper invoked by the local Ansible playbook only.
set -eu
[ "$(id -u)" -eq 0 ] || exit 77
[ "$#" -eq 1 ] || exit 64
case "$1" in check|apply) operation=$1 ;; *) exit 64 ;; esac
project=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
manifest=$project/deployment.json
candidate=$project/zz-capstone-evidence.conf
[ "$(cat /etc/machine-id)" = "$(jq -r .machine_id "$manifest")" ] || exit 77
instance=$(jq -er .instance_id "$manifest")
expected=$(jq -er .configuration_sha256 "$manifest")
original=$(jq -er .existing_nginx_digest "$manifest")
rules=$(jq -er .custom_rules_sha256 "$manifest")
binding=$(jq -er .deployment_binding "$manifest")
for hash in "$instance" "$expected" "$original" "$rules" "$binding"; do
  [ "${#hash}" -eq 64 ] || exit 77
  case "$hash" in *[!0-9a-f]*) exit 77 ;; esac
done
[ "$(sha256sum "$candidate" | awk '{print $1}')" = "$expected" ] || exit 77
DOCKER=/usr/local/bin/docker
[ "$($DOCKER inspect --format '{{.Id}}' waf)" = "$instance" ] || exit 77
container_stage=$($DOCKER exec -u 0 "$instance" mktemp -d /tmp/capstone-waf-deploy.XXXXXX)
case "$container_stage" in /tmp/capstone-waf-deploy.*) ;; *) exit 77 ;; esac
result_file=$(mktemp /var/lib/capstone-automation/ansible/tmp/waf-producer.XXXXXX)
cleanup() {
  $DOCKER exec -u 0 "$instance" rm -rf -- "$container_stage" >/dev/null 2>&1 || true
  rm -f "$result_file"
}
trap cleanup EXIT INT TERM
$DOCKER exec -u 0 "$instance" chown 0:101 "$container_stage"
$DOCKER exec -u 0 "$instance" chmod 750 "$container_stage"
$DOCKER cp "$candidate" "$instance:$container_stage/candidate.conf" >/dev/null
$DOCKER exec -u 0 -i "$instance" sh -s -- "$operation" "$container_stage" "$expected" "$original" "$rules" >"$result_file" <<'INNER'
set -eu
umask 077
operation=$1; stage=$2; expected=$3; original=$4; rules=$5
target=/etc/nginx/conf.d/zz-capstone-evidence.conf
custom=/etc/modsecurity.d/owasp-crs/rules/REQUEST-948-GROOT_A_WAF.conf
audit=/var/log/modsecurity/audit.log
access=/var/log/modsecurity/capstone-access.log
installed=false
step=preflight
native_nginx() {
  # nginx log symlinks point to /dev/stdout and /dev/stderr. A UID switch
  # must retain writable test descriptors without changing operational logs.
  for native_stream_id in 1 2; do
    native_output_path=$(readlink "/proc/$$/fd/$native_stream_id")
    case "$native_output_path" in "$stage"/*) ;; *) return 77 ;; esac
    [ -f "$native_output_path" ] && [ ! -L "$native_output_path" ] || return 77
    chown 101:101 "$native_output_path"
  done
  setpriv --reuid 101 --regid 101 --clear-groups /usr/sbin/nginx "$@"
}
sha() { sha256sum "$1" | awk '{print $1}'; }
base_digest() { find /etc/nginx -type f ! -path "$target" -exec sha256sum {} \; | sort | sha256sum | awk '{print $1}'; }
metadata_digest() { find /etc/nginx -type f ! -path "$target" -exec stat -c '%n:%u:%g:%a:%h' {} \; | sort | sha256sum | awk '{print $1}'; }
check_master() { [ "$(cat /tmp/nginx.pid)" = "$master" ] && [ "$(awk '{print $22}' /proc/"$master"/stat)" = "$ticks" ]; }
has_access_fd() {
  # Container UID0 lacks CAP_SYS_PTRACE: inspect the writer's /proc FDs as
  # its own UID instead of silently treating EACCES as an absent log handle.
  setpriv --reuid 101 --regid 101 --clear-groups sh -s -- "$1" "$access" <<'FDPROBE'
set -eu
for access_fd in /proc/"$1"/fd/*; do
  [ "$(readlink "$access_fd" 2>/dev/null || true)" != "$2" ] || exit 0
done
exit 1
FDPROBE
}
producer_loaded() {
  has_access_fd "$master" || return 1
  for loaded_stat in /proc/[0-9]*/stat; do
    loaded_pid=$(awk -v parent="$master" '$4==parent{print $1}' "$loaded_stat" 2>/dev/null || true)
    if [ -n "$loaded_pid" ] && has_access_fd "$loaded_pid"; then return 0; fi
  done
  return 1
}
reload_verified() {
  reload_expectation=$1
  for proc in /proc/[0-9]*/stat; do awk -v parent="$master" '$4==parent{print $1}' "$proc" 2>/dev/null || true; done | sort >"$stage/children-before"
  native_nginx -s reload >"$stage/reload.log" 2>&1 || return 1
  reload_attempt=0
  while [ "$reload_attempt" -lt 50 ]; do
    check_master || return 1
    for proc in /proc/[0-9]*/stat; do awk -v parent="$master" '$4==parent{print $1}' "$proc" 2>/dev/null || true; done | sort >"$stage/children-after"
    if [ -n "$(comm -13 "$stage/children-before" "$stage/children-after")" ]; then
      if [ "$reload_expectation" = restored ] || producer_loaded; then return 0; fi
    fi
    sleep 0.1; reload_attempt=$((reload_attempt+1))
  done
  return 1
}

rollback() {
  status=$?
  if [ "$status" -ne 0 ]; then
    printf 'WAF producer step failed: %s (status %s)\n' "$step" "$status" >&2
    for log in "$stage"/*test.log "$stage"/reload.log; do
      [ ! -f "$log" ] || awk '/\[(emerg|alert)\]/{print; n++; if(n>=3)exit}' "$log" >&2
    done
  fi
  if [ "$status" -ne 0 ] && [ "$installed" = true ]; then
    if [ -f "$target" ] && [ ! -L "$target" ] && [ "$(sha "$target")" = "$expected" ]; then
      rm "$target"
      if native_nginx -t >"$stage/rollback-test.log" 2>&1 && reload_verified restored; then
        printf 'Producer failure: restored previous nginx configuration.\n' >&2
      else printf 'Producer failure: rollback validation/reload failed; operator intervention required.\n' >&2; fi
    else printf 'Producer failure: target changed concurrently; refused unsafe rollback.\n' >&2; fi
  fi
  exit "$status"
}
trap rollback EXIT
step=existing_configuration_digest
[ "$(base_digest)" = "$original" ]
step=custom_rules_digest
[ "$(sha "$custom")" = "$rules" ]
metadata=$(metadata_digest)
master=$(cat /tmp/nginx.pid)
ticks=$(awk '{print $22}' /proc/"$master"/stat)
# Already installed: require identical bytes and native configuration health.
if [ -e "$target" ] || [ -L "$target" ]; then
  [ -f "$target" ] && [ ! -L "$target" ] && [ "$(stat -c %h "$target")" -eq 1 ]
  [ "$(sha "$target")" = "$expected" ]
  [ "$(stat -c '%u:%g:%a' "$target")" = '0:0:644' ]
  native_nginx -t >"$stage/unchanged-test.log" 2>&1
  check_master
  if producer_loaded; then
    printf '{"changed":false,"configuration_verified":true,"master_unchanged":true,"producer_master_worker_fd_verified":true}\n'
  elif [ "$operation" = check ]; then
    printf '{"changed":false,"configuration_verified":true,"master_unchanged":true,"producer_master_worker_fd_verified":false,"reload_required":true}\n'
  else
    step=recover_interrupted_reload
    reload_verified producer
    printf '{"changed":true,"configuration_verified":true,"master_unchanged":true,"producer_master_worker_fd_verified":true,"interrupted_reload_recovered":true}\n'
  fi
  exit 0
fi
step=current_nginx_preflight
native_nginx -T >"$stage/active.conf" 2>"$stage/active-test.log"
step=existing_transaction_id_directive
[ "$(awk '/^[[:space:]]*modsecurity_transaction_id[[:space:]]/{n++}END{print n+0}' "$stage/active.conf")" -eq 0 ]
step=existing_include_directive
[ "$(awk '/include \/etc\/nginx\/conf.d\/\*\.conf;/{n++}END{print n+0}' /etc/nginx/nginx.conf)" -eq 1 ]
step=stage_configuration
cp -a /etc/nginx/. "$stage/"
cp "$stage/candidate.conf" "$stage/conf.d/zz-capstone-evidence.conf"
sed "s@include /etc/nginx/conf.d/\\*.conf;@include $stage/conf.d/*.conf;@" /etc/nginx/nginx.conf >"$stage/nginx.conf"
# Preserve an existing evidence file. Create an empty compatible one if absent.
if [ -e "$access" ] || [ -L "$access" ]; then
  [ -f "$access" ] && [ ! -L "$access" ] && [ "$(stat -c %h "$access")" -eq 1 ]
else
  # native_nginx -t also opens this output; pre-create with the actual writer owner.
  touch "$access"
  chown "$(stat -c '%u:%g' "$audit")" "$access"
  chmod 640 "$access"
fi
step=candidate_nginx_validation
find "$stage" -type d -exec chown 0:101 {} \; -exec chmod 750 {} \;
find "$stage" -type f -exec chown 0:101 {} \; -exec chmod 640 {} \;
native_nginx -p /etc/nginx/ -c "$stage/nginx.conf" -t >"$stage/candidate-test.log" 2>&1
[ "$(base_digest)" = "$original" ]
[ "$(metadata_digest)" = "$metadata" ]
[ "$(sha "$custom")" = "$rules" ]
check_master
[ "$(stat -c %d "$stage/candidate.conf")" = "$(stat -c %d /etc/nginx/conf.d)" ]
[ "$(sha "$stage/candidate.conf")" = "$expected" ]
[ "$(sha "$stage/conf.d/zz-capstone-evidence.conf")" = "$expected" ]
[ "$(stat -c '%u:%g:%a' "$stage/candidate.conf")" = '0:101:640' ]
if [ "$operation" = check ]; then
  printf '{"changed":false,"candidate_verified":true,"master_unchanged":true,"protected_candidate_verified":true,"same_filesystem_verified":true}\n'
  exit 0
fi
step=install_and_reload
[ "$(sha "$stage/candidate.conf")" = "$expected" ]
[ "$(sha "$stage/conf.d/zz-capstone-evidence.conf")" = "$expected" ]
[ "$(stat -c '%u:%g:%a' "$stage/candidate.conf")" = '0:101:640' ]
# Never create/follow a temporary path inside the nginx-writable conf.d.
# Link only the root-protected, validated source, atomically without replacing
# an existing target. Cleanup later removes the protected staging link.
chown 0:0 "$stage/candidate.conf"; chmod 644 "$stage/candidate.conf"
ln "$stage/candidate.conf" "$target"
installed=true
[ "$(sha "$target")" = "$expected" ]
native_nginx -t >"$stage/installed-test.log" 2>&1
reload_verified producer
[ "$(base_digest)" = "$original" ]
[ "$(metadata_digest)" = "$metadata" ]
[ "$(sha "$custom")" = "$rules" ]
check_master
printf '{"changed":true,"candidate_verified":true,"configuration_verified":true,"master_unchanged":true,"new_worker_observed":true,"producer_master_worker_fd_verified":true,"existing_configuration_unchanged":true,"custom_rules_unchanged":true}\n'
INNER
cat "$result_file"
