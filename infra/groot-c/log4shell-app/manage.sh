#!/usr/bin/env bash
# Existing C only. Never migrates, removes, pulls, builds, or modifies Apache.
set -euo pipefail
umask 077
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

ROOT=/opt/capstone-log4shell
PROJECT=capstone-log4shell
CONTAINER=log4shell-lab
SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
ACTION=${1:-help}
STAGE=

die(){ printf '%s\n' "$1" >&2; exit 1; }
usage(){
  cat <<'USAGE'
Usage: sudo bash manage.sh install|check|up|recreate|recover|verify|status
install requires LOG4SHELL_APP_JAR, LOG4SHELL_IMAGE (local sha256 image ID),
and LOG4SHELL_BIND_ADDRESS (private/loopback IPv4). Set LOG4SHELL_SOURCE_ROOT
when the repository root is not three directories above this script.
After install, use /opt/capstone-log4shell/manage.sh; the repository is not needed.
install only stages persistent files. up starts them; recreate replaces only the
verified managed container. Neither command adopts an existing unmanaged container.
recover explicitly repairs a missing/stale container-ID receipt only after the
full managed contract, mounted JAR bytes and real HTTP verification pass.
USAGE
}
[[ $# -le 1 ]] || die invalid_arguments
if [[ $ACTION == help || $ACTION == --help || $ACTION == -h ]]; then usage; exit 0; fi
[[ $ACTION =~ ^(install|check|up|recreate|recover|verify|status)$ ]] || die unknown_action
[[ $EUID == 0 && $(uname -s) == Linux ]] || die root_linux_required
for tool in docker python3 flock install mktemp sha256sum; do command -v "$tool" >/dev/null || die "missing_$tool"; done
DOCKER=$(command -v docker)
docker_local(){ env -i PATH="$PATH" HOME=/root "$DOCKER" --host unix:///var/run/docker.sock "$@"; }
compose(){ docker_local compose --project-name "$PROJECT" --project-directory "$ROOT" --env-file "$ROOT/managed.env" -f "$ROOT/compose.yaml" "$@"; }
contract(){ python3 -B "$ROOT/managed_contract.py" "$@"; }
container_id(){ docker_local container ls -a --no-trunc --filter "name=^/${CONTAINER}$" --format '{{.ID}}'; }
project_ids(){ docker_local container ls -a --no-trunc --filter "label=com.docker.compose.project=$PROJECT" --format '{{.ID}}'; }
cleanup(){ if [[ -n $STAGE && -d $STAGE ]]; then rm -rf -- "$STAGE"; fi; }
trap cleanup EXIT
python3 -B - <<'PY'
import os,pathlib,stat
root=pathlib.Path('/run/capstone-log4shell')
try: root.mkdir(mode=0o700)
except FileExistsError: pass
info=root.lstat()
assert stat.S_ISDIR(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o700
lock=root/'operation.lock'
try:
    fd=os.open(str(lock),os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    os.close(fd)
except FileExistsError: pass
info=lock.lstat()
assert stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600
PY
exec 9<>/run/capstone-log4shell/operation.lock
flock -n 9 || die management_operation_in_progress
docker_local info >/dev/null
docker_local compose version >/dev/null

check_files(){
  [[ -d $ROOT && ! -L $ROOT && -f $ROOT/manifest.json && ! -L $ROOT/managed_contract.py ]] || die installation_missing_or_incomplete
  # Authenticate the local validator before executing it; file ownership is the trust boundary.
  [[ $(stat -c '%u:%a' "$ROOT") == 0:700 && $(stat -c '%u:%a' "$ROOT/managed_contract.py") == 0:644 ]] || die unsafe_management_files
  contract files "$ROOT"
  local image
  image=$(contract field "$ROOT" image)
  docker_local image inspect "$image" | contract image "$image"
  compose config --quiet
}
check_existing(){
  local id
  check_inventory
  id=$(container_id)
  if [[ -n $id ]]; then
    inspect_managed | contract container "$ROOT"
  fi
}
check_inventory(){
  local named projected
  named=$(container_id) || return
  projected=$(project_ids) || return
  [[ $named == "$projected" ]] || die managed_project_container_inventory_mismatch
}
inspect_managed(){
  local image
  image=$(contract field "$ROOT" image) || return
  docker_local inspect "$image" "$CONTAINER"
}
verify(){
  local receipt_mode=${1:-container}
  check_inventory || return
  inspect_managed | contract "$receipt_mode" "$ROOT" running || return
  local address jar_sha mounted_sha
  jar_sha=$(contract field "$ROOT" jar_sha256) || return
  mounted_sha=$(docker_local exec --user 65532:65532 "$CONTAINER" sha256sum /app/spring-boot-application.jar) || return
  [[ $mounted_sha == "$jar_sha  /app/spring-boot-application.jar" ]] || die mounted_jar_bytes_changed
  address=$(contract field "$ROOT" bind_address) || return
  python3 -B "$ROOT/verify_log4shell_app.py" "http://${address}:8080/log4shell/"
}

case "$ACTION" in
  install)
    [[ ! -e $ROOT && ! -L $ROOT ]] || die managed_root_already_exists_use_check
    [[ -z $(container_id) && -z $(project_ids) ]] || die existing_container_not_adopted_stop_and_rename_separately
    : "${LOG4SHELL_APP_JAR:?explicit_prepared_jar_required}"
    : "${LOG4SHELL_IMAGE:?explicit_local_image_id_required}"
    : "${LOG4SHELL_BIND_ADDRESS:?explicit_private_bind_address_required}"
    REPOSITORY=${LOG4SHELL_SOURCE_ROOT:-$SOURCE_DIR/../../..}
    [[ -f $SOURCE_DIR/compose.yaml && -f $SOURCE_DIR/managed_contract.py ]] || die management_sources_missing
    [[ -f $REPOSITORY/deployment/validate_log4shell_jar.py && -f $REPOSITORY/deployment/verify_log4shell_app.py ]] || die repository_verification_sources_missing
    python3 -B - "$LOG4SHELL_APP_JAR" "$LOG4SHELL_IMAGE" "$LOG4SHELL_BIND_ADDRESS" <<'PY'
import ipaddress,pathlib,re,stat,sys
p=pathlib.Path(sys.argv[1]); s=p.lstat()
assert p.is_absolute() and stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and not s.st_mode & 0o022
assert re.fullmatch(r'sha256:[a-f0-9]{64}',sys.argv[2])
a=ipaddress.ip_address(sys.argv[3]); assert a.version==4 and str(a)==sys.argv[3]
assert any(a in ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.0/8'))
PY
    docker_local image inspect "$LOG4SHELL_IMAGE" | python3 -B "$SOURCE_DIR/managed_contract.py" image "$LOG4SHELL_IMAGE"
    JAR_SHA=$(python3 -B "$REPOSITORY/deployment/validate_log4shell_jar.py" "$LOG4SHELL_APP_JAR")
    STAGE=$(mktemp -d /opt/.capstone-log4shell-install.XXXXXXXX)
    install -d -o root -g root -m 0700 "$STAGE/artifacts"
    install -o root -g root -m 0644 "$SOURCE_DIR/compose.yaml" "$SOURCE_DIR/managed_contract.py" "$STAGE/"
    install -o root -g root -m 0750 "$SOURCE_DIR/manage.sh" "$STAGE/manage.sh"
    install -o root -g root -m 0644 "$REPOSITORY/deployment/validate_log4shell_jar.py" "$REPOSITORY/deployment/verify_log4shell_app.py" "$STAGE/"
    install -o root -g root -m 0644 "$LOG4SHELL_APP_JAR" "$STAGE/artifacts/$JAR_SHA.jar"
    [[ $(python3 -B "$STAGE/validate_log4shell_jar.py" "$STAGE/artifacts/$JAR_SHA.jar") == "$JAR_SHA" ]] || die copied_jar_changed
    python3 -B "$STAGE/managed_contract.py" install-manifest "$STAGE" "$ROOT" "$LOG4SHELL_IMAGE" "$LOG4SHELL_BIND_ADDRESS" "$JAR_SHA"
    mv -T -- "$STAGE" "$ROOT"
    STAGE=
    check_files
    printf '%s\n' 'log4shell_files_installed_use_up'
    ;;
  check)
    check_files
    check_existing
    ;;
  status)
    check_files
    check_inventory
    if [[ -z $(container_id) ]]; then printf '%s\n' 'log4shell_managed_container_absent'; else check_existing; fi
    ;;
  up|recreate)
    check_files
    check_existing
    arguments=(up -d --pull never --no-build --no-deps)
    if [[ $ACTION == recreate ]]; then arguments+=(--force-recreate); fi
    compose "${arguments[@]}" app
    inspect_managed | contract record "$ROOT"
    ready=false
    deadline=$((SECONDS + 90))
    while (( SECONDS < deadline )); do
      if verify >/dev/null 2>&1; then ready=true; break; fi
      sleep 2
    done
    [[ $ready == true ]] || die managed_container_verification_failed_left_for_review
    printf '%s\n' 'log4shell_managed_runtime_and_http_verified'
    ;;
  verify)
    check_files
    verify
    ;;
  recover)
    check_files
    verify candidate
    inspect_managed | contract record "$ROOT" running
    printf '%s\n' 'log4shell_container_id_receipt_recovered_after_verification'
    ;;
esac
