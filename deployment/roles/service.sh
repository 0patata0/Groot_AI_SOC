#!/usr/bin/env bash
# Fresh Ubuntu 24.04 amd64 service role. No package/image download or image build.
# Schema 9: fixed web images, Redis/Samba bundle and the rootless sudo terminal; older schemas require explicit migration.
# Official contracts: github.com/digininja/DVWA/{compose.yml,config/config.inc.php.dist,setup.php}
# httpd.apache.org/docs/2.4/expr.html (CONN_REMOTE_ADDR)
# documentation.wazuh.com/current/user-manual/reference/ossec-conf/client.html
set -Eeuo pipefail
umask 077
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C TZ=Asia/Seoul PYTHONDONTWRITEBYTECODE=1
unset DOCKER_HOST DOCKER_CONTEXT COMPOSE_FILE COMPOSE_PROJECT_NAME COMPOSE_PROFILES

die(){ printf 'service: %s\n' "$1" >&2; exit 1; }
note(){ printf 'service: %s\n' "$1"; }
sha(){ sha256sum -- "$1" | awk '{print $1}'; }
safe_path(){
  local p=$1
  [[ $p =~ ^/opt/[A-Za-z0-9._/-]+$ && $p != */../* && $p != */./* && $p != */.. && $p != */. && $p != */ && $p != *//* ]] || die unsafe_path
  while [[ $p != / ]]; do
    if [[ -e $p || -L $p ]]; then
      [[ -d $p && ! -L $p && $(stat -c %u "$p") == 0 ]] || die unsafe_parent
      (( (8#$(stat -c %a "$p") & 0022) == 0 )) || die writable_parent
    fi
    p=${p%/*}; [[ -n $p ]] || p=/
  done
}
source_path(){
  local stage
  if [[ $MODE =~ ^(check|verify)$ && $CAPSTONE_SOURCE =~ ^/var/tmp/capstone-bootstrap-[a-f0-9]{24}/source$ ]]; then
    stage=${CAPSTONE_SOURCE%/source}
    [[ -d /var/tmp && ! -L /var/tmp && $(stat -c '%u:%g:%a' /var/tmp) == 0:0:1777 ]] || die unsafe_staging_anchor
    [[ -d $stage && ! -L $stage && $(stat -c '%u:%g:%a' "$stage") == 0:0:700 ]] || die unsafe_staging_directory
    [[ -d $CAPSTONE_SOURCE && ! -L $CAPSTONE_SOURCE && $(stat -c %u "$CAPSTONE_SOURCE") == 0 ]] || die unsafe_staging_source
    (( (8#$(stat -c %a "$CAPSTONE_SOURCE") & 0022) == 0 )) || die writable_staging_source
  else
    safe_path "$CAPSTONE_SOURCE"
  fi
}
ipv4(){
  local ip=$1 n; local -a parts
  [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  IFS=. read -r -a parts <<<"$ip"
  for n in "${parts[@]}"; do [[ $n == 0 || $n =~ ^[1-9][0-9]{0,2}$ ]] && ((10#$n<=255)) || return 1; done
  ((10#${parts[0]}>0 && 10#${parts[0]}<224 && 10#${parts[0]}!=127))
}
regular(){ [[ -f $1 && ! -L $1 && $(stat -c %h "$1") == 1 ]] || die unsafe_file; }
logrun(){
  local name=$1; shift
  [[ $name =~ ^[a-z0-9-]+$ ]] || die log_name
  if ! timeout --kill-after=5s 180s "$@" >"$ROLE/evidence/$name.log" 2>&1; then
    die "${name}_failed_private_evidence_preserved"
  fi
}
docker_cmd(){ timeout --kill-after=3s 30s "$DOCKER" --host unix:///var/run/docker.sock "$@"; }
mark(){ printf '%s\n' "$1" >"$ROLE/phase.next"; sync "$ROLE/phase.next"; mv -T "$ROLE/phase.next" "$ROLE/phase"; sync "$ROLE"; }

apache_document(){
  cat <<EOF
# Independent DVWA only. No console, Java proxy, theme or WAF-exemption cookies.
ServerName capstone-service
<IfModule !remoteip_module>
LoadModule remoteip_module /usr/lib/apache2/modules/mod_remoteip.so
</IfModule>
RemoteIPHeader X-Forwarded-For
RemoteIPInternalProxy $SECURITY_HOST
<VirtualHost *:80>
DocumentRoot /var/www/html
<Location "/">
  Require expr "%{CONN_REMOTE_ADDR} == '$SECURITY_HOST' || %{CONN_REMOTE_ADDR} == '127.0.0.1' || %{CONN_REMOTE_ADDR} == '::1'"
</Location>
Alias /dvwa /var/www/html
<Directory /var/www/html>
  Options -Indexes
  AllowOverride All
  Require all granted
</Directory>
LogFormat "%a %l %u %t \"%r\" %>s %b" capstone_combined
CustomLog /var/log/capstone-service/access.log capstone_combined
ErrorLog /var/log/capstone-service/error.log
</VirtualHost>
EOF
}

offline_command(){ python3 -B "$CAPSTONE_SOURCE/deployment/offline_service.py" "$1"; }
offline_installer(){
  local action=$1
  local args=("--$action" --manifest "$LAB_MANIFEST" --origin "$LAB_PUBLIC_ORIGIN")
  if [[ $action == apply ]]; then
    [[ -f $LAB_ADMIN_KEY_FILE && ! -L $LAB_ADMIN_KEY_FILE ]] || die lab_admin_key_transfer_required
    args+=(--admin-key-file "$LAB_ADMIN_KEY_FILE")
  fi
  bash "$CAPSTONE_SOURCE/infra/groot-c/offline-labs/scripts/install.sh" "${args[@]}" "$LAB_WHEEL_DIR"
}
sudo_runtime(){
  python3 -B "$CAPSTONE_SOURCE/infra/groot-c/offline-labs/nonweb/sudo/runtime/bootstrap.py"     "--$1" --bundle "$LAB_SUDO_BUNDLE"
}
sudo_terminal_check(){
  /usr/bin/python3 -IB /opt/capstone-nonweb-labs/sudo_terminal.py check
}
nonweb_runtime(){
  local budget=600s
  # Two image loads may each use 300s before publisher and final checks.
  [[ $1 != apply ]] || budget=1200s
  timeout --kill-after=10s "$budget" python3 -B "$CAPSTONE_SOURCE/infra/groot-c/nonweb-labs/bootstrap.py" \
    "--$1" --bundle "$LAB_NONWEB_BUNDLE" --source-root "$CAPSTONE_SOURCE/infra/groot-c/nonweb-labs"
}

probe_owned(){
  local cid=$1 expected=$2 kind=$3
  [[ $cid =~ ^[a-f0-9]{64}$ && $expected =~ ^sha256:[a-f0-9]{64}$ ]] || die invalid_probe_identity
  [[ $kind == apache || $kind == gateway ]] || die invalid_probe_kind
  docker_cmd inspect --format '{{json .}}' "$cid" | jq -e --arg cid "$cid" --arg image "$expected" \
    --arg label "io.capstone.portable.${kind}-probe" \
    'type=="object" and .Id==$cid and .Image==$image and .Config.Labels[$label]=="service"' >/dev/null \
    || die "${kind}_probe_ownership_changed"
}
remove_owned_probe(){
  local cid=$1 expected=$2 kind=$3
  probe_owned "$cid" "$expected" "$kind"
  docker_cmd rm --force "$cid" >/dev/null || die "${kind}_probe_cleanup_failed"
}
apache_image_probe(){
  local cid outcome=1
  cid=$(docker_cmd create --pull never --network none --read-only \
    --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 32 --memory 128m \
    --label io.capstone.portable.apache-probe=service --entrypoint sh "$APP_ID" \
    -c 'test -r /usr/lib/apache2/modules/mod_remoteip.so && php -m | grep -qx mysqli') || die apache_probe_creation_failed
  probe_owned "$cid" "$APP_ID" apache
  if docker_cmd start --attach "$cid" >/dev/null 2>&1; then outcome=0; fi
  remove_owned_probe "$cid" "$APP_ID" apache
  [[ $outcome == 0 ]] || die preloaded_dvwa_requires_remoteip_and_mysqli
}
gateway_image_probe(){
  local cid outcome=1
  regular "$ROLE/config/gateway.conf"
  # Syntax testing opens no host listener and never runs the image entrypoint.
  cid=$(docker_cmd create --pull never --network none --read-only --user 65532:65532 \
    --cap-drop ALL --security-opt no-new-privileges:true --ipc private \
    --pids-limit 64 --memory 128m --cpus 0.5 --workdir /tmp --no-healthcheck \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=32m,mode=1777 \
    --log-driver json-file --log-opt max-size=10m --log-opt max-file=3 \
    --mount "type=bind,src=$ROLE/config/gateway.conf,dst=/etc/capstone-gateway.conf,readonly" \
    --label io.capstone.portable.gateway-probe=service --entrypoint nginx "$GATEWAY_ID" \
    -t -c /etc/capstone-gateway.conf) || die gateway_probe_creation_failed
  probe_owned "$cid" "$GATEWAY_ID" gateway
  if docker_cmd start --attach "$cid" >"$ROLE/evidence/gateway-preflight.log" 2>&1; then outcome=0; fi
  remove_owned_probe "$cid" "$GATEWAY_ID" gateway
  [[ $outcome == 0 ]] || die gateway_syntax_check_failed_private_evidence_preserved
}

compose_document(){
  jq -n --arg app "$APP_ID" --arg db "$DB_ID" --arg gateway "$GATEWAY_ID" --arg bind "$SERVICE_HOST:$WEB_BACKEND_PORT:80" \
    '{services:{dvwa:{image:$app,container_name:"capstone-service-dvwa",pull_policy:"never",
      restart:"unless-stopped",env_file:["./credentials/app.env"],ports:[$bind],
      networks:["front","private"],depends_on:{db:{condition:"service_healthy"}},
      volumes:["./config/apache.conf:/etc/apache2/sites-enabled/000-default.conf:ro",
        "./config/bootstrap.php:/opt/capstone-bootstrap.php:ro","./logs:/var/log/capstone-service"],
      labels:{"io.capstone.role":"service"},security_opt:["no-new-privileges:true"],pids_limit:256,
      healthcheck:{test:["CMD","php","-r","exit(strpos(@file_get_contents(\"http://127.0.0.1/login.php\"),\"DVWA\")!==false?0:1);"],interval:"5s",timeout:"3s",retries:24},
      logging:{driver:"json-file",options:{"max-size":"10m","max-file":"3"}}},
    db:{image:$db,container_name:"capstone-service-db",pull_policy:"never",restart:"unless-stopped",
      env_file:["./credentials/db.env"],networks:["private"],volumes:["database:/var/lib/mysql"],
      healthcheck:{test:["CMD","healthcheck.sh","--connect","--innodb_initialized"],interval:"5s",timeout:"3s",retries:30},
      labels:{"io.capstone.role":"service"},security_opt:["no-new-privileges:true"],pids_limit:256,
      logging:{driver:"json-file",options:{"max-size":"10m","max-file":"3"}}},
    gateway:{image:$gateway,container_name:"capstone-service-gateway",pull_policy:"never",restart:"unless-stopped",
      entrypoint:["nginx"],command:["-c","/etc/capstone-gateway.conf","-g","daemon off;"],working_dir:"/tmp",
      user:"65532:65532",read_only:true,cap_drop:["ALL"],security_opt:["no-new-privileges:true"],
      pids_limit:64,mem_limit:"128m",cpus:0.5,network_mode:"host",ipc:"private",
      tmpfs:["/tmp:rw,nosuid,nodev,noexec,size=32m,mode=1777"],healthcheck:{disable:true},
      volumes:[{type:"bind",source:"./config/gateway.conf",target:"/etc/capstone-gateway.conf",
        read_only:true,bind:{create_host_path:false}}],
      labels:{"io.capstone.role":"service"},
      logging:{driver:"json-file",options:{"max-size":"10m","max-file":"3"}}}},
      networks:{front:{},private:{internal:true}},volumes:{database:{}}}'
}

ssh_macs() { python3 -B "$CAPSTONE_SOURCE/deployment/ssh_macs.py" "$1"; }
settings(){
  [[ $# == 1 && $1 =~ ^(check|apply|verify)$ ]] || die 'usage: bash service.sh check|apply|verify'
  MODE=$1
  [[ $EUID == 0 && $(uname -m) == x86_64 ]] || die root_amd64_required
  [[ $(. /etc/os-release; printf '%s:%s' "$ID" "$VERSION_ID") == ubuntu:24.04 ]] || die ubuntu_24_04_required
  : "${CAPSTONE_ROOT:=/opt/capstone}" "${CAPSTONE_SOURCE:?uploaded_source_required}"
  : "${SECURITY_HOST:?}" "${SIEM_HOST:?}" "${SERVICE_HOST:?}" "${WEB_BACKEND_PORT:=80}" "${WAF_PORT:=8080}"
  : "${DVWA_IMAGE:=ghcr.io/digininja/dvwa:latest}" "${MARIADB_IMAGE:=mariadb:10}"
  : "${WAF_IMAGE:=owasp/modsecurity-crs:nginx}"
  : "${LAB_MANIFEST:=/opt/capstone-prereqs/cve_list.json}" "${LAB_WHEEL_DIR:=/opt/capstone-prereqs/wheels}"
  : "${LAB_PUBLIC_ORIGIN:?https_public_origin_required}" "${LAB_GATEWAY_PORT:=18091}"
  : "${LAB_ADMIN_KEY_FILE:=/opt/capstone-prereqs/lab-admin.key}" "${LAB_SUDO_BUNDLE:=/opt/capstone-prereqs/sudo}"
  : "${LAB_NONWEB_BUNDLE:=/opt/capstone-prereqs/nonweb}"
  [[ -z ${LOG4SHELL_APP_JAR:-} && -z ${LOG4SHELL_IMAGE:-} ]] || die schema9_requires_prebuilt_manifest_images_not_legacy_jar_options
  : "${WAZUH_CA_FILE:=/opt/capstone-prereqs/wazuh-root-ca.pem}"
  : "${WAZUH_ENROLLMENT_PASS_FILE:=/opt/capstone-prereqs/wazuh-enrollment.pass}"
  for value in "$SECURITY_HOST" "$SIEM_HOST" "$SERVICE_HOST"; do ipv4 "$value" || die literal_ipv4_required; done
  [[ $SECURITY_HOST != "$SIEM_HOST" && $SECURITY_HOST != "$SERVICE_HOST" && $SIEM_HOST != "$SERVICE_HOST" ]] || die distinct_hosts_required
  [[ $WEB_BACKEND_PORT =~ ^[1-9][0-9]{0,4}$ ]] && ((WEB_BACKEND_PORT<=65535)) || die invalid_backend_port
  [[ $WEB_BACKEND_PORT != 22 && $WEB_BACKEND_PORT != 1514 && $WEB_BACKEND_PORT != 1515 ]] || die reserved_port
  [[ $WAF_PORT =~ ^[1-9][0-9]{0,4}$ ]] && ((WAF_PORT<=65535)) || die invalid_waf_port
  for value in "$DVWA_IMAGE" "$MARIADB_IMAGE" "$WAF_IMAGE"; do [[ $value =~ ^[a-zA-Z0-9][a-zA-Z0-9._/:@-]+$ ]] || die invalid_image_reference; done
  safe_path "$CAPSTONE_ROOT"; source_path
  [[ -d $CAPSTONE_SOURCE/deployment/roles ]] || die uploaded_source_missing
  ROLE=$CAPSTONE_ROOT/service
  for tool in docker jq python3 openssl timeout ip ss flock nsenter sha256sum sync systemctl; do command -v "$tool" >/dev/null || die "preinstall_${tool}_required"; done
  DOCKER=$(command -v docker)
  COMPOSE=("$DOCKER" --host unix:///var/run/docker.sock compose --project-name capstone-service --project-directory "$ROLE" -f "$ROLE/compose.json")
  [[ -x /var/ossec/bin/wazuh-agentd && -x /var/ossec/bin/wazuh-logcollector ]] || die preinstall_wazuh_agent_required
  [[ $(dpkg-query -W -f='${Version}' wazuh-agent 2>/dev/null) == 4.14.8-* ]] || die wazuh_agent_4_14_8_required
  docker_cmd info --format '{{.OSType}}/{{.Architecture}}' | grep -Eq '^linux/(x86_64|amd64)$' || die native_docker_required
  docker_cmd compose version >/dev/null || die compose_plugin_required
  ip -j address show | jq -e --arg ip "$SERVICE_HOST" 'any(.[] .addr_info[]?; .family=="inet" and .local==$ip)' >/dev/null || die service_ip_not_local
  APP_ID=$(docker_cmd image inspect --format '{{.Id}} {{.Os}} {{.Architecture}}' "$DVWA_IMAGE") || die preloaded_dvwa_image_required
  DB_ID=$(docker_cmd image inspect --format '{{.Id}} {{.Os}} {{.Architecture}}' "$MARIADB_IMAGE") || die preloaded_mariadb_image_required
  GATEWAY_ID=$(docker_cmd image inspect --format '{{.Id}} {{.Os}} {{.Architecture}}' "$WAF_IMAGE") || die preloaded_gateway_image_required
  [[ $APP_ID =~ ^sha256:[a-f0-9]{64}\ linux\ amd64$ && $DB_ID =~ ^sha256:[a-f0-9]{64}\ linux\ amd64$ && $GATEWAY_ID =~ ^sha256:[a-f0-9]{64}\ linux\ amd64$ ]] || die amd64_images_required
  APP_ID=${APP_ID%% *}; DB_ID=${DB_ID%% *}; GATEWAY_ID=${GATEWAY_ID%% *}
  regular "$CAPSTONE_SOURCE/deployment/ssh_macs.py"
  ssh_macs check >/dev/null || die ssh_macs_check_failed
  regular "$CAPSTONE_SOURCE/deployment/offline_service.py"
  regular "$CAPSTONE_SOURCE/infra/groot-c/offline-labs/nonweb/sudo/runtime/bootstrap.py"
  regular "$CAPSTONE_SOURCE/infra/groot-c/nonweb-labs/bootstrap.py"
  export CAPSTONE_SOURCE SECURITY_HOST SERVICE_HOST LAB_MANIFEST LAB_PUBLIC_ORIGIN LAB_GATEWAY_PORT LAB_ADMIN_KEY_FILE LAB_NONWEB_BUNDLE GATEWAY_ID ROLE DOCKER WEB_BACKEND_PORT
  LAB_PROFILE=$(offline_command profile) || die offline_lab_prerequisites_invalid
  INPUT=$(jq -cnS --arg root "$CAPSTONE_ROOT" --arg a "$SECURITY_HOST" --arg b "$SIEM_HOST" --arg c "$SERVICE_HOST" \
    --argjson port "$WEB_BACKEND_PORT" --arg app "$APP_ID" --arg db "$DB_ID" --argjson lab "$LAB_PROFILE" \
    --arg sshmacs "$(sha "$CAPSTONE_SOURCE/deployment/ssh_macs.py")" \
    --arg sudo "$LAB_SUDO_BUNDLE" --arg nonweb "$LAB_NONWEB_BUNDLE" --arg wheels "$LAB_WHEEL_DIR" --arg key "$LAB_ADMIN_KEY_FILE" \
    '{ssh_macs_sha256:$sshmacs,schema:9,role:"service",root:$root,security_host:$a,siem_host:$b,service_host:$c,port:$port,app_image_id:$app,db_image_id:$db,offline_labs:$lab,sudo_bundle:$sudo,nonweb_bundle:$nonweb,wheel_directory:$wheels,admin_key_file:$key}')

}

fresh_agent(){
  [[ -d /var/ossec && ! -L /var/ossec && -d /var/ossec/etc && ! -L /var/ossec/etc ]] || die unsafe_agent_parent
  regular /var/ossec/etc/ossec.conf
  [[ ! -s /var/ossec/etc/client.keys ]] || die existing_registered_agent_refused
  [[ ! -L /var/ossec/etc/client.keys ]] || die unsafe_agent_keys
  python3 -B - "$SIEM_HOST" <<'PY'
import pathlib,sys,xml.etree.ElementTree as E
p=pathlib.Path('/var/ossec/etc/ossec.conf')
r=E.fromstring('<capstone>'+p.read_text()+'</capstone>')
a=r.findall('ossec_config/client/server/address')
assert len(a)==1 and a[0].text.strip() in ('MANAGER_IP',sys.argv[1]), 'nonfresh_agent_config'
assert len(r.findall('ossec_config/client'))==1, 'ambiguous_agent_client'
PY
}
fresh_namespace(){
  local names
  [[ ! -e $ROLE && ! -L $ROLE ]] || die existing_or_partial_role_refused
  names=$(docker_cmd ps -aq --filter label=com.docker.compose.project=capstone-service) || die container_inventory_failed
  [[ -z $names ]] || die existing_compose_project_refused
  for name in capstone-service-dvwa capstone-service-db capstone-service-log4shell capstone-service-gateway; do
    names=$(docker_cmd ps -aq --filter "name=^/${name}$") || die container_inventory_failed
    [[ -z $names ]] || die existing_container_name_refused
  done
  names=$(docker_cmd volume ls -q --filter label=com.docker.compose.project=capstone-service) || die volume_inventory_failed
  [[ -z $names ]] || die existing_project_volume_refused
  names=$(docker_cmd network ls -q --filter label=com.docker.compose.project=capstone-service) || die network_inventory_failed
  [[ -z $names ]] || die existing_project_network_refused
  names=$(docker_cmd volume ls --format '{{.Name}}') || die volume_inventory_failed
  ! grep -Fxq capstone-service_database <<<"$names" || die existing_database_volume_refused
  names=$(docker_cmd network ls --format '{{.Name}}') || die network_inventory_failed
  ! grep -Eq '^capstone-service_(front|private|lab)$' <<<"$names" || die existing_network_name_refused
  names=$(ss -H -ltn "sport = :$WEB_BACKEND_PORT") || die port_inventory_failed
  [[ -z $names ]] || die backend_port_in_use
  names=$(ss -H -ltn "sport = :$LAB_GATEWAY_PORT") || die port_inventory_failed
  [[ -z $names ]] || die gateway_port_in_use
  offline_installer check || die offline_lab_preflight_failed
  sudo_runtime check || die sudo_runtime_preflight_failed
  nonweb_runtime check || die nonweb_runtime_preflight_failed
  fresh_agent
}
assert_managed(){
  safe_path "$ROLE"
  regular "$ROLE/manifest.json"; regular "$ROLE/input.json"
  [[ $(stat -c '%u:%g:%a' "$ROLE") == 0:0:700 ]] || die role_permissions_changed
  [[ $(cat "$ROLE/input.json") == "$INPUT" ]] || die changed_inputs_require_manual_migration
  [[ $(stat -c '%u:%g:%a' "$ROLE/manifest.json") == 0:0:600 ]] || die manifest_permissions_changed
  jq -e 'keys==["agent_config_sha256","container_ids","enrollment_ca_sha256","enrollment_pass_sha256","files","role","schema","script_sha256","state"] and
    .schema==9 and .role=="service" and .state=="complete" and
    (.container_ids|keys)==["db","dvwa","gateway"] and
    (.container_ids|all(type=="string" and test("^[a-f0-9]{64}$"))) and
    ([.agent_config_sha256,.enrollment_ca_sha256,.enrollment_pass_sha256,.script_sha256]|all(type=="string" and test("^[a-f0-9]{64}$"))) and
    (.files|keys)==["compose.json","config/apache.conf","config/bootstrap.php","config/gateway.conf","config/ossec.conf.candidate","credentials/admin-password","credentials/app.env","credentials/db-password","credentials/db-root-password","credentials/db.env","input.json"] and
    (.files|all(type=="string" and test("^[a-f0-9]{64}$")))' "$ROLE/manifest.json" >/dev/null || die deployment_incomplete
  [[ $(sha "${BASH_SOURCE[0]}") == $(jq -r .script_sha256 "$ROLE/manifest.json") ]] || die deployment_script_changed
  local file expected mode
  while IFS=$'\t' read -r file expected; do
    [[ $file =~ ^[a-zA-Z0-9._/-]+$ && $file != *..* && $file != /* ]] || die manifest_path_invalid
    regular "$ROLE/$file"
    if [[ $file == */* ]]; then safe_path "$ROLE/${file%/*}"; fi
    mode=600; [[ $file == config/apache.conf || $file == config/bootstrap.php || $file == config/gateway.conf ]] && mode=644
    [[ $(stat -c '%u:%g:%a' "$ROLE/$file") == "0:0:$mode" ]] || die managed_permissions_changed
    [[ $(sha "$ROLE/$file") == "$expected" ]] || die managed_file_changed
  done < <(jq -r '.files|to_entries[]|[.key,.value]|@tsv' "$ROLE/manifest.json")
  for file in /var/ossec/etc/ossec.conf /var/ossec/etc/capstone-manager-ca.pem /var/ossec/etc/capstone-enrollment.pass; do
    regular "$file"
    [[ $(stat -c '%U:%G:%a' "$file") == root:wazuh:640 ]] || die managed_agent_permissions_changed
  done
  [[ $(sha /var/ossec/etc/ossec.conf) == $(jq -r .agent_config_sha256 "$ROLE/manifest.json") ]] || die agent_config_changed
  [[ $(sha /var/ossec/etc/capstone-manager-ca.pem) == $(jq -r .enrollment_ca_sha256 "$ROLE/manifest.json") && $(sha /var/ossec/etc/capstone-enrollment.pass) == $(jq -r .enrollment_pass_sha256 "$ROLE/manifest.json") ]] || die enrollment_files_changed
}

write_files(){
  mkdir -m 700 "$ROLE"
  mkdir -m 700 "$ROLE/evidence" "$ROLE/credentials" "$ROLE/config"
  mkdir -m 755 "$ROLE/logs"
  offline_command render >"$ROLE/config/gateway.conf"
  printf '%s\n' "$INPUT" >"$ROLE/input.json"
  cp -p /var/ossec/etc/ossec.conf "$ROLE/evidence/ossec.conf.before"
  sha /var/ossec/etc/ossec.conf >"$ROLE/evidence/agent-before.sha256"
  openssl rand -hex 32 >"$ROLE/credentials/db-password"
  openssl rand -hex 32 >"$ROLE/credentials/db-root-password"
  openssl rand -hex 24 >"$ROLE/credentials/admin-password"
  {
    printf 'MYSQL_DATABASE=dvwa\nMYSQL_USER=dvwa\nMYSQL_PASSWORD=%s\nMYSQL_ROOT_PASSWORD=%s\nTZ=Asia/Seoul\n' \
      "$(cat "$ROLE/credentials/db-password")" "$(cat "$ROLE/credentials/db-root-password")"
  } >"$ROLE/credentials/db.env"
  {
    printf 'DB_SERVER=db\nDB_DATABASE=dvwa\nDB_USER=dvwa\nDB_PASSWORD=%s\nDEFAULT_SECURITY_LEVEL=impossible\nTZ=Asia/Seoul\n' \
      "$(cat "$ROLE/credentials/db-password")"
  } >"$ROLE/credentials/app.env"
  apache_document >"$ROLE/config/apache.conf"
  # No shell interpolation of credentials or arbitrary host paths in Compose.
  compose_document >"$ROLE/compose.json"
  cat >"$ROLE/config/bootstrap.php" <<'PHP'
<?php
// Local, once-only bootstrap. Never run the destructive setup against tables.
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
function db() { return new mysqli(getenv('DB_SERVER'),getenv('DB_USER'),getenv('DB_PASSWORD'),'dvwa',3306); }
function request($method,$data='',$cookie='') {
  $opts=['method'=>$method,'timeout'=>10,'follow_location'=>0,'ignore_errors'=>true];
  $opts['header']="Content-Type: application/x-www-form-urlencoded\r\n".($cookie!==''?"Cookie: $cookie\r\n":'');
  if ($method==='POST') $opts['content']=$data;
  $body=file_get_contents('http://127.0.0.1/setup.php',false,stream_context_create(['http'=>$opts]));
  if ($body===false || strlen($body)>1048576) throw new Exception('setup_response_invalid');
  return [$body,$http_response_header];
}
try {
  $c=db(); $mode=$argv[1]??'';
  if ($mode==='init') {
    $n=$c->query("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='dvwa'")->fetch_row()[0];
    if ((int)$n!==0) throw new Exception('existing_tables_refuse_reset');
    $password=trim(stream_get_contents(STDIN,256));
    if (!preg_match('/^[a-f0-9]{48}$/D',$password)) throw new Exception('admin_input_invalid');
    [$html,$headers]=request('GET'); $cookie='';
    foreach ($headers as $h) if (preg_match('/^Set-Cookie:\s*(PHPSESSID=[a-zA-Z0-9,-]+);/i',$h,$m)) $cookie=$m[1];
    if ($cookie==='' || preg_match_all("/name='user_token' value='([a-f0-9]{32})'/",$html,$m)!==1) throw new Exception('setup_token_invalid');
    request('POST',http_build_query(['create_db'=>'Create / Reset Database','user_token'=>$m[1][0]]),$cookie);
    $c=db();
    if ((int)$c->query('SELECT COUNT(*) FROM users')->fetch_row()[0]!==5) throw new Exception('seed_count_invalid');
    foreach ($c->query('SELECT user_id,user FROM users') as $row) {
      $hash=md5($row['user']==='admin'?$password:bin2hex(random_bytes(24)));
      $st=$c->prepare('UPDATE users SET password=? WHERE user_id=?'); $st->bind_param('si',$hash,$row['user_id']); $st->execute();
    }
  } elseif ($mode!=='verify') throw new Exception('mode_invalid');
  $c=db();
  if ((int)$c->query("SELECT COUNT(*) FROM users WHERE user='admin' AND password<>MD5('password')")->fetch_row()[0]!==1) throw new Exception('admin_not_initialized');
  $c->query('SELECT comment_id FROM guestbook LIMIT 1');
  $body=file_get_contents('http://127.0.0.1/login.php',false,stream_context_create(['http'=>['timeout'=>5]]));
  if ($body===false || strpos($body,'DVWA')===false) throw new Exception('login_unavailable');
  echo "dvwa_ready\n";
} catch (Throwable $e) { fwrite(STDERR,"dvwa_bootstrap_or_verification_failed\n"); exit(1); }
PHP
  chmod 644 "$ROLE/config/apache.conf" "$ROLE/config/bootstrap.php" "$ROLE/config/gateway.conf"
  sync "$ROLE/input.json" "$ROLE/compose.json" "$ROLE/config/apache.conf" "$ROLE/config/bootstrap.php" \
    "$ROLE/config/gateway.conf" \
    "$ROLE/credentials/"* "$ROLE/credentials" "$ROLE"
  mark prepared
}

enrollment_inputs(){
  for file in "$WAZUH_CA_FILE" "$WAZUH_ENROLLMENT_PASS_FILE"; do
    safe_path "${file%/*}"; regular "$file"
    [[ $(stat -c %u "$file") == 0 ]] || die prerequisite_owner
  done
  [[ $(stat -c %a "$WAZUH_ENROLLMENT_PASS_FILE") == 600 ]] || die enrollment_secret_mode
  openssl x509 -in "$WAZUH_CA_FILE" -noout -checkend 86400 >/dev/null 2>&1 || die enrollment_ca_invalid
  [[ $(stat -c %s "$WAZUH_ENROLLMENT_PASS_FILE") -ge 32 && $(stat -c %s "$WAZUH_ENROLLMENT_PASS_FILE") -le 257 ]] || die enrollment_secret_length
}
configure_agent(){
  enrollment_inputs
  [[ $(sha /var/ossec/etc/ossec.conf) == $(cat "$ROLE/evidence/agent-before.sha256") ]] || die agent_config_cas_changed
  fresh_agent
  # Destination files are exclusive; this role never adopts an old enrollment.
  [[ ! -e /var/ossec/etc/capstone-manager-ca.pem && ! -L /var/ossec/etc/capstone-manager-ca.pem && ! -e /var/ossec/etc/capstone-enrollment.pass && ! -L /var/ossec/etc/capstone-enrollment.pass ]] || die enrollment_destination_exists
  install -o root -g wazuh -m 640 "$WAZUH_CA_FILE" /var/ossec/etc/capstone-manager-ca.pem
  install -o root -g wazuh -m 640 "$WAZUH_ENROLLMENT_PASS_FILE" /var/ossec/etc/capstone-enrollment.pass
  sync /var/ossec/etc/capstone-manager-ca.pem /var/ossec/etc/capstone-enrollment.pass /var/ossec/etc
  python3 -B - "$ROLE" "$SIEM_HOST" <<'PY'
import os,pathlib,re,sys,xml.etree.ElementTree as E
root,manager=pathlib.Path(sys.argv[1]),sys.argv[2]
p=pathlib.Path('/var/ossec/etc/ossec.conf'); b=p.read_text()
client=f'''<client>
    <server><address>{manager}</address><port>1514</port><protocol>tcp</protocol></server>
    <crypto_method>aes</crypto_method><notify_time>20</notify_time><time-reconnect>60</time-reconnect>
    <disable-active-response>yes</disable-active-response>
    <enrollment><enabled>yes</enabled><manager_address>{manager}</manager_address><port>1515</port>
      <agent_name>capstone-service</agent_name><server_ca_path>/var/ossec/etc/capstone-manager-ca.pem</server_ca_path>
      <authorization_pass_path>/var/ossec/etc/capstone-enrollment.pass</authorization_pass_path>
      <delay_after_enrollment>5</delay_after_enrollment></enrollment>
  </client>'''
candidate,n=re.subn(r'<client>.*?</client>',lambda _:client,b,flags=re.S); assert n==1
for f in ('access.log','error.log'):
    location=str(root/'logs'/f)
    assert location not in candidate
    candidate+='\n<ossec_config><localfile><log_format>apache</log_format><location>'+location+'</location></localfile></ossec_config>\n'
E.fromstring('<capstone>'+candidate+'</capstone>')
q=root/'config/ossec.conf.candidate';q.write_text(candidate);os.chmod(q,0o600)
with q.open('rb') as h: os.fsync(h.fileno())
PY
  mark agent-config-armed
  logrun agent-stop systemctl stop wazuh-agent
  fresh_agent
  [[ $(sha /var/ossec/etc/ossec.conf) == $(cat "$ROLE/evidence/agent-before.sha256") ]] || die agent_config_changed_before_install
  [[ ! -e /var/ossec/etc/.capstone-ossec.conf.new && ! -L /var/ossec/etc/.capstone-ossec.conf.new ]] || die agent_candidate_destination_exists
  install -o root -g wazuh -m 640 "$ROLE/config/ossec.conf.candidate" /var/ossec/etc/.capstone-ossec.conf.new
  sync /var/ossec/etc/.capstone-ossec.conf.new
  mv -T /var/ossec/etc/.capstone-ossec.conf.new /var/ossec/etc/ossec.conf
  sync /var/ossec/etc
  logrun agent-config-check /var/ossec/bin/wazuh-agentd -t
  logrun agent-log-check /var/ossec/bin/wazuh-logcollector -t
  mark enrollment-start-armed
  logrun agent-enable systemctl enable wazuh-agent
  logrun agent-start systemctl start wazuh-agent
  local deadline=$((SECONDS+120))
  while ((SECONDS<deadline)); do
    if [[ -s /var/ossec/etc/client.keys ]] && grep -Eq "^status='connected'" /var/ossec/var/run/wazuh-agentd.state 2>/dev/null; then break; fi
    sleep 2
  done
  [[ -s /var/ossec/etc/client.keys ]] && grep -Eq "^status='connected'" /var/ossec/var/run/wazuh-agentd.state || die agent_enrollment_or_connection_pending
  mark agent-connected
}

runtime_contract(){
  local name=$1 expected=$2
  [[ $name == dvwa || $name == db || $name == gateway ]] || return 1
  if [[ $name == gateway ]]; then offline_command gateway-contract >/dev/null; return; fi
  jq -e --arg project capstone-service --arg image "$expected" --arg name "$name" \
    --arg root "$ROLE" --arg ip "$SERVICE_HOST" --arg port "$WEB_BACKEND_PORT" '
    def env_is($key; $value): [.Config.Env[]? | select(startswith($key+"="))]==[$key+"="+$value];
    .State.Running==true and .State.Restarting==false and .Image==$image and
    .Config.Labels["com.docker.compose.project"]==$project and .Config.Labels["com.docker.compose.service"]==$name and
    .HostConfig.Privileged==false and .HostConfig.RestartPolicy.Name=="unless-stopped" and
    ((.HostConfig.SecurityOpt//[])|any(.=="no-new-privileges:true" or .=="no-new-privileges")) and
    (if $name=="db" then
      .State.Health.Status=="healthy" and ((.HostConfig.PortBindings//{})|length)==0 and
      (.Mounts|length)==1 and .Mounts[0].Type=="volume" and .Mounts[0].Name=="capstone-service_database" and
      .Mounts[0].Destination=="/var/lib/mysql" and .Mounts[0].RW==true and
      (.NetworkSettings.Networks|keys)==["capstone-service_private"]
    else
      .State.Health.Status=="healthy" and
      .HostConfig.PortBindings=={"80/tcp":[{"HostIp":$ip,"HostPort":$port}]} and
      (.NetworkSettings.Networks|keys)==["capstone-service_front","capstone-service_private"] and
      ((.Mounts|map({Type,Source,Destination,RW})|sort_by(.Destination))==([
        {Type:"bind",Source:($root+"/config/apache.conf"),Destination:"/etc/apache2/sites-enabled/000-default.conf",RW:false},
        {Type:"bind",Source:($root+"/config/bootstrap.php"),Destination:"/opt/capstone-bootstrap.php",RW:false},
        {Type:"bind",Source:($root+"/logs"),Destination:"/var/log/capstone-service",RW:true}]|sort_by(.Destination)))
    end)' >/dev/null
}
verify_offline_apps(){
  local deadline=$((SECONDS+90))
  while ((SECONDS<deadline)); do
    if offline_command verify >/dev/null 2>&1; then return; fi
    sleep 2
  done
  die offline_labs_gateway_or_runtime_verification_failed
}

verify(){
  ssh_macs verify >/dev/null || die ssh_macs_verify_failed
  assert_managed
  local name id expected
  for name in dvwa db gateway; do
    id=$(docker_cmd ps -aq --no-trunc --filter "name=^/capstone-service-${name}$")
    [[ $id =~ ^[a-f0-9]{64}$ && $id == $(jq -r --arg name "$name" '.container_ids[$name]' "$ROLE/manifest.json") ]] || die managed_container_identity_changed
    expected=$APP_ID; [[ $name == db ]] && expected=$DB_ID; [[ $name == gateway ]] && expected=$GATEWAY_ID
    docker_cmd inspect --format '{{json .}}' "$id" | runtime_contract "$name" "$expected" || die managed_runtime_mismatch
  done
  docker_cmd network inspect --format '{{json .}}' capstone-service_private | jq -e \
    '.Internal==true and ([.Containers[].Name]|sort)==["capstone-service-db","capstone-service-dvwa"]' >/dev/null || die private_network_changed
  docker_cmd network inspect --format '{{json .}}' capstone-service_front | jq -e \
    '.Internal==false and ([.Containers[].Name]|sort)==["capstone-service-dvwa"]' >/dev/null || die front_network_changed
  docker_cmd exec capstone-service-dvwa php /opt/capstone-bootstrap.php verify >/dev/null 2>&1 || die dvwa_verification_failed
  verify_offline_apps
  # A deliberately stopped sudo lab is valid; do not restart it to verify installation.
  sudo_terminal_check >/dev/null || die sudo_terminal_verification_failed
  nonweb_runtime verify >/dev/null || die nonweb_runtime_verification_failed
  systemctl is-active --quiet wazuh-agent || die agent_not_active
  grep -Eq "^status='connected'" /var/ossec/var/run/wazuh-agentd.state || die agent_not_connected
  note 'verified: DVWA initialized, DB private, six-item catalog, three pinned web images, three terminal labs including independent rootless sudo, peer ACL configured, Wazuh connected; no attack test executed'
}

main(){
  settings "$@"
  if [[ $MODE == check ]]; then
    if [[ -e $ROLE || -L $ROLE ]]; then assert_managed; else fresh_namespace; fi
    note 'check passed: schema9 fixed web images/wheels/sudo and nonweb bundles; common admin key and enrollment transferred before apply'
    return
  fi
  if [[ $MODE == verify ]]; then verify; return; fi
  if [[ ! -d $CAPSTONE_ROOT ]]; then install -d -o root -g root -m 755 "$CAPSTONE_ROOT"; fi
  safe_path "$CAPSTONE_ROOT"
  if [[ ! -e $CAPSTONE_ROOT/.service-deploy.lock && ! -L $CAPSTONE_ROOT/.service-deploy.lock ]]; then
    (set -o noclobber; : >"$CAPSTONE_ROOT/.service-deploy.lock") || die lock_creation_failed
  fi
  regular "$CAPSTONE_ROOT/.service-deploy.lock"
  [[ $(stat -c '%u:%g:%a' "$CAPSTONE_ROOT/.service-deploy.lock") == 0:0:600 ]] || die unsafe_lock
  exec 9<>"$CAPSTONE_ROOT/.service-deploy.lock"
  flock -n 9 || die concurrent_service_deployment
  if [[ -e $ROLE || -L $ROLE ]]; then verify; return; fi
  fresh_namespace
  offline_command key-check >/dev/null || die lab_common_key_precondition_failed
  [[ -f $WAZUH_CA_FILE && -f $WAZUH_ENROLLMENT_PASS_FILE ]] || die enrollment_prerequisites_missing
  enrollment_inputs
  timeout --kill-after=2s 12s openssl s_client -connect "$SIEM_HOST:1515" -CAfile "$WAZUH_CA_FILE" \
    -verify_ip "$SIEM_HOST" -verify_return_error -no_ign_eof </dev/null >/dev/null 2>&1 || die enrollment_tls_identity_failed
  apache_image_probe
  ssh_macs install || die ssh_macs_install_failed
  write_files
  mark gateway-syntax-test-armed
  gateway_image_probe
  mark gateway-syntax-checked
  mark offline-install-armed
  [[ -f $LAB_ADMIN_KEY_FILE && ! -L $LAB_ADMIN_KEY_FILE ]] || die lab_admin_key_transfer_required
  logrun offline-install bash "$CAPSTONE_SOURCE/infra/groot-c/offline-labs/scripts/install.sh" --apply \
    --manifest "$LAB_MANIFEST" --origin "$LAB_PUBLIC_ORIGIN" --admin-key-file "$LAB_ADMIN_KEY_FILE" "$LAB_WHEEL_DIR"
  mark sudo-runtime-install-armed
  # The dedicated rootless setup can take longer than a container start.
  if ! timeout --kill-after=10s 600s python3 -B "$CAPSTONE_SOURCE/infra/groot-c/offline-labs/nonweb/sudo/runtime/bootstrap.py" \
      --apply --bundle "$LAB_SUDO_BUNDLE" >"$ROLE/evidence/sudo-install.json" 2>"$ROLE/evidence/sudo-install.log"; then
    die sudo_runtime_install_failed_private_evidence_preserved
  fi
  mark nonweb-runtime-install-armed
  # The console account now exists. The separate helper loads its approved
  # Redis/Samba image bundle and starts the terminal service. The sudo adapter
  # keeps its independent rootless runtime and accepts a stopped lab.
  if ! nonweb_runtime apply >"$ROLE/evidence/nonweb-install.json" 2>"$ROLE/evidence/nonweb-install.log"; then
    die nonweb_runtime_install_failed_private_evidence_preserved
  fi
  mark nonweb-runtime-installed
  logrun compose-config "${COMPOSE[@]}" config --quiet
  mark compose-start-armed
  logrun compose-start "${COMPOSE[@]}" up --detach --pull never --no-build --wait --wait-timeout 120
  logrun apache-check "$DOCKER" --host unix:///var/run/docker.sock exec capstone-service-dvwa apachectl -t
  logrun gateway-check "$DOCKER" --host unix:///var/run/docker.sock exec capstone-service-gateway nginx -t -c /etc/capstone-gateway.conf
  mark database-initialization-armed
  # Never repeat this on a partial deployment: existing ROLE without complete
  # manifest is refused at entry, even if the prior command outcome is unknown.
  if ! timeout --kill-after=5s 45s "$DOCKER" --host unix:///var/run/docker.sock exec -i capstone-service-dvwa php /opt/capstone-bootstrap.php init \
       <"$ROLE/credentials/admin-password" >"$ROLE/evidence/db-init.log" 2>&1; then die database_initialization_failed_preserved; fi
  mark database-initialized
  mark lab-verification-armed
  verify_offline_apps
  # A deliberately stopped sudo lab is valid; do not restart it to verify installation.
  sudo_terminal_check >/dev/null || die sudo_terminal_verification_failed
  nonweb_runtime verify >/dev/null || die nonweb_runtime_verification_failed
  mark lab-ready
  configure_agent
  local files='{}' file container_ids='{}' name id
  for file in input.json compose.json config/apache.conf config/bootstrap.php config/gateway.conf \
    config/ossec.conf.candidate credentials/db.env credentials/app.env credentials/admin-password credentials/db-password credentials/db-root-password; do
    files=$(jq -cn --argjson old "$files" --arg name "$file" --arg hash "$(sha "$ROLE/$file")" '$old+{($name):$hash}')
  done
  for name in dvwa db gateway; do
    id=$(docker_cmd ps -aq --no-trunc --filter "name=^/capstone-service-${name}$")
    [[ $id =~ ^[a-f0-9]{64}$ ]] || die created_container_identity_invalid
    container_ids=$(jq -cn --argjson old "$container_ids" --arg name "$name" --arg id "$id" '$old+{($name):$id}')
  done
  jq -nS --argjson files "$files" --arg agent "$(sha /var/ossec/etc/ossec.conf)" \
    --argjson containers "$container_ids" \
    --arg script "$(sha "${BASH_SOURCE[0]}")" --arg ca "$(sha /var/ossec/etc/capstone-manager-ca.pem)" \
    --arg pass "$(sha /var/ossec/etc/capstone-enrollment.pass)" \
    '{schema:9,role:"service",state:"complete",container_ids:$containers,files:$files,agent_config_sha256:$agent,script_sha256:$script,enrollment_ca_sha256:$ca,enrollment_pass_sha256:$pass}' >"$ROLE/manifest.json"
  sync "$ROLE/manifest.json" "$ROLE"
  mark complete
  verify
  note 'apply complete; generated credentials remain in root-only service/credentials'
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
