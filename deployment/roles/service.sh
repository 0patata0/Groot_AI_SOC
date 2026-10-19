#!/usr/bin/env bash
# Fresh Ubuntu 24.04 amd64 service role. No package/image download or image build.
# The lab application is compiled offline during apply unless a JAR is supplied.
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
docker_cmd(){ timeout --kill-after=3s 30s "$DOCKER" "$@"; }
mark(){ printf '%s\n' "$1" >"$ROLE/phase.next"; sync "$ROLE/phase.next"; mv -T "$ROLE/phase.next" "$ROLE/phase"; sync "$ROLE"; }

lab_reference(){ [[ $1 =~ ^([A-Za-z0-9][A-Za-z0-9._/:-]*@)?sha256:[a-f0-9]{64}$ ]]; }
hostname_valid(){
  local name=$1 label; local -a labels
  [[ $name =~ ^[a-z0-9.-]+$ ]] || return 1
  [[ ${#name} -le 253 && $name == *.* && $name != .* && $name != *. && $name != *..* ]] || return 1
  IFS=. read -r -a labels <<<"$name"
  for label in "${labels[@]}"; do [[ $label =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || return 1; done
  [[ ${labels[${#labels[@]}-1]} =~ [a-z] ]]
}
apache_document(){
  cat <<EOF
# Dedicated service deployment. Authorize the connection peer, not spoofable XFF.
ServerName capstone-service
<IfModule !remoteip_module>
LoadModule remoteip_module /usr/lib/apache2/modules/mod_remoteip.so
</IfModule>
RemoteIPHeader X-Forwarded-For
RemoteIPInternalProxy $SECURITY_HOST
<IfModule !proxy_module>
LoadModule proxy_module /usr/lib/apache2/modules/mod_proxy.so
</IfModule>
<IfModule !proxy_http_module>
LoadModule proxy_http_module /usr/lib/apache2/modules/mod_proxy_http.so
</IfModule>
ProxyRequests Off
<VirtualHost *:80>
DocumentRoot /var/www/html
ProxyPass /log4shell/ http://log4shell:8080/log4shell/ connectiontimeout=3 timeout=10
ProxyPassReverse /log4shell/ http://log4shell:8080/log4shell/
<Location "/">
  Require expr "%{CONN_REMOTE_ADDR} == '$SECURITY_HOST' || %{CONN_REMOTE_ADDR} == '127.0.0.1' || %{CONN_REMOTE_ADDR} == '::1'"
</Location>
Alias /dvwa /var/www/html
<Directory /var/www/html>
  Options -Indexes
  AllowOverride All
  Require all granted
</Directory>
LogFormat "%a %l %u %t \\"%r\\" %>s %b \\"%{Referer}i\\" \\"%{User-Agent}i\\"" capstone_combined
CustomLog /var/log/capstone-service/access.log capstone_combined
ErrorLog /var/log/capstone-service/error.log
</VirtualHost>
EOF
  if [[ -n ${LOG4SHELL_HOSTNAME:-} ]]; then
    hostname_valid "$LOG4SHELL_HOSTNAME" || die invalid_log4shell_hostname
    local origin="http://$LOG4SHELL_HOSTNAME"
    [[ ${WAF_PORT:-8080} == 80 ]] || origin="$origin:${WAF_PORT:-8080}"
    cat <<EOF
<VirtualHost *:80>
ServerName $LOG4SHELL_HOSTNAME
DocumentRoot /var/www/html
ProxyPass /log4shell/ http://log4shell:8080/log4shell/ connectiontimeout=3 timeout=10
ProxyPassReverse /log4shell/ http://log4shell:8080/log4shell/
RedirectMatch 302 "^/(?!log4shell/).*" "$origin/log4shell/"
<Location "/">
  Require expr "%{CONN_REMOTE_ADDR} == '$SECURITY_HOST' || %{CONN_REMOTE_ADDR} == '127.0.0.1' || %{CONN_REMOTE_ADDR} == '::1'"
</Location>
<Directory /var/www/html>
  Options -Indexes
  AllowOverride All
  Require all granted
</Directory>
LogFormat "%a %l %u %t \\"%r\\" %>s %b \\"%{Referer}i\\" \\"%{User-Agent}i\\"" capstone_combined
CustomLog /var/log/capstone-service/access.log capstone_combined
ErrorLog /var/log/capstone-service/error.log
</VirtualHost>
EOF
  fi
}
lab_jar_check(){
  python3 -B "$CAPSTONE_SOURCE/deployment/validate_log4shell_jar.py" "$1"
}
lab_source_check(){
  python3 -B "$CAPSTONE_SOURCE/infra/groot-c/log4shell-app/tools/prepare_from_image.py" check "$CAPSTONE_SOURCE"
}
prepare_lab_jar(){
  if [[ $LAB_JAR_MODE == auto ]]; then
    # This is the first preparation step after creating the private role
    # directories. A compiler failure cannot deploy any service container.
    if ! python3 -B "$CAPSTONE_SOURCE/infra/groot-c/log4shell-app/tools/prepare_from_image.py" \
        build "$CAPSTONE_SOURCE" "$LAB_ID" "$ROLE/config/log4shell-app.jar" \
        --expected-source-sha256 "$LAB_SOURCE_SHA" --docker "$DOCKER" \
        >"$ROLE/evidence/log4shell-build.json" 2>"$ROLE/evidence/log4shell-build.log"; then
      die offline_log4shell_build_failed_private_evidence_preserved
    fi
    LAB_JAR_SHA=$(lab_jar_check "$ROLE/config/log4shell-app.jar") || die invalid_built_log4shell_jar
    jq -e --arg source "$LAB_SOURCE_SHA" --arg image "$LAB_ID" --arg jar "$LAB_JAR_SHA" \
      '.schema==1 and .mode=="offline-image-jdk" and .source_sha256==$source and .image_id==$image and
       .package.output_sha256==$jar and .package.dependencies_unchanged==true and
       .package.loader_and_metadata_unchanged==true and .temporary_containers_removed==true' \
      "$ROLE/evidence/log4shell-build.json" >/dev/null || die offline_build_evidence_mismatch
  else
    [[ $(lab_jar_check "$LOG4SHELL_APP_JAR") == "$LAB_JAR_SHA" ]] || die lab_jar_changed_before_copy
    install -o root -g root -m 0644 "$LOG4SHELL_APP_JAR" "$ROLE/config/log4shell-app.jar"
    [[ $(sha "$ROLE/config/log4shell-app.jar") == "$LAB_JAR_SHA" ]] || die lab_jar_changed_during_copy
    jq -nS --arg jar "$LAB_JAR_SHA" '{schema:1,mode:"provided",output_sha256:$jar}' >"$ROLE/evidence/log4shell-build.json"
  fi
}

apache_image_probe(){
  local cid outcome=1
  cid=$(docker_cmd create --pull never --network none --read-only \
    --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 32 --memory 128m \
    --label io.capstone.portable.apache-probe=service --entrypoint sh "$APP_ID" \
    -c 'test -r /usr/lib/apache2/modules/mod_proxy.so && test -r /usr/lib/apache2/modules/mod_proxy_http.so && php -m | grep -qx mysqli') || die apache_probe_creation_failed
  [[ $cid =~ ^[a-f0-9]{64}$ ]] || die invalid_apache_probe_identity
  if timeout --kill-after=2s 20s "$DOCKER" start --attach "$cid" >/dev/null 2>&1; then outcome=0; fi
  docker_cmd rm --force "$cid" >/dev/null || die apache_probe_cleanup_failed
  [[ $outcome == 0 ]] || die preloaded_dvwa_requires_proxy_modules_and_mysqli
}

compose_document(){
  jq -n --arg app "$APP_ID" --arg db "$DB_ID" --arg lab "$LAB_ID" --arg bind "$SERVICE_HOST:$WEB_BACKEND_PORT:80" \
    '{services:{dvwa:{image:$app,container_name:"capstone-service-dvwa",pull_policy:"never",
      restart:"unless-stopped",env_file:["./credentials/app.env"],ports:[$bind],
      networks:["front","private","lab"],depends_on:{db:{condition:"service_healthy"},log4shell:{condition:"service_started"}},
      volumes:["./config/apache.conf:/etc/apache2/sites-enabled/000-default.conf:ro",
        "./config/bootstrap.php:/opt/capstone-bootstrap.php:ro",
        "./logs:/var/log/capstone-service"],
      labels:{"io.capstone.role":"service"},security_opt:["no-new-privileges:true"],pids_limit:256,
      healthcheck:{test:["CMD","php","-r","exit(strpos(@file_get_contents(\"http://127.0.0.1/login.php\"),\"DVWA\")!==false?0:1);"],interval:"5s",timeout:"3s",retries:24},
      logging:{driver:"json-file",options:{"max-size":"10m","max-file":"3"}}},
    db:{image:$db,container_name:"capstone-service-db",pull_policy:"never",restart:"unless-stopped",
      env_file:["./credentials/db.env"],networks:["private"],volumes:["database:/var/lib/mysql"],
      healthcheck:{test:["CMD","healthcheck.sh","--connect","--innodb_initialized"],interval:"5s",timeout:"3s",retries:30},
      labels:{"io.capstone.role":"service"},security_opt:["no-new-privileges:true"],pids_limit:256,
      logging:{driver:"json-file",options:{"max-size":"10m","max-file":"3"}}},
    log4shell:{image:$lab,container_name:"capstone-service-log4shell",pull_policy:"never",restart:"unless-stopped",
      entrypoint:["java"],command:["-jar","/app/spring-boot-application.jar"],working_dir:"/app",
      user:"65532:65532",read_only:true,cap_drop:["ALL"],security_opt:["no-new-privileges:true"],
      pids_limit:128,mem_limit:"512m",cpus:1.0,dns:["127.0.0.1"],networks:["lab"],
      tmpfs:["/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777"],healthcheck:{disable:true},
      volumes:[{type:"bind",source:"./config/log4shell-app.jar",target:"/app/spring-boot-application.jar",
        read_only:true,bind:{create_host_path:false}}],
      environment:{TZ:"Asia/Seoul",JAVA_TOOL_OPTIONS:"-Xms64m -Xmx256m -Duser.timezone=Asia/Seoul",
        SERVER_ADDRESS:"0.0.0.0",SERVER_PORT:"8080",SERVER_SERVLET_CONTEXT_PATH:"/log4shell",LOGGING_CONFIG:"classpath:log4j2-spring.xml"},
      labels:{"io.capstone.role":"service"},
      logging:{driver:"json-file",options:{"max-size":"10m","max-file":"3"}}}},
      networks:{front:{},private:{internal:true},lab:{internal:true}},volumes:{database:{}}}'
}

settings(){
  [[ $# == 1 && $1 =~ ^(check|apply|verify)$ ]] || die 'usage: bash service.sh check|apply|verify'
  MODE=$1
  [[ $EUID == 0 && $(uname -m) == x86_64 ]] || die root_amd64_required
  [[ $(. /etc/os-release; printf '%s:%s' "$ID" "$VERSION_ID") == ubuntu:24.04 ]] || die ubuntu_24_04_required
  : "${CAPSTONE_ROOT:=/opt/capstone}" "${CAPSTONE_SOURCE:?uploaded_source_required}"
  : "${SECURITY_HOST:?}" "${SIEM_HOST:?}" "${SERVICE_HOST:?}" "${WEB_BACKEND_PORT:=80}" "${WAF_PORT:=8080}" "${LOG4SHELL_HOSTNAME:=}"
  : "${DVWA_IMAGE:=ghcr.io/digininja/dvwa:latest}" "${MARIADB_IMAGE:=mariadb:10}"
  : "${LOG4SHELL_IMAGE:=ghcr.io/christophetd/log4shell-vulnerable-app@sha256:6f88430688108e512f7405ac3c73d47f5c370780b94182854ea2cddc6bd59929}"
  : "${LOG4SHELL_APP_JAR:=}"
  : "${WAZUH_CA_FILE:=/opt/capstone-prereqs/wazuh-root-ca.pem}"
  : "${WAZUH_ENROLLMENT_PASS_FILE:=/opt/capstone-prereqs/wazuh-enrollment.pass}"
  for value in "$SECURITY_HOST" "$SIEM_HOST" "$SERVICE_HOST"; do ipv4 "$value" || die literal_ipv4_required; done
  [[ $SECURITY_HOST != "$SIEM_HOST" && $SECURITY_HOST != "$SERVICE_HOST" && $SIEM_HOST != "$SERVICE_HOST" ]] || die distinct_hosts_required
  [[ $WEB_BACKEND_PORT =~ ^[1-9][0-9]{0,4}$ ]] && ((WEB_BACKEND_PORT<=65535)) || die invalid_backend_port
  [[ $WEB_BACKEND_PORT != 22 && $WEB_BACKEND_PORT != 1514 && $WEB_BACKEND_PORT != 1515 ]] || die reserved_port
  [[ $WAF_PORT =~ ^[1-9][0-9]{0,4}$ ]] && ((WAF_PORT<=65535)) || die invalid_waf_port
  [[ -z $LOG4SHELL_HOSTNAME ]] || hostname_valid "$LOG4SHELL_HOSTNAME" || die invalid_log4shell_hostname
  for value in "$DVWA_IMAGE" "$MARIADB_IMAGE"; do [[ $value =~ ^[a-zA-Z0-9][a-zA-Z0-9._/:@-]+$ ]] || die invalid_image_reference; done
  lab_reference "$LOG4SHELL_IMAGE" || die log4shell_digest_or_image_id_required
  safe_path "$CAPSTONE_ROOT"; source_path
  [[ -d $CAPSTONE_SOURCE/deployment/roles ]] || die uploaded_source_missing
  ROLE=$CAPSTONE_ROOT/service
  for tool in docker jq python3 openssl timeout ip ss flock nsenter sha256sum sync systemctl; do command -v "$tool" >/dev/null || die "preinstall_${tool}_required"; done
  DOCKER=$(command -v docker)
  COMPOSE=("$DOCKER" compose --project-name capstone-service --project-directory "$ROLE" -f "$ROLE/compose.json")
  [[ -x /var/ossec/bin/wazuh-agentd && -x /var/ossec/bin/wazuh-logcollector ]] || die preinstall_wazuh_agent_required
  [[ $(dpkg-query -W -f='${Version}' wazuh-agent 2>/dev/null) == 4.14.8-* ]] || die wazuh_agent_4_14_8_required
  docker_cmd info --format '{{.OSType}}/{{.Architecture}}' | grep -Eq '^linux/(x86_64|amd64)$' || die native_docker_required
  docker_cmd compose version >/dev/null || die compose_plugin_required
  ip -j address show | jq -e --arg ip "$SERVICE_HOST" 'any(.[] .addr_info[]?; .family=="inet" and .local==$ip)' >/dev/null || die service_ip_not_local
  APP_ID=$(docker_cmd image inspect --format '{{.Id}} {{.Os}} {{.Architecture}}' "$DVWA_IMAGE") || die preloaded_dvwa_image_required
  DB_ID=$(docker_cmd image inspect --format '{{.Id}} {{.Os}} {{.Architecture}}' "$MARIADB_IMAGE") || die preloaded_mariadb_image_required
  LAB_ID=$(docker_cmd image inspect --format '{{.Id}} {{.Os}} {{.Architecture}}' "$LOG4SHELL_IMAGE") || die preloaded_log4shell_image_required
  [[ $APP_ID =~ ^sha256:[a-f0-9]{64}\ linux\ amd64$ && $DB_ID =~ ^sha256:[a-f0-9]{64}\ linux\ amd64$ && $LAB_ID =~ ^sha256:[a-f0-9]{64}\ linux\ amd64$ ]] || die amd64_images_required
  APP_ID=${APP_ID%% *}; DB_ID=${DB_ID%% *}; LAB_ID=${LAB_ID%% *}
  # Compose declares Java, arguments and workdir explicitly. The pinned image
  # supplies the reviewed JDK/JRE; its default entrypoint/CMD are never inherited.
  regular "$CAPSTONE_SOURCE/deployment/validate_log4shell_jar.py"
  regular "$CAPSTONE_SOURCE/deployment/verify_log4shell_app.py"
  LAB_VALIDATOR_SHA=$(sha "$CAPSTONE_SOURCE/deployment/validate_log4shell_jar.py")
  LAB_VERIFIER_SHA=$(sha "$CAPSTONE_SOURCE/deployment/verify_log4shell_app.py")
  LAB_JAR_MODE=auto; LAB_JAR_SHA=; LAB_SOURCE_SHA=
  if [[ -n $LOG4SHELL_APP_JAR ]]; then
    LAB_JAR_MODE=provided
    [[ $LOG4SHELL_APP_JAR == /opt/* && $LOG4SHELL_APP_JAR == *.jar ]] || die invalid_log4shell_jar_path
    safe_path "${LOG4SHELL_APP_JAR%/*}"; regular "$LOG4SHELL_APP_JAR"
    [[ $(stat -c %u "$LOG4SHELL_APP_JAR") == 0 ]] || die prepared_jar_must_be_root_owned
    (( (8#$(stat -c %a "$LOG4SHELL_APP_JAR") & 0022) == 0 )) || die prepared_jar_must_not_be_writable
    LAB_JAR_SHA=$(lab_jar_check "$LOG4SHELL_APP_JAR") || die invalid_prepared_log4shell_jar
  else
    # Read-only precheck: no container, compiler, output directory or JAR.
    LAB_SOURCE_SHA=$(lab_source_check | jq -er '.source_sha256|select(test("^[a-f0-9]{64}$"))') || die offline_lab_sources_invalid
  fi
  INPUT=$(jq -cnS --arg root "$CAPSTONE_ROOT" --arg a "$SECURITY_HOST" --arg b "$SIEM_HOST" --arg c "$SERVICE_HOST" \
    --argjson port "$WEB_BACKEND_PORT" --arg app "$APP_ID" --arg db "$DB_ID" --arg lab "$LAB_ID" \
    --arg labref "$LOG4SHELL_IMAGE" --arg jar "$LAB_JAR_SHA" --arg validator "$LAB_VALIDATOR_SHA" --arg verifier "$LAB_VERIFIER_SHA" \
    --arg jarmode "$LAB_JAR_MODE" --arg source "$LAB_SOURCE_SHA" \
    --arg labhost "$LOG4SHELL_HOSTNAME" --argjson wafport "$WAF_PORT" \
    '{schema:6,role:"service",root:$root,security_host:$a,siem_host:$b,service_host:$c,port:$port,app_image_id:$app,db_image_id:$db,lab_image_id:$lab,lab_image_ref:$labref,lab_jar_mode:$jarmode,lab_source_sha256:$source,lab_jar_sha256:$jar,lab_validator_sha256:$validator,lab_verifier_sha256:$verifier,log4shell_hostname:$labhost,public_waf_port:$wafport}')
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
  for name in capstone-service-dvwa capstone-service-db capstone-service-log4shell; do
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
  fresh_agent
}
assert_managed(){
  safe_path "$ROLE"
  regular "$ROLE/manifest.json"; regular "$ROLE/input.json"
  [[ $(stat -c '%u:%g:%a' "$ROLE") == 0:0:700 ]] || die role_permissions_changed
  [[ $(cat "$ROLE/input.json") == "$INPUT" ]] || die changed_inputs_require_manual_migration
  [[ $(stat -c '%u:%g:%a' "$ROLE/manifest.json") == 0:0:600 ]] || die manifest_permissions_changed
  jq -e 'keys==["agent_config_sha256","enrollment_ca_sha256","enrollment_pass_sha256","files","role","schema","script_sha256","state"] and
    .schema==6 and .role=="service" and .state=="complete" and
    ([.agent_config_sha256,.enrollment_ca_sha256,.enrollment_pass_sha256,.script_sha256]|all(type=="string" and test("^[a-f0-9]{64}$"))) and
    (.files|keys)==["compose.json","config/apache.conf","config/bootstrap.php","config/log4shell-app.jar","config/ossec.conf.candidate","config/verify-log4shell.py","credentials/admin-password","credentials/app.env","credentials/db-password","credentials/db-root-password","credentials/db.env","evidence/log4shell-build.json","input.json"] and
    (.files|all(type=="string" and test("^[a-f0-9]{64}$")))' "$ROLE/manifest.json" >/dev/null || die deployment_incomplete
  [[ $(sha "${BASH_SOURCE[0]}") == $(jq -r .script_sha256 "$ROLE/manifest.json") ]] || die deployment_script_changed
  local file expected mode
  while IFS=$'\t' read -r file expected; do
    [[ $file =~ ^[a-zA-Z0-9._/-]+$ && $file != *..* && $file != /* ]] || die manifest_path_invalid
    regular "$ROLE/$file"
    if [[ $file == */* ]]; then safe_path "$ROLE/${file%/*}"; fi
    mode=600; [[ $file == config/apache.conf || $file == config/bootstrap.php || $file == config/log4shell-app.jar ]] && mode=644
    [[ $(stat -c '%u:%g:%a' "$ROLE/$file") == "0:0:$mode" ]] || die managed_permissions_changed
    [[ $(sha "$ROLE/$file") == "$expected" ]] || die managed_file_changed
  done < <(jq -r '.files|to_entries[]|[.key,.value]|@tsv' "$ROLE/manifest.json")
  if [[ $LAB_JAR_MODE == auto ]]; then
    LAB_JAR_SHA=$(lab_jar_check "$ROLE/config/log4shell-app.jar") || die installed_lab_jar_invalid
    jq -e --arg source "$LAB_SOURCE_SHA" --arg image "$LAB_ID" --arg jar "$LAB_JAR_SHA" \
      '.schema==1 and .mode=="offline-image-jdk" and .source_sha256==$source and .image_id==$image and
       .package.output_sha256==$jar and .package.dependencies_unchanged==true and
       .package.loader_and_metadata_unchanged==true and .temporary_containers_removed==true' \
      "$ROLE/evidence/log4shell-build.json" >/dev/null || die installed_lab_build_evidence_changed
  else
    [[ $(sha "$ROLE/config/log4shell-app.jar") == "$LAB_JAR_SHA" ]] || die installed_lab_jar_changed
  fi
  [[ $(sha "$ROLE/config/verify-log4shell.py") == "$LAB_VERIFIER_SHA" ]] || die installed_lab_verifier_changed
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
  prepare_lab_jar
  install -o root -g root -m 0600 "$CAPSTONE_SOURCE/deployment/verify_log4shell_app.py" "$ROLE/config/verify-log4shell.py"
  [[ $(sha "$ROLE/config/verify-log4shell.py") == "$LAB_VERIFIER_SHA" ]] || die lab_verifier_changed_during_copy
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
  chmod 644 "$ROLE/config/apache.conf" "$ROLE/config/bootstrap.php"
  sync "$ROLE/input.json" "$ROLE/compose.json" "$ROLE/config/apache.conf" "$ROLE/config/bootstrap.php" \
    "$ROLE/config/log4shell-app.jar" "$ROLE/config/verify-log4shell.py" \
    "$ROLE/evidence/log4shell-build.json" \
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
  [[ $name == dvwa || $name == db || $name == log4shell ]] || return 1
  jq -e --arg project capstone-service --arg image "$expected" --arg name "$name" \
    --arg root "$ROLE" --arg ip "$SERVICE_HOST" --arg port "$WEB_BACKEND_PORT" '
    def env_is($key; $value): [.Config.Env[]? | select(startswith($key+"="))]==[$key+"="+$value];
    .State.Running==true and .State.Restarting==false and .Image==$image and
    .Config.Labels["com.docker.compose.project"]==$project and .Config.Labels["com.docker.compose.service"]==$name and
    .HostConfig.Privileged==false and .HostConfig.RestartPolicy.Name=="unless-stopped" and
    ((.HostConfig.SecurityOpt//[])|any(.=="no-new-privileges:true" or .=="no-new-privileges")) and
    (if $name=="log4shell" then
      .State.Health==null and .Config.Healthcheck.Test==["NONE"] and
      .Config.User=="65532:65532" and .Config.Cmd==["-jar","/app/spring-boot-application.jar"] and
      .Config.Entrypoint==["java"] and .Config.WorkingDir=="/app" and .HostConfig.ReadonlyRootfs==true and
      .HostConfig.CapDrop==["ALL"] and ((.HostConfig.CapAdd//[])|length)==0 and
      .HostConfig.PidsLimit==128 and .HostConfig.Memory==536870912 and .HostConfig.NanoCpus==1000000000 and
      .HostConfig.Dns==["127.0.0.1"] and
      .HostConfig.Tmpfs=={"/tmp":"rw,nosuid,nodev,noexec,size=64m,mode=1777"} and
      ((.HostConfig.PortBindings//{})|length)==0 and
      (.NetworkSettings.Networks|keys)==["capstone-service_lab"] and
      ((.Mounts|map(select(.Type!="tmpfs")|{Type,Source,Destination,RW}))==[
        {Type:"bind",Source:($root+"/config/log4shell-app.jar"),Destination:"/app/spring-boot-application.jar",RW:false}]) and
      all(.Mounts[]?; .Type!="tmpfs" or .Destination=="/tmp") and
      env_is("TZ"; "Asia/Seoul") and
      env_is("JAVA_TOOL_OPTIONS"; "-Xms64m -Xmx256m -Duser.timezone=Asia/Seoul") and
      env_is("SERVER_ADDRESS"; "0.0.0.0") and env_is("SERVER_PORT"; "8080") and
      env_is("SERVER_SERVLET_CONTEXT_PATH"; "/log4shell") and
      env_is("LOGGING_CONFIG"; "classpath:log4j2-spring.xml")
    elif $name=="db" then
      .State.Health.Status=="healthy" and ((.HostConfig.PortBindings//{})|length)==0 and
      (.Mounts|length)==1 and .Mounts[0].Type=="volume" and .Mounts[0].Name=="capstone-service_database" and
      .Mounts[0].Destination=="/var/lib/mysql" and .Mounts[0].RW==true and
      (.NetworkSettings.Networks|keys)==["capstone-service_private"]
    else
      .State.Health.Status=="healthy" and
      .HostConfig.PortBindings=={"80/tcp":[{"HostIp":$ip,"HostPort":$port}]} and
      (.NetworkSettings.Networks|keys)==["capstone-service_front","capstone-service_lab","capstone-service_private"] and
      ((.Mounts|map({Type,Source,Destination,RW})|sort_by(.Destination))==([
        {Type:"bind",Source:($root+"/config/apache.conf"),Destination:"/etc/apache2/sites-enabled/000-default.conf",RW:false},
        {Type:"bind",Source:($root+"/config/bootstrap.php"),Destination:"/opt/capstone-bootstrap.php",RW:false},
        {Type:"bind",Source:($root+"/logs"),Destination:"/var/log/capstone-service",RW:true}]|sort_by(.Destination)))
    end)' >/dev/null
}
verify_lab_app(){
  local deadline=$((SECONDS+90)) pid
  pid=$(docker_cmd inspect --format '{{.State.Pid}}' capstone-service-dvwa) || die service_namespace_unavailable
  [[ $pid =~ ^[1-9][0-9]*$ ]] || die service_namespace_unavailable
  while ((SECONDS<deadline)); do
    # Only enter the network namespace: Python, source and files stay on host.
    if nsenter --target "$pid" --net -- python3 -B "$ROLE/config/verify-log4shell.py" "http://127.0.0.1/log4shell/" \
         "$LOG4SHELL_HOSTNAME" "$WAF_PORT" >/dev/null 2>&1; then
      return
    fi
    sleep 2
  done
  die log4shell_spring_route_or_logging_verification_failed
}
verify(){
  assert_managed
  local name id expected
  for name in dvwa db log4shell; do
    id=$(docker_cmd ps -aq --filter "name=^/capstone-service-${name}$")
    [[ $id =~ ^[a-f0-9]{12,64}$ ]] || die managed_container_missing
    expected=$APP_ID; [[ $name == db ]] && expected=$DB_ID; [[ $name == log4shell ]] && expected=$LAB_ID
    docker_cmd inspect --format '{{json .}}' "$id" | runtime_contract "$name" "$expected" || die managed_runtime_mismatch
  done
  docker_cmd network inspect --format '{{json .}}' capstone-service_private | jq -e \
    '.Internal==true and ([.Containers[].Name]|sort)==["capstone-service-db","capstone-service-dvwa"]' >/dev/null || die private_network_changed
  docker_cmd network inspect --format '{{json .}}' capstone-service_lab | jq -e \
    '.Internal==true and ([.Containers[].Name]|sort)==["capstone-service-dvwa","capstone-service-log4shell"]' >/dev/null || die lab_network_changed
  docker_cmd network inspect --format '{{json .}}' capstone-service_front | jq -e \
    '.Internal==false and ([.Containers[].Name]|sort)==["capstone-service-dvwa"]' >/dev/null || die front_network_changed
  docker_cmd exec capstone-service-dvwa php /opt/capstone-bootstrap.php verify >/dev/null 2>&1 || die dvwa_verification_failed
  verify_lab_app
  systemctl is-active --quiet wazuh-agent || die agent_not_active
  grep -Eq "^status='connected'" /var/ossec/var/run/wazuh-agentd.state || die agent_not_connected
  note 'verified: DVWA initialized, DB private, isolated Spring Log4Shell UI/runtime versions and benign logging, peer ACL configured, Wazuh connected; no attack test executed'
}

main(){
  settings "$@"
  if [[ $MODE == check ]]; then
    if [[ -e $ROLE || -L $ROLE ]]; then assert_managed; else fresh_namespace; fi
    note "check passed: installed prerequisites/local images; lab JAR mode=$LAB_JAR_MODE (automatic compilation only at apply); enrollment prerequisites required at apply"
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
  [[ -f $WAZUH_CA_FILE && -f $WAZUH_ENROLLMENT_PASS_FILE ]] || die enrollment_prerequisites_missing
  enrollment_inputs
  timeout --kill-after=2s 12s openssl s_client -connect "$SIEM_HOST:1515" -CAfile "$WAZUH_CA_FILE" \
    -verify_ip "$SIEM_HOST" -verify_return_error -no_ign_eof </dev/null >/dev/null 2>&1 || die enrollment_tls_identity_failed
  apache_image_probe
  write_files
  logrun compose-config "${COMPOSE[@]}" config --quiet
  mark compose-start-armed
  logrun compose-start "${COMPOSE[@]}" up --detach --pull never --no-build --wait --wait-timeout 120
  logrun apache-check "$DOCKER" exec capstone-service-dvwa apachectl -t
  mark database-initialization-armed
  # Never repeat this on a partial deployment: existing ROLE without complete
  # manifest is refused at entry, even if the prior command outcome is unknown.
  if ! timeout --kill-after=5s 45s "$DOCKER" exec -i capstone-service-dvwa php /opt/capstone-bootstrap.php init \
       <"$ROLE/credentials/admin-password" >"$ROLE/evidence/db-init.log" 2>&1; then die database_initialization_failed_preserved; fi
  mark database-initialized
  mark lab-verification-armed
  verify_lab_app
  mark lab-ready
  configure_agent
  local files='{}' file
  for file in input.json compose.json config/apache.conf config/bootstrap.php config/verify-log4shell.py \
    config/log4shell-app.jar evidence/log4shell-build.json \
    config/ossec.conf.candidate credentials/db.env credentials/app.env credentials/admin-password credentials/db-password credentials/db-root-password; do
    files=$(jq -cn --argjson old "$files" --arg name "$file" --arg hash "$(sha "$ROLE/$file")" '$old+{($name):$hash}')
  done
  jq -nS --argjson files "$files" --arg agent "$(sha /var/ossec/etc/ossec.conf)" \
    --arg script "$(sha "${BASH_SOURCE[0]}")" --arg ca "$(sha /var/ossec/etc/capstone-manager-ca.pem)" \
    --arg pass "$(sha /var/ossec/etc/capstone-enrollment.pass)" \
    '{schema:6,role:"service",state:"complete",files:$files,agent_config_sha256:$agent,script_sha256:$script,enrollment_ca_sha256:$ca,enrollment_pass_sha256:$pass}' >"$ROLE/manifest.json"
  sync "$ROLE/manifest.json" "$ROLE"
  mark complete
  verify
  note 'apply complete; generated credentials remain in root-only service/credentials'
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
