#!/usr/bin/env python3
"""Fresh-host SOC management extension, invoked only by root deploy.sh.

No download, package install, remote shell, automatic approval, or attack test.
check is read-only. export-siem is a secret stdout stream intended exclusively
for the controller's authenticated SSH pipe; other results are sanitized JSON.
Partial installations are retained and cannot be silently adopted or retried.
"""
import argparse
import ast
import base64
import contextlib
import hashlib
import grp
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.dont_write_bytecode = True  # check also stays read-only without an external -B flag.
from soc_runtime import Refused, agent_ar, firewall, manager_ar, need, render, validate_profile, verify_agent_ar, verify_firewall
from report_publisher import provision as provision_report_publisher

STATE = Path("/var/lib/capstone-soc")
CODE = Path("/opt/capstone-soc")
FIXED_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
             "LC_ALL": "C.UTF-8", "TZ": "Asia/Seoul", "PYTHONDONTWRITEBYTECODE": "1"}
SOURCES = tuple("infra/mcp/" + name for name in (
    "rule_change_executor.py", "rule_change_mcp.py", "rule_readonly_install.py", "service_action_executor.py", "incident_containment.py",
    "soc_bot.py", "soc_management_events.py", "operations_approval.py", "approval_card_cleanup.py",
    "response-mcp.py", "wazuh_containment_ar.py", "managed_suricata_evidence.py")) + tuple("infra/hermes/" + name for name in (
    "soc_management_controller.py", "soc_management_run.py", "soc_alert_watch.prompt", "SOUL.groot.md",
    "capstone-management.service.example", "capstone-management.timer.example")) + (
    "deployment/soc_management.py", "deployment/soc_runtime.py", "deployment/soc_agent_block.py", "deployment/response_entrypoint.py",
    "deployment/report_publisher.py")
PRIVATE = (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"), ipaddress.ip_network("192.168.0.0/16"))


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value, "duplicate_json_key")
        value[key] = item
    return value


def parse(raw):
    return json.loads(raw, object_pairs_hook=unique)


def trusted_directory(path):
    path = Path(path)
    for p in (path, *path.parents):
        s = p.lstat()
        stage = p == Path("/var/tmp") and stat.S_IMODE(s.st_mode) == 0o1777 and \
            re.fullmatch(r"capstone-bootstrap-[0-9a-f]{24}", path.parts[3] if len(path.parts) > 3 else "")
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and (stage or not s.st_mode & 0o022), "untrusted_directory")


def read(path, limit=4 * 1024 * 1024, secret=False):
    path = Path(path); trusted_directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1 and
             not s.st_mode & 0o022 and 0 <= s.st_size <= limit, "untrusted_file")
        if secret:
            need(stat.S_IMODE(s.st_mode) == 0o600, "root_private_file_required")
        data = os.read(fd, limit + 1)
        identity = lambda x: (x.st_dev, x.st_ino, x.st_mode, x.st_uid, x.st_gid, x.st_nlink, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
        need(len(data) == s.st_size and identity(s) == identity(os.fstat(fd)) == identity(path.lstat()), "file_changed")
        return data
    finally:
        os.close(fd)


def mkdir(path, mode=0o700, uid=0, gid=0):
    p = Path(path)
    if p.exists() or p.is_symlink():
        trusted_directory(p)
        need(p.stat().st_uid == uid and p.stat().st_gid == gid and stat.S_IMODE(p.stat().st_mode) == mode, "directory_owner_or_mode_changed")
        return
    trusted_directory(p.parent)
    p.mkdir(mode=mode); os.chown(p, uid, gid); os.chmod(p, mode)


def write(path, data, mode=0o600, uid=0, gid=0):
    p = Path(path); trusted_directory(p.parent)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode); os.fchown(fd, uid, gid)
        with os.fdopen(fd, "wb", closefd=False) as output:
            output.write(data); output.flush(); os.fsync(fd)
    finally:
        os.close(fd)


def replace_owned(path, data, *, uid=0, mode=None, wazuh_gid=None):
    """Existing bind-mounted configuration: preserve its inode and owner."""
    p = Path(path); s = p.lstat()
    group_exception = wazuh_gid is not None and s.st_gid == wazuh_gid and stat.S_IMODE(s.st_mode) == 0o660
    need(stat.S_ISREG(s.st_mode) and s.st_uid == uid and s.st_nlink == 1 and
         (not s.st_mode & 0o022 or group_exception), "replacement_not_owned")
    fd = os.open(p, os.O_WRONLY | os.O_NOFOLLOW)
    try:
        need((s.st_dev, s.st_ino) == (os.fstat(fd).st_dev, os.fstat(fd).st_ino), "replacement_inode_changed")
        with os.fdopen(fd, "wb", closefd=False) as output:
            output.write(data); output.truncate(); output.flush(); os.fsync(fd)
        if mode is not None:
            os.fchmod(fd, mode)
    finally:
        os.close(fd)


def run(argv, data=None, timeout=45):
    result = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=FIXED_ENV, timeout=timeout, check=False)
    need(len(result.stdout) <= 16 * 1024 * 1024 and len(result.stderr) <= 2 * 1024 * 1024, "command_output_limit")
    need(result.returncode == 0, "command_failed_" + Path(argv[0]).name)
    return result.stdout


def docker(*args, timeout=45):
    binary = shutil.which("docker", path=FIXED_ENV["PATH"])
    need(binary in ("/usr/bin/docker", "/usr/local/bin/docker"), "supported_local_docker_required")
    read(binary, 128 * 1024 * 1024)
    return run([binary, "--host", "unix:///var/run/docker.sock", *args], timeout=timeout)


def inspect(name, project):
    value = parse(docker("inspect", name))
    need(type(value) is list and len(value) == 1, "container_inspection")
    item = value[0]
    need(item["Name"] == "/" + name and re.fullmatch(r"[0-9a-f]{64}", item["Id"]) and
         item["Config"].get("Labels", {}).get("com.docker.compose.project") == project and
         item["State"]["Running"] and not item["State"].get("Restarting"), "owned_running_container_required")
    return item


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Refused("HTTP_redirect_refused")


def request(url, method="GET", body=None, headers=None, ca=None):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca)) if ca else ssl.create_default_context()))
    h = {"Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(url, data=canonical(body) if body is not None else None, headers=h, method=method)
    try:
        with opener.open(req, timeout=20) as response:
            data = response.read(2 * 1024 * 1024 + 1)
            need(len(data) <= 2 * 1024 * 1024, "HTTP_response_limit")
            return data, dict(response.headers)
    except (OSError, urllib.error.HTTPError, ValueError):
        raise Refused("application_API_failed") from None


def settings(environ=None):
    env = os.environ if environ is None else environ
    need(env.get("CAPSTONE_ROOT", "/opt/capstone") == "/opt/capstone", "fixed_capstone_root_required")
    source = Path(env.get("CAPSTONE_SOURCE", ""))
    need(source.is_absolute(), "source_required")
    hosts = {}
    for key in ("SECURITY_HOST", "SIEM_HOST", "SERVICE_HOST"):
        ip = ipaddress.IPv4Address(env.get(key, ""))
        need(str(ip) == env[key] and any(ip in net for net in PRIVATE), "private_host_required")
        hosts[key] = str(ip)
    need(len(set(hosts.values())) == 3, "distinct_hosts_required")
    interface = env.get("MONITOR_INTERFACE", "ens192")
    need(re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", interface), "interface_invalid")
    port = int(env.get("SSH_PORT", "22")); need(1 <= port <= 65535, "SSH_port_invalid")
    protected = set(hosts.values())
    supplied = env.get("LOG_PROTECTED_IPS", "")
    for item in supplied.split(",") if supplied else []:
        ip = ipaddress.IPv4Address(item); need(str(ip) == item, "protected_IP_invalid"); protected.add(item)
    endpoint = urllib.parse.urlsplit(env.get("LLM_BASE_URL", ""))
    need(endpoint.scheme in ("http", "https") and endpoint.hostname, "LLM_endpoint_required")
    try:
        protected.add(str(ipaddress.IPv4Address(endpoint.hostname)))
    except ValueError:
        need(bool(supplied), "hostname_LLM_requires_explicit_protected_IPs")
    admin = []
    for item in env.get("ADMIN_PROTECTED_CIDRS", "").split(","):
        if not item:
            continue
        net = ipaddress.IPv4Network(item, strict=True)
        need(str(net) == item and net.prefixlen > 0, "canonical_admin_CIDR_required")
        admin.append(str(net))
    return {"source": source, "hosts": hosts, "interface": interface, "ssh_port": port,
            "protected_ips": sorted(protected), "waf_port": int(env.get("WAF_PORT", "8080")),
            "admin_protected_cidrs": sorted(set(admin))}


def source_bundle(s):
    result = {}
    for relative in SOURCES:
        data = read(s["source"] / relative)
        if relative.endswith(".py"):
            ast.parse(data)
        result[Path(relative).name] = data
    return result


def public_key(raw):
    parts = raw.decode("ascii").strip().split()
    need(len(parts) in (2, 3) and parts[0] == "ssh-ed25519" and
         re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", parts[1]), "Ed25519_public_key_required")
    value = base64.b64decode(parts[1], validate=True)
    need(len(value) == 51 and value[:4] == b"\0\0\0\x0b" and value[4:15] == b"ssh-ed25519", "public_key_encoding")
    return " ".join(parts[:2])


def wazuh_config(path, gid):
    p = Path(path)
    need(str(p) in ("/var/ossec/etc/ossec.conf", "/var/lib/docker/volumes/capstone-siem_wazuh_etc/_data/ossec.conf"), "fixed_wazuh_config_required")
    for directory in p.parents:
        st = directory.lstat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o002 and
             (not st.st_mode & 0o020 or st.st_gid == gid), "wazuh_parent_metadata")
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_gid == gid and
             stat.S_IMODE(st.st_mode) == 0o660 and st.st_nlink == 1 and st.st_size <= 1024 * 1024, "wazuh_config_metadata")
        raw = os.read(fd, 1024 * 1024 + 1)
        need(len(raw) == st.st_size and (st.st_dev, st.st_ino, st.st_mtime_ns, st.st_ctime_ns) ==
             (p.lstat().st_dev, p.lstat().st_ino, p.lstat().st_mtime_ns, p.lstat().st_ctime_ns), "wazuh_config_changed")
        return raw
    finally:
        os.close(fd)


def account_free(name):
    try:
        pwd.getpwnam(name)
    except KeyError:
        return
    raise Refused("unmanaged_account_exists_" + name)


def check(s, role):
    bundle = source_bundle(s)
    commands = ["python3", "docker", "sshd", "ssh-keygen", "visudo", "sudo", "systemctl", "ip", "ss", "runuser", "useradd", "usermod"]
    if role == "security":
        commands.append("nft")
    for command in commands:
        need(shutil.which(command, path=FIXED_ENV["PATH"]), "required_command_" + command)
    need(sys.platform == "linux" and os.geteuid() == 0, "Linux_root_required")
    need(not Path("/etc/ssh/sshrc").exists(), "system_ssh_rc_refused")
    if STATE.exists():
        trusted_directory(STATE)
        need((STATE / (role + ".json")).exists(), "partial_or_unowned_SOC_state_requires_review")
        return {"status": "existing_requires_verify", "role": role}
    for path in (CODE, "/opt/rule-change", "/opt/rule-view", "/etc/sudoers.d/capstone-rule-readonly", "/etc/ssh/sshd_config.d/63-capstone-rule-readonly.conf", "/etc/rule-change", "/var/lib/rule-change", "/usr/local/sbin/rule-change-executor"):
        need(not os.path.lexists(path), "existing_SOC_namespace_refused")
    units = ["rule-change-worker.service", "rule-change-worker.timer"]
    directories = ["/opt/socbot", "/etc/socbot", "/var/lib/socbot", "/opt/capstone-management", "/etc/capstone-management", "/var/lib/capstone-management"] if role == "siem" else ["/opt/resp", "/var/lib/capstone"]
    units += ["soc-bot.service", "capstone-management.service", "capstone-management.timer"] if role == "siem" else ["capstone-soc-firewall.service"]
    for path in directories + ["/etc/systemd/system/" + unit for unit in units] + ["/usr/local/libexec/capstone-soc-docker", "/usr/local/libexec/capstone-response-apply", "/usr/local/sbin/capstone-response-mcp"]:
        need(not os.path.lexists(path), "unmanaged_SOC_file_or_unit_exists")
    for name in ("rulechg", "ruleview", "socbot") if role == "siem" else ("rulechg", "ruleview", "resp"):
        account_free(name)
    for name in ("rulechg", "ruleview") if role == "siem" else ("rulechg", "ruleview", "resp"):
        for path in ("/etc/sudoers.d/capstone-soc-" + name, "/etc/ssh/sshd_config.d/64-capstone-soc-" + name + ".conf"):
            need(not os.path.lexists(path), "unmanaged_privilege_grant_exists")
    if role == "security":
        need(not os.path.lexists("/usr/local/sbin/agent_block"), "existing_block_helper_refused")
        tables = parse(run(["nft", "-j", "list", "tables"]))
        need(not any(x.get("table", {}).get("name") == "capstone_fw" for x in tables.get("nftables", [])), "existing_firewall_table_refused")
    return {"status": "prerequisites_checked", "role": role, "sources": len(bundle),
            "network_requests": 0, "services_started": 0, "files_written": 0}


def base_profile(s, role, agent_id, hu, containers, machine):
    mounts = [m for m in containers.get("capstone-wazuh-dashboard", {}).get("Mounts", [])
              if m["Destination"] == "/usr/share/wazuh-dashboard/config/opensearch_dashboards.yml"]
    if role == "b":
        need(len(mounts) == 1 and mounts[0]["Source"] == "/opt/capstone/siem/wazuh/config/wazuh_dashboard/opensearch_dashboards.yml", "dashboard_mount_contract")
    return validate_profile({"schema": 1, "role": role, "root": "/opt/capstone",
        "security_host": s["hosts"]["SECURITY_HOST"], "siem_host": s["hosts"]["SIEM_HOST"], "service_host": s["hosts"]["SERVICE_HOST"],
        "agent_id": agent_id, "interface": s["interface"], "machine_id": machine,
        "docker": shutil.which("docker", path=FIXED_ENV["PATH"]), "hermes_uid": hu[0], "hermes_gid": hu[1],
        "manager_etc": "/var/lib/docker/volumes/capstone-siem_wazuh_etc/_data", "protected_ips": s["protected_ips"],
        "admin_protected_cidrs": s["admin_protected_cidrs"],
        "waf_port": s["waf_port"], "container_ids": {name: value["Id"] for name, value in containers.items()},
        "dashboard_rw": mounts[0]["RW"] if mounts else False})


def begin(s, role, profile):
    mkdir(STATE); mkdir(CODE, 0o755)
    write(STATE / (role + "-intent.json"), canonical({"schema": 1, "role": role, "profile": profile,
          "source_sha256": {k: digest(v) for k, v in source_bundle(s).items()}, "automatic_retry": False}))


def create_account(name, home, shell="/usr/sbin/nologin"):
    account_free(name)
    run(["useradd", "--system", "--user-group", "--no-create-home", "--home-dir", home, "--shell", shell, name])
    run(["usermod", "--password", "*", name])
    return pwd.getpwnam(name)


def forced_account(name, home, public, program, sudo_program):
    user = create_account(name, home, "/bin/bash")
    mkdir(home, 0o750, 0, user.pw_gid); mkdir(Path(home) / ".ssh", 0o750, 0, user.pw_gid)
    write(Path(home) / ".ssh/authorized_keys", ('restrict,command="' + program + '" ' + public + "\n").encode(), 0o640, 0, user.pw_gid)
    policy = ("Defaults:" + name + " env_reset\nDefaults:" + name + " !setenv\n" + name +
              " ALL=(root) NOPASSWD: " + sudo_program + ' ""\n')
    sudo = Path("/etc/sudoers.d/capstone-soc-" + name); write(sudo, policy.encode(), 0o440)
    run(["visudo", "-cf", str(sudo)])
    ssh = ("Match User " + name + "\n    ForceCommand " + program + "\n    AuthenticationMethods publickey\n"
           "    PasswordAuthentication no\n    KbdInteractiveAuthentication no\n    DisableForwarding yes\n"
           "    PermitTTY no\n    X11Forwarding no\n    PermitUserRC no\nMatch all\n")
    write("/etc/ssh/sshd_config.d/64-capstone-soc-" + name + ".conf", ssh.encode(), 0o644)
    return user


def install_docker(profile):
    directory = Path("/usr/local/libexec")
    if not directory.exists():
        mkdir(directory, 0o755)
    write(directory / "capstone-soc-docker", ("#!/bin/sh\nexec /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin " +
          profile["docker"] + " --host unix:///var/run/docker.sock \"$@\"\n").encode(), 0o750)


def install_rules(bundle, p, token, key, readonly_key):
    user = forced_account("rulechg", "/opt/rule-change", key, "/opt/rule-change/run-rule-change.sh", "/usr/local/sbin/rule-change-executor")
    mkdir("/etc/rule-change"); mkdir("/var/lib/rule-change")
    for name in ("rule_change_mcp.py", "service_action_executor.py", "incident_containment.py", "managed_suricata_evidence.py"):
        write(Path("/opt/rule-change") / name, render(name, bundle[name], p), 0o640, 0, user.pw_gid)
    write("/usr/local/sbin/rule-change-executor", render("rule_change_executor.py", bundle["rule_change_executor.py"], p), 0o750)
    write("/opt/rule-change/run-rule-change.sh", b"#!/bin/sh\nexec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin /usr/bin/python3 -I -B /opt/rule-change/rule_change_mcp.py\n", 0o750, 0, user.pw_gid)
    namespace = {"__name__": "capstone_rule_readonly_install"}
    exec(compile(bundle["rule_readonly_install.py"], "rule_readonly_install.py", "exec"), namespace)
    namespace["install"](p["role"], readonly_key)
    write("/etc/rule-change/broker.token", (token + "\n").encode())
    url = "https://" + p["siem_host"] + ":8445" if p["role"] == "a" else "http://127.0.0.1:8090"
    write("/etc/rule-change/config.json", canonical({"host": p["role"], "broker_url": url, "broker_token_file": "/etc/rule-change/broker.token"}))
    unit = "[Unit]\nDescription=Capstone exact approved SOC worker\nAfter=docker.service network-online.target\n[Service]\nType=oneshot\nUser=root\nGroup=root\nExecStart=/usr/local/sbin/rule-change-executor --once\nTimeoutStartSec=600\nNoNewPrivileges=yes\nPrivateTmp=yes\nUMask=0077\n"
    write("/etc/systemd/system/rule-change-worker.service", unit.encode(), 0o644)
    timer = "[Unit]\nDescription=Capstone exact approved SOC worker timer\n[Timer]\nOnBootSec=30s\nOnUnitInactiveSec=10s\nAccuracySec=1s\nUnit=rule-change-worker.service\n[Install]\nWantedBy=timers.target\n"
    write("/etc/systemd/system/rule-change-worker.timer", timer.encode(), 0o644)


def validate_stream(obj, s):
    fields = {"schema", "hosts", "protected_ips", "admin_protected_cidrs", "interface", "ssh_port", "agent_id", "rule_token", "response_token", "public_key", "readonly_public_key", "siem_host_key", "hermes_uid", "hermes_gid"}
    need(type(obj) is dict and set(obj) == fields and obj["schema"] == 1 and obj["hosts"] == s["hosts"] and
         obj["protected_ips"] == s["protected_ips"] and obj["admin_protected_cidrs"] == s["admin_protected_cidrs"] and
         obj["interface"] == s["interface"] and obj["ssh_port"] == s["ssh_port"], "secret_stream_profile_mismatch")
    for name in ("rule_token", "response_token"):
        need(isinstance(obj[name], str) and re.fullmatch(r"[0-9a-f]{64}", obj[name]), "secret_stream_token_format")
    need(obj["rule_token"] != obj["response_token"], "independent_tokens_required")
    for name in ("public_key", "readonly_public_key", "siem_host_key"):
        need(public_key(obj[name].encode()) == obj[name], "stream_public_key")
    need(obj["public_key"].split()[:2] != obj["readonly_public_key"].split()[:2], "independent_readonly_key_required")
    need(re.fullmatch(r"[0-9]{3,8}", obj["agent_id"]) and obj["agent_id"] != "000", "stream_agent_id")
    need(all(type(obj[k]) is int and 1 <= obj[k] < 65534 for k in ("hermes_uid", "hermes_gid")), "stream_Hermes_identity")
    return obj


def receive_security(s):
    raw = sys.stdin.buffer.read(16385); need(len(raw) <= 16384, "secret_stream_limit")
    obj = validate_stream(parse(raw), s)
    if (STATE / "import.json").exists():
        need(parse(read(STATE / "import.json", secret=True)) == obj, "imported_secret_stream_changed")
        if (STATE / "security.json").exists():
            verify(s, "security")
        else:
            need(not (STATE / "security-intent.json").exists(), "partial_security_requires_review")
        return {"status": "received", "role": "security", "mutations": 0, "secrets_printed": False}
    need(not STATE.exists(), "existing_SOC_state_refused")
    mkdir(STATE); write(STATE / "import.json", canonical(obj))
    return {"status": "received", "role": "security", "secrets_printed": False}


def prepare_siem(s):
    if (STATE / "siem.json").exists():
        verify(s, "siem")
        return {"status": "prepared", "role": "siem", "already_active": True, "mutations": 0}
    if (STATE / "siem-prepared.json").exists():
        prepared = parse(read(STATE / "siem-prepared.json", secret=True))
        need(prepared["files"] == installed_hashes("siem") and prepared["source_sha256"] ==
             {k: digest(v) for k, v in source_bundle(s).items()}, "prepared_siem_changed")
        wait_broker()
        return {"status": "prepared", "role": "siem", "mutations": 0}
    check(s, "siem"); bundle = source_bundle(s)
    need(not STATE.exists(), "SOC_prepare_already_started")
    listeners = run(["ss", "-H", "-ltn"]).decode()
    need(not any(line.split()[3].rsplit(":", 1)[-1] == "8090" for line in listeners.splitlines() if len(line.split()) > 3), "broker_port_occupied")
    root = Path("/opt/capstone/siem")
    creds = parse(read(root / "app-credentials.json", secret=True))
    config = parse(read("/opt/capstone-prereqs/siem.json", secret=True))
    aid = creds["mattermost_admin_id"]
    need(re.fullmatch(r"[a-z0-9]{26}", aid), "explicit_approver_ID_required")
    hu = pwd.getpwnam("capstone-hermes")
    containers = {name: inspect(name, "capstone-siem") for name in
                  ("capstone-wazuh-manager", "capstone-wazuh-dashboard", "capstone-hermes", "capstone-mattermost")}
    mount = [m for m in containers["capstone-wazuh-manager"]["Mounts"] if m["Destination"] == "/var/ossec/etc"]
    need(len(mount) == 1 and mount[0]["Source"] == "/var/lib/docker/volumes/capstone-siem_wazuh_etc/_data" and mount[0]["RW"], "manager_volume_contract")
    network = containers["capstone-mattermost"]["NetworkSettings"]["Networks"].get("capstone-siem_chat", {})
    peer = str(ipaddress.IPv4Address(network["IPAddress"]))
    auth = base64.b64encode((creds["readonly_username"] + ":" + creds["readonly_password"]).encode()).decode()
    api = "https://" + s["hosts"]["SIEM_HOST"] + ":55000"
    token, _ = request(api + "/security/user/authenticate?raw=true", "POST", headers={"Authorization": "Basic " + auth}, ca=root / "tls/root-ca.pem")
    agents, _ = request(api + "/agents?name=capstone-security&status=active&limit=2", headers={"Authorization": "Bearer " + token.decode().strip()}, ca=root / "tls/root-ca.pem")
    items = parse(agents)["data"]["affected_items"]
    need(len(items) == 1 and items[0]["name"] == "capstone-security" and items[0]["status"] == "active" and
         items[0]["ip"] == s["hosts"]["SECURITY_HOST"], "registered_security_agent_required")
    p = base_profile(s, "b", items[0]["id"], (hu.pw_uid, hu.pw_gid), containers, read("/etc/machine-id").decode().strip())
    # Validate every transform before the first account or application mutation.
    gate = render("soc_management_run.py", bundle["soc_management_run.py"], p)
    for name in ("rule_change_executor.py", "service_action_executor.py", "soc_bot.py", "soc_management_events.py"):
        render(name, bundle[name], p)
    controller = render("soc_management_controller.py", bundle["soc_management_controller.py"], p, gate)
    begin(s, "siem", p); install_docker(p)
    private = STATE / "management_ed25519"
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "capstone-soc-management", "-f", str(private)])
    key = public_key(read(str(private) + ".pub"))
    readonly_private = STATE / "readonly_ed25519"
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "capstone-soc-readonly", "-f", str(readonly_private)])
    readonly_key = public_key(read(str(readonly_private) + ".pub"))
    need(readonly_key != key, "separate_readonly_key_required")
    share = {"schema": 1, "hosts": s["hosts"], "protected_ips": s["protected_ips"], "interface": s["interface"], "ssh_port": s["ssh_port"],
             "admin_protected_cidrs": s["admin_protected_cidrs"],
             "agent_id": p["agent_id"], "rule_token": secrets.token_hex(32), "response_token": secrets.token_hex(32), "public_key": key, "readonly_public_key": readonly_key,
             "siem_host_key": public_key(read("/etc/ssh/ssh_host_ed25519_key.pub")), "hermes_uid": hu.pw_uid, "hermes_gid": hu.pw_gid}
    write(STATE / "export.json", canonical(share))
    mm = "http://" + s["hosts"]["SIEM_HOST"] + ":8065"
    login, headers = request(mm + "/api/v4/users/login", "POST", {"login_id": config["mattermost_admin_username"], "password": config["mattermost_admin_password"]})
    need(parse(login).get("id") == aid, "bootstrap_approver_identity_changed")
    auth = {"Authorization": "Bearer " + next(v for k, v in headers.items() if k.lower() == "token")}
    request(mm + "/api/v4/config/patch", "PUT", {"ServiceSettings": {"EnableIncomingWebhooks": True, "AllowedUntrustedInternalConnections": s["hosts"]["SIEM_HOST"]}}, auth)
    actual, _ = request(mm + "/api/v4/config", headers=auth)
    service_settings = parse(actual)["ServiceSettings"]
    need(service_settings["EnableIncomingWebhooks"] is True and service_settings["AllowedUntrustedInternalConnections"] == s["hosts"]["SIEM_HOST"], "Mattermost_callback_configuration_not_effective")
    def report_api(method, path, body=None, absent=False):
        # request() sanitizes HTTP failures; only the explicit lookup may be absent.
        if absent:
            users, hdr = request(mm + "/api/v4/users/usernames", "POST", ["soc-report"], auth)
            found = parse(users)
            need(len(found) <= 1, "publisher_duplicate_username")
            return (found[0] if found else None), hdr
        data, hdr = request(mm + "/api/v4" + path, method, body, auth)
        return parse(data), hdr
    try:
        # The interactive Hermes channel and automated report channel are distinct.
        channels, _ = report_api('GET', '/teams/' + creds['mattermost_team_id'] + '/channels?page=0&per_page=200')
        need(len(channels) < 200, 'bootstrap_channel_inventory_limit')
        alerts = [c for c in channels if c.get('name') == 'soc-alerts-agent' and not c.get('delete_at')]
        need(len(alerts) <= 1, 'duplicate_report_channels')
        if alerts:
            report_channel = alerts[0]
        else:
            report_channel, _ = report_api('POST', '/channels', {
                'team_id': creds['mattermost_team_id'], 'name': 'soc-alerts-agent', 'display_name': 'soc-alerts-agent', 'type': 'O',
                'header': 'SOC 자동 보고 · 봇을 멘션해 후속 조회 · -agent: 두 봇 참여'})
        for uid in (aid, creds['mattermost_bot_id']):
            report_api('POST', '/channels/' + report_channel['id'] + '/members', {'user_id': uid})
        publisher = provision_report_publisher(report_api, creds["mattermost_team_id"], report_channel['id'])
    finally:
        request(mm + "/api/v4/users/logout", "POST", headers=auth)
    hook_id = publisher["hook"]["id"]
    webhook = mm + "/hooks/" + hook_id
    sb = create_account("socbot", "/opt/socbot")
    mkdir("/opt/socbot", 0o750, 0, sb.pw_gid); mkdir("/etc/socbot", 0o750, 0, sb.pw_gid); mkdir("/var/lib/socbot", 0o700, sb.pw_uid, sb.pw_gid)
    for name in ("soc_bot.py", "operations_approval.py", "soc_management_events.py", "approval_card_cleanup.py"):
        write(Path("/opt/socbot") / name, render(name, bundle[name], p), 0o640, 0, sb.pw_gid)
    write("/etc/socbot/root-ca.pem", read(root / "tls/root-ca.pem"), 0o640, 0, sb.pw_gid)
    environment = {"IDX": "https://" + p["siem_host"] + ":9200", "WAPI": api,
        "IDX_USER": creds["readonly_username"], "IDX_PASS": creds["readonly_password"],
        "WAPI_USER": creds["readonly_username"], "WAPI_PASS": creds["readonly_password"],
        "MM_WEBHOOK": webhook, "LISTEN": p["siem_host"] + ":8090", "BROKER_TOKEN": share["response_token"],
        "SLASH_TOKEN": secrets.token_hex(32),
        "RULE_BROKER_TOKEN": share["rule_token"], "APPROVERS": aid, "RULE_APPROVERS": aid,
        "RULE_MM_SOURCE_CIDRS": peer + "/32", "MM_ACTION_URL": "http://" + p["siem_host"] + ":8090",
        "SOC_MANAGEMENT_EVENTS_DB": "/var/lib/socbot/management-events.sqlite3"}
    write("/etc/socbot/settings.json", canonical(environment), 0o640, 0, sb.pw_gid)
    launcher = "#!/usr/bin/python3 -IB\nimport json,os\nfrom pathlib import Path\nenv=json.loads(Path('/etc/socbot/settings.json').read_bytes())\nenv.update(PATH='/usr/bin:/bin',PYTHONDONTWRITEBYTECODE='1')\nos.execve('/usr/bin/python3',['/usr/bin/python3','-I','-B','/opt/socbot/soc_bot.py','serve'],env)\n"
    write("/opt/socbot/serve", launcher.encode(), 0o750, 0, sb.pw_gid)
    unit = "[Unit]\nDescription=Capstone authenticated approval broker\nAfter=docker.service network-online.target\n[Service]\nUser=socbot\nGroup=socbot\nExecStart=/opt/socbot/serve\nRestart=on-failure\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nReadWritePaths=/var/lib/socbot\nUMask=0077\n[Install]\nWantedBy=multi-user.target\n"
    write("/etc/systemd/system/soc-bot.service", unit.encode(), 0o644)
    install_rules(bundle, p, share["rule_token"], key, share["readonly_public_key"])
    mkdir("/opt/capstone-management", 0o755); mkdir("/etc/capstone-management"); mkdir("/var/lib/capstone-management")
    write("/opt/capstone-management/soc_management_controller.py", controller, 0o750)
    write("/opt/capstone-management/soc_alert_watch.prompt", bundle["soc_alert_watch.prompt"], 0o644)
    write("/etc/capstone-management/controller.env", ("RULE_BROKER_TOKEN=" + share["rule_token"] + "\nMM_WEBHOOK=" + webhook + "\n").encode())
    for name in ("capstone-management.service.example", "capstone-management.timer.example"):
        write(Path("/etc/systemd/system") / name.removesuffix(".example"), read(s["source"] / "infra/hermes" / name), 0o644)
    run(["sshd", "-t"]); run(["systemctl", "reload", "ssh"])
    run(["systemctl", "daemon-reload"]); run(["systemctl", "enable", "--now", "soc-bot.service"])
    wait_broker()
    write(STATE / "siem-prepared.json", canonical({"profile": p, "callback_peer": peer, "approver_id": aid,
          "webhook_id": hook_id, "source_sha256": {k: digest(v) for k, v in bundle.items()}, "files": installed_hashes("siem")}))
    return {"status": "prepared", "role": "siem", "management_timer_enabled": False, "approval_messages_sent": 0}


def wait_broker():
    for _ in range(15):
        try:
            run(["/usr/local/sbin/rule-change-executor", "--broker-check"], timeout=20)
            return
        except Refused:
            time.sleep(1)
    raise Refused("authenticated_broker_health_failed")


def wait_readonly_api(s):
    """Only bootstrap readiness; no case retry or model outage substitution."""
    root = Path("/opt/capstone/siem")
    creds = parse(read(root / "app-credentials.json", secret=True))
    auth = base64.b64encode((creds["readonly_username"] + ":" + creds["readonly_password"]).encode()).decode()
    base = "https://" + s["hosts"]["SIEM_HOST"] + ":55000"
    until = time.monotonic() + 150
    while time.monotonic() < until:
        try:
            token, _ = request(base + "/security/user/authenticate?raw=true", "POST", headers={"Authorization": "Basic " + auth}, ca=root / "tls/root-ca.pem")
            raw, _ = request(base + "/agents?limit=1", headers={"Authorization": "Bearer " + token.decode().strip()}, ca=root / "tls/root-ca.pem")
            value = parse(raw)
            need(value.get("error") == 0 and type(value["data"]["affected_items"]) is list, "authenticated_API_readiness")
            return
        except (Refused, KeyError, ValueError, UnicodeError):
            time.sleep(2)
    raise Refused("manager_API_readiness_timeout")


def mcp_probe(profile):
    # Read-only protocol negotiation from the exact immutable Hermes container.
    # A successful list never substitutes for human approval or attack E2E.
    program = '''import asyncio,os
from mcp import ClientSession,StdioServerParameters
from mcp.client.stdio import stdio_client
async def main():
 for alias in ('soc-rule-a','soc-rule-b','soc-rule-write-a','soc-rule-write-b','soc-resp'):
  params=StdioServerParameters(command='/usr/bin/ssh',args=['-T','-F','/opt/data/home/.ssh/soc_config',alias],env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
  with open(os.devnull,'w') as sink:
   async with stdio_client(params,errlog=sink) as (reader,writer):
    async with ClientSession(reader,writer) as session:
     await session.initialize()
     result=await session.list_tools()
     names={x.name for x in result.tools}
     expected={'block_ip','unblock_ip','list_blocks'} if alias=='soc-resp' else ({'propose_rule_edit','propose_rule_change','propose_service_action'} | ({'temporarily_contain_ip'} if alias.endswith('-a') else set()) if '-write-' in alias else {'get_rule_change_target','get_rule_change_status','get_service_action_target','get_operation_status'})
     assert not result.next_cursor and names==expected and len(names)==len(result.tools)
asyncio.run(asyncio.wait_for(main(),timeout=90))
'''
    docker("exec", "--user", str(profile["hermes_uid"]) + ":" + str(profile["hermes_gid"]),
           profile["container_ids"]["capstone-hermes"], "/opt/hermes/.venv/bin/python", "-I", "-B", "-c", program, timeout=100)


def install_response(bundle, p, share):
    user = forced_account("resp", "/opt/resp", share["public_key"], "/opt/resp/run-response", "/usr/local/sbin/capstone-response-mcp")
    write("/opt/resp/run-response", b"#!/bin/sh\nexec /usr/bin/sudo -n /usr/local/sbin/capstone-response-mcp\n", 0o750, 0, user.pw_gid)
    write(CODE / "response-mcp.py", render("response-mcp.py", bundle["response-mcp.py"], p), 0o600)
    write(CODE / "response.json", canonical({"RESP_BROKER_URL": "https://" + p["siem_host"] + ":8445",
          "RESP_BROKER_TOKEN": share["response_token"],
          "RESP_MAX_MINUTES": "120", "RESP_DEFAULT_MINUTES": "10"}))
    # The root-owned wrapper, not resp's environment, supplies all credentials.
    # No agent_block sudo rule exists for either unprivileged MCP account.
    write("/usr/local/sbin/capstone-response-mcp", render("response_entrypoint.py", bundle["response_entrypoint.py"], p), 0o750)
    write("/usr/local/libexec/capstone-response-apply", bundle["soc_agent_block.py"], 0o750)


def apply_security(s):
    if (STATE / "security.json").exists():
        verify(s, "security")
        return security_public(parse(read(STATE / "security.json", secret=True)))
    share = validate_stream(parse(read(STATE / "import.json", secret=True)), s)
    need(not (STATE / "security-intent.json").exists(), "security_SOC_already_started")
    bundle = source_bundle(s)
    containers = {name: inspect(name, "capstone-security") for name in ("capstone-security-waf", "capstone-security-suricata")}
    s = dict(s)
    command = containers["capstone-security-suricata"]["Config"]["Cmd"]
    need(type(command) is list and command.count("-i") == 1, "sensor_interface_contract")
    interface = command[command.index("-i") + 1]
    need(re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", interface) and interface != "auto" and
         s["interface"] in ("auto", interface), "sensor_interface_mismatch")
    s["interface"] = interface
    p = base_profile(s, "a", share["agent_id"], (share["hermes_uid"], share["hermes_gid"]), containers, read("/etc/machine-id").decode().strip())
    # A typed profile and syntax-rendered source precede any grant.
    for name in ("rule_change_executor.py", "incident_containment.py", "service_action_executor.py", "wazuh_containment_ar.py"):
        render(name, bundle[name], p)
    tables = parse(run(["nft", "-j", "list", "tables"]))
    need(not any(x.get("table", {}).get("name") == "capstone_fw" for x in tables.get("nftables", [])), "existing_containment_table_refused")
    for name in ("rulechg", "resp"):
        account_free(name)
    need(not os.path.lexists("/usr/local/sbin/agent_block"), "existing_agent_block_refused")
    gid = grp.getgrnam("wazuh").gr_gid
    old = wazuh_config("/var/ossec/etc/ossec.conf", gid); new = agent_ar(old)
    mkdir(CODE, 0o755)
    write(STATE / "security-intent.json", canonical({"profile": p, "source_sha256": {k: digest(v) for k, v in bundle.items()}, "automatic_retry": False}))
    write(STATE / "agent-ossec-before.xml", old)
    install_docker(p); install_rules(bundle, p, share["rule_token"], share["public_key"], share["readonly_public_key"])
    install_response(bundle, p, share)
    mkdir("/var/lib/capstone")
    write(CODE / "containment.nft", firewall(p["protected_ips"], p["admin_protected_cidrs"]), 0o600)
    run(["nft", "-c", "-f", str(CODE / "containment.nft")])
    run(["nft", "-f", str(CODE / "containment.nft")])
    unit = "[Unit]\nDescription=Capstone bounded incident firewall sets\nAfter=network-pre.target\nBefore=rule-change-worker.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/sh -c '/usr/sbin/nft list table inet capstone_fw >/dev/null 2>&1 || /usr/sbin/nft -f /opt/capstone-soc/containment.nft'\n[Install]\nWantedBy=multi-user.target\n"
    write("/etc/systemd/system/capstone-soc-firewall.service", unit.encode(), 0o644)
    write("/var/ossec/active-response/bin/capstone-containment", render("wazuh_containment_ar.py", bundle["wazuh_containment_ar.py"], p), 0o750)
    replace_owned("/var/ossec/etc/ossec.conf", new, wazuh_gid=gid)
    run(["/var/ossec/bin/wazuh-agentd", "-t"])
    run(["sshd", "-t"]); run(["systemctl", "reload", "ssh"])
    run(["/usr/local/sbin/rule-change-executor", "--check"], timeout=90); wait_broker()
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "--now", "capstone-soc-firewall.service", "rule-change-worker.timer"])
    run(["systemctl", "restart", "wazuh-agent.service"], timeout=90)
    receipt = {"schema": 1, "status": "applied", "role": "security", "profile": p,
               "ssh_host_ed25519": public_key(read("/etc/ssh/ssh_host_ed25519_key.pub")),
               "agent_config_sha256": digest(new), "container_ids": p["container_ids"], "attack_tested": False,
               "source_sha256": {k: digest(v) for k, v in bundle.items()}}
    receipt["files"] = installed_hashes("security")
    write(STATE / "security.json", canonical(receipt))
    return security_public(receipt)


def security_public(receipt):
    return {"schema": 1, "status": "applied", "role": "security", "ssh_host_ed25519": receipt["ssh_host_ed25519"],
            "agent_id": receipt["profile"]["agent_id"], "container_ids": receipt["container_ids"], "attack_tested": False}


def hermes_file(path, data, uid, gid, existing=False):
    # These data files are intentionally owned by the non-root Hermes account.
    # They are never imported or used as a root executable/configuration.
    path = Path(path)
    if existing:
        replace_owned(path, data, uid=uid, mode=0o600)
    else:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.fchown(fd, uid, gid); os.write(fd, data); os.fsync(fd)
        finally:
            os.close(fd)


def activate_siem(s):
    prepared = parse(read(STATE / "siem-prepared.json", secret=True)); p = validate_profile(prepared["profile"])
    evidence = sys.stdin.buffer.read(16385); need(len(evidence) <= 16384, "security_receipt_limit")
    evidence = parse(evidence)
    need(type(evidence) is dict and set(evidence) == {"schema", "status", "role", "ssh_host_ed25519", "agent_id", "container_ids", "attack_tested"} and
         evidence["schema"] == 1 and evidence.get("role") == "security" and evidence.get("status") == "applied" and
         evidence.get("agent_id") == p["agent_id"] and evidence["attack_tested"] is False and
         set(evidence["container_ids"]) == {"capstone-security-waf", "capstone-security-suricata"} and
         all(re.fullmatch(r"[0-9a-f]{64}", value) for value in evidence["container_ids"].values()), "security_install_receipt_required")
    hostkey = public_key(evidence["ssh_host_ed25519"].encode())
    if (STATE / "siem.json").exists():
        saved = parse(read(STATE / "siem.json", secret=True))
        need(saved["security_receipt"] == evidence, "security_receipt_changed")
        verify(s, "siem")
        return {"status": "active", "role": "siem", "mutations": 0, "attack_tested": False}
    need(not (STATE / "activation-intent.json").exists(), "partial_activation_requires_review")
    need(prepared["files"] == installed_hashes("siem") and prepared["source_sha256"] ==
         {k: digest(v) for k, v in source_bundle(s).items()}, "prepared_siem_source_or_files_changed")
    share = validate_stream(parse(read(STATE / "export.json", secret=True)), s)
    hu = pwd.getpwnam("capstone-hermes"); need((hu.pw_uid, hu.pw_gid) == (p["hermes_uid"], p["hermes_gid"]), "Hermes_identity_changed")
    data = Path("/opt/capstone/siem/capstone-hermes")
    write(STATE / "activation-intent.json", canonical({"security_receipt": evidence, "automatic_retry": False}))
    ssh = data / "home/.ssh"
    hermes_file(ssh / "soc_ed25519", read(STATE / "management_ed25519", secret=True), hu.pw_uid, hu.pw_gid)
    hermes_file(ssh / "soc_readonly_ed25519", read(STATE / "readonly_ed25519", secret=True), hu.pw_uid, hu.pw_gid)
    token = lambda ip: ip if s["ssh_port"] == 22 else "[" + ip + "]:" + str(s["ssh_port"])
    known = token(p["security_host"]) + " " + hostkey + "\n" + token(p["siem_host"]) + " " + share["siem_host_key"] + "\n"
    hermes_file(ssh / "soc_known_hosts", known.encode(), hu.pw_uid, hu.pw_gid)
    config = ""
    for alias, host, user in (("soc-rule-a", p["security_host"], "ruleview"), ("soc-rule-b", p["siem_host"], "ruleview"), ("soc-rule-write-a", p["security_host"], "rulechg"), ("soc-rule-write-b", p["siem_host"], "rulechg"), ("soc-resp", p["security_host"], "resp")):
        config += ("Host " + alias + "\n HostName " + host + "\n Port " + str(s["ssh_port"]) + "\n User " + user +
                   "\n IdentityFile /opt/data/home/.ssh/" + ("soc_readonly_ed25519" if user == "ruleview" else "soc_ed25519") + "\n IdentitiesOnly yes\n BatchMode yes\n StrictHostKeyChecking yes\n"
                   " UserKnownHostsFile /opt/data/home/.ssh/soc_known_hosts\n ConnectTimeout 10\n")
    hermes_file(ssh / "soc_config", config.encode(), hu.pw_uid, hu.pw_gid)
    # Parse data as JSON only; the initial role writes JSON-compatible YAML.
    hc = parse((data / "config.yaml").read_bytes())
    need(set(hc["mcp_servers"]) == {"wazuh-ro", "security-events"}, "unexpected_existing_MCP_servers")
    for name, alias in (("rule-a", "soc-rule-a"), ("rule-b", "soc-rule-b"), ("rule-write-a", "soc-rule-write-a"), ("rule-write-b", "soc-rule-write-b"), ("resp", "soc-resp")):
        hc["mcp_servers"][name] = {"command": "ssh", "args": ["-T", "-F", "/opt/data/home/.ssh/soc_config", alias],
            "connect_timeout": 30, "timeout": 720 if name in ("resp", "rule-write-a", "rule-write-b") else 90, "supports_parallel_tool_calls": False,
            "tools": {"resources": False, "prompts": False}, "trust": "full"}
    tools = ["mcp-wazuh-ro", "mcp-security-events", "mcp-rule-a", "mcp-rule-b", "mcp-rule-write-a", "mcp-rule-write-b", "mcp-resp"]
    hc["toolsets"] = tools; hc["platform_toolsets"] = {"mattermost": tools, "cli": tools}
    hermes_file(data / "config.yaml", canonical(hc), hu.pw_uid, hu.pw_gid, True)
    soul = source_bundle(s)["SOUL.groot.md"]
    soul += ("\n\n## 초기 설치 토폴로지 정정\n이 절은 위의 과거 운영 주소·경로 설명보다 우선한다. "
             "보안 A=" + p["security_host"] + ", SIEM B=" + p["siem_host"] + ", 서비스 C=" + p["service_host"] +
             ". 도구 대상 ID a:modsecurity-custom, a:suricata-local, b:wazuh-local-rules를 사용한다. "
             "물리 경로·컨테이너·승인자는 root 설치 프로필에 결속돼 있으며 호출자가 바꿀 수 없다. "
             "a:chatproxy는 이 설치에 없으며 호출하지 않는다. Native AR는 사건 등록만 수행한다. "
             "임시 선차단은 LLM의 조사와 rule-write-a MCP 호출 뒤 증거·보호주소·600초 TTL 검사로 실행된다. "
             "관리자 CIDR은 IP 차단에서만 보호되며 탐지 로그나 WAF 요청 검사를 면제하지 않는다.\n").encode()
    hermes_file(data / "SOUL.md", soul, hu.pw_uid, hu.pw_gid, True)
    management = data / "management"; need(not management.exists(), "management_home_exists")
    management.mkdir(mode=0o700); os.chown(management, hu.pw_uid, hu.pw_gid)
    management_config = parse(canonical(hc)); management_config["plugins"] = {"enabled": []}
    for name, content in (("config.yaml", canonical(management_config)), ("SOUL.md", soul)):
        hermes_file(management / name, content, hu.pw_uid, hu.pw_gid)
    # Protect installed configuration copies and restart the same owned ID.
    now = inspect("capstone-hermes", "capstone-siem"); need(now["Id"] == p["container_ids"]["capstone-hermes"], "Hermes_container_replaced")
    docker("restart", "--time", "30", now["Id"], timeout=90)
    manager = inspect("capstone-wazuh-manager", "capstone-siem")
    need(manager["Id"] == p["container_ids"]["capstone-wazuh-manager"], "manager_container_replaced")
    paths = [Path("/opt/capstone/siem/wazuh/config/wazuh_cluster/wazuh_manager.conf"), Path(p["manager_etc"]) / "ossec.conf"]
    volume_gid = int(docker("exec", manager["Id"], "stat", "-c", "%g", "/var/ossec/etc/ossec.conf").decode().strip())
    for i, path in enumerate(paths):
        original = wazuh_config(path, volume_gid) if i else read(path)
        revised = manager_ar(original, p["agent_id"])
        write(STATE / ("manager-config-before-" + str(i) + ".xml"), original)
        replace_owned(path, revised, wazuh_gid=volume_gid if i else None)
    docker("exec", manager["Id"], "/var/ossec/bin/wazuh-analysisd", "-t", timeout=60)
    docker("restart", "--time", "30", manager["Id"], timeout=90)
    wait_readonly_api(s)
    wait_broker(); run(["/usr/local/sbin/rule-change-executor", "--check"], timeout=90)
    mcp_probe(p)
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "--now", "rule-change-worker.timer", "capstone-management.timer"])
    receipt = {"schema": 1, "role": "siem", "status": "active", "profile": p,
        "approver_id": prepared["approver_id"], "callback_peer": prepared["callback_peer"], "files": installed_hashes("siem"),
        "native_AR_registration_only": True, "model_failure_fallback_blocking": False, "attack_tested": False,
        "security_receipt": evidence, "source_sha256": {k: digest(v) for k, v in source_bundle(s).items()}}
    write(STATE / "siem.json", canonical(receipt))
    return {"status": "active", "role": "siem", "MCP_servers": 7, "native_AR_registration_only": True,
            "management_timer_enabled": True, "attack_tested": False}


def installed_hashes(role):
    paths = [Path("/usr/local/sbin/rule-change-executor"), Path("/usr/local/libexec/capstone-soc-docker")]
    roots = [Path("/opt/rule-change"), Path("/opt/rule-view"), Path("/etc/rule-change")]
    units = ["rule-change-worker.service", "rule-change-worker.timer"]
    if role == "siem":
        roots += [Path("/opt/socbot"), Path("/etc/socbot"), Path("/opt/capstone-management"), Path("/etc/capstone-management")]
        units += ["soc-bot.service", "capstone-management.service", "capstone-management.timer"]
    else:
        roots += [Path("/opt/resp"), CODE]
        paths += [Path("/usr/local/sbin/capstone-response-mcp"), Path("/usr/local/libexec/capstone-response-apply"), Path("/var/ossec/active-response/bin/capstone-containment")]
        units += ["capstone-soc-firewall.service"]
    for root in roots:
        paths += sorted(p for p in root.rglob("*") if not p.is_dir())
    paths += [Path("/etc/systemd/system") / name for name in units]
    for account in ("rulechg",) if role == "siem" else ("rulechg", "resp"):
        paths += [Path("/etc/sudoers.d/capstone-soc-" + account), Path("/etc/ssh/sshd_config.d/64-capstone-soc-" + account + ".conf")]
    paths += [Path("/etc/sudoers.d/capstone-rule-readonly"), Path("/etc/ssh/sshd_config.d/63-capstone-rule-readonly.conf")]
    return {str(path): digest(read(path)) for path in paths}


def verify(s, role):
    saved = parse(read(STATE / (role + ".json"), secret=True)); p = validate_profile(saved["profile"])
    need(saved["role"] == role and saved["status"] in ("applied", "active"), "completed_SOC_receipt_required")
    need(saved["files"] == installed_hashes(role), "SOC_managed_files_changed")
    need(saved["source_sha256"] == {k: digest(v) for k, v in source_bundle(s).items()}, "SOC_source_profile_changed")
    need(p["protected_ips"] == s["protected_ips"] and p["admin_protected_cidrs"] == s["admin_protected_cidrs"] and
         s["interface"] in ("auto", p["interface"]) and
         (p["security_host"], p["siem_host"], p["service_host"]) == tuple(s["hosts"][k] for k in ("SECURITY_HOST", "SIEM_HOST", "SERVICE_HOST")), "SOC_profile_changed")
    for name, cid in p["container_ids"].items():
        need(inspect(name, "capstone-security" if role == "security" else "capstone-siem")["Id"] == cid, "managed_container_replaced")
    run(["sshd", "-t"]); run(["/usr/local/sbin/rule-change-executor", "--check"], timeout=90); wait_broker()
    units = ["rule-change-worker.timer"] + (["soc-bot.service", "capstone-management.timer"] if role == "siem" else ["capstone-soc-firewall.service"])
    for unit in units:
        run(["systemctl", "is-enabled", unit]); run(["systemctl", "is-active", unit])
    if role == "siem":
        mm = inspect("capstone-mattermost", "capstone-siem")
        need(mm["NetworkSettings"]["Networks"]["capstone-siem_chat"]["IPAddress"] == saved["callback_peer"], "callback_source_changed")
        mcp_probe(p)
    else:
        table = parse(run(["nft", "-j", "list", "table", "inet", "capstone_fw"]))
        verify_firewall(table, p["protected_ips"], p["admin_protected_cidrs"])
        verify_agent_ar(wazuh_config("/var/ossec/etc/ossec.conf", grp.getgrnam("wazuh").gr_gid))
        command = inspect("capstone-security-suricata", "capstone-security")["Config"]["Cmd"]
        need(command.count("-i") == 1 and command[command.index("-i") + 1] == p["interface"], "sensor_interface_changed")
    return {"status": "verified", "role": role, "rule_approval_required": True, "temporary_TTL_seconds": 600,
            "approved_retention_seconds": 3600, "LLM_management": True, "attack_tested": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "prepare-siem", "export-siem", "receive-security", "apply-security", "activate-siem", "verify"))
    parser.add_argument("--role", choices=("siem", "security"))
    args = parser.parse_args(); os.umask(0o077)
    try:
        need(sys.platform == "linux" and os.geteuid() == 0, "Linux_root_required")
        s = settings()
        if args.action in ("check", "verify"):
            need(args.role is not None, "role_required")
            result = check(s, args.role) if args.action == "check" else verify(s, args.role)
        elif args.action == "export-siem":
            need((STATE / "siem-prepared.json").exists(), "prepared_siem_required")
            result = validate_stream(parse(read(STATE / "export.json", secret=True)), s)
        else:
            result = {"prepare-siem": prepare_siem, "receive-security": receive_security,
                      "apply-security": apply_security, "activate-siem": activate_siem}[args.action](s)
        sys.stdout.buffer.write(canonical(result))
    except Exception as error:
        code = str(error) if isinstance(error, Refused) else type(error).__name__
        print(json.dumps({"status": "failed", "phase": args.action, "reason": code,
              "partial_installation": STATE.exists(), "automatic_retry": False,
              "operator_review_required": STATE.exists()}, sort_keys=True), file=sys.stderr)
        raise SystemExit(78)


if __name__ == "__main__":
    main()
