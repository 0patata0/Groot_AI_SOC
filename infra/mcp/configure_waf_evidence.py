#!/usr/bin/env python3
"""Operator-only WAF evidence enrollment after reviewed proxy deployment.

Not an MCP tool or sudo grant. Run from the root-owned installed directory;
first test/reload both nginx instances, then enroll their exact configuration.
No secret or request content is read. No container is created or restarted.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

DOCKER = "/usr/local/bin/docker"
WAF = "waf"
PROXY = "chatproxy"
NETWORK = "secstack_waf-net"
POLICY = Path("/etc/rule-change/waf-evidence.json")
CONFIGS = (
    "/etc/modsecurity.d/modsecurity.conf", "/etc/modsecurity.d/setup.conf",
    "/etc/modsecurity.d/modsecurity-override.conf", "/etc/nginx/nginx.conf",
    "/etc/nginx/conf.d/default.conf", "/etc/nginx/includes/proxy_backend.conf",
    "/etc/nginx/conf.d/zz-capstone-evidence.conf", "/etc/nginx/conf.d/zz-capstone-labs.conf",
)


def need(ok, code):
    if not ok:
        raise ValueError(code)


def run(args):
    result = subprocess.run([DOCKER, "--host", "unix:///var/run/docker.sock", *args],
        capture_output=True, timeout=15, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    need(result.returncode == 0 and len(result.stdout) <= 2 * 1024 * 1024, "fixed_docker_read_failed")
    return result.stdout


def main():
    need(os.geteuid() == 0, "root_required")
    for directory in (POLICY.parent, *POLICY.parent.parents):
        s = directory.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022, "unsafe_policy_directory")
    rows = json.loads(run(["inspect", WAF, PROXY]))
    waf, proxy = rows
    need(all(row["State"]["Running"] for row in rows), "nginx_not_running")
    need(waf["NetworkSettings"]["Networks"][NETWORK]["IPAddress"] == "172.18.0.2" and
         proxy["NetworkSettings"]["Networks"][NETWORK]["IPAddress"] == "172.18.0.3", "reviewed_network_required")
    config = {name: run(["exec", waf["Id"], "cat", name]) for name in CONFIGS}
    labs = config["/etc/nginx/conf.d/zz-capstone-labs.conf"].decode()
    need(labs.count("set_real_ip_from 172.18.0.3;") == 1 and
         not re.search(r"(?m)^\s*(?:set_real_ip_from\s+172\.18\.0\.1;|172\.18\.0\.1\s+1;)", labs),
         "broad_gateway_trust_refused")
    producer = config["/etc/nginx/conf.d/zz-capstone-evidence.conf"].decode()
    matches = re.findall(r'modsecurity_transaction_id "v2:([0-9a-f]{64}):\$request_id:\$msec:\$time_iso8601";', producer)
    need(len(matches) == 1, "producer_binding_invalid")
    proxy_config = run(["exec", proxy["Id"], "cat", "/etc/nginx/nginx.conf"])
    need(proxy_config.count(b"proxy_pass http://172.18.0.2:8080;") == 4 and
         proxy_config.count(b"proxy_set_header X-Capstone-Lab-Mode enforce;") == 4 and
         b"proxy_pass http://10.200.10.20:80/_offline-labs/;" not in proxy_config and
         b"proxy_pass http://192.168.16.230:80;" not in proxy_config, "enforced_proxy_routes_required")
    value = {"schema_version": 1, "container_id": waf["Id"], "proxy_container_id": proxy["Id"],
        "proxy_config_sha256": hashlib.sha256(proxy_config).hexdigest(), "deployment_binding": matches[0],
        "destination_ip": "172.18.0.2", "destination_ports": [8080, 8443],
        "config_sha256": {name: hashlib.sha256(raw).hexdigest() for name, raw in config.items()}}
    after = json.loads(run(["inspect", WAF, PROXY]))
    need([(r["Id"], r["State"]["Pid"], r["State"]["StartedAt"], r["NetworkSettings"]) for r in after] ==
         [(r["Id"], r["State"]["Pid"], r["State"]["StartedAt"], r["NetworkSettings"]) for r in rows], "container_changed")
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    temporary = POLICY.with_name(".waf-evidence.next")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(raw); output.flush(); os.fsync(output.fileno())
        if os.path.lexists(POLICY):
            s = POLICY.lstat()
            need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600,
                 "unsafe_existing_policy")
        os.replace(temporary, POLICY)
    finally:
        if temporary.exists(): temporary.unlink()
    print(json.dumps({"enrolled": True, "policy_sha256": hashlib.sha256(raw).hexdigest(),
                      "container_ids_preserved": True, "mcp_added": 0}))


if __name__ == "__main__": main()
