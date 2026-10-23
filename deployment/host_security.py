#!/usr/bin/env python3
"""Additive host/management segmentation for the service and SIEM roles.

Only this module's table is replaced atomically. Docker, existing lab guards,
operator SSH routes, and the security host's perimeter policy stay separately
owned. No download, package installation, model call or container operation.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import hashlib
import tempfile

TABLE = "capstone_host_guard"
CONFIG = Path("/etc/capstone-host-security/config.json")
CODE = Path("/opt/capstone-host-security/host_security.py")
UNIT = Path("/etc/systemd/system/capstone-host-security.service")
RECEIPT = Path("/var/lib/capstone-host-security/receipt.json")


def configuration(value):
    required = {"schema", "role", "security_host", "siem_host", "service_host",
                "interface", "ssh_port", "web_port", "legacy_bridge",
                "allow_legacy_management_http"}
    optional = {"management_cidrs", "dashboard_cidrs", "chat_cidrs", "dashboard_denied_cidrs"}
    if not isinstance(value, dict) or not required <= set(value) or set(value) - required - optional or value["schema"] != 1:
        raise ValueError("host_guard_config_fields")
    if value["role"] not in ("siem", "service"):
        raise ValueError("host_guard_role")
    hosts = [value[k] for k in ("security_host", "siem_host", "service_host")]
    if len(set(hosts)) != 3 or any(str(ipaddress.IPv4Address(x)) != x or
            not ipaddress.ip_address(x).is_private for x in hosts):
        raise ValueError("host_guard_addresses")
    for name in ("interface", "legacy_bridge"):
        if not isinstance(value[name], str) or not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,15}", value[name]):
            raise ValueError("host_guard_interface")
    for name in ("ssh_port", "web_port"):
        if type(value[name]) is not int or not 1 <= value[name] <= 65535:
            raise ValueError("host_guard_port")
    if type(value["allow_legacy_management_http"]) is not bool:
        raise ValueError("host_guard_legacy_flag")
    value = dict(value)
    for name in optional:
        networks = value.setdefault(name, [])
        if not isinstance(networks, list) or len(networks) > 128:
            raise ValueError("host_guard_sources")
        for item in networks:
            network = ipaddress.IPv4Network(item, strict=True)
            if str(network) != item or not network.prefixlen or network.is_multicast:
                raise ValueError("host_guard_source")
    return value


def rules(value):
    c = configuration(value)
    a, b, peer = (c[x] for x in ("security_host", "siem_host", "service_host"))
    nic, ssh, web = c["interface"], c["ssh_port"], c["web_port"]
    common = [f'iifname "{nic}" ct state invalid drop',
              f'iifname "{nic}" ct state established,related accept',
              f'iifname "{nic}" ip protocol icmp limit rate 10/second accept']
    management = ([f'iifname "{nic}" ip saddr {{ {", ".join(c["management_cidrs"])} }} tcp dport {ssh} accept']
                  if c["management_cidrs"] else [])
    if c["role"] == "siem":
        dashboard_denied = ([f'iifname "{nic}" ip saddr {{ {", ".join(c["dashboard_denied_cidrs"])} }} tcp dport 443 drop']
                            if c["dashboard_denied_cidrs"] else [])
        dashboard = ([f'iifname "{nic}" ip saddr {{ {", ".join(c["dashboard_cidrs"])} }} tcp dport 443 accept']
                     if c["dashboard_cidrs"] else [])
        chat = ([f'iifname "{nic}" ip saddr {{ {", ".join(c["chat_cidrs"])} }} tcp dport 8444 accept']
                if c["chat_cidrs"] else [])
        local_ports = [ssh, 8444, 8445] + ([8090] if c["allow_legacy_management_http"] else [])
        published = [443, 1514, 1515] + ([8065] if c["allow_legacy_management_http"] else [])
        incoming = dashboard_denied + common + management + chat + dashboard + [f'iifname "{nic}" ip saddr {a} tcp dport {{ {", ".join(map(str, local_ports))} }} accept',
                             f'iifname "{nic}" drop']
        forwarding = [x.replace("tcp dport 443", "meta l4proto tcp ct original proto-dst 443") for x in dashboard_denied] + common + [x.replace("tcp dport 443", "meta l4proto tcp ct status dnat ct original proto-dst 443") for x in dashboard] + [
            f'iifname "{nic}" ip saddr {a} meta l4proto tcp ct status dnat ct original proto-dst {{ {", ".join(map(str, published))} }} accept',
            f'iifname "{nic}" ip saddr {peer} meta l4proto tcp ct status dnat ct original proto-dst {{ 1514, 1515 }} accept',
            f'iifname "{nic}" drop']
    else:
        bridge = c["legacy_bridge"]
        incoming = [f'iifname "{bridge}" ct state established,related ct direction reply accept',
                    f'iifname "{bridge}" drop'] + common + management + [
            f'iifname "{nic}" ip saddr {{ {a}, {b} }} tcp dport {ssh} accept',
            f'iifname "{nic}" ip saddr {a} tcp dport {web} accept',
            f'iifname "{nic}" drop']
        forwarding = [f'iifname "{bridge}" ct state established,related ct direction reply accept',
                      f'iifname "{bridge}" drop'] + common + [
            f'iifname "{nic}" ip saddr {a} meta l4proto tcp ct status dnat ct original proto-dst 8080 accept',
            f'iifname "{nic}" drop']
    def chain(name, entries):
        return (f' chain {name} {{ type filter hook {name} priority -25; policy accept;\n' +
                "".join("  " + entry + "\n" for entry in entries) + " }\n")
    return f"table inet {TABLE} {{\n" + chain("input", incoming) + chain("forward", forwarding) + "}\n"


def run(args, data=None):
    p = subprocess.run(args, input=data, capture_output=True, text=True, timeout=20)
    if p.returncode:
        raise RuntimeError("host_guard_command_failed:" + Path(args[0]).name)
    return p.stdout


def trusted(path):
    p = Path(path)
    for item in (p, *p.parents):
        s = item.lstat()
        if stat.S_ISLNK(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise ValueError("host_guard_untrusted_path")
    return p


def load():
    return configuration(json.loads(trusted(CONFIG).read_text()))


def authenticated_ssh_peer():
    """Use this invocation's sshd-provided context, never other listening sockets."""
    pid = os.getpid()
    for _ in range(16):
        try:
            env = Path(f"/proc/{pid}/environ").read_bytes().split(b"\0")
            values = [x.split(b"=", 1)[1].decode() for x in env if x.startswith(b"SSH_CONNECTION=")]
            if len(values) == 1:
                fields = values[0].split()
                if len(fields) == 4:
                    return str(ipaddress.IPv4Address(fields[0])) + "/32"
            status = Path(f"/proc/{pid}/status").read_text()
            pid = int(next(x.split()[1] for x in status.splitlines() if x.startswith("PPid:")))
            if pid <= 1:
                break
        except (OSError, ValueError, StopIteration):
            break
    return None


def from_environment(role):
    a = str(ipaddress.IPv4Address(os.environ["SECURITY_HOST"]))
    route = json.loads(run(["ip", "-j", "route", "get", a]))
    if len(route) != 1 or not route[0].get("dev"):
        raise ValueError("host_guard_management_route")
    networks = [x for x in os.environ.get("MANAGEMENT_ALLOWED_CIDRS", "").split(",") if x]
    current = authenticated_ssh_peer()
    if current and current not in networks:
        networks.append(current)
    if not networks:
        raise ValueError("host_guard_authenticated_management_source_required")
    return configuration({"schema": 1, "role": role, "security_host": a,
        "siem_host": os.environ["SIEM_HOST"], "service_host": os.environ["SERVICE_HOST"],
        "interface": route[0]["dev"], "ssh_port": int(os.environ.get("SSH_PORT", "22")),
        "web_port": int(os.environ.get("WEB_BACKEND_PORT", "80")), "legacy_bridge": "docker0",
        "management_cidrs": sorted(set(networks)),
        "dashboard_cidrs": [x for x in os.environ.get("DASHBOARD_ALLOWED_CIDRS", "").split(",") if x],
        "dashboard_denied_cidrs": [x for x in os.environ.get("DASHBOARD_DENIED_CIDRS", "192.168.15.0/24").split(",") if x],
        "chat_cidrs": [x for x in os.environ.get("CHAT_ALLOWED_CIDRS", "").split(",") if x],
        "allow_legacy_management_http": False})


def atomic(path, data, mode=0o600):
    path = Path(path)
    trusted(path.parent)
    if path.exists() or path.is_symlink():
        trusted(path)
    fd, name = tempfile.mkstemp(prefix=".host-guard-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            os.fchmod(out.fileno(), mode)
            os.fchown(out.fileno(), 0, 0)
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def normalized(raw):
    """Compare the whole owned table, ignoring kernel identity/counters only."""
    output = []
    for item in json.loads(raw).get("nftables", []):
        if "metainfo" in item:
            continue
        value = {k: {a: b for a, b in v.items() if a not in ("handle", "index")}
                 for k, v in item.items()}
        output.append(value)
    return output


def apply(c):
    # No flush ruleset, broad iptables change, or Docker policy replacement.
    old = subprocess.run(["nft", "list", "table", "inet", TABLE], capture_output=True, text=True)
    transaction = (f"delete table inet {TABLE}\n" if old.returncode == 0 else "") + rules(c)
    run(["nft", "--check", "-f", "-"], transaction)
    run(["nft", "-f", "-"], transaction)
    actual = run(["nft", "-j", "list", "table", "inet", TABLE])
    RECEIPT.parent.mkdir(mode=0o700, exist_ok=True)
    receipt = {"schema": 1, "config_sha256": digest(c),
               "source_sha256": hashlib.sha256(trusted(CODE).read_bytes()).hexdigest(),
               "semantic_sha256": digest(normalized(actual))}
    atomic(RECEIPT, (json.dumps(receipt, sort_keys=True) + "\n").encode())
    return {"status": "applied", "role": c["role"], "table": TABLE,
            "semantic_sha256": receipt["semantic_sha256"]}


def verify(c):
    actual = run(["nft", "-j", "list", "table", "inet", TABLE])
    saved = json.loads(trusted(RECEIPT).read_text())
    if (saved.get("config_sha256") != digest(c) or
            saved.get("source_sha256") != hashlib.sha256(trusted(CODE).read_bytes()).hexdigest() or
            saved.get("semantic_sha256") != digest(normalized(actual))):
        raise ValueError("host_guard_policy_drift")
    data = json.loads(actual)["nftables"]
    chains = [x["chain"] for x in data if "chain" in x]
    if len(chains) != 2 or any(x.get("hook") != x["name"] or x.get("prio") != -25 or
                              x.get("policy") != "accept" for x in chains):
        raise ValueError("host_guard_chains_changed")
    expected_count = rules(c).count("\n  ")
    if len([x for x in data if "rule" in x]) != expected_count:
        raise ValueError("host_guard_rule_count_changed")
    return {"status": "verified", "role": c["role"], "table": TABLE,
            "rules": expected_count}


def install(c):
    if os.geteuid() != 0:
        raise ValueError("host_guard_root_required")
    for path in (CODE.parent, CONFIG.parent):
        path.mkdir(mode=0o755, parents=True, exist_ok=True)
        trusted(path)
    source = Path(__file__).read_bytes()
    if Path(__file__).resolve() != CODE:
        atomic(CODE, source, 0o644)
    atomic(CONFIG, (json.dumps(c, sort_keys=True, indent=2) + "\n").encode())
    atomic(UNIT, ("[Unit]\nDescription=Capstone host and lab management segmentation\n"
                    "DefaultDependencies=no\nAfter=local-fs.target\nBefore=network-pre.target docker.service\n"
                    "Wants=network-pre.target\n[Service]\nType=oneshot\nRemainAfterExit=yes\n"
                    "ExecStart=/usr/bin/python3 -I -B /opt/capstone-host-security/host_security.py apply\n"
                    "ExecReload=/usr/bin/python3 -I -B /opt/capstone-host-security/host_security.py apply\n"
                    "NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n"
                    "StateDirectory=capstone-host-security\nStateDirectoryMode=0700\n"
                    "RestrictAddressFamilies=AF_NETLINK AF_UNIX\n[Install]\nWantedBy=multi-user.target\n").encode(), 0o644)
    run(["systemctl", "daemon-reload"])
    # Apply while management SSH remains established; install before Docker at boot.
    run(["systemctl", "enable", "--now", UNIT.name])
    run(["systemctl", "reload", UNIT.name])
    return verify(c)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("print", "check", "install", "apply", "verify"))
    parser.add_argument("--configuration", type=Path)
    parser.add_argument("--role", choices=("siem", "service"))
    args = parser.parse_args()
    c = (configuration(json.loads(args.configuration.read_text())) if args.configuration else
         from_environment(args.role) if args.role else load())
    if args.action == "print":
        print(rules(c), end="")
        return
    if os.geteuid() != 0:
        raise ValueError("host_guard_root_required")
    if args.action == "check":
        # Syntax-only check does not create a kernel table.
        old = subprocess.run(["nft", "list", "table", "inet", TABLE], capture_output=True)
        run(["nft", "--check", "-f", "-"], (f"delete table inet {TABLE}\n" if old.returncode == 0 else "") + rules(c))
        result = {"status": "syntax_checked", "role": c["role"]}
    else:
        result = {"install": install, "apply": apply, "verify": verify}[args.action](c)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
