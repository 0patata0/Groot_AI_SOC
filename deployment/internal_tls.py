#!/usr/bin/env python3
"""Fixed TLS frontends for cross-host chat and signed approval traffic.

The SIEM's existing CA signs a dedicated IP/DNS server identity. Nginx runs
without capabilities as a locked account, preserves WebSockets, and replaces
untrusted forwarding headers. Private keys never enter the controller stream.
"""
import argparse
import grp
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import secrets
import ssl
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path("/etc/capstone-internal-tls")
USER = "capstone-tls"
UNIT = Path("/etc/systemd/system/capstone-internal-tls.service")
TRUST = Path("/usr/local/share/ca-certificates/capstone-siem.crt")


def run(args, data=None, timeout=30):
    p = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError("internal_tls_command_failed:" + Path(args[0]).name)
    return p.stdout


def safe(path, private=False):
    path = Path(path)
    for p in (path, *path.parents):
        s = p.lstat()
        if stat.S_ISLNK(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise ValueError("internal_tls_untrusted_path")
    if private and stat.S_IMODE(path.stat().st_mode) & 0o007:
        raise ValueError("internal_tls_private_mode")
    return path


def write(path, raw, mode=0o644, gid=0):
    path = Path(path)
    safe(path.parent)
    if path.exists() or path.is_symlink():
        safe(path)
    fd, name = tempfile.mkstemp(prefix=".tls-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            os.fchmod(out.fileno(), mode)
            os.fchown(out.fileno(), 0, gid)
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def nginx_configuration(host, security_host):
    host = str(ipaddress.IPv4Address(host))
    security_host = str(ipaddress.IPv4Address(security_host))
    if not ipaddress.ip_address(host).is_private:
        raise ValueError("internal_tls_private_host_required")
    def server(port, backend):
        return f""" server {{
  listen {host}:{port} ssl;
  server_name capstone-siem.internal {host};
  ssl_certificate {ROOT}/server.crt;
  ssl_certificate_key {ROOT}/server.key;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_session_tickets off;
  client_max_body_size 110m;
  location / {{
   proxy_pass http://{backend};
   proxy_http_version 1.1;
   proxy_set_header Host $http_host;
   proxy_set_header X-Forwarded-Proto https;
   proxy_set_header X-Real-IP $remote_addr;
   proxy_set_header X-Forwarded-For $remote_addr;
   proxy_set_header Upgrade $http_upgrade;
   proxy_set_header Connection $capstone_connection;
   proxy_read_timeout 600s;
   proxy_send_timeout 600s;
  }}
 }}
"""
    return ("worker_processes 1;\npid /run/capstone-internal-tls/nginx.pid;\n"
            "error_log stderr crit;\nevents { worker_connections 512; }\nhttp {\n"
            " access_log off;\n server_tokens off;\n"
            " client_body_temp_path /run/capstone-internal-tls/client-body;\n"
            " proxy_temp_path /run/capstone-internal-tls/proxy;\n"
            " fastcgi_temp_path /run/capstone-internal-tls/fastcgi;\n"
            " uwsgi_temp_path /run/capstone-internal-tls/uwsgi;\n"
            " scgi_temp_path /run/capstone-internal-tls/scgi;\n"
            " map $http_upgrade $capstone_connection { default upgrade; '' close; }\n"
            # Only the security edge may supply the already-observed client IP.
            + f" set_real_ip_from {security_host};\n"
            " real_ip_header X-Forwarded-For;\n real_ip_recursive on;\n"
            + server(8444, host + ":8065") + server(8445, "127.0.0.1:8090") + "}\n").encode()


def unit():
    return ("[Unit]\nDescription=Capstone internal management TLS\n"
            "After=network-online.target docker.service\nWants=network-online.target\n"
            "[Service]\nType=simple\nUser=capstone-tls\nGroup=capstone-tls\n"
            "ExecStartPre=/usr/sbin/nginx -t -c /etc/capstone-internal-tls/nginx.conf\n"
            "ExecStart=/usr/sbin/nginx -c /etc/capstone-internal-tls/nginx.conf -g 'daemon off;'\n"
            "ExecReload=/bin/kill -HUP $MAINPID\nRestart=on-failure\nRestartSec=2s\n"
            "RuntimeDirectory=capstone-internal-tls\nRuntimeDirectoryMode=0700\n"
            "NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n"
            "PrivateDevices=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\n"
            "ProtectControlGroups=yes\nRestrictSUIDSGID=yes\nCapabilityBoundingSet=\n"
            "RestrictAddressFamilies=AF_INET AF_UNIX\nLockPersonality=yes\n"
            "MemoryMax=128M\nTasksMax=32\nTimeoutStopSec=15s\n"
            "[Install]\nWantedBy=multi-user.target\n").encode()


def install_trust(ca):
    ca = safe(ca)
    run(["openssl", "verify", "-CAfile", str(ca), str(ca)])
    raw = ca.read_bytes()
    if TRUST.exists() and TRUST.read_bytes() != raw:
        raise ValueError("internal_tls_trust_anchor_changed")
    write(TRUST, raw)
    run(["update-ca-certificates"], timeout=60)
    return hashlib.sha256(raw).hexdigest()


def install(host, ca, ca_key):
    host = str(ipaddress.IPv4Address(host))
    ca, ca_key = safe(ca), safe(ca_key, private=True)
    ROOT.mkdir(mode=0o755, exist_ok=True)
    safe(ROOT)
    run(["systemctl", "disable", "--now", "nginx.service"])
    run(["systemctl", "mask", "nginx.service"])
    if (ROOT / "profile.json").exists():
        p = json.loads(safe(ROOT / "profile.json").read_text())
        if p["host"] != host or p["ca_sha256"] != hashlib.sha256(ca.read_bytes()).hexdigest():
            raise ValueError("internal_tls_existing_profile_changed")
        return verify(require_broker=False)
    try:
        account = pwd.getpwnam(USER)
        if account.pw_uid < 1 or account.pw_shell not in ("/usr/sbin/nologin", "/bin/false"):
            raise ValueError("internal_tls_existing_account")
    except KeyError:
        run(["useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent",
             "--shell", "/usr/sbin/nologin", USER])
        account = pwd.getpwnam(USER)
    if grp.getgrgid(account.pw_gid).gr_name != USER or any(g.gr_name in ("sudo", "docker", "adm")
            for g in grp.getgrall() if USER in g.gr_mem or g.gr_gid == account.pw_gid):
        raise ValueError("internal_tls_privileged_account")
    public = run(["openssl", "x509", "-in", str(ca), "-pubkey", "-noout"])
    if public != run(["openssl", "pkey", "-in", str(ca_key), "-pubout"]):
        raise ValueError("internal_tls_CA_key_mismatch")
    key, cert, csr, ext = (ROOT / n for n in ("server.key", "server.crt", "server.csr", "server.ext"))
    if any(p.exists() or p.is_symlink() for p in (key, cert, csr, ext)):
        raise ValueError("internal_tls_partial_state_requires_review")
    run(["openssl", "req", "-new", "-newkey", "rsa:3072", "-nodes", "-sha256",
         "-keyout", str(key), "-out", str(csr), "-subj", "/O=Capstone/CN=capstone-siem.internal"])
    write(ext, ("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:capstone-siem.internal,IP:" + host + "\n").encode())
    run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
         "-set_serial", str(secrets.randbits(127) + 1), "-out", str(cert), "-days", "365",
         "-sha256", "-extfile", str(ext)])
    os.chown(key, 0, account.pw_gid)
    os.chmod(key, 0o440)
    os.chmod(cert, 0o444)
    run(["openssl", "verify", "-CAfile", str(ca), "-verify_ip", host, str(cert)])
    install_trust(ca)
    write(ROOT / "root-ca.pem", ca.read_bytes(), 0o444)
    write(ROOT / "nginx.conf", nginx_configuration(host, os.environ["SECURITY_HOST"]))
    write(UNIT, unit())
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "--now", UNIT.name])
    profile = {"schema": 1, "host": host, "ca_sha256": hashlib.sha256(ca.read_bytes()).hexdigest(),
               "ports": [8444, 8445], "tls_backend_scope": "same-host HTTP only",
               "config_sha256": hashlib.sha256((ROOT / "nginx.conf").read_bytes()).hexdigest()}
    write(ROOT / "profile.json", (json.dumps(profile, sort_keys=True) + "\n").encode(), 0o600)
    for attempt in range(5):
        try:
            return verify(require_broker=False)
        except (OSError, urllib.error.URLError):
            if attempt == 4:
                raise
            time.sleep(0.3)


def verify(require_broker=True):
    profile = json.loads(safe(ROOT / "profile.json").read_text())
    if hashlib.sha256(safe(ROOT / "nginx.conf").read_bytes()).hexdigest() != profile["config_sha256"]:
        raise ValueError("internal_tls_configuration_drift")
    if safe(UNIT).read_bytes() != unit():
        raise ValueError("internal_tls_unit_drift")
    if hashlib.sha256(safe(ROOT / "root-ca.pem").read_bytes()).hexdigest() != profile["ca_sha256"]:
        raise ValueError("internal_tls_CA_drift")
    if (stat.S_IMODE(safe(ROOT / "server.key", private=True).stat().st_mode) != 0o440 or
            (ROOT / "server.key").stat().st_gid != pwd.getpwnam(USER).pw_gid):
        raise ValueError("internal_tls_private_key_permissions")
    if run(["systemctl", "is-active", UNIT.name]).strip() != b"active":
        raise ValueError("internal_tls_service_inactive")
    run(["openssl", "x509", "-in", str(ROOT / "server.crt"), "-noout", "-checkend", "2592000"])
    context = ssl.create_default_context(cafile=str(ROOT / "root-ca.pem"))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    states = []
    for port, path, expected in ((8444, "/api/v4/system/ping", 200), (8445, "/operations/health", 401)):
        try:
            with opener.open("https://" + profile["host"] + ":" + str(port) + path, timeout=8) as response:
                status = response.status
        except urllib.error.HTTPError as error:
            status = error.code
        if status != expected and (port != 8445 or require_broker):
            raise ValueError("internal_tls_backend_health")
        states.append({"port": port, "status": status, "certificate_verified": True})
    return {"status": "verified", "services": states, "ca_sha256": profile["ca_sha256"]}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "verify", "export", "trust"))
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--ca-key", type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError("internal_tls_root_required")
    if args.action == "install":
        base = Path(os.environ.get("CAPSTONE_ROOT", "/opt/capstone")) / "siem/tls"
        result = install(os.environ["SIEM_HOST"], args.ca_file or base / "root-ca.pem",
                         args.ca_key or base / "root-ca-key.pem")
    elif args.action == "verify":
        result = verify()
    elif args.action == "export":
        result = {"schema": 1, "siem_host": os.environ["SIEM_HOST"],
                  "ca_pem": safe(ROOT / "root-ca.pem").read_text()}
    else:
        import sys
        value = json.loads(sys.stdin.buffer.read(16385))
        if set(value) != {"schema", "siem_host", "ca_pem"} or value["schema"] != 1 or value["siem_host"] != os.environ["SIEM_HOST"]:
            raise ValueError("internal_tls_CA_transfer_profile")
        ROOT.mkdir(mode=0o755, exist_ok=True)
        write(ROOT / "root-ca.pem", value["ca_pem"].encode(), 0o444)
        result = {"status": "trusted", "ca_sha256": install_trust(ROOT / "root-ca.pem")}
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
