#!/usr/bin/env python3
"""Render the reviewed, fixed October 2026 Wazuh VPN window; never deploy it."""
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shutil
import stat
import sys

BASE_SHA256 = "2790ab83df6c4e1b13ac00a277ea8158a16bb767c2c2b1e0a2c5f01b598b8424"
CONTAINER_ID = "2c6923e7a66ebf55ef28f866cda77a3000f3ed26f7937198927cd73d5cd85403"
DOMAIN = "wazuh.grootlab.duckdns.org"
EXPIRES = "2026-10-20T14:59:00Z"
BASE = "/home/groot_a/capstone/chatproxy"
INCLUDE = BASE + "/tls/wazuh-vpn-window.allow.conf"
ACTIVE_INCLUDE = ("# Fixed demonstration window; expires " + EXPIRES + "\nallow 192.168.15.0/24;\n").encode()
CLOSED_INCLUDE = b"# Wazuh demonstration VPN window closed; no temporary addresses.\n"
# Nginx's time_iso8601 uses the worker timezone. Accept UTC only: any timezone
# change fails closed for VPN clients. Bracketed '+' avoids configuration escapes.
TIME_PATTERNS = (
    r"^2026-10-19T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9][+]00:00$",
    r"^2026-10-20T(?:0[0-9]|1[0-3]):[0-5][0-9]:[0-5][0-9][+]00:00$",
    r"^2026-10-20T14:(?:[0-4][0-9]|5[0-8]):[0-5][0-9][+]00:00$",
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def global_guard():
    patterns = "".join('        "~' + pattern + '" 1;\n' for pattern in TIME_PATTERNS)
    return (
        "    # BEGIN CAPSTONE_WAZUH_DEMO_WINDOW_20261020\n"
        "    geo $remote_addr $capstone_wazuh_demo_vpn {\n"
        "        default 0;\n        192.168.15.0/24 1;\n    }\n"
        "    map $time_iso8601 $capstone_wazuh_demo_active {\n"
        "        default 0;\n" + patterns + "    }\n"
        '    map "$capstone_wazuh_demo_vpn:$capstone_wazuh_demo_active" $capstone_wazuh_demo_deny {\n'
        '        default 0;\n        "1:0" 1;\n    }\n'
        "    # END CAPSTONE_WAZUH_DEMO_WINDOW_20261020\n"
    )


def window_denies(address, timestamp):
    """Reference decision used by offline boundary tests, matching the maps."""
    is_vpn = ipaddress.ip_address(address) in ipaddress.ip_network("192.168.15.0/24")
    active = any(re.fullmatch(pattern, timestamp) for pattern in TIME_PATTERNS)
    return is_vpn and not active


def render(data):
    if digest(data) != BASE_SHA256:
        raise ValueError("baseline_sha256_mismatch")
    text = data.decode("utf-8")
    anchor = "    server {\n        listen 8443 ssl;\n        server_name " + DOMAIN + ";\n"
    if text.count(anchor) != 1 or text.count("http {\n") != 1:
        raise ValueError("ambiguous_configuration_anchor")
    start = text.index(anchor)
    end = text.index("    # Log4Shell", start)
    original = text[start:end]
    changed = original.replace("/etc/nginx/tls/wazuhduck.crt", "/etc/nginx/tls/chatduck.crt", 1)
    changed = changed.replace("/etc/nginx/tls/wazuhduck.key", "/etc/nginx/tls/chatduck.key", 1)
    guard = "        # The UTC request-time guard still closes VPN access if the timer/reload fails.\n"
    guard += "        if ($capstone_wazuh_demo_deny) { return 403; }\n"
    changed = changed.replace("        ssl_protocols TLSv1.2 TLSv1.3;\n", "        ssl_protocols TLSv1.2 TLSv1.3;\n" + guard, 1)
    changed = changed.replace("        deny  all;", "        include /etc/nginx/tls/wazuh-vpn-window.allow.conf;\n        deny  all;", 1)
    candidate = (text[:start] + changed + text[end:]).replace("http {\n", "http {\n" + global_guard(), 1).encode()
    state = {
        "schema": 1, "domain": DOMAIN, "vpn_cidr": "192.168.15.0/24", "expires_utc": EXPIRES,
        "container": "chatproxy", "container_id": CONTAINER_ID,
        "config": BASE + "/nginx.conf", "include": INCLUDE,
        "baseline_sha256": BASE_SHA256, "active_config_sha256": digest(candidate),
        "active_include_sha256": digest(ACTIVE_INCLUDE), "closed_include_sha256": digest(CLOSED_INCLUDE),
    }
    return candidate, state


def main():
    if len(sys.argv) != 3:
        raise ValueError("usage: render.py BASELINE_NGINX_CONF NEW_OUTPUT_DIRECTORY")
    source, destination = map(Path, sys.argv[1:])
    if not stat.S_ISREG(source.lstat().st_mode):
        raise ValueError("regular_baseline_file_required")
    candidate, state = render(source.read_bytes())
    destination.mkdir(mode=0o700, exist_ok=False)
    try:
        for name, content in (("nginx.conf", candidate), ("wazuh-vpn-window.allow.conf", ACTIVE_INCLUDE),
                              ("wazuh-vpn-window.closed.conf", CLOSED_INCLUDE),
                              ("state.json", (json.dumps(state, indent=2, sort_keys=True) + "\n").encode())):
            path = destination / name
            with path.open("xb") as output:
                output.write(content)
            path.chmod(0o600 if name == "state.json" else 0o644)
    except BaseException:
        shutil.rmtree(destination)
        raise
    print(json.dumps(state, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, UnicodeError) as error:
        print("wazuh_demo_render_refused: " + str(error), file=sys.stderr)
        raise SystemExit(1)
