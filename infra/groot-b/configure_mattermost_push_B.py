#!/usr/bin/env python3
"""Groot_B TPNS preparation: default --check reads/probes only; --apply opts in.

Run on B as root. No package installation, compose, DNS or firewall changes.
Probes use mm-app's network namespace and its readable CA bundle, with host
Python TLS verification. No device_id/test push is sent. Applying enables
subsequent normal notifications through Mattermost's TPNS. Rollback needs a
working mmctl API: if mm-app cannot restart, automatic recovery is not assured;
the protected backup must then be restored by an operator. No offline recovery.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time

TARGET = {
    "EmailSettings.PushNotificationServer": "https://push-test.mattermost.com",
    "EmailSettings.PushNotificationContents": "generic_no_channel",
    "EmailSettings.SendPushNotifications": True,
}
# Only the network namespace is entered; host Python reads mm-app's CA bundle.
PROBE = r'''
import concurrent.futures, http.client, json, os, secrets, socket, ssl, struct, sys
try:
    if sys.argv[1] == "health":
        c = http.client.HTTPConnection("127.0.0.1", 8065, timeout=3)
        c.request("GET", "/api/v4/system/ping")  # No device_id: no push side effect.
        r = c.getresponse()
        assert r.status == 200 and json.loads(r.read(8192))["status"] == "OK"
        c.close()
    else:
        host = "push-test.mattermost.com"
        if not os.path.isfile(sys.argv[2]) or not os.access(sys.argv[2], os.R_OK):
            print("CA: mm-app bundle missing or unreadable; host CA fallback refused", flush=True)
            sys.exit(1)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cafile=sys.argv[2])
        print("CA: readable mm-app bundle loaded; host default CA store not used", flush=True)
        ident = secrets.randbits(16)
        query = struct.pack("!6H", ident, 0x100, 1, 0, 0, 0)
        query += b"".join(bytes([len(x)]) + x.encode() for x in host.split("."))
        query += b"\0\0\1\0\1"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(5)
            s.connect(("127.0.0.11", 53))
            s.send(query)
            data = s.recv(65535)
        rid, flags, qd, an, _, _ = struct.unpack_from("!6H", data)
        assert rid == ident and flags & 0x8000 and not flags & 0x020f and qd == 1
        def skip_name(pos):
            while True:
                n = data[pos]
                if n & 0xc0 == 0xc0:
                    return pos + 2
                assert n <= 63
                pos += 1
                if n == 0:
                    return pos
                pos += n
        pos = skip_name(12) + 4
        addresses = set()
        for _ in range(an):
            pos = skip_name(pos)
            kind, cls, ttl, length = struct.unpack_from("!HHIH", data, pos)
            pos += 10
            if kind == 1 and cls == 1 and length == 4:
                addresses.add(socket.inet_ntoa(data[pos:pos + 4]))
            pos += length
        assert addresses
        print("DNS: embedded resolver returned " + str(len(addresses)) + " unique IPv4 addresses", flush=True)
        def check_address(address):
            try:
                with socket.create_connection((address, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as tls:
                        tls.sendall(("GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n").encode())
                        response = http.client.HTTPResponse(tls)
                        response.begin()
                        return address, response.status == 200, "HTTP " + str(response.status)
            except Exception as error:
                return address, False, type(error).__name__
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(check_address, sorted(addresses)))
        for address, ok, detail in results:
            print("HTTPS IPv4 " + address + ": " + ("PASS " if ok else "FAIL ") + detail, flush=True)
        successes = sum(ok for _, ok, _ in results)
        if not successes:
            sys.exit(1)
        print("HTTPS: " + str(successes) + "/" + str(len(results)) + " reachable; mm-app CA and hostname verified", flush=True)
except Exception as exc:
    print("Probe failed: " + type(exc).__name__, flush=True)
    sys.exit(1)
'''


class Failure(Exception):
    pass


def run(args, label, timeout=20):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise Failure(label + " failed or timed out") from None
    if result.returncode:
        raise Failure(label + " failed (exit " + str(result.returncode) + ")")
    return result.stdout


def inspect():
    state = json.loads(run(["docker", "inspect", "mm-app"], "container inspection"))[0]
    if not state["State"]["Running"] or state["State"]["Pid"] <= 0:
        raise Failure("mm-app is not running")
    return state


def config():
    values = {}
    for key, expected in TARGET.items():
        value = json.loads(run(["docker", "exec", "mm-app", "/mattermost/bin/mmctl",
                               "--local", "config", "get", key], "local config read"))
        if type(value) is not type(expected):
            raise Failure("unexpected selected config value type")
        values[key] = value
    return values


def probe(pid, mode, quiet=False):
    cafile = "/proc/%s/root/etc/ssl/certs/ca-certificates.crt" % pid
    args = ["nsenter", "-t", str(pid), "-n", "/usr/bin/python3", "-B", "-c", PROBE, mode, cafile]
    result = subprocess.run(args, capture_output=True, text=True, timeout=45 if mode == "network" else 10)
    if not quiet:
        print(result.stdout.strip())  # Only our fixed probe messages; no response bodies.
    if result.returncode:
        raise Failure(mode + " probe failed")


def set_values(values):
    for key, value in values.items():
        arg = str(value).lower() if isinstance(value, bool) else value
        run(["docker", "exec", "mm-app", "/mattermost/bin/mmctl", "--local",
             "config", "set", key, arg], "selected config write")


def restart_and_verify(expected):
    run(["docker", "restart", "--time", "30", "mm-app"], "mm-app restart", 45)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            probe(inspect()["State"]["Pid"], "health", quiet=True)
            if config() != expected:
                raise Failure("effective selected config does not match")
            return
        except (Failure, subprocess.TimeoutExpired):
            time.sleep(2)
    raise Failure("mm-app health/config verification timed out")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="read-only readiness check (default)")
    mode.add_argument("--apply", action="store_true", help="enable TPNS if currently disabled; matching settings are a no-op")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise Failure("run on Groot_B as root")
    if any(not shutil.which(cmd) for cmd in ("docker", "nsenter")) or not os.access("/usr/bin/python3", os.X_OK):
        raise Failure("docker, nsenter and /usr/bin/python3 are required")
    state = inspect()
    env = {entry.partition("=")[0].upper(): entry.partition("=")[2] for entry in state["Config"].get("Env", [])}
    env_keys = env.keys()
    if any("MM_" + key.replace(".", "_").upper() in env_keys for key in TARGET):
        raise Failure("selected EmailSettings have environment overrides; resolve them first")
    if (env.get("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt") != "/etc/ssl/certs/ca-certificates.crt"
            or "SSL_CERT_DIR" in env_keys):
        raise Failure("container CA overrides require manual verification before using this fixed-bundle probe")
    before = config()
    probe(state["State"]["Pid"], "health", quiet=True)
    probe(state["State"]["Pid"], "network")
    current = inspect()
    if (state["Id"], state["State"]["Pid"]) != (current["Id"], current["State"]["Pid"]) or config() != before:
        raise Failure("container/config changed during checks; rerun")
    if args.apply and before["EmailSettings.SendPushNotifications"] and before != TARGET:
        raise Failure("push is already enabled with different settings; automatic changes are refused")
    print("PASS: root, container, local config, overrides, health and network preflight")
    if not args.apply:
        print("Read-only check complete; no settings changed or notifications sent.")
        return
    if before == TARGET:
        print("NO-OP: target settings already active; read-only checks passed; no restart or backup needed.")
        return
    os.umask(0o077)
    backup = Path(tempfile.mkdtemp(prefix="mattermost-push-", dir="/var/backups")) / "selected-settings.json"
    with backup.open("x", encoding="utf-8") as stream:
        json.dump(before, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    for path, mode in ((backup.parent, 0o700), (backup, 0o600)):
        info = path.stat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != mode:
            raise Failure("backup ownership/permissions verification failed; settings unchanged")
    print("Selected-settings backup: " + str(backup))
    try:
        set_values(TARGET)
        restart_and_verify(TARGET)
    except BaseException as error:
        cause = str(error) if isinstance(error, Failure) else type(error).__name__
        try:
            enabled = "EmailSettings.SendPushNotifications"
            restore = [(enabled, False)] + [(key, value) for key, value in before.items() if key != enabled]
            restore.append((enabled, before[enabled]))
            for key, value in restore:
                try:
                    set_values({key: value})
                except Exception:
                    pass  # Attempt all three keys; final read-back decides success.
            restart_and_verify(before)
        except BaseException:
            raise Failure(cause + "; rollback could not be verified; use the protected backup") from None
        raise Failure(cause + "; original selected settings restored and verified") from None
    print("APPLIED: TPNS enabled with generic_no_channel; health/config verified. No test push sent.")


if __name__ == "__main__":
    try:
        main()
    except (Exception, KeyboardInterrupt) as exc:
        print("ERROR: " + (str(exc) if isinstance(exc, Failure) else type(exc).__name__), file=sys.stderr)
        sys.exit(1)
