#!/usr/bin/env python3
"""Existing-container, offline candidate only. No installation or publication.

Parent operator verifies fixed container/image and holds rule-change then Vector
locks. Run as root inside that same container. argv: pinned manifest, parser
worker copy, fixed attempt name (16 lowercase hex). All writes stay in a NEW
/tmp/capstone-suricata-update-20261015-<attempt> directory. Retain on failure.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import sys
import time

from compare_rules import compare, native_parser, native_active_map, WORKER_SHA256

RULES = {
    "/rules/suricata.rules": "f11a97da8db542030b5767860eb7e5c4d5045d57385baf5b1cca6ff540faef97",
    "/rules/GROOT_A_local.rules": "82f41d6532f5b2333178ea51e92ce5c2beedd1052c6a585deb6b91e42bcbe9cf",
    "/rules/all.rules": "8669bab4923070dac1ed474f4c96c6a90ad92a794518a19fc628bc8354619da6"}
CONFIG = "/etc/suricata/suricata.yaml"
UPDATE = "/usr/bin/suricata-update"
SURI = "/usr/bin/suricata"
PACKAGE = Path("/usr/lib/suricata/python/suricata/update")
CID = "39ce628179fb39cac72fa59ccb562475a8f874a58eec401b6c6e187614bebd0d"
IMAGE = "sha256:d4fd70f7955f1f9d5c8f54d0b91dd22e359bebce6fba5423d1182f33ae0d59ff"
RUNTIME = {
    UPDATE: "930098a1581c040c67ca5ec3575cfa76e4f43e6ac6ae0fb019f432c9d3b8557e",
    SURI: "c2f2ec727be9d6f925e9164b59786ba5bf6f6b61452a6901a4013c996a06aa8d",
    CONFIG: "8c234811ce9a8d49f3a55c0c7e62c72f28431ad392c75deae910aa917c225ad1"}
POLICY = "capstone-suricata-update-offline-candidate-1"
HEX = re.compile(r"[0-9a-f]{64}\Z")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(path, limit=64 * 1024 * 1024):
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= limit:
            raise ValueError("regular_file_bound")
        with os.fdopen(os.dup(fd), "rb") as stream:
            data = stream.read(limit + 1)
        after = os.fstat(fd)
        if identity(before) != identity(after) or len(data) != before.st_size:
            raise ValueError("file_changed")
        current = os.stat(path, follow_symlinks=False)
        if identity(before) != identity(current):
            raise ValueError("path_changed")
        return data, identity(before)
    finally:
        os.close(fd)


def identity(s):
    return [s.st_dev, s.st_ino, s.st_size, s.st_uid, s.st_gid,
            stat.S_IMODE(s.st_mode), s.st_nlink, s.st_mtime_ns, s.st_ctime_ns]


def write(path, data):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, "wb") as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())
    directory = os.open(str(Path(path).parent), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def json_bytes(obj):
    return (json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n").encode()


def unique_pairs(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError("duplicate_json_key")
        result[k] = v
    return result


def load_pins(path):
    data, ident = read(path, 128 * 1024)
    if ident[3:7] != [0, 0, 0o400, 1]:
        raise ValueError("manifest_owner_mode")
    obj = json.loads(data, object_pairs_hook=unique_pairs)
    if data != json_bytes(obj) or set(obj) != {
            "schema_version", "policy", "container_id", "image_id", "files"}:
        raise ValueError("manifest_shape")
    if obj["schema_version"] != 1 or obj["policy"] != POLICY:
        raise ValueError("manifest_policy")
    if obj["container_id"] != CID or obj["image_id"] != IMAGE:
        raise ValueError("manifest_identity")
    files = obj["files"]
    if not isinstance(files, dict) or not 7 <= len(files) <= 160:
        raise ValueError("manifest_files_bound")
    if not {UPDATE, SURI, CONFIG, *RULES} <= files.keys():
        raise ValueError("manifest_required_files")
    for p, sha in files.items():
        package = re.fullmatch(r"/usr/lib/suricata/python/suricata/update/[A-Za-z0-9_./-]+\.py", p)
        if p not in {UPDATE, SURI, CONFIG, *RULES} and not (package and ".." not in p):
            raise ValueError("manifest_path")
        if not isinstance(sha, str) or not HEX.fullmatch(sha):
            raise ValueError("manifest_sha")
    if any(files[k] != v for k, v in {**RULES, **RUNTIME}.items()):
        raise ValueError("current_rules_pin")
    if not any(p.endswith("/suricata/update/main.py") for p in files):
        raise ValueError("tool_source_missing")
    expected_package = {p for p in files if p.startswith(str(PACKAGE) + "/")}
    actual_package = {str(p) for p in PACKAGE.rglob("*.py")}
    if expected_package != actual_package:
        raise ValueError("tool_package_inventory_changed")
    return obj


def snapshot(pins):
    if {str(p) for p in PACKAGE.rglob("*.py")} != {
            p for p in pins["files"] if p.startswith(str(PACKAGE) + "/")}:
        raise ValueError("tool_package_inventory_changed")
    answer = {}
    for p, expected in pins["files"].items():
        data, meta = read(p, 128 * 1024 * 1024 if p == SURI else 64 * 1024 * 1024)
        if digest(data) != expected:
            raise ValueError("runtime_source_changed")
        answer[p] = {"sha256": expected, "identity": meta}
    return answer


def limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (120, 120))
    resource.setrlimit(resource.RLIMIT_FSIZE, (128 * 1024 * 1024, 128 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_AS, (3 * 1024**3, 3 * 1024**3))


def command(argv, job, name, seconds):
    # File-backed output avoids pipe descendants holding communicate() open.
    # Keep our child leader unreaped until its private PGID has been cleaned.
    log = job / (name + ".log")
    fd = os.open(str(log), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC",
           "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
           "TMPDIR": str(job / "tmp")}
    started = time.monotonic()
    proc = None
    timed_out = False
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=fd,
                                stderr=fd, cwd=job, env=env,
                                start_new_session=True, preexec_fn=limits)
        while os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
            if time.monotonic() - started >= seconds:
                timed_out = True
                break
            time.sleep(0.05)
    finally:
        if proc is not None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
        os.fsync(fd)
        os.close(fd)
        os.chmod(log, 0o400)
    data, _ = read(log, 16 * 1024 * 1024)
    result = {"returncode": proc.returncode, "timeout": timed_out,
              "seconds": round(time.monotonic() - started, 3), "log_sha256": digest(data)}
    if timed_out or proc.returncode != 0:
        raise ValueError("command_failed_" + name)
    return result, data


def run(manifest, worker_path, attempt):
    if os.geteuid() != 0 or sys.platform != "linux" or not re.fullmatch(r"[0-9a-f]{16}", attempt):
        raise ValueError("fixed_linux_root_attempt_required")
    os.umask(0o077)
    def interrupted(signum, frame):
        raise ValueError("candidate_interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    pins = load_pins(manifest)
    before = snapshot(pins)
    worker, _ = read(worker_path, 256 * 1024)
    if digest(worker) != WORKER_SHA256:
        raise ValueError("worker_source_changed")
    # No guessed binaries/package locations: the parent supplies inspected pins.
    job = Path("/tmp/capstone-suricata-update-20261015-" + attempt)
    job.mkdir(mode=0o700)
    result = {"schema_version": 1, "policy": POLICY, "status": "incomplete",
              "job": str(job), "container_id": pins["container_id"],
              "image_id": pins["image_id"], "network_fetch": False,
              "rules_published": False, "service_signals": 0,
              "approval_worker_changed": False}
    try:
        for name in ("input", "state", "cache", "output", "tmp"):
            (job / name).mkdir(mode=0o700)
        write(job / "pins.json", json_bytes(pins))
        write(job / "before.json", json_bytes(before))
        write(job / "worker-parser-source.py", worker)
        data = {p: read(p)[0] for p in RULES}
        if any(digest(data[p]) != RULES[p] for p in RULES):
            raise ValueError("input_snapshot_sha_changed")
        et, local, combined = [data[p] for p in RULES]
        if combined != et + local:
            raise ValueError("existing_concat_contract_broken")
        for name, raw in (("suricata.rules", et), ("local.rules", local), ("all.rules", combined)):
            write(job / "input" / name, raw)
        native_rule = native_parser(read(PACKAGE / "rule.py", 256 * 1024)[0])
        # 1.3.8 always resolves flowbits. Preserve the current enabled set by
        # supplying ONLY native-parsed active inputs, never dormant feed rules
        # that the resolver could enable. Original three snapshots stay intact.
        projection = {}
        for name, original in (("et-active.rules", et), ("local-active.rules", local)):
            active, duplicates = native_active_map(original, native_rule, False)
            projected = ("\n".join(body for _, body in active.values()) + "\n").encode("utf-8")
            if native_active_map(projected, native_rule, False)[0] != active:
                raise ValueError("active_projection_changed")
            write(job / "input" / name, projected)
            projection[name] = {"active_rules": len(active), "sha256": digest(projected),
                                "bytes": len(projected), "source_sha256": digest(original)}
        result["input_projection"] = {"policy": "native_current_active_only", "files": projection}
        write(job / "projection.json", json_bytes(result["input_projection"]))
        write(job / "empty.conf", b"")
        # Offline cache filename is the installed 1.3.8 Fetch contract. The only
        # source is a fixed file:// URL; --offline prohibits even fetching it.
        url = (job / "input" / "et-active.rules").as_uri()
        cache_name = hashlib.md5(url.encode()).hexdigest() + "-et-active.rules"
        projected_et = read(job / "input" / "et-active.rules")[0]
        write(job / "cache" / cache_name, projected_et)
        config = {"sources": [], "local": [], "ignore": [],
                  "data-directory": str(job / "state"), "cache-directory": str(job / "cache"),
                  "output": str(job / "output"), "dist-rule-directory": None,
                  "suricata-conf": str(job / "intentionally-absent-engine-config.yaml"),
                  "reload-command": None, "test-command": None,
                  **{k: str(job / "empty.conf") for k in
                     ("disable-conf", "enable-conf", "modify-conf", "drop-conf")}}
        # JSON is a YAML subset. Never read ambient update.yaml or filter files.
        write(job / "update.yaml", json_bytes(config))
        result["version_check"], version = command([UPDATE, "-V"], job, "version", 10)
        if not re.search(rb"\b1\.3\.8\b", version):
            raise ValueError("update_version_changed")
        args = [UPDATE, "-c", str(job / "update.yaml"), "--suricata", SURI,
                "--suricata-version", "8.0.6", "--offline", "--no-reload", "--no-test",
                "--fail", "--url", url, "--local", str(job / "input" / "local-active.rules")]
        write(job / "argv.json", json_bytes(args))
        result["update"], _ = command(args, job, "update", 120)
        generated, _ = read(job / "output" / "suricata.rules")
        result["comparison"] = compare(et, local, combined, generated, worker, native_rule)
        result["generated_sha256"] = digest(generated)
        result["generated_bytes"] = len(generated)
        write(job / "comparison.json", json_bytes(result["comparison"]))
        if result["comparison"]["input_effective_rules"] != 52495:
            raise ValueError("fixed_active_rule_count_changed")
        if not result["comparison"]["active_rule_maps_equal"]:
            raise ValueError("rule_semantics_changed")
        if sorted(p.name for p in (job / "output").iterdir()) != ["suricata.rules"]:
            raise ValueError("unexpected_output_dependency")
        # Suricata 8.0.6 initializes outputs BEFORE its -T early exit. Actual
        # config has an absolute managed EVE path: -l alone is insufficient.
        # Keep syntax/PCAP tests in the operator's separate read-only/private
        # engine namespace. Never call -T against the live writer config here.
        result["native_syntax_verified"] = False
        result["native_replay_verified"] = False
        result["status"] = "candidate_compared_native_test_pending"
    except Exception as exc:
        result["status"] = "rejected"
        result["reason"] = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
    finally:
        try:
            result["protected_files_unchanged"] = snapshot(pins) == before
        except Exception:
            result["protected_files_unchanged"] = False
        if not result["protected_files_unchanged"]:
            result["status"] = "rejected"
            result["reason"] = "protected_files_changed"
        write(job / "result.json", json_bytes(result))
    print(json_bytes(result).decode(), end="")
    return 0 if result["status"] == "candidate_compared_native_test_pending" else 1


if __name__ == "__main__":
    try:
        if len(sys.argv) != 4:
            raise ValueError("three_arguments_required")
        sys.exit(run(*sys.argv[1:]))
    except Exception as exc:
        print(json.dumps({"status": "rejected_before_result", "reason": type(exc).__name__}, sort_keys=True))
        sys.exit(1)
