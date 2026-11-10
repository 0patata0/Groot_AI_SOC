#!/usr/bin/env python3
"""Offline, fresh-install Harness² audit support; no package or model installer.

The parent deploy.sh SIEM role calls prepare(), verify(), then explicitly
activate(config_check=the_core_validator). CLI install orchestrates those three
steps; --prepare-only omits activation. Preparation never calls systemctl.
Existing installations are verified, never overwritten by this module.

Audit JSON is opaque here: configuration() checks bounded JSON, not the audit
core's schema. CLI check and activation load the checked, root-controlled core's
pure _validate_config(), returning the same configuration or raising.

Runner contract: server_audit.py scheduled; server_context.py with no arguments.
The root collector atomically publishes root-owned context/snapshot files. Its
fixed existing wrapper drops discovery to soc-ollama with runuser. The collector
can read service-owned sources but cannot write outside its state namespace.
"""
import argparse
import ast
import base64
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import stat
import subprocess
import sys
import tarfile
from types import ModuleType
import zlib


COMMIT = "6868817518876de8fd170c6a8354daca273b6191"
MANIFEST_SHA256 = "c6a5b628683132c174be1e90ee11c90ef3ab28a35aac15b5a9617356192bcd35"
ARCHIVE_NAME = "harness2-6868817.tar.gz"
ROOT = Path("/opt/capstone-harness2")
VENDOR = ROOT / "vendor" / COMMIT
ETC = Path("/etc/capstone-harness2")
CONFIG = ETC / "audit.json"
LOCK = ETC / "framework.lock.json"
RECEIPT = ETC / "installation.json"
STATE = Path("/var/lib/capstone-harness2")
REPORTS = STATE / "reports"
SNAPSHOTS = STATE / "sources"
CONTEXT = STATE / "context.json"
UNIT_DIR = Path("/etc/systemd/system")
SERVICE = "capstone-harness2-audit.service"
CONTEXT_SERVICE = "capstone-harness2-context.service"
TIMER = "capstone-harness2-audit.timer"
RUNNERS = ("server_audit.py", "server_context.py")
SOURCES = (*RUNNERS, "framework.lock.json")
PYTHONS = ("/usr/bin/python3", "/usr/bin/python3.12", "/usr/bin/python3.13",
           "/usr/local/bin/python3.12", "/usr/local/bin/python3.13")
MAX_SOURCE = 2 * 1024 * 1024
MAX_ARCHIVE = 32 * 1024 * 1024
MAX_EXPANDED = 64 * 1024 * 1024
MAX_CONFIG = 65536


def need(ok, code):
    if not ok:
        raise ValueError("harness_maintenance_" + code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode()


def _pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def _parse(raw):
    return json.loads(raw, object_pairs_hook=_pairs,
                      parse_constant=lambda _: need(False, "nonfinite_json"))


def configuration(value):
    """Pure bounded JSON check; deliberately makes no audit-schema assumptions."""
    need(type(value) is dict, "config_object_required")
    count = 0

    def visit(item, depth=0):
        nonlocal count
        count += 1
        need(depth <= 16 and count <= 8192, "config_complexity")
        if type(item) is dict:
            need(all(type(k) is str and len(k) <= 256 for k in item), "config_keys")
            for v in item.values():
                visit(v, depth + 1)
        elif type(item) is list:
            for v in item:
                visit(v, depth + 1)
        else:
            need(type(item) in (str, int, float, bool, type(None)), "config_json_type")
            if type(item) is str:
                need(len(item) <= MAX_CONFIG and "\x00" not in item, "config_string")

    visit(value)
    raw = canonical(value)
    need(len(raw) <= MAX_CONFIG, "config_size")
    return _parse(raw)  # independent copy; caller cannot mutate a checked plan


def _relative(name):
    need(type(name) is str and 0 < len(name) <= 512 and "\\" not in name
         and all(32 <= ord(c) < 127 for c in name), "archive_path")
    path = PurePosixPath(name)
    need(not path.is_absolute() and path.as_posix() == name
         and all(p not in ("", ".", "..") for p in name.split("/")), "archive_path")
    return path


def checked_manifest(raw):
    """Verify the exact parent-owned lock bytes, then their structural contract."""
    need(type(raw) is bytes and 0 < len(raw) <= MAX_SOURCE, "manifest_size")
    need(sha(raw) == MANIFEST_SHA256, "manifest_pin")
    value = _parse(raw)
    need(type(value) is dict and set(value) == {
        "schema", "source", "commit", "version", "license", "python",
        "archive_sha256", "archive_size", "files"}, "manifest_fields")
    identity = {"schema": 1, "source": "https://github.com/google-research/harness2",
                "commit": COMMIT, "version": "0.1.0", "license": "Apache-2.0",
                "python": ">=3.12,<3.14"}
    need(type(value["schema"]) is int and all(value[k] == v for k, v in identity.items()),
         "manifest_identity")
    need(type(value["archive_size"]) is int and 0 < value["archive_size"] <= MAX_ARCHIVE,
         "archive_size")
    need(type(value["archive_sha256"]) is str and
         re.fullmatch(r"[0-9a-f]{64}", value["archive_sha256"]), "archive_hash")
    files = value["files"]
    need(type(files) is dict and 1 <= len(files) <= 4096, "manifest_files")
    total = 0
    for name, record in files.items():
        path = _relative(name)
        need(not any(p.as_posix() in files for p in path.parents if p != PurePosixPath(".")),
             "manifest_file_parent")
        need(type(record) is dict and set(record) == {"sha256", "size"}, "manifest_file_fields")
        need(type(record["size"]) is int and 0 <= record["size"] <= MAX_EXPANDED,
             "manifest_file_size")
        need(type(record["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", record["sha256"]),
             "manifest_file_hash")
        total += record["size"]
    need(total <= MAX_EXPANDED, "manifest_expanded_size")
    return value


def checked_archive(raw, manifest_raw):
    """Validate the canonical full-source tar.gz entirely before any extraction.

    Only the exact sorted regular-file list is accepted. tarfile.extract* is
    never used. Decompression is bounded even when an input contains no files.
    """
    lock = checked_manifest(manifest_raw)
    need(type(raw) is bytes and len(raw) == lock["archive_size"] and
         sha(raw) == lock["archive_sha256"], "archive_integrity")
    try:
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        expanded = decoder.decompress(raw, MAX_EXPANDED + 8 * 1024 * 1024 + 1)
        need(len(expanded) <= MAX_EXPANDED + 8 * 1024 * 1024 and decoder.eof
             and not decoder.unused_data and not decoder.unconsumed_tail, "archive_compression")
        files = {}
        with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
            for member in archive:
                name = member.name
                _relative(name)
                need(member.type == tarfile.REGTYPE and not member.linkname and
                     member.sparse is None and not any("sparse" in k.lower() for k in member.pax_headers),
                     "archive_member_type")
                need(member.mode == 0o644, "archive_member_mode")
                need(name in lock["files"] and name not in files, "archive_unexpected_or_duplicate")
                expected = lock["files"][name]
                need(member.size == expected["size"], "archive_member_size")
                stream = archive.extractfile(member)
                need(stream is not None, "archive_member_unreadable")
                with stream:
                    data = stream.read(member.size + 1)
                need(len(data) == member.size and sha(data) == expected["sha256"], "archive_member_hash")
                files[name] = data
            need(not any(expanded[archive.offset:]), "archive_trailing_data")
        need(list(files) == sorted(lock["files"]), "archive_missing_or_unsorted")
        return files
    except (tarfile.TarError, zlib.error, EOFError) as exc:
        raise ValueError("harness_maintenance_invalid_archive") from exc


def encoded_source_bundle(files):
    """Pure transport encoding; filenames are fixed, not arbitrary destinations."""
    need(type(files) is dict and set(files) == set(SOURCES), "source_names")
    for name, raw in files.items():
        need(type(raw) is bytes and 0 < len(raw) <= MAX_SOURCE, "source_size")
        if name in RUNNERS:
            ast.parse(raw, filename=name)  # never execute a supplied runner
        else:
            checked_manifest(raw)
    return {"schema": 1, "files": {name: {"sha256": sha(raw),
            "content_b64": base64.b64encode(raw).decode("ascii")} for name, raw in files.items()}}


def checked_source_bundle(value):
    need(type(value) is dict and set(value) == {"schema", "files"}
         and type(value["schema"]) is int and value["schema"] == 1, "source_bundle_fields")
    need(type(value["files"]) is dict and set(value["files"]) == set(SOURCES), "source_names")
    files = {}
    for name, item in value["files"].items():
        need(type(item) is dict and set(item) == {"sha256", "content_b64"}, "source_record")
        encoded = item["content_b64"]
        need(type(encoded) is str and len(encoded) <= 4 * ((MAX_SOURCE + 2) // 3), "encoded_size")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, UnicodeError) as exc:
            raise ValueError("harness_maintenance_source_encoding") from exc
        need(sha(raw) == item["sha256"], "source_hash")
        files[name] = raw
    encoded_source_bundle(files)
    return files


def _trusted(path, directory=False):
    path = Path(path)
    need(path.is_absolute(), "absolute_local_path_required")
    for p in (path, *path.parents):
        meta = p.lstat()
        need(not stat.S_ISLNK(meta.st_mode) and meta.st_uid == 0 and not meta.st_mode & 0o022,
             "root_controlled_path_required")
        if p != path or directory:
            need(stat.S_ISDIR(meta.st_mode), "directory_required")
        else:
            need(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1, "regular_single_link_required")
    return path


def _read(path, limit=MAX_SOURCE):
    path = _trusted(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        meta = os.fstat(stream.fileno())
        need(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1 and meta.st_uid == 0
             and not meta.st_mode & 0o022 and meta.st_size <= limit, "source_file_unsafe")
        raw = stream.read(limit + 1)
    need(len(raw) <= limit, "source_file_size")
    return raw


def source_bundle(source_root):
    """Read root-controlled staged sources on B and encode them for prepare()."""
    base = Path(source_root) / "infra/validation/harness2"
    return encoded_source_bundle({name: _read(base / name) for name in SOURCES})


def _mkdir(path, mode=0o755):
    _trusted(path.parent, directory=True)
    path.mkdir(mode=mode)
    os.chown(path, 0, 0)
    path.chmod(mode)


def _write(path, data, mode=0o644, uid=0, gid=0):
    _trusted(path.parent, directory=True)
    need(not os.path.lexists(path), "destination_exists")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        os.fchown(stream.fileno(), uid, gid)
        os.fchmod(stream.fileno(), mode)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    _sync(path.parent)


def _sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def extract_archive(raw, manifest_raw, destination):
    """Extract a checked artifact into a new root-owned tree, never over a tree."""
    files = checked_archive(raw, manifest_raw)
    destination = Path(destination)
    need(not os.path.lexists(destination), "vendor_destination_exists")
    _mkdir(destination)
    for name, data in files.items():
        path = destination / name
        for parent in reversed(path.parents):
            if parent.is_relative_to(destination) and not parent.exists():
                _mkdir(parent)
        _write(path, data)
    _sync(destination)
    return len(files)


def unit_documents(python="/usr/bin/python3"):
    need(python in PYTHONS, "python_path")
    common = ("NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\n"
              "PrivateTmp=yes\nReadOnlyPaths=/tmp /var/tmp\nPrivateDevices=yes\n"
              "ProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectKernelLogs=yes\n"
              "ProtectControlGroups=yes\nRestrictSUIDSGID=yes\nRestrictRealtime=yes\n"
              "RestrictNamespaces=yes\nLockPersonality=yes\n"
              "AmbientCapabilities=\nUMask=0077\nKillMode=control-group\nTimeoutStopSec=10\n"
              "Environment=PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 TZ=Asia/Seoul\n")
    audit = ("[Unit]\nDescription=Read-only Harness2 audit of shared SOC skills\n"
             f"Requires={CONTEXT_SERVICE}\nAfter={CONTEXT_SERVICE}\n"
             "[Service]\nType=oneshot\nUser=root\nGroup=root\n" + common +
             f"ExecStart={python} -I -B {ROOT}/server_audit.py scheduled\n"
             f"WorkingDirectory={ROOT}\nReadWritePaths={REPORTS}\n"
             "CapabilityBoundingSet=\n"
             "PrivateNetwork=yes\nRestrictAddressFamilies=AF_UNIX\n"
             "SystemCallFilter=~@mount @reboot @swap @raw-io @privileged @network-io\n"
             "TimeoutStartSec=900\nMemoryMax=512M\nTasksMax=64\nCPUQuota=50%\n")
    # The context unit runs as the default root identity WITHOUT explicit
    # User=/Group=: on B, explicit User=root plus NoNewPrivileges
    # made the wrapper's runuser setuid() fail with EPERM (observed 2026-11-10),
    # while either option alone worked. Keep NoNewPrivileges; omit User=/Group=.
    context = ("[Unit]\nDescription=Collect sanitized current SOC model and MCP catalog\n"
               "After=network-online.target\nWants=network-online.target\n"
               "[Service]\nType=oneshot\n" + common +
               f"ExecStart={python} -I -B {ROOT}/server_context.py\n"
               f"WorkingDirectory={ROOT}\nReadWritePaths={STATE}\nReadOnlyPaths={REPORTS}\n"
               # runuser needs SETUID/SETGID; read-only DAC access is needed for
               # service-owned 0700 source directories. No DAC write override.
               "CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_DAC_READ_SEARCH\n"
               "PrivateNetwork=no\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n"
               "SystemCallFilter=~@mount @reboot @swap @raw-io\n"
               "TimeoutStartSec=180\nMemoryMax=512M\nTasksMax=64\nCPUQuota=50%\n")
    timer = ("[Unit]\nDescription=Daily Harness2 audit at 03:00 KST\n"
             "[Timer]\nOnCalendar=*-*-* 03:00:00 Asia/Seoul\nPersistent=false\n"
             f"Unit={SERVICE}\nAccuracySec=1s\nRandomizedDelaySec=0\n"
             "[Install]\nWantedBy=timers.target\n")
    return {SERVICE: audit.encode(), CONTEXT_SERVICE: context.encode(), TIMER: timer.encode()}


def _root():
    need(sys.platform == "linux" and os.geteuid() == 0, "linux_root_required")


def _run(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=30,
                            env={"PATH": "/usr/bin:/bin", "LANG": "C",
                                 "PYTHONDONTWRITEBYTECODE": "1"})
    need(result.returncode == 0, "command_failed_" + Path(argv[0]).name)
    return result.stdout.strip()


def _python_check(python):
    need(python in PYTHONS, "python_path")
    path = Path(python)
    _trusted(path.parent, directory=True)
    # Distribution /usr/bin/python3 is commonly a root-owned symlink.
    seen = set()
    while path.is_symlink():
        need(path not in seen and len(seen) < 8 and path.lstat().st_uid == 0, "python_link")
        seen.add(path)
        link = Path(os.readlink(path))
        path = Path(os.path.abspath(link if link.is_absolute() else path.parent / link))
        _trusted(path.parent, directory=True)
    _trusted(path)
    version = _run([python, "-I", "-B", "-c",
                    "import sys; print('%d.%d' % sys.version_info[:2])"])
    need(version in ("3.12", "3.13"), "python_version")


def _context_account():
    import grp
    user = pwd.getpwnam("soc-ollama")
    need(user.pw_uid != 0 and user.pw_gid == grp.getgrnam("soc-ollama").gr_gid,
         "existing_soc_ollama_account_required")
    return user


def _metadata(path, mode, uid=0, gid=0):
    meta = path.lstat()
    need(not stat.S_ISLNK(meta.st_mode) and meta.st_uid == uid and meta.st_gid == gid
         and stat.S_IMODE(meta.st_mode) == mode, "installed_permissions")
    return meta


def _core_validator(raw):
    """Load only the verified fixed audit source; never call its CLI/run_audit.

    Parent owns this source and its bundle digest. Import definitions are trusted
    installer code, not candidate/model text. sys.modules is needed by dataclass.
    """
    name = "_capstone_harness2_install_core"
    module = ModuleType(name)
    module.__file__ = str(ROOT / "server_audit.py")
    need(name not in sys.modules, "core_import_in_progress")
    sys.modules[name] = module
    try:
        exec(compile(raw, module.__file__, "exec"), module.__dict__)
        validate = getattr(module, "_validate_config", None)
        need(callable(validate), "core_config_validator_required")
        return validate
    finally:
        sys.modules.pop(name, None)


def _checked_core_config(value, validator):
    need(callable(validator), "core_config_validator_required")
    config = configuration(value)
    need(configuration(validator(configuration(config))) == config, "core_config_changed")
    return config


def _inputs(archive_path, audit_config, source_root, files, python):
    _root()
    need((source_root is None) != (files is None), "choose_one_source_input")
    sources = checked_source_bundle(source_bundle(source_root) if files is None else files)
    archive_path = Path(archive_path)
    need(archive_path.name == ARCHIVE_NAME, "offline_archive_filename")
    archive = _read(archive_path, MAX_ARCHIVE)
    checked_archive(archive, sources["framework.lock.json"])
    _python_check(python)
    config = _checked_core_config(audit_config, _core_validator(sources["server_audit.py"]))
    return sources, config, archive


def check(archive_path, *, audit_config, source_root=None, files=None,
          python="/usr/bin/python3"):
    """Read-only prerequisites and pure core config validation; no audit/discovery."""
    sources, _, _ = _inputs(archive_path, audit_config, source_root, files, python)
    return {"status": "prerequisites_checked", "commit": COMMIT, "python": python,
            "vendor_files": len(checked_manifest(sources["framework.lock.json"])["files"]),
            "core_config_schema_checked": True}


def prepare(archive_path, *, audit_config, source_root=None, files=None,
            python="/usr/bin/python3"):
    """Install from offline artifact plus staged sources OR encoded source bundle.

    No service reload/start/enable, package install or audit/discovery occurs.
    A failed partial fresh installation is preserved for operator inspection;
    a subsequent invocation will refuse to overwrite its unreceipted namespace.
    """
    sources, config, archive = _inputs(archive_path, audit_config, source_root, files, python)
    user = _context_account()
    if os.path.lexists(RECEIPT):
        result = verify(audit_config=config, files=encoded_source_bundle(sources))
        need(result["python"] == python, "existing_python_changed")
        return result
    documents = unit_documents(python)
    for path in (ROOT, ETC, STATE, *(UNIT_DIR / name for name in documents)):
        need(not os.path.lexists(path), "unmanaged_namespace_exists")
        _trusted(path.parent, directory=True)
    _mkdir(ROOT)
    _mkdir(ROOT / "vendor")
    extract_archive(archive, sources["framework.lock.json"], VENDOR)
    _mkdir(ETC)
    _mkdir(STATE)
    _mkdir(REPORTS, 0o700)
    _mkdir(SNAPSHOTS, 0o700)
    _write(CONTEXT, b"", 0o600)
    for name in RUNNERS:
        _write(ROOT / name, sources[name])
    _write(LOCK, sources["framework.lock.json"])
    _write(CONFIG, canonical(config), 0o600)
    for name, raw in documents.items():
        _write(UNIT_DIR / name, raw)
    receipt = {"schema": 1, "commit": COMMIT, "python": python,
               "manifest_sha256": MANIFEST_SHA256, "config_sha256": sha(canonical(config)),
               "source_sha256": {n: sha(sources[n]) for n in RUNNERS},
               "runtime_uid": user.pw_uid, "runtime_gid": user.pw_gid}
    _write(RECEIPT, canonical(receipt), 0o600)
    return verify(audit_config=config, files=encoded_source_bundle(sources))


def verify(*, audit_config=None, files=None):
    """Verify disk bytes/permissions and Python, without loading or starting units."""
    _root()
    saved = _parse(_read(RECEIPT))
    need(type(saved) is dict and set(saved) == {"schema", "commit", "python", "manifest_sha256",
         "config_sha256", "source_sha256", "runtime_uid", "runtime_gid"}
         and type(saved["schema"]) is int and saved["schema"] == 1 and saved["commit"] == COMMIT
         and saved["manifest_sha256"] == MANIFEST_SHA256, "receipt_contract")
    _python_check(saved["python"])
    user = _context_account()
    need(type(saved["runtime_uid"]) is int and type(saved["runtime_gid"]) is int and
         (saved["runtime_uid"], saved["runtime_gid"]) == (user.pw_uid, user.pw_gid), "runtime_identity")
    for path, mode in ((ROOT, 0o755), (ROOT / "vendor", 0o755), (VENDOR, 0o755),
                       (ETC, 0o755), (STATE, 0o755), (REPORTS, 0o700), (SNAPSHOTS, 0o700)):
        _trusted(path, directory=True)
        _metadata(path, mode)
    lock_raw = _read(LOCK)
    lock = checked_manifest(lock_raw)
    _metadata(LOCK, 0o644)
    _metadata(RECEIPT, 0o600)
    config_raw = _read(CONFIG, MAX_CONFIG)
    config = configuration(_parse(config_raw))
    _metadata(CONFIG, 0o600)
    need(config_raw == canonical(config) and sha(config_raw) == saved["config_sha256"], "installed_config_hash")
    if audit_config is not None:
        need(config == configuration(audit_config), "requested_config_changed")
    need(type(saved["source_sha256"]) is dict and set(saved["source_sha256"]) == set(RUNNERS),
         "receipt_sources")
    for name in RUNNERS:
        raw = _read(ROOT / name)
        _metadata(ROOT / name, 0o644)
        need(sha(raw) == saved["source_sha256"][name], "installed_runner_hash")
        ast.parse(raw, filename=name)
    if files is not None:
        wanted = checked_source_bundle(files)
        need(all(sha(wanted[n]) == saved["source_sha256"][n] for n in RUNNERS), "requested_sources_changed")
    expected_dirs = {p.as_posix() for name in lock["files"] for p in PurePosixPath(name).parents
                     if p != PurePosixPath(".")}
    observed = set()
    for base, dirs, names in os.walk(VENDOR, followlinks=False):
        for name in dirs:
            path = Path(base) / name
            need(path.relative_to(VENDOR).as_posix() in expected_dirs, "unexpected_vendor_directory")
            _trusted(path, directory=True)
            _metadata(path, 0o755)
        for name in names:
            path = Path(base) / name
            relative = path.relative_to(VENDOR).as_posix()
            need(relative in lock["files"], "unexpected_vendor_file")
            raw = _read(path, MAX_EXPANDED)
            _metadata(path, 0o644)
            need({"sha256": sha(raw), "size": len(raw)} == lock["files"][relative], "installed_vendor_hash")
            observed.add(relative)
    need(observed == set(lock["files"]), "installed_vendor_missing")
    for name, raw in unit_documents(saved["python"]).items():
        need(_read(UNIT_DIR / name) == raw, "installed_unit_changed")
        _metadata(UNIT_DIR / name, 0o644)
    _checked_core_config(config, _core_validator(_read(ROOT / "server_audit.py")))
    meta = _metadata(CONTEXT, 0o600)
    need(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1, "context_regular_file_required")
    return {"status": "prepared_verified", "commit": COMMIT, "python": saved["python"],
            "vendor_files": len(observed), "activation_checked": False}


def _loaded_units():
    for name in (CONTEXT_SERVICE, SERVICE, TIMER):
        text = _run(["/usr/bin/systemctl", "show", name, "--property=LoadState",
                     "--property=FragmentPath", "--property=DropInPaths"])
        rows = _pairs(line.split("=", 1) for line in text.splitlines() if "=" in line)
        need(rows == {"LoadState": "loaded", "FragmentPath": str(UNIT_DIR / name),
                      "DropInPaths": ""}, "unit_override_or_load_failure")


def activate(*, config_check=None):
    """Parent-only explicit activation; never run an audit immediately or install pip.

    config_check defaults to the verified installed core's _validate_config.
    It must return the same JSON; normalization requires a new prepared config.
    """
    _root()
    result = verify()
    value = configuration(_parse(_read(CONFIG, MAX_CONFIG)))
    if config_check is None:
        config_check = _core_validator(_read(ROOT / "server_audit.py"))
    _checked_core_config(value, config_check)
    _run(["/usr/bin/systemctl", "daemon-reload"])
    _loaded_units()
    _run(["/usr/bin/systemctl", "enable", "--now", TIMER])
    return {**result, **verify_activation()}


def verify_activation():
    """Inspect activation separately from preparation and actual audit success."""
    result = verify()
    _loaded_units()
    need(_run(["/usr/bin/systemctl", "is-enabled", TIMER]) == "enabled", "timer_not_enabled")
    need(_run(["/usr/bin/systemctl", "is-active", TIMER]) == "active", "timer_not_active")
    return {**result, "status": "timer_active", "activation_checked": True,
            "audit_execution_verified": False}


def main(argv=None):
    """Parent's harness-check/install/verify; install explicitly activates daily work."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "install", "verify"))
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--audit-config", type=Path)
    parser.add_argument("--python", choices=PYTHONS, default="/usr/bin/python3")
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args(argv)
    need(not args.prepare_only or args.action == "install", "prepare_only_requires_install")
    _root()
    _trusted(args.bundle, directory=True)
    config = configuration(_parse(_read(args.audit_config or args.bundle / "audit.json", MAX_CONFIG)))
    sources = source_bundle(args.source_root)
    if args.action == "verify":
        result = verify(audit_config=config, files=sources)
        need(result["python"] == args.python, "requested_python_changed")
        result = verify_activation()
    else:
        operation = check if args.action == "check" else prepare
        result = operation(args.bundle / ARCHIVE_NAME, audit_config=config,
                           files=sources, python=args.python)
        if args.action == "install" and not args.prepare_only:
            result = activate()
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, SyntaxError, KeyError, subprocess.SubprocessError):
        # Never print configuration values, file contents or subprocess stderr.
        print("Harness2 installation check failed; inspect the fixed inputs and permissions.", file=sys.stderr)
        sys.exit(1)
