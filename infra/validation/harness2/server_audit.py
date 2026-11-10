#!/usr/bin/env python3
"""Read-only, stdlib SOC structural audit using the pinned official Harness² core.

Installer contract (Python 3.12): write build_config(...) to the root-owned
/etc/capstone-harness2/audit.json; export the FULL official source (no .git,
venv, bytecode or unlisted files) under framework_root. framework_files is the
trusted framework.lock.json['files'] mapping of relative paths to sha256/size.
The commit is a trusted installer attestation bound to that manifest, not a
claim that this module independently authenticates Git history or signatures.

component_paths overrides only IDs returned by default_component_paths().
Use root-owned collector snapshots for service-user-owned originals. All IDs
are mandatory. Paths, config and source files must have no symlink components,
be owned by root and not group/world writable. Reports directory must already
exist, be separate from inputs, and is the only writable destination.

CLI: /usr/bin/python3 -I -B /opt/capstone-harness2/server_audit.py manual|scheduled
The parent owns systemd scheduling (03:00 Asia/Seoul, Persistent=false), context
collection, installation, MCP authorization and operational approval. Never
forward model-supplied config, paths or origins. This module has no model,
network, subprocess, installer or source-write API. Drafts are review items,
not patches or permission to apply changes. Only pinned official code executes;
SOC Python is parsed/compiled, never imported or executed.
"""

from __future__ import annotations

import argparse
import ast
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import fcntl
import importlib.util
import itertools
import json
import os
from pathlib import Path
import re
import stat
import sys
import threading
import uuid


PINNED_COMMIT = "6868817518876de8fd170c6a8354daca273b6191"
# Canonical {commit, files} digest from the trusted full-source lock for this pin.
PINNED_MANIFEST_SHA256 = "24fdd3ca70a52a41594350b14714ba016197e171b72a38f3ff690f1e5ab70cfc"
CONFIG_PATH = "/etc/capstone-harness2/audit.json"
REPORTS_DIR = "/var/lib/capstone-harness2/reports"
CONTEXT_PATH = "/var/lib/capstone-harness2/context.json"
ORIGINS = frozenset({"manual", "scheduled"})
KST = timezone(timedelta(hours=9), "KST")
MAX_CONTEXT_AGE = 180
MAX_CONFIG = 2 * 1024 * 1024
MAX_CONTEXT = 1024 * 1024
MAX_SOURCE = 2 * 1024 * 1024
MAX_VENDOR_FILE = 16 * 1024 * 1024
MAX_VENDOR_TOTAL = 64 * 1024 * 1024
MAX_VENDOR_FILES = 2048
MAX_REPORT = 4 * 1024 * 1024
MAX_DUPLICATE_PAIRS = 128
MAX_DUPLICATE_CANDIDATES = 30
MAX_DUPLICATE_CHARS = 32768
SKILLS = ("soc-output", "soc-query", "soc-investigate", "soc-change", "soc-recover")
SURFACES = ("native", "sdk", "management")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_IMPORT_LOCK = threading.RLock()
_REPORT_NAME = re.compile(r"\d{8}T\d{12}\+0900-[0-9a-f]{64}\.json\Z")


class AuditError(ValueError):
    """A bounded code, never an exception containing source/credential content."""


@dataclass(frozen=True)
class FilePolicy:
    """Production defaults. Non-root policy is ONLY for isolated local tests.

    This cannot be supplied through audit.json or the CLI. Sticky ancestor
    allowance is needed for test directories below /private/tmp, not deployment.
    """

    uid: int = 0
    allow_sticky_ancestors: bool = False


def default_component_paths() -> dict[str, str]:
    """Fixed SOC IDs and host paths; caller may substitute trusted snapshots."""
    roots = {
        "native": "/opt/hermes-data/plugins/groot-query-completion",
        "sdk": "/opt/capstone-ollama-trial",
        "management": "/opt/capstone-management",
    }
    prompts = {
        "native": "/opt/hermes-data/SOUL.md",
        "sdk": roots["sdk"] + "/soc_policy.md",
        "management": "/opt/hermes-data/management/SOUL.md",
    }
    common = ("chat_markdown", "output_contract", "workflow_contract")
    scripts = {
        "native": {name: name + ".py" for name in (*common, "chat_contract", "read_contract",
                   "grounding", "alignment", "progress", "gateway_health")},
        "sdk": {name: name + ".py" for name in (*common, "chat_contract", "read_contract",
                "grounding", "harness", "runtime", "chat", "chat_policy", "policy",
                "query_grounding", "gateway_health")},
        "management": {name: name + ".py" for name in (*common, "soc_management_run",
                       "soc_management_controller")},
    }
    scripts["native"].update(harness="chat_harness.py", query_grounding="__init__.py")
    paths = {}
    for surface in SURFACES:
        paths[surface + "/systemprompt.md"] = prompts[surface]
        for skill in SKILLS:
            filename = "SKILL.md" if skill == "soc-output" else "skill-" + skill + ".md"
            paths[f"{surface}/skills/{skill}/SKILL.md"] = roots[surface] + "/" + filename
        for name, filename in scripts[surface].items():
            paths[f"{surface}/scripts/{name}.py"] = roots[surface] + "/" + filename
    return paths


def _need(condition, code):
    if not condition:
        raise AuditError(code)


def _json_bytes(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"
    except (TypeError, ValueError, RecursionError):
        raise AuditError("invalid_json_value") from None


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _decode_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            _need(key not in result, "duplicate_json_key")
            result[key] = value
        return result

    def reject_constant(value):
        raise AuditError("nonfinite_json")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                          parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise AuditError("invalid_json") from None


def _absolute(path):
    try:
        path = os.fspath(path)
    except TypeError:
        raise AuditError("absolute_path_required") from None
    _need(isinstance(path, str) and 1 < len(path) <= 4096 and path.startswith("/"),
          "absolute_path_required")
    _need("\\" not in path and "\x00" not in path and
          all(p not in ("", ".", "..") for p in path[1:].split("/")), "unsafe_path")
    return path


def _relative(path):
    _need(isinstance(path, str) and 0 < len(path) <= 512 and not path.startswith("/")
          and "\\" not in path and "\x00" not in path
          and all(p not in ("", ".", "..") for p in path.split("/")), "unsafe_relative_path")
    return path


def _secure_stat(info, policy, *, directory=False, ancestor=False):
    _need(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode),
          "not_directory" if directory else "not_regular_file")
    owners = (0, policy.uid) if ancestor else (policy.uid,)
    _need(info.st_uid in owners, "untrusted_owner")
    sticky = (directory and ancestor and policy.allow_sticky_ancestors
              and info.st_uid == 0 and info.st_mode & stat.S_ISVTX)
    _need(not info.st_mode & 0o022 or sticky, "writable_by_others")
    if not directory:
        _need(info.st_nlink == 1, "hardlink_rejected")


@contextmanager
def _directory(path, policy):
    """Walk with dirfds/O_NOFOLLOW; never resolve an attacker-controlled link."""
    parts = _absolute(path)[1:].split("/")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _secure_stat(os.fstat(fd), policy, directory=True, ancestor=True)
        for i, part in enumerate(parts):
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
            _secure_stat(os.fstat(fd), policy, directory=True, ancestor=i != len(parts) - 1)
        yield fd
    finally:
        os.close(fd)


def _read_at(directory_fd, name, limit, policy):
    _need("/" not in name and name not in ("", ".", ".."), "unsafe_filename")
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    try:
        before = os.fstat(fd)
        _secure_stat(before, policy)
        _need(before.st_size <= limit, "file_size_limit")
        chunks, count = [], 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
            _need(count <= limit, "file_size_limit")
        after = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns,
                              s.st_uid, s.st_mode, s.st_nlink)
        _need(identity(before) == identity(after) and count == after.st_size, "file_changed_during_read")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _read(path, limit, policy):
    path = _absolute(path)
    with _directory(str(Path(path).parent), policy) as fd:
        return _read_at(fd, Path(path).name, limit, policy)


def _manifest(files):
    _need(isinstance(files, dict) and 3 <= len(files) <= MAX_VENDOR_FILES, "invalid_framework_files")
    total = 0
    for name, item in files.items():
        _relative(name)
        _need(isinstance(item, dict) and set(item) == {"sha256", "size"}, "invalid_file_manifest")
        _need(isinstance(item["sha256"], str) and _SHA.fullmatch(item["sha256"]), "invalid_sha256")
        _need(type(item["size"]) is int and 0 <= item["size"] <= MAX_VENDOR_FILE, "invalid_file_size")
        total += item["size"]
    _need(total <= MAX_VENDOR_TOTAL, "framework_total_limit")
    _need({"harness2/__init__.py", "harness2/core/__init__.py", "harness2/core/tree.py"} <= files.keys(),
          "missing_official_core")
    digest = _sha(_json_bytes({"commit": PINNED_COMMIT, "files": files}))
    _need(digest == PINNED_MANIFEST_SHA256, "not_pinned_full_source_manifest")
    return digest


def build_config(framework_root, framework_files, *, reports_dir=REPORTS_DIR,
                 component_paths=None, collector_facts=None, context_path=CONTEXT_PATH):
    """Pure config builder; performs no I/O. Pass lock['files'] unchanged.

    Overrides are a subset of the fixed ID map; the returned map is complete.
    Static collector_facts are provenance only, never a fresh runtime observation.
    """
    paths = default_component_paths()
    if component_paths is not None:
        _need(isinstance(component_paths, dict) and component_paths.keys() <= paths.keys(),
              "unknown_component_id")
        paths.update({key: os.fspath(value) for key, value in component_paths.items()})
    config = {
        "schema_version": 1,
        "framework": {"root": os.fspath(framework_root), "commit": PINNED_COMMIT,
                      "files": framework_files, "manifest_sha256": _manifest(framework_files)},
        "reports_dir": os.fspath(reports_dir), "component_paths": paths,
        "collector_facts": {} if collector_facts is None else collector_facts,
        "context_path": os.fspath(context_path),
    }
    return _validate_config(config)


def _validate_config(config):
    raw = _json_bytes(config)
    _need(len(raw) <= MAX_CONFIG, "config_size_limit")
    config = _decode_json(raw)  # immutable per-call snapshot of caller's objects
    _need(isinstance(config, dict) and set(config) == {
        "schema_version", "framework", "reports_dir", "component_paths", "collector_facts", "context_path"
    } and type(config["schema_version"]) is int and config["schema_version"] == 1, "invalid_config_schema")
    fw = config["framework"]
    _need(isinstance(fw, dict) and set(fw) == {"root", "commit", "files", "manifest_sha256"},
          "invalid_framework_config")
    _need(fw["commit"] == PINNED_COMMIT, "unpinned_commit")
    _need(_manifest(fw["files"]) == fw["manifest_sha256"], "manifest_hash_mismatch")
    root = _absolute(fw["root"])
    reports = _absolute(config["reports_dir"])
    _absolute(config["context_path"])
    paths = config["component_paths"]
    _need(isinstance(paths, dict) and paths.keys() == default_component_paths().keys(), "component_id_mismatch")
    _need(isinstance(config["collector_facts"], dict)
          and len(_json_bytes(config["collector_facts"])) <= 32768, "invalid_collector_facts")
    for path in (*paths.values(), config["context_path"], CONFIG_PATH):
        _absolute(path)
        _need(path != reports and not path.startswith(reports + "/"), "reports_overlap_input")
    _need(len(set(paths.values())) == len(paths), "component_path_alias")
    _need(root != reports and not reports.startswith(root + "/")
          and not root.startswith(reports + "/"), "reports_overlap_framework")
    originals = config["collector_facts"].get("component_sources")
    if originals is not None:
        _need(isinstance(originals, dict) and originals.keys() == paths.keys(), "invalid_component_sources")
        for path in originals.values():
            _absolute(path)
    return config


def validate_config(config):
    """Public pure schema validator, returning a detached validated dictionary."""
    return _validate_config(config)


def _error_code(exc):
    if isinstance(exc, AuditError):
        return str(exc)
    if isinstance(exc, FileNotFoundError):
        return "missing_file"
    if isinstance(exc, PermissionError):
        return "permission_denied"
    return "unsafe_or_unreadable_path"


def _verify_framework(framework, policy):
    """Verify exact full inventory, hashes and sizes; retain only import bytes."""
    wanted = framework["files"]
    observed, imports = {}, {}
    expected_dirs = {str(parent) for rel in wanted for parent in Path(rel).parents if str(parent) != "."}
    seen_dirs = set()
    with _directory(framework["root"], policy) as root_fd:
        def walk(fd, prefix=""):
            entries = os.listdir(fd)
            _need(len(entries) <= MAX_VENDOR_FILES * 2, "framework_inventory_limit")
            for name in sorted(entries):
                rel = prefix + name
                _relative(rel)
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    _need(rel in expected_dirs, "unlisted_framework_directory")
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        _secure_stat(os.fstat(child), policy, directory=True)
                        seen_dirs.add(rel)
                        walk(child, rel + "/")
                    finally:
                        os.close(child)
                else:
                    _need(rel in wanted, "unlisted_framework_file")
                    raw = _read_at(fd, name, MAX_VENDOR_FILE, policy)
                    observed[rel] = {"sha256": _sha(raw), "size": len(raw)}
                    _need(observed[rel] == wanted[rel], "framework_source_mismatch")
                    if rel in ("harness2/__init__.py", "harness2/core/__init__.py", "harness2/core/tree.py"):
                        imports[rel] = raw
        walk(root_fd)
    _need(observed.keys() == wanted.keys() and seen_dirs == expected_dirs, "missing_framework_file")
    return observed, imports


@contextmanager
def _official_tree(framework, imports):
    """On-demand import from verified bytes, without ambient harness2 or .pyc.

    A private package namespace avoids adopting an installed/unpinned harness2
    and leaves any parent's imports untouched. The functions are the unmodified
    official harness2.core.tree implementation, not a local reimplementation.
    """
    prefix = "_capstone_harness2_" + framework["manifest_sha256"]
    with _IMPORT_LOCK:
        loaded = []
        try:
            for suffix, rel, package in (
                ("", "harness2/__init__.py", True),
                (".core", "harness2/core/__init__.py", True),
                (".core.tree", "harness2/core/tree.py", False),
            ):
                name = prefix + suffix
                _need(name not in sys.modules, "official_import_collision")
                filename = framework["root"] + "/" + rel
                spec = importlib.util.spec_from_loader(name, loader=None, origin=filename, is_package=package)
                module = importlib.util.module_from_spec(spec)
                module.__file__ = filename
                if package:
                    module.__path__ = [str(Path(filename).parent)]
                sys.modules[name] = module
                loaded.append(name)
                exec(compile(imports[rel], filename, "exec", dont_inherit=True), module.__dict__)
            _need(all(callable(getattr(module, name, None)) for name in
                      ("SurfaceSpec", "validate", "diff_summary", "is_allowed")), "unsupported_official_api")
            yield module
        finally:
            for name in reversed(loaded):
                sys.modules.pop(name, None)


def _surface(tree, name):
    return tree.SurfaceSpec(
        name="soc-" + name, always_on=("systemprompt.md",), always_on_max=65536,
        always_on_cap_reason="fixed audit structural cap; not a model context estimate",
        skill_dir="skills", skill_name_rule="must_match", trigger_hint="Review actual runtime skill routing.",
        autotrigger_file="systemprompt.md", trigger_line="", subagent_requires_mode=True,
        plugin_dir=None, hooks_file=None, compile_skill_scripts=True, reject_empty_always_on=True,
    )


def _parse_component(relative, raw):
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError:
        raise AuditError("source_not_utf8") from None
    _need("\x00" not in text, "source_contains_nul")
    _need(bool(text.strip()), "empty_component")
    if relative.startswith("scripts/"):
        try:
            ast.parse(text, filename=relative)
        except (SyntaxError, ValueError, RecursionError):
            raise AuditError("python_parse_failed") from None
    elif relative.startswith("skills/"):
        lines = text.splitlines()
        _need(lines[0] == "---" and "---" in lines[1:], "skill_frontmatter_missing")
        end = lines.index("---", 1)
        _need(len("\n".join(lines[:end + 1])) <= 600, "skill_frontmatter_beyond_official_window")
        fields = {}
        for line in lines[1:end]:
            if not line.strip() or line.startswith("#"):
                continue
            match = re.fullmatch(r"(name|description):\s*(\S.*)", line)
            _need(match is not None, "unsupported_skill_frontmatter")
            key, value = match.groups()
            _need(key not in fields and value[0] not in "'\"[{:|>&*!", "unsupported_skill_scalar")
            fields[key] = value.strip()
        _need(fields.keys() == {"name", "description"} and fields["name"] == relative.split("/")[1],
              "invalid_skill_identity")
    return text


def _timestamp(value):
    _need(isinstance(value, str) and len(value) <= 64, "invalid_observation_time")
    try:
        result = datetime.fromisoformat(value)
    except ValueError:
        raise AuditError("invalid_observation_time") from None
    _need(result.utcoffset() is not None, "observation_timezone_required")
    return result


def _context(path, now, policy):
    result = {"status": "incomplete", "path": path,
              "limitation": "Catalog names/schema hashes only, not full schemas; configured model identity, inference untested."}
    try:
        raw = _read(path, MAX_CONTEXT, policy)
        result["sha256"] = _sha(raw)
        doc = _decode_json(raw)
        _need(isinstance(doc, dict) and type(doc.get("schema")) is int and doc["schema"] == 1,
              "invalid_context_schema")
        _need(doc.get("status") in ("observed", "unavailable"), "invalid_context_status")
        result["source_observations"] = doc.get("source_observations")
        result["observed_at_kst"] = doc.get("observed_at_kst")
        observed = _timestamp(doc.get("observed_at_kst"))
        age = (now - observed).total_seconds()
        result["age_seconds"] = age
        _need(0 <= age <= MAX_CONTEXT_AGE, "context_stale_or_future")
        _need(doc["status"] == "observed", "context_unavailable")
        _need(all(type(doc.get(k)) is int and doc[k] == 0 for k in
                  ("model_calls", "tool_calls", "chat_posts", "protected_calls")), "context_calls_unverified")
        _need(isinstance(doc.get("model"), str) and 0 < len(doc["model"]) <= 512
              and isinstance(doc.get("access_mode"), str) and 0 < len(doc["access_mode"]) <= 128,
              "context_model_missing")
        catalog = doc.get("catalog")
        _need(isinstance(catalog, list) and 0 < len(catalog) <= 1024, "context_catalog_missing")
        names = set()
        for entry in catalog:
            _need(isinstance(entry, dict) and all(isinstance(entry.get(k), str) and 0 < len(entry[k]) <= 512
                  for k in ("server", "name", "alias", "schema_sha256"))
                  and _SHA.fullmatch(entry["schema_sha256"]), "context_catalog_invalid")
            identity = (entry["server"], entry["name"], entry["alias"])
            _need(identity not in names, "context_catalog_duplicate")
            names.add(identity)
        _need(isinstance(doc.get("catalog_sha256"), str) and _SHA.fullmatch(doc["catalog_sha256"]),
              "context_catalog_hash_missing")
        catalog_bytes = json.dumps(catalog, sort_keys=True, separators=(",", ":")).encode()
        _need(_sha(catalog_bytes) == doc["catalog_sha256"], "context_catalog_hash_mismatch")
        hashes = doc.get("configuration_sha256")
        _need(isinstance(hashes, dict) and 0 < len(hashes) <= 1024 and all(
            isinstance(k, str) and len(k) <= 4096 and isinstance(v, str) and _SHA.fullmatch(v)
            for k, v in hashes.items()), "context_configuration_hashes_missing")
        _need(doc.get("error_code") is None, "context_collector_error")
        result.update(status="observed", model=doc["model"], access_mode=doc["access_mode"],
                      catalog=catalog, catalog_sha256=doc["catalog_sha256"],
                      configuration_sha256=hashes, counters={k: doc[k] for k in
                      ("model_calls", "tool_calls", "chat_posts", "protected_calls")},
                      catalog_hash_basis="verified catalog projection hash; schema hashes attested by collector")
    except (AuditError, OSError) as exc:
        result["error_code"] = _error_code(exc)
    return result


def _snapshot_binding(config, context, sources, now):
    observations = context.pop("source_observations", None)
    originals = config["collector_facts"].get("component_sources", config["component_paths"])
    result = {"status": "incomplete", "components": {}}
    try:
        _need(isinstance(observations, dict), "source_snapshot_missing")
        _need(observations.keys() == config["component_paths"].keys(),
              "source_snapshot_ids_mismatch")
        for key, path in config["component_paths"].items():
            item = observations[key]
            _need(isinstance(item, dict) and item.get("path") == originals[key], "source_snapshot_path_mismatch")
            _need(item.get("status") == "observed" and item.get("error_code") is None, "source_snapshot_unavailable")
            observed = _timestamp(item.get("observed_at_kst"))
            _need(0 <= (now - observed).total_seconds() <= MAX_CONTEXT_AGE
                  and observed <= _timestamp(context["observed_at_kst"]), "source_snapshot_stale_or_future")
            _need(sources[key]["status"] == "read" and item.get("sha256") == sources[key].get("sha256")
                  and type(item.get("size")) is int and item["size"] == sources[key].get("size"),
                  "source_snapshot_hash_mismatch")
            _need(all(type(item.get(k)) is int and item[k] >= 0 for k in ("uid", "gid"))
                  and isinstance(item.get("mode"), str) and re.fullmatch(r"0o[0-7]{3,4}", item["mode"]),
                  "source_snapshot_metadata_invalid")
            result["components"][key] = {k: item[k] for k in
                ("path", "status", "sha256", "size", "uid", "gid", "mode", "observed_at_kst")}
            result["components"][key]["snapshot_path"] = path
        expected_config = config["collector_facts"].get("configuration_paths")
        if expected_config is not None:
            _need(isinstance(expected_config, list) and all(isinstance(p, str) for p in expected_config)
                  and set(expected_config) == set(context.get("configuration_sha256", {})),
                  "context_configuration_paths_mismatch")
        result["status"] = "verified"
    except AuditError as exc:
        result["error_code"] = str(exc)
    return result


def _cross_copy(sources):
    result = []
    for skill in SKILLS:
        ids = [f"{surface}/skills/{skill}/SKILL.md" for surface in SURFACES]
        hashes = {key: sources[key].get("sha256") for key in ids}
        complete = all(sources[key]["status"] == "read" for key in ids)
        status = ("identical" if len(set(hashes.values())) == 1 else "drift") if complete else "incomplete"
        result.append({"skill": skill, "status": status, "copies": hashes})
    return result


def _duplicates(trees, sources):
    items, truncated = [], []
    for surface, tree in trees.items():
        for rel, text in sorted(tree.items()):
            if not rel.startswith("skills/"):
                continue
            key = surface + "/" + rel
            if len(text) > MAX_DUPLICATE_CHARS:
                truncated.append(key)
                continue
            body = text.split("---", 2)[-1]
            words = set(re.findall(r"\w+", body.casefold()))
            if len(words) >= 4:
                items.append((key, rel, words))
    candidates, compared = [], 0
    pair_limit = candidate_limit = False
    for left, right in itertools.combinations(items, 2):
        if left[1] == right[1]:
            continue  # same-skill replicas have their own exact drift report
        if compared >= MAX_DUPLICATE_PAIRS:
            pair_limit = True
            break
        compared += 1
        score = len(left[2] & right[2]) / len(left[2] | right[2])
        if score >= 0.85:
            if len(candidates) == MAX_DUPLICATE_CANDIDATES:
                candidate_limit = True
                continue
            candidates.append({"components": [left[0], right[0]], "token_jaccard": round(score, 4),
                               "sha256": [sources[left[0]]["sha256"], sources[right[0]]["sha256"]]})
    return {"method": "bounded casefolded body-token Jaccard >= 0.85; review leads only",
            "pairs_compared": compared, "pair_limit": MAX_DUPLICATE_PAIRS,
            "candidate_limit": MAX_DUPLICATE_CANDIDATES, "skipped_large_components": truncated,
            "truncated": bool(truncated or pair_limit or candidate_limit), "candidates": candidates,
            "automatic_merge": False}


def _atomic_file(fd, name, raw, *, replace=False):
    temp = ".audit-" + uuid.uuid4().hex + ".tmp"
    out = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        with os.fdopen(out, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(temp, name, src_dir_fd=fd, dst_dir_fd=fd)
        else:
            os.link(temp, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
        os.fsync(fd)
    finally:
        try:
            os.unlink(temp, dir_fd=fd)
        except FileNotFoundError:
            pass
        os.fsync(fd)


def _store(report, reports_dir, policy):
    raw = _json_bytes(report)
    _need(len(raw) <= MAX_REPORT, "report_size_limit")
    digest = _sha(raw)
    at = _timestamp(report["observed_at_kst"]).astimezone(KST)
    filename = at.strftime("%Y%m%dT%H%M%S%f%z") + "-" + digest + ".json"
    pointer = {"schema_version": 1, "report": filename, "sha256": digest,
               "observed_at_kst": report["observed_at_kst"]}
    with _directory(reports_dir, policy) as fd:
        fcntl.flock(fd, fcntl.LOCK_EX)
        # An existing non-regular pointer is rejected, not followed/replaced.
        previous = None
        try:
            previous = _decode_json(_read_at(fd, "latest.json", 4096, policy))
            _need(isinstance(previous, dict), "invalid_latest_pointer")
            previous_at = _timestamp(previous.get("observed_at_kst"))
        except FileNotFoundError:
            pass
        _atomic_file(fd, filename, raw)
        if previous is None or at >= previous_at:
            _atomic_file(fd, "latest.json", _json_bytes(pointer), replace=True)
    return {"report": report, "report_file": filename, "sha256": digest}


def run_audit(config, origin="manual", *, policy=None, now=None):
    """Read fixed inputs, run official structural checks, persist immutable report.

    Returns {report: {...}, report_file: basename, sha256: digest}. Status is
    'passed', 'findings' or 'incomplete', always scoped to structural checks.
    Invalid trust config/storage raises AuditError/OSError; input failures are
    recorded as incomplete. policy/now are injectable ONLY for isolated tests.
    """
    _need(isinstance(origin, str) and origin in ORIGINS, "invalid_origin")
    config = _validate_config(config)
    policy = FilePolicy() if policy is None else policy
    now = datetime.now(KST) if now is None else now
    _need(isinstance(now, datetime) and now.utcoffset() is not None, "aware_time_required")
    now = now.astimezone(KST)
    with _directory(config["reports_dir"], policy):
        pass  # Reject unsafe storage before any expensive work/import.
    report = {
        "schema_version": 1, "scope": "structural checks", "origin": origin,
        "observed_at_kst": now.isoformat(timespec="microseconds"), "status": "incomplete",
        "config_sha256": _sha(_json_bytes(config)), "collector_facts": config["collector_facts"],
        "model_calls": 0, "tool_calls": 0, "chat_posts": 0, "protected_calls": 0,
        "source_writes": 0, "automatic_adoption": False, "operational_changes_require_approval": True,
        "limitations": ["No correctness, improvement, latency or live inference claim.",
                        "Fixed SOC projection, not exhaustive runtime composition; no synthetic trigger text.",
                        "Per-file observations are not a transactional snapshot of all services.",
                        "Duplicate candidates are bounded lexical leads, never automatic merges."],
        "framework": {"status": "incomplete", "commit": PINNED_COMMIT,
                      "root": config["framework"]["root"],
                      "manifest_sha256": config["framework"]["manifest_sha256"],
                      "commit_basis": "trusted root manifest attestation"},
        "sources": {}, "surfaces": {}, "framework_diffs": [], "review_drafts": [],
    }
    report["context"] = _context(config["context_path"], now, policy)
    trees = {surface: {} for surface in SURFACES}
    for key, path in sorted(config["component_paths"].items()):
        surface, relative = key.split("/", 1)
        source = {"path": path, "status": "incomplete"}
        try:
            raw = _read(path, MAX_SOURCE, policy)
            source.update(sha256=_sha(raw), size=len(raw))
            trees[surface][relative] = _parse_component(relative, raw)
            source["status"] = "read"
        except (AuditError, OSError) as exc:
            source["error_code"] = _error_code(exc)
        report["sources"][key] = source
    try:
        hashes, imports = _verify_framework(config["framework"], policy)
        report["framework"].update(status="verified", files=hashes)
        with _official_tree(config["framework"], imports) as official:
            for surface in SURFACES:
                spec = _surface(official, surface)
                missing = [key for key, value in report["sources"].items()
                           if key.startswith(surface + "/") and value["status"] != "read"]
                result = {"status": "incomplete" if missing else "passed", "unreadable_components": missing}
                try:
                    _need(all(official.is_allowed(spec, rel) for rel in trees[surface]), "off_surface_component")
                    result["census"] = official.validate(spec, trees[surface], allow_subagents=False)
                except ValueError as exc:
                    result["status"] = "incomplete" if missing else "findings"
                    # Do not echo exception text: it can contain arbitrary source literals.
                    result["error_code"] = "official_validation_failed"
                    result["diagnostic_sha256"] = _sha(str(exc).encode("utf-8", errors="replace"))
                report["surfaces"][surface] = result
            for left, right in itertools.combinations(SURFACES, 2):
                complete = all(report["sources"][key]["status"] == "read" for key in report["sources"]
                               if key.startswith((left + "/", right + "/")))
                item = {"before": left, "after": right, "status": "observed" if complete else "incomplete",
                        "basis": "fixed cross-surface projection; additions/removals may be intentional"}
                if complete:
                    item["diff"] = official.diff_summary(_surface(official, left), trees[left], trees[right])
                report["framework_diffs"].append(item)
    except Exception as exc:
        # Official API incompatibility/parse failure must never become a pass.
        report["framework"].update(status="incomplete", error_code=(
            _error_code(exc) if isinstance(exc, (AuditError, OSError)) else "official_core_unavailable"))
    report["cross_copy_skills"] = _cross_copy(report["sources"])
    report["source_snapshot"] = _snapshot_binding(config, report["context"], report["sources"], now)
    report["duplicates"] = _duplicates(trees, report["sources"])
    complete = (report["context"]["status"] == "observed" and report["framework"]["status"] == "verified"
                and report["source_snapshot"]["status"] != "incomplete"
                and len(report["surfaces"]) == len(SURFACES)
                and all(value["status"] != "incomplete" for value in report["surfaces"].values()))
    findings = (any(value["status"] == "findings" for value in report["surfaces"].values())
                or any(item["status"] == "drift" for item in report["cross_copy_skills"])
                or bool(report["duplicates"]["candidates"]))
    report["status"] = ("findings" if findings else "passed") if complete else "incomplete"
    report["draft_status"] = "review_only" if complete else "withheld_incomplete_evidence"
    if complete:
        for surface, item in report["surfaces"].items():
            if item["status"] == "findings":
                report["review_drafts"].append({"kind": "review_structural_findings", "surface": surface,
                    "diagnostic_sha256": item["diagnostic_sha256"], "requires_approval": True, "apply": False})
        for item in report["cross_copy_skills"]:
            if item["status"] == "drift":
                report["review_drafts"].append({"kind": "review_skill_drift", "skill": item["skill"],
                    "source_sha256": item["copies"], "requires_approval": True, "apply": False})
        for item in report["duplicates"]["candidates"]:
            report["review_drafts"].append({"kind": "review_possible_duplicate", **item,
                                           "requires_approval": True, "apply": False})
    return _store(report, config["reports_dir"], policy)


def get_latest(reports_dir=REPORTS_DIR, *, policy=None):
    """Read-only bounded summary for a future MCP tool; never initiates an audit.

    Raises on missing/corrupt/unsafe evidence. It does not claim a stored report
    is current; observed_at_kst is always returned. No source bodies or metadata
    supplied by model input are exposed in the summary.
    """
    policy = FilePolicy() if policy is None else policy
    with _directory(reports_dir, policy) as fd:
        pointer = _decode_json(_read_at(fd, "latest.json", 4096, policy))
        _need(isinstance(pointer, dict) and set(pointer) == {
            "schema_version", "report", "sha256", "observed_at_kst"} and pointer["schema_version"] == 1,
            "invalid_latest_pointer")
        name = pointer["report"]
        _need(isinstance(name, str) and _REPORT_NAME.fullmatch(name), "invalid_report_name")
        _need(isinstance(pointer["sha256"], str) and _SHA.fullmatch(pointer["sha256"])
              and name.endswith("-" + pointer["sha256"] + ".json"), "invalid_report_hash")
        raw = _read_at(fd, name, MAX_REPORT, policy)
        _need(_sha(raw) == pointer["sha256"], "report_hash_mismatch")
        report = _decode_json(raw)
    _need(isinstance(report, dict) and report.get("schema_version") == 1
          and report.get("scope") == "structural checks" and report.get("origin") in ORIGINS
          and report.get("status") in ("passed", "findings", "incomplete")
          and report.get("observed_at_kst") == pointer["observed_at_kst"]
          and report.get("automatic_adoption") is False, "invalid_report_schema")
    at = _timestamp(report["observed_at_kst"]).astimezone(KST)
    _need(name.startswith(at.strftime("%Y%m%dT%H%M%S%f%z") + "-"), "report_time_mismatch")
    return {"schema_version": 1, "scope": "structural checks", "status": report["status"],
            "origin": report["origin"], "observed_at_kst": report["observed_at_kst"],
            "report_file": name, "sha256": pointer["sha256"],
            "automatic_adoption": False, "operational_changes_require_approval": True}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Pinned official Harness² structural checks only.")
    parser.add_argument("origin", choices=sorted(ORIGINS))
    args = parser.parse_args(argv)
    try:
        config = _decode_json(_read(CONFIG_PATH, MAX_CONFIG, FilePolicy()))
        result = run_audit(config, args.origin)
        report = result["report"]
        print(json.dumps({"scope": report["scope"], "status": report["status"],
                          "report_file": result["report_file"], "sha256": result["sha256"]}))
        # A persisted incomplete/finding report is a completed audit job, not a
        # systemd execution failure. Consumers MUST inspect report['status'].
        return 0
    except (AuditError, OSError) as exc:
        print(json.dumps({"scope": "structural checks", "status": "incomplete", "error_code": _error_code(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
