"""Strict, shared offline-lab manifest validation; standard library only."""
import json
import os
from pathlib import Path
import re
import stat

CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}\Z")
IMAGE_ID_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
IMAGE_TAG_RE = re.compile(r"(?:[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?/)?(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*[a-z0-9]+(?:[._-][a-z0-9]+)*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z")
MAX_MANIFEST_BYTES = 65536
COMMON = {"cve_id", "software", "vulnerable_version"}
REQUIRED = COMMON | {"image_tag", "image_id", "host_port", "container_port"}
ALLOWED = REQUIRED | {"description", "path", "type"}
LAB_TYPES = frozenset(("managed-http", "managed-terminal", "existing-http", "local-cli"))
# Runtime targets are code-owned. A catalog entry cannot choose a socket,
# image, host path, executable or arbitrary terminal destination.
TERMINAL_LABS = {"CVE-2022-0543": "redis", "CVE-2017-7494": "samba", "CVE-2021-3156": "sudo"}


class ManifestError(ValueError):
    pass


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError("duplicate_json_key")
        result[key] = value
    return result


def text(value, maximum, empty=False):
    if not isinstance(value, str) or len(value) > maximum or (not empty and not value.strip()):
        raise ManifestError("invalid_manifest_string")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ManifestError("manifest_control_character")
    return value


def validate_manifest(value):
    if not isinstance(value, list) or len(value) > 32:
        raise ManifestError("manifest_array_max_32_required")
    result, ids, ports = [], set(), set()
    for raw in value:
        if not isinstance(raw, dict):
            raise ManifestError("manifest_fields_mismatch")
        kind = raw.get("type", "managed-http")
        if not isinstance(kind, str) or kind not in LAB_TYPES:
            raise ManifestError("invalid_lab_type")
        required = REQUIRED if kind == "managed-http" else COMMON | {"type"}
        allowed = ALLOWED if kind == "managed-http" else required | {"description"}
        if kind == "existing-http":
            allowed |= {"path"}
        if not required <= raw.keys() or raw.keys() - allowed:
            raise ManifestError("manifest_fields_mismatch")
        item = dict(raw)
        item["type"] = kind
        for key, size in (("cve_id", 28), ("software", 120), ("vulnerable_version", 120)):
            text(item[key], size)
        valid_id = item["cve_id"] == "LAB-DVWA" if kind == "existing-http" else CVE_RE.fullmatch(item["cve_id"])
        if not valid_id or item["cve_id"] in ids:
            raise ManifestError("invalid_or_duplicate_cve")
        if kind == "managed-terminal" and item["cve_id"] not in TERMINAL_LABS:
            raise ManifestError("unsupported_terminal_lab")
        if kind == "managed-http":
            text(item["image_tag"], 255)
            text(item["image_id"], 71)
            if not IMAGE_TAG_RE.fullmatch(item["image_tag"]) or not IMAGE_ID_RE.fullmatch(item["image_id"]):
                raise ManifestError("invalid_pinned_image")
            for key in ("host_port", "container_port"):
                minimum = 1024 if key == "host_port" else 1
                if type(item[key]) is not int or not minimum <= item[key] <= 65535:
                    raise ManifestError("invalid_lab_port")
            if item["host_port"] in ports:
                raise ManifestError("duplicate_host_port")
            ports.add(item["host_port"])
        item["description"] = text(item.get("description", ""), 600, empty=True)
        if kind in {"managed-http", "existing-http"}:
            item["path"] = text(item.get("path", "/"), 256)
            if not re.fullmatch(r"/[A-Za-z0-9/_.~-]*", item["path"]) or "//" in item["path"] or ".." in item["path"].split("/"):
                raise ManifestError("invalid_lab_path")
        ids.add(item["cve_id"])
        result.append(item)
    return result


def trusted_path(path, directory=False):
    """Require a real root-controlled path, including every parent component."""
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ManifestError("absolute_trusted_path_required")
    for component in reversed((path,) + tuple(path.parents)):
        info = component.lstat()
        expected_dir = directory or component != path
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise ManifestError("root_controlled_path_required")
        if expected_dir and not stat.S_ISDIR(info.st_mode):
            raise ManifestError("trusted_directory_required")
        if not expected_dir and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
            raise ManifestError("trusted_regular_file_required")
    return path


def load_manifest(path, require_root=False):
    path = Path(path)
    if require_root:
        trusted_path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_MANIFEST_BYTES:
            raise ManifestError("invalid_manifest_file")
        if require_root and (info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1):
            raise ManifestError("root_controlled_manifest_required")
        data = stream.read(MAX_MANIFEST_BYTES + 1)
    if len(data) > MAX_MANIFEST_BYTES:
        raise ManifestError("manifest_too_large")
    return validate_manifest(json.loads(data.decode("utf-8"), object_pairs_hook=unique_object))
