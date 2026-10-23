#!/usr/bin/env python3
"""Root-owned, fixed-target executor for human-approved rule changes.

The stdio MCP user may invoke this file *without arguments* via one sudoers
entry. It accepts fixed JSON operations, including full-file ``propose`` and
literal ``propose-edit``, on stdin. A root-only
systemd timer invokes ``--once`` to complete approved proposals. No MCP field
is a filesystem path, container name, command, URL, or approval identity.

This file is intentionally separate from response-mcp.py: rule edits always
fail closed when the broker, approver, validation, or live base has changed.
"""

import contextlib
from datetime import datetime
import difflib
import fcntl
import hashlib
import hmac
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
from types import SimpleNamespace
import unicodedata
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

CONFIG_PATH = Path("/etc/rule-change/config.json")
STATE_DIR = Path("/var/lib/rule-change")
DOCKER = "/usr/local/bin/docker"  # fixed path on the live A/B hosts
MAX_CANDIDATE = 128 * 1024
MAX_DIFF = 512 * 1024
MAX_EDITS = 16
MAX_EDIT_TEXT = 64 * 1024
# JSON escaping can expand a bounded UTF-8 candidate or stored diff. Keep
# transport/state limits separate from the unchanged rule-file size limit.
MAX_REQUEST = 1024 * 1024
MAX_STATE = 4 * 1024 * 1024
MAX_RULESET = 64 * 1024 * 1024
PROPOSAL_ID = re.compile(r"^[0-9a-f]{16,64}$")
HEX_SHA = re.compile(r"^[0-9a-f]{64}$")
SURICATA_ET_OVERRIDES = frozenset((2034806, 2034802))
SURICATA_LLM_BIT = b"groot_llm_api"
# Exact destination/revision pairs: legacy endpoint or the approved two-endpoint list.
# Other lists, list spellings, subnets and free revisions are not accepted.
SURICATA_LLM_MARKER_PROFILES = (
    (b"211.170.162.110", b"1"),
    (b"[211.170.162.110,211.170.162.111]", b"2"),
)
EXTENSION_DIR = Path("/opt/rule-change")
_EXTENSIONS = {}
INCIDENT_LOCATION = "/home/groot_a/capstone/secstack/logs/suricata/eve.json"

TARGETS = {
    "a:modsecurity-custom": {
        "host": "a", "kind": "waf", "path": "/home/groot_a/capstone/secstack/conf/GROOT_A_WAF.conf",
        "container": "waf", "container_path": "/etc/modsecurity.d/owasp-crs/rules/REQUEST-948-GROOT_A_WAF.conf",
        "mount_source": "/home/groot_a/capstone/secstack/conf/GROOT_A_WAF.conf", "mount_dest": "/etc/modsecurity.d/owasp-crs/rules/REQUEST-948-GROOT_A_WAF.conf",
        "impact": "WAF nginx configuration test and reload; DetectionOnly remains enabled. Single-file bind requires inode-preserving write.",
    },
    "a:suricata-local": {
        "host": "a", "kind": "suricata", "path": "/home/groot_a/capstone/suricata/ruleset/GROOT_A_local.rules",
        "et_path": "/home/groot_a/capstone/suricata/ruleset/suricata.rules",
        "all_path": "/home/groot_a/capstone/suricata/ruleset/all.rules",
        "container": "suricata", "container_path": "/rules/all.rules",
        "mount_source": "/home/groot_a/capstone/suricata/ruleset", "mount_dest": "/rules",
        "impact": "Suricata passive local rules and all.rules are replaced together and syntax-tested. Only ET2034806/2034802 exact upstream-derived overrides with the fixed Ollama flowbit guard are allowed; the ET source file stays unchanged. The existing Suricata container restarts because -S prevents hot reload; detection pauses briefly. Runtime rule statistics and load time are checked. No inline/drop transition.",
    },
    "b:wazuh-local-rules": {
        "host": "b", "kind": "wazuh", "path": "/var/lib/docker/volumes/single-node_wazuh_etc/_data/rules/local_rules.xml",
        "container": "single-node-wazuh.manager-1", "container_path": "/var/ossec/etc/rules/local_rules.xml",
        "mount_source": "/var/lib/docker/volumes/single-node_wazuh_etc/_data", "mount_dest": "/var/ossec/etc",
        "impact": "Wazuh analysisd test and manager container restart; brief SIEM collection interruption is possible.",
    },
}


class RuleChangeError(Exception):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def proposal_limits():
    return {"max_candidate_utf8_bytes": MAX_CANDIDATE,
            "max_diff_utf8_bytes": MAX_DIFF,
            "max_edits": MAX_EDITS,
            "max_edit_text_utf8_bytes": MAX_EDIT_TEXT,
            "edit_matching": "exactly_once_in_original_nonoverlapping",
            "review_presentation": "automatic_multipart_if_needed",
            "approval_scope": "entire_candidate_once"}


def _validated_edits(edits):
    """Validate the bounded literal-edit protocol before acquiring a live lock."""
    if not isinstance(edits, list) or not 1 <= len(edits) <= MAX_EDITS:
        raise RuleChangeError("edits must contain 1..16 literal replacements")
    encoded, total = [], 0
    for edit in edits:
        if not isinstance(edit, dict) or set(edit) != {"old_text", "new_text"}:
            raise RuleChangeError("each edit must contain only old_text and new_text")
        old, new = edit["old_text"], edit["new_text"]
        if not isinstance(old, str) or not old or not isinstance(new, str):
            raise RuleChangeError("old_text must be nonempty text and new_text must be text")
        if old == new:
            raise RuleChangeError("an edit must change its matched text")
        try:
            old, new = old.encode("utf-8"), new.encode("utf-8")
        except UnicodeEncodeError:
            raise RuleChangeError("edit text must be valid UTF-8") from None
        total += len(old) + len(new)
        if total > MAX_EDIT_TEXT:
            raise RuleChangeError("combined old_text and new_text exceed 64 KiB UTF-8")
        encoded.append((old, new))
    return encoded


def _edit_candidate(current, edits):
    """Resolve every edit in the original bytes, then splice once without normalization."""
    spans = []
    size = len(current)
    for index, (old, new) in enumerate(edits, 1):
        start = current.find(old)
        if start < 0:
            raise RuleChangeError("edit %d old_text is absent from the original file" % index)
        # Searching one byte after the first start also detects overlapping matches.
        if current.find(old, start + 1) >= 0:
            raise RuleChangeError("edit %d old_text must match exactly once in the original file" % index)
        spans.append((start, start + len(old), new))
        size += len(new) - len(old)
    spans.sort(key=lambda span: span[0])
    if any(right[0] < left[1] for left, right in zip(spans, spans[1:])):
        raise RuleChangeError("edit ranges overlap in the original file")
    if not 0 < size <= MAX_CANDIDATE:
        raise RuleChangeError("assembled candidate must be nonempty and <=128 KiB UTF-8")
    parts, cursor = [], 0
    for start, end, new in spans:
        parts.extend((current[cursor:start], new))
        cursor = end
    parts.append(current[cursor:])
    try:
        return b"".join(parts).decode("utf-8")
    except UnicodeDecodeError:
        raise RuleChangeError("assembled candidate must be valid UTF-8") from None


def proposal_digest(payload):
    keys = ("target", "base_sha256", "candidate_sha256", "diff_sha256", "diff", "requested_by", "expires_at")
    canonical = {key: payload[key] for key in keys}
    return sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))


@contextlib.contextmanager
def _parent_fd(path):
    """Anchor every path component; never follow a parent or leaf symlink."""
    path = Path(path)
    if not path.is_absolute() or not path.name:
        raise RuleChangeError("file path must be absolute")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open("/", flags)
    try:
        for part in path.parts[1:-1]:
            if part in ("", ".", ".."):
                raise RuleChangeError("unsafe path component")
            try:
                next_fd = os.open(part, flags, dir_fd=fd)
            except OSError:
                raise RuleChangeError("target parent path is unavailable or contains a symlink") from None
            os.close(fd)
            fd = next_fd
        yield fd
    finally:
        os.close(fd)


def _read_regular(path, limit=MAX_CANDIDATE):
    path = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    with _parent_fd(path) as parent:
        fd = os.open(path.name, flags, dir_fd=parent)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > limit or st.st_nlink != 1:
                raise RuleChangeError("target must be a bounded, single-link regular file")
            data = b""
            while len(data) <= limit:
                chunk = os.read(fd, min(1024 * 1024, limit + 1 - len(data)))
                if not chunk:
                    break
                data += chunk
            if len(data) > limit:
                raise RuleChangeError("file exceeded size limit")
            return data, st
        finally:
            os.close(fd)


def _atomic_bytes(path, data, old_stat=None, mode=0o600):
    path = Path(path)
    with _parent_fd(path) as parent:
        temp_name = ".%s.%s" % (path.name, secrets.token_hex(12))
        fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=parent)
        try:
            with os.fdopen(fd, "wb") as out:
                out.write(data)
                out.flush()
                os.fsync(out.fileno())
                if old_stat:
                    os.fchown(out.fileno(), old_stat.st_uid, old_stat.st_gid)
                    os.fchmod(out.fileno(), stat.S_IMODE(old_stat.st_mode))
                else:
                    os.fchmod(out.fileno(), mode)
            os.replace(temp_name, path.name, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
        finally:
            try:
                os.unlink(temp_name, dir_fd=parent)
            except FileNotFoundError:
                pass


def _inplace_bytes(path, data, expected_inode):
    """Only for the live WAF single-file bind; replacement would leave an old inode mounted."""
    path = Path(path)
    with _parent_fd(path) as parent:
        fd = os.open(path.name, os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_ino != expected_inode or st.st_nlink != 1:
                raise RuleChangeError("WAF bind inode changed")
            os.ftruncate(fd, 0)
            offset = 0
            while offset < len(data):
                offset += os.write(fd, data[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)


def _suricata_lines(data):
    """Join only explicit backslash-newline continuations; omit whole comments."""
    pending, single_line = b"", True
    for line in data.split(b"\n"):
        if not line.strip() or line.lstrip().startswith(b"#"):
            continue
        # The engine silently skips indented first lines, unlike continuation
        # lines. Never count such a marker/signature as an active rule.
        if not pending and line[:1] in (b" ", b"\t"):
            raise RuleChangeError("Suricata rule must start at column zero")
        if line.endswith(b"\\"):
            pending += line[:-1]
            single_line = False
            continue
        yield pending + line, single_line
        pending, single_line = b"", True
    if pending:
        raise RuleChangeError("unterminated Suricata rule continuation")


def _suricata_rule(line, single_line=True):
    """Read option boundaries without treating quoted msg/content/PCRE as options."""
    opening, closing = line.find(b"("), line.rfind(b")")
    if opening < 0 or closing <= opening or line[closing + 1:].strip():
        raise RuleChangeError("invalid Suricata rule boundary")
    options, start, quoted, escaped = [], opening + 1, False, False
    for pos in range(start, closing):
        char = line[pos]
        if escaped:
            escaped = False
        elif char == 92:
            escaped = True
        elif char == 34:
            quoted = not quoted
        elif char == 59 and not quoted:
            token_start = start + len(line[start:pos]) - len(line[start:pos].lstrip())
            token = line[token_start:pos]
            key, colon, value = token.partition(b":")
            if not re.fullmatch(rb"[A-Za-z0-9_.]+", key.strip()):
                raise RuleChangeError("invalid Suricata option boundary")
            value_start = token_start + len(key) + len(colon) + len(value) - len(value.lstrip())
            options.append((key.strip().lower(), value.strip(), token_start, value_start,
                            value_start + len(value.strip())))
            start = pos + 1
    if quoted or escaped or line[start:closing].strip():
        raise RuleChangeError("unterminated Suricata option")
    return {"line": line, "single_line": single_line, "header": line[:opening].split(), "options": options}


def _suricata_number(rule, key):
    found = [option for option in rule["options"] if option[0] == key]
    if len(found) != 1 or not re.fullmatch(rb"[0-9]+", found[0][1]):
        raise RuleChangeError("Suricata rule requires one numeric " + key.decode("ascii"))
    return int(found[0][1]), found[0]


def _validate_suricata_overrides(candidate, et):
    rules = [_suricata_rule(*line) for line in _suricata_lines(candidate)]
    overrides = {sid: rule for rule in rules
                 for sid, _ in [_suricata_number(rule, b"sid")] if sid in SURICATA_ET_OVERRIDES}
    if not overrides:
        return  # Existing local-only files and removal of overrides remain supported.
    marker = [rule for rule in rules if _suricata_number(rule, b"sid")[0] == 1000000]
    fixed_options = [
        (b"msg", b'"GROOT-LOCAL observed Ollama API transport marker (noalert)"'),
        (b"flow", b"to_server,established"), (b"flowbits", b"set,groot_llm_api"),
        (b"flowbits", b"noalert"), (b"sid", b"1000000")]
    if len(marker) != 1 or not any(
            marker[0]["header"] == b"alert tcp 192.168.16.230 any ->".split() + [address, b"11434"] and
            [(key, value) for key, value, *_ in marker[0]["options"]] == fixed_options + [(b"rev", revision)]
            for address, revision in SURICATA_LLM_MARKER_PROFILES):
        raise RuleChangeError("ET overrides require one exact narrow Ollama marker profile (.110/rev1 or [.110,.111]/rev2)")

    vendor = {sid: [] for sid in SURICATA_ET_OVERRIDES}
    for line, single_line in _suricata_lines(et):
        if SURICATA_LLM_BIT not in line and not any(str(sid).encode("ascii") in line for sid in vendor):
            continue
        rule = _suricata_rule(line, single_line)
        sid, _ = _suricata_number(rule, b"sid")
        if sid in vendor:
            vendor[sid].append(rule)
        # The private flowbit may be written only by the fixed local marker.
        for key, value, *_ in rule["options"]:
            if key == b"flowbits" and SURICATA_LLM_BIT in re.findall(rb"[A-Za-z0-9_.]+", value):
                raise RuleChangeError("ET source unexpectedly uses the private Ollama flowbit")
    if any(len(matches) != 1 for matches in vendor.values()):
        raise RuleChangeError("ET overrides require exactly one current signature for each fixed ET SID")
    for rule in rules:
        for key, value, *_ in rule["options"]:
            if key == b"flowbits" and SURICATA_LLM_BIT in re.findall(rb"[A-Za-z0-9_.]+", value) and \
                    value != b"isnotset,groot_llm_api" and rule is not marker[0]:
                raise RuleChangeError("additional Ollama flowbit writer or unsupported operation")
    for sid, candidate_rule in overrides.items():
        original = vendor[sid][0]
        _, sid_option = _suricata_number(original, b"sid")
        revision, rev_option = _suricata_number(original, b"rev")
        if not 0 < revision < 2**32 - 1:
            raise RuleChangeError("ET signature revision cannot be incremented")
        edits = [(sid_option[2], sid_option[2], b"flowbits:isnotset,groot_llm_api; "),
                 (rev_option[3], rev_option[4], str(revision + 1).encode("ascii"))]
        expected = original["line"]
        for start, end, replacement in sorted(edits, reverse=True):
            expected = expected[:start] + replacement + expected[end:]
        if not original["single_line"] or not candidate_rule["single_line"] or candidate_rule["line"] != expected:
            raise RuleChangeError("ET override must exactly preserve upstream bytes except guard and revision +1")


def _validate_candidate(kind, content):
    if not isinstance(content, str):
        raise RuleChangeError("candidate_content must be text")
    encoded = content.encode("utf-8")
    if not encoded or len(encoded) > MAX_CANDIDATE or b"\x00" in encoded or b"\r" in encoded:
        raise RuleChangeError("candidate must be nonempty UTF-8 text without NUL/CR and <=128 KiB")
    if any(unicodedata.category(ch) == "Cf" for ch in content):
        raise RuleChangeError("Unicode format/bidirectional control characters are forbidden in rules")
    if not content.endswith("\n"):
        raise RuleChangeError("candidate must end with a newline")
    active = "\n".join(line for line in content.splitlines() if not line.lstrip().startswith("#"))
    if kind == "waf":
        modes = re.findall(r"(?im)^\s*SecRuleEngine\s+(\S+)\s*$", active)
        if modes != ["DetectionOnly"]:
            raise RuleChangeError("WAF candidate must retain exactly one SecRuleEngine DetectionOnly directive")
        if re.search(r"(?im)^\s*(?:Include|SecRemoteRules|SecAuditLog|SecUploadDir|SecDataDir)\b", active):
            raise RuleChangeError("WAF candidate may not redirect includes, logs, or paths")
        if re.search(r"(?i)\bexec\s*:|\bctl\s*:\s*ruleEngine\b", active):
            raise RuleChangeError("WAF exec/ruleEngine override action is forbidden")
    elif kind == "suricata":
        rules = [_suricata_rule(*line) for line in _suricata_lines(encoded)]
        if any(not rule["header"] or rule["header"][0] != b"alert" for rule in rules):
            raise RuleChangeError("Suricata local rules must remain alert-only")
        sids = [_suricata_number(rule, b"sid")[0] for rule in rules]
        if not sids or len(sids) != len(set(sids)) or any(
                not 1000000 <= sid <= 1000099 and sid not in SURICATA_ET_OVERRIDES for sid in sids):
            raise RuleChangeError("Suricata SIDs must be unique local IDs or the two fixed ET overrides")
    elif kind == "wazuh":
        if re.search(r"<!\s*(?:DOCTYPE|ENTITY)", content, re.IGNORECASE):
            raise RuleChangeError("XML entity/DOCTYPE directives are forbidden")
        try:
            root = ET.fromstring("<root>" + content + "</root>")
        except ET.ParseError as exc:
            raise RuleChangeError("Wazuh XML fragment is invalid: %s" % exc) from None
        if any(child.tag != "group" for child in root):
            raise RuleChangeError("Wazuh local file may contain only top-level group elements")
        if any(elem.tag in ("command", "active-response") for elem in root.iter()):
            raise RuleChangeError("Wazuh active response/command elements are forbidden")
        ids = [elem.attrib.get("id", "") for elem in root.iter("rule")]
        if not ids or any(not re.fullmatch(r"\d{6}", rid) for rid in ids) or len(ids) != len(set(ids)):
            raise RuleChangeError("Wazuh rule IDs must be unique six-digit values")
    else:
        raise RuleChangeError("unsupported target kind")
    return encoded


def _waf_inventory_statements(content):
    """Only explicit continuations and whole-line comments in this fixed file."""
    pending = ""
    for line in content.split("\n"):
        if not line.strip() or line.lstrip().startswith("#"):
            if pending:
                raise ValueError("comment or blank inside a continued statement")
            continue
        if line.endswith("\\"):
            pending += line[:-1]
            continue
        yield pending + line
        pending = ""
    if pending:
        raise ValueError("unfinished WAF continuation")


def _waf_inventory_arguments(statement):
    """Keep escapes and inner action quotes; never scan operators for IDs."""
    arguments, index = [], 0
    while index < len(statement):
        if statement[index].isspace():
            index += 1
            continue
        quote = statement[index] if statement[index] in "\"'" else None
        if quote:
            index += 1
        start = index
        while index < len(statement):
            char = statement[index]
            if char == "\\":
                index += 2
                if index > len(statement):
                    raise ValueError("unfinished WAF escape")
                continue
            if quote and char == quote:
                break
            if not quote and char.isspace():
                break
            if not quote and char in "\"'":
                raise ValueError("unsupported WAF argument quoting")
            index += 1
        if quote and (index == len(statement) or statement[index] != quote):
            raise ValueError("unfinished WAF quote")
        arguments.append(statement[start:index])
        if quote:
            index += 1
            if index < len(statement) and not statement[index].isspace():
                raise ValueError("unsupported WAF argument boundary")
    return arguments


def _waf_inventory_actions(actions):
    fields, start, quote, escaped = [], 0, None, False
    for index, char in enumerate(actions):
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == ",":
            fields.append(actions[start:index].strip())
            start = index + 1
    if quote or escaped:
        raise ValueError("unfinished WAF action")
    fields.append(actions[start:].strip())
    ids, chained = [], False
    for field in fields:
        key, colon, value = field.partition(":")
        key, value = key.strip().lower(), value.strip()
        if not re.fullmatch(r"[a-z][a-z0-9_]*", key) or (colon and not value):
            raise ValueError("unsupported WAF action boundary")
        if key == "id":
            if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
                value = value[1:-1]
            if not colon or not re.fullmatch(r"[0-9]{1,10}", value) or not 0 < int(value) < 2**31:
                raise ValueError("unsupported WAF ID")
            ids.append(int(value))
        elif key == "chain":
            if colon or chained:
                raise ValueError("unsupported WAF chain")
            chained = True
    if len(ids) > 1:
        raise ValueError("multiple IDs on one WAF declaration")
    return ids, chained


def _waf_inventory(content):
    ids, pending_chain = [], False
    details = {"secrule_directives": 0, "secaction_directives": 0, "chain_continuations": 0}
    # These directives do not define new IDs. Includes, conditional sections,
    # defaults and unknown grammar are deliberately not guessed or followed.
    neutral = {"secruleengine", "seccomponentsignature", "secmarker",
               "secruleremovebyid", "secruleremovebytag", "secruleremovebymsg",
               "secruleupdatetargetbyid", "secruleupdatetargetbytag", "secruleupdatetargetbymsg"}
    for statement in _waf_inventory_statements(content):
        args = _waf_inventory_arguments(statement)
        directive = args[0].lower()
        if directive in neutral and len(args) >= 2 and not pending_chain:
            continue
        if directive == "secrule" and len(args) in (3, 4) and args[1] and args[2]:
            details["secrule_directives"] += 1
            rule_ids, chained = _waf_inventory_actions(args[3]) if len(args) == 4 else ([], False)
            if pending_chain:
                if rule_ids:
                    raise ValueError("ID on WAF chain continuation")
                details["chain_continuations"] += 1
            elif len(rule_ids) != 1:
                raise ValueError("WAF starter without ID")
            ids.extend(rule_ids)
            pending_chain = chained
        elif directive == "secaction" and len(args) == 2 and not pending_chain:
            rule_ids, chained = _waf_inventory_actions(args[1])
            if len(rule_ids) != 1 or chained:
                raise ValueError("unsupported SecAction ID/chain")
            details["secaction_directives"] += 1
            ids.extend(rule_ids)
        else:
            raise ValueError("unsupported WAF statement")
    if pending_chain:
        raise ValueError("unfinished WAF chain")
    return ids, details


def _suricata_inventory(data):
    ids = []
    details = {"local_sid_count": 0, "et_override_count": 0, "other_sid_count": 0, "noalert_count": 0}
    for line, single_line in _suricata_lines(data):
        rule = _suricata_rule(line, single_line)
        # This target's established grammar is alert-only with the default GID.
        # SID uniqueness across unrelated generator IDs would be misleading.
        if len(rule["header"]) != 7 or rule["header"][0] != b"alert" or rule["header"][4] not in (b"->", b"<>"):
            raise ValueError("unsupported Suricata rule header")
        if any(key == b"gid" for key, *_ in rule["options"]) and _suricata_number(rule, b"gid")[0] != 1:
            raise ValueError("unsupported Suricata generator")
        sid = _suricata_number(rule, b"sid")[0]
        if not 0 < sid < 2**32:
            raise ValueError("unsupported Suricata SID")
        ids.append(sid)
        category = ("local_sid_count" if 1000000 <= sid <= 1000099 else
                    "et_override_count" if sid in SURICATA_ET_OVERRIDES else "other_sid_count")
        details[category] += 1
        if any((key == b"flowbits" and value == b"noalert") or (key == b"noalert" and not value)
               for key, value, *_ in rule["options"]):
            details["noalert_count"] += 1
    return ids, details


def _wazuh_inventory(content):
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)", content, re.IGNORECASE):
        raise ValueError("unsupported XML declaration")
    root = ET.fromstring("<root>" + content + "</root>")
    if root.text and root.text.strip():
        raise ValueError("text outside Wazuh groups")
    ids, levels = [], {}
    for group in root:
        if group.tag != "group" or (group.text and group.text.strip()) or (group.tail and group.tail.strip()):
            raise ValueError("unsupported Wazuh group structure")
        for rule in group:
            if rule.tag != "rule" or (rule.tail and rule.tail.strip()):
                raise ValueError("unsupported Wazuh rule structure")
            rid, level = rule.get("id", ""), rule.get("level", "")
            if not re.fullmatch(r"[0-9]{6}", rid) or not re.fullmatch(r"[0-9]{1,2}", level) or not 0 <= int(level) <= 16:
                raise ValueError("unsupported Wazuh ID/level")
            if any(not isinstance(elem.tag, str) or "{" in elem.tag or
                   elem.tag in ("rule", "command", "active-response") for elem in rule.iter() if elem is not rule):
                raise ValueError("unsupported Wazuh nested declaration")
            ids.append(int(rid))
            label = str(int(level))
            levels[label] = levels.get(label, 0) + 1
    return ids, {"level_counts": levels, "level0_count": levels.get("0", 0)}


def rule_inventory(kind, data):
    """Exact bounded file definitions, not validation or active-engine totals.

    Parse failure discards all partial counts. Raw target reads remain available;
    inventory adds no permission, command, write, or external-file access.
    """
    result = {"schema_version": 1, "kind": kind, "scope": "target_file_definitions",
              "source_sha256": sha256(data), "status": "unavailable", "declared_count": None,
              "unique_id_count": None, "ids": [], "duplicate_ids": [], "contiguous_id_groups": [],
              "runtime_load_verified": False,
              "evidence_scope_ko": "대상 파일에 선언된 룰 정의만 집계했습니다. 엔진의 실제 적재 여부와 전체 활성 룰 수는 미확인입니다.",
              "details": {}}
    try:
        if len(data) > MAX_CANDIDATE or b"\x00" in data or b"\r" in data:
            raise ValueError("unsupported inventory input")
        content = data.decode("utf-8")
        if any(unicodedata.category(char) == "Cf" for char in content):
            raise ValueError("unsupported invisible format control")
        if kind == "waf":
            ids, details = _waf_inventory(content)
        elif kind == "suricata":
            ids, details = _suricata_inventory(data)
        elif kind == "wazuh":
            ids, details = _wazuh_inventory(content)
        else:
            raise ValueError("unsupported inventory kind")
    except (ValueError, RuleChangeError, ET.ParseError):
        result["error"] = "syntax_or_scope_unsupported"
        return result
    counts = {}
    for rid in ids:
        counts[rid] = counts.get(rid, 0) + 1
    unique, groups = sorted(counts), []
    for rid in unique:
        if groups and rid == groups[-1]["end"] + 1:
            groups[-1]["end"] = rid
        else:
            groups.append({"start": rid, "end": rid})
    result.update(status="complete", declared_count=len(ids), unique_id_count=len(unique), ids=unique,
                  duplicate_ids=sorted(rid for rid, count in counts.items() if count > 1),
                  contiguous_id_groups=groups, details=details)
    return result


class NoBrokerRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise RuleChangeError("approval broker redirect refused")


class Broker:
    def __init__(self, url, token):
        if url not in ("https://10.200.10.10:8445", "http://127.0.0.1:8090") or not isinstance(token, str) or len(token) < 32:
            raise RuleChangeError("dedicated approval broker is not configured")
        self.url, self.key = url, token.encode("ascii")
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoBrokerRedirect())

    def request(self, method, path, body=None):
        data = b"" if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
        nonce = secrets.token_hex(16)
        timestamp = str(int(time.time()))
        message = ("v1\n%s\n%s\n%s\n%s\n%s" % (method, path, timestamp, nonce, sha256(data))).encode("ascii")
        signature = hmac.new(self.key, message, hashlib.sha256).hexdigest()
        req = urllib.request.Request(self.url + path, data=None if body is None else data, method=method, headers={
            "X-Rule-Timestamp": timestamp, "X-Rule-Nonce": nonce,
            "X-Rule-Signature": signature, "Content-Type": "application/json",
        })
        try:
            # A large proposal posts all review parts before its single
            # approval card. The broker bounds that sequence below 120 s.
            timeout = 120 if method == "POST" and path == "/rule-changes" else (
                30 if method == "POST" and (path == "/operations" or
                    re.fullmatch(r"/operations/[0-9a-f]{32}/result", path)) else 12)
            with self.opener.open(req, timeout=timeout) as res:
                raw = res.read(65537)
                status = res.status
                response_signature = res.headers.get("X-Rule-Response-Signature", "")
        except (OSError, urllib.error.HTTPError) as exc:
            raise RuleChangeError("approval broker unavailable or rejected request") from exc
        if len(raw) > 65536:
            raise RuleChangeError("approval broker response too large")
        response_message = ("v1\n%s\n%d\n%s" % (nonce, status, sha256(raw))).encode("ascii")
        expected = hmac.new(self.key, response_message, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(response_signature, expected):
            raise RuleChangeError("approval broker response signature invalid")
        try:
            answer = json.loads(raw)
        except (UnicodeDecodeError, ValueError):
            raise RuleChangeError("invalid approval broker response") from None
        if not isinstance(answer, dict):
            raise RuleChangeError("invalid approval broker response")
        return answer

    def health(self):
        response = self.request("GET", "/rule-changes/health")
        if response.get("status") != "ready":
            raise RuleChangeError("approval broker health check failed")
        return True


class Runner:
    def call(self, argv, timeout=30):
        try:
            result = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuleChangeError("service command unavailable or timed out") from exc
        if result.returncode:
            raise RuleChangeError("service command failed: %s" % " ".join(argv[:4]))
        if len(result.stdout) > 1024 * 1024:
            raise RuleChangeError("service command output too large")
        return result.stdout


class Engine:
    def __init__(self, host, broker, state_dir=STATE_DIR, targets=None, runner=None, clock=None, read_only=False):
        if host not in ("a", "b"):
            raise RuleChangeError("invalid host ID")
        self.host = host
        self.broker = broker
        self.state_dir = Path(state_dir)
        self.targets = TARGETS if targets is None else targets
        self.runner = runner or Runner()
        self.clock = clock or time.time
        self.read_only = read_only
        if not read_only:
            self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            st = os.lstat(self.state_dir)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700:
                raise RuleChangeError("state directory must be owned by the executor and mode 0700")

    @contextlib.contextmanager
    def locked(self):
        fd = os.open(self.state_dir / ".lock", os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def spec(self, target):
        if not isinstance(target, str) or target not in self.targets:
            raise RuleChangeError("target is not allowlisted")
        spec = self.targets[target]
        if spec["host"] != self.host:
            raise RuleChangeError("target is not on this host")
        return spec

    def _record_path(self, rid):
        if not isinstance(rid, str) or not PROPOSAL_ID.fullmatch(rid):
            raise RuleChangeError("invalid proposal ID")
        return self.state_dir / (rid + ".json")

    def _save(self, record):
        path = self._record_path(record["proposal_id"])
        data = json.dumps(record, ensure_ascii=False, sort_keys=True).encode("utf-8")
        if len(data) > MAX_STATE:
            raise RuleChangeError("proposal state exceeds 4 MiB storage limit")
        _atomic_bytes(path, data, mode=0o600)

    def _load(self, rid):
        data, _ = _read_regular(self._record_path(rid), limit=MAX_STATE)
        record = json.loads(data)
        if record.get("proposal_id") != rid:
            raise RuleChangeError("corrupt proposal record")
        return record

    def _inspect(self, spec, timeout=15, recovering=False):
        raw = self.runner.call([DOCKER, "inspect", spec["container"]], timeout=timeout)
        try:
            info = json.loads(raw)[0]
        except (ValueError, IndexError, KeyError, TypeError):
            raise RuleChangeError("invalid container inspection") from None
        # A failed Suricata start may leave this same container stopped. Recovery
        # still checks its identity, mounts and passive command before restarting.
        recovering = recovering and spec["kind"] == "suricata"
        if not recovering and not info.get("State", {}).get("Running"):
            raise RuleChangeError("target container is not running")
        health = info.get("State", {}).get("Health", {}).get("Status")
        if not recovering and health and health != "healthy":
            raise RuleChangeError("target container health is not healthy")
        mounts = info.get("Mounts") or []
        expected_rw = spec["kind"] == "wazuh"
        if not any(m.get("Source") == spec["mount_source"] and m.get("Destination") == spec["mount_dest"]
                   and m.get("RW") is expected_rw for m in mounts):
            raise RuleChangeError("live container mount differs from fixed target")
        if spec["kind"] == "waf":
            env = info.get("Config", {}).get("Env") or []
            if "MODSEC_RULE_ENGINE=DetectionOnly" not in env:
                raise RuleChangeError("WAF is not in DetectionOnly mode")
        if spec["kind"] == "suricata":
            cmd = info.get("Config", {}).get("Cmd") or []
            if "-S" not in cmd or "/rules/all.rules" not in cmd or "-q" in cmd:
                raise RuleChangeError("Suricata runtime no longer matches passive all.rules contract")
            if not recovering and (info["State"].get("OOMKilled") or info["State"].get("Restarting")):
                raise RuleChangeError("Suricata container is OOM-killed or restarting")
            if not isinstance(info.get("Id"), str) or not HEX_SHA.fullmatch(info["Id"]):
                raise RuleChangeError("invalid Suricata container identity")
            return {"container": spec["container"], "running": bool(info["State"].get("Running")),
                    "health": health or "not_reported", "container_id": info["Id"],
                    "started_at": info["State"].get("StartedAt")}
        return {"container": spec["container"], "running": True, "health": health or "not_reported"}

    def _snapshot(self, spec):
        current, st = _read_regular(spec["path"])
        aux = {}
        if spec["kind"] == "suricata":
            et, _ = _read_regular(spec["et_path"], MAX_RULESET)
            all_rules, _ = _read_regular(spec["all_path"], MAX_RULESET)
            if all_rules != et + current:
                raise RuleChangeError("loaded Suricata all.rules is not exactly ET + local rules")
            aux = {"et_sha256": sha256(et), "all_sha256": sha256(all_rules)}
            expected_remote = aux["all_sha256"]
        else:
            expected_remote = sha256(current)
        remote = self.runner.call([DOCKER, "exec", spec["container"], "sha256sum", spec["container_path"]]).decode().split()
        if not remote or remote[0] != expected_remote:
            raise RuleChangeError("host and live container rule content differ")
        if spec["kind"] == "waf":
            remote_inode = self.runner.call([DOCKER, "exec", "waf", "stat", "-c", "%i", spec["container_path"]]).decode().strip()
            if remote_inode != str(st.st_ino):
                raise RuleChangeError("WAF host path inode differs from live bind mount")
        return current, st, aux

    def _candidate_preflight(self, spec, candidate):
        """Test Suricata's candidate without changing the active all.rules.

        WAF's single-file bind and Wazuh's live manager rules directory have no
        proven alternate-config test path here. Those two receive structural
        checks before approval, then engine tests after swap but before reload.
        """
        if spec["kind"] != "suricata":
            return "offline guard checks passed; full engine syntax test after approval and before reload"
        et, _ = _read_regular(spec["et_path"], MAX_RULESET)
        _validate_suricata_overrides(candidate, et)
        with _parent_fd(spec["all_path"]) as directory:
            staged = ".rule-change-probe-%s.rules" % secrets.token_hex(12)
            fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=directory)
            try:
                with os.fdopen(fd, "wb") as out:
                    out.write(et)
                    out.write(candidate)
                    out.flush()
                    os.fchmod(out.fileno(), 0o644)
                    os.fsync(out.fileno())
                container_file = "/rules/" + staged
                self.runner.call([DOCKER, "exec", "suricata", "suricata", "-T", "-S", container_file], timeout=180)
                return "offline guards and Suricata -T on staged ET+candidate passed; active all.rules unchanged"
            finally:
                os.unlink(staged, dir_fd=directory)

    def get_target(self, target):
        spec = self.spec(target)
        with self.locked():
            runtime = self._inspect(spec)
            current, _, aux = self._snapshot(spec)
            try:
                content = current.decode("utf-8")
            except UnicodeDecodeError:
                raise RuleChangeError("current local rule file is not UTF-8") from None
            return {"target": target, "rule_inventory": rule_inventory(spec["kind"], current),
                    "content": content, "sha256": sha256(current),
                    "runtime": runtime, "impact": spec["impact"], "related_hashes": aux,
                    "limits": proposal_limits()}

    def _proposal_spec(self, target, base_sha256, reason):
        spec = self.spec(target)
        if not isinstance(base_sha256, str) or not HEX_SHA.fullmatch(base_sha256):
            raise RuleChangeError("base_sha256 must be a SHA-256 from get_rule_change_target")
        if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 200 or any(ord(c) < 32 for c in reason):
            raise RuleChangeError("reason must be 1..200 printable characters")
        if any(unicodedata.category(ch) == "Cf" for ch in reason):
            raise RuleChangeError("reason contains invisible Unicode format controls")
        return spec

    def _proposal_snapshot(self, spec, base_sha256):
        """Caller holds the same lock used by the approval worker."""
        pending = sum(1 for path in self.state_dir.glob("*.json") if self._load(path.stem).get("status") == "pending")
        if pending >= 10:
            raise RuleChangeError("too many pending proposals")
        runtime = self._inspect(spec)
        current, st, aux = self._snapshot(spec)
        if sha256(current) != base_sha256:
            raise RuleChangeError("target changed since it was read; fetch current content and retry")
        return current, st, aux, runtime

    def propose(self, target, base_sha256, candidate_content, reason):
        spec = self._proposal_spec(target, base_sha256, reason)
        candidate = _validate_candidate(spec["kind"], candidate_content)
        with self.locked():
            current, st, aux, runtime = self._proposal_snapshot(spec, base_sha256)
            return self._propose_candidate(target, spec, current, st, aux, runtime,
                                           candidate_content, candidate, reason)

    def propose_edit(self, target, base_sha256, edits, reason):
        spec = self._proposal_spec(target, base_sha256, reason)
        validated = _validated_edits(edits)
        with self.locked():
            current, st, aux, runtime = self._proposal_snapshot(spec, base_sha256)
            candidate_content = _edit_candidate(current, validated)
            candidate = _validate_candidate(spec["kind"], candidate_content)
            return self._propose_candidate(target, spec, current, st, aux, runtime,
                                           candidate_content, candidate, reason, edit_count=len(validated))

    def _propose_candidate(self, target, spec, current, st, aux, runtime,
                           candidate_content, candidate, reason, edit_count=None):
        """Shared complete-candidate approval path; caller must hold the live-state lock."""
        if current == candidate:
            raise RuleChangeError("candidate is identical to the live rule file")
        validation = self._candidate_preflight(spec, candidate)
        diff = "".join(difflib.unified_diff(
            current.decode("utf-8").splitlines(keepends=True), candidate_content.splitlines(keepends=True),
            fromfile=target + " before", tofile=target + " after",
        ))
        mode = {"waf": "DetectionOnly", "suricata": "passive", "wazuh": "manager"}[spec["kind"]]
        diff = ("Impact: " + spec["impact"] + "\nReason: " + reason.strip() +
                "\nPreflight: " + validation + "\nRuntime: " + runtime["container"] +
                " running, health=" + runtime["health"] + ", mode=" + mode + "\n" + diff)
        diff_bytes = diff.encode("utf-8")
        if len(diff_bytes) > MAX_DIFF:
            raise RuleChangeError("complete approval diff exceeds 512 KiB UTF-8 limit")
        payload = {
            "target": target, "base_sha256": sha256(current), "candidate_sha256": sha256(candidate),
            "diff_sha256": sha256(diff_bytes), "diff": diff,
            "requested_by": "hermes-rule-change", "expires_at": int(self.clock()) + 600,
        }
        digest = proposal_digest(payload)
        answer = self.broker.request("POST", "/rule-changes", payload)
        rid = answer.get("proposal_id")
        if not answer.get("posted") or not isinstance(rid, str) or not PROPOSAL_ID.fullmatch(rid):
            raise RuleChangeError("broker did not post a valid approval card")
        if answer.get("proposal_digest") != digest or answer.get("expires_at") != payload["expires_at"]:
            raise RuleChangeError("broker proposal binding mismatch")
        if self._record_path(rid).exists():
            raise RuleChangeError("duplicate proposal ID")
        record = {
            "proposal_id": rid, "payload": payload, "proposal_digest": digest,
            "candidate_content": candidate_content, "aux": aux, "status": "pending",
            "base_file": {"inode": st.st_ino, "uid": st.st_uid, "gid": st.st_gid,
                          "mode": stat.S_IMODE(st.st_mode)},
            "created_at": int(self.clock()), "result": "",
        }
        self._save(record)
        result = {"proposal_id": rid, "status": "pending", "target": target,
                  "before_sha256": payload["base_sha256"], "after_sha256": payload["candidate_sha256"],
                  "runtime_before": runtime, "approval_expires_at": payload["expires_at"],
                  "validation": validation, "limits": proposal_limits(),
                  "review_posted": True, "review_location": "Mattermost approval channel"}
        if edit_count is None:
            result["diff"] = diff  # Preserve the existing full-file proposal response.
        else:
            # The authenticated broker has already posted the complete review.
            # Return its identifiers rather than sending the file/diff back to the model.
            result.update(proposal_digest=digest, diff_sha256=payload["diff_sha256"],
                          diff_utf8_bytes=len(diff_bytes), candidate_utf8_bytes=len(candidate),
                          edit_count=edit_count)
        return result

    def _checked_decision(self, record):
        payload = record["payload"]
        if proposal_digest(payload) != record["proposal_digest"]:
            raise RuleChangeError("local proposal binding mismatch")
        if sha256(record["candidate_content"].encode("utf-8")) != payload["candidate_sha256"]:
            raise RuleChangeError("candidate content changed")
        if sha256(payload["diff"].encode("utf-8")) != payload["diff_sha256"]:
            raise RuleChangeError("proposal diff changed")
        answer = self.broker.request("GET", "/rule-changes/" + record["proposal_id"])
        for key in ("target", "base_sha256", "candidate_sha256", "diff_sha256", "expires_at"):
            if answer.get(key) != payload[key]:
                raise RuleChangeError("broker decision binding mismatch")
        if answer.get("proposal_digest") != record["proposal_digest"]:
            raise RuleChangeError("broker digest mismatch")
        if answer.get("status") not in ("pending", "approved", "denied", "expired", "consumed"):
            raise RuleChangeError("invalid broker decision")
        return answer

    def status(self, rid):
        with self.locked():
            record = self._load(rid)
            out = {"proposal_id": rid, "target": record["payload"]["target"], "status": record["status"],
                   "before_sha256": record["payload"]["base_sha256"], "after_sha256": record["payload"]["candidate_sha256"],
                   "result": record.get("result", "")}
            if record["status"] == "pending":
                try:
                    decision = self._checked_decision(record)
                    out["approval_status"] = decision["status"]
                    out["approved_by"] = decision.get("by", "") if decision["status"] == "approved" else ""
                except RuleChangeError:
                    out["approval_status"] = "unavailable"
            return out

    def _backup(self, record, name, path):
        data, st = _read_regular(path, MAX_RULESET)
        backup = self.state_dir / (record["proposal_id"] + "." + name + ".bak")
        _atomic_bytes(backup, data, mode=0o600)
        record.setdefault("backups", {})[name] = {"path": str(backup), "sha256": sha256(data),
                                                     "mode": stat.S_IMODE(st.st_mode), "uid": st.st_uid, "gid": st.st_gid,
                                                     "inode": st.st_ino}

    def _restore(self, record, spec):
        names = {"primary": spec["path"]}
        if spec["kind"] == "suricata":
            names["all"] = spec["all_path"]
        for name, path in names.items():
            info = record.get("backups", {}).get(name)
            if not info:
                raise RuleChangeError("backup unavailable for recovery")
            data, _ = _read_regular(info["path"], MAX_RULESET)
            if sha256(data) != info["sha256"]:
                raise RuleChangeError("backup hash mismatch")
            if spec["kind"] == "waf":
                _inplace_bytes(path, data, info["inode"])
            else:
                _, old = _read_regular(path, MAX_RULESET)
                saved = SimpleNamespace(st_uid=info["uid"], st_gid=info["gid"], st_mode=info["mode"])
                _atomic_bytes(path, data, saved)

    def _service_apply(self, spec, record, candidate):
        kind = spec["kind"]
        primary, st = _read_regular(spec["path"])
        if sha256(primary) != record["payload"]["base_sha256"]:
            raise RuleChangeError("live file changed since proposal")
        if kind == "waf":
            _inplace_bytes(spec["path"], candidate, record["base_file"]["inode"])
            remote_hash = self.runner.call([DOCKER, "exec", "waf", "sha256sum", spec["container_path"]]).decode().split()[0]
            if remote_hash != sha256(candidate):
                raise RuleChangeError("WAF bind-mounted content hash mismatch")
            self.runner.call([DOCKER, "exec", "waf", "nginx", "-t"], timeout=60)
            self.runner.call([DOCKER, "exec", "waf", "nginx", "-s", "reload"], timeout=30)
        elif kind == "suricata":
            et, _ = _read_regular(spec["et_path"], MAX_RULESET)
            all_rules, all_st = _read_regular(spec["all_path"], MAX_RULESET)
            if sha256(et) != record["aux"]["et_sha256"] or sha256(all_rules) != record["aux"]["all_sha256"]:
                raise RuleChangeError("Suricata ET/loaded rules changed since proposal")
            if all_rules != et + primary:
                raise RuleChangeError("Suricata combined rules drifted")
            _validate_suricata_overrides(candidate, et)
            _atomic_bytes(spec["path"], candidate, st)
            _atomic_bytes(spec["all_path"], et + candidate, all_st)
            self.runner.call([DOCKER, "exec", "suricata", "suricata", "-T", "-S", "/rules/all.rules"], timeout=180)
            self._restart_suricata(spec)
        elif kind == "wazuh":
            _atomic_bytes(spec["path"], candidate, st)
            self.runner.call([DOCKER, "exec", spec["container"], "/var/ossec/bin/wazuh-analysisd", "-t"], timeout=60)
            self.runner.call([DOCKER, "restart", spec["container"]], timeout=120)
            self._wait_wazuh_manager(spec)
        else:
            raise RuleChangeError("unsupported target kind")
        self._inspect(spec)
        final, _ = _read_regular(spec["path"])
        if sha256(final) != sha256(candidate):
            raise RuleChangeError("post-apply file hash mismatch")
        remote = self.runner.call([DOCKER, "exec", spec["container"], "sha256sum", spec["container_path"]]).decode().split()
        if kind == "suricata":
            et, _ = _read_regular(spec["et_path"], MAX_RULESET)
            all_rules, _ = _read_regular(spec["all_path"], MAX_RULESET)
            if sha256(et) != record["aux"]["et_sha256"] or all_rules != et + candidate:
                raise RuleChangeError("post-apply loaded Suricata rules mismatch")
            expected_remote = sha256(all_rules)
        else:
            expected_remote = sha256(candidate)
        if not remote or remote[0] != expected_remote:
            raise RuleChangeError("container readback hash mismatch")

    @staticmethod
    def _suricata_time(value):
        try:
            if not isinstance(value, str):
                raise ValueError
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError
            return parsed.timestamp()
        except (ValueError, OverflowError):
            raise RuleChangeError("invalid or timezone-free Suricata runtime timestamp") from None

    def _suricata_socket(self, command, timeout):
        raw = self.runner.call([DOCKER, "exec", "suricata", "suricatasc", "-c", command], timeout=timeout)
        try:
            answer = json.loads(raw)
            rows = answer["message"]
            if answer["return"] != "OK" or not isinstance(rows, list) or len(rows) != 1 or \
                    not isinstance(rows[0], dict) or type(rows[0].get("id")) is not int or rows[0]["id"] != 0:
                raise ValueError
            return rows[0]
        except (ValueError, KeyError, TypeError):
            # suricatasc 8 can exit zero even when its JSON response is NOK.
            raise RuleChangeError("Suricata socket rejected request or returned an invalid single-tenant response") from None

    def _restart_suricata(self, spec):
        before = self._inspect(spec, recovering=True)
        requested_at = self.clock()
        self.runner.call([DOCKER, "restart", "--time", "30", spec["container"]], timeout=120)
        deadline = time.monotonic() + 90
        last_error = "runtime not ready"

        def remaining():
            seconds = deadline - time.monotonic()
            if seconds <= 0:
                raise RuleChangeError("Suricata readiness deadline exceeded")
            return min(10, seconds)

        while time.monotonic() < deadline:
            try:
                runtime = self._inspect(spec, timeout=remaining())
                if runtime["container_id"] != before["container_id"] or runtime["started_at"] == before["started_at"]:
                    raise RuleChangeError("Suricata existing container restart was not observed")
                started_at = self._suricata_time(runtime["started_at"])
                stats = self._suricata_socket("ruleset-stats", remaining())
                if any(type(stats.get(key)) is not int or stats[key] < 0
                       for key in ("rules_loaded", "rules_failed", "rules_skipped")) or \
                        stats["rules_loaded"] == 0 or stats["rules_failed"] != 0 or stats["rules_skipped"] != 0:
                    raise RuleChangeError("Suricata runtime rules are absent, failed, skipped or malformed")
                loaded_at = self._suricata_time(self._suricata_socket("ruleset-reload-time", remaining()).get("last_reload"))
                now = self.clock()
                if not requested_at - 1 <= started_at <= loaded_at <= now + 5:
                    raise RuleChangeError("Suricata runtime rule load time is stale or inconsistent")
                after = self._inspect(spec, timeout=remaining())
                if (after["container_id"], after["started_at"]) != (runtime["container_id"], runtime["started_at"]):
                    raise RuleChangeError("Suricata restarted during runtime verification")
                return
            except RuleChangeError as exc:
                if time.monotonic() >= deadline:
                    break
                last_error = str(exc)
            time.sleep(max(0, min(2, deadline - time.monotonic())))
        raise RuleChangeError("Suricata did not become ready: " + last_error)

    def _wait_wazuh_manager(self, spec):
        deadline = self.clock() + 90
        while self.clock() < deadline:
            try:
                self._inspect(spec)
                status = self.runner.call([DOCKER, "exec", spec["container"],
                                           "/var/ossec/bin/wazuh-control", "status"], timeout=15).decode("utf-8", "replace")
                if all("%s is running" % process in status for process in ("wazuh-analysisd", "wazuh-remoted", "wazuh-db")):
                    return
            except RuleChangeError:
                pass
            time.sleep(3)
        raise RuleChangeError("Wazuh manager processes did not become ready")

    def _apply_approved(self, record):
        spec = self.spec(record["payload"]["target"])
        candidate = _validate_candidate(spec["kind"], record["candidate_content"])
        self._inspect(spec)
        current, st, aux = self._snapshot(spec)
        base_file = record["base_file"]
        if (sha256(current) != record["payload"]["base_sha256"] or aux != record["aux"] or
                st.st_ino != base_file["inode"] or st.st_uid != base_file["uid"] or
                st.st_gid != base_file["gid"] or stat.S_IMODE(st.st_mode) != base_file["mode"]):
            raise RuleChangeError("live state changed since proposal")
        if spec["kind"] == "suricata":
            et, _ = _read_regular(spec["et_path"], MAX_RULESET)
            _validate_suricata_overrides(candidate, et)
        # Durable backup before consuming the one-use approval.
        self._backup(record, "primary", spec["path"])
        if spec["kind"] == "suricata":
            self._backup(record, "all", spec["all_path"])
        record["status"] = "prepared"
        self._save(record)
        consumed = self.broker.request("POST", "/rule-changes/" + record["proposal_id"] + "/consume",
                                       {"proposal_digest": record["proposal_digest"]})
        if consumed.get("status") != "consumed" or consumed.get("proposal_digest") != record["proposal_digest"]:
            raise RuleChangeError("one-time approval consume failed")
        record["status"] = "applying"
        record["approval_consumed"] = True
        record["result_posted"] = False
        self._save(record)
        try:
            self._service_apply(spec, record, candidate)
        except Exception as exc:
            try:
                self._restore(record, spec)
                self._reload_after_restore(spec)
                self._verify_restored(record, spec)
                record["status"], record["result"] = "rolled_back", "apply failed; backup restored: %s" % exc
            except Exception as restore_exc:
                record["status"], record["result"] = "recovery_failed", "apply and recovery failed: %s; %s" % (exc, restore_exc)
            self._save(record)
            try:
                self._post_result(record)
            except RuleChangeError:
                pass  # final result delivery retries; the rule is never replayed
            return
        record["status"], record["result"] = "applied", "approved exact proposal applied and service checked"
        self._save(record)
        try:
            self._post_result(record)
        except RuleChangeError:
            pass

    def _post_result(self, record):
        if not record.get("approval_consumed") or record.get("result_posted"):
            return
        status = record["status"]
        if status not in ("applied", "rolled_back", "recovery_failed", "failed"):
            return
        if "result_payload" not in record:
            spec = self.spec(record["payload"]["target"])
            try:
                readback, _ = _read_regular(spec["path"])
                readback_sha = sha256(readback)
            except (OSError, RuleChangeError):
                # Failure remains explicit; an unreadable file cannot be
                # reported as an applied or successfully rolled-back change.
                if status in ("applied", "rolled_back"):
                    record["status"], status = "recovery_failed", "recovery_failed"
                    record["result"] = "final rule file unreadable"
                    self._save(record)
                readback_sha = sha256(b"")
            payload = record["payload"]
            if status == "applied" and readback_sha != payload["candidate_sha256"]:
                record["status"], status = "recovery_failed", "recovery_failed"
                record["result"] = "applied rule file changed before result report"
                self._save(record)
            if status == "rolled_back" and readback_sha != payload["base_sha256"]:
                record["status"], status = "recovery_failed", "recovery_failed"
                record["result"] = "rollback rule file hash mismatch"
                self._save(record)
            record["result_payload"] = {
                "proposal_digest": record["proposal_digest"], "status": status,
                "before_sha256": payload["base_sha256"], "after_sha256": payload["candidate_sha256"],
                "readback_sha256": readback_sha, "detail": str(record.get("result", ""))[:200],
            }
            self._save(record)
        result_payload = record["result_payload"]
        answer = self.broker.request("POST", "/rule-changes/" + record["proposal_id"] + "/result", result_payload)
        if answer.get("status") != result_payload["status"] or answer.get("readback_sha256") != result_payload["readback_sha256"] or not answer.get("result_posted"):
            raise RuleChangeError("broker did not post final result")
        record["result_posted"] = True
        self._save(record)

    def _abort_preconsume(self, record, detail):
        """Tell the approver an approved proposal was never consumed/applied."""
        if record["status"] != "pending" or record.get("approval_consumed"):
            raise RuleChangeError("abort is allowed only before approval consumption")
        spec = self.spec(record["payload"]["target"])
        try:
            if spec["kind"] in ("waf", "wazuh"):
                remote = self.runner.call([DOCKER, "exec", spec["container"], "sha256sum", spec["container_path"]]).decode().split()
                if not remote or not HEX_SHA.fullmatch(remote[0]):
                    raise RuleChangeError("container readback unavailable")
                readback_sha = remote[0]
                detail = "live container readback; " + detail
            else:
                current, _ = _read_regular(spec["path"])
                readback_sha = sha256(current)
                detail = "local source readback; " + detail
        except (OSError, RuleChangeError):
            readback_sha = sha256(b"")
            detail = "readback unavailable; " + detail
        record["abort_payload"] = {"proposal_digest": record["proposal_digest"],
                                   "readback_sha256": readback_sha, "detail": detail[:200]}
        record["status"], record["result"] = "abort_pending", "approved but not applied: " + detail[:200]
        record["abort_attempts"] = 0
        self._save(record)
        self._post_abort(record)

    def _post_abort(self, record):
        if record["status"] != "abort_pending":
            return
        if record.get("abort_attempts", 0) >= 3:
            record["status"] = "abort_report_error"
            record["result"] = "approved change was not applied; Mattermost abort card could not be confirmed"
            self._save(record)
            return
        record["abort_attempts"] = record.get("abort_attempts", 0) + 1
        self._save(record)
        answer = self.broker.request("POST", "/rule-changes/" + record["proposal_id"] + "/abort", record["abort_payload"])
        if answer.get("status") != "aborted" or not answer.get("result_posted") or \
                answer.get("readback_sha256") != record["abort_payload"]["readback_sha256"]:
            raise RuleChangeError("broker did not post abort result")
        record["status"], record["result"] = "aborted", "approved proposal not applied; operator informed"
        self._save(record)

    def _reload_after_restore(self, spec):
        if spec["kind"] == "waf":
            self.runner.call([DOCKER, "exec", "waf", "nginx", "-t"], timeout=60)
            self.runner.call([DOCKER, "exec", "waf", "nginx", "-s", "reload"])
        elif spec["kind"] == "suricata":
            self._restart_suricata(spec)
        elif spec["kind"] == "wazuh":
            self.runner.call([DOCKER, "restart", spec["container"]], timeout=120)
            self._wait_wazuh_manager(spec)
        self._inspect(spec)

    def _verify_restored(self, record, spec):
        current, _, aux = self._snapshot(spec)
        if sha256(current) != record["payload"]["base_sha256"] or aux != record["aux"]:
            raise RuleChangeError("rollback readback differs from approved base")

    def worker_once(self):
        results = []
        with self.locked():
            for path in sorted(self.state_dir.glob("*.json")):
                record = self._load(path.stem)
                if record["status"] == "abort_pending":
                    try:
                        self._post_abort(record)
                    except RuleChangeError:
                        pass
                    results.append({"proposal_id": path.stem, "status": record["status"]})
                    continue
                if record["status"] in ("applied", "rolled_back", "recovery_failed", "failed"):
                    try:
                        self._post_result(record)
                    except RuleChangeError:
                        pass  # retry next timer tick; never reapply
                    continue
                if record["status"] == "applying":
                    # A crash after approval consumption must never be retried.
                    try:
                        spec = self.spec(record["payload"]["target"])
                        self._restore(record, spec)
                        self._reload_after_restore(spec)
                        self._verify_restored(record, spec)
                        record["status"], record["result"] = "rolled_back", "interrupted apply restored from backup"
                    except Exception as exc:
                        record["status"], record["result"] = "recovery_failed", "interrupted apply recovery failed: %s" % exc
                    self._save(record)
                    try:
                        self._post_result(record)
                    except RuleChangeError:
                        pass
                    results.append({"proposal_id": path.stem, "status": record["status"]})
                    continue
                if record["status"] not in ("pending", "prepared"):
                    continue
                try:
                    decision = self._checked_decision(record)
                    if decision["status"] in ("denied", "expired"):
                        record["status"] = decision["status"]
                        self._save(record)
                    elif decision["status"] == "approved":
                        if int(self.clock()) >= record["payload"]["expires_at"]:
                            raise RuleChangeError("approval expired before apply")
                        try:
                            self._apply_approved(record)
                        except RuleChangeError as exc:
                            # A proposal whose base/mount/health drifted must
                            # not be retried against a later, different state.
                            if record["status"] == "pending":
                                try:
                                    self._abort_preconsume(record, str(exc))
                                except RuleChangeError:
                                    pass  # durable abort_pending record retries
                            elif record["status"] == "prepared":
                                record["result"] = "approval consume state uncertain; awaiting broker reconciliation"
                                self._save(record)
                            else:
                                record["status"], record["result"] = "failed", "approved proposal not applied: %s" % exc
                                self._save(record)
                    elif decision["status"] == "consumed":
                        # Crash between consume and recording 'applying'. No replay.
                        record["status"], record["result"] = "failed", "approval already consumed; no replay"
                        record["approval_consumed"] = True
                        record["result_posted"] = False
                        self._save(record)
                        try:
                            self._post_result(record)
                        except RuleChangeError:
                            pass
                except RuleChangeError as exc:
                    if int(self.clock()) >= record["payload"]["expires_at"]:
                        record["status"], record["result"] = "expired", "approval unavailable or expired; no apply"
                    elif record["status"] == "prepared":
                        # A consume HTTP response may be lost after the broker
                        # committed it. Keep the durable backup and reconcile
                        # the broker status on the next timer run; never guess.
                        record["result"] = "approval consume state uncertain; awaiting broker reconciliation"
                    else:
                        # Broker outages retain pending until expiry; other errors
                        # are visible to the operator and still cannot apply.
                        record["result"] = str(exc)
                    self._save(record)
                results.append({"proposal_id": path.stem, "status": record["status"]})
        return results

    def check(self):
        """Read-only install preflight; never stages, posts, consumes, or reloads."""
        found = {}
        for target, spec in self.targets.items():
            if spec["host"] != self.host:
                continue
            runtime = self._inspect(spec)
            current, _, aux = self._snapshot(spec)
            found[target] = {"sha256": sha256(current), "runtime": runtime, "related_hashes": aux}
        if not found:
            raise RuleChangeError("no target configured for host")
        return {"host": self.host, "targets": found, "broker_configured": True}


def _secure_config(path=CONFIG_PATH):
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o077:
        raise RuleChangeError("config must be root-owned mode 0600")
    with open(path, encoding="utf-8") as source:
        conf = json.load(source)
    if set(conf) != {"host", "broker_url", "broker_token_file"}:
        raise RuleChangeError("invalid configuration fields")
    token_path = Path(conf["broker_token_file"])
    token_st = os.lstat(token_path)
    if not stat.S_ISREG(token_st.st_mode) or token_st.st_uid != 0 or stat.S_IMODE(token_st.st_mode) & 0o077:
        raise RuleChangeError("broker token file must be root-owned mode 0600")
    token = token_path.read_text(encoding="ascii").strip()
    return conf["host"], Broker(conf["broker_url"], token)


def _load_extension(name):
    """Never import an operation executor from cwd, PYTHONPATH or caller input."""
    if name not in ("service_action_executor", "incident_containment"):
        raise RuleChangeError("unsupported operation extension")
    if name in _EXTENSIONS:
        return _EXTENSIONS[name]
    path = EXTENSION_DIR / (name + ".py")
    for directory in (EXTENSION_DIR, *EXTENSION_DIR.parents):
        st = directory.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022:
            raise RuleChangeError("operation extension directory must be root-owned and not writable by others")
    _, st = _read_regular(path, 256 * 1024)
    if st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022:
        raise RuleChangeError("operation extension must be root-owned and not writable by others")
    spec = importlib.util.spec_from_file_location("_capstone_" + name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    _EXTENSIONS[name] = module
    return module


def _operation_services(engine):
    services = [_load_extension("service_action_executor").ServiceActionService(engine)]
    if engine.host == "a":
        services.append(_load_extension("incident_containment").ContainmentService(engine))
    return services


def _operation_status(engine, request_id):
    if not isinstance(request_id, str) or not re.fullmatch(r"[0-9a-f]{32}", request_id):
        raise RuleChangeError("invalid operation request ID")
    matches = [service for service in _operation_services(engine)
               if (getattr(service, "state_dir", getattr(service, "directory", None)) / (request_id + ".json")).exists()]
    if len(matches) != 1:
        raise RuleChangeError("operation request is missing or ambiguous")
    return matches[0].status(request_id)


def _unique_request(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RuleChangeError("duplicate request field")
        result[key] = value
    return result


def _submit_incident(host, broker, incident):
    """Root AR evidence registration, with no engine, approval or firewall path."""
    if host != "a" or os.geteuid() != 0 or "SUDO_USER" in os.environ:
        raise RuleChangeError("incident registration requires direct root on host a")
    fields = {"event_id", "timestamp", "agent_id", "rule_id", "level", "src_ip", "location"}
    if type(incident) is not dict or set(incident) != fields:
        raise RuleChangeError("invalid incident fields")
    if (incident["agent_id"] != "001" or incident["rule_id"] != "100110" or
            type(incident["level"]) is not int or incident["level"] != 9 or
            incident["location"] != INCIDENT_LOCATION or
            not isinstance(incident["event_id"], str) or
            not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", incident["event_id"])):
        raise RuleChangeError("invalid incident source or identity")
    try:
        source, timestamp = incident["src_ip"], incident["timestamp"]
        if not isinstance(source, str) or str(ipaddress.IPv4Address(source)) != source:
            raise ValueError("invalid IPv4")
        if not isinstance(timestamp, str) or not 1 <= len(timestamp) <= 40:
            raise ValueError("invalid timestamp")
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        now = time.time()
        if dt.tzinfo is None or not now - 300 <= dt.timestamp() <= now + 2:
            raise ValueError("stale timestamp")
    except (ValueError, OverflowError):
        raise RuleChangeError("invalid or stale incident evidence") from None
    identity = {key: incident[key] for key in ("event_id", "agent_id", "rule_id", "location")}
    event_key = "incident:" + sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode())
    result = broker.request("POST", "/management/incidents", incident)
    if (type(result) is not dict or set(result) != {"queued", "event_key", "seq"} or
            result["queued"] is not True or result["event_key"] != event_key or
            type(result["seq"]) is not int or result["seq"] <= 0):
        raise RuleChangeError("incident queue receipt invalid")
    return result


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if os.geteuid() != 0:
        raise RuleChangeError("root helper must run as root")
    host, broker = _secure_config()
    if not argv:
        raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
        if len(raw) > MAX_REQUEST:
            raise RuleChangeError("request too large")
        request = json.loads(raw, object_pairs_hook=_unique_request)
        if not isinstance(request, dict):
            raise RuleChangeError("request must be a JSON object")
        if request.get("operation") == "submit-incident":
            if set(request) != {"operation", "incident"}:
                raise RuleChangeError("invalid incident request fields")
            result = _submit_incident(host, broker, request["incident"])
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
            return
    engine = Engine(host, broker, read_only=argv in (["--check"], ["--broker-check"]))
    if argv == ["--broker-check"]:
        broker.health()
        result = {"broker": "authenticated_response_verified", "host": host}
    elif argv == ["--check"]:
        result = engine.check()
    elif argv == ["--once"]:
        services = _operation_services(engine)
        result = {"processed": [], "operations": []}
        # Reconcile time-bounded containment before potentially slow rule
        # syntax tests or service readiness waits. Kernel TTL is independent.
        if engine.host == "a":
            result["operations"].extend(services[1].worker_once())
        result["processed"] = engine.worker_once()
        result["operations"].extend(services[0].worker_once())
    elif not argv:
        if request.get("operation") == "get" and set(request) == {"operation", "target"}:
            result = engine.get_target(request["target"])
        elif request.get("operation") == "propose" and set(request) == {"operation", "target", "base_sha256", "candidate_content", "reason"}:
            result = engine.propose(request["target"], request["base_sha256"], request["candidate_content"], request["reason"])
        elif request.get("operation") == "propose-edit" and set(request) == {"operation", "target", "base_sha256", "edits", "reason"}:
            result = engine.propose_edit(request["target"], request["base_sha256"], request["edits"], request["reason"])
        elif request.get("operation") == "status" and set(request) == {"operation", "proposal_id"}:
            result = engine.status(request["proposal_id"])
        elif request.get("operation") == "service-get" and set(request) == {"operation", "target"}:
            result = _load_extension("service_action_executor").ServiceActionService(engine).get_target(request["target"])
        elif request.get("operation") == "service-propose" and set(request) == {"operation", "target", "action", "base_state_sha256", "reason"}:
            result = _load_extension("service_action_executor").ServiceActionService(engine).propose(
                request["target"], request["action"], request["base_state_sha256"], request["reason"])
        elif request.get("operation") == "contain-ip" and set(request) == {"operation", "ip", "reason"}:
            if engine.host != "a":
                raise RuleChangeError("temporary containment is available only on host a")
            if os.environ.get("SUDO_USER") != "rulechg":
                raise RuleChangeError("temporary containment requires the restricted MCP caller")
            result = _load_extension("incident_containment").ContainmentService(engine).propose(
                request["ip"], request["reason"], requested_by="hermes-mcp")
        elif request.get("operation") == "operation-status" and set(request) == {"operation", "request_id"}:
            result = _operation_status(engine, request["request_id"])
        else:
            raise RuleChangeError("unsupported operation or arguments")
    else:
        raise RuleChangeError("unsupported command-line arguments")
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (RuleChangeError, OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False))
        sys.exit(1)
