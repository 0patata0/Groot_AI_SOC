#!/usr/bin/env python3
"""Root-owned, fixed-target executor for human-approved rule changes.

The stdio MCP user may invoke this file *without arguments* via one sudoers
entry. It accepts only ``get``, ``propose``, and ``status`` JSON on stdin. A root-only
systemd timer invokes ``--once`` to complete approved proposals. No MCP field
is a filesystem path, container name, command, URL, or approval identity.

This file is intentionally separate from response-mcp.py: rule edits always
fail closed when the broker, approver, validation, or live base has changed.
"""

import contextlib
import difflib
import fcntl
import hashlib
import hmac
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
MAX_DIFF = 8 * 1024
MAX_REQUEST = 256 * 1024
MAX_RULESET = 64 * 1024 * 1024
PROPOSAL_ID = re.compile(r"^[0-9a-f]{16,64}$")
HEX_SHA = re.compile(r"^[0-9a-f]{64}$")

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
        "impact": "Suricata passive local rules and loaded all.rules are replaced together; syntax test and rule reload follow. No inline/drop transition.",
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
        if re.search(r"(?im)^\s*(?:drop|reject|rejectsrc|rejectdst|pass|bypass)\s", active):
            raise RuleChangeError("Suricata local rules must remain alert-only")
        sids = [int(x) for x in re.findall(r"(?i)\bsid\s*:\s*(\d+)\s*;", active)]
        if not sids or len(sids) != len(set(sids)) or any(not 1000000 <= sid <= 1000099 for sid in sids):
            raise RuleChangeError("Suricata local SIDs must be unique and within 1000000..1000099")
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


class Broker:
    def __init__(self, url, token):
        if url not in ("http://10.200.10.10:8090", "http://127.0.0.1:8090") or not isinstance(token, str) or len(token) < 32:
            raise RuleChangeError("dedicated approval broker is not configured")
        self.url, self.key = url, token.encode("ascii")
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

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
            with self.opener.open(req, timeout=12) as res:
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
        _atomic_bytes(path, json.dumps(record, ensure_ascii=False, sort_keys=True).encode("utf-8"), mode=0o600)

    def _load(self, rid):
        data, _ = _read_regular(self._record_path(rid), limit=MAX_REQUEST)
        record = json.loads(data)
        if record.get("proposal_id") != rid:
            raise RuleChangeError("corrupt proposal record")
        return record

    def _inspect(self, spec):
        raw = self.runner.call([DOCKER, "inspect", spec["container"]], timeout=15)
        try:
            info = json.loads(raw)[0]
        except (ValueError, IndexError, KeyError, TypeError):
            raise RuleChangeError("invalid container inspection") from None
        if not info.get("State", {}).get("Running"):
            raise RuleChangeError("target container is not running")
        health = info.get("State", {}).get("Health", {}).get("Status")
        if health and health != "healthy":
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
            return {"target": target, "content": content, "sha256": sha256(current),
                    "runtime": runtime, "impact": spec["impact"], "related_hashes": aux}

    def propose(self, target, base_sha256, candidate_content, reason):
        spec = self.spec(target)
        if not isinstance(base_sha256, str) or not HEX_SHA.fullmatch(base_sha256):
            raise RuleChangeError("base_sha256 must be a SHA-256 from get_rule_change_target")
        if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 200 or any(ord(c) < 32 for c in reason):
            raise RuleChangeError("reason must be 1..200 printable characters")
        if any(unicodedata.category(ch) == "Cf" for ch in reason):
            raise RuleChangeError("reason contains invisible Unicode format controls")
        candidate = _validate_candidate(spec["kind"], candidate_content)
        with self.locked():
            pending = sum(1 for path in self.state_dir.glob("*.json") if self._load(path.stem).get("status") == "pending")
            if pending >= 10:
                raise RuleChangeError("too many pending proposals")
            runtime = self._inspect(spec)
            current, st, aux = self._snapshot(spec)
            if sha256(current) != base_sha256:
                raise RuleChangeError("target changed since it was read; fetch current content and retry")
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
            if len(diff.encode("utf-8")) > MAX_DIFF:
                raise RuleChangeError("diff exceeds 8 KiB approval-card limit; split the edit")
            payload = {
                "target": target, "base_sha256": sha256(current), "candidate_sha256": sha256(candidate),
                "diff_sha256": sha256(diff.encode("utf-8")), "diff": diff,
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
            return {"proposal_id": rid, "status": "pending", "target": target,
                    "before_sha256": payload["base_sha256"], "after_sha256": payload["candidate_sha256"],
                    "diff": diff, "runtime_before": runtime, "approval_expires_at": payload["expires_at"],
                    "validation": validation}

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
            _atomic_bytes(spec["path"], candidate, st)
            _atomic_bytes(spec["all_path"], et + candidate, all_st)
            self.runner.call([DOCKER, "exec", "suricata", "suricata", "-T", "-S", "/rules/all.rules"], timeout=180)
            self.runner.call([DOCKER, "exec", "suricata", "suricatasc", "-c", "reload-rules"], timeout=180)
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
            if all_rules != et + candidate:
                raise RuleChangeError("post-apply loaded Suricata rules mismatch")
            expected_remote = sha256(all_rules)
        else:
            expected_remote = sha256(candidate)
        if not remote or remote[0] != expected_remote:
            raise RuleChangeError("container readback hash mismatch")

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
            self.runner.call([DOCKER, "exec", "suricata", "suricatasc", "-c", "reload-rules"], timeout=180)
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


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if os.geteuid() != 0:
        raise RuleChangeError("root helper must run as root")
    host, broker = _secure_config()
    engine = Engine(host, broker, read_only=argv in (["--check"], ["--broker-check"]))
    if argv == ["--broker-check"]:
        broker.health()
        result = {"broker": "authenticated_response_verified", "host": host}
    elif argv == ["--check"]:
        result = engine.check()
    elif argv == ["--once"]:
        result = {"processed": engine.worker_once()}
    elif not argv:
        raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
        if len(raw) > MAX_REQUEST:
            raise RuleChangeError("request too large")
        request = json.loads(raw)
        if not isinstance(request, dict):
            raise RuleChangeError("request must be a JSON object")
        if request.get("operation") == "get" and set(request) == {"operation", "target"}:
            result = engine.get_target(request["target"])
        elif request.get("operation") == "propose" and set(request) == {"operation", "target", "base_sha256", "candidate_content", "reason"}:
            result = engine.propose(request["target"], request["base_sha256"], request["candidate_content"], request["reason"])
        elif request.get("operation") == "status" and set(request) == {"operation", "proposal_id"}:
            result = engine.status(request["proposal_id"])
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
