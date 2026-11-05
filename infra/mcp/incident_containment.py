#!/usr/bin/env python3
"""Bounded incident containment on A, with server-verified evidence and HITL retention.

No daemon, package, container configuration, arbitrary command, or caller supplied
log path is accepted. The existing root rule-change worker owns reconciliation.
Only new entries in the existing inet/capstone_fw/agent_block set are managed.
Per-element comments bind ownership to an incident and absolute deadline; manual
changes or a firewall reload that removes the comment relinquish ownership.
"""
import contextlib
from datetime import datetime
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat

TARGET = "a:incident-ip"
TEMP_SECONDS = 600
KEEP_SECONDS = 3600
COOLDOWN_SECONDS = 60
LOOKBACK_SECONDS = 300
EVE_PATH = Path("/home/groot_a/capstone/secstack/logs/suricata/eve.json")
MANAGED_ROOT = Path("/var/lib/capstone-raw-operations")
MANAGED_READER = Path("/opt/rule-change/managed_suricata_evidence.py")
WAF_READER = Path("/opt/rule-change/managed_waf_evidence.py")
NFT = "/usr/sbin/nft"
BLOCK_LOCK = Path("/var/lib/capstone/agent_block.lock")
RID = re.compile(r"[0-9a-f]{32}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
PROTECTED = tuple(ipaddress.ip_network(x) for x in (
    "211.170.162.0/24",  # campus DGX endpoints .110/.111 and their infrastructure
    "172.18.0.2/32", "172.18.0.3/32", "172.19.0.2/32",  # fixed WAF / trusted proxy endpoints
    "168.126.63.1/32", "168.126.63.2/32", "8.8.8.8/32", "8.8.4.4/32",
    "1.1.1.1/32", "1.0.0.1/32", "9.9.9.9/32"))
# RFC1918 is an address class, not an implicit trust boundary. Live role-based
# never_block entries, interfaces/gateways/DNS and established sessions still win.
RFC1918 = tuple(ipaddress.ip_network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
DESTINATIONS = tuple(ipaddress.ip_network(x) for x in ("192.168.16.230/32", "10.200.10.0/24"))
# Recon, policy alerts and the historical DGX false-positive ET pair are excluded.
ATTACK_CATEGORIES = frozenset(("Attempted Administrator Privilege Gain",
    "Attempted User Privilege Gain", "Web Application Attack",
    "Successful Administrator Privilege Gain", "Successful User Privilege Gain"))
EXCLUDED_SIDS = frozenset((1000000, 1000001, 1000002, 1000010, 1000050, 1000051,
                           2034802, 2034806))
TERMINAL = frozenset(("released", "expired", "failed", "ownership_lost"))


class ContainmentError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def operation_digest(payload):
    return digest({k: payload[k] for k in ("request_id", "kind", "target", "plan", "plan_sha256", "expires_at", "requested_by")})


def checked_ip(value):
    if not isinstance(value, str):
        raise ContainmentError("source must be a canonical public or RFC1918 IPv4")
    try:
        addr = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        raise ContainmentError("source must be a canonical public or RFC1918 IPv4") from None
    if str(addr) != value or not (addr.is_global or any(addr in n for n in RFC1918)) or addr.is_multicast or addr.is_reserved or any(addr in n for n in PROTECTED):
        raise ContainmentError("protected, special-use, or non-canonical source address")
    return addr


def timestamp(value):
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            raise ValueError()
        return dt.timestamp()
    except (ValueError, TypeError, AttributeError):
        raise ContainmentError("event timestamp lacks a valid explicit timezone") from None


def validated_evidence(events, ip, now):
    """One recent bidirectional attack flow is enough for provisional containment.

    Alert content/signatures are never copied into the approval card. The input
    is trusted only for its provenance: the helper reads the fixed sensor log.
    A completed investigation or three independent flows is not required.
    Caller descriptions, fabricated IDs, outbound traffic and non-attack events
    are not sensor evidence. The LLM requests containment; this is validation.
    """
    checked_ip(ip)
    rows = {}
    for event in events:
        if not isinstance(event, dict) or event.get("event_type") != "alert":
            continue
        try:
            seen = timestamp(event.get("timestamp"))
            alert = event["alert"]
            sid = int(alert["signature_id"])
            flow = event.get("flow", {})
            destination = ipaddress.IPv4Address(event["dest_ip"])
            fid = event["flow_id"]
            # The bidirectional flow counters and TCP application parser avoid
            # admitting a lone spoofable SYN/UDP packet as an attack identity.
            valid = (now - LOOKBACK_SECONDS <= seen <= now + 2 and
                     event.get("src_ip") == ip and event.get("proto") == "TCP" and
                     event.get("direction") == "to_server" and
                     flow.get("src_ip") == ip and flow.get("dest_ip") == str(destination) and
                     event.get("in_iface") == "ens192" and
                     any(destination in n for n in DESTINATIONS) and
                     type(alert.get("severity")) is int and alert.get("severity") in (1, 2) and
                     alert.get("category") in ATTACK_CATEGORIES and
                     sid not in EXCLUDED_SIDS and sid >= 1000000 and
                     isinstance(fid, int) and not isinstance(fid, bool) and fid > 0 and
                     int(flow.get("pkts_toserver", 0)) >= 2 and
                     int(flow.get("pkts_toclient", 0)) >= 1 and
                     event.get("app_proto") in ("http", "http2", "tls", "ssh", "smtp", "smb", "dcerpc"))
            if not valid:
                continue
            row = {"timestamp": event["timestamp"], "flow_id": fid,
                   "src_ip": ip, "dest_ip": str(destination),
                   "dest_port": int(event["dest_port"]), "signature_id": sid,
                   "severity": alert["severity"], "category": alert["category"]}
            if not 1 <= row["dest_port"] <= 65535:
                continue
            # Keep the newest observation per flow/signature. An older alert
            # in the same persistent TCP flow must not hide a later attack
            # after administrator release. Independent flows still count once.
            key = (fid, sid)
            if key not in rows or (seen, canonical(row)) > (timestamp(rows[key]['timestamp']), canonical(rows[key])):
                rows[key] = row
        except (KeyError, ValueError, TypeError, ContainmentError):
            continue
    ordered = sorted(rows.values(), key=lambda r: (r["timestamp"], r["flow_id"]))
    if not ordered:
        raise ContainmentError("no recent inbound severity-1/2 attack flow observed by the trusted sensor")
    return {"sensor": "a:suricata", "window_seconds": LOOKBACK_SECONDS,
            "independent_flows": len({row['flow_id'] for row in ordered}), "events": ordered[-16:]}


def _reader_namespace(path):
    # Fixed extension loaded from the exact verified bytes. Neither caller path
    # nor cwd/PYTHONPATH participates; malformed managed state never falls back.
    for directory in (path.parent, *path.parent.parents):
        st = directory.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022:
            raise ContainmentError("unsafe managed evidence extension directory")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1 or
                stat.S_IMODE(before.st_mode) & 0o022 or not 0 < before.st_size <= 64 * 1024):
            raise ContainmentError("unsafe managed evidence extension")
        raw = os.read(fd, 64 * 1024 + 1)
        def identity(st):
            return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode,
                    st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        if (len(raw) != before.st_size or identity(before) != identity(os.fstat(fd)) or
                identity(before) != identity(path.lstat())):
            raise ContainmentError("managed evidence extension changed")
    finally:
        os.close(fd)
    namespace = {"__name__": "_capstone_managed_evidence", "__file__": str(path)}
    exec(compile(raw, str(path), "exec"), namespace)
    return namespace


def _managed_evidence(ip, now):
    namespace = _reader_namespace(MANAGED_READER)
    try:
        return namespace["read_evidence"](ip, now, validated_evidence)
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        raise ContainmentError("managed sensor evidence unavailable or insufficient; no legacy fallback") from None


def read_suricata_evidence(ip, now, path=EVE_PATH):
    if Path(path) == EVE_PATH and os.path.lexists(MANAGED_ROOT):
        return _managed_evidence(ip, now)
    events = []
    for source in (Path(str(path) + ".1"), Path(path)):
        try:
            fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except FileNotFoundError:
            if source == Path(path):
                raise ContainmentError("live Suricata evidence log is unavailable") from None
            continue
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise ContainmentError("evidence source is not a regular sensor log")
            start = max(0, st.st_size - 16 * 1024 * 1024)
            os.lseek(fd, start, os.SEEK_SET)
            data = b""
            while len(data) < 16 * 1024 * 1024:
                part = os.read(fd, min(1024 * 1024, 16 * 1024 * 1024 - len(data)))
                if not part:
                    break
                data += part
            lines = data.splitlines()
            if start and lines:
                lines = lines[1:]
            for line in lines:
                if len(line) > 256 * 1024:
                    continue
                try:
                    events.append(json.loads(line))
                except (ValueError, UnicodeDecodeError):
                    continue
        finally:
            os.close(fd)
    return validated_evidence(events, ip, now)


def read_evidence(ip, now, path=EVE_PATH, *, after=None):
    checked_ip(ip)
    try:
        return ContainmentService._fresh_evidence(read_suricata_evidence(ip, now, path), after)
    except (ContainmentError, OSError):
        if Path(path) != EVE_PATH:
            raise
    # A failed sensor is never replaced with an unverified copy of its log.
    # An independently attested WAF denial is another trusted source instead.
    try:
        return ContainmentService._fresh_evidence(_reader_namespace(WAF_READER)["read_evidence"](
            ip, now, _reader_namespace(MANAGED_READER)), after)
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        raise ContainmentError("no verified recent Suricata attack flow or WAF attack denial; containment refused") from None


def _set_object(data, name):
    try:
        obj = json.loads(data)
        matches = [r["set"] for r in obj["nftables"] if "set" in r and r["set"].get("name") == name]
        if len(matches) != 1:
            raise ValueError()
        s = matches[0]
        if s.get("family") != "inet" or s.get("table") != "capstone_fw" or s.get("type") != "ipv4_addr":
            raise ValueError()
        return s
    except (KeyError, TypeError, ValueError):
        raise ContainmentError("unexpected firewall set representation") from None


def _element(value):
    return value.get("elem", value) if isinstance(value, dict) else {"val": value}


def _contains(value, addr):
    value = _element(value).get("val", value)
    try:
        if isinstance(value, str):
            return addr in ipaddress.ip_network(value, strict=False)
        if isinstance(value, dict) and set(value) == {"prefix"}:
            p = value["prefix"]
            return addr in ipaddress.ip_network(str(p["addr"]) + "/" + str(p["len"]), strict=False)
        if isinstance(value, dict) and set(value) == {"range"}:
            return ipaddress.ip_address(value["range"][0]) <= addr <= ipaddress.ip_address(value["range"][1])
    except (KeyError, TypeError, ValueError):
        pass
    raise ContainmentError("unrecognized protected-network expression")


class NftBackend:
    def __init__(self, engine):
        self.engine = engine

    @contextlib.contextmanager
    def locked(self):
        # Shared with existing manual agent_block and its expiry reaper. Never
        # invoke agent_block while holding this lock (it would lock recursively).
        readonly = getattr(self.engine, "read_only", False)
        try:
            fd = os.open(BLOCK_LOCK, (os.O_RDONLY if readonly else os.O_CREAT | os.O_RDWR) | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileNotFoundError:
            if not readonly:
                raise
            yield
            return
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_nlink != 1:
                raise ContainmentError("unsafe firewall mutation lock")
            fcntl.flock(fd, fcntl.LOCK_SH if readonly else fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _set(self, name):
        return _set_object(self.engine.runner.call([NFT, "-j", "list", "set", "inet", "capstone_fw", name]), name)

    def check_protected(self, ip):
        addr = checked_ip(ip)
        if any(_contains(e, addr) for e in self._set("never_block").get("elem", [])):
            raise ContainmentError("source is in the live never_block set")
        # Protect local interface addresses/default gateways and active SSH or
        # outgoing management/service connections. No caller-supplied endpoint.
        addresses = json.loads(self.engine.runner.call(["/usr/sbin/ip", "-j", "address", "show"]))
        routes = json.loads(self.engine.runner.call(["/usr/sbin/ip", "-j", "route", "show", "default"]))
        if any(a.get("local") == ip for row in addresses for a in row.get("addr_info", [])) or any(r.get("gateway") == ip for r in routes):
            raise ContainmentError("source is a local address or gateway")
        resolver = Path("/etc/resolv.conf").read_text()
        if any(line.split()[1] == ip for line in resolver.splitlines()
               if len(line.split()) >= 2 and line.split()[0] == "nameserver"):
            raise ContainmentError("source is a configured DNS resolver")
        sockets = self.engine.runner.call(["/usr/bin/ss", "-Htn4", "state", "established"]).decode()
        for line in sockets.splitlines():
            cols = line.split()
            if len(cols) < 4:
                raise ContainmentError("cannot verify established endpoint protection")
            local, peer = cols[-2:]
            try:
                local_port = int(local.rsplit(":", 1)[1])
                remote_ip, remote_port = peer.rsplit(":", 1)
                remote_port = int(remote_port)
                remote_ip = remote_ip.strip("[]")
            except (ValueError, IndexError):
                raise ContainmentError("cannot parse established endpoint protection") from None
            if remote_ip == ip and (local_port == 22 or local_port >= 32768 or remote_port in (22, 53, 123, 443, 8090, 9200, 11434, 55000)):
                raise ContainmentError("source is an active SSH or outgoing service endpoint")

    def snapshot(self, ip):
        s = self._set("agent_block")
        if "timeout" not in s.get("flags", []):
            raise ContainmentError("firewall set does not support kernel expiry")
        elements = [_element(e) for e in s.get("elem", [])]
        matches = [e for e in elements if e.get("val") == ip]
        if len(matches) > 1:
            raise ContainmentError("duplicate firewall element")
        return {"ip": ip, "set_handle": s.get("handle"), "element": matches[0] if matches else None}

    @staticmethod
    def tag(record, deadline=None):
        return "contain:%s:%d" % (record["request_id"], deadline if deadline is not None else record["owned_deadline"])

    def owned(self, record, observation):
        element = observation.get("element")
        return bool(element and element.get("comment") == self.tag(record))

    def _audit(self, action, record):
        try:
            self.engine.runner.call(["/usr/bin/logger", "-t", "agent_block", "-p", "auth.notice", "--",
                "action=%s ip=%s result=ok reason=contain:%s by=incident-helper" % (action, record["ip"], record["request_id"])])
        except Exception:
            pass  # durable incident state remains available even if syslog fails

    def create(self, record):
        self.check_protected(record["ip"])
        if self.snapshot(record["ip"])["element"] is not None:
            raise ContainmentError("existing block is not owned by this incident")
        remaining = int(record["owned_deadline"] - self.engine.clock())
        if not 1 <= remaining <= TEMP_SECONDS:
            raise ContainmentError("temporary deadline is invalid or expired")
        command = 'create element inet capstone_fw agent_block { %s timeout %ds comment "%s" }' % (record["ip"], remaining, self.tag(record))
        self.engine.runner.call([NFT, command])
        observed = self.snapshot(record["ip"])
        if not self.owned(record, observed):
            raise ContainmentError("new firewall element ownership readback failed")
        self._audit("add", record)
        return observed

    def release(self, record):
        observed = self.snapshot(record["ip"])
        if observed["element"] is None:
            return observed
        if not self.owned(record, observed):
            raise ContainmentError("firewall element ownership changed; refusing release")
        self.engine.runner.call([NFT, "delete", "element", "inet", "capstone_fw", "agent_block", "{", record["ip"], "}"])
        after = self.snapshot(record["ip"])
        if after["element"] is not None:
            raise ContainmentError("firewall release readback failed")
        self._audit("del", record)
        return after

    def retain(self, record, deadline):
        self.check_protected(record["ip"])
        observed = self.snapshot(record["ip"])
        # Crash after the atomic replacement: recognize exactly the persisted
        # absolute deadline, without reissuing add or refreshing the TTL.
        future = dict(record, owned_deadline=deadline)
        if self.owned(future, observed):
            return observed
        if not self.owned(record, observed):
            raise ContainmentError("temporary block disappeared or ownership changed")
        remaining = int(deadline - self.engine.clock())
        if not 1 <= remaining <= KEEP_SECONDS:
            raise ContainmentError("approved retention deadline is expired or invalid")
        command = ('delete element inet capstone_fw agent_block { %s }; '
                   'create element inet capstone_fw agent_block { %s timeout %ds comment "%s" }') % (record["ip"], record["ip"], remaining, self.tag(record, deadline))
        self.engine.runner.call([NFT, command])
        after = self.snapshot(record["ip"])
        if not self.owned(future, after):
            raise ContainmentError("retention ownership readback failed")
        self._audit("add", record)
        return after


class ContainmentService:
    def __init__(self, engine, backend=None, evidence=None):
        self.engine = engine
        self.directory = Path(engine.state_dir) / "containment"
        self.backend = backend or NftBackend(engine)
        self.evidence = evidence or read_evidence
        if engine.host == "a":
            if not getattr(engine, "read_only", False):
                self.directory.mkdir(mode=0o700, parents=False, exist_ok=True)
            st = os.lstat(self.directory)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700:
                raise ContainmentError("containment state directory must be owned by executor, mode 0700")

    def _path(self, rid):
        if not isinstance(rid, str) or not RID.fullmatch(rid):
            raise ContainmentError("invalid containment request ID")
        return self.directory / (rid + ".json")

    def _save(self, record):
        path = self._path(record["request_id"])
        temporary = self.directory / ("." + secrets.token_hex(16))
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "wb") as out:
                out.write(canonical(record)); out.flush(); os.fsync(out.fileno())
            os.replace(temporary, path)
            dfd = os.open(self.directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        finally:
            if temporary.exists():
                temporary.unlink()

    def _load(self, rid):
        fd = os.open(self._path(rid), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o600 or st.st_size > 128 * 1024 or st.st_nlink != 1:
                raise ContainmentError("unsafe incident state")
            record = json.loads(os.read(fd, 128 * 1024 + 1))
        finally:
            os.close(fd)
        if record.get("request_id") != rid:
            raise ContainmentError("incident state identity mismatch")
        checked_ip(record["ip"])
        payload = record["payload"]
        if (payload.get("request_id") != rid or payload.get("kind") != "containment" or
                payload.get("target") != TARGET or payload["plan"].get("ip") != record["ip"] or
                payload["plan"].get("keep_seconds") != KEEP_SECONDS or
                payload["plan"].get("temporary_expires_at") != payload.get("expires_at") or
                digest(payload["plan"]) != payload.get("plan_sha256") or
                operation_digest(payload) != record.get("proposal_digest") or
                digest(record["evidence"]) != payload["plan"].get("evidence_sha256") or
                any(type(record[k]) is not int for k in ("created_at", "owned_deadline", "cooldown_until")) or
                payload["expires_at"] != record["created_at"] + TEMP_SECONDS or
                not record["created_at"] < record["owned_deadline"] <= record["created_at"] + TEMP_SECONDS + KEEP_SECONDS):
            raise ContainmentError("incident state plan or absolute deadline is inconsistent")
        if 'closed_at' in record and (type(record['closed_at']) is not int or
                record['closed_at'] < record['created_at'] or record['status'] not in TERMINAL):
            raise ContainmentError('incident close time is inconsistent')
        applied={'initial_apply_observed_at','initial_apply_observation_sha256'} & record.keys()
        if applied and (len(applied)!=2 or type(record['initial_apply_observed_at']) is not int or
                not record['created_at']<=record['initial_apply_observed_at']<=payload['expires_at'] or
                not isinstance(record['initial_apply_observation_sha256'],str) or
                not SHA.fullmatch(record['initial_apply_observation_sha256'])):
            raise ContainmentError('initial application observation is inconsistent')
        return record

    def _records(self):
        paths = sorted(self.directory.glob("*.json"))
        if len(paths) > 4096:
            raise ContainmentError("incident archive requires operator maintenance")
        return [self._load(p.stem) for p in paths]

    @staticmethod
    def _ended_at(r):
        # Old records without verified close metadata retain their original
        # deadline. Never infer a release from mtime, card time, or an empty set.
        return min(r['owned_deadline'], r.get('closed_at', r['owned_deadline']))

    @staticmethod
    def _cooldown_until(r):
        # Apply the current user-approved interval to existing records without
        # rewriting their historical signed evidence/plan or extending a block.
        return min(r["cooldown_until"], ContainmentService._ended_at(r) + COOLDOWN_SECONDS)

    def _mark_closed(self, record):
        """Call only after ownership-bound release and absent-element readback."""
        now = int(self.engine.clock())
        if now < record['created_at']:
            raise ContainmentError('clock moved before incident creation')
        record.setdefault('closed_at', now)
        record['cooldown_until'] = self._ended_at(record) + COOLDOWN_SECONDS

    @staticmethod
    def _fresh_evidence(evidence, after):
        if after is None:
            return evidence
        events = [row for row in evidence.get('events', [])
                  if isinstance(row, dict) and timestamp(row.get('timestamp')) > after]
        if not events:
            raise ContainmentError('no new verified attack after previous containment ended; old evidence cannot reblock')
        evidence = dict(evidence, events=events, after_previous_containment_at=after)
        if evidence.get('sensor') == 'a:suricata':
            evidence['independent_flows'] = len({row['flow_id'] for row in events})
        elif evidence.get('sensor') == 'a:modsecurity':
            evidence['http_transactions'] = len({row['transaction_id'] for row in events})
        else:
            raise ContainmentError('unknown trusted evidence sensor')
        return evidence

    @staticmethod
    def _summary(r):
        return {"request_id": r["request_id"], "target": TARGET, "kind": "containment", "ip": r["ip"],
                "workflow_created_at": r["created_at"],
                "initial_apply_observed_at": r.get("initial_apply_observed_at"),
                "initial_apply_observation_sha256": r.get("initial_apply_observation_sha256"),
                "initial_apply_time_scope": ("kernel ownership readback after create; not first-packet drop time"
                    if "initial_apply_observed_at" in r else "not recorded; do not infer from deadline or TTL"),
                "status": r["status"], "temporary_expires_at": r["payload"]["expires_at"],
                "owned_deadline": r["owned_deadline"], "keep_seconds": KEEP_SECONDS,
                "cooldown_seconds": COOLDOWN_SECONDS,
                "cooldown_until": ContainmentService._cooldown_until(r),
                "closed_at": r.get('closed_at'),
                "evidence_sha256": r["payload"]["plan"]["evidence_sha256"],
                "independent_flows": r["evidence"]["independent_flows"],
                "evidence_sensor": r["evidence"]["sensor"],
                "http_transactions": r["evidence"].get("http_transactions", 0),
                "result": r.get("result", ""), "result_posted": r.get("result_posted", False)}

    def status(self, rid):
        if self.engine.host != "a":
            raise ContainmentError("incident containment exists only on host A")
        with self.engine.locked():
            record = self._load(rid)
            result = self._summary(record)
            result["status_source"] = "persistent_workflow"
            result["live_observed_at"] = int(self.engine.clock())
            try:
                with self.backend.locked():
                    observed = self.backend.snapshot(record["ip"])
                element = observed.get("element")
                owned_deadlines = [record["owned_deadline"]]
                if record["status"] == "keeping" and record.get("consumed"):
                    owned_deadlines.append(record["keep_deadline"])
                matched = next((d for d in owned_deadlines if element and
                                element.get("comment") == NftBackend.tag(record, d)), None)
                result["live_block_state"] = "absent" if element is None else "owned" if matched is not None else "foreign"
                result["live_owned_deadline"] = matched
                result["live_remaining_seconds"] = element.get("expires") if matched is not None else None
                result["live_observation_sha256"] = digest(observed)
            except Exception:
                result["live_block_state"] = "unavailable"
                result["live_owned_deadline"] = None
                result["live_remaining_seconds"] = None
                result["live_observation_sha256"] = None
            return result

    def propose(self, ip, reason, requested_by="hermes"):
        if self.engine.host != "a":
            raise ContainmentError("incident containment exists only on host A")
        checked_ip(ip)
        if not isinstance(reason, str) or not reason.strip() or len(reason.encode()) > 1000 or any(ord(c) < 32 for c in reason):
            raise ContainmentError("reason must be nonempty single-line text up to 1000 bytes")
        if not re.fullmatch(r"[A-Za-z0-9_.:@-]{1,80}", requested_by):
            raise ContainmentError("invalid requester")
        with self.engine.locked():
            now = int(self.engine.clock())
            records = self._records()
            ended = []
            for old in records:
                if old["ip"] == ip:
                    if old["status"] not in TERMINAL and now < old["owned_deadline"]:
                        return dict(self._summary(old), duplicate=True)
                    if now < self._cooldown_until(old):
                        raise ContainmentError("same-IP cooldown active; repeated requests cannot renew containment")
                    ended.append(self._ended_at(old))
            if sum(r["status"] not in TERMINAL and now < r["owned_deadline"] for r in records) >= 8:
                raise ContainmentError("concurrent temporary containment limit reached")
            cutoff = max(ended) if ended else None
            # Apply the boundary before selecting the default source: a stale
            # but still-in-lookback IDS flow cannot hide a NEW WAF transaction.
            observed = (self.evidence(ip, now, after=cutoff) if self.evidence is read_evidence
                        else self.evidence(ip, now))
            evidence = self._fresh_evidence(observed, cutoff)
            self.engine.broker.health()  # authenticated availability before mutation
            rid = secrets.token_hex(16)
            deadline = now + TEMP_SECONDS
            with self.backend.locked():
                self.backend.check_protected(ip)
                before = self.backend.snapshot(ip)
                if before["element"] is not None:
                    raise ContainmentError("existing manual/other block is preserved")
                plan = {"ip": ip, "action": "temporary_block", "temporary_expires_at": deadline,
                        "keep_seconds": KEEP_SECONDS, "before_observation_sha256": digest(before),
                        "evidence_sha256": digest(evidence)}
                payload = {"request_id": rid, "kind": "containment", "target": TARGET, "plan": plan,
                           "plan_sha256": digest(plan), "expires_at": deadline, "requested_by": requested_by}
                record = {"request_id": rid, "ip": ip, "reason": reason, "evidence": evidence,
                          "payload": payload, "proposal_digest": operation_digest(payload),
                          "status": "creating", "created_at": now, "owned_deadline": deadline,
                          "cooldown_until": deadline + COOLDOWN_SECONDS, "result_posted": False}
                self._save(record)  # persist ownership before touching the kernel
                try:
                    applied = self.backend.create(record)
                    observed_at = int(self.engine.clock())
                    element = applied.get('element') if isinstance(applied,dict) else None
                    if (isinstance(element,dict) and applied.get('ip')==ip and element.get('val')==ip and
                            element.get('comment')==NftBackend.tag(record) and now<=observed_at<=deadline):
                        record['initial_apply_observed_at']=observed_at
                        record['initial_apply_observation_sha256']=digest(applied)
                    record["status"] = "awaiting_card"
                    self._save(record)
                except Exception:
                    try:
                        self.backend.release(record)
                    except Exception:
                        pass
                    record["status"], record["result"] = "failed", "temporary containment did not complete; kernel TTL remains the fallback"
                    self._save(record)
                    raise
            try:
                reply = self.engine.broker.request("POST", "/operations", payload)
                self._checked_reply(record, reply)
                if not reply.get("posted"):
                    raise ContainmentError("retention approval card was not posted")
            except Exception:
                self._release(record, "failed", "approval card unavailable; temporary block released")
                raise ContainmentError("approval posting failed; own temporary block released or left only until its original kernel deadline") from None
            record["status"] = "pending"
            self._save(record)
            return self._summary(record)

    def _checked_reply(self, record, reply):
        p = record["payload"]
        expected = {"request_id": record["request_id"], "kind": "containment", "target": TARGET,
                    "plan_sha256": p["plan_sha256"], "proposal_digest": record["proposal_digest"],
                    "expires_at": p["expires_at"]}
        if not isinstance(reply, dict) or any(reply.get(k) != v for k, v in expected.items()):
            raise ContainmentError("broker response does not match the exact incident plan")
        return reply

    def _release(self, record, terminal, detail):
        try:
            with self.backend.locked():
                after = self.backend.release(record)
            record["status"], record["result"] = terminal, detail
            self._mark_closed(record)
        except Exception:
            record["status"], record["result"] = "ownership_lost", "release not confirmed; never removing a different owner's block; original kernel TTL still applies to any owned entry"
            after = {"ip": record["ip"], "observation": "unavailable_or_changed"}
        record["after_observation_sha256"] = digest(after)
        self._save(record)

    def _post_result(self, record):
        if not record.get("consumed") or record.get("result_posted"):
            return
        status = record["status"] if record["status"] in ("kept", "released", "expired") else "failed"
        body = record.get("result_body")
        if body is None:
            body = {"proposal_digest": record["proposal_digest"], "status": status,
                    "after_observation_sha256": record["after_observation_sha256"],
                    "detail": record["result"][:200]}
            record["result_body"] = body
            self._save(record)
        response = self.engine.broker.request("POST", "/operations/%s/result" % record["request_id"], body)
        self._checked_reply(record, response)
        if not response.get("result_posted"):
            raise ContainmentError("operation result card not posted")
        record["result_posted"] = True
        self._save(record)

    def _ack_expiry(self, record):
        """Retry broker bookkeeping after local expiry; never mutate the firewall."""
        if record.get("consumed"):
            self._post_result(record)
            return
        response = self._checked_reply(record, self.engine.broker.request(
            "GET", "/operations/" + record["request_id"]))
        if response.get("status") == "expired":
            response = self._checked_reply(record, self.engine.broker.request(
                "POST", "/operations/%s/consume" % record["request_id"],
                {"proposal_digest": record["proposal_digest"]}))
        # A lost consume response is reconciled from the same bound record.
        # A consumed keep decision must never be relabelled as expired approval.
        if response.get("status") != "consumed" or response.get("consumed_decision") != "expired":
            return
        record["consumed"] = True
        self._save(record)
        self._post_result(record)

    def _advance(self, record):
        now = int(self.engine.clock())
        if record["status"] == "kept" and now >= record["owned_deadline"]:
            self._release(record, "expired", "approved retention reached its fixed deadline")
            if hasattr(self.backend, "_audit"):
                self.backend._audit("expire", record)
            self._post_result(record)
            return
        if record["status"] == "expired" and not record.get("consumed"):
            self._ack_expiry(record)
            return
        if record["status"] in TERMINAL or record["status"] == "kept":
            self._post_result(record)
            return
        if record["status"] in ("creating", "awaiting_card"):
            # Never resume a partially completed initial operation or post a
            # fresh card: a disconnected caller must not gain a new deadline.
            self._release(record, "failed", "interrupted initial containment released")
            return
        if record["status"] == "keeping":
            deadline = record["keep_deadline"]
            if now >= deadline:
                record["owned_deadline"] = deadline
                self._release(record, "expired", "approved retention deadline elapsed")
                return
            try:
                with self.backend.locked():
                    after = self.backend.retain(record, deadline)
                record["owned_deadline"] = deadline
                record["status"], record["result"] = "kept", "administrator retained this exact source until the recorded absolute deadline"
                record["after_observation_sha256"] = digest(after)
                self._save(record)
            except Exception:
                self._release(record, "failed", "retention could not be safely applied; temporary containment released")
            self._post_result(record)
            return
        if now >= record["payload"]["expires_at"]:
            self._release(record, "expired", "no timely retention approval; original temporary deadline elapsed")
            # Expiry is enforced locally even if the broker is unavailable.
            # A later worker retries only acknowledgement/reporting.
            self._ack_expiry(record)
            return
        decision = self._checked_reply(record, self.engine.broker.request("GET", "/operations/" + record["request_id"]))
        status = decision.get("status")
        if status == "pending":
            return
        if status not in ("approved", "denied", "expired", "consumed"):
            raise ContainmentError("unknown operation decision state")
        if status == "consumed":
            # Consumption without our durable intended decision cannot authorize
            # a fresh retention. Release, never replay a guessed approval.
            record["consumed"] = True
            self._release(record, "failed", "approval was already consumed; refusing a new retention")
            self._post_result(record)
            return
        intended = decision.get("decision")
        if status == "approved":
            decided_at = decision.get("decided_at")
            if intended != "keep" or not isinstance(decided_at, (int, float)) or isinstance(decided_at, bool) or not record["created_at"] <= decided_at < record["payload"]["expires_at"] or decided_at > now + 2:
                raise ContainmentError("invalid retention decision binding or time")
            record["keep_deadline"] = int(decided_at) + KEEP_SECONDS
            record["cooldown_until"] = record["keep_deadline"] + COOLDOWN_SECONDS
        record["consume_intent"] = intended
        self._save(record)
        consumed = self.engine.broker.request("POST", "/operations/%s/consume" % record["request_id"], {"proposal_digest": record["proposal_digest"]})
        self._checked_reply(record, consumed)
        expected = "keep" if status == "approved" else "release" if status == "denied" else "expired"
        if consumed.get("consumed_decision") != expected:
            raise ContainmentError("consumed decision differs from reviewed incident")
        record["consumed"] = True
        if status == "approved":
            record["status"] = "keeping"
            self._save(record)
            self._advance(record)
        else:
            self._release(record, "released" if status == "denied" else "expired", "administrator released the temporary block" if status == "denied" else "temporary approval expired")
            self._post_result(record)

    def worker_once(self):
        if self.engine.host != "a":
            return []
        results = []
        with self.engine.locked():
            for record in self._records():
                try:
                    self._advance(record)
                except Exception:
                    # Kernel timeout survives network/worker failure. Never
                    # interpret a poll error as a retention authorization.
                    pass
                results.append(self._summary(record))
        return results
