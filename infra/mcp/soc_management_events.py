#!/usr/bin/env python3
"""Durable notification outbox. Never restores approval authority or executes work."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
from datetime import datetime

DEFAULT_DB = "/var/lib/socbot/management-events.sqlite3"
LOCATION = "/home/groot_a/capstone/secstack/logs/suricata/eve.json"
MAX_DB_BYTES = 128 * 1024 * 1024
MAX_PAYLOAD_BYTES = 8192
KINDS = frozenset(("rule_change", "operation", "incident"))


class OutboxError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def validate_incident(value, now=None):
    fields = {"event_id", "timestamp", "agent_id", "rule_id", "level", "src_ip", "location"}
    if type(value) is not dict or set(value) != fields:
        raise OutboxError("invalid_incident_fields")
    if not isinstance(value["event_id"], str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value["event_id"]):
        raise OutboxError("invalid_event_id")
    if (value["agent_id"] != "001" or value["rule_id"] != "100110" or
            type(value["level"]) is not int or value["level"] != 9 or value["location"] != LOCATION):
        raise OutboxError("incident_source_mismatch")
    stamp = value["timestamp"]
    try:
        if not isinstance(stamp, str) or len(stamp) > 40:
            raise ValueError()
        dt = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            raise ValueError()
        instant = dt.timestamp()
    except (ValueError, OverflowError):
        raise OutboxError("invalid_incident_timestamp") from None
    now = time.time() if now is None else now
    if not now - 300 <= instant <= now + 2:
        raise OutboxError("stale_incident")
    try:
        address = ipaddress.IPv4Address(value["src_ip"])
        if not isinstance(value["src_ip"], str) or str(address) != value["src_ip"]:
            raise ValueError()
    except (ValueError, ipaddress.AddressValueError):
        raise OutboxError("invalid_source_ipv4") from None
    # This is only an incident hint. No IP eligibility or blocking decision here.
    return json.loads(canonical(value))


class Outbox:
    def __init__(self, path=None):
        self.path = Path(path or os.environ.get("SOC_MANAGEMENT_EVENTS_DB", DEFAULT_DB))

    def _check_parent(self):
        if not self.path.is_absolute():
            raise OutboxError("outbox_absolute_path_required")
        for parent in (self.path.parent, *self.path.parent.parents):
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode):
                raise OutboxError("outbox_parent_not_directory")
        info = self.path.parent.lstat()
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise OutboxError("outbox_parent_requires_owner_0700")

    def _check_file(self):
        info = self.path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > MAX_DB_BYTES):
            raise OutboxError("outbox_file_metadata_invalid")
        return info.st_dev, info.st_ino

    def _connect(self, create=False, readonly=False):
        self._check_parent()
        if create:
            try:
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                os.close(fd)
            except FileExistsError:
                pass
        identity = self._check_file()
        uri = self.path.as_uri() + ("?mode=ro" if readonly else "?mode=rw")
        conn = sqlite3.connect(uri, uri=True, timeout=2)
        try:
            if self._check_file() != identity:
                raise OutboxError("outbox_identity_changed")
            conn.execute("PRAGMA trusted_schema=OFF")
            if not readonly:
                conn.execute("PRAGMA synchronous=FULL")
                conn.execute("PRAGMA journal_mode=DELETE")
            if conn.execute("PRAGMA user_version").fetchone()[0] != 1:
                if not create or conn.execute("SELECT count(*) FROM sqlite_master").fetchone()[0] != 0:
                    raise OutboxError("outbox_schema_mismatch")
                conn.execute("CREATE TABLE events (seq INTEGER PRIMARY KEY AUTOINCREMENT, event_key TEXT NOT NULL UNIQUE, kind TEXT NOT NULL, at INTEGER NOT NULL, payload TEXT NOT NULL)")
                conn.execute("PRAGMA user_version=1")
                conn.commit()
            return conn
        except Exception:
            conn.close()
            raise

    def initialize(self):
        conn = self._connect(create=True)
        conn.close()

    def append(self, event_key, kind, payload, now=None):
        if (not isinstance(event_key, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,240}", event_key)
                or kind not in KINDS or type(payload) is not dict):
            raise OutboxError("invalid_outbox_event")
        encoded = canonical(payload)
        if len(encoded.encode()) > MAX_PAYLOAD_BYTES:
            raise OutboxError("outbox_payload_too_large")
        conn = self._connect(create=True)
        try:
            with conn:
                conn.execute("INSERT OR IGNORE INTO events(event_key,kind,at,payload) VALUES(?,?,?,?)",
                             (event_key, kind, int(time.time() if now is None else now), encoded))
                row = conn.execute("SELECT seq,kind,payload FROM events WHERE event_key=?", (event_key,)).fetchone()
                if row[1:] != (kind, encoded):
                    raise OutboxError("outbox_event_key_conflict")
            return row[0]
        finally:
            conn.close()

    def read(self, after=0, limit=100):
        if type(after) is not int or not 0 <= after <= 2**63 - 1 or type(limit) is not int or not 1 <= limit <= 100:
            raise OutboxError("invalid_outbox_cursor")
        conn = self._connect(readonly=True)
        try:
            conn.execute("BEGIN")
            latest = conn.execute("SELECT coalesce(max(seq),0) FROM events").fetchone()[0]
            rows = conn.execute("SELECT seq,event_key,kind,at,payload FROM events WHERE seq>? ORDER BY seq LIMIT ?", (after, limit)).fetchall()
            return {"events": [{"seq": row[0], "event_key": row[1], "kind": row[2], "at": row[3], "payload": json.loads(row[4])} for row in rows],
                    "latest_seq": latest}
        finally:
            conn.close()


def incident_event(value, now=None):
    payload = validate_incident(value, now)
    identity = {key: payload[key] for key in ("event_id", "agent_id", "rule_id", "location")}
    key = "incident:" + hashlib.sha256(canonical(identity).encode()).hexdigest()
    return key, payload
