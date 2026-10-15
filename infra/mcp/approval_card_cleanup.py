#!/usr/bin/env python3
"""Bounded expiry of exact unanswered approval cards; never approval storage.

Only cards created through this module get durable cleanup bindings. Decisions
are protected before the broker accepts them. A restart never restores approval
authority. Review parts, result posts and untracked historical cards are excluded.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import ssl
import stat
import time
import urllib.error
import urllib.parse
import urllib.request

ID = re.compile(r"[a-z0-9]{26}\Z")
RID = re.compile(r"[a-f0-9]{16}(?:[a-f0-9]{16})?\Z")
MAX_BYTES = 2 * 1024 * 1024
MAX_DB_BYTES = 128 * 1024 * 1024
MAX_ATTEMPTS = 5
GRACE_SECONDS = 0
EXPIRED_MESSAGE = "만료된 승인 요청"
KINDS = frozenset(("legacy", "rule", "operation"))


class CleanupError(Exception):
    def __init__(self, code, retryable=False):
        self.code, self.retryable = code, retryable
        super().__init__(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def attachments_empty(props):
    """Mattermost serializes cleared attachment slices as null on readback."""
    if not isinstance(props, dict):
        return False
    value = props.get("attachments")
    return value is None or (isinstance(value, list) and not value)


def non_attachment_props(props):
    return {key: value for key, value in props.items() if key != "attachments"}


def visible(post):
    """Only stable visible fields; Mattermost removes integration secrets on GET."""
    props = post.get("props", {})
    if not isinstance(props, dict) or not isinstance(props.get("attachments"), list):
        raise CleanupError("card_shape_mismatch")
    attachments = []
    for item in props["attachments"]:
        if not isinstance(item, dict):
            raise CleanupError("card_shape_mismatch")
        part = {key: item.get(key) for key in ("title", "text", "footer", "color", "fields")}
        actions = item.get("actions", [])
        if not isinstance(actions, list) or any(not isinstance(action, dict) for action in actions):
            raise CleanupError("card_shape_mismatch")
        part["actions"] = [{key: action.get(key) for key in ("id", "name", "style")} for action in actions]
        attachments.append(part)
    return {"message": post.get("message", ""), "attachments": attachments}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class RestClient:
    def __init__(self, base, token, bot_id, channel_id):
        parsed = urllib.parse.urlsplit(base)
        if (parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or
                parsed.password or parsed.query or parsed.fragment or not token or
                any(ch in token for ch in "\r\n") or not ID.fullmatch(bot_id) or not ID.fullmatch(channel_id)):
            raise CleanupError("rest_configuration_invalid")
        self.base, self.token, self.bot_id, self.channel_id = base.rstrip("/"), token, bot_id, channel_id
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()))

    def request(self, method, path, body=None, absent=False):
        if method not in ("GET", "POST", "PUT"):
            raise CleanupError("unsupported_http_method")
        data = None if body is None else canonical(body).encode()
        if data is not None and len(data) > MAX_BYTES:
            raise CleanupError("request_too_large")
        req = urllib.request.Request(self.base + "/api/v4" + path, data=data, method=method,
              headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
        deadline = time.monotonic() + 5
        try:
            with self.opener.open(req, timeout=5) as response:
                if response.status != (201 if method == "POST" else 200):
                    raise CleanupError("http_status")
                # read() can wait indefinitely on a peer trickling bytes. read1
                # plus a shrinking socket timeout bounds the whole response.
                raw = bytearray()
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise CleanupError("response_deadline", True)
                    sock = getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None)
                    if sock is not None:
                        sock.settimeout(remaining)
                    chunk = response.read1(min(65536, MAX_BYTES + 1 - len(raw)))
                    if not chunk:
                        break
                    raw.extend(chunk)
                    if len(raw) > MAX_BYTES:
                        raise CleanupError("response_too_large")
        except urllib.error.HTTPError as exc:
            if exc.code == 404 and absent:
                return None
            raise CleanupError("http_" + str(exc.code), exc.code == 429 or 500 <= exc.code <= 599) from None
        except (TimeoutError, OSError, urllib.error.URLError):
            raise CleanupError("transport_unavailable", True) from None
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeError):
            raise CleanupError("invalid_response") from None
        if not isinstance(value, dict):
            raise CleanupError("invalid_response")
        return value

    def verify_identity(self):
        user = self.request("GET", "/users/me")
        if (user.get("id") != self.bot_id or user.get("is_bot") is not True or
                user.get("delete_at") != 0 or "system_admin" in str(user.get("roles", "")).split()):
            raise CleanupError("bot_identity_mismatch")


class Ledger:
    def __init__(self, path):
        self.path = Path(path)

    def connect(self):
        if not self.path.is_absolute():
            raise CleanupError("ledger_path_invalid")
        for parent in (self.path.parent, *self.path.parent.parents):
            if not stat.S_ISDIR(parent.lstat().st_mode):
                raise CleanupError("ledger_parent_invalid")
        parent = self.path.parent.lstat()
        if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700:
            raise CleanupError("ledger_parent_permissions")
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            os.close(fd)
        except FileExistsError:
            pass
        before = self.path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.geteuid() or
                stat.S_IMODE(before.st_mode) != 0o600 or before.st_size > MAX_DB_BYTES):
            raise CleanupError("ledger_file_permissions")
        conn = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=2)
        try:
            after = self.path.lstat()
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise CleanupError("ledger_identity_changed")
            conn.execute("PRAGMA trusted_schema=OFF")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA journal_mode=DELETE")
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            if version == 0 and conn.execute("SELECT count(*) FROM sqlite_master").fetchone()[0] == 0:
                conn.executescript("""
                  CREATE TABLE cards (card_key TEXT PRIMARY KEY, kind TEXT NOT NULL, request_id TEXT NOT NULL,
                    binding TEXT NOT NULL, expires_at INTEGER NOT NULL, post_id TEXT NOT NULL DEFAULT '',
                    visible_sha256 TEXT NOT NULL DEFAULT '', state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt INTEGER NOT NULL DEFAULT 0, reason TEXT NOT NULL DEFAULT '');
                  CREATE TABLE audit (seq INTEGER PRIMARY KEY, card_key TEXT NOT NULL, event TEXT NOT NULL,
                    at INTEGER NOT NULL, detail TEXT NOT NULL);
                  PRAGMA user_version=1;
                """)
            elif version != 1:
                raise CleanupError("ledger_schema_mismatch")
            conn.row_factory = sqlite3.Row
            return conn
        except Exception:
            conn.close()
            raise

    @staticmethod
    def audit(conn, key, event, detail=""):
        conn.execute("INSERT INTO audit(card_key,event,at,detail) VALUES(?,?,?,?)", (key, event, int(time.time()), detail))

    def row(self, key):
        conn = self.connect()
        try:
            row = conn.execute("SELECT * FROM cards WHERE card_key=?", (key,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def transition(self, key, old, new, reason="", next_attempt=0):
        conn = self.connect()
        try:
            with conn:
                placeholders = ",".join("?" for _ in old)
                count = conn.execute("UPDATE cards SET state=?,reason=?,next_attempt=? WHERE card_key=? AND state IN (" +
                       placeholders + ")", (new, reason, next_attempt, key, *old)).rowcount
                if count:
                    self.audit(conn, key, new, reason)
                return count == 1
        finally:
            conn.close()


class CardCleanup:
    def __init__(self, client, ledger):
        self.client, self.ledger = client, ledger

    @staticmethod
    def key(kind, rid):
        if kind not in KINDS or not isinstance(rid, str) or not RID.fullmatch(rid):
            raise CleanupError("request_identity_invalid")
        return kind + ":" + rid

    def post(self, kind, rid, rec, payload, expires_at):
        key = self.key(kind, rid)
        nonce = rec.get("nonce")
        if not isinstance(nonce, str) or not re.fullmatch(r"[a-f0-9]{32,64}", nonce):
            raise CleanupError("nonce_invalid")
        if type(expires_at) is not int or not time.time() < expires_at <= time.time() + 901:
            raise CleanupError("expiry_invalid")
        binding = {"version": 1, "kind": kind, "request_id": rid,
                   "nonce_sha256": hashlib.sha256(nonce.encode()).hexdigest(),
                   "proposal_digest": rec.get("proposal_digest", ""), "expires_at": expires_at,
                   "bot_id": self.client.bot_id, "channel_id": self.client.channel_id}
        self.client.verify_identity()
        conn = self.ledger.connect()
        try:
            with conn:
                conn.execute("INSERT INTO cards(card_key,kind,request_id,binding,expires_at,state) VALUES(?,?,?,?,?,'posting')",
                             (key, kind, rid, canonical(binding), expires_at))
                self.ledger.audit(conn, key, "posting")
        finally:
            conn.close()
        post = self.client.request("POST", "/posts", {"channel_id": self.client.channel_id, "message": "",
             "props": {"attachments": payload["attachments"], "capstone_approval": binding}})
        if (not ID.fullmatch(str(post.get("id", ""))) or post.get("user_id") != self.client.bot_id or
                post.get("channel_id") != self.client.channel_id or post.get("root_id", "") or
                post.get("delete_at") != 0 or post.get("props", {}).get("capstone_approval") != binding):
            raise CleanupError("created_card_mismatch")
        projected = visible(post)
        if not any(part["actions"] for part in projected["attachments"]):
            raise CleanupError("created_card_has_no_actions")
        conn = self.ledger.connect()
        try:
            with conn:
                count = conn.execute("UPDATE cards SET post_id=?,visible_sha256=?,state='bound' WHERE card_key=? AND state='posting'",
                            (post["id"], digest(projected), key)).rowcount
                if count != 1:
                    raise CleanupError("card_binding_conflict")
                self.ledger.audit(conn, key, "bound")
        finally:
            conn.close()
        return True, "ok"

    def pending(self, kind, rid):
        return self.ledger.transition(self.key(kind, rid), ("bound",), "pending")

    def protect(self, kind, rid, body=None, allow_absent=False):
        key = self.key(kind, rid)
        row = self.ledger.row(key)
        if row is None:  # Older webhook card: never a cleanup target.
            return True
        if body is not None:
            binding = json.loads(row["binding"])
            if (not isinstance(body, dict) or body.get("post_id") != row["post_id"] or
                    body.get("channel_id") != binding["channel_id"]):
                return False
        if row["state"] == "protected":
            return True
        if allow_absent and row["state"] == "cleaned":
            return True  # Later automatic expiry reporting must remain possible.
        return self.ledger.transition(key, ("bound", "pending", "queued", "retry"), "protected")

    def expire(self, kind, rid, rec):
        # The caller passes the record BEFORE changing its status to expired.
        if (rec.get("status") != "pending" or rec.get("by") or rec.get("decision") or
                rec.get("consumed_decision") or rec.get("result_posted") or rec.get("result_status") or
                rec.get("result_digest") or rec.get("result_request_digest") or rec.get("consumed_ts")):
            return False
        return self.ledger.transition(self.key(kind, rid), ("pending",), "queued")

    def _verify(self, row):
        if (not ID.fullmatch(row["post_id"]) or
                self.key(row["kind"], row["request_id"]) != row["card_key"]):
            raise CleanupError("stored_identity_invalid")
        binding = json.loads(row["binding"])
        if (binding.get("bot_id") != self.client.bot_id or binding.get("channel_id") != self.client.channel_id or
                binding.get("kind") != row["kind"] or binding.get("request_id") != row["request_id"] or
                binding.get("expires_at") != row["expires_at"]):
            raise CleanupError("stored_binding_mismatch")
        post = self.client.request("GET", "/posts/" + row["post_id"], absent=True)
        if post is None or (type(post.get("delete_at")) is int and post["delete_at"] > 0):
            return None, "already_absent"
        if (post.get("id") != row["post_id"] or post.get("user_id") != self.client.bot_id or
                post.get("channel_id") != self.client.channel_id or post.get("root_id", "") or
                post.get("delete_at") != 0 or post.get("props", {}).get("capstone_approval") != binding):
            raise CleanupError("live_card_binding_mismatch")
        if post.get("message") == EXPIRED_MESSAGE and attachments_empty(post["props"]):
            return post, "already_cleaned"  # A prior PUT may have succeeded before its response was lost.
        if digest(visible(post)) != row["visible_sha256"]:
            raise CleanupError("live_card_binding_mismatch")
        return post, "pending"

    def _clean(self, row, post):
        # Mattermost DELETE also deletes replies. Its partial-update endpoint
        # (HTTP PUT, despite the /patch suffix) changes only this root post.
        # Preserve every unrelated prop; never enumerate, modify or delete replies.
        props = dict(post["props"])
        props["attachments"] = []
        updated = self.client.request("PUT", "/posts/" + row["post_id"] + "/patch",
                                      {"message": EXPIRED_MESSAGE, "props": props})
        returned_props = updated.get("props")
        if (updated.get("id") != row["post_id"] or updated.get("user_id") != self.client.bot_id or
                updated.get("channel_id") != self.client.channel_id or updated.get("delete_at") != 0 or
                updated.get("root_id", "") or updated.get("message") != EXPIRED_MESSAGE or
                not attachments_empty(returned_props) or
                non_attachment_props(returned_props) != non_attachment_props(props)):
            raise CleanupError("cleanup_readback_mismatch")

    def cleanup_once(self, now=None, limit=8):
        now = int(time.time() if now is None else now)
        if type(limit) is not int or not 1 <= limit <= 8:
            raise CleanupError("invalid_cleanup_limit")
        conn = self.ledger.connect()
        try:
            with conn:
                abandoned = conn.execute("SELECT card_key FROM cards WHERE state='cleaning' "
                    "AND attempts>=? AND next_attempt<=? LIMIT ?", (MAX_ATTEMPTS, now, limit)).fetchall()
                for record in abandoned:
                    conn.execute("UPDATE cards SET state='protected',reason='restart_retry_limit' WHERE card_key=? AND state='cleaning'",
                                 (record["card_key"],))
                    self.ledger.audit(conn, record["card_key"], "protected", "restart_retry_limit")
                # A durable pending certificate survives broker restart only as
                # a cleanup candidate. It never recreates the approval record.
                rows = conn.execute("SELECT * FROM cards WHERE state IN ('pending','queued','retry','cleaning') "
                        "AND expires_at+?<=? AND next_attempt<=? AND attempts<? ORDER BY expires_at LIMIT ?",
                        (GRACE_SECONDS, now, now, MAX_ATTEMPTS, limit)).fetchall()
                chosen = []
                for record in rows:
                    row = dict(record)
                    count = conn.execute("UPDATE cards SET state='cleaning',attempts=attempts+1,next_attempt=? "
                         "WHERE card_key=? AND state=? AND attempts=?", (now + 300, row["card_key"], row["state"], row["attempts"])).rowcount
                    if count:
                        self.ledger.audit(conn, row["card_key"], "cleanup_check")
                        row["attempts"] += 1
                        chosen.append(row)
        finally:
            conn.close()
        outcomes = ["restart_retry_limit"] * len(abandoned)
        identity_error = None
        if chosen:
            try:
                self.client.verify_identity()
            except CleanupError as exc:
                identity_error = exc
            except Exception:
                identity_error = CleanupError("identity_verification_failed")
        for row in chosen:
            try:
                if identity_error is not None:
                    raise identity_error
                post, status = self._verify(row)
                if status == "pending":
                    self._clean(row, post)
                    status = "cleaned"
                self.ledger.transition(row["card_key"], ("cleaning",), "cleaned", status)
                outcomes.append(status)
            except CleanupError as exc:
                retry = exc.retryable and row["attempts"] < MAX_ATTEMPTS
                self.ledger.transition(row["card_key"], ("cleaning",), "retry" if retry else "protected",
                    exc.code, now + min(3600, 60 * 2 ** row["attempts"]) if retry else 0)
                outcomes.append(exc.code)
            except Exception:
                self.ledger.transition(row["card_key"], ("cleaning",), "protected", "verification_failed")
                outcomes.append("verification_failed")
        return outcomes


def configured(env=None):
    env = os.environ if env is None else env
    if env.get("SOC_APPROVAL_CARD_CLEANUP", "") != "1":
        return None
    client = RestClient(env.get("SOC_CARD_MM_URL", ""), env.get("SOC_CARD_MM_TOKEN", ""),
                        env.get("SOC_CARD_MM_BOT_ID", ""), env.get("SOC_CARD_MM_CHANNEL_ID", ""))
    return CardCleanup(client, Ledger(env.get("SOC_CARD_CLEANUP_DB", "/var/lib/socbot/approval-cards.sqlite3")))
