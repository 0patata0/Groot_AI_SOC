"""Reconcile this bot with shared -agent/-hermes/-ollama channel suffixes.

Uses the existing Mattermost adapter HTTP session and credentials. No chat
messages, invitations of other users, private-channel joins or role edits.
Unclassified public channels are not joined; default channels are response-gated.
Mattermost v11.11.1 API contract: teams/{team}/channels and
users/{user}/teams/{team}/channels/members; POST channels/{channel}/members.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from pathlib import Path
import sys
import time
from typing import Any, Mapping
from urllib.parse import urlsplit

LOGGER = logging.getLogger(__name__)
POLL_SECONDS = 60
PASS_SECONDS = 30
HTTP_SECONDS = 5
MAX_BYTES = 2 * 1024 * 1024
PAGE_SIZE = 50
MAX_PAGES = 20
MAX_MEMBERSHIPS = 2000
MAX_JOIN_ATTEMPTS = 20
_ID = re.compile(r"[a-z0-9]{26}\Z")


def channel_scope(channel):
    """Visible display name is the shared policy, including for new users."""
    text = channel.get('display_name', channel.get('name', ''))
    match = re.search(r'-(agent|ollama|hermes)$', text.strip().lower()) if isinstance(text, str) else None
    return match[1] if match else None


def wanted(channel, engine):
    return engine in ('hermes', 'ollama') and channel_scope(channel) in ('agent', engine)


def install_gate(home):
    """Wrap the native non-DM gate; default channels cannot bypass routing."""
    classes = {vars(m).get('MattermostAdapter') for m in tuple(sys.modules.values()) if m}
    classes = {c for c in classes if isinstance(c, type) and hasattr(c, '_apply_channel_gating')}
    if len(classes) != 1:
        raise ValueError('mattermost_adapter_unavailable')
    cls = classes.pop(); original = cls._apply_channel_gating
    if getattr(original, '_capstone_suffix_gate', False):
        return
    def gated(self, channel_id, text):
        try:
            p = Path(home) / 'health/channel-routing.json'
            if p.is_symlink() or p.stat().st_size > MAX_BYTES:
                return None
            value = json.loads(p.read_bytes())
            if not 0 <= time.time() - value['checked_at'] <= 150 or channel_id not in value['allowed']:
                return None
        except Exception:
            return None
        return original(self, channel_id, text)
    gated._capstone_suffix_gate = True
    cls._apply_channel_gating = gated


class SyncUnavailable(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _id(value: Any) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _configuration(env: Mapping[str, str]) -> tuple[str, str] | None:
    team = env.get("CAPSTONE_MM_TEAM_ID", "")
    if not team:
        return None
    home = env.get("MATTERMOST_HOME_CHANNEL", "")
    if not _id(team) or not _id(home):
        raise SyncUnavailable("configuration_invalid")
    return team, home


async def _request(adapter: Any, method: str, path: str, *, params: dict | None = None,
                   payload: dict | None = None) -> Any:
    call = getattr(adapter, '_capstone_api', None)
    if callable(call):
        if params:
            from urllib.parse import urlencode
            path += '?' + urlencode(params)
        return await call(method, path, payload)
    session = getattr(adapter, "_session", None)
    base = getattr(adapter, "_base_url", None)
    auth = getattr(adapter, "_auth_header", None)
    if session is None or not isinstance(base, str) or not callable(auth):
        raise SyncUnavailable("adapter_unavailable")
    parsed = urlsplit(base)
    if (parsed.scheme not in ("http", "https") or not parsed.hostname or
            parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise SyncUnavailable("adapter_unavailable")
    headers = auth()
    if not isinstance(headers, dict) or not headers.get("Authorization"):
        raise SyncUnavailable("adapter_unavailable")
    kwargs = {"headers": headers, "timeout": HTTP_SECONDS, "allow_redirects": False}
    if params is not None:
        kwargs["params"] = params
    if payload is not None:
        kwargs["json"] = payload
    request = {'GET': session.get, 'POST': session.post}.get(method)
    if method == 'DELETE':
        request = session.delete
    async with request(base.rstrip("/") + "/api/v4" + path, **kwargs) as response:
        if response.status in (401, 403):
            raise SyncUnavailable("access_denied")
        if response.status == 429:
            raise SyncUnavailable("rate_limited")
        if response.status != (201 if method == "POST" else 200):
            raise SyncUnavailable("http_unavailable")
        length = getattr(response, "content_length", None)
        if isinstance(length, int) and length > MAX_BYTES:
            raise SyncUnavailable("response_too_large")
        body = bytearray()
        async for chunk in response.content.iter_chunked(16384):
            if len(body) + len(chunk) > MAX_BYTES:
                raise SyncUnavailable("response_too_large")
            body.extend(chunk)
        try:
            return json.loads(body)
        except (ValueError, UnicodeError):
            raise SyncUnavailable("invalid_response") from None


def _public(channel: Any, team: str) -> bool:
    return (isinstance(channel, dict) and _id(channel.get("id")) and
            channel.get("team_id") == team and channel.get("type") == "O" and
            type(channel.get("delete_at")) is int and channel["delete_at"] == 0)


async def _sync(adapter: Any, team: str, home: str, result: dict) -> None:
    engine = getattr(adapter, '_capstone_engine', 'hermes')
    if engine not in ('hermes', 'ollama'):
        raise SyncUnavailable('engine_identity')
    bot_id = getattr(adapter, "_bot_user_id", None)
    if not _id(bot_id):
        raise SyncUnavailable("adapter_unavailable")
    me = await _request(adapter, "GET", "/users/me")
    if (not isinstance(me, dict) or me.get("id") != bot_id or
            me.get("is_bot") is not True or me.get("delete_at") != 0 or
            "system_admin" in str(me.get("roles", "")).split()):
        raise SyncUnavailable("bot_identity_mismatch")
    home_channel = await _request(adapter, "GET", "/channels/" + home)
    if (not isinstance(home_channel, dict) or home_channel.get("id") != home or
            home_channel.get("team_id") != team or home_channel.get("delete_at") != 0):
        raise SyncUnavailable("home_team_mismatch")
    memberships = await _request(
        adapter, "GET", "/users/" + bot_id + "/teams/" + team + "/channels/members")
    if not isinstance(memberships, list) or len(memberships) > MAX_MEMBERSHIPS:
        raise SyncUnavailable("membership_limit_or_shape")
    joined = set()
    for item in memberships:
        if (not isinstance(item, dict) or item.get("user_id") != bot_id or
                not _id(item.get("channel_id"))):
            raise SyncUnavailable("membership_identity_mismatch")
        joined.add(item["channel_id"])
    public = {}; known = {}
    for page in range(MAX_PAGES):
        channels = await _request(adapter, "GET", "/teams/" + team + "/channels",
                                  params={"page": page, "per_page": PAGE_SIZE})
        if not isinstance(channels, list) or len(channels) > PAGE_SIZE:
            raise SyncUnavailable("channel_page_invalid")
        for channel in channels:
            if _public(channel, team):
                known[channel['id']] = channel
                if wanted(channel, engine):
                    public[channel["id"]] = channel
        if len(channels) < PAGE_SIZE:
            break
    else:
        raise SyncUnavailable("channel_page_limit")
    result["public_channels"] = len(public)
    callback = getattr(adapter, '_capstone_routes', None)
    if callable(callback):
        callback(set(public))
    # Publish the response allowlist before membership changes. Even mandatory
    # default-channel membership cannot cause replies outside the suffix policy.
    if engine == 'hermes' and getattr(adapter, '_capstone_home', None):
        excluded = set(getattr(adapter, '_capstone_managed_channels', ()))
        p = Path(adapter._capstone_home) / 'health/channel-routing.json'
        p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temp = p.with_name('.channel-routing-new')
        with temp.open('w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump({'checked_at': time.time(), 'allowed': sorted(set(public) - excluded)}, stream)
        os.replace(temp, p)
    leaving = sorted((joined & set(known)) - set(public))
    for cid in leaving[:MAX_JOIN_ATTEMPTS]:
        if known[cid].get('name') == 'town-square':
            continue  # Mattermost may require membership; the response gate denies it.
        fresh = await _request(adapter, 'GET', '/channels/' + cid)
        if not _public(fresh, team) or wanted(fresh, engine):
            continue
        await _request(adapter, 'DELETE', '/channels/' + cid + '/members/' + bot_id)
        result['left'] += 1
    pending = sorted(set(public) - joined)
    result["already_joined"] = len(set(public) & joined)
    result["deferred"] = max(0, len(pending) - MAX_JOIN_ATTEMPTS)
    for channel_id in pending[:MAX_JOIN_ATTEMPTS]:
        try:
            # Re-read immediately before a write; a channel may have been
            # archived, moved or made private after the public list was read.
            channel = await _request(adapter, "GET", "/channels/" + channel_id)
            if not _public(channel, team) or not wanted(channel, engine) or channel.get("id") != channel_id:
                result["skipped"] += 1
                continue
            member = await _request(adapter, "POST", "/channels/" + channel_id + "/members",
                                    payload={"user_id": bot_id})
            if (not isinstance(member, dict) or member.get("channel_id") != channel_id or
                    member.get("user_id") != bot_id):
                raise SyncUnavailable("join_response_mismatch")
            result["joined"] += 1
        except SyncUnavailable as error:
            result["failed"] += 1
            result["reason"] = error.code
            if error.code == "rate_limited":
                break
    if result["failed"]:
        result["status"] = "partial"


async def sync_once(adapter: Any, env: Mapping[str, str] | None = None) -> dict:
    """Bounded pass; return only fixed codes/counts, never API bodies or IDs."""
    result = {"status": "ok", "reason": "", "joined": 0, "failed": 0,
              "skipped": 0, "deferred": 0, "already_joined": 0, "public_channels": 0, 'left': 0}
    try:
        configuration = _configuration(os.environ if env is None else env)
        if configuration is None:
            result["status"] = "disabled"
            return result
        await asyncio.wait_for(_sync(adapter, *configuration, result), timeout=PASS_SECONDS)
    except SyncUnavailable as error:
        result.update(status="unavailable", reason=error.code)
    except asyncio.TimeoutError:
        result.update(status="unavailable", reason="timeout")
    except Exception:
        result.update(status="unavailable", reason="lookup_failed")
    return result
