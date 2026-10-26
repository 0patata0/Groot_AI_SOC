"""Native gateway startup hook; no message is needed to start synchronization.

Install next to HOOK.yaml under $HERMES_HOME/hooks/groot-mattermost-channel-sync.
The core is installed under $HERMES_HOME/plugins/groot-mattermost-context.
Native hooks have no shutdown event: gateway event-loop shutdown cancels the
retained task, and its async session context closes the HTTP client.
"""

from __future__ import annotations

import asyncio
import importlib.util
import logging
import os
from pathlib import Path
import re
import types
from urllib.parse import urlsplit

LOGGER = logging.getLogger(__name__)
_TASK = None
_ID = re.compile(r"[a-z0-9]{26}\Z")


def _settings():
    keys = ("CAPSTONE_MM_TEAM_ID", "CAPSTONE_MM_BOT_ID", "MATTERMOST_HOME_CHANNEL",
            "MATTERMOST_URL", "MATTERMOST_TOKEN", "HERMES_HOME", "CAPSTONE_MM_MANAGED_CHANNELS")
    values = {key: os.environ.get(key, "") for key in keys}
    if not values["CAPSTONE_MM_TEAM_ID"]:
        return None
    if not all(_ID.fullmatch(values[key]) for key in keys[:3]):
        raise ValueError("configuration_invalid")
    base = urlsplit(values["MATTERMOST_URL"])
    if (base.scheme not in ("http", "https") or not base.hostname or base.username or
            base.password or base.query or base.fragment or not values["MATTERMOST_TOKEN"] or
            not Path(values["HERMES_HOME"]).is_absolute()):
        raise ValueError("configuration_invalid")
    if any(char in values["MATTERMOST_TOKEN"] for char in ("\r", "\n")):
        raise ValueError("configuration_invalid")
    return values


def _load_core(home):
    path = Path(home) / "plugins" / "groot-mattermost-context" / "channel_sync.py"
    if not path.is_file() or path.is_symlink():
        raise ValueError("core_unavailable")
    spec = importlib.util.spec_from_file_location("capstone_mattermost_channel_sync_hook_core", path)
    if spec is None or spec.loader is None:
        raise ValueError("core_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not callable(getattr(module, "sync_once", None)):
        raise ValueError("core_unavailable")
    return module


async def _run(settings, core):
    import aiohttp

    # Only the configured native Mattermost URL and pinned bot token are used.
    # No proxy/environment redirect or cookie persistence is introduced.
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=core.HTTP_SECONDS),
        connector=aiohttp.TCPConnector(limit=2), cookie_jar=aiohttp.DummyCookieJar(),
        trust_env=False,
    ) as session:
        adapter = types.SimpleNamespace(
            _session=session, _base_url=settings["MATTERMOST_URL"].rstrip("/"),
            _token=settings["MATTERMOST_TOKEN"], _bot_user_id=settings["CAPSTONE_MM_BOT_ID"],
            _auth_header=lambda: {"Authorization": "Bearer " + settings["MATTERMOST_TOKEN"]},
            _capstone_home=settings['HERMES_HOME'],
            _capstone_managed_channels=settings.get('CAPSTONE_MM_MANAGED_CHANNELS', '').split(','),
        )
        while True:
            result = await core.sync_once(adapter, settings)
            # The core returns fixed codes and counters only, never API text.
            if result["status"] != "ok" or result["joined"]:
                LOGGER.info("Mattermost public channel sync status=%s reason=%s joined=%d failed=%d deferred=%d",
                            result["status"], result["reason"], result["joined"], result["failed"], result["deferred"])
            await asyncio.sleep(core.POLL_SECONDS)


def _finished(task):
    if task.cancelled():
        return
    try:
        error = task.exception()
    except asyncio.CancelledError:
        return
    if error is not None:
        # Exception strings may contain URLs or credentials; never log them.
        LOGGER.warning("Mattermost public channel sync stopped: runtime_unavailable")


async def handle(event_type, context):
    global _TASK
    if event_type != "gateway:startup" or not isinstance(context, dict):
        return
    if "mattermost" not in context.get("platforms", []):
        return
    if _TASK is not None and not _TASK.done():
        return
    try:
        settings = _settings()
        if settings is None:
            return
        core = _load_core(settings["HERMES_HOME"])
        core.install_gate(settings['HERMES_HOME'])
    except Exception:
        LOGGER.warning("Mattermost public channel sync disabled: configuration_or_core_unavailable")
        return
    _TASK = asyncio.create_task(_run(settings, core), name="groot-mattermost-channel-sync")
    _TASK.add_done_callback(_finished)
