import asyncio
import importlib.util
import json
from pathlib import Path
import types
import unittest
from unittest.mock import AsyncMock, patch


SPEC = importlib.util.spec_from_file_location("capstone_channel_sync", Path(__file__).with_name("channel_sync.py"))
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)
TEAM, HOME, BOT, NEW = (letter * 26 for letter in "thbn")
ENV = {"CAPSTONE_MM_TEAM_ID": TEAM, "MATTERMOST_HOME_CHANNEL": HOME}


def channel(channel_id=NEW, **changes):
    return {"id": channel_id, "team_id": TEAM, "type": "O", "delete_at": 0, **changes}


class Response:
    def __init__(self, value, status=200, content_length=None, chunks=None):
        self.status = status
        self.content_length = content_length
        self.raw = json.dumps(value).encode()
        self.chunks = chunks
        self.content = self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def iter_chunked(self, size):
        if self.chunks is not None:
            for chunk in self.chunks:
                yield chunk
        else:
            for start in range(0, len(self.raw), size):
                yield self.raw[start:start + size]


class Session:
    def __init__(self, *, publics=None, members=None, fresh=None, me=None, home=None):
        self.calls = []
        self.publics = [channel(HOME), channel()] if publics is None else publics
        self.members = [{"channel_id": HOME, "user_id": BOT}] if members is None else members
        self.fresh = fresh
        self.me = {"id": BOT, "is_bot": True, "delete_at": 0, "roles": "system_user"} if me is None else me
        self.home = channel(HOME) if home is None else home
        self.overrides = {}

    def request(self, method, url, **kwargs):
        path = url.split("/api/v4", 1)[1]
        self.calls.append((method, path, kwargs))
        override = self.overrides.get((method, path))
        if override is not None:
            return override
        if path == "/users/me":
            return Response(self.me)
        if path == "/channels/" + HOME:
            return Response(self.home)
        if path.endswith("/channels/members"):
            return Response(self.members)
        if path == "/teams/" + TEAM + "/channels":
            page = kwargs["params"]["page"]
            size = kwargs["params"]["per_page"]
            return Response(self.publics[page * size:(page + 1) * size])
        if method == "GET" and path.startswith("/channels/"):
            cid = path.rsplit("/", 1)[1]
            return Response(self.fresh if self.fresh is not None else channel(cid))
        if method == "POST" and path.endswith("/members"):
            return Response({"channel_id": path.split("/")[2], "user_id": BOT}, 201)
        raise AssertionError("unexpected fake request")

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)


def adapter(session=None, **changes):
    return types.SimpleNamespace(_session=session or Session(), _base_url="https://chat.example.invalid",
                                 _bot_user_id=BOT, _auth_header=lambda: {"Authorization": "Bearer synthetic"}, **changes)


class SyncTest(unittest.IsolatedAsyncioTestCase):
    async def test_only_new_public_self_membership_is_written(self):
        a = adapter()
        result = await m.sync_once(a, ENV)
        self.assertEqual((result["status"], result["joined"], result["already_joined"]), ("ok", 1, 1))
        writes = [(method, path, kw) for method, path, kw in a._session.calls if method == "POST"]
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0][1], "/channels/" + NEW + "/members")
        self.assertEqual(writes[0][2]["json"], {"user_id": BOT})
        self.assertTrue(all(call[2]["timeout"] == 5 and call[2]["allow_redirects"] is False for call in a._session.calls))
        self.assertFalse(any("/posts" in call[1] or "/roles" in call[1] for call in a._session.calls))
        self.assertFalse(any(identifier in json.dumps(result) for identifier in (TEAM, HOME, BOT, NEW)))

    async def test_missing_team_does_not_make_requests(self):
        a = adapter()
        result = await m.sync_once(a, {})
        self.assertEqual(result["status"], "disabled")
        self.assertEqual(a._session.calls, [])

    async def test_invalid_settings_fail_before_request(self):
        for env in ({**ENV, "CAPSTONE_MM_TEAM_ID": "../other"}, {"CAPSTONE_MM_TEAM_ID": TEAM}):
            a = adapter()
            self.assertEqual((await m.sync_once(a, env))["reason"], "configuration_invalid")
            self.assertEqual(a._session.calls, [])

    async def test_bot_identity_and_admin_token_are_refused(self):
        for changes in ({"id": "x" * 26}, {"is_bot": False}, {"roles": "system_user system_admin"}, {"delete_at": 1}):
            s = Session()
            s.me.update(changes)
            self.assertEqual((await m.sync_once(adapter(s), ENV))["reason"], "bot_identity_mismatch")
            self.assertFalse(any(c[0] == "POST" for c in s.calls))

    async def test_wrong_home_team_and_missing_home_membership_refuse(self):
        for s, reason in ((Session(home=channel(HOME, team_id="x" * 26)), "home_team_mismatch"),
                          (Session(members=[]), "home_membership_missing")):
            self.assertEqual((await m.sync_once(adapter(s), ENV))["reason"], reason)
            self.assertFalse(any(c[0] == "POST" for c in s.calls))

    async def test_foreign_membership_identity_refused(self):
        s = Session(members=[{"channel_id": HOME, "user_id": "x" * 26}])
        self.assertEqual((await m.sync_once(adapter(s), ENV))["reason"], "membership_identity_mismatch")
        self.assertFalse(any(c[0] == "POST" for c in s.calls))

    async def test_private_foreign_deleted_and_malformed_channels_skipped(self):
        values = [channel("p" * 26, type="P"), channel("x" * 26, team_id="x" * 26),
                  channel("d" * 26, delete_at=5), channel("bad"), None]
        s = Session(publics=[channel(HOME), *values])
        result = await m.sync_once(adapter(s), ENV)
        self.assertEqual((result["public_channels"], result["joined"]), (1, 0))
        self.assertFalse(any(c[0] == "POST" for c in s.calls))

    async def test_channel_privacy_change_before_write_is_skipped(self):
        s = Session(fresh=channel(type="P"))
        result = await m.sync_once(adapter(s), ENV)
        self.assertEqual((result["skipped"], result["joined"]), (1, 0))
        self.assertFalse(any(c[0] == "POST" for c in s.calls))

    async def test_existing_members_not_rejoined(self):
        s = Session(members=[{"channel_id": HOME, "user_id": BOT}, {"channel_id": NEW, "user_id": BOT}])
        result = await m.sync_once(adapter(s), ENV)
        self.assertEqual((result["joined"], result["already_joined"]), (0, 2))
        self.assertFalse(any(c[0] == "POST" for c in s.calls))

    async def test_permission_failure_is_safe_code_without_role_change(self):
        s = Session()
        s.overrides[("POST", "/channels/" + NEW + "/members")] = Response({"secret": "do-not-log"}, 403)
        result = await m.sync_once(adapter(s), ENV)
        self.assertEqual((result["status"], result["failed"], result["reason"]), ("partial", 1, "access_denied"))
        self.assertNotIn("do-not-log", json.dumps(result))
        self.assertFalse(any("roles" in c[1] for c in s.calls))

    async def test_redirects_and_invalid_json_are_not_followed(self):
        for response, reason in ((Response({}, 302), "http_unavailable"),
                                  (Response({}, chunks=[b"not JSON"]), "invalid_response")):
            s = Session()
            s.overrides[("GET", "/users/me")] = response
            self.assertEqual((await m.sync_once(adapter(s), ENV))["reason"], reason)
            self.assertEqual(len(s.calls), 1)

    async def test_response_limit_applies_to_length_and_stream(self):
        for response in (Response({}, content_length=33), Response({}, chunks=[b"x" * 17, b"x" * 16])):
            s = Session()
            s.overrides[("GET", "/users/me")] = response
            with patch.object(m, "MAX_BYTES", 32):
                self.assertEqual((await m.sync_once(adapter(s), ENV))["reason"], "response_too_large")

    async def test_page_and_join_limits(self):
        publics = [channel(HOME)] + [channel(str(n).zfill(26)) for n in range(7)]
        s = Session(publics=publics)
        with patch.object(m, "PAGE_SIZE", 2), patch.object(m, "MAX_PAGES", 2):
            self.assertEqual((await m.sync_once(adapter(s), ENV))["reason"], "channel_page_limit")
        self.assertFalse(any(c[0] == "POST" for c in s.calls))
        s = Session(publics=publics)
        with patch.object(m, "MAX_JOIN_ATTEMPTS", 2):
            result = await m.sync_once(adapter(s), ENV)
        self.assertEqual((result["joined"], result["deferred"]), (2, 5))

    async def test_total_timeout_and_cancellation(self):
        async def waiting(*args):
            await asyncio.sleep(100)
        with patch.object(m, "_sync", side_effect=waiting), patch.object(m, "PASS_SECONDS", 0.001):
            self.assertEqual((await m.sync_once(adapter(), ENV))["reason"], "timeout")
        with patch.object(m, "_sync", side_effect=waiting):
            task = asyncio.create_task(m.sync_once(adapter(), ENV))
            await asyncio.sleep(0)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

    async def test_wrong_join_response_does_not_claim_success(self):
        s = Session()
        s.overrides[("POST", "/channels/" + NEW + "/members")] = Response({"channel_id": NEW, "user_id": "x" * 26}, 201)
        result = await m.sync_once(adapter(s), ENV)
        self.assertEqual((result["joined"], result["failed"], result["reason"]), (0, 1, "join_response_mismatch"))


class StartupTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("channel_sync_startup_test", Path(__file__).parent / "startup" / "handler.py")
        self.hook = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.hook)
        self.settings = {**ENV, "CAPSTONE_MM_BOT_ID": BOT, "MATTERMOST_URL": "https://chat.example.invalid",
                         "MATTERMOST_TOKEN": "synthetic-private-token", "HERMES_HOME": "/synthetic/hermes"}

    async def asyncTearDown(self):
        task = self.hook._TASK
        if task is not None and not task.done():
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

    async def test_missing_team_or_platform_starts_no_task(self):
        with patch.dict(self.hook.os.environ, {}, clear=True):
            await self.hook.handle("gateway:startup", {"platforms": ["mattermost"]})
        self.assertIsNone(self.hook._TASK)
        with patch.dict(self.hook.os.environ, self.settings, clear=True):
            await self.hook.handle("gateway:startup", {"platforms": ["telegram"]})
            await self.hook.handle("other:event", {"platforms": ["mattermost"]})
        self.assertIsNone(self.hook._TASK)

    async def test_bot_pin_and_url_validation_prevent_task(self):
        for changes in ({"CAPSTONE_MM_BOT_ID": ""}, {"MATTERMOST_URL": "https://user:pass@example.invalid"},
                        {"MATTERMOST_TOKEN": "private\nvalue"}, {"HERMES_HOME": "relative"}):
            with patch.dict(self.hook.os.environ, {**self.settings, **changes}, clear=True), \
                    self.assertLogs(self.hook.LOGGER, level="WARNING") as logs:
                await self.hook.handle("gateway:startup", {"platforms": ["mattermost"]})
            self.assertIsNone(self.hook._TASK)
            self.assertNotIn("private", " ".join(logs.output))
            self.assertNotIn("user:pass", " ".join(logs.output))

    async def test_nonblocking_start_and_duplicate_start(self):
        started = asyncio.Event()
        async def blocked(*args):
            started.set()
            await asyncio.sleep(100)
        with patch.dict(self.hook.os.environ, self.settings, clear=True), \
                patch.object(self.hook, "_load_core", return_value=m), \
                patch.object(self.hook, "_run", side_effect=blocked):
            await asyncio.wait_for(self.hook.handle("gateway:startup", {"platforms": ["mattermost"]}), 0.1)
            first = self.hook._TASK
            await started.wait()
            await self.hook.handle("gateway:startup", {"platforms": ["mattermost"]})
            self.assertIs(first, self.hook._TASK)

    async def test_client_closed_on_cancel_and_exact_bot_pin_used(self):
        closed = []
        options = []
        called = asyncio.Event()
        class Client:
            def __init__(self, **kwargs):
                options.append(kwargs)
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                closed.append(True)
        async def sync(a, env):
            self.assertEqual(a._bot_user_id, BOT)
            self.assertEqual(a._base_url, self.settings["MATTERMOST_URL"])
            self.assertEqual(a._auth_header(), {"Authorization": "Bearer synthetic-private-token"})
            self.assertEqual(env, self.settings)
            called.set()
            return {"status": "ok", "reason": "", "joined": 0, "failed": 0, "deferred": 0}
        fake = types.SimpleNamespace(ClientSession=Client, ClientTimeout=lambda **kw: kw,
                                     TCPConnector=lambda **kw: kw, DummyCookieJar=lambda: "dummy")
        core = types.SimpleNamespace(HTTP_SECONDS=5, POLL_SECONDS=300, sync_once=sync)
        with patch.dict("sys.modules", {"aiohttp": fake}):
            task = asyncio.create_task(self.hook._run(self.settings, core))
            await called.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertEqual(closed, [True])
        self.assertEqual(options[0]["trust_env"], False)
        self.assertEqual(options[0]["connector"], {"limit": 2})

    async def test_task_error_logged_without_exception_details(self):
        async def failed():
            raise RuntimeError("synthetic-private-token must never be logged")
        task = asyncio.create_task(failed())
        with self.assertRaises(RuntimeError):
            await task
        with self.assertLogs(self.hook.LOGGER, level="WARNING") as logs:
            self.hook._finished(task)
        self.assertIn("runtime_unavailable", " ".join(logs.output))
        self.assertNotIn("synthetic-private-token", " ".join(logs.output))


if __name__ == "__main__":
    unittest.main()
