"""Gateway-owned liveness receipts. No token, message or user data is stored."""
import asyncio
import contextlib
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time


def publish(path, engine, connected, worker):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    value = {'schema': 1, 'engine': engine, 'pid': os.getpid(),
             'process_start_ticks': int(Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19]),
             'checked_at': int(time.time()), 'websocket_connected': bool(connected), 'worker_alive': bool(worker)}
    fd, name = tempfile.mkstemp(prefix='.health-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(value, stream); stream.flush(); os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name): os.unlink(name)


async def ollama_watch(ws, path, worker):
    try:
        while True:
            connected = False
            try:
                pong = await ws.ping()
                await asyncio.wait_for(pong, 10)
                connected = True
            except Exception:
                pass
            publish(path, 'ollama', connected, worker is not None and not worker.done())
            await asyncio.sleep(20)
    finally:
        publish(path, 'ollama', False, worker is not None and not worker.done())


def install_hermes(ctx):
    """Wrap the established native connection hook, preserving its behavior.

    The adapter's authentication acknowledgement is observed, never inferred
    from its optimistic log line. Native aiohttp heartbeat closes dead sockets.
    """
    from gateway.platforms.base import BasePlatformAdapter
    path = Path('/opt/hermes/plugins/platforms/mattermost/adapter.py')
    if hashlib.sha256(path.read_bytes()).hexdigest() != ADAPTER_SHA256:
        raise ValueError('gateway_health_adapter_pin_mismatch')
    original = BasePlatformAdapter._mark_connected
    if getattr(original, '_capstone_health', False): return
    tasks = set()

    async def watch(adapter):
        destination = Path(os.environ['HERMES_HOME']) / 'health/chat.json'
        while not adapter._closing:
            ws = adapter._ws
            connected = (ws is not None and not ws.closed and adapter._capstone_authenticated_ws is ws)
            task = adapter._ws_task
            publish(destination, 'hermes', connected, task is not None and not task.done())
            await asyncio.sleep(20)
        publish(destination, 'hermes', False, False)

    def wrapped(adapter, *args, **kwargs):
        result = original(adapter, *args, **kwargs)
        if type(adapter).__name__ == 'MattermostAdapter' and not getattr(adapter, '_capstone_health_started', False):
            adapter._capstone_health_started = True
            adapter._capstone_authenticated_ws = None
            handler = adapter._handle_ws_event
            async def event(value):
                if (value.get('seq_reply') == 1 and value.get('status') == 'OK') or (value.get('event') == 'hello' and value.get('broadcast',{}).get('user_id') == adapter._bot_user_id):
                    adapter._capstone_authenticated_ws = adapter._ws
                return await handler(value)
            adapter._handle_ws_event = event
            task = asyncio.create_task(watch(adapter), name='capstone-gateway-health')
            tasks.add(task); task.add_done_callback(tasks.discard)
        return result
    wrapped._capstone_health = True
    BasePlatformAdapter._mark_connected = wrapped
    def unload():
        if BasePlatformAdapter._mark_connected is wrapped: BasePlatformAdapter._mark_connected = original
        for task in tasks: task.cancel()
    ctx.on_unload(unload)


ADAPTER_SHA256 = '1bbe71e24cf7fd212f38b13cb421bb5b05c841ea4d70a061d6dcb57253e6c47b'
