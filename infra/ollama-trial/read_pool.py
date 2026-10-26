"""Worker-local read transports; each session is owned and closed by one task.

No answers, agent memory, tool wrappers, approval state, or credentials are
shared between requests. Mixed read/write MCP servers are never retained.
"""
import asyncio
import hashlib
import json
from types import SimpleNamespace

from policy import READ_TOOLS, PARITY_TOOLS, alias, require

IDLE_SECONDS = 300
CONNECT_SECONDS = 30


def eligible(servers, chosen):
    return bool(servers and chosen and all(
        server in READ_TOOLS and READ_TOOLS[server] == PARITY_TOOLS[server]
        for server in servers) and set(chosen) <= {
            alias(server, name) for server in servers for name in READ_TOOLS[server]})


class _Transport:
    def __init__(self, server, profile, factory, idle_seconds):
        self.server, self.profile, self.factory = server, profile, factory
        self.idle_seconds = idle_seconds
        self.queue = asyncio.Queue()
        self.client = self.connector = None
        self.retiring = False
        self.reconnections = 0
        self.task = asyncio.create_task(self._serve(), name='mcp-read-' + server)

    async def _disconnect(self):
        client, self.client, self.connector = self.client, None, None
        if client is not None:
            await client.close_all_sessions()

    async def _connect(self):
        self.client = self.factory(config={'mcpServers': {self.server: self.profile}},
                                   code_mode=False, sandbox=False,
                                   sampling_callback=None, elicitation_callback=None)
        # Register the session before initialize, so partial startup is closed.
        async with asyncio.timeout(CONNECT_SECONDS):
            session = await self.client.create_session(self.server, auto_initialize=False)
            self.connector = session.connector
            await session.initialize()

    async def _serve(self):
        pending = None
        try:
            while True:
                try:
                    pending = await asyncio.wait_for(self.queue.get(), self.idle_seconds)
                except asyncio.TimeoutError:
                    break
                if pending is None:
                    break
                operation, args, kwargs, future = pending
                if future.cancelled():
                    continue
                try:
                    # Only discovery may reconnect/retry automatically. A tool
                    # call, including a read, is never silently replayed here.
                    for attempt in range(2 if operation == 'list_tools' else 1):
                        try:
                            if self.connector is not None and not self.connector.is_connected:
                                await self._disconnect()
                                if operation != 'list_tools':
                                    raise ConnectionError('read_transport_lost_before_call')
                                self.reconnections += 1
                            if self.connector is None:
                                await self._connect()
                            seconds = kwargs.get('read_timeout_seconds')
                            timeout = seconds.total_seconds() if seconds is not None else CONNECT_SECONDS
                            async with asyncio.timeout(timeout):
                                result = await getattr(self.connector, operation)(*args, **kwargs)
                            break
                        except Exception:
                            await self._disconnect()
                            if operation != 'list_tools' or attempt:
                                raise
                            self.reconnections += 1
                    if not future.done():
                        future.set_result(result)
                except Exception as exc:
                    if not future.done():
                        # Do not expose the suspended owner frame through a
                        # caller's exception/traceback cleanup.
                        future.set_exception(exc.with_traceback(None))
                except asyncio.CancelledError:
                    if not future.done():
                        future.cancel()
                    raise
                finally:
                    pending = None
        except asyncio.CancelledError:
            if pending is not None and not pending[-1].done():
                pending[-1].cancel()
            raise
        finally:
            self.retiring = True
            await self._disconnect()
            while not self.queue.empty():
                item = self.queue.get_nowait()
                if item is not None and not item[-1].done():
                    item[-1].set_exception(ConnectionError('read_transport_closed'))

    async def request(self, operation, *args, **kwargs):
        require(operation in ('list_tools', 'call_tool'), 'pool_operation')
        if operation == 'call_tool':
            require(args and args[0] in READ_TOOLS[self.server], 'pool_read_tool_only')
        require(not self.retiring and not self.task.done(), 'read_transport_closed')
        future = asyncio.get_running_loop().create_future()
        self.queue.put_nowait((operation, args, kwargs, future))
        try:
            return await future
        except asyncio.CancelledError:
            # A timed-out caller cannot leave an in-flight operation attached
            # to a connection that a subsequent request might borrow.
            self.retiring = True
            self.task.cancel()
            raise

    async def stop(self):
        self.retiring = True
        if not self.task.done():
            self.queue.put_nowait(None)
        try:
            await asyncio.wait_for(asyncio.shield(self.task), 10)
        except asyncio.TimeoutError:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
        except asyncio.CancelledError:
            if not self.task.cancelled():
                raise


class _Connector:
    def __init__(self, lease, transport):
        self.lease, self.transport = lease, transport

    async def list_tools(self):
        require(not self.lease.closed, 'read_lease_closed')
        return await self.transport.request('list_tools')

    async def call_tool(self, name, arguments, **kwargs):
        require(not self.lease.closed, 'read_lease_closed')
        return await self.transport.request('call_tool', name, arguments, **kwargs)


class _Lease:
    def __init__(self, pool, transports, created):
        self.pool, self.transports, self.closed = pool, transports, False
        self.created = created
        self.before = {s: t.reconnections for s, t in transports.items()}
        self.sessions = {s: SimpleNamespace(connector=_Connector(self, t)) for s, t in transports.items()}

    def get_all_active_sessions(self):
        require(not self.closed, 'read_lease_closed')
        return self.sessions.copy()

    def metrics(self):
        return {'enabled': True, 'created': sorted(self.created),
                'reused': sorted(set(self.transports) - set(self.created)),
                'discovery_reconnections': sum(t.reconnections - self.before[s] for s, t in self.transports.items()),
                'idle_seconds': self.pool.idle_seconds}

    async def invalidate(self):
        for transport in self.transports.values():
            await transport.stop()

    async def close_all_sessions(self):
        if not self.closed:
            self.closed = True
            self.pool.lock.release()


class ReadConnectionPool:
    def __init__(self, *, idle_seconds=IDLE_SECONDS, client_factory=None):
        require(0 < idle_seconds <= 300, 'pool_idle_bound')
        self.idle_seconds, self.factory = idle_seconds, client_factory
        self.transports, self.signature = {}, None
        self.lock = asyncio.Lock()
        self.loop = None
        self.closed = False

    async def borrow(self, config, servers, chosen):
        require(not self.closed and eligible(servers, chosen), 'pool_read_scope')
        loop = asyncio.get_running_loop()
        require(self.loop is None or self.loop is loop, 'pool_event_loop')
        self.loop = loop
        await self.lock.acquire()
        try:
            require(not self.closed, 'pool_closed')
            signature = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
            if signature != self.signature:
                for transport in self.transports.values():
                    await transport.stop()
                self.transports.clear()
                self.signature = signature
            factory = self.factory
            if factory is None:
                from mcp_use import MCPClient
                factory = MCPClient
            created = []
            for server, profile in servers.items():
                old = self.transports.get(server)
                if old is None or old.retiring or old.task.done():
                    if old is not None:
                        await old.stop()
                    self.transports[server] = _Transport(server, profile, factory, self.idle_seconds)
                    created.append(server)
            return _Lease(self, {s: self.transports[s] for s in servers}, created)
        except BaseException:
            self.lock.release()
            raise

    async def close(self):
        self.closed = True
        async with self.lock:
            for transport in self.transports.values():
                await transport.stop()
            self.transports.clear()
