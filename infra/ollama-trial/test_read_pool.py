import asyncio
from datetime import timedelta
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from read_pool import ReadConnectionPool, eligible

A = 'mcp__rule_a__get_rule_change_target'
B = 'mcp__rule_b__get_rule_change_target'
CONFIG = {'model': 'fixture', 'access_mode': 'hermes-parity',
          'mcpServers': {'rule-a': {'args':['a']}, 'rule-b': {'args':['b']}}}


class Factory:
    def __init__(self):
        self.clients, self.reads, self.fail_lists = [], 0, 0
        self.fail_call, self.block, self.partial_init = False, False, False
        self.started = asyncio.Event()

    def __call__(self, **kw):
        parent = self
        class Client:
            def __init__(self):
                self.closed = False
                self.owner = None
                self.list_count = 0
                self.server = next(iter(kw['config']['mcpServers']))
                self.connector = self

            @property
            def is_connected(self):
                return not self.closed

            async def create_session(self, name, auto_initialize):
                assert not auto_initialize
                return self

            async def initialize(self):
                self.owner = asyncio.current_task()
                if parent.partial_init:
                    raise ConnectionError('partial startup')

            async def list_tools(self):
                assert self.owner is asyncio.current_task()
                self.list_count += 1
                if parent.fail_lists:
                    parent.fail_lists -= 1
                    raise ConnectionError('stale transport')
                return ['schema-v' + str(self.list_count)]

            async def call_tool(self, name, args, **kwargs):
                assert self.owner is asyncio.current_task()
                parent.reads += 1
                parent.started.set()
                if parent.fail_call:
                    raise ConnectionError('read interrupted')
                if parent.block:
                    await asyncio.Event().wait()
                return {'fresh_value': parent.reads, 'arguments': args}

            async def close_all_sessions(self):
                assert self.owner is asyncio.current_task()
                self.closed = True
        client = Client()
        self.clients.append(client)
        return client


class Pool(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.factory = Factory()
        self.pool = ReadConnectionPool(client_factory=self.factory)
        self.addAsyncCleanup(self.pool.close)

    async def borrow(self, names=('rule-a',), config=CONFIG):
        servers = {s: config['mcpServers'][s] for s in names}
        return await self.pool.borrow(config, servers, [A if s=='rule-a' else B for s in names])

    async def test_transport_reuse_keeps_fresh_schema_and_results(self):
        for index in range(2):
            lease = await self.borrow()
            connector = lease.get_all_active_sessions()['rule-a'].connector
            self.assertEqual(await connector.list_tools(), ['schema-v'+str(index+1)])
            answer = await connector.call_tool('get_rule_change_target', {'turn':index})
            self.assertEqual(answer, {'fresh_value':index+1,'arguments':{'turn':index}})
            self.assertEqual(lease.metrics()['reused'], ['rule-a'] if index else [])
            await lease.close_all_sessions()
            with self.assertRaisesRegex(ValueError,'read_lease_closed'):
                await connector.list_tools()
        self.assertEqual(len(self.factory.clients), 1)
        await self.pool.close()
        self.assertTrue(self.factory.clients[0].closed)

    async def test_host_subset_isolated_and_retained_connections_not_exposed(self):
        for names in [('rule-a',), ('rule-b',), ('rule-a','rule-b')]:
            lease = await self.borrow(names)
            self.assertEqual(set(lease.get_all_active_sessions()),set(names))
            for s in lease.get_all_active_sessions().values():await s.connector.list_tools()
            await lease.close_all_sessions()
        self.assertEqual(len(self.factory.clients), 2)

    async def test_protected_and_mixed_servers_never_pooled(self):
        for servers, tools in [({'resp':{}}, ['mcp__resp__list_blocks']),
                ({'rule-write-a':{}}, ['mcp__rule_write_a__propose_rule_edit']),
                ({'rule-a':{}}, [B]), ({'rule-a':{}}, None)]:
            self.assertFalse(eligible(servers, tools))
        lease=await self.borrow();connector=lease.get_all_active_sessions()['rule-a'].connector
        with self.assertRaisesRegex(ValueError,'pool_read_tool_only'):
            await connector.call_tool('propose_rule_edit',{})
        await lease.close_all_sessions()
        self.assertEqual(self.factory.reads,0)

    async def test_config_change_discards_old_connection(self):
        first=await self.borrow();await first.get_all_active_sessions()['rule-a'].connector.list_tools()
        await first.close_all_sessions()
        second=await self.borrow(config={**CONFIG,'model':'changed'})
        await second.get_all_active_sessions()['rule-a'].connector.list_tools()
        self.assertTrue(self.factory.clients[0].closed)
        self.assertEqual(second.metrics()['created'],['rule-a'])
        await second.close_all_sessions()

    async def test_idle_expiry_reopens_on_demand(self):
        self.pool.idle_seconds=.02
        first=await self.borrow();await first.get_all_active_sessions()['rule-a'].connector.list_tools()
        await first.close_all_sessions();await asyncio.sleep(.05)
        self.assertTrue(self.factory.clients[0].closed)
        second=await self.borrow();await second.get_all_active_sessions()['rule-a'].connector.list_tools()
        self.assertEqual(len(self.factory.clients),2)
        await second.close_all_sessions()

    async def test_stale_discovery_reconnects_once(self):
        first=await self.borrow();connector=first.get_all_active_sessions()['rule-a'].connector
        await connector.list_tools();self.factory.fail_lists=1
        await connector.list_tools()
        self.assertTrue(self.factory.clients[0].closed)
        self.assertEqual(first.metrics()['discovery_reconnections'],1)
        await first.close_all_sessions()

    async def test_read_failure_is_not_replayed(self):
        first=await self.borrow();connector=first.get_all_active_sessions()['rule-a'].connector
        await connector.list_tools();self.factory.fail_call=True
        with self.assertRaises(ConnectionError):await connector.call_tool('get_rule_change_target',{})
        self.assertEqual(self.factory.reads,1)
        self.factory.fail_call=False
        await connector.list_tools()
        self.assertEqual((await connector.call_tool('get_rule_change_target',{}))['fresh_value'],2)
        await first.close_all_sessions()

    async def test_timeout_retires_owned_transport_and_recovers_next_request(self):
        first=await self.borrow();connector=first.get_all_active_sessions()['rule-a'].connector
        await connector.list_tools();self.factory.block=True
        with self.assertRaises(TimeoutError):
            await connector.call_tool('get_rule_change_target',{},read_timeout_seconds=timedelta(seconds=.02))
        self.assertEqual(self.factory.reads,1)
        self.assertTrue(self.factory.clients[0].closed)
        await first.close_all_sessions()

    async def test_cancellation_closes_in_owner_task_without_replay(self):
        first=await self.borrow();connector=first.get_all_active_sessions()['rule-a'].connector
        await connector.list_tools();self.factory.block=True
        task=asyncio.create_task(connector.call_tool('get_rule_change_target',{}))
        await self.factory.started.wait();task.cancel()
        with self.assertRaises(asyncio.CancelledError):await task
        await first.close_all_sessions();self.factory.block=False
        second=await self.borrow();await second.get_all_active_sessions()['rule-a'].connector.list_tools()
        self.assertTrue(self.factory.clients[0].closed)
        self.assertEqual(len(self.factory.clients),2)
        self.assertEqual(self.factory.reads,1)
        await second.close_all_sessions()

    async def test_partial_startup_failure_closes_both_bounded_attempts(self):
        self.factory.partial_init=True
        lease=await self.borrow()
        with self.assertRaises(ConnectionError):await lease.get_all_active_sessions()['rule-a'].connector.list_tools()
        self.assertEqual(len(self.factory.clients),2)
        self.assertTrue(all(x.closed for x in self.factory.clients))
        await lease.close_all_sessions()


if __name__=='__main__':unittest.main()
