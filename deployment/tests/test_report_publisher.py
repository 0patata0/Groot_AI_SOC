import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import report_publisher as p


class FakeAPI:
    def __init__(self):
        self.calls = []
        self.user = None
        self.hooks = []
        self.channel = {'team_id': 't'*26, 'name': 'soc-alerts'}
        self.created = 0
        self.bad_owner = False

    def __call__(self, method, path, body=None, absent=False):
        self.calls.append((method, path, copy.deepcopy(body)))
        if path == '/channels/'+'c'*26:
            result = self.channel
        elif path.startswith('/users/'):
            result = self.user
        elif path == '/bots':
            self.user = {'id': 'b'*26, 'username': p.USERNAME, 'is_bot': True, 'roles': 'system_user'}
            self.created += 1
            result = {'user_id': 'b'*26}
        elif path.startswith('/bots/'):
            result = {'description': p.DESCRIPTION, 'display_name': p.USERNAME}
        elif path.endswith('/members'):
            result = {}
        elif path == '/hooks/incoming':
            result = {**body, 'id': 'h'*26}
            if self.bad_owner:
                result['user_id'] = 'a'*26
            self.hooks.append(result)
        elif path.startswith('/hooks/incoming?'):
            result = self.hooks
        elif path.startswith('/hooks/incoming/'):
            result = self.hooks[0]
        else:
            raise AssertionError(path)
        return copy.deepcopy(result), {}


class PublisherTests(unittest.TestCase):
    def test_actual_owner_is_dedicated_bot_and_retry_reuses_same_hook(self):
        api = FakeAPI()
        first = p.provision(api, 't'*26, 'c'*26)
        second = p.provision(api, 't'*26, 'c'*26)
        self.assertEqual(first, second)
        self.assertEqual(api.created, 1)
        self.assertEqual(len(api.hooks), 1)
        self.assertEqual(first['hook']['user_id'], first['bot_id'])
        self.assertTrue(first['hook']['channel_locked'])
        self.assertFalse(any('/tokens' in path or method in ('PUT', 'PATCH', 'DELETE')
                             for method, path, _ in api.calls))

    def test_existing_human_or_admin_is_never_renamed_or_adopted(self):
        for attrs in ({'is_bot': False}, {'roles': 'system_admin system_user'}):
            api = FakeAPI()
            api.user = {'id': 'b'*26, 'username': p.USERNAME, 'is_bot': True,
                        'roles': 'system_user', **attrs}
            with self.assertRaisesRegex(ValueError, 'active_nonadmin'):
                p.provision(api, 't'*26, 'c'*26)
            self.assertEqual([x for x in api.calls if x[0] != 'GET'], [])

    def test_wrong_channel_stops_before_mutation(self):
        api = FakeAPI(); api.channel['name'] = 'town-square'
        with self.assertRaisesRegex(ValueError, 'channel_identity'):
            p.provision(api, 't'*26, 'c'*26)
        self.assertEqual(len(api.calls), 1)

    def test_server_ignoring_owner_is_rejected(self):
        api = FakeAPI(); api.bad_owner = True
        with self.assertRaisesRegex(ValueError, 'hook_identity'):
            p.provision(api, 't'*26, 'c'*26)

    def test_existing_unlocked_hook_is_not_reused(self):
        api = FakeAPI(); p.provision(api, 't'*26, 'c'*26)
        api.hooks[0]['channel_locked'] = False
        with self.assertRaisesRegex(ValueError, 'hook_identity'):
            p.provision(api, 't'*26, 'c'*26)

    def test_duplicate_hooks_require_review(self):
        api = FakeAPI(); p.provision(api, 't'*26, 'c'*26)
        api.hooks.append(copy.deepcopy(api.hooks[0]))
        with self.assertRaisesRegex(ValueError, 'duplicate_hooks'):
            p.provision(api, 't'*26, 'c'*26)


if __name__ == '__main__':
    unittest.main()
