from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import unittest
from challenge import ChallengeLimit, ChallengeStore
from practice_mode import check, issue, safe_java_cookies, safe_lab_cookies


class ModeTests(unittest.TestCase):
    def test_retired_dvwa_cookie_cannot_become_a_primary_session(self):
        # Independent reconstruction of the retired issuer, using a test key.
        secret, address = 'test-only-secret', '192.168.15.12'
        retired_key = hmac.new(secret.encode(), b'capstone-practice-dvwa-v1', hashlib.sha256).hexdigest()
        retired, _ = issue(retired_key, address, now=1000)
        self.assertIsNone(check(secret, retired, address, now=1001))
        for lab in ('CVE-2021-44228', 'CVE-2021-41773', 'CVE-2021-42013', 'CVE-2021-3156'):
            self.assertEqual(safe_lab_cookies('__Secure-groot_lab_dvwa_mode=' + retired, lab), '')

    def test_expiry_binding_key_rotation_and_signature(self):
        value, expiry = issue('first secret', '192.168.15.12', now=1000)
        self.assertEqual(expiry,1600)
        self.assertEqual(check('first secret',value,'192.168.15.12',now=1599),1600)
        self.assertIsNone(check('first secret',value,'192.168.15.12',now=1600))
        self.assertIsNone(check('first secret',value,'192.168.15.12',now=999))
        self.assertIsNone(check('first secret',value,'192.168.15.13',now=1200))
        self.assertIsNone(check('rotated secret',value,'192.168.15.12',now=1200))
        self.assertIsNone(check('first secret',value+'a','192.168.15.12',now=1200))

    def test_only_one_valid_java_cookie_is_forwarded(self):
        self.assertEqual(safe_java_cookies('groot_lab_mode=private; __Secure-groot_log4shell_java_https=a.b_c-12; other=secret'), '__Secure-groot_log4shell_java_https=a.b_c-12')
        self.assertEqual(safe_java_cookies('groot_log4shell_java_http=one; groot_log4shell_java_http=two'),'')
        self.assertEqual(safe_java_cookies('groot_log4shell_java_http=bad\r\nX: forged'),'')

    def test_each_route_has_its_own_cookie_allowlist(self):
        raw = ('groot_lab_mode=private; PHPSESSID=0123456789abcdef0123456789; '
               'security=low; __Secure-groot_log4shell_java_https=a.b_c-12; admin=secret')
        self.assertEqual(safe_lab_cookies(raw, 'LAB-DVWA'),
                         'PHPSESSID=0123456789abcdef0123456789; security=low')
        self.assertEqual(safe_lab_cookies(raw, 'CVE-2021-44228'),
                         '__Secure-groot_log4shell_java_https=a.b_c-12')
        for identifier in ('CVE-2021-41773', 'CVE-2021-42013', 'CVE-2021-3156', 'LAB-OTHER', ''):
            self.assertEqual(safe_lab_cookies(raw, identifier), '')

    def test_dvwa_invalid_duplicates_and_header_injection_fail_closed(self):
        for raw in ('PHPSESSID=short', 'PHPSESSID=' + 'x' * 129,
                    'PHPSESSID=0123456789abcdef\r\nX-Forged: yes',
                    'PHPSESSID=0123456789abcdef; PHPSESSID=fedcba9876543210',
                    'security=low; security=high', 'security=LOW', 'security=low,admin=yes',
                    'security="low"', 'security', 'security=low;' + 'x' * 4096):
            with self.subTest(raw=raw[:80]):
                self.assertEqual(safe_lab_cookies(raw, 'LAB-DVWA'), '')
        for level in ('low', 'medium', 'high', 'impossible'):
            self.assertEqual(safe_lab_cookies('security=' + level, 'LAB-DVWA'), 'security=' + level)


class ChallengeTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000
        self.elapsed = 200
        self.store = ChallengeStore(clock=lambda:self.now,monotonic=lambda:self.elapsed)
        self.secret = 'test-only-practice-exception-key'
        self.address = '192.168.15.12'
        self.host = 'log4shell.grootlab.duckdns.org'

    def new(self):
        challenge = self.store.issue(self.address,self.host)
        proof = hmac.new(hashlib.sha256(self.secret.encode()).digest(),challenge['message'].encode(),hashlib.sha256).hexdigest()
        return challenge,proof

    def verify(self, challenge, proof, address=None, host=None):
        return self.store.verify(self.secret,challenge['challenge_id'],proof,address or self.address,host or self.host)

    def test_message_is_unique_context_bound_and_success_is_single_use(self):
        first,proof = self.new();second,_ = self.new()
        self.assertNotEqual(first['challenge_id'],second['challenge_id'])
        self.assertNotEqual(first['message'],second['message'])
        self.assertTrue(first['message'].isascii())
        self.assertIn('client_ip='+self.address,first['message'])
        self.assertIn('host='+self.host,first['message'])
        self.assertIn('expires_at=1030',first['message'])
        self.assertRegex(first['message'],r'nonce=[0-9a-f]{64}\n')
        self.assertTrue(self.verify(first,proof))
        self.assertFalse(self.verify(first,proof))

    def test_invalid_proofs_and_context_consume_challenge(self):
        for bad in (None,[],self.secret,hashlib.sha256(self.secret.encode()).hexdigest(),'0'*64,'a'*65):
            challenge,proof = self.new()
            self.assertFalse(self.verify(challenge,bad))
            self.assertFalse(self.verify(challenge,proof))
        for address,host in (('192.168.15.13',self.host),(self.address,'localhost:18090')):
            challenge,proof = self.new()
            self.assertFalse(self.verify(challenge,proof,address,host))
            self.assertFalse(self.verify(challenge,proof))

    def test_wall_clock_and_monotonic_expiry_fail_closed(self):
        challenge,proof = self.new();self.now = 1029
        self.assertTrue(self.verify(challenge,proof))
        self.now = 1000;challenge,proof = self.new();self.now = 1030
        self.assertFalse(self.verify(challenge,proof))
        self.now = 1000;challenge,proof = self.new();self.now = 999
        self.assertFalse(self.verify(challenge,proof))
        self.now = 1000;challenge,proof = self.new();self.elapsed += 30
        self.assertFalse(self.verify(challenge,proof))

    def test_capacity_limits_and_expiry_cleanup(self):
        for _ in range(8):self.new()
        with self.assertRaises(ChallengeLimit):self.new()
        for index in range(31):
            for _ in range(8):self.store.issue('192.168.16.'+str(index+1),self.host)
        with self.assertRaises(ChallengeLimit):self.store.issue('192.168.17.1',self.host)
        self.now += 30;self.elapsed += 30
        self.assertEqual(self.store.issue(self.address,self.host)['expires_at'],1060)

    def test_concurrent_replay_has_exactly_one_success(self):
        challenge,proof = self.new()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _:self.verify(challenge,proof),range(16)))
        self.assertEqual(sum(results),1)

    def test_restart_or_key_rotation_invalidates_pending_proof(self):
        challenge,proof = self.new()
        self.assertFalse(self.store.verify('rotated-key',challenge['challenge_id'],proof,self.address,self.host))
        self.assertFalse(self.verify(challenge,proof))
        challenge,proof = self.new();self.store.clear()
        self.assertFalse(self.verify(challenge,proof))


if __name__=='__main__':unittest.main()
