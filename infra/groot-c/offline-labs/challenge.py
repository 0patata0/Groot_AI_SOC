"""Bounded, single-use challenges for the WAF practice exception key.

The browser sends HMAC-SHA-256(SHA-256(UTF-8(key)), UTF-8(message)).
Neither the key nor its reusable SHA-256 digest is part of this protocol.
"""
from dataclasses import dataclass
import hashlib
import hmac
import ipaddress
import re
import secrets
import threading
import time

TTL = 30
PER_ADDRESS_LIMIT = 8
GLOBAL_LIMIT = 256
CONTEXT = 'capstone-waf-practice-session-v1'


class ChallengeLimit(Exception):
    """No new challenge may be allocated until an existing one expires."""


@dataclass(frozen=True)
class _Pending:
    address: str
    host: str
    message: str
    issued: int
    expires: int
    deadline: float


class ChallengeStore:
    def __init__(self, *, clock=None, monotonic=None):
        self._clock = clock or time.time
        self._monotonic = monotonic or time.monotonic
        self._pending = {}
        self._lock = threading.Lock()

    def _clean(self, now, elapsed):
        for identifier, item in list(self._pending.items()):
            if now < item.issued or now >= item.expires or elapsed >= item.deadline:
                del self._pending[identifier]

    def issue(self, address, host):
        # The application derives both values from its fixed proxy boundary.
        # Restrict them here too so the ASCII message cannot gain extra fields.
        if str(ipaddress.ip_address(address)) != address:
            raise ValueError('invalid challenge address')
        if not isinstance(host, str) or not re.fullmatch(r'[A-Za-z0-9.\[\]:-]{1,255}', host):
            raise ValueError('invalid challenge host')
        with self._lock:
            now, elapsed = int(self._clock()), self._monotonic()
            self._clean(now, elapsed)
            if len(self._pending) >= GLOBAL_LIMIT or sum(item.address == address for item in self._pending.values()) >= PER_ADDRESS_LIMIT:
                raise ChallengeLimit()
            identifier = secrets.token_hex(16)
            while identifier in self._pending:
                identifier = secrets.token_hex(16)
            expires = now + TTL
            message = '\n'.join((CONTEXT, 'challenge_id=' + identifier,
                                 'nonce=' + secrets.token_hex(32), 'expires_at=' + str(expires),
                                 'client_ip=' + address, 'host=' + host))
            self._pending[identifier] = _Pending(address, host, message, now, expires, elapsed + TTL)
        return {'challenge_id': identifier, 'message': message, 'expires_at': expires,
                'algorithm': 'HMAC-SHA-256', 'key_derivation': 'SHA-256'}

    def verify(self, secret, identifier, proof, address, host):
        # Pop under the same lock as issuance: concurrent attempts can never
        # verify one challenge twice. Invalid proofs and context also consume it.
        with self._lock:
            self._clean(int(self._clock()), self._monotonic())
            item = self._pending.pop(identifier, None) if isinstance(identifier, str) and re.fullmatch(r'[0-9a-f]{32}', identifier) else None
        if item is None or not isinstance(proof, str) or not re.fullmatch(r'[0-9a-f]{64}', proof):
            return False
        derived_key = hashlib.sha256(secret.encode('utf-8')).digest()
        expected = hmac.new(derived_key, item.message.encode('ascii'), hashlib.sha256).hexdigest()
        valid_proof = hmac.compare_digest(expected, proof)
        return valid_proof and item.address == address and item.host == host

    def clear(self):
        with self._lock:
            self._pending.clear()
