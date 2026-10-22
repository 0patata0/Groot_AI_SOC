"""Short-lived, client-bound WAF observation sessions; never an IP allowlist."""
import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import time

COOKIE = 'groot_lab_mode'
TTL = 600
JAVA_COOKIES = frozenset(('groot_log4shell_java_http', '__Secure-groot_log4shell_java_https'))


def client_address(request):
    # The fixed TLS proxy overwrites this header. The application only listens
    # on host loopback and Apache restricts the backend path to that proxy.
    raw = request.headers.get('x-lab-client-ip', request.client.host)
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return ''


def signing_key(secret):
    return hmac.new(secret.encode(), b'capstone-practice-mode-v1', hashlib.sha256).digest()


def issue(secret, address, now=None):
    now = int(time.time() if now is None else now)
    if not address:
        raise ValueError('missing client address')
    payload = base64.urlsafe_b64encode(json.dumps([now, now + TTL, address, secrets.token_hex(16)], separators=(',', ':')).encode()).rstrip(b'=').decode()
    signature = hmac.new(signing_key(secret), payload.encode(), hashlib.sha256).hexdigest()
    return payload + '.' + signature, now + TTL


def check(secret, value, address, now=None):
    now = int(time.time() if now is None else now)
    if not isinstance(value, str) or len(value) > 512 or not address:
        return None
    try:
        payload, signature = value.split('.')
        if not re.fullmatch(r'[A-Za-z0-9_-]+', payload) or not re.fullmatch(r'[0-9a-f]{64}', signature):
            return None
        expected = hmac.new(signing_key(secret), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        issued, expiry, bound_address, nonce = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
        if type(issued) is not int or type(expiry) is not int or expiry - issued != TTL:
            return None
        if not issued <= now < expiry or bound_address != address or not re.fullmatch(r'[0-9a-f]{32}', nonce):
            return None
        return expiry
    except (ValueError, TypeError, UnicodeError):
        return None


def safe_lab_cookies(raw, lab_id):
    """Use a route-selected cookie allowlist; never forward the mode cookie."""
    if not isinstance(raw, str) or len(raw) > 4096:
        return ''
    if lab_id == 'CVE-2021-44228':
        patterns = {name: r'[A-Za-z0-9_.-]{1,256}' for name in JAVA_COOKIES}
    elif lab_id == 'LAB-DVWA':
        patterns = {'PHPSESSID': r'[A-Za-z0-9,-]{16,128}',
                    'security': r'(?:low|medium|high|impossible)'}
    else:
        return ''
    result, seen = [], set()
    for part in raw.split(';'):
        name, separator, value = part.strip().partition('=')
        if name not in patterns:
            continue
        if not separator or name in seen or not re.fullmatch(patterns[name], value):
            return ''
        seen.add(name)
        result.append(name + '=' + value)
    return '; '.join(result)


def safe_java_cookies(raw):
    """Compatibility entry point for the original Java-only route."""
    return safe_lab_cookies(raw, 'CVE-2021-44228')
