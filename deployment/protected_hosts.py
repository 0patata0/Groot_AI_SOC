#!/usr/bin/env python3
"""Resolve the explicit bootstrap protection set without DNS or network calls."""
import ipaddress
import re
import sys
import urllib.parse


ADMIN_INPUT_LIMIT = 8192
ADMIN_ENTRY_LIMIT = 128
ADMIN_FORBIDDEN = tuple(ipaddress.IPv4Network(value) for value in
                        ('0.0.0.0/32', '127.0.0.0/8', '224.0.0.0/4'))


def admin_cidrs(raw):
    """Normalize optional operator IPv4 exceptions without resolving any names.

    Host bits are normalized (192.0.2.123/24 -> 192.0.2.0/24). An entire range
    is refused if it overlaps a forbidden address class, including after a
    broad prefix has been normalized. This never modifies server/LLM protection.
    """
    if not isinstance(raw, str) or len(raw) > ADMIN_INPUT_LIMIT or any(
            ord(char) < 32 and char != '\t' or ord(char) == 127 for char in raw):
        raise ValueError('invalid administrator range input')
    if not raw.strip():
        return ''
    entries = raw.split(',')
    if len(entries) > ADMIN_ENTRY_LIMIT:
        raise ValueError('too many administrator ranges')
    networks = []
    for item in entries:
        item = item.strip()
        if not re.fullmatch(r'[0-9]+(?:\.[0-9]+){3}(?:/(?:[0-9]|[12][0-9]|3[0-2]))?', item):
            raise ValueError('IPv4 address or CIDR required')
        try:
            network = ipaddress.IPv4Network(item, strict=False)
        except ValueError:
            raise ValueError('IPv4 address or CIDR required') from None
        if network.prefixlen == 0 or any(network.overlaps(forbidden) for forbidden in ADMIN_FORBIDDEN):
            raise ValueError('administrator range overlaps a forbidden address class')
        networks.append(network)
    return ','.join(str(network) for network in ipaddress.collapse_addresses(networks))


def protection_set(hosts, llm_url, extra=''):
    def address(value):
        ip = ipaddress.IPv4Address(value)
        if str(ip) != value or ip.is_loopback or ip.is_unspecified or ip.is_multicast:
            raise ValueError('canonical unicast IPv4 required')
        return str(ip)

    protected = {address(value) for value in hosts}
    additions = [] if not extra else [address(value) for value in extra.split(',')]
    protected.update(additions)
    hostname = urllib.parse.urlsplit(llm_url).hostname
    try:
        protected.add(address(hostname))
    except (ValueError, TypeError):
        # A hostname can change independently of this reviewed offline profile.
        # Its operator-approved addresses must be listed explicitly, never guessed.
        if not set(additions) - set(hosts):
            raise ValueError('hostname LLM requires explicit LOG_PROTECTED_IPS') from None
    if len(protected) > 32:
        raise ValueError('at most 32 protected IPv4 addresses')
    return ','.join(sorted(protected, key=ipaddress.IPv4Address))


def cli(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
        if len(args) == 2 and args[0] == '--admin-cidrs':
            print(admin_cidrs(args[1]))
        elif len(args) == 5 and not args[0].startswith('--'):
            print(protection_set(args[:3], args[3], args[4]))
        else:
            raise ValueError('three hosts, LLM URL and optional protection list required')
    except (ValueError, TypeError):
        message = ('invalid administrator ranges; use optional comma-separated IPv4 addresses or CIDRs '
                   '(no /0, loopback, multicast or unspecified range)') if args[:1] == ['--admin-cidrs'] else (
                   'invalid protection set; use IPv4 literals (LLM hostname needs explicit addresses)')
        print(message, file=sys.stderr)
        return 64
    return 0


if __name__ == '__main__':
    sys.exit(cli())
