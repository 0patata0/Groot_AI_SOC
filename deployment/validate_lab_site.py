#!/usr/bin/env python3
"""Validate data before it is interpolated into Nginx or shell configuration."""
import ipaddress
import re
import sys
from urllib.parse import urlsplit

def validate(origin, port, allowed, subnet):
    u = urlsplit(origin)
    hostname = u.hostname or ''
    if not (u.scheme == 'https' and u.path == '' and not u.query and not u.fragment and
            not u.username and not u.password and re.fullmatch(r'[a-z0-9.-]+', hostname) and
            len(hostname) <= 253 and '.' in hostname and re.search('[a-z]', hostname.split('.')[-1]) and
            all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p) for p in hostname.split('.'))):
        raise ValueError('HTTPS DNS origin without path required')
    actual_port = u.port or 443
    if not (str(port).isdigit() and 1 <= int(port) <= 65535 and actual_port == int(port)):
        raise ValueError('HTTPS origin/port mismatch')
    authority = hostname if actual_port == 443 else hostname + ':' + str(actual_port)
    if origin != 'https://' + authority: raise ValueError('canonical HTTPS origin required')
    rfc1918 = [ipaddress.ip_network(x) for x in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
    public = allowed == 'all'
    nets = [] if public else [ipaddress.ip_network(x, strict=True) for x in allowed.split(',')]
    if not public and (not 1 <= len(nets) <= 32 or len(nets) != len(set(nets))):
        raise ValueError('one to 32 unique internal/VPN networks required')
    for n in nets:
        if n.version != 4 or not any(n.subnet_of(p) for p in rfc1918):
            raise ValueError('only RFC1918 internal/VPN networks allowed')
    proxy = ipaddress.ip_network(subnet, strict=True)
    if proxy.version != 4 or proxy.prefixlen != 29 or not any(proxy.subnet_of(n) for n in rfc1918):
        raise ValueError('private /29 proxy subnet required')
    if any(proxy.overlaps(n) for n in nets): raise ValueError('proxy/client network overlap')
    return {'origin': origin, 'hostname': hostname, 'authority': authority, 'port': actual_port,
            'allowed': ['all'] if public else [str(n) for n in nets], 'subnet': str(proxy),
            'waf_ip': str(proxy.network_address + 2), 'edge_ip': str(proxy.network_address + 3)}

if __name__ == '__main__':
    try:
        if len(sys.argv) != 5: raise ValueError('four site arguments required')
        validate(*sys.argv[1:])
    except ValueError as exc:
        print('lab site: ' + str(exc), file=sys.stderr)
        sys.exit(1)
